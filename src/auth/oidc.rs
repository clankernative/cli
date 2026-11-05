//! Google desktop authorization code + S256 PKCE and signed ID-token validation.

use aws_lc_rs::{
    digest,
    rand::{SecureRandom as _, SystemRandom},
    signature,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Identity, Result, Saved, Secret, fail, http, invalid, login_required, secret_shape};

const AUTHORIZATION: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub(super) const TOKEN: &str = "https://oauth2.googleapis.com/token";
pub(super) const JWKS: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub(super) fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| {
            fail(
                "clock_unavailable",
                "A valid system clock is required for sign-in.",
            )
        })
}

pub(super) fn hash(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, value).as_ref())
}

fn random() -> Result<Secret> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new().fill(&mut bytes).map_err(|_| {
        fail(
            "entropy_unavailable",
            "Secure OS randomness is required for sign-in.",
        )
    })?;
    Ok(Secret(URL_SAFE_NO_PAD.encode(bytes)))
}

pub(super) struct Proof {
    pub(super) state: Secret,
    nonce: Secret,
    verifier: Secret,
}

impl Proof {
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            state: random()?,
            nonce: random()?,
            verifier: random()?,
        })
    }

    pub(super) fn authorization_url(&self, identity: &Identity, redirect: &str) -> String {
        let query = form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", identity.desktop_client.client_id.as_str()),
                ("redirect_uri", redirect),
                ("response_type", "code"),
                ("scope", "openid email"),
                ("access_type", "offline"),
                ("prompt", "select_account consent"),
                ("hd", &identity.hosted_domain),
                ("state", &self.state.0),
                ("nonce", &self.nonce.0),
                ("code_challenge_method", "S256"),
                ("code_challenge", &hash(self.verifier.0.as_bytes())),
            ])
            .finish();
        format!("{AUTHORIZATION}?{query}")
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Secret,
    refresh_token: Option<Secret>,
    token_type: String,
    expires_in: u64,
}

#[derive(Deserialize)]
pub(super) struct Claims {
    iss: String,
    aud: String,
    azp: Option<String>,
    pub(super) sub: String,
    pub(super) email: String,
    email_verified: bool,
    hd: String,
    pub(super) exp: u64,
    iat: u64,
    nonce: Option<String>,
}

impl Claims {
    fn validate(&self, identity: &Identity, nonce: Option<&str>, at: u64) -> Result<()> {
        if !matches!(
            self.iss.as_str(),
            "https://accounts.google.com" | "accounts.google.com"
        ) || self.aud != identity.desktop_client.client_id
            || self
                .azp
                .as_ref()
                .is_some_and(|party| party != &identity.desktop_client.client_id)
            || !self.email_verified
            || self.hd != identity.hosted_domain
            || !human_email(&self.email, &identity.hosted_domain)
            || self.sub.is_empty()
            || self.sub.len() > 255
            || !self.sub.bytes().all(|b| b.is_ascii_alphanumeric())
            || self.iat > at.saturating_add(60)
            || self.exp <= at.saturating_add(30)
            || self.exp > at.saturating_add(7_200)
            || self.exp <= self.iat
            || nonce.is_some_and(|expected| self.nonce.as_deref() != Some(expected))
        {
            return Err(fail(
                "identity_refused",
                "The identity token did not match this company, OAuth client, sign-in request or current time.",
            ));
        }
        Ok(())
    }
}

pub(super) fn human_email(email: &str, domain: &str) -> bool {
    let Some((local, actual_domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && email.len() <= 254
        && !local.contains('@')
        && local.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'+' | b'-')
        })
        && actual_domain == domain
        && !actual_domain.ends_with(".gserviceaccount.com")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: Option<String>,
}

#[derive(Deserialize)]
struct Keys {
    keys: Vec<Key>,
}

#[derive(Deserialize)]
struct Key {
    kid: String,
    alg: String,
    kty: String,
    #[serde(rename = "use")]
    usage: String,
    n: String,
    e: String,
}

fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())
}

fn verify(
    token: &Secret,
    keys: &Keys,
    identity: &Identity,
    nonce: Option<&str>,
    at: u64,
) -> Result<Claims> {
    if !secret_shape(&token.0) || keys.keys.len() > 20 {
        return Err(invalid());
    }
    let mut parts = token.0.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid());
    };
    let header: Header = serde_json::from_slice(&decode(header)?).map_err(|_| invalid())?;
    if header.alg != "RS256"
        || header.typ.as_deref().is_some_and(|kind| kind != "JWT")
        || header.kid.is_empty()
        || header.kid.len() > 128
    {
        return Err(invalid());
    }
    let matches: Vec<_> = keys
        .keys
        .iter()
        .filter(|key| key.kid == header.kid)
        .collect();
    let [key] = matches.as_slice() else {
        return Err(invalid());
    };
    if key.alg != "RS256" || key.kty != "RSA" || key.usage != "sig" {
        return Err(invalid());
    }
    let n = decode(&key.n)?;
    let e = decode(&key.e)?;
    let signing_input = token
        .0
        .rsplit_once('.')
        .map(|(value, _)| value)
        .ok_or_else(invalid)?;
    signature::RsaPublicKeyComponents { n: &n, e: &e }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            signing_input.as_bytes(),
            &decode(signature)?,
        )
        .map_err(|_| invalid())?;
    let claims: Claims = serde_json::from_slice(&decode(payload)?).map_err(|_| invalid())?;
    claims.validate(identity, nonce, at)?;
    Ok(claims)
}

pub(super) struct Tokens {
    pub(super) id_token: Secret,
    pub(super) refresh_token: Option<Secret>,
    pub(super) claims: Claims,
}

fn tokens(
    transport: &impl http::Transport,
    response: &http::Response,
    identity: &Identity,
    nonce: Option<&str>,
    at: u64,
) -> Result<Tokens> {
    let tokens: TokenResponse = response.json(200)?;
    if tokens.token_type != "Bearer"
        || !(1..=7_200).contains(&tokens.expires_in)
        || tokens
            .refresh_token
            .as_ref()
            .is_some_and(|token| !secret_shape(&token.0))
    {
        return Err(invalid());
    }
    let keys: Keys = transport.send(http::Request::get(JWKS.into()))?.json(200)?;
    let claims = verify(&tokens.id_token, &keys, identity, nonce, at)?;
    Ok(Tokens {
        id_token: tokens.id_token,
        refresh_token: tokens.refresh_token,
        claims,
    })
}

pub(super) fn exchange(
    transport: &impl http::Transport,
    identity: &Identity,
    proof: &Proof,
    redirect: &str,
    code: &Secret,
) -> Result<Tokens> {
    let request = http::Request::form(
        TOKEN.into(),
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &identity.desktop_client.client_id),
            ("client_secret", &identity.desktop_client.client_secret.0),
            ("code", &code.0),
            ("redirect_uri", redirect),
            ("code_verifier", &proof.verifier.0),
        ],
    );
    let response = transport.send(request)?;
    tokens(transport, &response, identity, Some(&proof.nonce.0), now()?)
}

pub(super) fn refresh(transport: &impl http::Transport, saved: &Saved, at: u64) -> Result<Tokens> {
    let refresh = saved.refresh_token.as_ref().ok_or_else(login_required)?;
    let request = http::Request::form(
        TOKEN.into(),
        &[
            ("grant_type", "refresh_token"),
            (
                "client_id",
                &saved.binding.identity.desktop_client.client_id,
            ),
            (
                "client_secret",
                &saved.binding.identity.desktop_client.client_secret.0,
            ),
            ("refresh_token", &refresh.0),
        ],
    );
    let response = transport.send(request)?;
    let tokens = tokens(transport, &response, &saved.binding.identity, None, at)?;
    if tokens.claims.sub != saved.subject || tokens.claims.email != saved.actor {
        return Err(invalid());
    }
    Ok(tokens)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use aws_lc_rs::signature::KeyPair as _;
    use serde_json::{Value, json};

    // Generate ephemeral test keys; no private key fixture is committed.
    pub(in crate::auth) fn signed(claims: &Value) -> (Secret, Value) {
        fn element<'a>(bytes: &mut &'a [u8], tag: u8) -> &'a [u8] {
            assert_eq!(bytes[0], tag);
            let initial = bytes[1];
            *bytes = &bytes[2..];
            let length = if initial < 128 {
                usize::from(initial)
            } else {
                let count = usize::from(initial & 127);
                let length = bytes[..count]
                    .iter()
                    .fold(0_usize, |n, b| n * 256 + usize::from(*b));
                *bytes = &bytes[count..];
                length
            };
            let result = &bytes[..length];
            *bytes = &bytes[length..];
            result
        }
        let key = signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let mut der = key.public_key().as_ref();
        let mut sequence = element(&mut der, 0x30);
        let n = element(&mut sequence, 0x02);
        let n = n.strip_prefix(&[0]).unwrap_or(n);
        let e = element(&mut sequence, 0x02);
        let jwks = json!({"keys":[{"kid":"ephemeral-test-key","kty":"RSA","alg":"RS256","use":"sig","n":URL_SAFE_NO_PAD.encode(n),"e":URL_SAFE_NO_PAD.encode(e)}]});
        let header =
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"ephemeral-test-key","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let input = format!("{header}.{payload}");
        let mut signature = vec![0; key.public_modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .unwrap();
        (
            Secret(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))),
            jwks,
        )
    }

    pub(in crate::auth) fn claims(nonce: Option<&str>, at: u64) -> Value {
        json!({"iss":"https://accounts.google.com","aud":"123-desktop.apps.googleusercontent.com","sub":"123456789","email":"employee@company.example","email_verified":true,"hd":"company.example","iat":at,"exp":at+3600,"nonce":nonce})
    }

    #[test]
    fn pkce_uses_rfc7636_s256_vector() {
        assert_eq!(
            hash(b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn signed_tokens_require_signature_issuer_audience_nonce_domain_and_expiry() {
        let at = now().unwrap();
        let identity = super::super::tests::binding().identity;
        let (token, jwks) = signed(&claims(Some("expected-nonce"), at));
        let keys: Keys = serde_json::from_value(jwks).unwrap();
        assert!(verify(&token, &keys, &identity, Some("expected-nonce"), at).is_ok());
        assert!(verify(&token, &keys, &identity, Some("wrong-nonce"), at).is_err());
        assert!(verify(&token, &keys, &identity, Some("expected-nonce"), at + 3600).is_err());
        let (input, encoded_signature) = token.0.rsplit_once('.').unwrap();
        let mut signature = decode(encoded_signature).unwrap();
        signature[0] ^= 1;
        let tampered = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert!(
            verify(
                &Secret(tampered),
                &keys,
                &identity,
                Some("expected-nonce"),
                at
            )
            .is_err()
        );
        for (field, value) in [
            ("iss", json!("https://attacker.example")),
            ("aud", json!("other-client")),
            ("azp", json!("other-client")),
            ("sub", json!("")),
            ("hd", json!("other.example")),
            ("email", json!("employee@other.example")),
            ("email", json!("robot@project.iam.gserviceaccount.com")),
            ("email_verified", json!(false)),
            ("exp", json!(at - 1)),
            ("iat", json!(at + 120)),
            ("nonce", json!("wrong-nonce")),
        ] {
            let mut claims = claims(Some("expected-nonce"), at);
            claims[field] = value;
            let (token, jwks) = signed(&claims);
            let keys: Keys = serde_json::from_value(jwks).unwrap();
            assert!(
                verify(&token, &keys, &identity, Some("expected-nonce"), at).is_err(),
                "{field}"
            );
        }
    }
}

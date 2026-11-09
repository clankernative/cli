//! Bounded HTTPS with no ambient proxies, cookie jar, redirects or write retries.

use serde::Deserialize;
use std::{collections::BTreeMap, time::Duration};

use super::{MAX_DOCUMENT, Result, Secret, fail, invalid};
use zeroize::Zeroize as _;

pub(super) enum BodyLimit {
    Auth,
    Api,
    SecretValue,
    Sqlite,
}

impl BodyLimit {
    const fn bytes(self) -> u64 {
        match self {
            Self::Auth | Self::SecretValue => 65_536,
            Self::Api => 1_048_576,
            Self::Sqlite => 16_777_216,
        }
    }
}

pub(super) struct Request {
    pub(super) url: String,
    pub(super) headers: Vec<(String, String)>,
    body: Option<Secret>,
    pub(super) response_limit: BodyLimit,
}

impl Request {
    #[cfg(test)]
    pub(super) fn body(&self) -> Option<&str> {
        self.body.as_ref().map(|body| body.0.as_str())
    }
    pub(super) fn get(url: String) -> Self {
        Self {
            url,
            headers: vec![("Accept".into(), "application/json".into())],
            body: None,
            response_limit: BodyLimit::Auth,
        }
    }

    pub(super) fn form(url: String, fields: &[(&str, &str)]) -> Self {
        let body = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        Self {
            url,
            headers: vec![
                (
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("Accept".into(), "application/json".into()),
            ],
            body: Some(Secret(body)),
            response_limit: BodyLimit::Auth,
        }
    }

    pub(super) fn json(url: String, body: String) -> Self {
        Self {
            url,
            headers: vec![
                ("Accept".into(), "application/json".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: Some(Secret(body)),
            response_limit: BodyLimit::Api,
        }
    }

    pub(super) fn bearer(&mut self, token: &Secret) {
        self.headers
            .push(("Authorization".into(), format!("Bearer {}", token.0)));
    }

    pub(super) fn cookie(&mut self, cookie: &Secret) {
        self.headers.push(("Cookie".into(), cookie.0.clone()));
    }
}

pub(super) struct Response {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl Drop for Response {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

impl Response {
    pub(super) fn json<T: serde::de::DeserializeOwned>(&self, status: u16) -> Result<T> {
        if self.status == 401 || self.status == 403 {
            return Err(fail(
                "authentication_rejected",
                "Authentication or app access was refused. Sign in again or contact your instance administrator.",
            ));
        }
        if self.status != status || self.body.len() > MAX_DOCUMENT {
            return Err(invalid());
        }
        let content_types: Vec<_> = self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .collect();
        if content_types.len() != 1
            || !content_types[0]
                .1
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(invalid());
        }
        serde_json::from_slice(&self.body).map_err(|_| invalid())
    }

    pub(super) fn session_cookie(&self) -> Result<Option<Secret>> {
        let mut found = None;
        for (_, value) in self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        {
            let mut parts = value.split(';').map(str::trim);
            let Some(cookie) = parts.next() else {
                return Err(invalid());
            };
            if !cookie.starts_with("__Host-day2_") {
                continue;
            }
            let mut attributes = BTreeMap::new();
            for part in parts {
                let (name, value) = part.split_once('=').map_or((part, None), |(name, value)| {
                    (name, Some(value.trim().to_ascii_lowercase()))
                });
                if attributes
                    .insert(name.trim().to_ascii_lowercase(), value)
                    .is_some()
                {
                    return Err(invalid());
                }
            }
            if found.is_some()
                || !valid_cookie(cookie)
                || attributes.get("secure") != Some(&None)
                || attributes.get("httponly") != Some(&None)
                || attributes.get("path").and_then(Option::as_deref) != Some("/")
                || attributes.get("samesite").and_then(Option::as_deref) != Some("strict")
                || attributes.contains_key("domain")
            {
                return Err(invalid());
            }
            found = Some(Secret(cookie.into()));
        }
        Ok(found)
    }

    pub(super) fn logout_confirmed(&self, cookie: &Secret) -> bool {
        let Some((name, _)) = cookie.0.split_once('=') else {
            return false;
        };
        let cleared = format!("{name}=");
        let locations: Vec<_> = self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("location"))
            .collect();
        matches!(self.status, 302 | 303)
            && locations.len() == 1
            && locations[0].1 == "/?gcp-iap-mode=CLEAR_LOGIN_COOKIE"
            && self.headers.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("set-cookie")
                    && value.split(';').next() == Some(&cleared)
                    && value
                        .split(';')
                        .any(|part| part.trim().eq_ignore_ascii_case("max-age=0"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
        sync::Arc,
        thread,
        time::Instant,
    };

    struct TlsFixture {
        origin: String,
        port: u16,
        roots: ureq::tls::RootCerts,
        server: thread::JoinHandle<Vec<String>>,
    }

    impl TlsFixture {
        fn start(redirect: String) -> Self {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let roots = vec![ureq::tls::Certificate::from_der(cert.der()).to_owned()].into();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = thread::spawn(move || {
                let config = Arc::new(config);
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut attempts = 0;
                let mut requests = Vec::new();
                while attempts < 5 && Instant::now() < deadline {
                    let socket = match listener.accept() {
                        Ok((socket, _)) => socket,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("TLS fixture accept: {error}"),
                    };
                    attempts += 1;
                    // macOS can inherit the listener's nonblocking mode.
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let connection = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                    let mut stream = rustls::StreamOwned::new(connection, socket);
                    let mut bytes = Vec::new();
                    while bytes.len() < 8192 && !bytes.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        if stream.read_exact(&mut byte).is_err() {
                            break;
                        }
                        bytes.push(byte[0]);
                    }
                    if !bytes.ends_with(b"\r\n\r\n") {
                        continue;
                    }
                    let request = String::from_utf8(bytes).unwrap();
                    let oversized = request.starts_with("GET /oversized ");
                    let redirecting = request.starts_with("GET /redirect ");
                    requests.push(request);
                    let body = if oversized {
                        vec![b' '; super::super::MAX_DOCUMENT + 1]
                    } else {
                        b"{\"ok\":true}".to_vec()
                    };
                    let status = if redirecting { "302 Found" } else { "200 OK" };
                    let location = if redirecting {
                        format!("Location: {redirect}\r\n")
                    } else {
                        String::new()
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{location}\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(&body);
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                }
                assert_eq!(attempts, 5);
                requests
            });
            Self {
                origin: format!("https://localhost:{port}"),
                port,
                roots,
                server,
            }
        }

        fn client(&self) -> Native {
            // Preserve the production provider. Only the test trust roots differ.
            let production = Native::tls_config();
            let provider = production
                .unversioned_rustls_crypto_provider()
                .clone()
                .unwrap();
            let tls = ureq::tls::TlsConfig::builder()
                .unversioned_rustls_crypto_provider(provider)
                .root_certs(self.roots.clone())
                .build();
            Native::with_tls(tls)
        }
    }

    #[test]
    fn real_tls_validates_certificates_and_hostname_refuses_redirects_and_bounds_bodies() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let fixture = TlsFixture::start(format!(
            "https://localhost:{}/secret",
            target.local_addr().unwrap().port()
        ));
        let client = fixture.client();
        let mut request = Request::get(format!("{}/ok", fixture.origin));
        request.bearer(&Secret("synthetic-bearer-canary".into()));
        let value: serde_json::Value = client.send(request).unwrap().json(200).unwrap();
        assert_eq!(value["ok"], true);
        // Neither failed TLS handshake may send an HTTP Authorization header.
        assert!(
            Native::new()
                .send(Request::get(format!("{}/untrusted", fixture.origin)))
                .is_err()
        );
        assert!(
            client
                .send(Request::get(format!(
                    "https://127.0.0.1:{}/wrong-host",
                    fixture.port
                )))
                .is_err()
        );
        let mut request = Request::get(format!("{}/redirect", fixture.origin));
        request.bearer(&Secret("synthetic-bearer-canary".into()));
        let redirected = client.send(request);
        assert!(
            redirected.is_err()
                || redirected
                    .as_ref()
                    .is_ok_and(|response| response.status == 302)
        );
        assert_eq!(
            target.accept().err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(
            client
                .send(Request::get(format!("{}/oversized", fixture.origin)))
                .is_err()
        );
        let requests = fixture.server.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].contains("synthetic-bearer-canary"));
    }

    #[test]
    fn native_transport_refuses_plaintext_before_dispatching_credentials() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let native = Native::new();
        assert!(native.0.config().https_only());
        assert!(native.0.config().proxy().is_none());
        assert_eq!(native.0.config().max_redirects(), 0);
        assert_eq!(native.0.config().max_response_header_size(), 16_384);
        let mut request = Request::get(format!("http://{}/", listener.local_addr().unwrap()));
        request.bearer(&Secret("synthetic-token-canary".into()));
        assert!(native.send(request).is_err());
        assert_eq!(
            listener.accept().err().unwrap().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn duplicate_cookie_attributes_and_provider_error_bodies_are_refused() {
        let response = Response {status:200,headers:vec![("set-cookie".into(),"__Host-day2_reports_aabb=synthetic-cookie-value; Secure; HttpOnly; Path=/; Path=/other; SameSite=Strict".into())],body:vec![]};
        assert!(response.session_cookie().is_err());
        let response = Response {
            status: 403,
            headers: vec![],
            body: b"provider-secret-canary".to_vec(),
        };
        let error = response.json::<serde_json::Value>(200).err().unwrap();
        assert!(!format!("{error:?}").contains("provider-secret-canary"));
    }
}

pub(super) fn valid_cookie(cookie: &str) -> bool {
    let Some((name, value)) = cookie.split_once('=') else {
        return false;
    };
    name.starts_with("__Host-day2_")
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        && (16..=512).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Session {
    pub(super) actor: String,
    pub(super) csrf_token: Secret,
}

pub(super) trait Transport {
    fn send(&self, request: Request) -> Result<Response>;
}

pub(super) struct Native(ureq::Agent);

impl Native {
    pub(super) fn new() -> Self {
        Self::with_tls(Self::tls_config())
    }

    fn tls_config() -> ureq::tls::TlsConfig {
        ureq::tls::TlsConfig::builder()
            .unversioned_rustls_crypto_provider(std::sync::Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .build()
    }

    fn with_tls(tls: ureq::tls::TlsConfig) -> Self {
        Self(
            ureq::Agent::config_builder()
                .tls_config(tls)
                .https_only(true)
                .proxy(None)
                .max_redirects(0)
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(15)))
                .timeout_connect(Some(Duration::from_secs(5)))
                .max_response_header_size(16_384)
                .build()
                .into(),
        )
    }
}

impl Transport for Native {
    fn send(&self, request: Request) -> Result<Response> {
        let failure = || {
            fail(
                "auth_transport_failed",
                "The authentication request failed. Redirects and automatic mutation retries are disabled.",
            )
        };
        let mut response = if let Some(body) = request.body {
            let mut builder = self.0.post(&request.url);
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            builder.send(body.0.as_str()).map_err(|_| failure())?
        } else {
            let mut builder = self.0.get(&request.url);
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            builder.call().map_err(|_| failure())?
        };
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                value
                    .to_str()
                    .map(|value| (name.as_str().into(), value.into()))
                    .map_err(|_| invalid())
            })
            .collect::<Result<Vec<_>>>()?;
        let body = response
            .body_mut()
            .with_config()
            .limit(request.response_limit.bytes())
            .read_to_vec()
            .map_err(|_| failure())?;
        Ok(Response {
            status,
            headers,
            body,
        })
    }
}

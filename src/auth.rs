//! Human login adapters for the platform's Google IAP and app-session channel.

use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::IsTerminal as _, time::Duration};

use super::Failure;

mod api;
mod browser;
mod http;
mod lock;
mod oidc;
mod store;

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, Failure>;
const DISCOVERY_PATH: &str = "/.well-known/day2-cli.json";
const SELECTED: &str = "selected-instance";
const MAX_DOCUMENT: usize = 65_536;

#[derive(Args)]
pub(super) struct Login {
    /// HTTPS company app origin, e.g. <https://tools.company.example>
    #[arg(long)]
    instance: String,
    /// Print the sign-in URL on stderr instead of opening a browser on this machine
    #[arg(long)]
    no_browser: bool,
    /// Maximum seconds to wait for browser sign-in
    #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(30..=300))]
    timeout: u64,
}

#[derive(Args)]
pub(super) struct Context {
    /// HTTPS company app origin; defaults to the most recent successful login
    #[arg(long)]
    instance: Option<String>,
}

#[derive(Args)]
pub(super) struct Call {
    #[command(flatten)]
    context: Context,
    /// Admitted operation ID from this app's `OpenAPI` document
    #[arg(required_unless_present = "invocation", conflicts_with = "invocation")]
    operation: Option<String>,
    /// JSON input object (defaults to {})
    #[arg(long, conflicts_with_all = ["input_file", "invocation"])]
    input: Option<String>,
    /// Read a bounded JSON input object from this file, or - for stdin
    #[arg(long, conflicts_with = "invocation")]
    input_file: Option<std::path::PathBuf>,
    /// Required for commands; preserve this exact key when reconciling a retry
    #[arg(long, conflicts_with = "invocation")]
    idempotency_key: Option<String>,
    /// Ask commands to return after durable acceptance
    #[arg(long = "async", conflicts_with = "invocation")]
    asynchronous: bool,
    /// Read an existing invocation receipt without dispatching the command again
    #[arg(long)]
    invocation: Option<String>,
}

pub(super) fn openapi(context: &Context) -> Result<api::Output> {
    api::openapi(context)
}

pub(super) fn call(options: &Call) -> Result<api::Output> {
    api::call(options)
}

fn fail(code: &'static str, message: &'static str) -> Failure {
    Failure {
        exit_code: 3,
        code,
        message: message.into(),
    }
}

fn invalid() -> Failure {
    fail(
        "invalid_auth_response",
        "The authentication response was refused.",
    )
}

fn login_required() -> Failure {
    fail(
        "login_required",
        "Run day2 login --instance https://your-company-app first.",
    )
}

/// Only a canonical HTTPS origin can select a credential destination.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Origin(String);

impl Origin {
    fn parse(input: &str) -> Result<Self> {
        let canonical = input.strip_suffix('/').unwrap_or(input);
        let host = canonical.strip_prefix("https://").unwrap_or_default();
        if host.len() > 253
            || !host.contains('.')
            || !host.split('.').all(|part| label(part) && part.len() <= 63)
            || !host
                .rsplit('.')
                .next()
                .is_some_and(|part| part.bytes().all(|b| b.is_ascii_lowercase()))
        {
            return Err(fail(
                "invalid_instance",
                "Use an exact HTTPS hostname without a port, path, credentials, query or fragment.",
            ));
        }
        Ok(Self(canonical.into()))
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.0)
    }

    fn key(&self) -> String {
        format!("instance-{}", oidc::hash(self.0.as_bytes()))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Discovery {
    schema_version: u32,
    instance_origin: String,
    installation: String,
    environment: String,
    identity: Identity,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    scheme: Scheme,
    desktop_client: DesktopClient,
    hosted_domain: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DesktopClient {
    client_id: String,
    client_secret: RegistrationValue,
}

// Google Desktop registrations are public-client metadata, not user credentials.
// Still omit the registration value from diagnostics and result envelopes.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
struct RegistrationValue(String);

impl std::fmt::Debug for RegistrationValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[redacted desktop registration]")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Scheme {
    #[serde(rename = "google_iap")]
    GoogleIap,
}

impl Discovery {
    fn validate(&self, origin: &Origin) -> Result<()> {
        let identity = &self.identity;
        let client = identity
            .desktop_client
            .client_id
            .strip_suffix(".apps.googleusercontent.com");
        let domain = &identity.hosted_domain;
        if self.schema_version != 1
            || self.instance_origin != origin.0
            || !instance_identifier(&self.installation)
            || !instance_identifier(&self.environment)
            || !client.is_some_and(|prefix| {
                !prefix.is_empty()
                    && prefix.len() <= 200
                    && prefix
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            || !(16..=256).contains(&identity.desktop_client.client_secret.0.len())
            || !identity
                .desktop_client
                .client_secret
                .0
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            || domain.len() > 253
            || !domain.contains('.')
            || !domain
                .split('.')
                .all(|part| label(part) && part.len() <= 63)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

// Match the platform's instance installation/environment identifiers. DNS
// labels have a different alphabet; an underscore is valid in an instance name.
fn instance_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !value.starts_with("day2_")
        && !value.starts_with("sqlite_")
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

// No Debug: these values must never enter diagnostics or output envelopes.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    schema_version: u32,
    binding: Discovery,
    subject: String,
    actor: String,
    id_token: Secret,
    refresh_token: Option<Secret>,
    expires_at: u64,
    cookie: Option<Secret>,
}

fn secret_shape(value: &str) -> bool {
    (16..=16_384).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_graphic())
}

impl Saved {
    fn validate(&self, origin: &Origin) -> Result<()> {
        self.binding.validate(origin)?;
        if self.schema_version != 1
            || !secret_shape(&self.id_token.0)
            || self
                .refresh_token
                .as_ref()
                .is_some_and(|token| !secret_shape(&token.0))
            || self
                .cookie
                .as_ref()
                .is_some_and(|cookie| !http::valid_cookie(&cookie.0))
            || !oidc::human_email(&self.actor, &self.binding.identity.hosted_domain)
            || self.subject.is_empty()
            || self.subject.len() > 255
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn summary(&self) -> Value {
        json!({
            "instance": self.binding.instance_origin,
            "installation": self.binding.installation,
            "environment": self.binding.environment,
            "actor": self.actor,
            "expires_at": self.expires_at,
            "authentication": "google_iap_and_app_session"
        })
    }
}

fn discover(transport: &impl http::Transport, origin: &Origin) -> Result<Discovery> {
    let response = transport.send(http::Request::get(origin.endpoint(DISCOVERY_PATH)))?;
    if response.status != 200 {
        return Err(fail(
            "instance_setup_required",
            "The app's public /.well-known/day2-cli.json discovery document is unavailable. Ask the instance administrator to complete the company setup in docs/LOGIN.md.",
        ));
    }
    let discovery: Discovery = response.json(200)?;
    discovery.validate(origin)?;
    Ok(discovery)
}

fn selected(store: &impl store::Store, context: &Context) -> Result<Origin> {
    let input = match &context.instance {
        Some(value) => value.clone(),
        None => store.get(SELECTED)?.ok_or_else(login_required)?,
    };
    Origin::parse(&input)
}

fn load(store: &impl store::Store, origin: &Origin) -> Result<Saved> {
    let value = store.get(&origin.key())?.ok_or_else(login_required)?;
    if value.len() > MAX_DOCUMENT {
        return Err(invalid());
    }
    let saved: Saved = serde_json::from_str(&value).map_err(|_| invalid())?;
    saved.validate(origin)?;
    Ok(saved)
}

fn persist(store: &impl store::Store, origin: &Origin, saved: &Saved) -> Result<()> {
    saved.validate(origin)?;
    let value = serde_json::to_string(saved).map_err(|_| invalid())?;
    store.set(&origin.key(), &value)
}

fn session(
    transport: &impl http::Transport,
    origin: &Origin,
    saved: &mut Saved,
) -> Result<http::Session> {
    let mut request = http::Request::get(origin.endpoint("/api/session"));
    request.bearer(&saved.id_token);
    if let Some(cookie) = &saved.cookie {
        request.cookie(cookie);
    }
    let response = transport.send(request)?;
    let session: http::Session = response.json(200)?;
    if session.actor != saved.actor || !secret_shape(&session.csrf_token.0) {
        return Err(invalid());
    }
    if let Some(cookie) = response.session_cookie()? {
        saved.cookie = Some(cookie);
    }
    if saved.cookie.is_none() {
        return Err(fail(
            "app_session_required",
            "The app did not establish a secure platform session.",
        ));
    }
    Ok(session)
}

pub(super) fn login(options: &Login, machine: bool) -> Result<(Value, String)> {
    // Fail before network, browser or credential-store work in headless/agent mode.
    if machine || !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return Err(fail(
            "interactive_required",
            "Login requires an interactive terminal and a browser on this machine. Sign in interactively, then use whoami --json.",
        ));
    }
    let origin = Origin::parse(&options.instance)?;
    let _guard = lock::Guard::acquire()?;
    let store = store::Native;
    store::ready()?;
    let transport = http::Native::new();
    let binding = discover(&transport, &origin)?;
    let proof = oidc::Proof::new()?;
    let callback = browser::Callback::bind(Duration::from_secs(options.timeout))?;
    let authorization = proof.authorization_url(&binding.identity, callback.redirect_uri());
    browser::open(&authorization, options.no_browser)?;
    let code = callback.receive(&proof.state)?;
    let saved = complete_login(&transport, binding, &proof, callback.redirect_uri(), &code)?;
    persist(&store, &origin, &saved)?;
    store::Store::set(&store, SELECTED, &origin.0)?;
    Ok((
        saved.summary(),
        format!("Signed in as {} at {}.\n", saved.actor, origin.0),
    ))
}

fn complete_login(
    transport: &impl http::Transport,
    binding: Discovery,
    proof: &oidc::Proof,
    redirect: &str,
    code: &Secret,
) -> Result<Saved> {
    let origin = Origin::parse(&binding.instance_origin)?;
    binding.validate(&origin)?;
    let tokens = oidc::exchange(transport, &binding.identity, proof, redirect, code)?;
    let mut saved = Saved {
        schema_version: 1,
        binding,
        subject: tokens.claims.sub,
        actor: tokens.claims.email,
        id_token: tokens.id_token,
        refresh_token: tokens.refresh_token,
        expires_at: tokens.claims.exp,
        cookie: None,
    };
    session(transport, &origin, &mut saved)?;
    Ok(saved)
}

fn identify(
    transport: &impl http::Transport,
    store: &impl store::Store,
    origin: &Origin,
    now: u64,
) -> Result<Saved> {
    let mut saved = load(store, origin)?;
    // Revalidate the company binding before sending any credential to its app.
    if discover(transport, origin)? != saved.binding {
        return Err(fail(
            "instance_changed",
            "The instance authentication configuration changed. Sign in again.",
        ));
    }
    if saved.expires_at <= now.saturating_add(60) {
        let refreshed = oidc::refresh(transport, &saved, now)?;
        // Commit a rotated refresh token before any subsequent app request can fail.
        saved.id_token = refreshed.id_token;
        if let Some(token) = refreshed.refresh_token {
            saved.refresh_token = Some(token);
        }
        saved.expires_at = refreshed.claims.exp;
        persist(store, origin, &saved)?;
    }
    session(transport, origin, &mut saved)?;
    persist(store, origin, &saved)?;
    Ok(saved)
}

pub(super) fn whoami(context: &Context) -> Result<(Value, String)> {
    let _guard = lock::Guard::acquire()?;
    let store = store::Native;
    let origin = selected(&store, context)?;
    let saved = identify(&http::Native::new(), &store, &origin, oidc::now()?)?;
    Ok((
        saved.summary(),
        format!(
            "{} at {} ({}/{})\n",
            saved.actor, origin.0, saved.binding.installation, saved.binding.environment
        ),
    ))
}

fn forget(
    transport: &impl http::Transport,
    store: &impl store::Store,
    origin: &Origin,
) -> Result<bool> {
    // Remove local secrets even if discovery, expiry or a remote outage prevents logout.
    let saved = load(store, origin);
    store.delete(&origin.key())?;
    if store.get(SELECTED)?.as_deref() == Some(&origin.0) {
        store.delete(SELECTED)?;
    }
    let Ok(mut saved) = saved else {
        return Ok(false);
    };
    if saved.expires_at <= oidc::now()?
        || discover(transport, origin).ok().as_ref() != Some(&saved.binding)
    {
        return Ok(false);
    }
    let Ok(session) = session(transport, origin, &mut saved) else {
        return Ok(false);
    };
    let mut request = http::Request::form(
        origin.endpoint("/logout"),
        &[("_csrf", &session.csrf_token.0)],
    );
    request.bearer(&saved.id_token);
    if let Some(cookie) = &saved.cookie {
        request.cookie(cookie);
    }
    request.headers.push(("Origin".into(), origin.0.clone()));
    Ok(transport.send(request).is_ok_and(|response| {
        saved
            .cookie
            .as_ref()
            .is_some_and(|cookie| response.logout_confirmed(cookie))
    }))
}

pub(super) fn logout(context: &Context) -> Result<(Value, String)> {
    let _guard = lock::Guard::acquire()?;
    let store = store::Native;
    let origin = selected(&store, context)?;
    let ended = forget(&http::Native::new(), &store, &origin)?;
    let message = if ended {
        "Local credentials removed and app session ended. Browser SSO remains signed in.\n"
    } else {
        "Local credentials removed. Remote session termination was not confirmed; it will expire. Browser SSO remains signed in.\n"
    };
    Ok((
        json!({"instance":origin.0,"local_credentials_removed":true,"app_session_ended":ended}),
        message.into(),
    ))
}

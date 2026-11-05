use super::*;
use http::{Request, Response, Transport};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
};
use store::Store;

const INSTANCE: &str = "https://tools.company.example";
const OTHER: &str = "https://tools.other.example";
const ACTOR: &str = "employee@company.example";
const COOKIE: &str = "__Host-day2_reports_aabb=synthetic-cookie-value";

#[derive(Default)]
struct Memory(RefCell<BTreeMap<String, String>>);

impl Store for Memory {
    fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.0.borrow().get(key).cloned())
    }
    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.0.borrow_mut().insert(key.into(), value.into());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.borrow_mut().remove(key);
        Ok(())
    }
}

#[derive(Default)]
struct Mock {
    requests: RefCell<Vec<Request>>,
    responses: RefCell<VecDeque<Response>>,
}

impl Transport for Mock {
    fn send(&self, request: Request) -> Result<Response> {
        self.requests.borrow_mut().push(request);
        self.responses.borrow_mut().pop_front().ok_or_else(invalid)
    }
}

fn response(value: &impl Serialize) -> Response {
    Response {
        status: 200,
        headers: vec![("content-type".into(), "application/json".into())],
        body: serde_json::to_vec(value).unwrap(),
    }
}

pub(super) fn binding() -> Discovery {
    Discovery {
        schema_version: 1,
        instance_origin: INSTANCE.into(),
        installation: "company".into(),
        environment: "production".into(),
        identity: Identity {
            scheme: Scheme::GoogleIap,
            desktop_client_id: "123-desktop.apps.googleusercontent.com".into(),
            hosted_domain: "company.example".into(),
        },
    }
}

fn saved() -> Saved {
    Saved {
        schema_version: 1,
        binding: binding(),
        subject: "123456789".into(),
        actor: ACTOR.into(),
        id_token: Secret("synthetic-id-token-value".into()),
        refresh_token: Some(Secret("synthetic-refresh-value".into())),
        expires_at: oidc::now().unwrap() + 3600,
        cookie: Some(Secret(COOKIE.into())),
    }
}

fn app_session() -> Response {
    let mut result = response(&json!({"actor":ACTOR,"csrf_token":"synthetic-csrf-token-value"}));
    result.headers.push((
        "set-cookie".into(),
        format!("{COOKIE}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800"),
    ));
    result
}

#[test]
fn origins_and_discovery_refuse_ambiguous_destinations() {
    assert_eq!(Origin::parse(&format!("{INSTANCE}/")).unwrap().0, INSTANCE);
    for value in [
        "http://company.example",
        "https://Company.example",
        "https://company.example:443",
        "https://company.example/path",
        "https://company.example?x=1",
        "https://user@company.example",
        "https://127.0.0.1",
        "https://company.example#fragment",
        "https://company.example\\@evil.example",
    ] {
        assert!(Origin::parse(value).is_err(), "{value}");
    }
    let origin = Origin::parse(INSTANCE).unwrap();
    binding().validate(&origin).unwrap();
    assert!(binding().validate(&Origin::parse(OTHER).unwrap()).is_err());
    for field in [
        "schema_version",
        "instance_origin",
        "installation",
        "environment",
        "identity",
    ] {
        let mut value = serde_json::to_value(binding()).unwrap();
        value[field] = Value::Null;
        assert!(serde_json::from_value::<Discovery>(value).is_err());
    }
}

#[test]
fn discovery_uses_platform_instance_identifiers_and_dns_domain_labels() {
    let origin = Origin::parse(INSTANCE).unwrap();
    let mut discovery = binding();
    discovery.installation = "company_tools".into();
    discovery.environment = "cli_canary".into();
    discovery.identity.hosted_domain = "my-company.example".into();
    discovery.validate(&origin).unwrap();
    for name in [
        "",
        "Company",
        "1company",
        "company-tools",
        "day2_internal",
        "sqlite_private",
    ] {
        discovery.installation = name.into();
        assert!(discovery.validate(&origin).is_err(), "{name}");
    }
    discovery.installation = "a".repeat(49);
    assert!(discovery.validate(&origin).is_err());
    discovery.installation = "company_tools".into();
    discovery.identity.hosted_domain = "company_tools.example".into();
    assert!(discovery.validate(&origin).is_err());
}

#[test]
fn identity_is_verified_online_and_credentials_never_cross_instance() {
    let origin = Origin::parse(INSTANCE).unwrap();
    let store = Memory::default();
    persist(&store, &origin, &saved()).unwrap();
    let mock = Mock::default();
    mock.responses
        .borrow_mut()
        .extend([response(&binding()), app_session()]);
    let identity = identify(&mock, &store, &origin, oidc::now().unwrap()).unwrap();
    assert_eq!(identity.actor, ACTOR);
    let requests = mock.requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url, format!("{INSTANCE}{DISCOVERY_PATH}"));
    assert!(
        requests[0]
            .headers
            .iter()
            .all(|(name, _)| name != "Authorization" && name != "Cookie")
    );
    assert_eq!(requests[1].url, format!("{INSTANCE}/api/session"));
    assert!(
        requests[1]
            .headers
            .iter()
            .any(|(name, value)| name == "Cookie" && value == COOKIE)
    );
    drop(requests);
    assert!(
        identify(
            &mock,
            &store,
            &Origin::parse(OTHER).unwrap(),
            oidc::now().unwrap()
        )
        .is_err()
    );
    assert_eq!(mock.requests.borrow().len(), 2);
    let summary = identity.summary().to_string();
    for secret in [
        "synthetic-id-token",
        "synthetic-refresh",
        "synthetic-cookie",
        "synthetic-csrf",
    ] {
        assert!(!summary.contains(secret));
    }
}

#[test]
fn changed_company_binding_stops_before_any_credential_dispatch() {
    let origin = Origin::parse(INSTANCE).unwrap();
    for pointer in [
        "/environment",
        "/identity/desktop_client_id",
        "/identity/hosted_domain",
        "/instance_origin",
    ] {
        let store = Memory::default();
        persist(&store, &origin, &saved()).unwrap();
        let mock = Mock::default();
        let mut value = serde_json::to_value(binding()).unwrap();
        *value.pointer_mut(pointer).unwrap() = json!(match pointer {
            "/environment" => "staging",
            "/identity/desktop_client_id" => "456-other.apps.googleusercontent.com",
            "/identity/hosted_domain" => "other.example",
            _ => OTHER,
        });
        mock.responses.borrow_mut().push_back(response(&value));
        assert!(identify(&mock, &store, &origin, oidc::now().unwrap()).is_err());
        assert_eq!(mock.requests.borrow().len(), 1);
    }
}

#[test]
fn malformed_redirected_oversized_and_wrong_actor_sessions_fail_closed() {
    let origin = Origin::parse(INSTANCE).unwrap();
    let mut redirected = app_session();
    redirected.status = 302;
    let mut oversized = app_session();
    oversized.body = vec![b' '; MAX_DOCUMENT + 1];
    let wrong_actor = response(
        &json!({"actor":"other@company.example","csrf_token":"synthetic-csrf-token-value"}),
    );
    let missing_csrf = response(&json!({"actor":ACTOR}));
    let mut unsafe_cookie = app_session();
    unsafe_cookie.headers[1].1 =
        format!("{COOKIE}; Domain=company.example; Path=/; HttpOnly; SameSite=Strict");
    for result in [
        redirected,
        oversized,
        wrong_actor,
        missing_csrf,
        unsafe_cookie,
    ] {
        let mock = Mock::default();
        mock.responses.borrow_mut().push_back(result);
        let mut identity = saved();
        assert!(session(&mock, &origin, &mut identity).is_err());
        assert_eq!(mock.requests.borrow().len(), 1);
    }
}

#[test]
fn logout_removes_only_selected_instance_even_when_remote_is_unavailable() {
    let store = Memory::default();
    let origin = Origin::parse(INSTANCE).unwrap();
    let other = Origin::parse(OTHER).unwrap();
    persist(&store, &origin, &saved()).unwrap();
    store.set(&other.key(), "other-instance-canary").unwrap();
    store.set(SELECTED, INSTANCE).unwrap();
    assert!(!forget(&Mock::default(), &store, &origin).unwrap());
    assert!(store.get(&origin.key()).unwrap().is_none());
    assert!(store.get(SELECTED).unwrap().is_none());
    assert_eq!(
        store.get(&other.key()).unwrap().unwrap(),
        "other-instance-canary"
    );
}

#[test]
fn logout_sends_csrf_cookie_and_exact_origin_without_following_redirect() {
    let store = Memory::default();
    let origin = Origin::parse(INSTANCE).unwrap();
    persist(&store, &origin, &saved()).unwrap();
    let mock = Mock::default();
    mock.responses.borrow_mut().extend([response(&binding()), app_session(), Response {status:303,headers:vec![("location".into(), "/?gcp-iap-mode=CLEAR_LOGIN_COOKIE".into()),("set-cookie".into(),"__Host-day2_reports_aabb=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0".into())],body:vec![]}]);
    assert!(forget(&mock, &store, &origin).unwrap());
    let requests = mock.requests.borrow();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].url, format!("{INSTANCE}/logout"));
    assert!(
        requests[2]
            .headers
            .iter()
            .any(|(name, value)| name == "Origin" && value == INSTANCE)
    );
    assert!(
        requests[2]
            .headers
            .iter()
            .any(|(name, value)| name == "Cookie" && value == COOKIE)
    );
    assert_eq!(requests[2].body(), Some("_csrf=synthetic-csrf-token-value"));
}

#[test]
fn complete_login_exchanges_pkce_verifies_signed_token_and_establishes_app_session() {
    let proof = oidc::Proof::new().unwrap();
    let redirect = "http://127.0.0.1:12345/oauth/callback";
    let authorization = proof.authorization_url(&binding().identity, redirect);
    let fields: BTreeMap<_, _> =
        form_urlencoded::parse(authorization.split_once('?').unwrap().1.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(fields["scope"], "openid email");
    assert_eq!(fields["code_challenge_method"], "S256");
    assert_eq!(fields["redirect_uri"], redirect);
    assert!(!fields.contains_key("client_secret"));
    let (token, jwks) = oidc::tests::signed(&oidc::tests::claims(
        Some(&fields["nonce"]),
        oidc::now().unwrap(),
    ));
    let mock = Mock::default();
    mock.responses.borrow_mut().extend([
        response(&json!({"id_token":token.0,"refresh_token":"synthetic-refresh-token-value","token_type":"Bearer","expires_in":3600})),
        response(&jwks),app_session(),
    ]);
    let identity = complete_login(
        &mock,
        binding(),
        &proof,
        redirect,
        &Secret("synthetic-authorization-code".into()),
    )
    .unwrap();
    assert_eq!(identity.actor, ACTOR);
    assert!(identity.cookie.is_some());
    let requests = mock.requests.borrow();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].url, oidc::TOKEN);
    let exchange: BTreeMap<_, _> = form_urlencoded::parse(requests[0].body().unwrap().as_bytes())
        .into_owned()
        .collect();
    assert_eq!(exchange["code"], "synthetic-authorization-code");
    assert_eq!(exchange["grant_type"], "authorization_code");
    assert_eq!(
        oidc::hash(exchange["code_verifier"].as_bytes()),
        fields["code_challenge"]
    );
    assert_eq!(requests[1].url, oidc::JWKS);
    assert_eq!(requests[2].url, format!("{INSTANCE}/api/session"));
    assert!(!requests[2].headers.iter().any(|(name, _)| name == "Cookie"));
}

#[test]
fn refresh_rotation_is_saved_even_if_subsequent_app_authentication_fails() {
    let origin = Origin::parse(INSTANCE).unwrap();
    let store = Memory::default();
    let at = oidc::now().unwrap();
    let mut identity = saved();
    identity.expires_at = at - 1;
    persist(&store, &origin, &identity).unwrap();
    let (token, jwks) = oidc::tests::signed(&oidc::tests::claims(None, at));
    let mock = Mock::default();
    mock.responses.borrow_mut().extend([
        response(&binding()),
        response(&json!({"id_token":token.0,"refresh_token":"synthetic-rotated-refresh-value","token_type":"Bearer","expires_in":3600})),
        response(&jwks),Response {status:403,headers:vec![],body:b"private-provider-error-canary".to_vec()},
    ]);
    let error = identify(&mock, &store, &origin, at).err().unwrap();
    assert!(!error.message.contains("private-provider-error-canary"));
    assert_eq!(mock.requests.borrow().len(), 4);
    let identity = load(&store, &origin).unwrap();
    assert_eq!(
        identity.refresh_token.unwrap().0,
        "synthetic-rotated-refresh-value"
    );
    assert_eq!(identity.expires_at, at + 3600);
}

#[test]
fn token_dispatch_is_not_retried_after_unknown_outcome() {
    let mock = Mock::default();
    let proof = oidc::Proof::new().unwrap();
    assert!(
        complete_login(
            &mock,
            binding(),
            &proof,
            "http://127.0.0.1:12345/oauth/callback",
            &Secret("synthetic-code-value".into())
        )
        .is_err()
    );
    assert_eq!(mock.requests.borrow().len(), 1);
}

#[test]
fn refresh_cannot_switch_google_subject_or_reuse_missing_credentials() {
    let at = oidc::now().unwrap();
    let identity = saved();
    let mut claims = oidc::tests::claims(None, at);
    claims["sub"] = json!("987654321");
    let (token, jwks) = oidc::tests::signed(&claims);
    let mock = Mock::default();
    mock.responses.borrow_mut().extend([
        response(&json!({"id_token":token.0,"token_type":"Bearer","expires_in":3600})),
        response(&jwks),
    ]);
    assert!(oidc::refresh(&mock, &identity, at).is_err());
    assert_eq!(mock.requests.borrow().len(), 2);
    let mut identity = saved();
    identity.refresh_token = None;
    assert_eq!(
        oidc::refresh(&Mock::default(), &identity, at)
            .err()
            .unwrap()
            .code,
        "login_required"
    );
}

use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) const VALUE: &[u8] = b"SYNTHETIC_SECRET_CLI_VALUE_NEVER_OUTPUT\n";
pub(super) struct File(pub(super) PathBuf);
impl File {
    pub(super) fn new(value: &[u8]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "day2-secret-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, value).unwrap();
        Self(path)
    }
}
impl Drop for File {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
pub(super) fn context() -> AppContext {
    AppContext {
        app: "reports".into(),
        auth: auth::Context::default(),
    }
}
pub(super) fn snapshot() -> Value {
    json!({"protocol":2,"kind":"app-secrets","scope":"company/production/reports","actor":"employee@company.example","authority":{"epoch":format!("sha256:{}", "a".repeat(64)),"revision":7},"secrets":[]})
}
pub(super) fn write_snapshot(rotate: bool) -> Value {
    let mut result = snapshot();
    if rotate {
        result["secrets"] = json!([{"name":"API_KEY","incarnation":"0123456789abcdef0123456789abcdef","container_created":true,"version":7,"blocked":false,"request_id":"previous-request"}]);
    }
    result
}

pub(super) fn receipt(operation: &str, version: Option<u64>, state: &str) -> Value {
    json!({"protocol":2,"kind":"app-secret-write","scope":"company/production/reports","actor":"employee@company.example","authority":snapshot()["authority"],"name":"API_KEY","incarnation":"0123456789abcdef0123456789abcdef","operation":operation,"request_id":"request-1","state":state,"version":version,"activation_performed":false})
}
fn mutation(path: PathBuf, expected_version: Option<&str>) -> Mutation {
    Mutation {
        context: context(),
        name: "API_KEY".into(),
        stdin: false,
        file: Some(path),
        request_id: "request-1".into(),
        expected_version: expected_version.map(str::to_owned),
    }
}

#[test]
fn create_and_rotate_send_private_values_once_and_output_only_metadata() {
    let file = File::new(VALUE);
    for rotate in [false, true] {
        let operation = if rotate { "rotate" } else { "create" };
        let args = mutation(file.0.clone(), rotate.then_some("7"));
        let command = if rotate {
            Command::Rotate(args)
        } else {
            Command::Create(args)
        };
        let (client, requests) = auth::app_test::client(vec![
            (200, write_snapshot(rotate).to_string()),
            (200, receipt(operation, Some(8), "stored").to_string()),
        ]);
        let (result, text) = run_using(&command, |_| Ok(client)).unwrap();
        assert!(
            !result
                .to_string()
                .contains(std::str::from_utf8(VALUE).unwrap())
        );
        assert!(!result.to_string().contains(&STANDARD.encode(VALUE)));
        assert!(!text.contains("SYNTHETIC_SECRET"));
        assert_eq!(result["version"], 8);
        assert_eq!(result["activation_performed"], false);
        let requests = requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].url,
            "https://tools.company.example/api/app-secrets"
        );
        assert_eq!(requests[1].url, requests[0].url);
        let headers = &requests[1].headers;
        assert!(
            headers
                .iter()
                .any(|(key, value)| key == "Origin" && value == "https://tools.company.example")
        );
        assert!(
            headers
                .iter()
                .any(|(key, value)| key == "Idempotency-Key" && value == "request-1")
        );
        assert!(headers.iter().any(|(key, _)| key == "Cookie"));
        assert!(headers.iter().any(|(key, _)| key == "Authorization"));
        assert!(headers.iter().any(|(key, _)| key == "X-CSRF-Token"));
        let submitted: Value = serde_json::from_str(requests[1].body.as_deref().unwrap()).unwrap();
        assert_eq!(
            STANDARD
                .decode(submitted["value"].as_str().unwrap())
                .unwrap(),
            VALUE
        );
        assert_eq!(submitted["operation"], operation);
        assert_eq!(submitted["expected_authority"], snapshot()["authority"]);
        assert_eq!(
            submitted["expected_version"],
            if rotate { json!(7) } else { Value::Null }
        );
    }
}

#[test]
fn wrong_company_actor_or_metadata_refuses_before_value_read_or_post() {
    for field in ["scope", "actor", "kind"] {
        let mut snapshot = snapshot();
        snapshot[field] = json!("foreign");
        let (client, requests) = auth::app_test::client(vec![(200, snapshot.to_string())]);
        let command = Command::Create(mutation("/does/not/exist".into(), None));
        assert_eq!(
            run_using(&command, |_| Ok(client)).unwrap_err().code,
            "invalid_secret_response"
        );
        assert_eq!(requests.borrow().len(), 1);
    }
    let (client, requests) = auth::app_test::client(vec![(403, "{}".into())]);
    let command = Command::Create(mutation("/does/not/exist".into(), None));
    assert_eq!(
        run_using(&command, |_| Ok(client)).unwrap_err().code,
        "secret_permission_denied"
    );
    assert_eq!(requests.borrow().len(), 1);
}

#[test]
fn altered_receipts_and_uncertain_outcomes_never_become_success_or_retry() {
    let file = File::new(VALUE);
    for field in ["scope", "actor", "name", "request_id", "operation"] {
        let mut response = receipt("create", Some(1), "stored");
        response[field] = json!("foreign");
        let (client, requests) = auth::app_test::client(vec![
            (200, snapshot().to_string()),
            (200, response.to_string()),
        ]);
        let result = run_using(&Command::Create(mutation(file.0.clone(), None)), |_| {
            Ok(client)
        });
        assert!(result.is_err());
        assert_eq!(requests.borrow().len(), 2);
    }
    let unknown = receipt("rotate", None, "unknown");
    let (client, requests) = auth::app_test::client(vec![
        (200, write_snapshot(true).to_string()),
        (202, unknown.to_string()),
    ]);
    let result = run_using(
        &Command::Rotate(mutation(file.0.clone(), Some("7"))),
        |_| Ok(client),
    );
    assert_eq!(result.unwrap_err().code, "secret_outcome_unknown");
    assert_eq!(requests.borrow().len(), 2);
    let (client, requests) = auth::app_test::client(vec![(200, unknown.to_string())]);
    let command = Command::Status(Status {
        context: context(),
        request_id: "request-1".into(),
    });
    assert_eq!(run_using(&command, |_| Ok(client)).unwrap().0, unknown);
    assert_eq!(
        requests.borrow()[0].url,
        "https://tools.company.example/api/app-secrets/requests/request-1"
    );
    for (status, body) in [(500, "{}"), (200, "not json"), (200, "{\"protocol\":1}")] {
        let (client, requests) =
            auth::app_test::client(vec![(200, snapshot().to_string()), (status, body.into())]);
        let error = run_using(&Command::Create(mutation(file.0.clone(), None)), |_| {
            Ok(client)
        })
        .unwrap_err();
        assert_eq!(error.exit_code, 5);
        assert_eq!(requests.borrow().len(), 2);
        assert!(!error.message.contains("SYNTHETIC_SECRET"));
    }
}

#[test]
fn invalid_mutation_arguments_fail_before_authentication() {
    for command in [
        Command::Create(mutation("/not/read".into(), Some("7"))),
        Command::Rotate(mutation("/not/read".into(), None)),
        Command::Rotate(mutation("/not/read".into(), Some("0"))),
    ] {
        assert_eq!(
            run_using(&command, |_| panic!(
                "must reject before opening credentials"
            ))
            .unwrap_err()
            .code,
            "invalid_secret_arguments"
        );
    }
    assert!(
        expected(&Command::Rotate(mutation("/not/read".into(), Some("none"))))
            .unwrap()
            .is_none()
    );
}

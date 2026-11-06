use super::*;
use crate::auth::{
    persist,
    store::Store,
    tests::{Memory, Mock, app_session, response, saved},
};
use serde_json::json;

fn spec() -> Value {
    json!({
        "openapi":"3.1.1", "info":{"version":format!("sha256:{}", "a".repeat(64))},
        "servers":[{"url":"https://tools.company.example"}],
        "security":[{"AppSession":[]}],
        "components":{"securitySchemes":{"AppSession":{"type":"apiKey","in":"cookie","name":"__Host-day2_reports_aabb"}}},
        "paths":{
            "/api/reports.list":{"get":{"operationId":"reports.list","tags":["query"],"parameters":[
                {"name":"search","in":"query","schema":{"type":"string"}},
                {"name":"filter","in":"query","content":{"application/json":{"schema":{"type":"object"}}}}
            ]}},
            "/api/reports.create":{"post":{"operationId":"reports.create","tags":["command"]}},
            "/api/session":{"get":{"operationId":"platform.session","tags":["platform"]}}
        }
    })
}

fn options(operation: Option<&str>) -> Call {
    Call {
        context: Context {
            instance: Some("https://tools.company.example".into()),
        },
        operation: operation.map(Into::into),
        input: None,
        input_file: None,
        idempotency_key: None,
        asynchronous: false,
        invocation: None,
    }
}

#[test]
fn catalog_binds_exact_origin_cookie_and_operation_before_consuming_input() {
    let origin = Origin::parse("https://tools.company.example").unwrap();
    for mutate in [
        |v: &mut Value| v["servers"][0]["url"] = json!("https://other.company.example"),
        |v: &mut Value| v["security"] = json!([]),
        |v: &mut Value| {
            v["components"]["securitySchemes"]["AppSession"]["name"] =
                json!("__Host-day2_other_aabb");
        },
        |v: &mut Value| v["info"]["version"] = json!("unbound"),
    ] {
        let mock = Mock::default();
        let mut document = spec();
        mutate(&mut document);
        mock.responses.borrow_mut().push_back(response(&document));
        assert!(catalog(&mock, &origin, &saved()).is_err());
    }
    for name in [
        "https://other.example/api/foo",
        "../secrets",
        "reports.list?x=1",
        "reports.list#x",
        "reports.list/other",
        "reports.%2e",
        "reports.list\r\nx:y",
    ] {
        assert!(validate_options(&options(Some(name))).is_err());
    }
    let mock = Mock::default();
    mock.responses.borrow_mut().push_back(response(&spec()));
    let mut call = options(Some("reports.unknown"));
    call.input_file = Some("/a/file/that/must/not/be/read".into());
    assert!(
        matches!(dispatch(&mock, &Memory::default(), &origin, &mut saved(), &call), Err(e) if e.code == "unknown_operation")
    );
    assert_eq!(mock.requests.borrow().len(), 1);
}

#[test]
fn query_uses_catalog_encoding_and_preserves_raw_payload() {
    let mock = Mock::default();
    mock.responses.borrow_mut().extend([
        response(&spec()),
        http::Response {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: b" {\"rows\": []} \n".to_vec(),
        },
    ]);
    let mut call = options(Some("reports.list"));
    call.input = Some(r#"{"search":"a&b/界","filter":{"Some":"x"}}"#.into());
    let result = dispatch(
        &mock,
        &Memory::default(),
        &Origin::parse("https://tools.company.example").unwrap(),
        &mut saved(),
        &call,
    )
    .unwrap();
    assert_eq!(result.body, " {\"rows\": []} \n");
    let requests = mock.requests.borrow();
    let request = &requests[1];
    assert_eq!(
        request.url,
        "https://tools.company.example/api/reports.list?search=a%26b%2F%E7%95%8C&filter=%7B%22Some%22%3A%22x%22%7D"
    );
    assert!(request.body().is_none());
    assert!(request.headers.iter().any(|(name, _)| name == "Cookie"));
    assert!(
        !request
            .headers
            .iter()
            .any(|(name, _)| name == "Idempotency-Key")
    );
    call.idempotency_key = Some("write-key".into());
    let mock = Mock::default();
    mock.responses.borrow_mut().push_back(response(&spec()));
    assert!(
        dispatch(
            &mock,
            &Memory::default(),
            &Origin::parse("https://tools.company.example").unwrap(),
            &mut saved(),
            &call
        )
        .is_err()
    );
    assert_eq!(mock.requests.borrow().len(), 1);
}

#[test]
fn command_requires_key_and_uses_exact_origin_current_csrf_and_cookie() {
    let origin = Origin::parse("https://tools.company.example").unwrap();
    let mut call = options(Some("reports.create"));
    call.input = Some("{ \"title\":\"keep exact input\" }".into());
    let mock = Mock::default();
    mock.responses.borrow_mut().push_back(response(&spec()));
    assert!(dispatch(&mock, &Memory::default(), &origin, &mut saved(), &call).is_err());
    assert_eq!(mock.requests.borrow().len(), 1);
    call.idempotency_key = Some("request_123".into());
    call.asynchronous = true;
    let mock = Mock::default();
    let mut accepted = response(
        &json!({"invocation_id":"api-command-123","status":"pending","status_url":"/api/invocations/api-command-123"}),
    );
    accepted.status = 202;
    accepted
        .headers
        .push(("location".into(), "/api/invocations/api-command-123".into()));
    mock.responses
        .borrow_mut()
        .extend([response(&spec()), app_session(), accepted]);
    let memory = Memory::default();
    let output = dispatch(&mock, &memory, &origin, &mut saved(), &call).unwrap();
    assert_eq!(output.exit_code, 0);
    let requests = mock.requests.borrow();
    let request = &requests[2];
    assert_eq!(request.body(), call.input.as_deref());
    for (name, value) in [
        ("Origin", origin.0.as_str()),
        ("Idempotency-Key", "request_123"),
        ("X-CSRF-Token", "synthetic-csrf-token-value"),
        ("Prefer", "respond-async"),
    ] {
        assert!(
            request
                .headers
                .iter()
                .any(|pair| pair.0 == name && pair.1 == value)
        );
    }
    assert!(memory.get(&origin.key()).unwrap().is_some());
}

#[test]
fn timeout_and_redirect_never_repeat_a_command_or_forward_credentials() {
    let origin = Origin::parse("https://tools.company.example").unwrap();
    let mut call = options(Some("reports.create"));
    call.idempotency_key = Some("original-key".into());
    for redirect in [false, true] {
        let mock = Mock::default();
        mock.responses
            .borrow_mut()
            .extend([response(&spec()), app_session()]);
        if redirect {
            mock.responses.borrow_mut().push_back(http::Response {
                status: 307,
                headers: vec![(
                    "location".into(),
                    "https://other.company.example/api/reports.create".into(),
                )],
                body: b"secret-provider-error".to_vec(),
            });
        }
        let result = dispatch(&mock, &Memory::default(), &origin, &mut saved(), &call);
        assert!(
            matches!(result, Err(e) if matches!(e.code,"api_outcome_unknown" | "api_redirect_refused") && !e.message.contains("secret-provider-error"))
        );
        assert_eq!(mock.requests.borrow().len(), 3);
    }
}

#[test]
fn pending_receipts_refuse_cross_origin_changed_ids_and_duplicate_locations() {
    for path in [
        "https://other.company.example/api/invocations/123",
        "//other.company.example/123",
        "/api/invocations/other",
        "/api/invocations/123?token=secret",
    ] {
        let mut response =
            response(&json!({"invocation_id":"123","status":"pending","status_url":path}));
        response.status = 202;
        response.headers.push(("location".into(), path.into()));
        assert!(pending(&response).is_err());
    }
    let mut response = response(
        &json!({"invocation_id":"123","status":"pending","status_url":"/api/invocations/123"}),
    );
    response.status = 202;
    response.headers.extend([
        ("location".into(), "/api/invocations/123".into()),
        ("location".into(), "/api/invocations/123".into()),
    ]);
    assert!(pending(&response).is_err());
}

#[test]
fn receipt_reads_dispatch_only_get_and_application_errors_stay_raw() {
    let mock = Mock::default();
    let mut error = response(&json!({"error":{"code":"forbidden","message":"Denied."}}));
    error.status = 403;
    let expected = error.body.clone();
    mock.responses
        .borrow_mut()
        .extend([response(&spec()), error]);
    let mut call = options(None);
    call.invocation = Some("api-command-123".into());
    let origin = Origin::parse("https://tools.company.example").unwrap();
    let memory = Memory::default();
    persist(&memory, &origin, &saved()).unwrap();
    let result = dispatch(&mock, &memory, &origin, &mut saved(), &call).unwrap();
    assert_eq!(result.exit_code, 3);
    assert_eq!(result.body.as_bytes(), expected);
    let requests = mock.requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[1].url,
        "https://tools.company.example/api/invocations/api-command-123"
    );
    assert!(requests[1].body().is_none());
}

#[test]
fn malformed_catalogs_inputs_and_responses_fail_closed() {
    for mutate in [
        |v: &mut Value| {
            v["paths"]["/api/reports.list"]["get"]["servers"] =
                json!([{ "url":"https://other.company.example" }]);
        },
        |v: &mut Value| v["paths"]["/api/reports.list"]["get"]["tags"] = json!(["command"]),
        |v: &mut Value| v["paths"]["/api/reports.list"]["get"]["security"] = json!([]),
        |v: &mut Value| v["paths"]["/api/other"] = v["paths"]["/api/reports.list"].clone(),
    ] {
        let mut value = spec();
        mutate(&mut value);
        assert!(endpoint(&value, "reports.list").is_err());
    }
    for input in [
        "[]".into(),
        "secret-not-json".into(),
        "x".repeat(MAX_INPUT + 1),
    ] {
        let mut call = options(Some("reports.create"));
        call.input = Some(input);
        assert!(read_input(&call).is_err());
    }
    assert!(
        output(http::Response {
            status: 200,
            headers: vec![("content-type".into(), "text/html".into())],
            body: b"secret-error-page".to_vec()
        })
        .is_err()
    );
    assert!(
        output(http::Response {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: vec![b' '; MAX_RESPONSE + 1]
        })
        .is_err()
    );
}

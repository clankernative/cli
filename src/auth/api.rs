//! Ordinary app HTTP calls selected only from the current admitted `OpenAPI` catalog.

use super::{
    Call, Context, Origin, Result, Saved, fail, http, identify, lock, oidc, selected, session,
    store,
};
use serde_json::Value;
use std::io::Read as _;

const MAX_RESPONSE: usize = 1_048_576;
const MAX_INPUT: usize = 65_536;

pub(crate) struct Output {
    pub(crate) body: String,
    pub(crate) exit_code: u8,
}

fn refused() -> super::super::Failure {
    fail(
        "invalid_api_contract",
        "The app API contract or response was refused.",
    )
}

fn arguments() -> super::super::Failure {
    fail(
        "invalid_call",
        "Use an admitted operation ID and JSON object. Commands require an explicit 1–128 character alphanumeric, underscore or hyphen idempotency key; queries refuse command flags.",
    )
}

fn identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn operation_name(value: &str) -> bool {
    value.len() <= 80
        && value.contains('.')
        && value.split('.').all(|part| {
            part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

fn json(response: &http::Response) -> Result<Value> {
    let types: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .collect();
    if response.body.len() > MAX_RESPONSE
        || types.len() != 1
        || types[0].1.split(';').next().map(str::trim) != Some("application/json")
    {
        return Err(refused());
    }
    serde_json::from_slice(&response.body).map_err(|_| refused())
}

fn authenticated(origin: &Origin, saved: &Saved, path: &str) -> http::Request {
    let mut request = http::Request::get(origin.endpoint(path));
    request.response_limit = http::BodyLimit::Api;
    request.bearer(&saved.id_token);
    if let Some(cookie) = &saved.cookie {
        request.cookie(cookie);
    }
    request
}

fn catalog(
    transport: &impl http::Transport,
    origin: &Origin,
    saved: &Saved,
) -> Result<http::Response> {
    let response = transport.send(authenticated(origin, saved, "/openapi.json"))?;
    if response.status != 200 {
        return Err(fail(
            "api_unavailable",
            "The authenticated app OpenAPI document is unavailable.",
        ));
    }
    let value = json(&response)?;
    let cookie_name = saved
        .cookie
        .as_ref()
        .and_then(|cookie| cookie.0.split_once('=').map(|pair| pair.0));
    if value["openapi"] != "3.1.1"
        || value["servers"] != serde_json::json!([{ "url": origin.0 }])
        || value["security"] != serde_json::json!([{ "AppSession": [] }])
        || value["components"]["securitySchemes"]["AppSession"]["type"] != "apiKey"
        || value["components"]["securitySchemes"]["AppSession"]["in"] != "cookie"
        || value["components"]["securitySchemes"]["AppSession"]["name"].as_str() != cookie_name
        || !value["info"]["version"]
            .as_str()
            .and_then(|id| id.strip_prefix("sha256:"))
            .is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
        || !value["paths"].is_object()
    {
        return Err(refused());
    }
    Ok(response)
}

pub(super) fn openapi(context: &Context) -> Result<Output> {
    let _guard = lock::Guard::acquire()?;
    let store = store::Native;
    let transport = http::Native::new();
    let origin = selected(&store, context)?;
    let saved = identify(&transport, &store, &origin, oidc::now()?)?;
    output(catalog(&transport, &origin, &saved)?)
}

pub(super) fn call(options: &Call) -> Result<Output> {
    // Refuse destinations, header injection and command identity before reading a body source.
    validate_options(options)?;
    let _guard = lock::Guard::acquire()?;
    let store = store::Native;
    let transport = http::Native::new();
    let origin = selected(&store, &options.context)?;
    let mut saved = identify(&transport, &store, &origin, oidc::now()?)?;
    dispatch(&transport, &store, &origin, &mut saved, options)
}

fn validate_options(options: &Call) -> Result<()> {
    if options
        .operation
        .as_deref()
        .is_some_and(|name| !operation_name(name))
        || options
            .invocation
            .as_deref()
            .is_some_and(|id| !identifier(id, 128))
        || options
            .idempotency_key
            .as_deref()
            .is_some_and(|key| !identifier(key, 128))
    {
        return Err(arguments());
    }
    Ok(())
}

fn endpoint<'a>(document: &'a Value, name: &str) -> Result<(&'a Value, bool)> {
    let path = format!("/api/{name}");
    let paths = document["paths"].as_object().ok_or_else(refused)?;
    let selected_path = paths.get(&path).ok_or_else(|| {
        fail(
            "unknown_operation",
            "The selected app does not publish this operation.",
        )
    })?;
    let matches: Vec<_> = paths
        .values()
        .filter_map(Value::as_object)
        .flat_map(|path| {
            path.iter()
                .filter(|(method, _)| matches!(method.as_str(), "get" | "post"))
        })
        .filter(|(_, operation)| operation["operationId"] == name)
        .collect();
    if matches.len() != 1
        || selected_path.get("servers").is_some()
        || selected_path.get("$ref").is_some()
    {
        return Err(refused());
    }
    let (method, operation) = matches[0];
    let command = method == "post";
    if selected_path.get(method) != Some(operation)
        || operation["tags"] != serde_json::json!([if command { "command" } else { "query" }])
        || operation.get("servers").is_some()
        || operation.get("security").is_some()
        || operation.get("$ref").is_some()
    {
        return Err(refused());
    }
    Ok((operation, command))
}

fn read_input(options: &Call) -> Result<(String, Value)> {
    let body = if let Some(path) = &options.input_file {
        let mut bytes = Vec::new();
        let mut reader: Box<dyn std::io::Read> = if path.as_os_str() == "-" {
            Box::new(std::io::stdin())
        } else {
            Box::new(std::fs::File::open(path).map_err(|_| {
                fail(
                    "input_unavailable",
                    "Could not read the selected input file.",
                )
            })?)
        };
        reader
            .by_ref()
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| arguments())?;
        String::from_utf8(bytes).map_err(|_| arguments())?
    } else {
        options.input.clone().unwrap_or_else(|| "{}".into())
    };
    if body.len() > MAX_INPUT {
        return Err(arguments());
    }
    let value: Value = serde_json::from_str(&body).map_err(|_| arguments())?;
    if !value.is_object() {
        return Err(arguments());
    }
    Ok((body, value))
}

fn query(operation: &Value, input: &Value) -> Result<String> {
    let parameters = operation["parameters"].as_array().ok_or_else(refused)?;
    let fields = input.as_object().ok_or_else(arguments)?;
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    let mut names = std::collections::BTreeSet::new();
    for parameter in parameters.iter().filter(|p| p["in"] == "query") {
        let name = parameter["name"].as_str().ok_or_else(refused)?;
        if !names.insert(name) {
            return Err(refused());
        }
        let value = fields.get(name).ok_or_else(arguments)?;
        let encoded = if parameter.get("content").is_some() {
            if parameter["content"]["application/json"]["schema"].is_null() {
                return Err(refused());
            }
            value.to_string()
        } else {
            match value {
                Value::String(text) => text.clone(),
                Value::Bool(_) | Value::Number(_) => value.to_string(),
                _ => return Err(arguments()),
            }
        };
        serializer.append_pair(name, &encoded);
    }
    if fields.len() != names.len() {
        return Err(arguments());
    }
    let query = serializer.finish();
    if query.len() > 16_384 {
        return Err(arguments());
    }
    Ok(query)
}

fn dispatch(
    transport: &impl http::Transport,
    store: &impl store::Store,
    origin: &Origin,
    saved: &mut Saved,
    options: &Call,
) -> Result<Output> {
    let document = catalog(transport, origin, saved)?;
    let mut request = if let Some(id) = &options.invocation {
        authenticated(origin, saved, &format!("/api/invocations/{id}"))
    } else {
        let name = options.operation.as_deref().ok_or_else(arguments)?;
        let value = json(&document)?;
        let (operation, command) = endpoint(&value, name)?;
        if (command && options.idempotency_key.is_none())
            || (!command && (options.idempotency_key.is_some() || options.asynchronous))
        {
            return Err(arguments());
        }
        // Catalog and flags have been admitted before a file or stdin can be consumed.
        let (body, input) = read_input(options)?;
        if command {
            let current = session(transport, origin, saved)?;
            super::persist(store, origin, saved)?;
            let mut request = http::Request::json(origin.endpoint(&format!("/api/{name}")), body);
            request.bearer(&saved.id_token);
            if let Some(cookie) = &saved.cookie {
                request.cookie(cookie);
            }
            request.headers.extend([
                ("Origin".into(), origin.0.clone()),
                ("X-CSRF-Token".into(), current.csrf_token.0.clone()),
                (
                    "Idempotency-Key".into(),
                    options.idempotency_key.clone().ok_or_else(arguments)?,
                ),
            ]);
            request
        } else {
            let query = query(operation, &input)?;
            let suffix = if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            };
            authenticated(origin, saved, &format!("/api/{name}{suffix}"))
        }
    };
    if options.asynchronous {
        request
            .headers
            .push(("Prefer".into(), "respond-async".into()));
    }
    // A dispatched command is never retried, including response read/validation failures.
    let response = transport.send(request).map_err(|_| fail("api_outcome_unknown", "The API exchange failed. A dispatched command may have committed; reconcile its existing invocation or reuse the exact original key and input. No retry was sent."))?;
    let result = (|| {
        if response.status == 202 {
            pending(&response)?;
        }
        output(response)
    })();
    result.map_err(|error| {
        if options.idempotency_key.is_some() {
            fail("api_outcome_unknown", "The command response was refused. It may have committed. No redirect or retry was followed; reconcile the original invocation or exact original key and input.")
        } else { error }
    })
}

fn pending(response: &http::Response) -> Result<()> {
    let body = json(response)?;
    let id = body["invocation_id"]
        .as_str()
        .filter(|id| identifier(id, 128))
        .ok_or_else(refused)?;
    let path = format!("/api/invocations/{id}");
    let locations: Vec<_> = response
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("location"))
        .collect();
    if body["status"] != "pending"
        || body["status_url"] != path
        || locations.len() != 1
        || locations[0].1 != path
    {
        return Err(fail(
            "api_outcome_unknown",
            "The command response did not contain an exact app invocation receipt. No redirect or retry was followed.",
        ));
    }
    Ok(())
}

fn output(response: http::Response) -> Result<Output> {
    if !(200..=599).contains(&response.status) || (300..=399).contains(&response.status) {
        return Err(fail(
            "api_redirect_refused",
            "The app redirected the API request. No credentials were forwarded and no command was retried.",
        ));
    }
    json(&response)?;
    Ok(Output {
        body: String::from_utf8(response.body).map_err(|_| refused())?,
        exit_code: if response.status < 300 { 0 } else { 3 },
    })
}

#[cfg(test)]
mod tests;

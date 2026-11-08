//! Authenticated app requests reuse the exact login binding and credential lock.
use super::{
    Context, Origin, Result, Saved, Secret, fail, http, identify_session, lock, oidc, selected,
    store,
};

pub(crate) struct Client {
    transport: Box<dyn http::Transport>,
    origin: Origin,
    saved: Saved,
    csrf: Secret,
    _guard: Option<lock::Guard>,
}

impl Client {
    pub(crate) fn download(
        &self,
        path: &str,
        id: &str,
        body: String,
    ) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>)> {
        use base64::Engine as _;
        let (limit, maximum) = match path {
            "/api/app-secrets/reveal" => (http::BodyLimit::SecretValue, 65_536),
            "/api/app-sqlite" => (http::BodyLimit::Sqlite, 16_777_216),
            _ => return Err(super::invalid()),
        };
        let mut request = http::Request::json(self.origin.endpoint(path), body);
        request.response_limit = limit;
        request
            .headers
            .retain(|(key, _)| !key.eq_ignore_ascii_case("accept"));
        request.headers.extend([
            ("Accept".into(), "application/octet-stream".into()),
            ("Origin".into(), self.origin.0.clone()),
            ("X-CSRF-Token".into(), self.csrf.0.clone()),
            ("Idempotency-Key".into(), id.into()),
        ]);
        request.bearer(&self.saved.id_token);
        if let Some(cookie) = &self.saved.cookie {
            request.cookie(cookie);
        }
        let mut response = self.transport.send(request)?;
        if response.status == 403 {
            return Err(fail(
                "secret_permission_denied",
                "The signed-in person is not authorized for this app's protected operation.",
            ));
        }
        if response.status == 409 {
            return Err(fail(
                "secret_conflict",
                "The selected version, authority or request ID changed. Inspect current metadata.",
            ));
        }
        let header = |name: &str| -> Option<&str> {
            let mut values = response
                .headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name));
            let value = values.next()?.1.as_str();
            if values.next().is_some() {
                None
            } else {
                Some(value)
            }
        };
        if response.status != 200
            || response.body.is_empty()
            || response.body.len() > maximum
            || header("content-type") != Some("application/octet-stream")
            || header("cache-control") != Some("no-store")
        {
            return Err(super::invalid());
        }
        let encoded = header("x-day2-result")
            .filter(|s| s.len() <= 8192)
            .ok_or_else(super::invalid)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| super::invalid())?;
        Ok((
            zeroize::Zeroizing::new(std::mem::take(&mut response.body)),
            decoded,
        ))
    }
    pub(crate) fn open(context: &Context) -> Result<Self> {
        let guard = lock::Guard::acquire()?;
        let transport = http::Native::new();
        let store = store::Native;
        let origin = selected(&store, context)?;
        let (saved, current) = identify_session(&transport, &store, &origin, oidc::now()?)?;
        Ok(Self {
            transport: Box::new(transport),
            origin,
            saved,
            csrf: current.csrf_token,
            _guard: Some(guard),
        })
    }

    pub(crate) fn actor(&self) -> &str {
        &self.saved.actor
    }

    pub(crate) fn scope(&self, app: &str) -> String {
        format!(
            "{}/{}/{app}",
            self.saved.binding.installation, self.saved.binding.environment
        )
    }

    fn send<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        mutation: Option<(&str, String)>,
    ) -> Result<T> {
        let write = mutation.is_some();
        if path != "/api/app-secrets"
            && path != "/api/app-sqlite"
            && !path
                .strip_prefix("/api/app-secrets/requests/")
                .is_some_and(super::super::secrets::request_id)
        {
            return Err(super::invalid());
        }
        let mut request = if let Some((id, body)) = mutation {
            let mut request = http::Request::json(self.origin.endpoint(path), body);
            request.headers.extend([
                ("Origin".into(), self.origin.0.clone()),
                ("X-CSRF-Token".into(), self.csrf.0.clone()),
                ("Idempotency-Key".into(), id.into()),
            ]);
            request
        } else {
            http::Request::get(self.origin.endpoint(path))
        };
        request.bearer(&self.saved.id_token);
        if let Some(cookie) = &self.saved.cookie {
            request.cookie(cookie);
        }
        let response = self.transport.send(request)?;
        match response.status {
            200 => response.json(200),
            202 if write => response.json(202),
            403 => Err(fail(
                "secret_permission_denied",
                "The signed-in person is not authorized for this app's secret operation.",
            )),
            409 => Err(fail(
                "secret_conflict",
                "The secret version, authority or request ID conflicted. Inspect secret status before preparing a new request.",
            )),
            _ => Err(fail(
                "secret_request_failed",
                "The secret request did not produce a confirmed result. Inspect its request ID before sending another mutation.",
            )),
        }
    }

    pub(crate) fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send(path, None)
    }
    pub(crate) fn write<T: serde::de::DeserializeOwned>(
        &self,
        id: &str,
        body: String,
    ) -> Result<T> {
        self.send("/api/app-secrets", Some((id, body)))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    pub(crate) struct Sent {
        pub(crate) url: String,
        pub(crate) headers: Vec<(String, String)>,
        pub(crate) body: Option<String>,
    }
    pub(crate) type Requests = Rc<RefCell<Vec<Sent>>>;

    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    struct Mock {
        requests: Requests,
        replies: RefCell<VecDeque<Reply>>,
    }

    impl http::Transport for Mock {
        fn send(&self, request: http::Request) -> Result<http::Response> {
            let body = request.body().map(str::to_owned);
            self.requests.borrow_mut().push(Sent {
                url: request.url,
                headers: request.headers,
                body,
            });
            let reply = self
                .replies
                .borrow_mut()
                .pop_front()
                .ok_or_else(super::super::invalid)?;
            Ok(http::Response {
                status: reply.status,
                headers: reply.headers,
                body: reply.body,
            })
        }
    }

    fn json_replies(replies: Vec<(u16, String)>) -> Vec<Reply> {
        replies
            .into_iter()
            .map(|(status, body)| Reply {
                status,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: body.into_bytes(),
            })
            .collect()
    }

    pub(crate) fn client(replies: Vec<(u16, String)>) -> (Client, Requests) {
        client_replies(json_replies(replies))
    }

    pub(crate) fn download_client(
        replies: Vec<(u16, String)>,
        metadata: &serde_json::Value,
        bytes: Vec<u8>,
    ) -> (Client, Requests) {
        use base64::Engine as _;
        let mut replies = json_replies(replies);
        replies.push(Reply {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "application/octet-stream".into()),
                ("Cache-Control".into(), "no-store".into()),
                (
                    "X-Day2-Result".into(),
                    base64::engine::general_purpose::STANDARD.encode(metadata.to_string()),
                ),
            ],
            body: bytes,
        });
        client_replies(replies)
    }

    fn client_replies(replies: Vec<Reply>) -> (Client, Requests) {
        let binding = super::super::tests::binding();
        let origin = Origin::parse(&binding.instance_origin).unwrap();
        let requests = Rc::new(RefCell::new(Vec::new()));
        let mock = Mock {
            requests: requests.clone(),
            replies: RefCell::new(replies.into()),
        };
        (
            Client {
                transport: Box::new(mock),
                origin,
                saved: Saved {
                    schema_version: 1,
                    binding,
                    subject: "123456789".into(),
                    actor: "employee@company.example".into(),
                    id_token: Secret("synthetic-id-token-value".into()),
                    refresh_token: None,
                    expires_at: 4_000_000_000,
                    cookie: Some(Secret(
                        "__Host-day2_reports_aabb=synthetic-cookie-value".into(),
                    )),
                },
                csrf: Secret("synthetic-csrf-token-value".into()),
                _guard: None,
            },
            requests,
        )
    }
    #[test]
    fn binary_download_refuses_redirects_duplicate_headers_wrong_types_and_oversized_payloads() {
        for case in 0..6 {
            let mut headers = vec![
                ("Content-Type".into(), "application/octet-stream".into()),
                ("Cache-Control".into(), "no-store".into()),
                ("X-Day2-Result".into(), "e30=".into()),
            ];
            let mut status = 200;
            match case {
                0 => status = 302,
                1 => headers[0].1 = "application/json".into(),
                2 => headers[1].1 = "public".into(),
                3 => headers.push(headers[2].clone()),
                4 => headers[2].1 = "not base64".into(),
                _ => {}
            }
            let body = vec![b'x'; if case == 5 { 65_537 } else { 10 }];
            let (client, requests) = client_replies(vec![Reply {
                status,
                headers,
                body,
            }]);
            assert!(
                client
                    .download("/api/app-secrets/reveal", "read-1", "{}".into())
                    .is_err()
            );
            assert_eq!(requests.borrow().len(), 1);
        }
    }
}

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

    struct Mock {
        requests: Requests,
        replies: RefCell<VecDeque<(u16, String)>>,
    }

    impl http::Transport for Mock {
        fn send(&self, request: http::Request) -> Result<http::Response> {
            let body = request.body().map(str::to_owned);
            self.requests.borrow_mut().push(Sent {
                url: request.url,
                headers: request.headers,
                body,
            });
            let (status, body) = self
                .replies
                .borrow_mut()
                .pop_front()
                .ok_or_else(super::super::invalid)?;
            Ok(http::Response {
                status,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: body.into_bytes(),
            })
        }
    }

    pub(crate) fn client(replies: Vec<(u16, String)>) -> (Client, Requests) {
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
}

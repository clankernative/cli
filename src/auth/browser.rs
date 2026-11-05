//! One bounded loopback callback; no token or authorization code is displayed.

use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use super::{Result, Secret, fail, invalid};

pub(super) struct Callback {
    listener: TcpListener,
    redirect: String,
    host: String,
    deadline: Instant,
}

impl Callback {
    pub(super) fn bind(timeout: Duration) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map_err(|_| {
            fail(
                "callback_unavailable",
                "Could not bind the loopback sign-in callback.",
            )
        })?;
        listener.set_nonblocking(true).map_err(|_| invalid())?;
        let host = listener.local_addr().map_err(|_| invalid())?.to_string();
        Ok(Self {
            listener,
            redirect: format!("http://{host}/oauth/callback"),
            host,
            deadline: Instant::now() + timeout,
        })
    }

    pub(super) fn redirect_uri(&self) -> &str {
        &self.redirect
    }

    pub(super) fn receive(&self, state: &Secret) -> Result<Secret> {
        let mut attempts = 0_u16;
        while Instant::now() < self.deadline && attempts < 128 {
            let mut stream = match self.listener.accept() {
                Ok((stream, address)) if address.ip().is_loopback() => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Ok(_) | Err(_) => return Err(invalid()),
            };
            attempts += 1;
            let code = read_request(&mut stream, self.deadline)
                .and_then(|request| parse_request(&request, &self.host, state));
            let (status, message) = match &code {
                Ok(_) => (
                    "200 OK",
                    "Sign-in received. You may close this tab and return to the terminal.",
                ),
                Err(error) if error.code == "login_cancelled" => (
                    "400 Bad Request",
                    "Sign-in was cancelled. Return to the terminal.",
                ),
                Err(_) => ("400 Bad Request", "This sign-in callback was refused."),
            };
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n\r\n{message}",
                message.len()
            );
            match code {
                Ok(code) => return Ok(code),
                Err(error) if error.code == "login_cancelled" => return Err(error),
                Err(_) => {}
            }
        }
        Err(fail(
            "login_timed_out",
            "Browser sign-in did not complete within its callback budget. Run login again.",
        ))
    }
}

fn read_request(stream: &mut TcpStream, deadline: Instant) -> Result<String> {
    // Accepted sockets can inherit nonblocking mode on macOS. Fragmented browser
    // requests still need to wait within the existing callback deadline.
    stream.set_nonblocking(false).map_err(|_| invalid())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    while bytes.len() < 8_192 && Instant::now() < deadline {
        let mut byte = [0];
        stream.read_exact(&mut byte).map_err(|_| invalid())?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|_| invalid());
        }
    }
    Err(invalid())
}

fn parse_request(request: &str, host: &str, state: &Secret) -> Result<Secret> {
    let mut lines = request.split("\r\n");
    let first = lines.next().ok_or_else(invalid)?;
    let words: Vec<_> = first.split(' ').collect();
    let ["GET", target, "HTTP/1.1"] = words.as_slice() else {
        return Err(invalid());
    };
    if !target.starts_with("/oauth/callback?") || target.contains('#') {
        return Err(invalid());
    }
    let mut hosts = 0_u8;
    for (index, line) in lines.take_while(|line| !line.is_empty()).enumerate() {
        if index >= 32 {
            return Err(invalid());
        }
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.eq_ignore_ascii_case("host") {
            if value.trim() != host {
                return Err(invalid());
            }
            hosts = hosts.checked_add(1).ok_or_else(invalid)?;
        } else if name.eq_ignore_ascii_case("origin")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err(invalid());
        }
    }
    if hosts != 1 {
        return Err(invalid());
    }
    let query = target
        .strip_prefix("/oauth/callback?")
        .ok_or_else(invalid)?;
    let mut fields = BTreeMap::new();
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        if !matches!(
            name.as_ref(),
            "state"
                | "code"
                | "error"
                | "error_description"
                | "error_uri"
                | "scope"
                | "authuser"
                | "hd"
                | "prompt"
        ) || fields
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(invalid());
        }
    }
    if fields.get("state") != Some(&state.0) {
        return Err(invalid());
    }
    if fields.contains_key("error") && !fields.contains_key("code") {
        return Err(fail(
            "login_cancelled",
            "Browser sign-in was refused or cancelled.",
        ));
    }
    if fields.contains_key("error")
        || fields.contains_key("error_description")
        || fields.contains_key("error_uri")
    {
        return Err(invalid());
    }
    let code = fields.remove("code").ok_or_else(invalid)?;
    if !(8..=4_096).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid());
    }
    Ok(Secret(code))
}

pub(super) fn open(url: &str, manual: bool) -> Result<()> {
    if manual {
        eprintln!("Open this URL in a browser on this machine:\n{url}");
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    let executable = "/usr/bin/open";
    #[cfg(target_os = "linux")]
    let executable = "/usr/bin/xdg-open";
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Err(fail(
        "browser_unavailable",
        "Use --no-browser to open the sign-in URL manually on this machine.",
    ));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let failure = || {
            fail(
                "browser_unavailable",
                "Could not open the system browser. Run login --no-browser to open the URL manually on this machine.",
            )
        };
        let mut child = Command::new(executable)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| failure())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().map_err(|_| failure())? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(failure())
                };
            }
            thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
        Err(failure())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_checks_state_host_method_path_and_duplicates() {
        let state = Secret("synthetic-state".into());
        let host = "127.0.0.1:12345";
        let valid = "GET /oauth/callback?state=synthetic-state&code=example-code HTTP/1.1\r\nHost: 127.0.0.1:12345\r\n\r\n";
        assert_eq!(
            parse_request(valid, host, &state).unwrap().0,
            "example-code"
        );
        for request in [
            valid.replace("synthetic-state", "wrong"),
            valid.replace("Host: 127.0.0.1:12345", "Host: attacker.example"),
            valid.replace("GET ", "POST "),
            valid.replace("/oauth/callback?", "/other?"),
            valid.replace(
                "&code=example-code",
                "&code=example-code&state=synthetic-state",
            ),
            valid.replace("&code=example-code", "&code=example-code&code=other-code"),
            valid.replace("\r\n\r\n", "\r\nOrigin: https://attacker.example\r\n\r\n"),
            valid.replace("\r\n\r\n", "\r\nHost: 127.0.0.1:12345\r\n\r\n"),
        ] {
            assert!(parse_request(&request, host, &state).is_err());
        }
    }

    #[test]
    fn actual_loopback_rejects_wrong_state_then_accepts_one_valid_callback() {
        let callback = Callback::bind(Duration::from_secs(3)).unwrap();
        let host = callback.host.clone();
        let sender = thread::spawn(move || {
            for state in ["wrong", "expected"] {
                let mut stream = TcpStream::connect(&host).unwrap();
                write!(
                    stream,
                    "GET /oauth/callback?state={state}&code=example-code HTTP/1.1\r\n"
                )
                .unwrap();
                thread::sleep(Duration::from_millis(75));
                write!(stream, "Host: {host}\r\n\r\n").unwrap();
                let mut response = String::new();
                stream.read_to_string(&mut response).unwrap();
                assert!(!response.contains("example-code"));
                assert!(!response.contains(state));
            }
        });
        assert_eq!(
            callback.receive(&Secret("expected".into())).unwrap().0,
            "example-code"
        );
        sender.join().unwrap();
    }
}

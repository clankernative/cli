use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{self, Read},
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: u64 = 1_048_576;

#[derive(Args)]
struct Context {
    /// Private instance.json for this installation and environment
    #[arg(long)]
    instance: PathBuf,
    /// Absolute path to the trusted platform distribution's day2 executable
    #[arg(long)]
    platform_cli: PathBuf,
    /// Trusted local operator listed in instance.control.operators; not remote login
    #[arg(long)]
    operator: String,
}

#[derive(Args)]
pub(super) struct List {
    app: String,
    #[command(flatten)]
    context: Context,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum, PartialEq, Eq, PartialOrd, Ord)]
enum Permission {
    #[value(name = "audit.read")]
    #[serde(rename = "audit.read")]
    AuditRead,
    #[value(name = "secrets.list")]
    #[serde(rename = "secrets.list")]
    SecretsList,
    #[value(name = "secrets.read")]
    #[serde(rename = "secrets.read")]
    SecretsRead,
    #[value(name = "sqlite.download")]
    #[serde(rename = "sqlite.download")]
    SqliteDownload,
}

#[derive(Args)]
pub(super) struct Check {
    app: String,
    /// Actor to assess; a diagnostic identity, not authentication
    actor: String,
    #[arg(long, value_enum)]
    permission: Permission,
    #[command(flatten)]
    context: Context,
}

#[derive(Args)]
pub(super) struct Change {
    app: String,
    /// Exact individual principal; no group, domain or service selectors
    owner: String,
    /// Exact stamp JSON returned by owners list
    #[arg(long)]
    expected: String,
    /// Stable identity for this change; reuse unchanged after an unknown outcome
    #[arg(long)]
    request_id: String,
    #[command(flatten)]
    context: Context,
}

#[derive(Subcommand)]
pub(super) enum Command {
    /// Show active owners, desired owners and current authority stamp
    List(List),
    /// Check an owner permission; exits 3 if denied, performs no protected read
    Check(Check),
    /// Add an active owner immediately; does not edit desired configuration
    Add(Change),
    /// Remove an active owner immediately; refuses removal of the last owner
    Remove(Change),
}

#[derive(Debug)]
pub(super) struct Failure {
    pub(super) exit_code: u8,
    pub(super) code: &'static str,
    pub(super) message: String,
}

fn failure(exit_code: u8, code: &'static str, message: impl Into<String>) -> Failure {
    Failure {
        exit_code,
        code,
        message: message.into(),
    }
}

fn invalid(message: &str) -> Failure {
    failure(2, "invalid_owner_arguments", message)
}

fn protocol_error() -> Failure {
    failure(
        5,
        "invalid_platform_response",
        "Platform owner response did not match the requested operation. Check the selected distribution version. A dispatched change may have committed; inspect owners and reuse the original request ID and arguments.",
    )
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Stamp {
    epoch: String,
    revision: u64,
}

impl Stamp {
    fn valid(&self) -> bool {
        self.epoch.strip_prefix("sha256:").is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) && i64::try_from(self.revision).is_ok_and(|revision| revision > 0)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    protocol: u32,
    kind: String,
    scope: String,
    app: String,
    action: String,
    mode: String,
    result: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspection {
    stamp: Stamp,
    enabled: bool,
    owners: BTreeSet<String>,
    desired_owners: BTreeSet<String>,
    desired_matches_active: bool,
    permissions: Vec<Permission>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckResult {
    actor: String,
    permission: Permission,
    allowed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    stamp: Stamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeResult {
    owner: String,
    request_id: String,
    expected: Stamp,
    receipt: Receipt,
    desired_config_changed: bool,
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn request(command: &Command) -> Result<(&Context, &str, &'static str, Value), Failure> {
    let (context, app, action, input) = match command {
        Command::List(args) => (&args.context, args.app.as_str(), "list", json!({})),
        Command::Check(args) => {
            if !label(&args.actor) {
                return Err(invalid("Actor must be an exact, bounded principal."));
            }
            (
                &args.context,
                args.app.as_str(),
                "check",
                json!({"actor":args.actor,"permission":args.permission}),
            )
        }
        Command::Add(args) | Command::Remove(args) => {
            if !label(&args.owner)
                || args.owner.contains(':')
                || args.owner.starts_with("client/")
                || args.owner.ends_with(".gserviceaccount.com")
            {
                return Err(invalid(
                    "Owner must be an individual principal, without group, domain or service selectors.",
                ));
            }
            if args.request_id.is_empty()
                || args.request_id.len() > 128
                || !args
                    .request_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            {
                return Err(invalid(
                    "Request ID must contain 1–128 letters, digits, dots, dashes or underscores.",
                ));
            }
            let expected: Stamp = serde_json::from_str(&args.expected).map_err(|_| {
                invalid("Expected stamp must be exact epoch/revision JSON from owners list.")
            })?;
            if !expected.valid() {
                return Err(invalid(
                    "Expected authority stamp has an invalid epoch or revision.",
                ));
            }
            let action = if matches!(command, Command::Add(_)) {
                "add"
            } else {
                "remove"
            };
            (
                &args.context,
                args.app.as_str(),
                action,
                json!({"owner":args.owner,"expected":expected,"request_id":args.request_id}),
            )
        }
    };
    if app.is_empty()
        || app.len() > 48
        || !app.as_bytes()[0].is_ascii_lowercase()
        || !app
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
    {
        return Err(invalid(
            "App must be a lowercase identifier of at most 48 bytes.",
        ));
    }
    if !label(&context.operator) {
        return Err(invalid("Select an exact local operator principal."));
    }
    if !context.platform_cli.is_absolute() {
        return Err(invalid(
            "--platform-cli must be an absolute path to the trusted platform day2 executable.",
        ));
    }
    Ok((context, app, action, input))
}

struct Running {
    child: Child,
    armed: bool,
}

#[cfg(unix)]
struct Interrupt {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handlers: Vec<signal_hook::SigId>,
}

#[cfg(unix)]
impl Interrupt {
    fn install() -> Result<Self, Failure> {
        let mut handler = Self {
            cancelled: std::sync::Arc::default(),
            handlers: Vec::new(),
        };
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            handler.handlers.push(
                signal_hook::flag::register(signal, handler.cancelled.clone()).map_err(|_| {
                    failure(
                        3,
                        "platform_unavailable",
                        "Cannot install local command cancellation handlers.",
                    )
                })?,
            );
        }
        Ok(handler)
    }
}

#[cfg(unix)]
impl Drop for Interrupt {
    fn drop(&mut self) {
        for handler in &self.handlers {
            signal_hook::low_level::unregister(*handler);
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        #[cfg(unix)]
        if let Ok(id) = i32::try_from(self.child.id()) {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(id),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bounded(mut reader: impl Read, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    let count = u64::try_from(bytes.len())
        .map_err(|_| io::Error::other("platform output exceeded byte budget"))?;
    if count > limit {
        return Err(io::Error::other("platform output exceeded byte budget"));
    }
    Ok(bytes)
}

fn execute(context: &Context, app: &str, action: &str, input: &Value) -> Result<Vec<u8>, Failure> {
    let instance = context.instance.canonicalize().map_err(|_| {
        failure(
            3,
            "instance_unavailable",
            "Cannot resolve the selected instance file.",
        )
    })?;
    if !instance.is_file() {
        return Err(invalid("Select an existing instance.json file."));
    }
    #[cfg(unix)]
    let interrupt = Interrupt::install()?;
    let mut process = Process::new(&context.platform_cli);
    process
        .args(["platform", "owners", action])
        .arg(instance)
        .arg(app)
        .arg(&context.operator)
        .arg(input.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        process.process_group(0);
    }
    let mut child = Running {
        child: process.spawn().map_err(|_| {
            failure(
                3,
                "platform_unavailable",
                "Cannot launch the selected platform CLI.",
            )
        })?,
        armed: true,
    };
    let stdout = child.child.stdout.take().ok_or_else(protocol_error)?;
    let stderr = child.child.stderr.take().ok_or_else(protocol_error)?;
    let (send, receive) = mpsc::channel();
    let readers: [(u8, Box<dyn Read + Send>, u64); 2] = [
        (0, Box::new(stdout), OUTPUT_LIMIT),
        (1, Box::new(stderr), 65_536),
    ];
    for (kind, reader, limit) in readers {
        let send = send.clone();
        thread::spawn(move || {
            let _ = send.send((kind, bounded(reader, limit)));
        });
    }
    drop(send);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut output = None;
    let mut streams = 0;
    let mut status = None;
    loop {
        #[cfg(unix)]
        if interrupt
            .cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(failure(
                130,
                "platform_interrupted",
                "Owner operation was interrupted and may have committed. Inspect owners and reuse the original request ID and arguments after an uncertain change.",
            ));
        }
        while let Ok((kind, result)) = receive.try_recv() {
            let bytes = result.map_err(|_| failure(5,"platform_output_limit","Platform output failed or exceeded its byte budget. A dispatched change may have committed; inspect owners before reusing the original request."))?;
            if kind == 0 {
                output = Some(bytes);
            }
            streams += 1;
        }
        if status.is_none() {
            status = child.child.try_wait().map_err(|_| failure(5,"platform_process_failed","Cannot observe the platform process. A dispatched change may have committed; inspect owners before reusing the original request."))?;
        }
        if let Some(status) = status.filter(|_| streams == 2) {
            child.armed = false;
            if !status.success() {
                return Err(failure(
                    3,
                    "platform_rejected",
                    "The platform rejected the owner operation. Check operator authorization, the current stamp, last-owner protection and distribution version. Reuse the original request ID and arguments if the outcome is uncertain.",
                ));
            }
            return output.ok_or_else(protocol_error);
        }
        if Instant::now() >= deadline {
            return Err(failure(
                5,
                "platform_timeout",
                "Platform owner operation exceeded 30 seconds. It may have committed; inspect owners and retry only with the original request ID and arguments.",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn validate(
    command: &Command,
    app: &str,
    action: &str,
    input: &Value,
    raw: &[u8],
) -> Result<(Value, String), Failure> {
    let response: Response = serde_json::from_slice(raw).map_err(|_| protocol_error())?;
    if response.protocol != 1
        || response.kind != "app-owners"
        || response.app != app
        || response.action != action
        || response.mode != "local-operator-only"
        || !label(&response.scope)
        || response.scope.split('/').count() != 3
        || !response.scope.ends_with(&format!("/{app}"))
    {
        return Err(protocol_error());
    }
    let text = match command {
        Command::List(_) => {
            let result: Inspection =
                serde_json::from_str(response.result.get()).map_err(|_| protocol_error())?;
            let permissions: BTreeSet<_> = result.permissions.iter().copied().collect();
            if !result.stamp.valid()
                || result.owners.len() > 512
                || result.desired_owners.len() > 512
                || !result
                    .owners
                    .iter()
                    .chain(&result.desired_owners)
                    .all(|owner| label(owner))
                || result.desired_matches_active != (result.owners == result.desired_owners)
                || result.permissions.len() != 4
                || permissions.len() != 4
            {
                return Err(protocol_error());
            }
            format!(
                "App: {}\nScope: {}\nEnabled: {}\nActive owners: {}\nStamp: {}\nDesired owners: {}\nDesired matches active: {}\n",
                app,
                response.scope,
                result.enabled,
                result.owners.into_iter().collect::<Vec<_>>().join(", "),
                serde_json::to_string(&result.stamp).map_err(|_| protocol_error())?,
                result
                    .desired_owners
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", "),
                result.desired_matches_active
            )
        }
        Command::Check(args) => {
            let result: CheckResult =
                serde_json::from_str(response.result.get()).map_err(|_| protocol_error())?;
            if result.actor != args.actor || result.permission != args.permission {
                return Err(protocol_error());
            }
            if !result.allowed {
                return Err(failure(
                    3,
                    "owner_permission_denied",
                    "The actor is not an enabled app's current owner for this permission.",
                ));
            }
            format!(
                "Allowed: {} on {} for {}. No secret or snapshot was read.\n",
                input["permission"], app, args.actor
            )
        }
        Command::Add(args) | Command::Remove(args) => {
            let result: ChangeResult =
                serde_json::from_str(response.result.get()).map_err(|_| protocol_error())?;
            if result.owner != args.owner
                || result.request_id != args.request_id
                || serde_json::to_value(&result.expected).map_err(|_| protocol_error())?
                    != input["expected"]
                || !result.receipt.stamp.valid()
                || result.receipt.stamp.epoch != result.expected.epoch
                || result.expected.revision.checked_add(1) != Some(result.receipt.stamp.revision)
                || result.desired_config_changed
            {
                return Err(protocol_error());
            }
            format!(
                "Owner {action} receipt for {app}: {}\nStamp: {}\nDesired configuration was not changed. Reconcile the private instance source before a full policy apply.\n",
                result.owner,
                serde_json::to_string(&result.receipt.stamp).map_err(|_| protocol_error())?
            )
        }
    };
    Ok((
        json!({"scope":response.scope,"app":response.app,"action":response.action,"mode":response.mode,"result":response.result}),
        text,
    ))
}

pub(super) fn run(command: &Command) -> Result<(Value, String), Failure> {
    let (context, app, action, input) = request(command)?;
    let raw = execute(context, app, action, &input)?;
    validate(command, app, action, &input, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> Context {
        Context {
            instance: "/private/instance.json".into(),
            platform_cli: "/trusted/platform/day2".into(),
            operator: "operator@example.com".into(),
        }
    }

    fn stamp(revision: u64) -> Value {
        json!({"epoch":format!("sha256:{}","a".repeat(64)),"revision":revision})
    }

    fn response(action: &str, result: &Value) -> Value {
        json!({"protocol":1,"kind":"app-owners","scope":"acme/dev/reports","app":"reports","action":action,"mode":"local-operator-only","result":result})
    }

    #[test]
    fn authority_revisions_require_positive_sqlite_integer_bounds() {
        let max = u64::try_from(i64::MAX).unwrap();
        for (revision, valid) in [
            (0, false),
            (1, true),
            (max, true),
            (max + 1, false),
            (u64::MAX, false),
        ] {
            let stamp: Stamp = serde_json::from_value(stamp(revision)).unwrap();
            assert_eq!(stamp.valid(), valid, "revision {revision}");
        }
    }

    #[test]
    fn owner_receipts_bind_request_identity_and_exact_authority_transition() {
        let command = Command::Add(Change {
            app: "reports".into(),
            owner: "owner@example.com".into(),
            expected: stamp(7).to_string(),
            request_id: "owner-request-1".into(),
            context: context(),
        });
        let (_, app, action, input) = request(&command).unwrap();
        let good = response(
            "add",
            &json!({"owner":"owner@example.com","request_id":"owner-request-1","expected":stamp(7),"receipt":{"stamp":stamp(8)},"desired_config_changed":false}),
        );
        assert!(
            validate(
                &command,
                app,
                action,
                &input,
                &serde_json::to_vec(&good).unwrap()
            )
            .is_ok()
        );
        for (field, value) in [
            ("app", json!("other")),
            ("action", json!("remove")),
            ("protocol", json!(2)),
            ("mode", json!("remote")),
            ("scope", json!("acme/dev/other")),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(
                validate(
                    &command,
                    app,
                    action,
                    &input,
                    &serde_json::to_vec(&bad).unwrap()
                )
                .is_err()
            );
        }
        for (field, value) in [
            ("owner", json!("someone-else")),
            ("request_id", json!("other-request")),
            ("expected", stamp(6)),
            ("receipt", json!({"stamp":stamp(9)})),
            ("desired_config_changed", json!(true)),
        ] {
            let mut bad = good.clone();
            bad["result"][field] = value;
            assert!(
                validate(
                    &command,
                    app,
                    action,
                    &input,
                    &serde_json::to_vec(&bad).unwrap()
                )
                .is_err()
            );
        }
        let duplicate = good.to_string().replace(
            "\"request_id\":\"owner-request-1\"",
            "\"request_id\":\"other\",\"request_id\":\"owner-request-1\"",
        );
        assert!(validate(&command, app, action, &input, duplicate.as_bytes()).is_err());
    }

    #[test]
    fn denied_checks_and_malformed_authority_never_report_success() {
        let command = Command::Check(Check {
            app: "reports".into(),
            actor: "person@example.com".into(),
            permission: Permission::SecretsRead,
            context: context(),
        });
        let (_, app, action, input) = request(&command).unwrap();
        let denied = response(
            "check",
            &json!({"actor":"person@example.com","permission":"secrets.read","allowed":false}),
        );
        let failure = validate(
            &command,
            app,
            action,
            &input,
            &serde_json::to_vec(&denied).unwrap(),
        )
        .unwrap_err();
        assert_eq!(failure.code, "owner_permission_denied");
        assert_eq!(failure.exit_code, 3);
        let mut wrong = denied;
        wrong["result"]["allowed"] = json!(true);
        wrong["result"]["actor"] = json!("other");
        assert!(
            validate(
                &command,
                app,
                action,
                &input,
                &serde_json::to_vec(&wrong).unwrap()
            )
            .is_err()
        );
        let list = Command::List(List {
            app: "reports".into(),
            context: context(),
        });
        let (_, app, action, input) = request(&list).unwrap();
        let mut result = response(
            "list",
            &json!({"stamp":stamp(7),"enabled":true,"owners":["owner"],"desired_owners":[],"desired_matches_active":false,"permissions":["audit.read","secrets.list","secrets.read","sqlite.download"]}),
        );
        assert!(
            validate(
                &list,
                app,
                action,
                &input,
                &serde_json::to_vec(&result).unwrap()
            )
            .is_ok()
        );
        result["result"]["desired_matches_active"] = json!(true);
        assert!(
            validate(
                &list,
                app,
                action,
                &input,
                &serde_json::to_vec(&result).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_output_rejects_overflow_and_bad_requests_fail_before_launch() {
        assert!(bounded(io::Cursor::new(vec![0; 33]), 32).is_err());
        assert_eq!(bounded(io::Cursor::new(vec![0; 32]), 32).unwrap().len(), 32);
        let managed_client = format!("client/client_keys/{}", "a".repeat(64));
        for owner in [
            "domain:example.com",
            "svc:worker",
            "group:owners@example.com",
            "x@project.iam.gserviceaccount.com",
            &managed_client,
            "client/",
            "client/client_keys/not-a-stable-id",
        ] {
            let command = Command::Add(Change {
                app: "reports".into(),
                owner: owner.into(),
                expected: stamp(7).to_string(),
                request_id: "test".into(),
                context: context(),
            });
            assert_eq!(run(&command).unwrap_err().code, "invalid_owner_arguments");
        }
        let command = Command::Add(Change {
            app: "reports".into(),
            owner: "owner@example.com".into(),
            expected: stamp(7).to_string().replace("7}", "7,\"revision\":7}"),
            request_id: "test".into(),
            context: context(),
        });
        assert!(request(&command).is_err());
    }
}

//! App-scoped metadata and one-shot secret writes; payloads never enter output.
use super::{Failure, auth, owners::Stamp};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write as _;
use std::{
    collections::BTreeSet,
    io::{IsTerminal as _, Read as _},
    path::PathBuf,
};
use zeroize::Zeroizing;

const PATH: &str = "/api/app-secrets";

#[derive(Args)]
pub(super) struct AppContext {
    app: String,
    #[command(flatten)]
    auth: auth::Context,
}

#[derive(Args)]
pub(super) struct Mutation {
    #[command(flatten)]
    context: AppContext,
    /// Logical secret name within the app's approved namespace
    name: String,
    /// Read the exact value from stdin, including any trailing newline
    #[arg(long, conflicts_with = "file", required_unless_present = "file")]
    stdin: bool,
    /// Read a regular file containing the exact value (maximum 64 KiB)
    #[arg(long, conflicts_with = "stdin", required_unless_present = "stdin")]
    file: Option<PathBuf>,
    /// Stable identity for this single submission; inspect status after uncertainty
    #[arg(long)]
    request_id: String,
    /// Required for rotate: the listed stored version, or 'none' for an empty container
    #[arg(long)]
    expected_version: Option<String>,
}

#[derive(Args)]
pub(super) struct Status {
    #[command(flatten)]
    context: AppContext,
    request_id: String,
}

#[derive(Subcommand)]
pub(super) enum Command {
    /// List managed secret metadata, without fetching values
    List(AppContext),
    /// Create an app secret and its first stored value
    Create(Mutation),
    /// Store a replacement value as a new version; app activation is separate
    Rotate(Mutation),
    /// Inspect a submitted write without resubmitting its value
    Status(Status),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    container_created: bool,
    version: Option<u64>,
    blocked: bool,
    request_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    protocol: u32,
    kind: String,
    scope: String,
    actor: String,
    authority: Stamp,
    secrets: Vec<Entry>,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Create,
    Rotate,
}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum State {
    Admitted,
    ContainerDispatched,
    ContainerCreated,
    VersionDispatched,
    Stored,
    Refused,
    Unknown,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    protocol: u32,
    kind: String,
    scope: String,
    actor: String,
    name: String,
    operation: Operation,
    request_id: String,
    authority: Stamp,
    state: State,
    version: Option<u64>,
    activation_performed: bool,
}

fn invalid() -> Failure {
    Failure { exit_code: 2, code: "invalid_secret_arguments", message: "Select an app, bounded secret name, value source and unique request ID. Rotate also requires --expected-version; create does not accept it.".into() }
}
fn protocol() -> Failure {
    Failure { exit_code: 5, code: "invalid_secret_response", message: "The platform secret response was refused. Inspect the request status before another mutation.".into() }
}

pub(super) fn request_id(id: &str) -> bool {
    !id.is_empty()
        && id != "."
        && id != ".."
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

fn context(context: &AppContext) -> Result<(), Failure> {
    let app = &context.app;
    if app.is_empty()
        || app.len() > 48
        || !app.as_bytes()[0].is_ascii_lowercase()
        || !app
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        || app.starts_with("day2_")
        || app.starts_with("sqlite_")
    {
        return Err(invalid());
    }
    Ok(())
}

fn version(value: u64) -> bool {
    i64::try_from(value).is_ok_and(|value| value > 0)
}

fn listing(client: &auth::AppClient, app: &str) -> Result<Listing, Failure> {
    let listing: Listing = client.get(PATH)?;
    let names: BTreeSet<_> = listing
        .secrets
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    if listing.protocol != 1
        || listing.kind != "app-secrets"
        || listing.scope != client.scope(app)
        || listing.actor != client.actor()
        || !listing.authority.valid()
        || listing.secrets.len() > 128
        || names.len() != listing.secrets.len()
        || listing.secrets.iter().any(|entry| {
            !name(&entry.name)
                || !request_id(&entry.request_id)
                || entry.version.is_some_and(|v| !version(v))
                || (!entry.container_created && entry.version.is_some())
        })
    {
        return Err(protocol());
    }
    Ok(listing)
}

fn valid_receipt(receipt: &Receipt, client: &auth::AppClient, app: &str) -> bool {
    receipt.protocol == 1
        && receipt.kind == "app-secret-write"
        && receipt.scope == client.scope(app)
        && name(&receipt.name)
        && request_id(&receipt.request_id)
        && receipt.authority.valid()
        && !receipt.activation_performed
        && receipt.version.is_none_or(version)
        && (receipt.state == State::Stored) == receipt.version.is_some()
}

fn read_value(input: &Mutation) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut value = Zeroizing::new(Vec::new());
    if let Some(path) = &input.file {
        if !std::fs::symlink_metadata(path)
            .map_err(|_| invalid())?
            .file_type()
            .is_file()
        {
            return Err(invalid());
        }
        let file = std::fs::File::open(path).map_err(|_| invalid())?;
        if !file.metadata().map_err(|_| invalid())?.is_file() {
            return Err(invalid());
        }
        file.take(65_537)
            .read_to_end(&mut value)
            .map_err(|_| invalid())?;
    } else {
        if std::io::stdin().is_terminal() {
            return Err(invalid());
        }
        std::io::stdin()
            .lock()
            .take(65_537)
            .read_to_end(&mut value)
            .map_err(|_| invalid())?;
    }
    if value.is_empty() || value.len() > 65_536 {
        return Err(invalid());
    }
    Ok(value)
}

fn check_state(
    snapshot: &Listing,
    args: &Mutation,
    operation: Operation,
    expected: Option<u64>,
) -> Result<(), Failure> {
    let previous = snapshot
        .secrets
        .iter()
        .find(|entry| entry.name == args.name);
    let allowed = match (operation, previous) {
        (Operation::Create, None) => true,
        (Operation::Create, Some(entry)) => {
            !entry.blocked && !entry.container_created && entry.request_id != args.request_id
        }
        (Operation::Rotate, Some(entry)) => {
            !entry.blocked
                && entry.container_created
                && entry.version == expected
                && entry.request_id != args.request_id
        }
        (Operation::Rotate, None) => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(Failure { exit_code: 3, code: "secret_conflict", message: "Inspect the current secret metadata and request status before supplying a replacement value.".into() })
    }
}

fn list_text(snapshot: &Listing, app: &str) -> String {
    let mut text = format!(
        "{} managed secrets for {app}. Values are not fetched.\n",
        snapshot.secrets.len()
    );
    text.push_str("Name\tStored version\tState\tLast request\n");
    for entry in &snapshot.secrets {
        let version = entry
            .version
            .map_or_else(|| "none".into(), |value| value.to_string());
        let state = if entry.blocked {
            "pending_or_unknown"
        } else if !entry.container_created {
            "not_created"
        } else if entry.version.is_none() {
            "empty"
        } else {
            "stored"
        };
        let _ = writeln!(
            text,
            "{}\t{version}\t{state}\t{}",
            entry.name, entry.request_id
        );
    }
    text.push_str("Stored versions require an explicit release to become active in an app.\n");
    text
}

pub(super) fn run(command: &Command) -> Result<(Value, String), Failure> {
    run_using(command, auth::AppClient::open)
}

#[cfg(test)]
mod tests;

fn expected(command: &Command) -> Result<Option<u64>, Failure> {
    let (args, rotate) = match command {
        Command::Create(args) => (args, false),
        Command::Rotate(args) => (args, true),
        _ => return Ok(None),
    };
    if !name(&args.name)
        || !request_id(&args.request_id)
        || rotate != args.expected_version.is_some()
    {
        return Err(invalid());
    }
    match args.expected_version.as_deref() {
        None | Some("none") => Ok(None),
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|value| version(*value))
            .map(Some)
            .ok_or_else(invalid),
    }
}

fn run_using(
    command: &Command,
    open: impl FnOnce(&auth::Context) -> Result<auth::AppClient, Failure>,
) -> Result<(Value, String), Failure> {
    let selected = match command {
        Command::List(context) => context,
        Command::Status(args) => &args.context,
        Command::Create(args) | Command::Rotate(args) => &args.context,
    };
    context(selected)?;
    if let Command::Status(args) = command {
        if !request_id(&args.request_id) {
            return Err(invalid());
        }
        let client = open(&selected.auth)?;
        let receipt: Receipt = client.get(&format!("{PATH}/requests/{}", args.request_id))?;
        if !valid_receipt(&receipt, &client, &selected.app) || receipt.request_id != args.request_id
        {
            return Err(protocol());
        }
        let text = format!(
            "Request {}: {}\n",
            receipt.request_id,
            serde_json::to_string(&receipt.state).map_err(|_| protocol())?
        );
        return Ok((serde_json::to_value(receipt).map_err(|_| protocol())?, text));
    }
    let operation = match command {
        Command::Create(_) => Some(Operation::Create),
        Command::Rotate(_) => Some(Operation::Rotate),
        _ => None,
    };
    let expected_version = expected(command)?;
    let client = open(&selected.auth)?;
    let snapshot = listing(&client, &selected.app)?;
    if let Command::List(_) = command {
        let text = list_text(&snapshot, &selected.app);
        return Ok((
            serde_json::to_value(snapshot).map_err(|_| protocol())?,
            text,
        ));
    }
    let (Command::Create(args) | Command::Rotate(args), Some(operation)) = (command, operation)
    else {
        return Err(invalid());
    };
    check_state(&snapshot, args, operation, expected_version)?;
    let value = read_value(args)?;
    let encoded = Zeroizing::new(STANDARD.encode(&value));
    // Names/IDs use closed ASCII alphabets; serialize only public metadata.
    let authority = serde_json::to_string(&snapshot.authority).map_err(|_| protocol())?;
    let expected = serde_json::to_string(&expected_version).map_err(|_| protocol())?;
    let operation_json = serde_json::to_string(&operation).map_err(|_| protocol())?;
    let body = format!(
        "{{\"operation\":{operation_json},\"name\":\"{}\",\"expected_authority\":{authority},\"expected_version\":{expected},\"value\":\"{}\"}}",
        args.name,
        encoded.as_str()
    );
    let receipt: Receipt = client.write(&args.request_id, body).map_err(|cause| {
        if matches!(cause.code, "secret_conflict" | "secret_permission_denied") { cause }
        else { Failure { exit_code:5, code:"secret_outcome_unknown", message:format!("Request {} has no confirmed outcome. Inspect app secrets status; do not resubmit the value.",args.request_id) } }
    })?;
    if !valid_receipt(&receipt, &client, &selected.app)
        || receipt.actor != client.actor()
        || receipt.name != args.name
        || receipt.operation != operation
        || receipt.request_id != args.request_id
        || serde_json::to_value(&receipt.authority).map_err(|_| protocol())?
            != serde_json::to_value(&snapshot.authority).map_err(|_| protocol())?
        || receipt
            .version
            .zip(expected_version)
            .is_some_and(|(new, old)| new <= old)
    {
        return Err(protocol());
    }
    if receipt.state != State::Stored {
        return Err(Failure {
            exit_code: 5,
            code: "secret_outcome_unknown",
            message: format!(
                "Request {} has no confirmed stored version. Use app secrets status; do not resubmit the value.",
                args.request_id
            ),
        });
    }
    let text = format!(
        "Stored {} version {}. Runtime activation was not performed.\n",
        receipt.name,
        receipt.version.ok_or_else(protocol)?
    );
    Ok((serde_json::to_value(receipt).map_err(|_| protocol())?, text))
}

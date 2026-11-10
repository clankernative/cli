//! Deliberate disclosure destinations and owner-authenticated sensitive requests.
use super::*;
use std::{
    fs::{File, OpenOptions},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
};

#[derive(Args)]
pub(crate) struct Reveal {
    #[command(flatten)]
    context: AppContext,
    name: String,
    /// New private output file; existing files and symlinks are refused
    #[arg(long, conflicts_with = "stdout", required_unless_present = "stdout")]
    output: Option<PathBuf>,
    /// Deliberately send exact secret bytes to stdout; incompatible with --json
    #[arg(long, conflicts_with = "output", required_unless_present = "output")]
    stdout: bool,
    /// Require this exact currently listed stored version
    #[arg(long)]
    version: Option<u64>,
    #[arg(long)]
    request_id: String,
}

#[derive(Args)]
pub(crate) struct Delete {
    #[command(flatten)]
    context: AppContext,
    name: String,
    /// Listed version, or 'none' for an existing empty container
    #[arg(long)]
    expected_version: String,
    #[arg(long)]
    request_id: String,
}

#[derive(Args)]
pub(crate) struct Download {
    #[command(flatten)]
    context: AppContext,
    /// New private SQLite file; no framework credentials or sessions are included
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    request_id: String,
}

#[derive(Subcommand)]
pub(crate) enum Sqlite {
    /// Download a consistent snapshot of admitted business tables as a new SQLite file
    Download(Download),
}

struct Destination {
    file: Option<File>,
    path: Option<PathBuf>,
    complete: bool,
}

impl Destination {
    fn reserve(path: Option<&PathBuf>) -> Result<Self, Failure> {
        let file = path
            .map(|path| {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
            })
            .transpose()
            .map_err(|_| output_failure())?;
        Ok(Self {
            file,
            path: path.cloned(),
            complete: false,
        })
    }

    fn finish(
        mut self,
        bytes: Zeroizing<Vec<u8>>,
        mut metadata: Value,
    ) -> Result<CommandOutput, Failure> {
        let Some(file) = &mut self.file else {
            return Ok(CommandOutput::Bytes(bytes));
        };
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| output_failure())?;
        self.complete = true;
        let path = self.path.as_ref().ok_or_else(output_failure)?;
        metadata["output"] = serde_json::json!(path);
        metadata["bytes"] = serde_json::json!(bytes.len());
        Ok(CommandOutput::Formatted(
            metadata,
            format!("Saved {} bytes to {}.\n", bytes.len(), path.display()),
        ))
    }
}

impl Drop for Destination {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        if let (Some(file), Some(path)) = (&self.file, &self.path) {
            // Remove only the file this command created, never a replacement.
            if let (Ok(opened), Ok(current)) = (file.metadata(), std::fs::symlink_metadata(path))
                && current.is_file()
                && opened.dev() == current.dev()
                && opened.ino() == current.ino()
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

fn output_failure() -> Failure {
    Failure{exit_code:2,code:"private_output_failed",message:"Select a new writable output file. Existing files are never replaced; inspect the destination for a partial file after an I/O failure.".into()}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultMetadata {
    protocol: u32,
    kind: String,
    scope: String,
    actor: String,
    authority: Stamp,
    request_id: String,
    name: Option<String>,
    incarnation: Option<String>,
    version: Option<u64>,
    artifact: Option<String>,
}

fn stamp_equal(a: &Stamp, b: &Stamp) -> bool {
    a.epoch == b.epoch && a.revision == b.revision && a.valid() && b.valid()
}

fn result_metadata(
    raw: &[u8],
    client: &auth::AppClient,
    app: &str,
    id: &str,
    stamp: &Stamp,
) -> Result<ResultMetadata, Failure> {
    let metadata: ResultMetadata = serde_json::from_slice(raw).map_err(|_| protocol())?;
    if metadata.protocol != 1
        || metadata.scope != client.scope(app)
        || metadata.actor != client.actor()
        || metadata.request_id != id
        || !stamp_equal(&metadata.authority, stamp)
    {
        return Err(protocol());
    }
    Ok(metadata)
}

pub(super) fn reveal(args: &Reveal, machine: bool) -> Result<CommandOutput, Failure> {
    if (args.stdout && machine) || args.stdout == args.output.is_some() {
        return Err(invalid());
    }
    reveal_using(args, auth::AppClient::open)
}

fn reveal_using(
    args: &Reveal,
    open: impl FnOnce(&auth::Context) -> Result<auth::AppClient, Failure>,
) -> Result<CommandOutput, Failure> {
    context(&args.context)?;
    if !name(&args.name)
        || !request_id(&args.request_id)
        || args.version.is_some_and(|v| !version(v))
    {
        return Err(invalid());
    }
    let client = open(&args.context.auth)?;
    let snapshot = listing(&client, &args.context.app)?;
    let entry = snapshot
        .secrets
        .iter()
        .find(|e| e.name == args.name && !e.blocked && e.container_created && e.version.is_some())
        .ok_or_else(invalid)?;
    if args.version.is_some_and(|v| Some(v) != entry.version) {
        return Err(invalid());
    }
    let destination = Destination::reserve(args.output.as_ref())?;
    let body=serde_json::json!({"name":entry.name,"incarnation":entry.incarnation,"version":entry.version,"expected_authority":snapshot.authority}).to_string();
    let (bytes, raw) = client.download("/api/app-secrets/reveal", &args.request_id, body)?;
    let meta = result_metadata(
        &raw,
        &client,
        &args.context.app,
        &args.request_id,
        &snapshot.authority,
    )?;
    if meta.kind != "app-secret-value"
        || meta.name.as_deref() != Some(&entry.name)
        || meta.incarnation.as_deref() != Some(&entry.incarnation)
        || meta.version != entry.version
        || meta.artifact.is_some()
    {
        return Err(protocol());
    }
    let metadata = serde_json::from_slice(&raw).map_err(|_| protocol())?;
    destination.finish(bytes, metadata)
}

pub(super) fn delete(args: &Delete) -> Result<CommandOutput, Failure> {
    delete_using(args, auth::AppClient::open)
}

fn delete_using(
    args: &Delete,
    open: impl FnOnce(&auth::Context) -> Result<auth::AppClient, Failure>,
) -> Result<CommandOutput, Failure> {
    context(&args.context)?;
    if !name(&args.name) || !request_id(&args.request_id) {
        return Err(invalid());
    }
    let expected = if args.expected_version == "none" {
        None
    } else {
        Some(
            args.expected_version
                .parse::<u64>()
                .ok()
                .filter(|v| version(*v))
                .ok_or_else(invalid)?,
        )
    };
    let client = open(&args.context.auth)?;
    let snapshot = listing(&client, &args.context.app)?;
    let entry = snapshot
        .secrets
        .iter()
        .find(|e| e.name == args.name && !e.blocked && e.container_created && e.version == expected)
        .ok_or_else(invalid)?;
    let body=serde_json::json!({"operation":"delete","name":entry.name,"expected_authority":snapshot.authority,"expected_version":expected,"expected_incarnation":entry.incarnation}).to_string();
    let receipt: Receipt = client.write(&args.request_id, body).map_err(|cause| {
        if matches!(cause.code,"secret_conflict"|"secret_permission_denied"){cause}else{Failure{exit_code:5,code:"secret_outcome_unknown",message:format!("Deletion request {} has no confirmed outcome. Inspect app secrets status before another mutation.",args.request_id)}}
    })?;
    if !valid_receipt(&receipt, &client, &args.context.app)
        || receipt.actor != client.actor()
        || receipt.operation != Operation::Delete
        || receipt.name != args.name
        || receipt.incarnation != entry.incarnation
        || receipt.request_id != args.request_id
        || !stamp_equal(&receipt.authority, &snapshot.authority)
    {
        return Err(protocol());
    }
    if receipt.state != State::Deleted {
        return Err(Failure {
            exit_code: 5,
            code: "secret_outcome_unknown",
            message: format!(
                "Deletion request {} is not confirmed. Inspect app secrets status before another mutation.",
                args.request_id
            ),
        });
    }
    let text = format!("Deleted {} and its stored versions.\n", args.name);
    Ok(CommandOutput::Formatted(
        serde_json::to_value(receipt).map_err(|_| protocol())?,
        text,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SqliteMetadata {
    protocol: u32,
    kind: String,
    scope: String,
    actor: String,
    authority: Stamp,
    artifact: String,
    maximum_bytes: usize,
}

pub(super) fn sqlite(command: &Sqlite) -> Result<CommandOutput, Failure> {
    let Sqlite::Download(args) = command;
    sqlite_using(args, auth::AppClient::open)
}

fn sqlite_using(
    args: &Download,
    open: impl FnOnce(&auth::Context) -> Result<auth::AppClient, Failure>,
) -> Result<CommandOutput, Failure> {
    context(&args.context)?;
    if !request_id(&args.request_id) {
        return Err(invalid());
    }
    let client = open(&args.context.auth)?;
    let snapshot: SqliteMetadata = client.get("/api/app-sqlite")?;
    if snapshot.protocol != 1
        || snapshot.kind != "app-sqlite"
        || snapshot.scope != client.scope(&args.context.app)
        || snapshot.actor != client.actor()
        || !snapshot.authority.valid()
        || snapshot.maximum_bytes != 16_777_216
        || !snapshot
            .artifact
            .strip_prefix("sha256:")
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
    {
        return Err(protocol());
    }
    let destination = Destination::reserve(Some(&args.output))?;
    let body = serde_json::json!({"expected_authority":snapshot.authority}).to_string();
    let (bytes, raw) = client.download("/api/app-sqlite", &args.request_id, body)?;
    let meta = result_metadata(
        &raw,
        &client,
        &args.context.app,
        &args.request_id,
        &snapshot.authority,
    )?;
    if meta.kind != "app-sqlite"
        || meta.artifact.as_deref() != Some(snapshot.artifact.as_str())
        || meta.name.is_some()
        || meta.version.is_some()
        || meta.incarnation.is_some()
        || !bytes.starts_with(b"SQLite format 3\0")
    {
        return Err(protocol());
    }
    destination.finish(bytes, serde_json::from_slice(&raw).map_err(|_| protocol())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt as _;

    fn args(path: Option<PathBuf>) -> Reveal {
        Reveal {
            context: super::super::tests::context(),
            name: "API_KEY".into(),
            stdout: path.is_none(),
            output: path,
            version: Some(7),
            request_id: "reveal-1".into(),
        }
    }
    fn output_path() -> super::super::tests::File {
        let path = super::super::tests::File::new(b"placeholder");
        std::fs::remove_file(&path.0).unwrap();
        path
    }
    fn metadata() -> Value {
        json!({"protocol":1,"kind":"app-secret-value","scope":"company/production/reports","actor":"employee@company.example","authority":super::super::tests::snapshot()["authority"],"request_id":"reveal-1","name":"API_KEY","incarnation":"0123456789abcdef0123456789abcdef","version":7})
    }
    #[test]
    fn reveal_requires_explicit_destination_and_refuses_json_stdout_before_login() {
        assert_eq!(
            reveal(&args(None), true).err().unwrap().code,
            "invalid_secret_arguments"
        );
        let output = output_path();
        let mut args = args(Some(output.0.clone()));
        args.stdout = true;
        assert_eq!(
            reveal(&args, false).err().unwrap().code,
            "invalid_secret_arguments"
        );
    }
    #[test]
    fn private_files_are_exclusive_and_failed_commands_remove_only_their_own_empty_file() {
        let path = output_path();
        {
            let destination = Destination::reserve(Some(&path.0)).unwrap();
            assert_eq!(
                std::fs::metadata(&path.0).unwrap().permissions().mode() & 0o777,
                0o600
            );
            drop(destination);
        }
        assert!(!path.0.exists());
        {
            let destination = Destination::reserve(Some(&path.0)).unwrap();
            std::fs::remove_file(&path.0).unwrap();
            std::fs::write(&path.0, b"replacement").unwrap();
            drop(destination);
            assert_eq!(std::fs::read(&path.0).unwrap(), b"replacement");
            std::fs::remove_file(&path.0).unwrap();
        }
        std::fs::write(&path.0, b"keep existing").unwrap();
        assert!(Destination::reserve(Some(&path.0)).is_err());
        assert_eq!(std::fs::read(&path.0).unwrap(), b"keep existing");
        let symlink = output_path();
        std::os::unix::fs::symlink(&path.0, &symlink.0).unwrap();
        assert!(Destination::reserve(Some(&symlink.0)).is_err());
    }
    #[test]
    fn disclosure_validates_binding_headers_and_exact_version_before_writing_file() {
        let path = output_path();
        let value = super::super::tests::VALUE;
        let (client, requests) = auth::app_test::download_client(
            vec![(200, super::super::tests::write_snapshot(true).to_string())],
            &metadata(),
            value.to_vec(),
        );
        let output = reveal_using(&args(Some(path.0.clone())), |_| Ok(client)).unwrap();
        let CommandOutput::Formatted(result, text) = output else {
            panic!("file result required")
        };
        assert_eq!(std::fs::read(&path.0).unwrap(), value);
        assert!(!result.to_string().contains(&STANDARD.encode(value)));
        assert!(!text.contains("SYNTHETIC_SECRET"));
        assert_eq!(requests.borrow().len(), 2);
        for field in ["scope", "actor", "name", "request_id", "incarnation"] {
            let path = output_path();
            let mut meta = metadata();
            meta[field] = json!("foreign");
            let (client, requests) = auth::app_test::download_client(
                vec![(200, super::super::tests::write_snapshot(true).to_string())],
                &meta,
                value.to_vec(),
            );
            assert!(reveal_using(&args(Some(path.0.clone())), |_| Ok(client)).is_err());
            assert!(!path.0.exists());
            assert_eq!(requests.borrow().len(), 2);
        }
    }
    #[test]
    fn delete_sends_no_value_and_requires_matching_receipt_without_retries() {
        let args = Delete {
            context: super::super::tests::context(),
            name: "API_KEY".into(),
            expected_version: "7".into(),
            request_id: "request-1".into(),
        };
        let (client, requests) = auth::app_test::client(vec![
            (200, super::super::tests::write_snapshot(true).to_string()),
            (
                200,
                super::super::tests::receipt("delete", None, "deleted").to_string(),
            ),
        ]);
        assert!(delete_using(&args, |_| Ok(client)).is_ok());
        let requests = requests.borrow();
        assert_eq!(requests.len(), 2);
        let body: Value = serde_json::from_str(requests[1].body.as_deref().unwrap()).unwrap();
        assert!(body.get("value").is_none());
        assert_eq!(body["expected_version"], 7);
        assert_eq!(
            body["expected_incarnation"],
            "0123456789abcdef0123456789abcdef"
        );
    }
    #[test]
    fn sqlite_download_checks_artifact_scope_and_header_before_creating_output() {
        let artifact = format!("sha256:{}", "a".repeat(64));
        let meta = json!({"protocol":1,"kind":"app-sqlite","scope":"company/production/reports","actor":"employee@company.example","authority":super::super::tests::snapshot()["authority"],"artifact":artifact,"maximum_bytes":16_777_216});
        let reply = json!({"protocol":1,"kind":"app-sqlite","scope":meta["scope"],"actor":meta["actor"],"authority":meta["authority"],"artifact":meta["artifact"],"request_id":"sqlite-1"});
        for (snapshot_artifact, response_artifact, accepted, request_count) in [
            (artifact.clone(), artifact.clone(), true, 2),
            (
                artifact.clone(),
                format!("sha256:{}", "b".repeat(64)),
                false,
                2,
            ),
            ("a".repeat(64), artifact.clone(), false, 1),
            (
                format!("sha256:{}", "A".repeat(64)),
                artifact.clone(),
                false,
                1,
            ),
            (format!("sha256:{}", "a".repeat(63)), artifact, false, 1),
        ] {
            let path = output_path();
            let args = Download {
                context: super::super::tests::context(),
                output: path.0.clone(),
                request_id: "sqlite-1".into(),
            };
            let mut meta = meta.clone();
            meta["artifact"] = json!(snapshot_artifact);
            let mut reply = reply.clone();
            reply["artifact"] = json!(response_artifact);
            let bytes = b"SQLite format 3\0synthetic fixture".to_vec();
            let (client, requests) = auth::app_test::download_client(
                vec![(200, meta.to_string())],
                &reply,
                bytes.clone(),
            );
            let result = sqlite_using(&args, |_| Ok(client));
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(requests.borrow().len(), request_count);
            if accepted {
                assert_eq!(std::fs::read(&path.0).unwrap(), bytes);
            } else {
                assert!(!path.0.exists());
            }
        }
    }
    #[test]
    fn stdout_contains_exact_bytes_only_after_deliberate_selection() {
        let value = super::super::tests::VALUE;
        let (client, _) = auth::app_test::download_client(
            vec![(200, super::super::tests::write_snapshot(true).to_string())],
            &metadata(),
            value.to_vec(),
        );
        let CommandOutput::Bytes(bytes) = reveal_using(&args(None), |_| Ok(client)).unwrap() else {
            panic!("exact byte output required")
        };
        assert_eq!(bytes.as_slice(), value);
    }

    #[test]
    fn uncertain_deletion_never_retries_or_reports_success() {
        for status in [202, 500] {
            let args = Delete {
                context: super::super::tests::context(),
                name: "API_KEY".into(),
                expected_version: "7".into(),
                request_id: "request-1".into(),
            };
            let (client, requests) = auth::app_test::client(vec![
                (200, super::super::tests::write_snapshot(true).to_string()),
                (
                    status,
                    super::super::tests::receipt("delete", None, "unknown").to_string(),
                ),
            ]);
            let error = delete_using(&args, |_| Ok(client)).err().unwrap();
            assert_eq!(error.exit_code, 5);
            assert_eq!(requests.borrow().len(), 2);
        }
    }
}

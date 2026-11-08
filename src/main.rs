//! Command parsing and text/JSON presentation for app ownership and offline catalogs.

use clap::{CommandFactory as _, Parser, Subcommand, error::ErrorKind};
use day2_cli::{Catalog, Operation, Roadmap};
use serde_json::{Value, json};
use std::{
    env,
    fmt::Write as _,
    io::{self, Write},
    process::ExitCode,
};

#[expect(
    clippy::redundant_pub_crate,
    reason = "Keep owner APIs binary-internal; unreachable_pub rejects the public visibility suggested by this nursery lint."
)]
mod owners;

#[expect(
    clippy::redundant_pub_crate,
    reason = "Keep authentication APIs binary-internal, as required by unreachable_pub."
)]
mod auth;
#[expect(
    clippy::redundant_pub_crate,
    reason = "Secret command adapters remain binary-internal."
)]
mod secrets;

#[expect(
    clippy::redundant_pub_crate,
    reason = "Completion adapters remain binary-internal."
)]
mod completion;

#[derive(Parser)]
#[command(
    version,
    about = "Day 2 CLI — company login, app ownership and command inventory"
)]
#[command(
    after_help = "Login requires company discovery and an IAP-allowlisted desktop OAuth client; see docs/LOGIN.md.\nApp owner commands require an explicitly selected local platform CLI.\nApp secrets and business-data SQLite downloads use owner-authenticated app sessions. Reveal requires a new private output file or explicit --stdout.\nHelp and version use text output; --json/--agent applies to command results and errors."
)]
struct Cli {
    /// Emit one versioned JSON result (also --agent)
    #[arg(long, visible_alias = "agent", global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print an offline shell completion script for the implemented commands
    Completion {
        /// Shell that will load the generated script
        #[arg(value_enum)]
        shell: completion::Shell,
    },
    /// Sign in to a company's Google IAP protected app using your browser
    Login(auth::Login),
    /// Verify your saved identity against the selected app
    Whoami(auth::Context),
    /// Remove local credentials and end the saved app session
    Logout(auth::Context),
    /// Print the authenticated app's generated `OpenAPI` JSON, without an envelope
    Openapi(auth::Context),
    /// Call an admitted app operation or read an invocation; print raw JSON
    Call(auth::Call),
    /// Manage an app through the selected platform installation
    App {
        #[command(subcommand)]
        command: AppCommand,
    },
    /// Browse v1 operations and their proposed Day 2 successors (offline)
    Catalog {
        /// Exact legacy command or namespace, e.g. 'sqlite query' or 'secrets'
        command: Option<String>,
        /// Filter by roadmap phase, e.g. M1
        #[arg(long)]
        phase: Option<String>,
    },
    /// Browse delivery phases, dependencies and acceptance criteria (offline)
    Roadmap {
        /// Phase to inspect, e.g. M1; omit to show every phase
        phase: Option<String>,
    },
}

#[derive(Subcommand)]
enum AppCommand {
    /// Download admitted business tables through an owner-authenticated session
    Sqlite {
        #[command(subcommand)]
        command: secrets::Sqlite,
    },
    /// Manage secret values in this app's approved provider namespace
    Secrets {
        #[command(subcommand)]
        command: secrets::Command,
    },
    /// Inspect or change active app owners as a trusted local operator
    Owners {
        #[command(subcommand)]
        command: owners::Command,
    },
}

#[derive(Debug)]
struct Failure {
    exit_code: u8,
    code: &'static str,
    message: String,
}

impl Failure {
    const fn not_found(message: String) -> Self {
        Self {
            exit_code: 4,
            code: "not_found",
            message,
        }
    }
}

fn phase_id(roadmap: &Roadmap, input: &str) -> Result<String, Failure> {
    roadmap
        .phases
        .iter()
        .find(|phase| phase.id.eq_ignore_ascii_case(input))
        .map(|phase| phase.id.clone())
        .ok_or_else(|| Failure::not_found(format!("Unknown roadmap phase: {input}")))
}

fn catalog_text(operations: &[&Operation], detail: bool) -> String {
    let mut output = String::from(
        "Command use cases → Day 2 delivery status\nimplemented_unqualified requires live company qualification; other successors remain planned.\n\n",
    );
    for operation in operations {
        // Formatting these built-in values into a String cannot fail.
        let _ = writeln!(
            output,
            "{:<32} {:<3} {:<24} {}",
            operation.legacy_command,
            operation.phase,
            operation.implementation_status,
            operation.proposed_command.as_deref().unwrap_or("Omit")
        );
        if detail {
            let _ = write!(
                output,
                "  Behavior: {}\n  Platform: {}\n  Work: {}\n  Boundary: {}\n  Evidence: {}\n\n",
                operation.behavior,
                operation.day2_support,
                operation.required_work,
                operation.safety_contract,
                operation
                    .day2_evidence
                    .first()
                    .map_or("No public platform reference", String::as_str)
            );
        }
    }
    let _ = writeln!(output, "\n{} command spellings shown.", operations.len());
    output
}

enum CommandOutput {
    Formatted(Value, String),
    Raw(String, u8),
    Bytes(zeroize::Zeroizing<Vec<u8>>),
}

impl From<(Value, String)> for CommandOutput {
    fn from((value, text): (Value, String)) -> Self {
        Self::Formatted(value, text)
    }
}

fn run(cli: &Cli, catalog: &Catalog, roadmap: &Roadmap) -> Result<CommandOutput, Failure> {
    match &cli.command {
        Command::Completion { shell } => {
            completion::generate(*shell, Cli::command()).map(CommandOutput::from)
        }
        Command::App { command } => run_app(command, cli.json),
        Command::Login(options) => auth::login(options, cli.json).map(CommandOutput::from),
        Command::Whoami(context) => auth::whoami(context).map(CommandOutput::from),
        Command::Logout(context) => auth::logout(context).map(CommandOutput::from),
        Command::Openapi(context) => {
            auth::openapi(context).map(|output| CommandOutput::Raw(output.body, output.exit_code))
        }
        Command::Call(options) => {
            auth::call(options).map(|output| CommandOutput::Raw(output.body, output.exit_code))
        }
        Command::Catalog { command, phase } => {
            let selected_phase = phase
                .as_deref()
                .map(|value| phase_id(roadmap, value))
                .transpose()?;
            let selected_command = command.as_deref().map(str::trim);
            let operations: Vec<_> = catalog
                .operations
                .iter()
                .filter(|operation| {
                    selected_command.is_none_or(|name| {
                        operation.legacy_command == name
                            || operation.legacy_command.starts_with(&format!("{name} "))
                    }) && selected_phase
                        .as_deref()
                        .is_none_or(|id| operation.phase == id)
                })
                .collect();
            if operations.is_empty() {
                return Err(Failure::not_found(
                    "No legacy operations match the selected command and phase.".into(),
                ));
            }
            let text = catalog_text(&operations, selected_command.is_some());
            Ok(CommandOutput::Formatted(
                json!({
                    "audited_on": catalog.audited_on,
                    "platform_source": catalog.platform_source,
                    "definitions": catalog.definitions,
                    "operations": operations
                }),
                text,
            ))
        }
        Command::Roadmap { phase } => {
            let selected_phase = phase
                .as_deref()
                .map(|value| phase_id(roadmap, value))
                .transpose()?;
            let phases: Vec<_> = roadmap
                .phases
                .iter()
                .filter(|phase| selected_phase.as_deref().is_none_or(|id| phase.id == id))
                .collect();
            let mut text = String::from("Day 2 CLI implementation roadmap\n\n");
            for phase in &phases {
                let _ = writeln!(
                    text,
                    "{} — {} [{}]\n  Depends on: {}",
                    phase.id,
                    phase.title,
                    phase.status,
                    if phase.depends_on.is_empty() {
                        "none".into()
                    } else {
                        phase.depends_on.join(", ")
                    }
                );
                for deliverable in &phase.deliverables {
                    let _ = writeln!(text, "  • {deliverable}");
                }
                if selected_phase.is_some() {
                    for work in &phase.platform_work {
                        let _ = writeln!(text, "  Platform work: {work}");
                    }
                    for criterion in &phase.acceptance {
                        let _ = writeln!(text, "  Acceptance: {criterion}");
                    }
                }
                text.push('\n');
            }
            Ok(CommandOutput::Formatted(json!({ "phases": phases }), text))
        }
    }
}

fn envelope(command: &str, result: Option<&Value>, failure: Option<&Failure>) -> Value {
    json!({
        "schema_version": 1,
        "ok": failure.is_none(),
        "command": command,
        "exit_code": failure.map_or(0, |error| error.exit_code),
        "result": result,
        "error": failure.map(|error| json!({"code": error.code, "message": error.message})),
        "next_actions": []
    })
}

fn write_output(output: &str) -> ExitCode {
    match io::stdout().lock().write_all(output.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Could not write output: {error}");
            ExitCode::FAILURE
        }
    }
}

fn emit_failure(command: &str, failure: &Failure, machine: bool) -> ExitCode {
    if machine {
        let output = format!("{}\n", envelope(command, None, Some(failure)));
        let written = write_output(&output);
        if written != ExitCode::SUCCESS {
            return written;
        }
    } else {
        eprintln!("{}: {}", failure.code, failure.message);
    }
    ExitCode::from(failure.exit_code)
}

fn main() -> ExitCode {
    let arguments: Vec<_> = env::args_os().collect();
    let machine = arguments
        .iter()
        .any(|argument| argument == "--json" || argument == "--agent");
    let cli = match Cli::try_parse_from(&arguments) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            return match error.print() {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            };
        }
        Err(error) => {
            return emit_failure(
                "parse",
                &Failure {
                    exit_code: 2,
                    code: "invalid_arguments",
                    message: error.to_string(),
                },
                machine,
            );
        }
    };
    let command = match cli.command {
        Command::Completion { .. } => "completion",
        Command::Login(_) => "login",
        Command::Whoami(_) => "whoami",
        Command::Logout(_) => "logout",
        Command::Openapi(_) => "openapi",
        Command::Call(_) => "call",
        Command::App {
            command: AppCommand::Secrets { .. },
        } => "app secrets",
        Command::App {
            command: AppCommand::Owners { .. },
        } => "app owners",
        Command::App {
            command: AppCommand::Sqlite { .. },
        } => "app sqlite",
        Command::Catalog { .. } => "catalog",
        Command::Roadmap { .. } => "roadmap",
    };
    let data = day2_cli::catalog()
        .and_then(|catalog| day2_cli::roadmap().map(|roadmap| (catalog, roadmap)));
    let (catalog, roadmap) = match data {
        Ok(data) => data,
        Err(error) => {
            return emit_failure(
                command,
                &Failure {
                    exit_code: 1,
                    code: "invalid_embedded_data",
                    message: error.to_string(),
                },
                cli.json,
            );
        }
    };
    match run(&cli, &catalog, &roadmap) {
        Ok(CommandOutput::Bytes(bytes)) => {
            use std::io::Write as _;
            if std::io::stdout().lock().write_all(&bytes).is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Ok(CommandOutput::Raw(body, status)) => {
            let written = write_output(&body);
            if written == ExitCode::SUCCESS {
                ExitCode::from(status)
            } else {
                written
            }
        }
        Ok(CommandOutput::Formatted(result, text)) => {
            if cli.json {
                write_output(&format!("{}\n", envelope(command, Some(&result), None)))
            } else {
                write_output(&text)
            }
        }
        Err(failure) => emit_failure(command, &failure, cli.json),
    }
}

fn run_app(command: &AppCommand, machine: bool) -> Result<CommandOutput, Failure> {
    match command {
        AppCommand::Secrets { command } => secrets::run(command, machine),
        AppCommand::Sqlite { command } => secrets::sqlite(command),
        AppCommand::Owners { command } => {
            owners::run(command)
                .map(CommandOutput::from)
                .map_err(|failure| Failure {
                    exit_code: failure.exit_code,
                    code: failure.code,
                    message: failure.message,
                })
        }
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn complete_parser_has_unique_arguments_and_groups() {
        Cli::command().debug_assert();
    }
}

//! Offline completion uses the executable's single command definition.

use super::Failure;
use clap::{Command, ValueEnum};
use serde_json::{Value, json};

#[derive(Clone, Copy, ValueEnum)]
pub(super) enum Shell {
    Bash,
    Zsh,
    Fish,
}

pub(super) fn generate(shell: Shell, mut command: Command) -> Result<(Value, String), Failure> {
    let (name, generator) = match shell {
        Shell::Bash => ("bash", clap_complete::Shell::Bash),
        Shell::Zsh => ("zsh", clap_complete::Shell::Zsh),
        Shell::Fish => ("fish", clap_complete::Shell::Fish),
    };
    // A Vec writer cannot return an I/O error. Generation never loads credentials,
    // starts a process, reads a live catalog or consults a selected app instance.
    let mut bytes = Vec::new();
    clap_complete::generate(generator, &mut command, "day2", &mut bytes);
    let script = String::from_utf8(bytes).map_err(|_| Failure {
        exit_code: 1,
        code: "invalid_completion_output",
        message: "Shell completion generation did not produce valid text.".into(),
    })?;
    Ok((json!({"shell":name,"script":script}), script))
}

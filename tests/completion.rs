//! Shell grammar and actual completion stay separate from the historical catalog.
use serde_json::Value;
use std::io::Write as _;
use std::process::{Command, Stdio};

#[test]
fn generated_scripts_parse_in_supported_shells() {
    for shell in ["bash", "zsh", "fish"] {
        let output = Command::new(env!("CARGO_BIN_EXE_day2"))
            .args(["completion", shell])
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/nonexistent-day2-completion-bus",
            )
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let mut parser = Command::new(shell)
            .args(match shell {
                "zsh" => &["-f", "-n"][..],
                "fish" => &["--no-config", "--no-execute"][..],
                _ => &["--noprofile", "--norc", "-n"][..],
            })
            .env_remove("BASH_ENV")
            .env_remove("ENV")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        parser
            .stdin
            .take()
            .unwrap()
            .write_all(&output.stdout)
            .unwrap();
        let checked = parser.wait_with_output().unwrap();
        assert!(checked.status.success(), "{shell}: {checked:?}");
        let machine = Command::new(env!("CARGO_BIN_EXE_day2"))
            .args(["completion", shell, "--json"])
            .output()
            .unwrap();
        assert!(machine.status.success(), "{machine:?}");
        let value: Value = serde_json::from_slice(&machine.stdout).unwrap();
        assert_eq!(value["command"], "completion");
        assert_eq!(value["result"]["shell"], shell);
        assert_eq!(
            value["result"]["script"],
            String::from_utf8(output.stdout).unwrap()
        );
    }
}

#[test]
fn fish_completes_nested_commands_without_configuration() {
    let generated = Command::new(env!("CARGO_BIN_EXE_day2"))
        .args(["completion", "fish"])
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent-day2-completion-bus",
        )
        .output()
        .unwrap();
    assert!(generated.status.success(), "{generated:?}");
    assert!(generated.stderr.is_empty(), "{generated:?}");
    for (input, required, excluded) in [
        (
            "day2 app ",
            &["owners", "secrets"][..],
            &["prototype", "sqlite", "publish", "snapshot"][..],
        ),
        (
            "day2 app secrets ",
            &["list", "create", "rotate", "status"][..],
            &["reveal", "delete", "activate"][..],
        ),
    ] {
        let mut shell = Command::new("fish")
            .args([
                "--no-config",
                "--command",
                &format!("source -; complete --do-complete='{input}'"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        shell
            .stdin
            .take()
            .unwrap()
            .write_all(&generated.stdout)
            .unwrap();
        let result = shell.wait_with_output().unwrap();
        assert!(result.status.success(), "{input}: {result:?}");
        assert!(result.stderr.is_empty(), "{input}: {result:?}");
        let text = String::from_utf8(result.stdout).unwrap();
        let choices: Vec<_> = text
            .lines()
            .map(|line| line.split('\t').next().unwrap())
            .collect();
        for name in required {
            assert!(choices.contains(name), "{input}: {choices:?}");
        }
        for name in excluded {
            assert!(!choices.contains(name), "{input}: {choices:?}");
        }
    }
}

#[test]
fn bash_completes_implemented_commands_without_historical_placeholders() {
    let generated = Command::new(env!("CARGO_BIN_EXE_day2"))
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let mut shell = Command::new("bash")
        .args(["--noprofile", "--norc", "-c", "source /dev/stdin; COMP_WORDS=(day2 app ''); COMP_CWORD=2; COMP_LINE='day2 app '; COMP_POINT=9; _day2 day2 '' app; printf '%s\\n' \"${COMPREPLY[@]}\""])
        .stdin(Stdio::piped())
        .env_remove("BASH_ENV")
        .env_remove("ENV")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    shell
        .stdin
        .take()
        .unwrap()
        .write_all(&generated.stdout)
        .unwrap();
    let result = shell.wait_with_output().unwrap();
    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    let text = String::from_utf8(result.stdout).unwrap();
    let choices: Vec<_> = text.lines().collect();
    assert!(choices.contains(&"owners"), "{choices:?}");
    assert!(choices.contains(&"secrets"), "{choices:?}");
    for planned in ["prototype", "sqlite", "publish", "snapshot"] {
        assert!(!choices.contains(&planned), "{choices:?}");
    }
}

#[test]
fn secrets_validation_errors_identify_the_secret_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_day2"))
        .args([
            "app",
            "secrets",
            "create",
            "reports",
            "invalid/name",
            "--stdin",
            "--request-id",
            "synthetic-request",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "app secrets");
    assert_eq!(value["error"]["code"], "invalid_secret_arguments");
}

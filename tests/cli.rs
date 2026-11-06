//! Process-level checks of the CLI contract and embedded requirements.

use serde_json::Value;
use std::process::{Command, Output};

#[cfg(test)]
fn day2(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_day2"))
        .args(arguments)
        .output()
        .expect("run day2")
}

#[cfg(test)]
fn document(output: &Output, code: i32) -> Value {
    assert_eq!(output.status.code(), Some(code), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).expect("one JSON document");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["exit_code"], code);
    assert_eq!(value["ok"], code == 0);
    value
}

#[test]
fn catalog_keeps_aliases_and_retirement_distinct() {
    let output = day2(&["catalog", "--json"]);
    let value = document(&output, 0);
    let operations = value["result"]["operations"].as_array().unwrap();
    assert_eq!(operations.len(), 41);
    assert_eq!(
        operations
            .iter()
            .filter(|op| op["legacy_state"] == "active")
            .count(),
        39
    );
    let alerts = operations
        .iter()
        .find(|op| op["legacy_command"] == "alerts")
        .unwrap();
    assert_eq!(alerts["alias_of"], "monitors");
    let metrics = operations
        .iter()
        .find(|op| op["legacy_command"] == "metrics")
        .unwrap();
    assert_eq!(metrics["legacy_state"], "retired");
    assert!(metrics["proposed_command"].is_null());
    assert!(
        operations
            .iter()
            .all(|op| op["implementation_status"] == "planned"
                || op["implementation_status"] == "omitted"
                || op["implementation_status"] == "implemented_unqualified")
    );
    let implemented: Vec<_> = operations
        .iter()
        .filter(|op| op["implementation_status"] == "implemented_unqualified")
        .map(|op| op["legacy_command"].as_str().unwrap())
        .collect();
    assert_eq!(implemented, ["login", "whoami", "logout"]);
}

#[test]
fn login_headless_is_structured_and_never_starts_browser_or_keychain() {
    let output = day2(&[
        "login",
        "--instance",
        "https://tools.company.example",
        "--json",
    ]);
    let value = document(&output, 3);
    assert_eq!(value["command"], "login");
    assert_eq!(value["error"]["code"], "interactive_required");
    let help = day2(&["--help"]);
    let text = String::from_utf8_lossy(&help.stdout);
    for command in ["login", "whoami", "logout"] {
        assert!(text.contains(command));
    }
}

#[test]
fn catalog_excludes_private_audit_metadata() {
    let catalog = day2_cli::catalog().unwrap();
    assert_eq!(catalog.schema_version, 2);
    let serialized = serde_json::to_value(&catalog).unwrap();
    assert!(serialized.get("legacy_source").is_none());
    for operation in serialized["operations"].as_array().unwrap() {
        assert!(operation.get("source").is_none());
        assert!(operation.get("arguments").is_none());
        for reference in operation["day2_evidence"].as_array().unwrap() {
            assert!(
                reference
                    .as_str()
                    .unwrap()
                    .starts_with("https://github.com/clankernative/platform/")
            );
        }
    }
    let output = document(&day2(&["catalog", "--json"]), 0);
    assert!(output["result"].get("legacy_source").is_none());
}

#[test]
fn filters_select_namespaces_exact_commands_and_phases() {
    let output = day2(&["catalog", "sqlite query", "--phase", "m3", "--agent"]);
    let value = document(&output, 0);
    let operations = value["result"]["operations"].as_array().unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["legacy_command"], "sqlite query");
    let output = day2(&["--json", "catalog", "secrets"]);
    let value = document(&output, 0);
    assert_eq!(value["result"]["operations"].as_array().unwrap().len(), 13);
}

#[test]
fn roadmap_has_no_missing_or_forward_dependencies() {
    let roadmap = day2_cli::roadmap().unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for phase in &roadmap.phases {
        assert!(phase.depends_on.iter().all(|id| seen.contains(id)));
        assert!(!phase.acceptance.is_empty());
        assert!(seen.insert(phase.id.clone()));
    }
    for operation in day2_cli::catalog().unwrap().operations {
        assert!(seen.contains(&operation.phase));
    }
    let value = document(&day2(&["roadmap", "M1", "--json"]), 0);
    assert_eq!(value["result"]["phases"].as_array().unwrap().len(), 1);
    assert_eq!(value["result"]["phases"][0]["id"], "M1");
}

#[test]
fn errors_are_structured_and_planned_operations_are_not_executable() {
    for arguments in [
        vec!["catalog", "missing", "--json"],
        vec!["roadmap", "M99", "--json"],
        vec!["catalog", "--phase", "M99", "--json"],
        vec!["catalog", "login", "--phase", "M5", "--json"],
    ] {
        let value = document(&day2(&arguments), 4);
        assert_eq!(value["error"]["code"], "not_found");
        assert!(value["result"].is_null());
    }
    for arguments in [
        vec!["login", "--json"],
        vec!["catalog", "--unknown", "--agent"],
        vec!["--json"],
    ] {
        let value = document(&day2(&arguments), 2);
        assert_eq!(value["error"]["code"], "invalid_arguments");
    }
}

#[test]
fn basic_text_output_explains_scope() {
    let help = day2(&["--help"]);
    assert!(help.status.success());
    assert!(
        String::from_utf8_lossy(&help.stdout)
            .contains("App owner commands require an explicitly selected local platform CLI")
    );
    let version = day2(&["--version"]);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")));
    let catalog = day2(&["catalog"]);
    assert!(catalog.status.success());
    assert!(String::from_utf8_lossy(&catalog.stdout).contains("41 command spellings"));
    let roadmap = day2(&["roadmap"]);
    assert!(roadmap.status.success());
    assert!(String::from_utf8_lossy(&roadmap.stdout).contains("M0"));
}

#[test]
fn owner_commands_require_explicit_local_context_before_any_launch() {
    let output = day2(&["app", "owners", "list", "reports", "--json"]);
    assert_eq!(document(&output, 2)["error"]["code"], "invalid_arguments");
    let output = day2(&[
        "app",
        "owners",
        "add",
        "reports",
        "domain:example.com",
        "--instance",
        "/does/not/exist",
        "--operator",
        "operator@example.com",
        "--platform-cli",
        "/not/a/platform/day2",
        "--expected",
        r#"{"epoch":"invalid","revision":1}"#,
        "--request-id",
        "test",
        "--json",
    ]);
    assert_eq!(
        document(&output, 2)["error"]["code"],
        "invalid_owner_arguments"
    );
    let output = day2(&[
        "app",
        "owners",
        "check",
        "reports",
        "owner@example.com",
        "--permission",
        "secrets.write",
        "--json",
    ]);
    assert_eq!(document(&output, 2)["error"]["code"], "invalid_arguments");
}

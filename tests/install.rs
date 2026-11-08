//! Installer boundaries: verify before writing and preserve existing ownership.
#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf, process::Command};

#[cfg(test)]
struct Fixture {
    root: PathBuf,
}

#[cfg(test)]
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "day2-installer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        for path in ["tools", "payload/day2-cli", "assets"] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        let fixture = Self { root };
        for (name, body) in [
            (
                "uname",
                "case \"$1\" in -s) echo Darwin;; -m) echo arm64;; esac",
            ),
            (
                "curl",
                "echo download >> \"$INSTALL_FIXTURE/network\"\nfor arg do case \"$arg\" in https:*) source=${arg##*/};; esac; done\nwhile [ \"$1\" != -o ]; do shift; done\ncp \"$INSTALL_FIXTURE/assets/$source\" \"$2\"",
            ),
            (
                "gh",
                "echo attest >> \"$INSTALL_FIXTURE/network\"\nbundle=no\nfor arg do if [ \"$arg\" = --bundle ]; then bundle=yes; fi; done\n[ \"$bundle\" = yes ] || exit 4\nexit \"$INSTALL_ATTEST_EXIT\"",
            ),
        ] {
            fixture.script(name, body);
        }
        for (name, contents) in [
            ("day2", "synthetic executable"),
            ("THIRD_PARTY_LICENSES.txt", "dependency notice"),
            ("SOURCE.json", "{}"),
            ("README.md", "install instructions"),
        ] {
            fs::write(fixture.root.join("payload/day2-cli").join(name), contents).unwrap();
        }
        let archive = fixture
            .root
            .join("assets/day2-cli-v0.3.0-aarch64-apple-darwin.tar.gz");
        assert!(
            Command::new("tar")
                .args(["-czf"])
                .arg(&archive)
                .arg("-C")
                .arg(fixture.root.join("payload"))
                .arg("day2-cli")
                .status()
                .unwrap()
                .success()
        );
        fs::write(
            fixture
                .root
                .join("assets/day2-cli-v0.3.0-aarch64-apple-darwin.tar.gz.sigstore.jsonl"),
            "synthetic test bundle",
        )
        .unwrap();
        let digest = Command::new("shasum")
            .args(["-a", "256"])
            .arg(&archive)
            .output()
            .unwrap();
        assert!(digest.status.success());
        let digest = String::from_utf8(digest.stdout).unwrap();
        fs::write(
            fixture.root.join("assets/SHA256SUMS"),
            format!(
                "{}  day2-cli-v0.3.0-aarch64-apple-darwin.tar.gz\n",
                digest.split_whitespace().next().unwrap()
            ),
        )
        .unwrap();
        fixture
    }

    fn script(&self, name: &str, body: &str) {
        let path = self.root.join("tools").join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn install(&self, attest_exit: &str) -> std::process::Output {
        Command::new("sh")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
            .arg("--prefix")
            .arg(self.root.join("bin"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("tools").display()),
            )
            .env("INSTALL_FIXTURE", &self.root)
            .env("INSTALL_ATTEST_EXIT", attest_exit)
            .output()
            .unwrap()
    }
}

#[cfg(test)]
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn installer_preserves_existing_executables_and_dangling_symlinks_before_network() {
    for symlink in [false, true] {
        let fixture = Fixture::new();
        fs::create_dir(fixture.root.join("bin")).unwrap();
        let destination = fixture.root.join("bin/day2");
        if symlink {
            std::os::unix::fs::symlink("missing-platform", &destination).unwrap();
        } else {
            fs::write(&destination, "existing platform executable").unwrap();
        }
        assert!(!fixture.install("0").status.success());
        assert!(!fixture.root.join("network").exists());
        if symlink {
            assert_eq!(
                fs::read_link(destination).unwrap(),
                PathBuf::from("missing-platform")
            );
        } else {
            assert_eq!(
                fs::read_to_string(destination).unwrap(),
                "existing platform executable"
            );
        }
    }
}

#[test]
fn installer_requires_both_checksum_and_provenance_and_retains_notices() {
    for failure in ["checksum", "missing_bundle", "attestation", "none"] {
        let fixture = Fixture::new();
        if failure == "checksum" {
            fs::write(
                fixture.root.join("assets/SHA256SUMS"),
                format!(
                    "{}  day2-cli-v0.3.0-aarch64-apple-darwin.tar.gz\n",
                    "0".repeat(64)
                ),
            )
            .unwrap();
        }
        if failure == "missing_bundle" {
            fs::remove_file(
                fixture
                    .root
                    .join("assets/day2-cli-v0.3.0-aarch64-apple-darwin.tar.gz.sigstore.jsonl"),
            )
            .unwrap();
        }
        let output = fixture.install(if failure == "attestation" { "1" } else { "0" });
        assert_eq!(output.status.success(), failure == "none", "{output:?}");
        assert_eq!(fixture.root.join("bin/day2").exists(), failure == "none");
        if failure == "none" {
            let bundle = fs::read_dir(fixture.root.join("bin"))
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| p.is_dir())
                .unwrap();
            assert_eq!(
                fs::read_to_string(bundle.join("THIRD_PARTY_LICENSES.txt")).unwrap(),
                "dependency notice"
            );
            assert_eq!(
                fs::read_to_string(fixture.root.join("bin/day2")).unwrap(),
                "synthetic executable"
            );
        }
    }
}

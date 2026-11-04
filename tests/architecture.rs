//! Exercise the effect boundary with real compiler diagnostics, including aliases.

use std::{
    fs, io,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

const POLICY: &str = include_str!("../architecture/clippy.toml");
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "day2-cli-architecture-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        // Refuse to reuse a pre-existing directory or symlink.
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    fn check(&self, source: &str) -> io::Result<Output> {
        fs::write(
            self.0.join("Cargo.toml"),
            "[package]\nname = \"boundary-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[lib]\npath = \"lib.rs\"\n[workspace]\n",
        )?;
        fs::write(self.0.join("clippy.toml"), POLICY)?;
        fs::write(self.0.join("lib.rs"), source)?;
        Command::new(env!("CARGO"))
            .current_dir(&self.0)
            .env("CLIPPY_CONF_DIR", &self.0)
            .env("CARGO_TARGET_DIR", self.0.join("target"))
            .args([
                "clippy",
                "--offline",
                "--quiet",
                "--",
                "-Dwarnings",
                "-Funsafe_code",
                "-Fclippy::disallowed_methods",
                "-Fclippy::disallowed_types",
                "-Fclippy::disallowed_macros",
            ])
            .output()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn effect_policy_accepts_pure_data() -> io::Result<()> {
    let output = Fixture::new()?.check("pub const fn identity(value: u64) -> u64 { value }")?;
    assert!(output.status.success(), "{output:?}");
    Ok(())
}

#[test]
fn effect_policy_rejects_ambient_effects_and_suppression() -> io::Result<()> {
    for (source, diagnostic) in [
        (
            "use std::env::var as read; pub fn value() { let _ = read(\"HOME\"); }",
            "disallowed_methods",
        ),
        (
            "pub fn value() { let _ = std::path::Path::new(\".\").exists(); }",
            "disallowed_methods",
        ),
        (
            "use std::time::Instant as Clock; pub fn value() { let _ = Clock::now(); }",
            "disallowed_methods",
        ),
        (
            "use std::process::Command as Process; pub fn value() { let _ = Process::new(\"sh\"); }",
            "disallowed_types",
        ),
        (
            "pub fn value() { let _ = std::fs::read(\"private\"); }",
            "disallowed_methods",
        ),
        (
            "pub fn value() { let _ = std::fs::remove_file(\"private\"); }",
            "disallowed_methods",
        ),
        (
            "pub fn value() { let _ = std::net::TcpStream::connect(\"127.0.0.1:1\"); }",
            "disallowed_types",
        ),
        (
            "pub fn value() { println!(\"private\"); }",
            "disallowed_macros",
        ),
        (
            "pub const VALUE: &str = env!(\"PATH\");",
            "disallowed_macros",
        ),
        (
            "#[allow(clippy::disallowed_methods)] pub fn value() { let _ = std::env::var(\"HOME\"); }",
            "incompatible with previous forbid",
        ),
        (
            "#[expect(clippy::disallowed_methods)] pub fn value() { let _ = std::env::var(\"HOME\"); }",
            "incompatible with previous forbid",
        ),
    ] {
        let output = Fixture::new()?.check(source)?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "admitted {source}");
        assert!(stderr.contains(diagnostic), "{source}\n{stderr}");
    }
    Ok(())
}

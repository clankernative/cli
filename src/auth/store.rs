//! OS credential storage only; no file, environment or plaintext fallback.

use super::{Result, fail};
use std::sync::LazyLock;

const SERVICE: &str = "com.clankernative.day2-cli.v1";

pub(super) trait Store {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn set(&self, key: &str, value: &str) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

pub(super) struct Native;

fn unavailable() -> super::Failure {
    fail(
        "credential_store_unavailable",
        "Unlock the OS credential store (macOS Keychain or Linux Secret Service) and try again. No plaintext fallback is available.",
    )
}

pub(super) fn ready() -> Result<()> {
    static INITIALIZED: LazyLock<keyring_core::Result<()>> = LazyLock::new(initialize);
    INITIALIZED.as_ref().copied().map_err(|_| unavailable())
}

fn initialize() -> keyring_core::Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()?;
    #[cfg(target_os = "linux")]
    let store = dbus_secret_service_keyring_store::Store::new()?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        keyring_core::set_default_store(store);
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    Err(keyring_core::Error::NoDefaultStore)
}

fn entry(key: &str) -> Result<keyring_core::Entry> {
    ready()?;
    keyring_core::Entry::new(SERVICE, key).map_err(|_| unavailable())
}

impl Store for Native {
    fn get(&self, key: &str) -> Result<Option<String>> {
        match entry(key)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(_) => Err(unavailable()),
        }
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        entry(key)?.set_password(value).map_err(|_| unavailable())
    }

    fn delete(&self, key: &str) -> Result<()> {
        match entry(key)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(_) => Err(unavailable()),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::process::Command;

    // This test uses real Secret Service over encrypted D-Bus. Run only in an
    // explicitly prepared disposable login session; never replace a user's store.
    #[test]
    #[ignore = "requires a disposable unlocked Linux Secret Service session"]
    fn native_secret_service_roundtrip() {
        let key = format!("qualification-{}", std::process::id());
        let store = Native;
        let child = |mode: &str| {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "auth::store::tests::native_probe_process",
                    "--test-threads=1",
                ])
                .env("DAY2_CLI_STORE_PROBE", mode)
                .env("DAY2_CLI_STORE_KEY", &key)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "native credential subprocess failed"
            );
        };
        assert!(store.get(&key).unwrap().is_none());
        store.set(&key, "synthetic-native-roundtrip").unwrap();
        child("read-and-rotate");
        assert_eq!(store.get(&key).unwrap().unwrap(), "x".repeat(65_536));
        child("delete");
        assert!(store.get(&key).unwrap().is_none());
        store.delete(&key).unwrap();
        let unavailable = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "auth::store::tests::native_probe_process",
                "--test-threads=1",
            ])
            .env("DAY2_CLI_STORE_PROBE", "unavailable")
            .env("DAY2_CLI_STORE_KEY", &key)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/nonexistent-day2-qualification-bus",
            )
            .output()
            .unwrap();
        assert!(
            unavailable.status.success(),
            "unavailable store must fail closed"
        );
    }

    #[test]
    #[ignore = "subprocess for the native Secret Service qualification"]
    fn native_probe_process() {
        let Ok(mode) = std::env::var("DAY2_CLI_STORE_PROBE") else {
            return;
        };
        let key = std::env::var("DAY2_CLI_STORE_KEY").unwrap();
        let store = Native;
        match mode.as_str() {
            "read-and-rotate" => {
                assert_eq!(
                    store.get(&key).unwrap().unwrap(),
                    "synthetic-native-roundtrip"
                );
                store.set(&key, &"x".repeat(65_536)).unwrap();
            }
            "delete" => {
                assert_eq!(store.get(&key).unwrap().unwrap(), "x".repeat(65_536));
                store.delete(&key).unwrap();
            }
            "unavailable" => {
                assert!(
                    matches!(store.get(&key), Err(error) if error.code == "credential_store_unavailable")
                );
            }
            _ => panic!("unknown native credential test mode"),
        }
    }
}

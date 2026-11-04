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

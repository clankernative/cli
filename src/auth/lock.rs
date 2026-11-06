//! Serialize credential writers so concurrent refresh cannot undo logout.

use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

use super::{Result, fail};

pub(super) struct Guard {
    _file: File,
}

impl Guard {
    pub(super) fn acquire() -> Result<Self> {
        let cache = std::env::var_os("XDG_CACHE_HOME")
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cache"))
            })
            .ok_or_else(unavailable)?;
        Self::at(&cache.join("day2-cli"))
    }

    fn at(directory: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{
                DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
            };
            // Cache parents carry no secrets; only our leaf and lock must be private.
            fs::create_dir_all(directory.parent().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
            match fs::DirBuilder::new().mode(0o700).create(directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(unavailable()),
            }
            let metadata = fs::symlink_metadata(directory).map_err(|_| unavailable())?;
            let user = nix::unistd::Uid::current().as_raw();
            if !metadata.is_dir()
                || metadata.uid() != user
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(unavailable());
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(directory.join("auth.lock"))
                .map_err(|_| unavailable())?;
            let metadata = file.metadata().map_err(|_| unavailable())?;
            if !metadata.is_file()
                || metadata.uid() != user
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(unavailable());
            }
            match file.try_lock() {
                Ok(()) => Ok(Self { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) => Err(fail(
                    "auth_busy",
                    "Another login, identity check or logout is running. Finish it before trying again.",
                )),
                Err(_) => Err(unavailable()),
            }
        }
        #[cfg(not(unix))]
        Err(unavailable())
    }
}

fn unavailable() -> super::Failure {
    fail(
        "auth_lock_unavailable",
        "Could not create a private authentication lock in the user cache directory.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_and_logout_cannot_hold_the_credential_writer_lock_together() {
        let directory = std::env::temp_dir().join(format!(
            "day2-auth-lock-{}-{}",
            std::process::id(),
            super::super::oidc::hash(b"lock-test")
        ));
        // Refuse pre-existing state; never delete another process's directory.
        fs::create_dir(&directory).unwrap();
        let leaf = directory.join("day2-cli");
        let first = Guard::at(&leaf).unwrap();
        assert_eq!(Guard::at(&leaf).err().unwrap().code, "auth_busy");
        drop(first);
        drop(Guard::at(&leaf).unwrap());
        fs::remove_dir_all(directory).unwrap();
    }
}

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use atomic_write_file::AtomicWriteFile;

use crate::error::ConfigError;
use crate::{ConfigSnapshot, to_json5};

/// Loads and validates a UTF-8 JSON5 configuration file.
pub fn load_file(path: impl AsRef<Path>) -> Result<ConfigSnapshot, ConfigError> {
    let path = path.as_ref();
    let source = fs::read_to_string(path).map_err(|error| ConfigError::io(path, error))?;
    crate::parse_json5(&source, &path.display().to_string())
}

/// Atomically writes a validated snapshot in the destination directory.
///
/// The temporary file is flushed and synchronized before replacement. On Unix,
/// existing permissions are preserved and new files are created with mode 0600.
pub fn write_file(path: impl AsRef<Path>, snapshot: &ConfigSnapshot) -> Result<(), ConfigError> {
    let path = path.as_ref();
    let contents = to_json5(snapshot)?;
    atomic_write_bytes(path, contents.as_bytes(), || Ok(()))
        .map_err(|error| ConfigError::io(path, error))
}

fn atomic_write_bytes(
    path: &Path,
    contents: &[u8],
    precommit: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::metadata(parent)?;
    }

    let mut file = AtomicWriteFile::open(path)?;
    set_permissions(path, file.as_file())?;
    file.write_all(contents)?;
    file.flush()?;
    file.sync_all()?;
    precommit()?;
    file.commit()?;
    sync_parent(parent)?;
    Ok(())
}

#[cfg(unix)]
fn set_permissions(path: &Path, file: &fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = match fs::metadata(path) {
        Ok(metadata) => metadata.permissions().mode() & 0o777,
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0o600,
        Err(error) => return Err(error),
    };
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_permissions(_path: &Path, _file: &fs::File) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: Option<&Path>) -> io::Result<()> {
    if let Some(parent) = parent {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_parent: Option<&Path>) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::atomic_write_bytes;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn precommit_failure_preserves_destination() {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "claw-config-unit-test-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).expect("create temporary directory");
        let cleanup = Cleanup(directory.clone());
        let path = directory.join("config.json5");
        std::fs::write(&path, "old").expect("write old file");

        let error = atomic_write_bytes(&path, b"new", || {
            Err(io::Error::other("injected precommit failure"))
        })
        .expect_err("write must fail");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(std::fs::read_to_string(path).expect("read old file"), "old");
        drop(cleanup);
    }

    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

//! Shared temporary-directory scaffolding for the adversarial suites.
//!
//! No external crate is used: the tests create, populate, and destroy a real
//! directory tree under the platform temporary directory. Every destructive
//! operation is confined to that tree.

// Each integration test binary compiles this module and uses a subset of it.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A real temporary directory tree that removes itself on drop.
pub(crate) struct TempTree {
    path: PathBuf,
}

impl TempTree {
    /// Creates a uniquely named tree under the platform temporary directory.
    pub(crate) fn new(label: &str) -> Self {
        let unique = format!(
            "claw-tools-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("temporary tree is creatable");
        let path = fs::canonicalize(&path).expect("temporary tree is canonicalizable");
        Self {
            path: strip_verbatim_prefix(&path),
        }
    }

    /// Returns the canonical tree root.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Joins a `/`-separated relative path onto the tree root.
    pub(crate) fn join(&self, relative: &str) -> PathBuf {
        let mut joined = self.path.clone();
        for component in relative.split('/') {
            joined.push(component);
        }
        joined
    }

    /// Creates a directory, including parents.
    pub(crate) fn dir(&self, relative: &str) -> PathBuf {
        let path = self.join(relative);
        fs::create_dir_all(&path).expect("directory is creatable");
        path
    }

    /// Writes a file, creating parents as needed.
    pub(crate) fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent directory is creatable");
        }
        fs::write(&path, contents).expect("file is writable");
        path
    }

    /// Reads a file back as text.
    pub(crate) fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.join(relative)).expect("file is readable")
    }

    /// Reports whether a path exists, without following links.
    pub(crate) fn exists(&self, relative: &str) -> bool {
        fs::symlink_metadata(self.join(relative)).is_ok()
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        // Best effort: a leaked temporary directory must never fail a test.
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Strips the Windows `\\?\` verbatim prefix so external tools such as
/// `mklink` accept the path.
fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.len() >= 2 && rest.as_bytes()[1] == b':' => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

/// Attempts to create a directory symbolic link, reporting whether it worked.
///
/// Creating one on Windows requires developer mode or elevation, so callers
/// treat `false` as "skip this case on this host" rather than as a failure.
#[cfg(windows)]
pub(crate) fn try_symlink_dir(original: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_dir(original, link).is_ok()
}

/// Attempts to create a directory symbolic link, reporting whether it worked.
#[cfg(unix)]
pub(crate) fn try_symlink_dir(original: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(original, link).is_ok()
}

/// Attempts to create a file symbolic link, reporting whether it worked.
#[cfg(windows)]
pub(crate) fn try_symlink_file(original: &Path, link: &Path) -> bool {
    std::os::windows::fs::symlink_file(original, link).is_ok()
}

/// Attempts to create a file symbolic link, reporting whether it worked.
#[cfg(unix)]
pub(crate) fn try_symlink_file(original: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(original, link).is_ok()
}

/// Attempts to create a Windows directory junction, reporting whether it
/// worked.
///
/// Junctions need no privilege, so on Windows this is the escape an attacker
/// can actually build. `mklink` is a `cmd` builtin, so it is invoked through
/// `cmd /c` with a fixed argument vector; no test input reaches it.
#[cfg(windows)]
pub(crate) fn try_junction(original: &Path, link: &Path) -> bool {
    use std::process::{Command, Stdio};

    let created = Command::new("cmd")
        .arg("/c")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(original)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    created && fs::symlink_metadata(link).is_ok()
}

/// Junctions do not exist outside Windows.
#[cfg(not(windows))]
pub(crate) fn try_junction(_original: &Path, _link: &Path) -> bool {
    false
}

/// Removes a directory link without following it.
///
/// Windows junctions and directory symlinks are directory entries and need
/// `remove_dir`; a unix symlink to a directory is not a directory and needs
/// `remove_file`. Either way the target is left untouched.
pub(crate) fn remove_dir_link(link: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        fs::remove_dir(link)
    }
    #[cfg(not(windows))]
    {
        fs::remove_file(link)
    }
}

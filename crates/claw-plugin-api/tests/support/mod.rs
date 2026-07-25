//! Shared helpers for the `claw-plugin-api` integration tests.

#![allow(dead_code, unreachable_pub)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A self-deleting directory beneath the system temporary directory.
///
/// This replaces the `tempfile` crate. `tempfile` seeds its name generator from
/// a newer `getrandom` line than the one `ring` already resolves in the root
/// dependency graph, and the root `deny.toml` - a frozen trust-root file that
/// cannot be edited - denies duplicate crate versions.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a fresh directory that no other test can collide with.
    ///
    /// Uniqueness comes from the process id (distinct per test binary), the
    /// creation timestamp and a per-process counter, so no randomness is
    /// required.
    pub fn new() -> std::io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "claw-plugin-api-test-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// The directory itself.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Creates a self-deleting temporary directory, panicking on failure.
#[must_use]
pub fn tempdir() -> TempDir {
    TempDir::new().expect("the system temporary directory must be writable")
}

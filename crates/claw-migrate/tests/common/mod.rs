//! Shared scaffolding for the per-provider migration fixtures.
//!
//! Every helper here is rooted in a temporary directory. Nothing in this module
//! reads or writes a real user profile, so the provider fixtures can never touch
//! `~/.claude`, `~/.codex` or `~/.hermes` on the machine running the suite.
#![expect(
    dead_code,
    reason = "this module is compiled into each integration-test binary separately, so a \
helper used by only claude.rs, codex.rs or hermes.rs is genuinely unused in the others"
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use claw_migrate::{
    Ed25519ArtifactSigner, HostPlatform, MigrationPlan, SecretStore, SecretStoreError, SecretValue,
    SystemPlatformPaths,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Self-cleaning temporary directory that stands in for a whole machine.
pub(crate) struct TestDir {
    path: PathBuf,
}

impl TestDir {
    pub(crate) fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "claw-migrate-{label}-{}-{sequence}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove stale test directory");
        }
        fs::create_dir_all(&path).expect("create test directory");
        let path = fs::canonicalize(path).expect("canonicalize test directory");
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("remove test directory");
        }
    }
}

/// In-memory secret store that records every routed credential.
#[derive(Default)]
pub(crate) struct MemorySecretStore {
    pub(crate) values: BTreeMap<String, SecretValue>,
    pub(crate) fail_put: bool,
}

impl MemorySecretStore {
    /// Returns the stored plaintext for an identifier, if any.
    pub(crate) fn plaintext(&self, id: &str) -> Option<String> {
        self.values
            .get(id)
            .map(|value| String::from_utf8_lossy(value.expose()).into_owned())
    }

    /// Returns true when some stored secret holds the given plaintext.
    pub(crate) fn holds(&self, plaintext: &str) -> bool {
        self.values
            .values()
            .any(|value| value.expose() == plaintext.as_bytes())
    }
}

impl SecretStore for MemorySecretStore {
    fn get(&mut self, id: &str) -> Result<Option<SecretValue>, SecretStoreError> {
        Ok(self.values.get(id).cloned())
    }

    fn put(&mut self, id: &str, value: SecretValue) -> Result<String, SecretStoreError> {
        if self.fail_put {
            return Err(SecretStoreError::new("injected put failure"));
        }
        self.values.insert(id.to_owned(), value);
        Ok(format!("keyring://gta-claw/{id}"))
    }

    fn remove(&mut self, id: &str) -> Result<(), SecretStoreError> {
        self.values.remove(id);
        Ok(())
    }
}

/// Platform paths rooted entirely inside the temporary directory.
pub(crate) fn paths(root: &TestDir, platform: HostPlatform) -> SystemPlatformPaths {
    SystemPlatformPaths::from_parts(
        platform,
        root.join("home"),
        root.join("config"),
        root.join("data"),
    )
}

pub(crate) fn signer() -> Ed25519ArtifactSigner {
    Ed25519ArtifactSigner::from_bytes("test-migration-key", &[11; 32])
}

pub(crate) fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("test file parent")).expect("create test file parent");
    fs::write(path, content).expect("write test file");
}

pub(crate) fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// Relative slash paths of every file under `root`.
pub(crate) fn files_under(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    collect_files(root, root, &mut found);
    found.sort();
    found
}

fn collect_files(root: &Path, current: &Path, found: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(current) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, found);
        } else if let Ok(relative) = path.strip_prefix(root) {
            found.push(
                relative
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
    }
}

/// Relative paths of every file under `root` whose bytes contain `plaintext`.
///
/// This is the whole-tree assertion behind "a migrated credential never lands on
/// disk": it walks the migration target and the backup tree rather than checking
/// only the files a test happens to name.
pub(crate) fn leaks(root: &Path, plaintext: &str) -> Vec<String> {
    let needle = plaintext.as_bytes();
    assert!(!needle.is_empty(), "plaintext probe must not be empty");
    let mut leaking = Vec::new();
    for relative in files_under(root) {
        let mut path = root.to_path_buf();
        for component in relative.split('/') {
            path.push(component);
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if bytes.windows(needle.len()).any(|window| window == needle) {
            leaking.push(relative);
        }
    }
    leaking
}

/// Reads `(kind, target)` pairs from the signed provider manifest.
///
/// The manifest is the applied plan's own record of every mutation, so asserting
/// against it proves the exact target set rather than the handful of paths a
/// test remembers to look at.
pub(crate) fn manifest_operations(target_root: &Path, provider: &str) -> Vec<(String, String)> {
    let manifest = target_root
        .join("config")
        .join("migrations")
        .join(format!("{provider}.json5"));
    let value: serde_json::Value =
        serde_json::from_str(&read(&manifest)).expect("parse provider manifest");
    value["operations"]
        .as_array()
        .expect("manifest operations array")
        .iter()
        .map(|operation| {
            (
                operation["kind"]
                    .as_str()
                    .expect("operation kind")
                    .to_owned(),
                operation["target"]
                    .as_str()
                    .expect("operation target")
                    .to_owned(),
            )
        })
        .collect()
}

/// Just the target paths recorded in the signed provider manifest.
pub(crate) fn manifest_targets(target_root: &Path, provider: &str) -> Vec<String> {
    manifest_operations(target_root, provider)
        .into_iter()
        .map(|(_, target)| target)
        .collect()
}

/// Diagnostic codes carried by a plan, sorted and deduplicated.
pub(crate) fn diagnostic_codes(plan: &MigrationPlan) -> Vec<String> {
    let mut codes = plan
        .result
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect::<Vec<_>>();
    codes.sort();
    codes.dedup();
    codes
}

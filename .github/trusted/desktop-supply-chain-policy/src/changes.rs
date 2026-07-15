//! Trusted Git changed-path manifest handling.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value as JsonValue, json};

use crate::identity::canonical_caseless;
use crate::ownership::is_codeowners_path_or_alias;
use crate::policy::is_non_ascii_security_path;
use crate::process::{CommandSpec, run};
use crate::{PolicyError, PolicyResult, error};

/// Maximum changed paths accepted from trusted Git.
pub const MAX_CHANGED_PATHS: usize = 20_000;
/// Maximum serialized changed-path bytes.
pub const MAX_CHANGED_BYTES: usize = 8 * 1024 * 1024;
/// Maximum direct base-to-head commits accepted for one pull request.
pub const MAX_PULL_REQUEST_COMMITS: usize = 10_000;
/// Maximum regular files accepted in one checkout's Git pack directory.
pub const MAX_GIT_PACK_FILES: usize = 64;
/// Maximum aggregate bytes accepted in one checkout's Git pack directory.
pub const MAX_GIT_PACK_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// One direct base-to-head path status.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChangedPath {
    /// Git status (`A`, `M`, `D`, or `T`).
    pub status: char,
    /// Slash-separated repository-relative path.
    pub path: String,
}

/// A versioned complete direct-diff manifest.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChangeManifest {
    /// Exact base OID.
    pub base: String,
    /// Exact head OID.
    pub head: String,
    /// Complete bounded changed paths.
    pub paths: Vec<ChangedPath>,
}

/// Requires a lowercase full Git object ID.
pub fn validate_oid(value: &str, label: &str) -> PolicyResult<()> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(PolicyError::new(format!(
        "{label} must be a lowercase 40-character Git OID"
    )))
}

fn null_device() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

fn git_spec(
    git: &Path,
    cwd: &Path,
    isolated_home: &Path,
    args: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> PolicyResult<CommandSpec> {
    let mut spec = CommandSpec::new(git, cwd)?
        .args(args)
        .env("HOME", isolated_home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null_device())
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("LC_ALL", "C")
        .timeout(Duration::from_secs(30))
        .output_limits(MAX_CHANGED_BYTES, 512 * 1024);
    if cfg!(windows) {
        spec = spec.env("USERPROFILE", isolated_home);
    }
    Ok(spec)
}

fn require_clean_stderr(bytes: &[u8], label: &str) -> PolicyResult<()> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "{label} wrote unexpected stderr: {}",
            String::from_utf8_lossy(bytes)
        )))
    }
}

fn verify_pack_storage(checkout: &Path) -> PolicyResult<()> {
    let pack_root = checkout.join(".git").join("objects").join("pack");
    if !pack_root.is_dir() {
        return Err(PolicyError::new(format!(
            "Git pack directory is unavailable: {}",
            pack_root.display()
        )));
    }
    let mut entries =
        fs::read_dir(&pack_root).map_err(|cause| error("read Git pack directory", cause))?;
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    entries.try_for_each(|entry| -> PolicyResult<()> {
        let entry = entry.map_err(|cause| error("read Git pack entry", cause))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|cause| error("inspect Git pack entry", cause))?;
        let extension = entry
            .path()
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !matches!(extension.as_str(), "pack" | "idx" | "rev")
        {
            return Err(PolicyError::new(format!(
                "Git pack directory contains an unexpected entry: {}",
                entry.path().display()
            )));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| PolicyError::new("Git pack file count overflow"))?;
        bytes = bytes
            .checked_add(metadata.len())
            .ok_or_else(|| PolicyError::new("Git pack byte count overflow"))?;
        if count > MAX_GIT_PACK_FILES || bytes > MAX_GIT_PACK_BYTES {
            return Err(PolicyError::new(format!(
                "Git pack storage exceeds fixed bounds: files={count} bytes={bytes}"
            )));
        }
        Ok(())
    })?;
    Ok(())
}

/// Verifies one checkout's exact HEAD and absence of credential-like local config.
pub fn verify_checkout(
    git: &Path,
    checkout: &Path,
    isolated_home: &Path,
    expected_oid: &str,
) -> PolicyResult<()> {
    validate_oid(expected_oid, "expected checkout OID")?;
    verify_pack_storage(checkout)?;
    let head = run(&git_spec(
        git,
        checkout,
        isolated_home,
        ["rev-parse", "--verify", "HEAD"],
    )?)?;
    if !head.status.success() {
        return Err(PolicyError::new(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&head.stderr)
        )));
    }
    require_clean_stderr(&head.stderr, "git rev-parse")?;
    let actual = std::str::from_utf8(&head.stdout)
        .map_err(|cause| error("decode checkout OID", cause))?
        .trim();
    if actual != expected_oid {
        return Err(PolicyError::new(format!(
            "checkout OID mismatch: expected {expected_oid}, found {actual}"
        )));
    }

    let config = run(&git_spec(
        git,
        checkout,
        isolated_home,
        [
            "config",
            "--local",
            "--get-regexp",
            r"(extraheader|credential|insteadof|hookspath)",
        ],
    )?)?;
    match config.status.code() {
        Some(1) if config.stdout.is_empty() && config.stderr.is_empty() => Ok(()),
        Some(0) => Err(PolicyError::new(format!(
            "checkout contains credential, URL rewrite, or hook configuration: {}",
            String::from_utf8_lossy(&config.stdout)
        ))),
        _ => Err(PolicyError::new(format!(
            "could not verify checkout credential isolation: {}",
            String::from_utf8_lossy(&config.stderr)
        ))),
    }
}

fn alternate_objects(candidate_repo: &Path) -> PolicyResult<OsString> {
    let objects = candidate_repo.join(".git").join("objects");
    if !objects.is_absolute() || !objects.is_dir() {
        return Err(PolicyError::new(format!(
            "candidate object directory is unavailable: {}",
            objects.display()
        )));
    }
    std::env::join_paths([objects]).map_err(|cause| error("encode alternate object path", cause))
}

fn repository_args(repository: &Path) -> [OsString; 2] {
    [
        OsString::from("--git-dir"),
        repository.join(".git").into_os_string(),
    ]
}

/// Requires the event base commit to be an ancestor of the immutable head.
pub fn verify_up_to_date(
    git: &Path,
    trusted_repo: &Path,
    candidate_repo: &Path,
    isolated_home: &Path,
    base: &str,
    head: &str,
) -> PolicyResult<()> {
    validate_oid(base, "base OID")?;
    validate_oid(head, "head OID")?;
    let [git_dir_flag, git_dir] = repository_args(trusted_repo);
    let spec = git_spec(
        git,
        trusted_repo,
        isolated_home,
        [
            git_dir_flag,
            git_dir,
            OsString::from("merge-base"),
            OsString::from("--is-ancestor"),
            OsString::from(base),
            OsString::from(head),
        ],
    )?
    .env(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        alternate_objects(candidate_repo)?,
    );
    let output = run(&spec)?;
    require_clean_stderr(&output.stderr, "git merge-base")?;
    match output.status.code() {
        Some(0) => Ok(()),
        Some(1) => Err(PolicyError::new(
            "pull request head is stale: base is not an ancestor of head",
        )),
        _ => Err(PolicyError::new(format!(
            "git merge-base failed with status {}",
            output.status
        ))),
    }
}

/// Requires a non-empty direct pull-request commit range within the fixed checkout cap.
pub fn validate_pull_request_commit_count(count: usize) -> PolicyResult<()> {
    if (1..=MAX_PULL_REQUEST_COMMITS).contains(&count) {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "pull request commit count must be between 1 and {MAX_PULL_REQUEST_COMMITS}, found {count}"
        )))
    }
}

fn verify_commit_count(
    git: &Path,
    trusted_repo: &Path,
    candidate_repo: &Path,
    isolated_home: &Path,
    base: &str,
    head: &str,
) -> PolicyResult<()> {
    let [git_dir_flag, git_dir] = repository_args(trusted_repo);
    let output = run(&git_spec(
        git,
        trusted_repo,
        isolated_home,
        [
            git_dir_flag,
            git_dir,
            OsString::from("rev-list"),
            OsString::from("--count"),
            OsString::from(format!("--max-count={}", MAX_PULL_REQUEST_COMMITS + 1)),
            OsString::from(head),
            OsString::from(format!("^{base}")),
            OsString::from("--"),
        ],
    )?
    .env(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        alternate_objects(candidate_repo)?,
    )
    .output_limits(64 * 1024, 64 * 1024))?;
    if !output.status.success() {
        return Err(PolicyError::new(format!(
            "git rev-list failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    require_clean_stderr(&output.stderr, "git rev-list")?;
    let count = std::str::from_utf8(&output.stdout)
        .map_err(|cause| error("decode pull request commit count", cause))?
        .trim();
    if count.is_empty() || !count.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolicyError::new(format!(
            "git rev-list returned an invalid commit count: {count:?}"
        )));
    }
    let parsed = count
        .parse::<usize>()
        .map_err(|cause| error("parse pull request commit count", cause))?;
    if count != parsed.to_string() {
        return Err(PolicyError::new(format!(
            "git rev-list returned a non-canonical commit count: {count:?}"
        )));
    }
    validate_pull_request_commit_count(parsed)
}

fn parse_name_status(bytes: &[u8]) -> PolicyResult<Vec<ChangedPath>> {
    let mut fields = bytes.split(|byte| *byte == 0);
    let mut paths = Vec::new();
    loop {
        let Some(status) = fields.next() else {
            break;
        };
        if status.is_empty() {
            if fields.next().is_some() {
                return Err(PolicyError::new(
                    "trusted Git changed-path output has trailing fields",
                ));
            }
            break;
        }
        let path = fields.next().ok_or_else(|| {
            PolicyError::new("trusted Git changed-path output ended after status")
        })?;
        if paths.len() >= MAX_CHANGED_PATHS {
            return Err(PolicyError::new(format!(
                "changed-path manifest exceeds {MAX_CHANGED_PATHS} entries"
            )));
        }
        if status.len() != 1 || !matches!(status[0], b'A' | b'M' | b'D' | b'T') {
            return Err(PolicyError::new(format!(
                "unexpected trusted Git path status: {}",
                String::from_utf8_lossy(status)
            )));
        }
        let path =
            std::str::from_utf8(path).map_err(|cause| error("changed path is not UTF-8", cause))?;
        validate_changed_path(path)?;
        paths.push(ChangedPath {
            status: char::from(status[0]),
            path: path.to_owned(),
        });
    }
    paths.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.status.cmp(&right.status))
    });
    Ok(paths)
}

fn validate_changed_path(path: &str) -> PolicyResult<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(PolicyError::new(format!(
            "changed path is not a normalized repository path: {path:?}"
        )));
    }
    Ok(())
}

/// Computes the complete bounded direct base-to-head changed-path manifest.
pub fn compute_manifest(
    git: &Path,
    trusted_repo: &Path,
    candidate_repo: &Path,
    isolated_home: &Path,
    base: &str,
    head: &str,
) -> PolicyResult<ChangeManifest> {
    verify_checkout(git, trusted_repo, isolated_home, base)?;
    verify_checkout(git, candidate_repo, isolated_home, head)?;
    verify_up_to_date(git, trusted_repo, candidate_repo, isolated_home, base, head)?;
    verify_commit_count(git, trusted_repo, candidate_repo, isolated_home, base, head)?;
    let [git_dir_flag, git_dir] = repository_args(trusted_repo);
    let spec = git_spec(
        git,
        trusted_repo,
        isolated_home,
        [
            git_dir_flag,
            git_dir,
            OsString::from("-c"),
            OsString::from("core.hooksPath=/dev/null"),
            OsString::from("diff"),
            OsString::from("--name-status"),
            OsString::from("-z"),
            OsString::from("--no-renames"),
            OsString::from("--no-ext-diff"),
            OsString::from("--no-textconv"),
            OsString::from(base),
            OsString::from(head),
            OsString::from("--"),
        ],
    )?
    .env(
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        alternate_objects(candidate_repo)?,
    );
    let output = run(&spec)?;
    if !output.status.success() {
        return Err(PolicyError::new(format!(
            "trusted Git diff failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    require_clean_stderr(&output.stderr, "trusted Git diff")?;
    Ok(ChangeManifest {
        base: base.to_owned(),
        head: head.to_owned(),
        paths: parse_name_status(&output.stdout)?,
    })
}

/// Writes a deterministic bounded JSON changed-path manifest.
pub fn write_manifest(path: &Path, manifest: &ChangeManifest) -> PolicyResult<()> {
    if !path.is_absolute() {
        return Err(PolicyError::new(
            "change manifest output path must be absolute",
        ));
    }
    let entries = manifest
        .paths
        .iter()
        .map(|entry| {
            json!({
                "status": entry.status.to_string(),
                "path": entry.path,
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&json!({
        "version": 1,
        "base": manifest.base,
        "head": manifest.head,
        "paths": entries,
    }))?;
    if bytes.len() > MAX_CHANGED_BYTES {
        return Err(PolicyError::new(format!(
            "serialized change manifest exceeds {MAX_CHANGED_BYTES} bytes"
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| PolicyError::new("change manifest output has no parent"))?;
    fs::create_dir_all(parent).map_err(|cause| error("create change manifest directory", cause))?;
    fs::write(path, bytes).map_err(|cause| error("write change manifest", cause))
}

/// Reads and validates a deterministic JSON changed-path manifest.
pub fn read_manifest(path: &Path) -> PolicyResult<ChangeManifest> {
    let metadata =
        fs::symlink_metadata(path).map_err(|cause| error("inspect change manifest", cause))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_CHANGED_BYTES as u64
    {
        return Err(PolicyError::new(
            "change manifest is not a bounded regular file",
        ));
    }
    let bytes = fs::read(path).map_err(|cause| error("read change manifest", cause))?;
    let root: JsonValue = serde_json::from_slice(&bytes)?;
    let object = root
        .as_object()
        .ok_or_else(|| PolicyError::new("change manifest root must be an object"))?;
    if object.len() != 4 || object.get("version").and_then(JsonValue::as_u64) != Some(1) {
        return Err(PolicyError::new(
            "change manifest version or schema changed",
        ));
    }
    let base = object
        .get("base")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| PolicyError::new("change manifest base is missing"))?
        .to_owned();
    let head = object
        .get("head")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| PolicyError::new("change manifest head is missing"))?
        .to_owned();
    validate_oid(&base, "manifest base OID")?;
    validate_oid(&head, "manifest head OID")?;
    let values = object
        .get("paths")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| PolicyError::new("change manifest paths are missing"))?;
    if values.len() > MAX_CHANGED_PATHS {
        return Err(PolicyError::new(format!(
            "change manifest exceeds {MAX_CHANGED_PATHS} paths"
        )));
    }
    let mut paths = Vec::with_capacity(values.len());
    for value in values {
        let entry = value
            .as_object()
            .ok_or_else(|| PolicyError::new("change manifest entry must be an object"))?;
        if entry.len() != 2 {
            return Err(PolicyError::new("change manifest entry schema changed"));
        }
        let status = entry
            .get("status")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| PolicyError::new("change manifest status is missing"))?;
        let mut chars = status.chars();
        let status = chars
            .next()
            .filter(|value| matches!(value, 'A' | 'M' | 'D' | 'T'))
            .ok_or_else(|| PolicyError::new("change manifest status is invalid"))?;
        if chars.next().is_some() {
            return Err(PolicyError::new("change manifest status is invalid"));
        }
        let path = entry
            .get("path")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| PolicyError::new("change manifest path is missing"))?;
        validate_changed_path(path)?;
        paths.push(ChangedPath {
            status,
            path: path.to_owned(),
        });
    }
    let mut sorted = paths.clone();
    sorted.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.status.cmp(&right.status))
    });
    if paths != sorted {
        return Err(PolicyError::new(
            "change manifest paths are not deterministically sorted",
        ));
    }
    Ok(ChangeManifest { base, head, paths })
}

/// Returns whether a complete changed-path entry can affect supply-chain policy.
#[must_use]
pub fn is_policy_relevant(path: &str) -> bool {
    if is_codeowners_path_or_alias(path) || is_non_ascii_security_path(path) {
        return true;
    }
    let components = path.split('/').map(canonical_caseless).collect::<Vec<_>>();
    let normalized = components.join("/");
    if normalized.starts_with(".github/workflows/")
        || normalized.starts_with(".github/trusted/desktop-supply-chain-policy/")
        || normalized.starts_with(".github/fixtures/cargo-audit/")
        || normalized.starts_with(".github/fixtures/security-tools/")
        || normalized
            .starts_with("crates/claw-security/tests/fixtures/desktop_supply_chain_policy/")
        || normalized == "crates/claw-security/tests/desktop_supply_chain_policy.rs"
        || normalized == ".gitattributes"
    {
        return true;
    }
    if components
        .iter()
        .any(|component| component == "rust-toolchain")
    {
        return true;
    }
    let file_name = components.last().map(String::as_str).unwrap_or_default();
    if matches!(
        file_name,
        "cargo.toml"
            | "cargo.lock"
            | "rust-toolchain.toml"
            | "rust-toolchain"
            | "rustfmt.toml"
            | "audit.toml"
    ) {
        return true;
    }
    let in_cargo_directory = normalized.starts_with(".cargo/") || normalized.contains("/.cargo/");
    if in_cargo_directory && matches!(file_name, "config" | "config.toml") {
        return true;
    }
    file_name.starts_with("deny") && file_name.ends_with(".toml")
        || file_name.starts_with(".deny") && file_name.ends_with(".toml")
}

/// Returns whether any complete changed path is policy-relevant.
#[must_use]
pub fn has_policy_relevant_change(manifest: &ChangeManifest) -> bool {
    manifest
        .paths
        .iter()
        .any(|entry| is_policy_relevant(&entry.path))
}

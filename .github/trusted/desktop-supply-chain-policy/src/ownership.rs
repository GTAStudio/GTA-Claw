//! Canonical ownership for the immutable desktop supply-chain boundary.

use std::collections::BTreeSet;

use crate::identity::canonical_caseless;
use crate::input::{DEFAULT_FILE_LIMIT, SafeRoot};
use crate::{PolicyError, PolicyResult};

/// Canonical repository ownership file.
pub const CODEOWNERS_PATH: &str = ".github/CODEOWNERS";
/// Sole canonical owner while the repository has one audited maintainer.
pub const CODEOWNER: &str = "@aizhihuxiao";

const CANONICAL_CODEOWNERS: &[u8] = include_bytes!("../../../CODEOWNERS");

const PATTERNS: [&str; 21] = [
    "/.github/CODEOWNERS",
    "/.github/workflows/bootstrap-desktop-supply-chain-policy.yml",
    "/.github/workflows/trusted-desktop-supply-chain-policy.yml",
    "/.github/trusted/desktop-supply-chain-policy/**",
    "/.github/workflows/rust.yml",
    "/.github/workflows/macos-packaging.yml",
    "/.github/fixtures/cargo-audit/**",
    "/.github/fixtures/security-tools/**",
    "/.gitattributes",
    "/.cargo/audit.toml",
    "/deny.toml",
    "rust-toolchain",
    "/rust-toolchain.toml",
    "/rustfmt.toml",
    "/desktop/Cargo.toml",
    "/desktop/Cargo.lock",
    "/desktop/deny.toml",
    "/desktop/apps/gta-claw-desktop/Cargo.toml",
    "/desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs",
    "/crates/claw-security/tests/desktop_supply_chain_policy.rs",
    "/crates/claw-security/tests/fixtures/desktop_supply_chain_policy/**",
];

const FROZEN_SURFACES: [&str; 21] = [
    ".github/CODEOWNERS",
    ".github/workflows/bootstrap-desktop-supply-chain-policy.yml",
    ".github/workflows/trusted-desktop-supply-chain-policy.yml",
    ".github/trusted/desktop-supply-chain-policy/Cargo.toml",
    ".github/workflows/rust.yml",
    ".github/workflows/macos-packaging.yml",
    ".github/fixtures/cargo-audit/unmaintained/Cargo.lock.fixture",
    ".github/fixtures/security-tools/bash-env-poison.sh",
    ".gitattributes",
    ".cargo/audit.toml",
    "deny.toml",
    "rust-toolchain",
    "rust-toolchain.toml",
    "rustfmt.toml",
    "desktop/Cargo.toml",
    "desktop/Cargo.lock",
    "desktop/deny.toml",
    "desktop/apps/gta-claw-desktop/Cargo.toml",
    "desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs",
    "crates/claw-security/tests/desktop_supply_chain_policy.rs",
    "crates/claw-security/tests/fixtures/desktop_supply_chain_policy/negative-cases.toml",
];

fn normalized(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"\r\n") {
            output.push(b'\n');
            index += 2;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    output
}

fn pattern_covers(pattern: &str, path: &str) -> bool {
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    if let Some(prefix) = pattern.strip_suffix("/**") {
        path.starts_with(prefix)
            && path
                .as_bytes()
                .get(prefix.len())
                .is_some_and(|separator| *separator == b'/')
    } else if !pattern.contains('/') {
        path.rsplit('/').next() == Some(pattern)
    } else {
        pattern == path
    }
}

/// Validates canonical ordered ownership text against a frozen-surface inventory.
pub fn validate_codeowners_text(text: &str, frozen_surfaces: &[&str]) -> PolicyResult<()> {
    let mut patterns = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 || fields[1] != CODEOWNER {
            return Err(PolicyError::new(format!(
                "CODEOWNERS entry must have one canonical owner: {line:?}"
            )));
        }
        patterns.push(fields[0]);
    }
    if patterns != PATTERNS {
        return Err(PolicyError::new(format!(
            "CODEOWNERS pattern inventory/order changed: {patterns:?}"
        )));
    }
    for surface in frozen_surfaces {
        if !patterns
            .iter()
            .any(|pattern| pattern_covers(pattern, surface))
        {
            return Err(PolicyError::new(format!(
                "exact-frozen surface is not owned: {surface}"
            )));
        }
    }
    let unique = patterns.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != patterns.len() {
        return Err(PolicyError::new(
            "CODEOWNERS contains duplicate ownership patterns",
        ));
    }
    Ok(())
}

/// Requires exact canonical ownership bytes and complete frozen-surface coverage.
pub fn validate_codeowners(root: &SafeRoot) -> PolicyResult<()> {
    let bytes = root.read_bytes(CODEOWNERS_PATH, DEFAULT_FILE_LIMIT)?;
    if normalized(&bytes) != normalized(CANONICAL_CODEOWNERS) {
        return Err(PolicyError::new(
            "canonical .github/CODEOWNERS bytes changed",
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|error| PolicyError::new(format!("CODEOWNERS is not UTF-8: {error}")))?;
    validate_codeowners_text(&text, &FROZEN_SURFACES)
}

/// Returns whether a repository path is a canonical or alternate CODEOWNERS location.
#[must_use]
pub fn is_codeowners_path_or_alias(path: &str) -> bool {
    let parts = path.split('/').map(canonical_caseless).collect::<Vec<_>>();
    let file_name = parts.last().map(String::as_str).unwrap_or_default();
    if file_name.trim_end_matches(['.', ' ']) == "codeowners" {
        return true;
    }
    let recognized_location =
        parts.len() == 1 || parts.len() == 2 && matches!(parts[0].as_str(), ".github" | "docs");
    recognized_location && !path.is_ascii() && !file_name.contains('.')
}

/// Returns the canonical ownership text for deterministic tests.
#[must_use]
pub fn canonical_codeowners() -> &'static str {
    std::str::from_utf8(CANONICAL_CODEOWNERS).expect("repository CODEOWNERS is compile-time UTF-8")
}

/// Returns the frozen surfaces required by the ownership contract.
#[must_use]
pub const fn frozen_surfaces() -> &'static [&'static str] {
    &FROZEN_SURFACES
}

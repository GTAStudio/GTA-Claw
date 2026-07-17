//! Static final-state policy and extensible root workspace validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use sha2::{Digest as _, Sha256};
use toml::Value as TomlValue;

use crate::identity::canonical_caseless;
use crate::input::{DEFAULT_FILE_LIMIT, SafeRoot};
use crate::ownership::{CODEOWNERS_PATH, is_codeowners_path_or_alias, validate_codeowners};
use crate::{PolicyError, PolicyResult, error};

const MAX_REPOSITORY_FILES: usize = 50_000;
const MAX_REPOSITORY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_LOCK_BYTES: u64 = 16 * 1024 * 1024;
const ROOT_MANIFEST: &str = "Cargo.toml";
const ROOT_LOCK: &str = "Cargo.lock";
const DESKTOP_MANIFEST: &str = "desktop/Cargo.toml";
const DESKTOP_LOCK: &str = "desktop/Cargo.lock";
const APP_MANIFEST: &str = "desktop/apps/gta-claw-desktop/Cargo.toml";
const TRUSTED_MANIFEST: &str = ".github/trusted/desktop-supply-chain-policy/Cargo.toml";
const TRUSTED_LOCK: &str = ".github/trusted/desktop-supply-chain-policy/Cargo.lock";
const LEGACY_VALIDATOR: &str = "crates/claw-security/tests/desktop_supply_chain_policy.rs";
const LEGACY_FIXTURES: &str = "crates/claw-security/tests/fixtures/desktop_supply_chain_policy";

const FINAL_ROOT_DENY: &[u8] = include_bytes!("../policy/final/root-deny.toml.fixture");
const FINAL_DESKTOP_MANIFEST: &[u8] = include_bytes!("../policy/final/desktop/Cargo.toml.fixture");
const FINAL_APP_MANIFEST: &[u8] =
    include_bytes!("../policy/final/desktop/apps/gta-claw-desktop/Cargo.toml.fixture");
const FINAL_DESKTOP_DENY: &[u8] = include_bytes!("../policy/final/desktop/deny.toml.fixture");
const FINAL_DESKTOP_LOCK: &[u8] = include_bytes!("../policy/final/desktop/Cargo.lock.fixture");
const FINAL_SMOKE_TEST: &[u8] =
    include_bytes!("../policy/final/desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs");
const FINAL_AUDIT_WARNING: &[u8] =
    include_bytes!("../policy/final/.github/fixtures/cargo-audit/unmaintained/Cargo.lock.fixture");
const FINAL_AUDIT_VULNERABLE: &[u8] =
    include_bytes!("../policy/final/.github/fixtures/cargo-audit/vulnerable/Cargo.lock.fixture");
const FINAL_BASH_POISON: &[u8] =
    include_bytes!("../policy/final/.github/fixtures/security-tools/bash-env-poison.sh");
const FINAL_SHA_POISON: &[u8] =
    include_bytes!("../policy/final/.github/fixtures/security-tools/shadow-bin/sha256sum");
const FINAL_TAR_POISON: &[u8] =
    include_bytes!("../policy/final/.github/fixtures/security-tools/shadow-bin/tar");

const ROOT_AUDIT: &[u8] = b"[advisories]\nignore = []\n";
const ROOT_TOOLCHAIN: &[u8] = b"[toolchain]\nchannel = \"1.97.0\"\ncomponents = [\"clippy\", \"rustfmt\"]\nprofile = \"minimal\"\n";
const ROOT_RUSTFMT: &[u8] = b"edition = \"2024\"\nmax_width = 100\nnewline_style = \"Unix\"\nuse_field_init_shorthand = true\nuse_try_shorthand = true\n";
const ROOT_GITATTRIBUTES: &[u8] = b"# Keep Rust workspace inputs deterministic on Windows checkouts.\n/.gitattributes text eol=lf\n*.rs text eol=lf\n*.slint text eol=lf\n*.toml text eol=lf\n*.yml text eol=lf\n*.yaml text eol=lf\n*.sh text eol=lf\nCargo.lock text eol=lf\nrust-toolchain text eol=lf\n.github/fixtures/security-tools/shadow-bin/* text eol=lf\n.github/trusted/desktop-supply-chain-policy/policy/final/.github/fixtures/security-tools/shadow-bin/* text eol=lf\n";

const BOOTSTRAP_FINGERPRINT: &str =
    "4a52e1daad1fc3b3136c72585e3934dae390dbe7e8e9e330e8c60da784a15237";

const BOOTSTRAP_SNAPSHOT_MAGIC: &[u8; 8] = b"GTABOOT1";

const BOOTSTRAP_FILES: [&str; 28] = [
    ".cargo/audit.toml",
    ".gitattributes",
    ".github/CODEOWNERS",
    ".github/workflows/bootstrap-desktop-supply-chain-policy.yml",
    ".github/workflows/docker-publish.yml",
    ".github/workflows/linux-packaging.yml",
    ".github/workflows/macos-packaging.yml",
    ".github/workflows/rust.yml",
    ".github/workflows/trusted-desktop-supply-chain-policy.yml",
    ".github/workflows/upstream-gateway-reference.yml",
    ".github/workflows/windows-packaging.yml",
    "Cargo.lock",
    "Cargo.toml",
    "apps/gta-claw-cli/Cargo.toml",
    "apps/gta-claw-daemon/Cargo.toml",
    "crates/claw-application/Cargo.toml",
    "crates/claw-config/Cargo.toml",
    "crates/claw-domain/Cargo.toml",
    "crates/claw-gateway-client/Cargo.toml",
    "crates/claw-platform/Cargo.toml",
    "crates/claw-protocol/Cargo.toml",
    "crates/claw-security/Cargo.toml",
    "deny.toml",
    "desktop/Cargo.lock",
    "desktop/Cargo.toml",
    "desktop/apps/gta-claw-desktop/Cargo.toml",
    "rust-toolchain.toml",
    "rustfmt.toml",
];

const BOOTSTRAP_MEMBER_MANIFESTS: [&str; 9] = [
    "apps/gta-claw-cli/Cargo.toml",
    "apps/gta-claw-daemon/Cargo.toml",
    "crates/claw-application/Cargo.toml",
    "crates/claw-config/Cargo.toml",
    "crates/claw-domain/Cargo.toml",
    "crates/claw-gateway-client/Cargo.toml",
    "crates/claw-platform/Cargo.toml",
    "crates/claw-protocol/Cargo.toml",
    "crates/claw-security/Cargo.toml",
];

const ALLOWED_LOCKS: [&str; 3] = [ROOT_LOCK, DESKTOP_LOCK, TRUSTED_LOCK];

const FORBIDDEN_GUI_NAMES: [&str; 11] = [
    "dioxus-desktop",
    "egui",
    "gtk",
    "iced",
    "slint",
    "slint-build",
    "tao",
    "webview2-com",
    "webkit2gtk",
    "winit",
    "wry",
];

/// Validated declarative root workspace information.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RootWorkspace {
    /// Canonical member directory to package name.
    pub members: BTreeMap<String, String>,
    /// Shared workspace package version.
    pub version: String,
}

fn parse_toml(root: &SafeRoot, path: &str, limit: u64) -> PolicyResult<TomlValue> {
    let text = root.read_text(path, limit)?;
    toml::from_str(&text).map_err(|cause| error(&format!("parse TOML {path}"), cause))
}

fn table<'a>(
    value: &'a TomlValue,
    key: &str,
) -> PolicyResult<&'a toml::map::Map<String, TomlValue>> {
    value
        .get(key)
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new(format!("missing TOML table: {key}")))
}

fn keys(table: &toml::map::Map<String, TomlValue>) -> BTreeSet<&str> {
    table.keys().map(String::as_str).collect()
}

fn expected_keys<'a>(values: &'a [&'a str]) -> BTreeSet<&'a str> {
    values.iter().copied().collect()
}

fn normalize_text(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"\r\n") {
            normalized.push(b'\n');
            index += 2;
        } else {
            normalized.push(bytes[index]);
            index += 1;
        }
    }
    normalized
}

fn require_exact_file(root: &SafeRoot, path: &str, expected: &[u8]) -> PolicyResult<()> {
    let actual = root.read_bytes(path, DEFAULT_FILE_LIMIT.max(expected.len() as u64))?;
    if normalize_text(&actual) != normalize_text(expected) {
        return Err(PolicyError::new(format!(
            "exact security policy file changed: {path}"
        )));
    }
    Ok(())
}

fn require_exact_lf_file(root: &SafeRoot, path: &str, expected: &[u8]) -> PolicyResult<()> {
    let actual = root.read_bytes(path, DEFAULT_FILE_LIMIT.max(expected.len() as u64))?;
    if expected.contains(&b'\r')
        || actual.contains(&b'\r')
        || expected.last() != Some(&b'\n')
        || actual != expected
    {
        return Err(PolicyError::new(format!(
            "exact LF security script changed: {path}"
        )));
    }
    Ok(())
}

pub(crate) fn is_forbidden_gui(name: &str) -> bool {
    let canonical = canonical_caseless(name).replace('_', "-");
    canonical.starts_with("i-slint")
        || ["gtk4", "gdk4", "gsk4"]
            .iter()
            .any(|prefix| canonical.starts_with(prefix))
        || FORBIDDEN_GUI_NAMES
            .iter()
            .any(|forbidden| canonical == canonical_caseless(forbidden))
}

fn require_workspace_inheritance(
    package: &toml::map::Map<String, TomlValue>,
    key: &str,
    path: &str,
) -> PolicyResult<()> {
    let inherited = package.get(key).and_then(TomlValue::as_table);
    if inherited.is_none_or(|value| {
        keys(value) != expected_keys(&["workspace"])
            || value.get("workspace").and_then(TomlValue::as_bool) != Some(true)
    }) {
        return Err(PolicyError::new(format!(
            "{path} package.{key} must inherit exactly from workspace"
        )));
    }
    Ok(())
}

fn normalized_member(value: &str) -> PolicyResult<String> {
    if value.contains('\\') || value.starts_with('/') || value.ends_with('/') {
        return Err(PolicyError::new(format!(
            "workspace member is not canonical: {value:?}"
        )));
    }
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || !matches!(parts[0], "apps" | "crates")
        || parts[1].is_empty()
        || !parts[1]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(PolicyError::new(format!(
            "workspace member must be one canonical apps/* or crates/* path: {value:?}"
        )));
    }
    Ok(value.to_owned())
}

fn manifest_path(member: &str) -> String {
    format!("{member}/Cargo.toml")
}

fn package_leaf(member: &str) -> &str {
    member.rsplit_once('/').map_or(member, |(_, name)| name)
}

fn validate_workspace_package(
    workspace: &toml::map::Map<String, TomlValue>,
) -> PolicyResult<String> {
    let package = workspace
        .get("package")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("root workspace.package table is missing"))?;
    if keys(package)
        != expected_keys(&[
            "version",
            "edition",
            "rust-version",
            "license",
            "repository",
        ])
    {
        return Err(PolicyError::new("root workspace.package schema changed"));
    }
    let version = package
        .get("version")
        .and_then(TomlValue::as_str)
        .filter(|value| valid_semver(value))
        .ok_or_else(|| PolicyError::new("root workspace version is not a plain semver"))?;
    for (key, expected) in [
        ("edition", "2024"),
        ("rust-version", "1.94.0"),
        ("license", "MIT"),
        ("repository", "https://github.com/GTAStudio/GTA-Claw"),
    ] {
        if package.get(key).and_then(TomlValue::as_str) != Some(expected) {
            return Err(PolicyError::new(format!(
                "root workspace.package.{key} changed"
            )));
        }
    }
    Ok(version.to_owned())
}

fn valid_semver(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_workspace_lints(workspace: &toml::map::Map<String, TomlValue>) -> PolicyResult<()> {
    let lints = workspace
        .get("lints")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("root workspace.lints table is missing"))?;
    let rust = lints
        .get("rust")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("root workspace.lints.rust table is missing"))?;
    if rust
        != &toml::map::Map::from_iter([
            (
                "missing_docs".to_owned(),
                TomlValue::String("warn".to_owned()),
            ),
            (
                "unsafe_code".to_owned(),
                TomlValue::String("forbid".to_owned()),
            ),
            (
                "unsafe_op_in_unsafe_fn".to_owned(),
                TomlValue::String("deny".to_owned()),
            ),
            (
                "unreachable_pub".to_owned(),
                TomlValue::String("warn".to_owned()),
            ),
        ])
    {
        return Err(PolicyError::new("root workspace Rust lint policy changed"));
    }
    let clippy = lints
        .get("clippy")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("root workspace.lints.clippy table is missing"))?;
    if clippy
        != &toml::map::Map::from_iter([("all".to_owned(), TomlValue::String("warn".to_owned()))])
    {
        return Err(PolicyError::new("root workspace Clippy policy changed"));
    }
    Ok(())
}

fn validate_profile(root_manifest: &TomlValue) -> PolicyResult<()> {
    let profile = table(root_manifest, "profile")?;
    if keys(profile) != expected_keys(&["release"]) {
        return Err(PolicyError::new("root profile schema changed"));
    }
    let release = profile
        .get("release")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("root release profile is missing"))?;
    if release
        != &toml::map::Map::from_iter([
            ("codegen-units".to_owned(), TomlValue::Integer(1)),
            ("lto".to_owned(), TomlValue::String("thin".to_owned())),
            ("strip".to_owned(), TomlValue::String("symbols".to_owned())),
        ])
    {
        return Err(PolicyError::new("root release profile changed"));
    }
    Ok(())
}

fn normalize_dependency_path(base: &str, dependency: &str) -> PolicyResult<String> {
    if dependency.contains('\\') || Path::new(dependency).is_absolute() {
        return Err(PolicyError::new(format!(
            "dependency path is not repository-relative: {dependency:?}"
        )));
    }
    let mut parts = if base.is_empty() {
        Vec::new()
    } else {
        base.split('/').map(str::to_owned).collect::<Vec<_>>()
    };
    for component in Path::new(dependency).components() {
        match component {
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or_else(|| PolicyError::new("dependency path component is not UTF-8"))?;
                if value.is_empty() {
                    return Err(PolicyError::new("dependency path has an empty component"));
                }
                parts.push(value.to_owned());
            }
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(PolicyError::new("dependency path escapes repository root"));
                }
            }
            Component::CurDir => {}
            _ => {
                return Err(PolicyError::new(
                    "dependency path contains an invalid component",
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(PolicyError::new(
            "dependency path resolves to repository root",
        ));
    }
    Ok(parts.join("/"))
}

fn valid_version_requirement(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.contains('*')
        && value != "latest"
        && value.bytes().all(|byte| !byte.is_ascii_control())
}

fn validate_dependency(
    dependency_name: &str,
    value: &TomlValue,
    manifest_directory: &str,
    declared_members: &BTreeSet<String>,
) -> PolicyResult<()> {
    if is_forbidden_gui(dependency_name) {
        return Err(PolicyError::new(format!(
            "root/headless manifest contains forbidden GUI dependency: {dependency_name}"
        )));
    }
    if let Some(version) = value.as_str() {
        if !valid_version_requirement(version) {
            return Err(PolicyError::new(format!(
                "dependency has a wildcard or invalid version: {dependency_name}"
            )));
        }
        return Ok(());
    }
    let dependency = value.as_table().ok_or_else(|| {
        PolicyError::new(format!(
            "dependency declaration is not a string or table: {dependency_name}"
        ))
    })?;
    let allowed = expected_keys(&[
        "default-features",
        "features",
        "optional",
        "package",
        "path",
        "version",
        "workspace",
    ]);
    if !keys(dependency).is_subset(&allowed)
        || dependency.contains_key("git")
        || dependency.contains_key("registry")
    {
        return Err(PolicyError::new(format!(
            "dependency source/schema is forbidden: {dependency_name}"
        )));
    }
    if let Some(package) = dependency.get("package") {
        let package = package.as_str().ok_or_else(|| {
            PolicyError::new(format!(
                "dependency package rename is not a string: {dependency_name}"
            ))
        })?;
        if is_forbidden_gui(package) {
            return Err(PolicyError::new(format!(
                "root/headless manifest aliases forbidden GUI package {package} as {dependency_name}"
            )));
        }
    }
    if dependency.get("workspace").and_then(TomlValue::as_bool) == Some(true) {
        if dependency.contains_key("path") || dependency.contains_key("version") {
            return Err(PolicyError::new(format!(
                "workspace-inherited dependency overrides source/version: {dependency_name}"
            )));
        }
        return Ok(());
    }
    if dependency.contains_key("workspace") {
        return Err(PolicyError::new(format!(
            "dependency workspace inheritance must be true: {dependency_name}"
        )));
    }
    if let Some(path) = dependency.get("path").and_then(TomlValue::as_str) {
        let resolved = normalize_dependency_path(manifest_directory, path)?;
        if !declared_members.contains(&resolved) {
            return Err(PolicyError::new(format!(
                "path dependency is not a declared root member: {dependency_name} -> {resolved}"
            )));
        }
        if dependency
            .get("version")
            .and_then(TomlValue::as_str)
            .is_none_or(|version| !valid_version_requirement(version))
        {
            return Err(PolicyError::new(format!(
                "path dependency must retain a bounded registry version: {dependency_name}"
            )));
        }
    } else if dependency
        .get("version")
        .and_then(TomlValue::as_str)
        .is_none_or(|version| !valid_version_requirement(version))
    {
        return Err(PolicyError::new(format!(
            "registry dependency lacks a valid version: {dependency_name}"
        )));
    }
    Ok(())
}

fn validate_dependencies(
    manifest: &TomlValue,
    manifest_directory: &str,
    declared_members: &BTreeSet<String>,
) -> PolicyResult<()> {
    if manifest.get("patch").is_some() || manifest.get("replace").is_some() {
        return Err(PolicyError::new(
            "root/headless manifests must not patch or replace sources",
        ));
    }
    for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(dependencies) = manifest.get(kind) {
            let dependencies = dependencies
                .as_table()
                .ok_or_else(|| PolicyError::new(format!("{kind} must be a TOML table")))?;
            for (name, value) in dependencies {
                validate_dependency(name, value, manifest_directory, declared_members)?;
            }
        }
    }
    if let Some(targets) = manifest.get("target") {
        let targets = targets
            .as_table()
            .ok_or_else(|| PolicyError::new("target must be a TOML table"))?;
        for target in targets.values() {
            let target = target
                .as_table()
                .ok_or_else(|| PolicyError::new("target entry must be a TOML table"))?;
            for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
                if let Some(dependencies) = target.get(kind) {
                    let dependencies = dependencies.as_table().ok_or_else(|| {
                        PolicyError::new(format!("target {kind} must be a TOML table"))
                    })?;
                    for (name, value) in dependencies {
                        validate_dependency(name, value, manifest_directory, declared_members)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_member_manifest(
    root: &SafeRoot,
    member: &str,
    declared_members: &BTreeSet<String>,
) -> PolicyResult<String> {
    let path = manifest_path(member);
    let manifest = parse_toml(root, &path, DEFAULT_FILE_LIMIT)?;
    if manifest.get("workspace").is_some() {
        return Err(PolicyError::new(format!(
            "root member declares a nested workspace: {path}"
        )));
    }
    let package = table(&manifest, "package")?;
    let name = package
        .get("name")
        .and_then(TomlValue::as_str)
        .ok_or_else(|| PolicyError::new(format!("{path} package name is missing")))?;
    if name != package_leaf(member)
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(PolicyError::new(format!(
            "{path} package name must match its canonical directory"
        )));
    }
    for key in [
        "version",
        "edition",
        "rust-version",
        "license",
        "repository",
    ] {
        require_workspace_inheritance(package, key, &path)?;
    }
    if package.get("source").is_some()
        || package.get("workspace").is_some()
        || package
            .get("publish")
            .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Err(PolicyError::new(format!(
            "{path} package source/publish/workspace override is forbidden"
        )));
    }
    if member == "crates/claw-config" {
        let lints = table(&manifest, "lints")?;
        let rust = lints
            .get("rust")
            .and_then(TomlValue::as_table)
            .ok_or_else(|| PolicyError::new("claw-config Rust lints are missing"))?;
        let clippy = lints
            .get("clippy")
            .and_then(TomlValue::as_table)
            .ok_or_else(|| PolicyError::new("claw-config Clippy lints are missing"))?;
        if keys(lints) != expected_keys(&["clippy", "rust"])
            || rust
                != &toml::map::Map::from_iter([
                    (
                        "missing_docs".to_owned(),
                        TomlValue::String("warn".to_owned()),
                    ),
                    (
                        "unsafe_code".to_owned(),
                        TomlValue::String("deny".to_owned()),
                    ),
                    (
                        "unsafe_op_in_unsafe_fn".to_owned(),
                        TomlValue::String("deny".to_owned()),
                    ),
                    (
                        "unreachable_pub".to_owned(),
                        TomlValue::String("warn".to_owned()),
                    ),
                ])
            || clippy
                != &toml::map::Map::from_iter([(
                    "all".to_owned(),
                    TomlValue::String("warn".to_owned()),
                )])
        {
            return Err(PolicyError::new(
                "claw-config's generated-code lint exception changed",
            ));
        }
    } else {
        let lints = table(&manifest, "lints")?;
        if keys(lints) != expected_keys(&["workspace"])
            || lints.get("workspace").and_then(TomlValue::as_bool) != Some(true)
        {
            return Err(PolicyError::new(format!(
                "{path} lints must inherit exactly from workspace"
            )));
        }
    }
    validate_dependencies(&manifest, member, declared_members)?;
    if member == "crates/claw-security" {
        let obsolete = ["serde_yaml_ng", "toml"]
            .into_iter()
            .filter(|name| {
                ["dependencies", "dev-dependencies", "build-dependencies"]
                    .into_iter()
                    .any(|kind| {
                        manifest
                            .get(kind)
                            .and_then(TomlValue::as_table)
                            .is_some_and(|dependencies| dependencies.contains_key(*name))
                    })
            })
            .collect::<Vec<_>>();
        if !obsolete.is_empty() {
            return Err(PolicyError::new(format!(
                "claw-security retains obsolete mutable-policy dependencies: {obsolete:?}"
            )));
        }
    }
    Ok(name.to_owned())
}

/// Validates the declaratively extensible root workspace and member manifests.
pub fn validate_root_workspace(root: &SafeRoot) -> PolicyResult<RootWorkspace> {
    let manifest = parse_toml(root, ROOT_MANIFEST, DEFAULT_FILE_LIMIT)?;
    let root_table = manifest
        .as_table()
        .ok_or_else(|| PolicyError::new("root Cargo.toml must be a table"))?;
    if keys(root_table) != expected_keys(&["profile", "workspace"]) {
        return Err(PolicyError::new("root Cargo.toml top-level schema changed"));
    }
    let workspace = table(&manifest, "workspace")?;
    if keys(workspace)
        != expected_keys(&[
            "dependencies",
            "exclude",
            "lints",
            "members",
            "package",
            "resolver",
        ])
    {
        return Err(PolicyError::new("root workspace schema changed"));
    }
    if workspace.get("resolver").and_then(TomlValue::as_str) != Some("3")
        || workspace.get("exclude")
            != Some(&TomlValue::Array(vec![TomlValue::String(
                "desktop".to_owned(),
            )]))
    {
        return Err(PolicyError::new(
            "root workspace resolver/exclude policy changed",
        ));
    }
    let member_values = workspace
        .get("members")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| PolicyError::new("root workspace members are missing"))?;
    if member_values.is_empty() || member_values.len() > 512 {
        return Err(PolicyError::new("root workspace member count is invalid"));
    }
    let mut member_paths = Vec::with_capacity(member_values.len());
    for value in member_values {
        let value = value
            .as_str()
            .ok_or_else(|| PolicyError::new("root workspace member is not a string"))?;
        member_paths.push(normalized_member(value)?);
    }
    let mut sorted = member_paths.clone();
    sorted.sort();
    sorted.dedup();
    if member_paths != sorted {
        return Err(PolicyError::new(
            "root workspace members must be unique and sorted",
        ));
    }
    let declared = member_paths.iter().cloned().collect::<BTreeSet<_>>();
    let version = validate_workspace_package(workspace)?;
    validate_workspace_lints(workspace)?;
    validate_profile(&manifest)?;
    let workspace_dependencies = workspace
        .get("dependencies")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("root workspace dependencies are missing"))?;
    for (name, value) in workspace_dependencies {
        validate_dependency(name, value, "", &declared)?;
    }

    let mut members = BTreeMap::new();
    for member in &member_paths {
        let name = validate_member_manifest(root, member, &declared)?;
        if members.insert(member.clone(), name).is_some() {
            return Err(PolicyError::new("duplicate canonical root member"));
        }
    }
    Ok(RootWorkspace { members, version })
}

fn repository_inventory(root: &SafeRoot) -> PolicyResult<Vec<String>> {
    let inventory = root
        .list_all(MAX_REPOSITORY_FILES, MAX_REPOSITORY_BYTES)?
        .into_iter()
        .map(|entry| entry.relative)
        .collect::<Vec<_>>();
    validate_casefold_paths(&inventory)?;
    Ok(inventory)
}

fn canonical_lower_component(component: &str) -> PolicyResult<String> {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.contains(['/', '\\'])
        || component.chars().any(char::is_control)
    {
        return Err(PolicyError::new(format!(
            "repository path component is unsafe: {component:?}"
        )));
    }
    let normalized = canonical_caseless(component);
    if normalized.is_empty()
        || matches!(normalized.as_str(), "." | "..")
        || normalized.contains(['/', '\\'])
        || normalized.chars().any(char::is_control)
    {
        return Err(PolicyError::new(format!(
            "normalized repository path component is unsafe: {component:?}"
        )));
    }
    Ok(normalized)
}

fn register_portable_path(
    nodes: &mut BTreeMap<Vec<String>, (String, bool)>,
    path: &str,
) -> PolicyResult<()> {
    let components = path.split('/').collect::<Vec<_>>();
    let mut key = Vec::with_capacity(components.len());
    let mut original = String::new();
    for (index, component) in components.iter().enumerate() {
        key.push(canonical_lower_component(component)?);
        if !original.is_empty() {
            original.push('/');
        }
        original.push_str(component);
        let is_file = index + 1 == components.len();
        if let Some((previous, previous_is_file)) = nodes.get(&key) {
            if previous != &original || is_file || *previous_is_file {
                return Err(PolicyError::new(format!(
                    "repository contains a Unicode-normalized path collision: {previous:?} and {original:?}"
                )));
            }
        } else {
            nodes.insert(key.clone(), (original.clone(), is_file));
        }
    }
    Ok(())
}

/// Rejects portable Unicode/case aliases and collisions before another platform reinterprets them.
pub fn validate_casefold_paths(paths: &[String]) -> PolicyResult<()> {
    let mut portable_nodes = BTreeMap::new();
    for path in paths {
        register_portable_path(&mut portable_nodes, path)?;
        let components = path.split('/').map(canonical_caseless).collect::<Vec<_>>();
        if components
            .iter()
            .any(|component| component == "rust-toolchain")
        {
            return Err(PolicyError::new(format!(
                "legacy rust-toolchain basename is forbidden at every repository depth: {path:?}"
            )));
        }
        if is_codeowners_path_or_alias(path) && path != CODEOWNERS_PATH {
            return Err(PolicyError::new(format!(
                "alternate, aliased, or duplicate CODEOWNERS path is forbidden: {path:?}"
            )));
        }
        if is_non_ascii_security_path(path) {
            return Err(PolicyError::new(format!(
                "security-sensitive path contains non-ASCII filesystem aliases: {path:?}"
            )));
        }
        let file_name = path.rsplit('/').next().unwrap_or(path);
        let portable_name = canonical_caseless(file_name);
        for component in path.split('/') {
            if component.ends_with('.') || component.ends_with(' ') || component.contains(':') {
                return Err(PolicyError::new(format!(
                    "repository path is not portable to Windows/macOS: {path:?}"
                )));
            }
            let device = canonical_caseless(component.split('.').next().unwrap_or(component));
            if matches!(device.as_str(), "con" | "prn" | "aux" | "nul")
                || device.strip_prefix("com").is_some_and(|value| {
                    matches!(value, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                })
                || device.strip_prefix("lpt").is_some_and(|value| {
                    matches!(value, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
                })
            {
                return Err(PolicyError::new(format!(
                    "repository path uses a reserved Windows device name: {path:?}"
                )));
            }
        }
        for canonical in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "rustfmt.toml",
        ] {
            if portable_name == canonical_caseless(canonical) && file_name != canonical {
                return Err(PolicyError::new(format!(
                    "security-sensitive file uses a case alias: {path}"
                )));
            }
        }
        for (prefix, portable_prefix) in [
            (".github/workflows/", &[".github", "workflows"][..]),
            (
                ".github/trusted/desktop-supply-chain-policy/",
                &[".github", "trusted", "desktop-supply-chain-policy"][..],
            ),
            (".cargo/", &[".cargo"][..]),
            ("apps/", &["apps"][..]),
            ("crates/", &["crates"][..]),
            ("desktop/", &["desktop"][..]),
        ] {
            if components
                .iter()
                .map(String::as_str)
                .zip(portable_prefix.iter().copied())
                .all(|(actual, expected)| actual == expected)
                && components.len() >= portable_prefix.len()
                && !path.starts_with(prefix)
            {
                return Err(PolicyError::new(format!(
                    "security-sensitive directory uses a case alias: {path}"
                )));
            }
        }
        let in_cargo_directory = components
            .iter()
            .take(components.len().saturating_sub(1))
            .any(|component| component == ".cargo");
        if in_cargo_directory && matches!(portable_name.as_str(), "config" | "config.toml") {
            return Err(PolicyError::new(format!(
                "repository Cargo configuration is forbidden, including case aliases: {path}"
            )));
        }
    }
    Ok(())
}

/// Returns whether a non-ASCII path can alias a security-sensitive repository input.
#[must_use]
pub fn is_non_ascii_security_path(path: &str) -> bool {
    if path.is_ascii() {
        return false;
    }
    let parts = path.split('/').map(canonical_caseless).collect::<Vec<_>>();
    let file_name = parts.last().map(String::as_str).unwrap_or_default();
    let policy_name = is_codeowners_path_or_alias(path)
        || file_name.ends_with(".toml")
        || file_name.ends_with(".lock")
        || file_name.ends_with(".yml")
        || file_name.ends_with(".yaml")
        || file_name.contains("cargo")
        || file_name.contains("config")
        || file_name.contains("deny")
        || file_name.contains("audit")
        || file_name.contains("rust-toolchain")
        || file_name.contains("rustfmt");
    policy_name
        || parts.first().is_some_and(|part| part == ".cargo")
        || parts.starts_with(&[".github".to_owned(), "workflows".to_owned()])
        || parts.starts_with(&[
            ".github".to_owned(),
            "trusted".to_owned(),
            "desktop-supply-chain-policy".to_owned(),
        ])
        || parts.first().is_some_and(|part| part == "desktop") && parts.len() <= 4
        || parts
            .first()
            .is_some_and(|part| matches!(part.as_str(), "apps" | "crates"))
            && parts.len() <= 3
}

fn validate_manifest_and_lock_inventory(
    root: &SafeRoot,
    workspace: &RootWorkspace,
) -> PolicyResult<()> {
    let inventory = repository_inventory(root)?;
    let lockfiles = inventory
        .iter()
        .filter(|path| path.rsplit('/').next() == Some("Cargo.lock"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if lockfiles != ALLOWED_LOCKS.into_iter().map(str::to_owned).collect() {
        return Err(PolicyError::new(format!(
            "Cargo.lock inventory changed: {lockfiles:?}"
        )));
    }

    let mut expected_manifests = BTreeSet::from([
        ROOT_MANIFEST.to_owned(),
        DESKTOP_MANIFEST.to_owned(),
        APP_MANIFEST.to_owned(),
        TRUSTED_MANIFEST.to_owned(),
    ]);
    expected_manifests.extend(workspace.members.keys().map(|member| manifest_path(member)));
    let manifests = inventory
        .iter()
        .filter(|path| path.rsplit('/').next() == Some("Cargo.toml"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if manifests != expected_manifests {
        return Err(PolicyError::new(format!(
            "Cargo.toml inventory does not match declared root members: expected {expected_manifests:?}, found {manifests:?}"
        )));
    }

    let allowed_policy_files = BTreeSet::from([
        ".cargo/audit.toml",
        ".github/trusted/desktop-supply-chain-policy/deny.toml",
        "deny.toml",
        "desktop/deny.toml",
    ]);
    for path in &inventory {
        let file_name = path.rsplit('/').next().unwrap_or(path);
        let cargo_config = (path.starts_with(".cargo/") || path.contains("/.cargo/"))
            && matches!(file_name, "config" | "config.toml");
        let deny_like = (file_name.starts_with("deny") || file_name.starts_with(".deny"))
            && file_name.ends_with(".toml");
        let audit_like = file_name == "audit.toml";
        if cargo_config {
            return Err(PolicyError::new(format!(
                "repository Cargo configuration is forbidden: {path}"
            )));
        }
        if (deny_like || audit_like) && !allowed_policy_files.contains(path.as_str()) {
            return Err(PolicyError::new(format!(
                "unexpected deny/audit policy file: {path}"
            )));
        }
    }
    Ok(())
}

fn lock_packages(lock: &TomlValue) -> PolicyResult<&Vec<TomlValue>> {
    if lock.get("version").and_then(TomlValue::as_integer) != Some(4) {
        return Err(PolicyError::new("Cargo.lock version must be exactly 4"));
    }
    lock.get("package")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| PolicyError::new("Cargo.lock package array is missing"))
}

fn valid_checksum(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Validates evolving root lock sources, local packages, and no-GUI policy.
pub fn validate_root_lock(root: &SafeRoot, workspace: &RootWorkspace) -> PolicyResult<()> {
    let lock = parse_toml(root, ROOT_LOCK, MAX_LOCK_BYTES)?;
    let packages = lock_packages(&lock)?;
    let expected_local = workspace.members.values().cloned().collect::<BTreeSet<_>>();
    let mut actual_local = BTreeSet::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| PolicyError::new("Cargo.lock package name is missing"))?;
        if is_forbidden_gui(name) {
            return Err(PolicyError::new(format!(
                "root/headless lock contains forbidden GUI package: {name}"
            )));
        }
        match package.get("source").and_then(TomlValue::as_str) {
            Some("registry+https://github.com/rust-lang/crates.io-index") => {
                let checksum = package
                    .get("checksum")
                    .and_then(TomlValue::as_str)
                    .ok_or_else(|| {
                        PolicyError::new(format!("registry package lacks checksum: {name}"))
                    })?;
                if !valid_checksum(checksum) {
                    return Err(PolicyError::new(format!(
                        "registry package checksum is invalid: {name}"
                    )));
                }
            }
            Some(source) => {
                return Err(PolicyError::new(format!(
                    "root lock contains forbidden package source for {name}: {source}"
                )));
            }
            None => {
                if package.get("checksum").is_some()
                    || !actual_local.insert(name.to_owned())
                    || !expected_local.contains(name)
                    || package.get("version").and_then(TomlValue::as_str)
                        != Some(workspace.version.as_str())
                {
                    return Err(PolicyError::new(format!(
                        "root lock local package does not match declared workspace: {name}"
                    )));
                }
            }
        }
    }
    if actual_local != expected_local {
        return Err(PolicyError::new(format!(
            "root lock local packages differ from declared workspace: expected {expected_local:?}, found {actual_local:?}"
        )));
    }
    Ok(())
}

fn validate_desktop_lock(root: &SafeRoot) -> PolicyResult<()> {
    let lock = parse_toml(root, DESKTOP_LOCK, MAX_LOCK_BYTES)?;
    let packages = lock_packages(&lock)?;
    let mut names = BTreeSet::new();
    let expected_local = BTreeSet::from([
        "claw-application".to_owned(),
        "claw-domain".to_owned(),
        "claw-platform".to_owned(),
        "claw-protocol".to_owned(),
        "gta-claw-desktop".to_owned(),
    ]);
    let mut local_packages = BTreeSet::new();
    for package in packages {
        let name = package
            .get("name")
            .and_then(TomlValue::as_str)
            .ok_or_else(|| PolicyError::new("desktop lock package name is missing"))?;
        names.insert(name.to_owned());
        if package.get("source").is_none() {
            if !expected_local.contains(name)
                || !local_packages.insert(name.to_owned())
                || package.get("version").and_then(TomlValue::as_str) != Some("0.1.0")
                || package.get("checksum").is_some()
            {
                return Err(PolicyError::new(format!(
                    "desktop lock contains unexpected local package: {name}"
                )));
            }
        } else if package.get("source").and_then(TomlValue::as_str)
            != Some("registry+https://github.com/rust-lang/crates.io-index")
            || package
                .get("checksum")
                .and_then(TomlValue::as_str)
                .is_none_or(|checksum| !valid_checksum(checksum))
        {
            return Err(PolicyError::new(format!(
                "desktop lock contains forbidden or unchecksummed source: {name}"
            )));
        }
    }
    if local_packages != expected_local {
        return Err(PolicyError::new(format!(
            "desktop lock local package set changed: expected {expected_local:?}, found {local_packages:?}"
        )));
    }
    for required in ["slint", "i-slint-backend-winit", "winit"] {
        if !names.contains(required) {
            return Err(PolicyError::new(format!(
                "desktop lock lost required GUI package: {required}"
            )));
        }
    }
    let forbidden = names
        .iter()
        .filter(|name| {
            name.as_str() == "quick-xml"
                || name.contains("wayland")
                || name.starts_with("smithay")
                || matches!(
                    name.as_str(),
                    "calloop-wayland-source" | "sctk-adwaita" | "smithay-clipboard"
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    if !forbidden.is_empty() {
        return Err(PolicyError::new(format!(
            "desktop lock contains forbidden Wayland chain: {forbidden:?}"
        )));
    }
    Ok(())
}

fn validate_final_fixed_files(root: &SafeRoot) -> PolicyResult<()> {
    validate_codeowners(root)?;
    for (path, expected) in [
        ("deny.toml", FINAL_ROOT_DENY),
        (".cargo/audit.toml", ROOT_AUDIT),
        ("rust-toolchain.toml", ROOT_TOOLCHAIN),
        ("rustfmt.toml", ROOT_RUSTFMT),
        (".gitattributes", ROOT_GITATTRIBUTES),
        (DESKTOP_MANIFEST, FINAL_DESKTOP_MANIFEST),
        (APP_MANIFEST, FINAL_APP_MANIFEST),
        ("desktop/deny.toml", FINAL_DESKTOP_DENY),
        (
            "desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs",
            FINAL_SMOKE_TEST,
        ),
        (
            ".github/fixtures/cargo-audit/unmaintained/Cargo.lock.fixture",
            FINAL_AUDIT_WARNING,
        ),
        (
            ".github/fixtures/cargo-audit/vulnerable/Cargo.lock.fixture",
            FINAL_AUDIT_VULNERABLE,
        ),
    ] {
        require_exact_file(root, path, expected)?;
    }
    for (path, expected) in [
        (
            ".github/fixtures/security-tools/bash-env-poison.sh",
            FINAL_BASH_POISON,
        ),
        (
            ".github/fixtures/security-tools/shadow-bin/sha256sum",
            FINAL_SHA_POISON,
        ),
        (
            ".github/fixtures/security-tools/shadow-bin/tar",
            FINAL_TAR_POISON,
        ),
    ] {
        require_exact_lf_file(root, path, expected)?;
    }
    #[cfg(unix)]
    for path in [
        ".github/fixtures/security-tools/shadow-bin/sha256sum",
        ".github/fixtures/security-tools/shadow-bin/tar",
    ] {
        use std::os::unix::fs::PermissionsExt as _;
        let executable = root.regular_file(path, DEFAULT_FILE_LIMIT)?;
        let mode = fs::metadata(&executable)
            .map_err(|cause| error("inspect shadow tool permissions", cause))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(PolicyError::new(format!(
                "security shadow tool is not executable: {path}"
            )));
        }
    }
    if root.exists(LEGACY_VALIDATOR)? || root.exists(LEGACY_FIXTURES)? {
        return Err(PolicyError::new(
            "legacy candidate-controlled desktop policy validator/fixtures are forbidden",
        ));
    }
    for source in [
        "desktop/apps/gta-claw-desktop/src/main.rs",
        "desktop/apps/gta-claw-desktop/build.rs",
    ] {
        root.regular_file(source, DEFAULT_FILE_LIMIT)?;
    }
    validate_desktop_lock(root)
}

/// Performs complete static final-state validation.
pub fn validate_final_static(root: &SafeRoot) -> PolicyResult<RootWorkspace> {
    validate_final_fixed_files(root)?;
    let workspace = validate_root_workspace(root)?;
    validate_manifest_and_lock_inventory(root, &workspace)?;
    validate_root_lock(root, &workspace)?;
    Ok(workspace)
}

fn bootstrap_manifest_inventory(root: &SafeRoot) -> PolicyResult<bool> {
    let inventory = repository_inventory(root)?;
    let actual = inventory
        .iter()
        .filter(|path| path.rsplit('/').next() == Some("Cargo.toml"))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut expected = BOOTSTRAP_MEMBER_MANIFESTS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    expected.extend([
        ROOT_MANIFEST.to_owned(),
        DESKTOP_MANIFEST.to_owned(),
        APP_MANIFEST.to_owned(),
        TRUSTED_MANIFEST.to_owned(),
    ]);
    let locks = inventory
        .iter()
        .filter(|path| path.rsplit('/').next() == Some("Cargo.lock"))
        .cloned()
        .collect::<BTreeSet<_>>();
    Ok(actual == expected
        && locks == ALLOWED_LOCKS.into_iter().map(str::to_owned).collect()
        && !root.exists("desktop/deny.toml")?
        && !root.exists(".github/fixtures/cargo-audit")?
        && !root.exists(".github/fixtures/security-tools")?
        && !root.exists(LEGACY_VALIDATOR)?
        && !root.exists(LEGACY_FIXTURES)?)
}

/// Computes the exact pre-P04f product and trust-root workflow fingerprint.
pub fn bootstrap_fingerprint(root: &SafeRoot) -> PolicyResult<String> {
    let mut digest = Sha256::new();
    for path in BOOTSTRAP_FILES {
        digest.update(path.as_bytes());
        digest.update([0]);
        let bytes = root.read_bytes(path, MAX_LOCK_BYTES)?;
        digest.update(normalize_text(&bytes));
        digest.update([0]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Serializes the exact pre-P04f policy inputs into the canonical Bootstrap snapshot format.
pub fn bootstrap_snapshot(root: &SafeRoot) -> PolicyResult<Vec<u8>> {
    let file_count = u32::try_from(BOOTSTRAP_FILES.len())
        .map_err(|_| PolicyError::new("Bootstrap snapshot file count exceeds u32"))?;
    let mut snapshot = Vec::new();
    snapshot.extend_from_slice(BOOTSTRAP_SNAPSHOT_MAGIC);
    snapshot.extend_from_slice(&file_count.to_le_bytes());
    for path in BOOTSTRAP_FILES {
        let path_length = u32::try_from(path.len())
            .map_err(|_| PolicyError::new("Bootstrap snapshot path length exceeds u32"))?;
        let bytes = normalize_text(&root.read_bytes(path, MAX_LOCK_BYTES)?);
        let data_length = u64::try_from(bytes.len())
            .map_err(|_| PolicyError::new("Bootstrap snapshot file length exceeds u64"))?;
        snapshot.extend_from_slice(&path_length.to_le_bytes());
        snapshot.extend_from_slice(&data_length.to_le_bytes());
        snapshot.extend_from_slice(path.as_bytes());
        snapshot.extend_from_slice(&bytes);
    }
    Ok(snapshot)
}

/// Writes a canonical Bootstrap snapshot generated from trusted policy inputs.
pub fn write_bootstrap_snapshot(root: &SafeRoot, output: &Path) -> PolicyResult<()> {
    fs::write(output, bootstrap_snapshot(root)?)
        .map_err(|cause| error("write Bootstrap snapshot", cause))
}

/// Returns whether a checkout is the exact short-lived pre-P04f policy state.
pub fn is_bootstrap_state(root: &SafeRoot) -> PolicyResult<bool> {
    validate_codeowners(root)?;
    Ok(
        bootstrap_manifest_inventory(root)?
            && bootstrap_fingerprint(root)? == BOOTSTRAP_FINGERPRINT,
    )
}

/// Returns the configured bootstrap fingerprint constant.
#[must_use]
pub const fn expected_bootstrap_fingerprint() -> &'static str {
    BOOTSTRAP_FINGERPRINT
}

/// Returns the canonical final desktop lock bytes for deterministic fixture assembly.
#[must_use]
pub const fn canonical_desktop_lock() -> &'static [u8] {
    FINAL_DESKTOP_LOCK
}

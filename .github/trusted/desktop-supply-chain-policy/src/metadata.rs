//! Trusted Cargo metadata execution and exact package binding.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value as JsonValue;

use crate::input::{SafeRoot, sha256};
use crate::policy::RootWorkspace;
use crate::process::{CommandSpec, canonical_tool, run_checked};
use crate::{PolicyError, PolicyResult, error};

const MAX_TOOL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
const TARGET_EXPRESSION: &str = r#"cfg(any(target_os = "windows", target_os = "macos"))"#;
const CARGO_VERSION: &str = "cargo 1.94.0 (85eff7c80 2026-01-15)";
const RUSTC_VERSION_PREFIX: &str = "rustc 1.94.0 (4a4ef493e 2026-03-02)";
/// Official Rust 1.94.0 Linux Cargo binary SHA-256.
pub const LINUX_CARGO_SHA256: &str =
    "77f14b761b02b47e6747473f556b3bc9f98f7e4525b7c3b8d74898ff816e4636";
/// Official Rust 1.94.0 Linux rustc binary SHA-256.
pub const LINUX_RUSTC_SHA256: &str =
    "103b60e1b1339968c1d74202ea1d45686037e82c4ea3e0569de24b18a1e6836a";

/// Absolute checksum-pinned Rust tools used only for metadata.
#[derive(Debug, Clone)]
pub struct MetadataTools {
    /// Actual Cargo executable, not a rustup proxy.
    pub cargo: PathBuf,
    /// Actual rustc executable.
    pub rustc: PathBuf,
    /// Lowercase SHA-256 for Cargo.
    pub cargo_sha256: String,
    /// Lowercase SHA-256 for rustc.
    pub rustc_sha256: String,
}

/// Constructs the production Linux tool pins from base-owned constants.
#[must_use]
pub fn linux_tools(cargo: PathBuf, rustc: PathBuf) -> MetadataTools {
    MetadataTools {
        cargo,
        rustc,
        cargo_sha256: LINUX_CARGO_SHA256.to_owned(),
        rustc_sha256: LINUX_RUSTC_SHA256.to_owned(),
    }
}

fn read_tool(path: &Path) -> PolicyResult<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|cause| error("inspect trusted Rust tool", cause))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_TOOL_BYTES {
        return Err(PolicyError::new(format!(
            "trusted Rust tool is not a bounded regular file: {}",
            path.display()
        )));
    }
    fs::read(path).map_err(|cause| error("read trusted Rust tool", cause))
}

fn verify_version(
    tool: &Path,
    cwd: &Path,
    args: &[&str],
    expected: &str,
    prefix: bool,
) -> PolicyResult<()> {
    let output = run_checked(
        &CommandSpec::new(tool, cwd)?
            .args(args)
            .env("LC_ALL", "C")
            .timeout(Duration::from_secs(10))
            .output_limits(64 * 1024, 64 * 1024),
        "trusted Rust tool version",
    )?;
    if !output.stderr.is_empty() {
        return Err(PolicyError::new(format!(
            "trusted Rust tool version wrote stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let version = std::str::from_utf8(&output.stdout)
        .map_err(|cause| error("decode trusted Rust tool version", cause))?
        .trim();
    let matches = if prefix {
        version.starts_with(expected)
    } else {
        version == expected
    };
    if !matches {
        return Err(PolicyError::new(format!(
            "trusted Rust tool version mismatch: expected {expected:?}, found {version:?}"
        )));
    }
    Ok(())
}

/// Verifies trusted Cargo/rustc canonical paths, checksums, and exact releases.
pub fn verify_tools(tools: &MetadataTools, cwd: &Path) -> PolicyResult<(PathBuf, PathBuf)> {
    let cargo = canonical_tool(&tools.cargo)?;
    let rustc = canonical_tool(&tools.rustc)?;
    let cargo_digest = sha256(&read_tool(&cargo)?);
    let rustc_digest = sha256(&read_tool(&rustc)?);
    if cargo_digest != tools.cargo_sha256 {
        return Err(PolicyError::new(format!(
            "trusted Cargo checksum mismatch: expected {}, found {cargo_digest}",
            tools.cargo_sha256
        )));
    }
    if rustc_digest != tools.rustc_sha256 {
        return Err(PolicyError::new(format!(
            "trusted rustc checksum mismatch: expected {}, found {rustc_digest}",
            tools.rustc_sha256
        )));
    }
    verify_version(&cargo, cwd, &["--version"], CARGO_VERSION, false)?;
    verify_version(&rustc, cwd, &["-Vv"], RUSTC_VERSION_PREFIX, true)?;
    Ok((cargo, rustc))
}

fn prepare_isolation(root: &Path, label: &str) -> PolicyResult<MetadataIsolation> {
    if !root.is_absolute() {
        return Err(PolicyError::new("metadata isolation root must be absolute"));
    }
    let base = root.join(label);
    if base.exists() {
        fs::remove_dir_all(&base)
            .map_err(|cause| error("remove prior metadata isolation", cause))?;
    }
    let isolation = MetadataIsolation {
        home: base.join("home"),
        cargo_home: base.join("cargo-home"),
        rustup_home: base.join("rustup-home"),
        target: base.join("target"),
        temp: base.join("temp"),
        cwd: base.join("cwd"),
    };
    for directory in [
        &isolation.home,
        &isolation.cargo_home,
        &isolation.rustup_home,
        &isolation.target,
        &isolation.temp,
        &isolation.cwd,
    ] {
        fs::create_dir_all(directory)
            .map_err(|cause| error("create metadata isolation directory", cause))?;
    }
    Ok(isolation)
}

struct MetadataIsolation {
    home: PathBuf,
    cargo_home: PathBuf,
    rustup_home: PathBuf,
    target: PathBuf,
    temp: PathBuf,
    cwd: PathBuf,
}

fn run_metadata(
    candidate: &SafeRoot,
    manifest: &str,
    tools: &MetadataTools,
    isolation_root: &Path,
    label: &str,
) -> PolicyResult<(JsonValue, MetadataIsolation)> {
    let isolation = prepare_isolation(isolation_root, label)?;
    let (cargo, rustc) = verify_tools(tools, &isolation.cwd)?;
    let manifest = candidate.regular_file(manifest, 4 * 1024 * 1024)?;
    let spec = CommandSpec::new(cargo, &isolation.cwd)?
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(&manifest)
        .env("HOME", &isolation.home)
        .env("CARGO_HOME", &isolation.cargo_home)
        .env("RUSTUP_HOME", &isolation.rustup_home)
        .env("CARGO_TARGET_DIR", &isolation.target)
        .env("CARGO_NET_OFFLINE", "true")
        .env("RUSTC", rustc)
        .env("TMPDIR", &isolation.temp)
        .env("TEMP", &isolation.temp)
        .env("TMP", &isolation.temp)
        .env("LC_ALL", "C")
        .timeout(Duration::from_secs(30))
        .output_limits(MAX_METADATA_BYTES, 512 * 1024);
    #[cfg(windows)]
    let spec = spec.env("USERPROFILE", &isolation.home);
    let output = run_checked(&spec, "trusted Cargo metadata")?;
    if !output.stderr.is_empty() {
        return Err(PolicyError::new(format!(
            "trusted Cargo metadata wrote unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let metadata: JsonValue = serde_json::from_slice(&output.stdout)
        .map_err(|cause| error("parse trusted Cargo metadata", cause))?;
    Ok((metadata, isolation))
}

fn object<'a>(
    value: &'a JsonValue,
    label: &str,
) -> PolicyResult<&'a serde_json::Map<String, JsonValue>> {
    value
        .as_object()
        .ok_or_else(|| PolicyError::new(format!("{label} must be a JSON object")))
}

fn array<'a>(value: &'a JsonValue, label: &str) -> PolicyResult<&'a Vec<JsonValue>> {
    value
        .as_array()
        .ok_or_else(|| PolicyError::new(format!("{label} must be a JSON array")))
}

fn text<'a>(value: Option<&'a JsonValue>, label: &str) -> PolicyResult<&'a str> {
    value
        .and_then(JsonValue::as_str)
        .ok_or_else(|| PolicyError::new(format!("{label} must be a JSON string")))
}

fn canonical_metadata_path(value: &str, label: &str) -> PolicyResult<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(PolicyError::new(format!(
            "{label} is not an absolute path: {value}"
        )));
    }
    fs::canonicalize(&path).map_err(|cause| error(&format!("canonicalize {label}"), cause))
}

fn require_path(
    value: &str,
    expected: &Path,
    candidate: &SafeRoot,
    label: &str,
) -> PolicyResult<()> {
    let actual = canonical_metadata_path(value, label)?;
    let expected = fs::canonicalize(expected)
        .map_err(|cause| error(&format!("canonicalize {label}"), cause))?;
    if actual != expected || !actual.starts_with(candidate.path()) {
        return Err(PolicyError::new(format!(
            "{label} escaped or changed: expected {}, found {}",
            expected.display(),
            actual.display()
        )));
    }
    Ok(())
}

fn string_array(value: Option<&JsonValue>, label: &str) -> PolicyResult<Vec<String>> {
    array(
        value.ok_or_else(|| PolicyError::new(format!("{label} is missing")))?,
        label,
    )?
    .iter()
    .map(|entry| {
        entry
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| PolicyError::new(format!("{label} contains a non-string")))
    })
    .collect()
}

fn require_package_metadata(
    package: &serde_json::Map<String, JsonValue>,
    expected_name: &str,
    expected_version: &str,
) -> PolicyResult<()> {
    for (key, expected) in [
        ("name", expected_name),
        ("version", expected_version),
        ("edition", "2024"),
        ("rust_version", "1.94.0"),
        ("license", "MIT"),
        ("repository", "https://github.com/GTAStudio/GTA-Claw"),
    ] {
        if text(package.get(key), key)? != expected {
            return Err(PolicyError::new(format!(
                "Cargo metadata package {key} changed"
            )));
        }
    }
    if !package.get("source").is_some_and(JsonValue::is_null) {
        return Err(PolicyError::new(
            "Cargo metadata workspace package unexpectedly has a source",
        ));
    }
    Ok(())
}

fn require_target(
    target: &serde_json::Map<String, JsonValue>,
    candidate: &SafeRoot,
    name: &str,
    kind: &str,
    source: &str,
    doc: bool,
    test: bool,
) -> PolicyResult<()> {
    if text(target.get("name"), "target.name")? != name
        || string_array(target.get("kind"), "target.kind")? != [kind]
        || string_array(target.get("crate_types"), "target.crate_types")? != ["bin"]
        || text(target.get("edition"), "target.edition")? != "2024"
        || target.get("doc").and_then(JsonValue::as_bool) != Some(doc)
        || target.get("test").and_then(JsonValue::as_bool) != Some(test)
        || target.get("doctest").and_then(JsonValue::as_bool) != Some(false)
    {
        return Err(PolicyError::new(format!(
            "Cargo metadata target identity changed: {name}"
        )));
    }
    require_path(
        text(target.get("src_path"), "target.src_path")?,
        &candidate.path().join(source),
        candidate,
        "target source path",
    )
}

fn require_desktop_dependencies(
    package: &serde_json::Map<String, JsonValue>,
    candidate: &SafeRoot,
) -> PolicyResult<()> {
    let dependencies = array(
        package
            .get("dependencies")
            .ok_or_else(|| PolicyError::new("desktop metadata dependencies are missing"))?,
        "desktop dependencies",
    )?;
    if dependencies.len() != 4 {
        return Err(PolicyError::new(format!(
            "desktop metadata dependency count changed: {}",
            dependencies.len()
        )));
    }
    let mut seen = BTreeSet::new();
    for dependency in dependencies {
        let dependency = object(dependency, "desktop dependency")?;
        let name = text(dependency.get("name"), "dependency.name")?;
        if !seen.insert(name.to_owned())
            || dependency
                .get("rename")
                .is_some_and(|value| !value.is_null())
            || dependency.get("optional").and_then(JsonValue::as_bool) != Some(false)
            || text(dependency.get("target"), "dependency.target")? != TARGET_EXPRESSION
            || dependency
                .get("registry")
                .is_some_and(|value| !value.is_null())
        {
            return Err(PolicyError::new(format!(
                "desktop metadata dependency controls changed: {name}"
            )));
        }
        match name {
            "claw-application" | "claw-platform" => {
                if dependency
                    .get("source")
                    .is_some_and(|value| !value.is_null())
                    || text(dependency.get("req"), "dependency.req")? != "^0.1.0"
                    || dependency.get("kind").is_some_and(|value| !value.is_null())
                    || dependency
                        .get("uses_default_features")
                        .and_then(JsonValue::as_bool)
                        != Some(true)
                    || !string_array(dependency.get("features"), "dependency.features")?.is_empty()
                {
                    return Err(PolicyError::new(format!(
                        "desktop local dependency metadata changed: {name}"
                    )));
                }
                let expected = candidate.path().join("crates").join(name);
                require_path(
                    text(dependency.get("path"), "dependency.path")?,
                    &expected,
                    candidate,
                    "desktop local dependency path",
                )?;
            }
            "slint" => {
                if text(dependency.get("source"), "slint.source")?
                    != "registry+https://github.com/rust-lang/crates.io-index"
                    || text(dependency.get("req"), "slint.req")? != "=1.17.1"
                    || dependency.get("kind").is_some_and(|value| !value.is_null())
                    || dependency.get("path").is_some_and(|value| !value.is_null())
                    || dependency
                        .get("uses_default_features")
                        .and_then(JsonValue::as_bool)
                        != Some(false)
                    || string_array(dependency.get("features"), "slint.features")?
                        != [
                            "accessibility",
                            "backend-winit-x11",
                            "compat-1-2",
                            "renderer-femtovg",
                            "renderer-software",
                            "std",
                        ]
                {
                    return Err(PolicyError::new("desktop Slint metadata changed"));
                }
            }
            "slint-build" => {
                if text(dependency.get("source"), "slint-build.source")?
                    != "registry+https://github.com/rust-lang/crates.io-index"
                    || text(dependency.get("req"), "slint-build.req")? != "=1.17.1"
                    || text(dependency.get("kind"), "slint-build.kind")? != "build"
                    || dependency.get("path").is_some_and(|value| !value.is_null())
                    || dependency
                        .get("uses_default_features")
                        .and_then(JsonValue::as_bool)
                        != Some(true)
                    || !string_array(dependency.get("features"), "slint-build.features")?.is_empty()
                {
                    return Err(PolicyError::new("desktop slint-build metadata changed"));
                }
            }
            _ => {
                return Err(PolicyError::new(format!(
                    "unexpected desktop metadata dependency: {name}"
                )));
            }
        }
    }
    Ok(())
}

/// Runs and verifies exact locked desktop package metadata.
pub fn validate_desktop_metadata(
    candidate: &SafeRoot,
    tools: &MetadataTools,
    isolation_root: &Path,
) -> PolicyResult<()> {
    let (metadata, isolation) = run_metadata(
        candidate,
        "desktop/Cargo.toml",
        tools,
        isolation_root,
        "desktop-metadata",
    )?;
    validate_desktop_metadata_value(candidate, &metadata, &isolation.target)
}

fn validate_desktop_metadata_value(
    candidate: &SafeRoot,
    metadata: &JsonValue,
    expected_target_path: &Path,
) -> PolicyResult<()> {
    let root = object(metadata, "desktop metadata")?;
    require_path(
        text(root.get("workspace_root"), "workspace_root")?,
        &candidate.path().join("desktop"),
        candidate,
        "desktop workspace root",
    )?;
    let target_directory = canonical_metadata_path(
        text(root.get("target_directory"), "target_directory")?,
        "target directory",
    )?;
    let expected_target = fs::canonicalize(expected_target_path)
        .map_err(|cause| error("canonicalize target", cause))?;
    if target_directory != expected_target {
        return Err(PolicyError::new(format!(
            "Cargo metadata target directory changed: expected {}, found {}",
            expected_target.display(),
            target_directory.display()
        )));
    }
    let packages = array(
        root.get("packages")
            .ok_or_else(|| PolicyError::new("metadata packages are missing"))?,
        "metadata packages",
    )?;
    if packages.len() != 1 {
        return Err(PolicyError::new(
            "desktop metadata must contain exactly one package",
        ));
    }
    let package = object(&packages[0], "desktop package")?;
    require_package_metadata(package, "gta-claw-desktop", "0.1.0")?;
    require_path(
        text(package.get("manifest_path"), "manifest_path")?,
        &candidate
            .path()
            .join("desktop/apps/gta-claw-desktop/Cargo.toml"),
        candidate,
        "desktop package manifest",
    )?;
    let id = text(package.get("id"), "package.id")?;
    for key in ["workspace_members", "workspace_default_members"] {
        if string_array(root.get(key), key)? != [id] {
            return Err(PolicyError::new(format!(
                "desktop metadata {key} must contain only the selected package"
            )));
        }
    }
    let targets = array(
        package
            .get("targets")
            .ok_or_else(|| PolicyError::new("desktop targets are missing"))?,
        "desktop targets",
    )?;
    if targets.len() != 3 {
        return Err(PolicyError::new(
            "desktop metadata must expose exactly three targets",
        ));
    }
    let mut by_name = BTreeMap::new();
    for target in targets {
        let target = object(target, "desktop target")?;
        let name = text(target.get("name"), "target.name")?.to_owned();
        if by_name.insert(name.clone(), target).is_some() {
            return Err(PolicyError::new(format!(
                "duplicate desktop metadata target: {name}"
            )));
        }
    }
    require_target(
        by_name
            .get("gta-claw-desktop")
            .ok_or_else(|| PolicyError::new("desktop bin target is missing"))?,
        candidate,
        "gta-claw-desktop",
        "bin",
        "desktop/apps/gta-claw-desktop/src/main.rs",
        true,
        true,
    )?;
    require_target(
        by_name
            .get("macos_winit_smoke")
            .ok_or_else(|| PolicyError::new("desktop smoke target is missing"))?,
        candidate,
        "macos_winit_smoke",
        "test",
        "desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs",
        false,
        true,
    )?;
    require_target(
        by_name
            .get("build-script-build")
            .ok_or_else(|| PolicyError::new("desktop build-script target is missing"))?,
        candidate,
        "build-script-build",
        "custom-build",
        "desktop/apps/gta-claw-desktop/build.rs",
        false,
        false,
    )?;
    require_desktop_dependencies(package, candidate)
}

/// Verifies an already bounded metadata document for adversarial parser tests.
pub fn validate_desktop_metadata_document(
    candidate: &SafeRoot,
    expected_target: &Path,
    document: &[u8],
) -> PolicyResult<()> {
    if document.len() > MAX_METADATA_BYTES {
        return Err(PolicyError::new(
            "metadata test document exceeds the production output bound",
        ));
    }
    let metadata: JsonValue = serde_json::from_slice(document)
        .map_err(|cause| error("parse bounded metadata document", cause))?;
    validate_desktop_metadata_value(candidate, &metadata, expected_target)
}

/// Runs and verifies the declared extensible root member metadata.
pub fn validate_root_metadata(
    candidate: &SafeRoot,
    workspace: &RootWorkspace,
    tools: &MetadataTools,
    isolation_root: &Path,
) -> PolicyResult<()> {
    let (metadata, _) = run_metadata(
        candidate,
        "Cargo.toml",
        tools,
        isolation_root,
        "root-metadata",
    )?;
    let root = object(&metadata, "root metadata")?;
    require_path(
        text(root.get("workspace_root"), "workspace_root")?,
        candidate.path(),
        candidate,
        "root workspace root",
    )?;
    let packages = array(
        root.get("packages")
            .ok_or_else(|| PolicyError::new("root metadata packages are missing"))?,
        "root packages",
    )?;
    if packages.len() != workspace.members.len() {
        return Err(PolicyError::new(format!(
            "root metadata package count differs from declared members: expected {}, found {}",
            workspace.members.len(),
            packages.len()
        )));
    }
    let mut ids = BTreeSet::new();
    let mut manifests = BTreeSet::new();
    for package in packages {
        let package = object(package, "root package")?;
        let name = text(package.get("name"), "package.name")?;
        require_package_metadata(package, name, &workspace.version)?;
        let manifest = canonical_metadata_path(
            text(package.get("manifest_path"), "manifest_path")?,
            "root member manifest",
        )?;
        if !manifest.starts_with(candidate.path()) {
            return Err(PolicyError::new(
                "root metadata member manifest escaped candidate root",
            ));
        }
        let relative = manifest
            .strip_prefix(candidate.path())
            .map_err(|cause| error("strip root metadata prefix", cause))?
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if !manifests.insert(relative) {
            return Err(PolicyError::new("duplicate root metadata member manifest"));
        }
        ids.insert(text(package.get("id"), "package.id")?.to_owned());
    }
    let expected_manifests = workspace
        .members
        .keys()
        .map(|member| format!("{member}/Cargo.toml"))
        .collect::<BTreeSet<_>>();
    if manifests != expected_manifests {
        return Err(PolicyError::new(format!(
            "root metadata manifests differ from declared members: expected {expected_manifests:?}, found {manifests:?}"
        )));
    }
    for key in ["workspace_members", "workspace_default_members"] {
        let actual = string_array(root.get(key), key)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        if actual != ids {
            return Err(PolicyError::new(format!(
                "root metadata {key} differs from declared package IDs"
            )));
        }
    }
    Ok(())
}

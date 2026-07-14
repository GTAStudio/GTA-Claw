//! Structured policy checks for the isolated desktop dependency graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};
use sha2::{Digest as _, Sha256};
use toml::Value as TomlValue;

const CARGO_AUDIT_VERSION: &str = "0.22.2";
const CARGO_AUDIT_CRATE_SHA256: &str =
    "700c2b240f7fd330c24b675fe429f73a5b676531fcc6300400b2b67f155ba12a";
const CARGO_DENY_VERSION: &str = "0.19.8";
const CARGO_DENY_ARCHIVE_SHA256: &str =
    "70e769ae3872e34d45132b17040859175e11401dc12dddb0303e0b8c7d088f3f";
const BOOTSTRAP_SCRIPT_SHA256: &str =
    "9318742e5473d235750a4c43297402babcbf8114e819dce5fb8838d1e1868653";
const AUDIT_EXIT_SCRIPT_SHA256: &str =
    "36b83e225e3849976c16b0e98f1269d24dfcdf89bc984f8914251dd3776f0a43";
const DENY_FIXTURE_SCRIPT_SHA256: &str =
    "c03d1a213671dfb73836adb8594978e39225ef45ea7c2f8d638d3dc35993e127";
const MACOS_RECORD_SCRIPT_SHA256: &str =
    "5d7c2eb2241919d19612f161b0bc35b9bf7e13c90205b1d44140c42922e2a513";
const MACOS_FORMAT_SCRIPT_SHA256: &str =
    "fd19669dd4face53ea143acb053afa5338657adfec97062bfb2371730367a631";
const MACOS_CHECK_SCRIPT_SHA256: &str =
    "3f37cbd23204a0e0ef83ab76f4bbd5390825eb41184d9bd4f571dce196da59c8";
const MACOS_CLIPPY_SCRIPT_SHA256: &str =
    "e23592c7931ce01185ab6260a14d3ae5a2414b22ff0221cc92174d486732a9ef";
const MACOS_TEST_SCRIPT_SHA256: &str =
    "3590a27ce767f332c4bfb5dfd34b959f2466e8b52642295590df1f9a228a7034";
const MACOS_BUILD_SCRIPT_SHA256: &str =
    "e34abe22fd87e8032c969a208ef418af014923ea36bb81f5ae90405e1817babc";
const MACOS_SELF_TEST_SCRIPT_SHA256: &str =
    "27d2be31ba5aa3ca97a37a715160d51724e22f660e90b418c96c02506b23fd8c";
const MACOS_SCAN_SCRIPT_SHA256: &str =
    "68f70456ef8bb868de33837ddc4f7f1db1e444bb56e7adff4eadf239cc5c964f";
const MACOS_SOURCE_SHELL_SCRIPT_SHA256: &str =
    "890ca42f80b5901969f5f2457a601624a7657c4ac33730ffbd48fa018db92823";
const MACOS_SOURCE_LINUX_SCRIPT_SHA256: &str =
    "ea0a1b4c38f9cd511907bc2129f0078c29303dd1823752dfe464e8a5e6888ca8";
const DENY_EXCEPTION_PATHS: [&str; 6] = [
    "deny.exceptions.toml",
    ".deny.exceptions.toml",
    ".cargo/deny.exceptions.toml",
    "desktop/deny.exceptions.toml",
    "desktop/.deny.exceptions.toml",
    "desktop/.cargo/deny.exceptions.toml",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate is under workspace/crates")
        .to_path_buf()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn sha256_text(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

fn parse_yaml(path: &Path) -> YamlValue {
    serde_yaml_ng::from_str(&read(path))
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn parse_toml(path: &Path) -> TomlValue {
    toml::from_str(&read(path)).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn deny_exception_files(root: &Path) -> Vec<String> {
    DENY_EXCEPTION_PATHS
        .iter()
        .filter(|relative| root.join(relative).is_file())
        .map(|relative| (*relative).to_owned())
        .collect()
}

fn yaml_key(key: &str) -> YamlValue {
    YamlValue::String(key.to_owned())
}

fn yaml_mapping(value: &YamlValue) -> Option<&YamlMapping> {
    if let YamlValue::Mapping(mapping) = value {
        Some(mapping)
    } else {
        None
    }
}

fn yaml_mapping_mut(value: &mut YamlValue) -> Option<&mut YamlMapping> {
    if let YamlValue::Mapping(mapping) = value {
        Some(mapping)
    } else {
        None
    }
}

fn yaml_get<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    yaml_mapping(value)?.get(yaml_key(key))
}

fn yaml_get_mut<'a>(value: &'a mut YamlValue, key: &str) -> Option<&'a mut YamlValue> {
    yaml_mapping_mut(value)?.get_mut(yaml_key(key))
}

fn yaml_string(value: Option<&YamlValue>) -> Option<&str> {
    if let Some(YamlValue::String(value)) = value {
        Some(value)
    } else {
        None
    }
}

fn yaml_bool(value: Option<&YamlValue>) -> Option<bool> {
    if let Some(YamlValue::Bool(value)) = value {
        Some(*value)
    } else {
        None
    }
}

fn yaml_sequence(value: Option<&YamlValue>) -> Option<&Vec<YamlValue>> {
    if let Some(YamlValue::Sequence(sequence)) = value {
        Some(sequence)
    } else {
        None
    }
}

fn yaml_sequence_mut(value: Option<&mut YamlValue>) -> Option<&mut Vec<YamlValue>> {
    if let Some(YamlValue::Sequence(sequence)) = value {
        Some(sequence)
    } else {
        None
    }
}

fn job_steps<'a>(workflow: &'a YamlValue, job: &str) -> Option<&'a Vec<YamlValue>> {
    yaml_sequence(yaml_get(
        yaml_get(yaml_get(workflow, "jobs")?, job)?,
        "steps",
    ))
}

fn job_steps_mut<'a>(workflow: &'a mut YamlValue, job: &str) -> Option<&'a mut Vec<YamlValue>> {
    yaml_sequence_mut(yaml_get_mut(
        yaml_get_mut(yaml_get_mut(workflow, "jobs")?, job)?,
        "steps",
    ))
}

fn step_by_name<'a>(workflow: &'a YamlValue, job: &str, name: &str) -> Option<&'a YamlValue> {
    job_steps(workflow, job)?
        .iter()
        .find(|step| yaml_string(yaml_get(step, "name")) == Some(name))
}

fn step_by_name_mut<'a>(
    workflow: &'a mut YamlValue,
    job: &str,
    name: &str,
) -> Option<&'a mut YamlValue> {
    job_steps_mut(workflow, job)?
        .iter_mut()
        .find(|step| yaml_string(yaml_get(step, "name")) == Some(name))
}

fn yaml_string_set(value: Option<&YamlValue>) -> Option<BTreeSet<String>> {
    yaml_sequence(value)?
        .iter()
        .map(|entry| yaml_string(Some(entry)).map(str::to_owned))
        .collect::<Option<_>>()
}

fn yaml_string_list(value: Option<&YamlValue>) -> Option<Vec<String>> {
    yaml_sequence(value)?
        .iter()
        .map(|entry| yaml_string(Some(entry)).map(str::to_owned))
        .collect::<Option<_>>()
}

fn yaml_string_map(value: Option<&YamlValue>) -> Option<BTreeMap<String, String>> {
    yaml_mapping(value?)?
        .iter()
        .map(|(key, value)| {
            Some((
                yaml_string(Some(key))?.to_owned(),
                yaml_string(Some(value))?.to_owned(),
            ))
        })
        .collect::<Option<_>>()
}

fn yaml_mapping_keys(value: Option<&YamlValue>) -> Option<BTreeSet<String>> {
    yaml_mapping(value?)?
        .keys()
        .map(|key| yaml_string(Some(key)).map(str::to_owned))
        .collect::<Option<_>>()
}

fn toml_string_set(value: Option<&TomlValue>) -> Option<BTreeSet<String>> {
    value
        .and_then(TomlValue::as_array)?
        .iter()
        .map(|entry| entry.as_str().map(str::to_owned))
        .collect::<Option<_>>()
}

fn expected_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn validate_critical_step(step: &YamlValue, label: &str, errors: &mut Vec<String>) {
    if yaml_get(step, "if").is_some() {
        errors.push(format!("{label} must not have an if condition"));
    }
    if yaml_get(step, "continue-on-error").is_some() {
        errors.push(format!("{label} must not set continue-on-error"));
    }
}

fn validate_permissions(workflow: &YamlValue, errors: &mut Vec<String>) {
    let Some(permissions) = yaml_get(workflow, "permissions").and_then(yaml_mapping) else {
        errors.push("workflow permissions must be an explicit mapping".to_owned());
        return;
    };
    let actual = permissions
        .iter()
        .filter_map(|(key, value)| {
            Some((
                yaml_string(Some(key))?.to_owned(),
                yaml_string(Some(value))?.to_owned(),
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let expected = BTreeMap::from([("contents".to_owned(), "read".to_owned())]);
    if actual != expected {
        errors.push(format!(
            "workflow permissions must be exactly contents: read, found {actual:?}"
        ));
    }

    let Some(jobs) = yaml_get(workflow, "jobs").and_then(yaml_mapping) else {
        errors.push("workflow jobs must be a mapping".to_owned());
        return;
    };
    let allowed = [
        BTreeMap::from([("contents".to_owned(), "read".to_owned())]),
        BTreeMap::from([
            ("actions".to_owned(), "read".to_owned()),
            ("contents".to_owned(), "read".to_owned()),
        ]),
    ];
    for (job_name, job) in jobs {
        let Some(permissions_value) = yaml_get(job, "permissions") else {
            continue;
        };
        let Some(permissions) = yaml_mapping(permissions_value) else {
            errors.push(format!(
                "job {} permissions must be a read-only mapping",
                yaml_string(Some(job_name)).unwrap_or("<unknown>")
            ));
            continue;
        };
        let actual = permissions
            .iter()
            .filter_map(|(key, value)| {
                Some((
                    yaml_string(Some(key))?.to_owned(),
                    yaml_string(Some(value))?.to_owned(),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        if !allowed.contains(&actual) {
            errors.push(format!(
                "job {} permissions exceed read-only allow-list: {actual:?}",
                yaml_string(Some(job_name)).unwrap_or("<unknown>")
            ));
        }
    }
}

fn validate_workflow_paths(workflow: &YamlValue, errors: &mut Vec<String>) {
    let Some(events) = yaml_get(workflow, "on") else {
        errors.push("workflow must declare on triggers".to_owned());
        return;
    };
    let expected_paths = [
        ".cargo/**",
        ".gitattributes",
        ".github/fixtures/cargo-audit/**",
        ".github/workflows/macos-packaging.yml",
        ".github/workflows/rust.yml",
        "apps/**",
        "crates/**",
        "desktop/**",
        "Cargo.lock",
        "Cargo.toml",
        ".deny*.toml",
        "deny*.toml",
        "rust-toolchain.toml",
        "rustfmt.toml",
    ]
    .map(str::to_owned)
    .to_vec();
    for event in ["push", "pull_request"] {
        let actual = yaml_string_list(yaml_get(
            yaml_get(events, event).unwrap_or(&YamlValue::Null),
            "paths",
        ));
        if actual.as_ref() != Some(&expected_paths) {
            errors.push(format!(
                "{event} paths must exactly match the ordered dependency policy inputs"
            ));
        }
    }
    let push_branches = yaml_string_set(yaml_get(
        yaml_get(events, "push").unwrap_or(&YamlValue::Null),
        "branches",
    ));
    if push_branches
        .as_ref()
        .is_none_or(|branches| branches != &expected_set(&["main"]))
    {
        errors.push("push branches must be exactly main".to_owned());
    }
}

fn validate_action_pins(workflow: &YamlValue, errors: &mut Vec<String>) {
    let Some(jobs) = yaml_get(workflow, "jobs").and_then(yaml_mapping) else {
        errors.push("workflow jobs must be a mapping".to_owned());
        return;
    };
    for job in jobs.values() {
        let Some(steps) = yaml_sequence(yaml_get(job, "steps")) else {
            continue;
        };
        for step in steps {
            let Some(action) = yaml_string(yaml_get(step, "uses")) else {
                continue;
            };
            if action.starts_with("./") {
                continue;
            }
            let Some((_, revision)) = action.rsplit_once('@') else {
                errors.push(format!("action is not revision pinned: {action}"));
                continue;
            };
            if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                errors.push(format!("action is not pinned to a full commit: {action}"));
            }
            if action.starts_with("actions/checkout@")
                && yaml_bool(yaml_get(
                    yaml_get(step, "with").unwrap_or(&YamlValue::Null),
                    "persist-credentials",
                )) != Some(false)
            {
                errors.push("every checkout must set persist-credentials: false".to_owned());
            }
            if action.starts_with("rustsec/audit-check@") {
                errors.push("raw audits must not use the Check API reporter".to_owned());
            }
        }
    }
}

fn validate_exact_run_step(
    workflow: &YamlValue,
    name: &str,
    expected_run: &str,
    errors: &mut Vec<String>,
) {
    let Some(step) = step_by_name(workflow, "supply-chain", name) else {
        errors.push(format!("missing {name} step"));
        return;
    };
    validate_critical_step(step, name, errors);
    if yaml_string(yaml_get(step, "run")) != Some(expected_run) {
        errors.push(format!("{name} command is not exact"));
    }
    if yaml_get(step, "uses").is_some() {
        errors.push(format!("{name} must run the raw CLI"));
    }
    if yaml_get(step, "working-directory").is_some() {
        errors.push(format!("{name} must not set working-directory"));
    }
}

fn validate_step_keys(step: &YamlValue, label: &str, expected: &[&str], errors: &mut Vec<String>) {
    if yaml_mapping_keys(Some(step)) != Some(expected_set(expected)) {
        errors.push(format!("{label} step schema changed"));
    }
}

fn validate_script_hash(step: &YamlValue, label: &str, expected: &str, errors: &mut Vec<String>) {
    let actual = yaml_string(yaml_get(step, "run"))
        .map(sha256_text)
        .unwrap_or_default();
    if actual != expected {
        errors.push(format!("{label} script hash changed: {actual}"));
    }
}

fn validate_supply_chain_job(workflow: &YamlValue, errors: &mut Vec<String>) {
    let Some(job) = yaml_get(workflow, "jobs").and_then(|jobs| yaml_get(jobs, "supply-chain"))
    else {
        errors.push("missing supply-chain job".to_owned());
        return;
    };
    if yaml_mapping_keys(Some(job)) != Some(expected_set(&["name", "runs-on", "steps"])) {
        errors.push("supply-chain job schema changed".to_owned());
    }
    if yaml_string(yaml_get(job, "runs-on")) != Some("ubuntu-latest") {
        errors.push("supply-chain job runner must be ubuntu-latest".to_owned());
    }
    for forbidden in ["if", "continue-on-error", "defaults", "env", "permissions"] {
        if yaml_get(job, forbidden).is_some() {
            errors.push(format!("supply-chain job must not set {forbidden}"));
        }
    }

    let expected_names = [
        "Checkout",
        "Bootstrap verified Rust security tools",
        "Audit root lockfile",
        "Audit desktop lockfile",
        "Test cargo-audit exit policy",
        "Test cargo-deny lock and exception policy",
        "Check root dependency policy",
        "Check Windows x64 desktop dependency policy",
        "Check Windows ARM64 desktop dependency policy",
        "Check macOS Intel desktop dependency policy",
        "Check macOS ARM64 desktop dependency policy",
        "Validate supply-chain policy",
    ];
    let actual_names = job_steps(workflow, "supply-chain")
        .into_iter()
        .flatten()
        .map(|step| {
            yaml_string(yaml_get(step, "name"))
                .unwrap_or("<unnamed>")
                .to_owned()
        })
        .collect::<Vec<_>>();
    if actual_names
        != expected_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    {
        errors.push(format!(
            "supply-chain ordered steps changed: {actual_names:?}"
        ));
    }
    let Some(steps) = job_steps(workflow, "supply-chain") else {
        return;
    };
    for step in steps {
        let label = yaml_string(yaml_get(step, "name")).unwrap_or("<unnamed>");
        validate_critical_step(step, label, errors);
        if yaml_get(step, "working-directory").is_some() {
            errors.push(format!("{label} must not set working-directory"));
        }
    }

    if let Some(step) = step_by_name(workflow, "supply-chain", "Checkout") {
        validate_step_keys(step, "Checkout", &["name", "uses", "with"], errors);
        if yaml_string(yaml_get(step, "uses"))
            != Some("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
            || yaml_mapping_keys(yaml_get(step, "with"))
                != Some(expected_set(&["persist-credentials"]))
            || yaml_bool(yaml_get(
                yaml_get(step, "with").unwrap_or(&YamlValue::Null),
                "persist-credentials",
            )) != Some(false)
        {
            errors.push("supply-chain checkout action or inputs changed".to_owned());
        }
    }

    let bootstrap_name = "Bootstrap verified Rust security tools";
    if let Some(step) = step_by_name(workflow, "supply-chain", bootstrap_name) {
        validate_step_keys(
            step,
            bootstrap_name,
            &["name", "shell", "env", "run"],
            errors,
        );
        if yaml_string(yaml_get(step, "shell")) != Some("bash") {
            errors.push("verified tool bootstrap shell must be bash".to_owned());
        }
        let expected_env = BTreeMap::from([
            (
                "CARGO_AUDIT_CRATE_SHA256".to_owned(),
                CARGO_AUDIT_CRATE_SHA256.to_owned(),
            ),
            (
                "CARGO_AUDIT_VERSION".to_owned(),
                CARGO_AUDIT_VERSION.to_owned(),
            ),
            (
                "CARGO_DENY_ARCHIVE_SHA256".to_owned(),
                CARGO_DENY_ARCHIVE_SHA256.to_owned(),
            ),
            (
                "CARGO_DENY_VERSION".to_owned(),
                CARGO_DENY_VERSION.to_owned(),
            ),
        ]);
        if yaml_string_map(yaml_get(step, "env")) != Some(expected_env) {
            errors.push("verified tool bootstrap environment changed".to_owned());
        }
        validate_script_hash(step, bootstrap_name, BOOTSTRAP_SCRIPT_SHA256, errors);
    }

    let exact_runs = [
        (
            "Validate supply-chain policy",
            "cargo test --locked --package claw-security --test desktop_supply_chain_policy",
        ),
        (
            "Check root dependency policy",
            "\"$CARGO_DENY_RUNNER\" --manifest-path \"$GITHUB_WORKSPACE/Cargo.toml\" --locked --all-features check --config \"$GITHUB_WORKSPACE/deny.toml\"",
        ),
        (
            "Audit root lockfile",
            "\"$CARGO_AUDIT_BIN\" audit --file Cargo.lock",
        ),
        (
            "Audit desktop lockfile",
            "\"$CARGO_AUDIT_BIN\" audit --file desktop/Cargo.lock --no-fetch",
        ),
    ];
    for (name, run) in exact_runs {
        validate_exact_run_step(workflow, name, run, errors);
        if let Some(step) = step_by_name(workflow, "supply-chain", name) {
            validate_step_keys(step, name, &["name", "run"], errors);
            if yaml_get(step, "env").is_some() {
                errors.push(format!("{name} must not override tool paths"));
            }
        }
    }

    for (name, hash) in [
        ("Test cargo-audit exit policy", AUDIT_EXIT_SCRIPT_SHA256),
        (
            "Test cargo-deny lock and exception policy",
            DENY_FIXTURE_SCRIPT_SHA256,
        ),
    ] {
        if let Some(step) = step_by_name(workflow, "supply-chain", name) {
            validate_step_keys(step, name, &["name", "shell", "run"], errors);
            if yaml_string(yaml_get(step, "shell")) != Some("bash") {
                errors.push(format!("{name} shell must be bash"));
            }
            validate_script_hash(step, name, hash, errors);
        }
    }

    let deny_targets = [
        (
            "Check Windows x64 desktop dependency policy",
            "x86_64-pc-windows-msvc",
        ),
        (
            "Check Windows ARM64 desktop dependency policy",
            "aarch64-pc-windows-msvc",
        ),
        (
            "Check macOS Intel desktop dependency policy",
            "x86_64-apple-darwin",
        ),
        (
            "Check macOS ARM64 desktop dependency policy",
            "aarch64-apple-darwin",
        ),
    ];
    for (name, target) in deny_targets {
        let expected = format!(
            "\"$CARGO_DENY_RUNNER\" --manifest-path \"$GITHUB_WORKSPACE/desktop/Cargo.toml\" --locked --target {target} check --config \"$GITHUB_WORKSPACE/desktop/deny.toml\" --warn unmaintained advisories licenses sources"
        );
        validate_exact_run_step(workflow, name, &expected, errors);
        if let Some(step) = step_by_name(workflow, "supply-chain", name) {
            validate_step_keys(step, name, &["name", "run"], errors);
            if !expected.contains("--locked --target") {
                errors.push(format!("{name} must lock the target graph"));
            }
        }
    }
}

fn validate_rust_workflow(workflow: &YamlValue) -> Vec<String> {
    let mut errors = Vec::new();
    validate_permissions(workflow, &mut errors);
    validate_workflow_paths(workflow, &mut errors);
    validate_action_pins(workflow, &mut errors);
    for forbidden in ["defaults", "env"] {
        if yaml_get(workflow, forbidden).is_some() {
            errors.push(format!("rust workflow must not set top-level {forbidden}"));
        }
    }
    validate_supply_chain_job(workflow, &mut errors);
    errors
}

fn validate_macos_workflow(workflow: &YamlValue) -> Vec<String> {
    let mut errors = Vec::new();
    validate_permissions(workflow, &mut errors);
    validate_action_pins(workflow, &mut errors);
    if yaml_get(workflow, "defaults").is_some() {
        errors.push("macOS workflow must not set top-level defaults".to_owned());
    }
    let expected_env = BTreeMap::from([
        ("CARGO_TERM_COLOR".to_owned(), "always".to_owned()),
        ("MACOSX_DEPLOYMENT_TARGET".to_owned(), "14.0".to_owned()),
        ("RUSTFLAGS".to_owned(), "-Dwarnings".to_owned()),
    ]);
    if yaml_string_map(yaml_get(workflow, "env")) != Some(expected_env) {
        errors.push("macOS workflow inherited environment changed".to_owned());
    }

    let Some(source_policy) =
        yaml_get(workflow, "jobs").and_then(|jobs| yaml_get(jobs, "source-policy"))
    else {
        errors.push("missing macOS source-policy job".to_owned());
        return errors;
    };
    if yaml_mapping_keys(Some(source_policy)) != Some(expected_set(&["name", "runs-on", "steps"]))
        || yaml_string(yaml_get(source_policy, "name")) != Some("Source policy and Linux rejection")
        || yaml_string(yaml_get(source_policy, "runs-on")) != Some("ubuntu-latest")
    {
        errors.push("macOS source-policy job schema or runner changed".to_owned());
    }
    for forbidden in [
        "if",
        "continue-on-error",
        "defaults",
        "env",
        "permissions",
        "strategy",
        "needs",
    ] {
        if yaml_get(source_policy, forbidden).is_some() {
            errors.push(format!("macOS source-policy job must not set {forbidden}"));
        }
    }
    let source_names = job_steps(workflow, "source-policy")
        .into_iter()
        .flatten()
        .map(|step| {
            yaml_string(yaml_get(step, "name"))
                .unwrap_or("<unnamed>")
                .to_owned()
        })
        .collect::<Vec<_>>();
    if source_names
        != [
            "Checkout",
            "Check shell syntax and forbidden committed artifacts",
            "Preserve Linux desktop rejection",
        ]
        .map(str::to_owned)
        .to_vec()
    {
        errors.push(format!(
            "macOS source-policy ordered steps changed: {source_names:?}"
        ));
    }
    if let Some(step) = step_by_name(workflow, "source-policy", "Checkout") {
        validate_step_keys(
            step,
            "source-policy Checkout",
            &["name", "uses", "with"],
            &mut errors,
        );
        if yaml_string(yaml_get(step, "uses"))
            != Some("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
            || yaml_mapping_keys(yaml_get(step, "with"))
                != Some(expected_set(&["persist-credentials"]))
            || yaml_bool(yaml_get(
                yaml_get(step, "with").unwrap_or(&YamlValue::Null),
                "persist-credentials",
            )) != Some(false)
        {
            errors.push("macOS source-policy checkout action or inputs changed".to_owned());
        }
    }
    for (name, hash) in [
        (
            "Check shell syntax and forbidden committed artifacts",
            MACOS_SOURCE_SHELL_SCRIPT_SHA256,
        ),
        (
            "Preserve Linux desktop rejection",
            MACOS_SOURCE_LINUX_SCRIPT_SHA256,
        ),
    ] {
        let Some(step) = step_by_name(workflow, "source-policy", name) else {
            continue;
        };
        validate_step_keys(step, name, &["name", "shell", "run"], &mut errors);
        validate_critical_step(step, name, &mut errors);
        if yaml_string(yaml_get(step, "shell")) != Some("bash")
            || yaml_get(step, "env").is_some()
            || yaml_get(step, "working-directory").is_some()
        {
            errors.push(format!("{name} source-policy controls changed"));
        }
        validate_script_hash(step, name, hash, &mut errors);
    }

    let Some(native) = yaml_get(workflow, "jobs").and_then(|jobs| yaml_get(jobs, "native")) else {
        return vec!["missing native macOS job".to_owned()];
    };
    if yaml_mapping_keys(Some(native))
        != Some(expected_set(&[
            "name", "needs", "strategy", "runs-on", "steps",
        ]))
    {
        errors.push("native macOS job schema changed".to_owned());
    }
    if yaml_string(yaml_get(native, "runs-on")) != Some("${{ matrix.runner }}")
        || yaml_string(yaml_get(native, "needs")) != Some("source-policy")
    {
        errors.push("native macOS runner or dependency changed".to_owned());
    }
    for forbidden in ["if", "continue-on-error", "defaults", "env", "permissions"] {
        if yaml_get(native, forbidden).is_some() {
            errors.push(format!("native macOS job must not set {forbidden}"));
        }
    }
    let strategy = yaml_get(native, "strategy").unwrap_or(&YamlValue::Null);
    if yaml_mapping_keys(Some(strategy)) != Some(expected_set(&["fail-fast", "matrix"]))
        || yaml_bool(yaml_get(strategy, "fail-fast")) != Some(false)
    {
        errors.push("native macOS strategy must be exact and fail-fast false".to_owned());
    }
    let matrix = yaml_get(strategy, "matrix").unwrap_or(&YamlValue::Null);
    if yaml_mapping_keys(Some(matrix)) != Some(expected_set(&["include"])) {
        errors.push("native macOS matrix schema changed".to_owned());
    }
    let actual_matrix = yaml_sequence(yaml_get(matrix, "include"))
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            Some((
                yaml_string(yaml_get(entry, "runner"))?.to_owned(),
                yaml_string(yaml_get(entry, "arch"))?.to_owned(),
            ))
        })
        .collect::<Vec<_>>();
    let expected_matrix = vec![
        ("macos-15".to_owned(), "arm64".to_owned()),
        ("macos-15-intel".to_owned(), "x86_64".to_owned()),
    ];
    if actual_matrix != expected_matrix {
        errors.push(format!(
            "native macOS matrix must cover exact ARM64 and Intel runners: {actual_matrix:?}"
        ));
    }
    for row in yaml_sequence(yaml_get(matrix, "include"))
        .into_iter()
        .flatten()
    {
        if yaml_mapping_keys(Some(row)) != Some(expected_set(&["runner", "arch"])) {
            errors.push("native macOS matrix row schema changed".to_owned());
        }
    }

    let expected_names = [
        "Checkout",
        "Record Apple tool versions",
        "Format both Cargo workspaces",
        "Check both Cargo workspaces",
        "Clippy both Cargo workspaces",
        "Test both Cargo workspaces natively",
        "Smoke-test native desktop window backend",
        "Build and validate native packages",
        "Run packaging self-tests",
        "Scan native artifacts for JavaScript runtimes",
        "Upload ephemeral native prototype artifacts",
    ];
    let actual_names = job_steps(workflow, "native")
        .into_iter()
        .flatten()
        .map(|step| {
            yaml_string(yaml_get(step, "name"))
                .unwrap_or("<unnamed>")
                .to_owned()
        })
        .collect::<Vec<_>>();
    if actual_names
        != expected_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    {
        errors.push(format!(
            "native macOS ordered steps changed: {actual_names:?}"
        ));
    }

    let script_steps = [
        (
            "Record Apple tool versions",
            MACOS_RECORD_SCRIPT_SHA256,
            &["name", "shell", "run"][..],
            Some("bash"),
        ),
        (
            "Format both Cargo workspaces",
            MACOS_FORMAT_SCRIPT_SHA256,
            &["name", "run"][..],
            None,
        ),
        (
            "Check both Cargo workspaces",
            MACOS_CHECK_SCRIPT_SHA256,
            &["name", "run"][..],
            None,
        ),
        (
            "Clippy both Cargo workspaces",
            MACOS_CLIPPY_SCRIPT_SHA256,
            &["name", "run"][..],
            None,
        ),
        (
            "Test both Cargo workspaces natively",
            MACOS_TEST_SCRIPT_SHA256,
            &["name", "run"][..],
            None,
        ),
        (
            "Build and validate native packages",
            MACOS_BUILD_SCRIPT_SHA256,
            &["name", "shell", "run"][..],
            Some("bash"),
        ),
        (
            "Scan native artifacts for JavaScript runtimes",
            MACOS_SCAN_SCRIPT_SHA256,
            &["name", "shell", "run"][..],
            Some("bash"),
        ),
    ];
    for (name, hash, keys, shell) in script_steps {
        let Some(step) = step_by_name(workflow, "native", name) else {
            continue;
        };
        validate_step_keys(step, name, keys, &mut errors);
        validate_script_hash(step, name, hash, &mut errors);
        if yaml_string(yaml_get(step, "shell")) != shell {
            errors.push(format!("{name} shell changed"));
        }
        if yaml_get(step, "env").is_some() || yaml_get(step, "working-directory").is_some() {
            errors.push(format!("{name} must not override env or working-directory"));
        }
    }

    if let Some(step) = step_by_name(workflow, "native", "Checkout") {
        validate_step_keys(
            step,
            "native Checkout",
            &["name", "uses", "with"],
            &mut errors,
        );
        if yaml_string(yaml_get(step, "uses"))
            != Some("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
            || yaml_mapping_keys(yaml_get(step, "with"))
                != Some(expected_set(&["persist-credentials"]))
            || yaml_bool(yaml_get(
                yaml_get(step, "with").unwrap_or(&YamlValue::Null),
                "persist-credentials",
            )) != Some(false)
        {
            errors.push("native macOS checkout action or inputs changed".to_owned());
        }
    }

    if let Some(step) = step_by_name(workflow, "native", "Run packaging self-tests") {
        validate_step_keys(
            step,
            "Run packaging self-tests",
            &["name", "if", "shell", "run"],
            &mut errors,
        );
        validate_script_hash(
            step,
            "Run packaging self-tests",
            MACOS_SELF_TEST_SCRIPT_SHA256,
            &mut errors,
        );
        if yaml_string(yaml_get(step, "shell")) != Some("bash") {
            errors.push("Run packaging self-tests shell changed".to_owned());
        }
    }

    if let Some(step) = step_by_name(
        workflow,
        "native",
        "Upload ephemeral native prototype artifacts",
    ) {
        validate_step_keys(
            step,
            "Upload ephemeral native prototype artifacts",
            &["name", "uses", "with"],
            &mut errors,
        );
        let with = yaml_get(step, "with").unwrap_or(&YamlValue::Null);
        let expected_path = "target/macos-package/apps/${{ matrix.arch }}/GTA Claw.app\ntarget/macos-package/headless/${{ matrix.arch }}/*.tar.gz\ntarget/macos-package/headless/${{ matrix.arch }}/*.sha256\ntarget/macos-package/manifests/*.sha256\n";
        if yaml_string(yaml_get(step, "uses"))
            != Some("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02")
            || yaml_mapping_keys(Some(with))
                != Some(expected_set(&[
                    "name",
                    "path",
                    "if-no-files-found",
                    "retention-days",
                ]))
            || yaml_string(yaml_get(with, "name"))
                != Some("macos-${{ matrix.arch }}-prototype-${{ github.sha }}")
            || yaml_string(yaml_get(with, "path")) != Some(expected_path)
            || yaml_string(yaml_get(with, "if-no-files-found")) != Some("error")
            || yaml_get(with, "retention-days").and_then(YamlValue::as_u64) != Some(7)
        {
            errors.push("native macOS upload action or inputs changed".to_owned());
        }
    }

    for step in job_steps(workflow, "native").into_iter().flatten() {
        let label = yaml_string(yaml_get(step, "name")).unwrap_or("<unnamed>");
        if label == "Run packaging self-tests" {
            if yaml_string(yaml_get(step, "if")) != Some("matrix.arch == 'arm64'")
                || yaml_get(step, "continue-on-error").is_some()
            {
                errors.push("macOS packaging self-test condition changed".to_owned());
            }
        } else {
            validate_critical_step(step, label, &mut errors);
        }
    }

    let native_test = step_by_name(workflow, "native", "Test both Cargo workspaces natively");
    let expected_native_test = "test \"$(uname -m)\" = \"${{ matrix.arch }}\"\ncargo test --workspace --all-targets --locked\ncargo test --manifest-path desktop/Cargo.toml --workspace --all-targets --locked\n";
    if native_test.and_then(|step| yaml_string(yaml_get(step, "run"))) != Some(expected_native_test)
    {
        errors.push("native macOS architecture assertion or test command changed".to_owned());
    }

    let name = "Smoke-test native desktop window backend";
    let Some(step) = step_by_name(workflow, "native", name) else {
        errors.push(format!("missing {name} step"));
        return errors;
    };
    validate_critical_step(step, name, &mut errors);
    if yaml_mapping_keys(Some(step))
        != Some(expected_set(&["name", "timeout-minutes", "env", "run"]))
    {
        errors.push("macOS backend smoke step schema changed".to_owned());
    }
    if yaml_get(step, "timeout-minutes").and_then(YamlValue::as_u64) != Some(2) {
        errors.push("macOS backend smoke must have a two-minute hard timeout".to_owned());
    }
    if yaml_string_map(yaml_get(step, "env"))
        != Some(BTreeMap::from([(
            "SLINT_BACKEND".to_owned(),
            "winit-software".to_owned(),
        )]))
    {
        errors.push("macOS backend smoke environment changed".to_owned());
    }
    if yaml_string(yaml_get(step, "run"))
        != Some("cargo test --manifest-path desktop/Cargo.toml --test macos_winit_smoke --locked")
    {
        errors.push("macOS backend smoke command is not exact".to_owned());
    }
    errors
}

fn toml_table<'a>(
    value: &'a TomlValue,
    key: &str,
) -> Option<&'a toml::map::Map<String, TomlValue>> {
    value.get(key)?.as_table()
}

fn toml_table_mut<'a>(
    value: &'a mut TomlValue,
    key: &str,
) -> Option<&'a mut toml::map::Map<String, TomlValue>> {
    value.get_mut(key)?.as_table_mut()
}

fn toml_keys(table: &toml::map::Map<String, TomlValue>) -> BTreeSet<String> {
    table.keys().cloned().collect()
}

fn validate_deny_toml(deny: &TomlValue) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(root) = deny.as_table() else {
        return vec!["desktop deny config must be a TOML table".to_owned()];
    };
    if toml_keys(root) != expected_set(&["advisories", "graph", "licenses", "sources"]) {
        errors.push("desktop deny top-level policy sections changed".to_owned());
    }

    let graph = toml_table(deny, "graph");
    if graph.and_then(|table| table.get("all-features")) != Some(&TomlValue::Boolean(true)) {
        errors.push("desktop deny graph.all-features must be true".to_owned());
    }
    if graph.is_none_or(|table| toml_keys(table) != expected_set(&["all-features"])) {
        errors.push("desktop deny graph policy keys changed".to_owned());
    }

    let advisories = toml_table(deny, "advisories");
    if advisories
        .and_then(|table| table.get("ignore"))
        .and_then(TomlValue::as_array)
        .is_none_or(|ignore| !ignore.is_empty())
    {
        errors.push("desktop deny advisories.ignore must be empty".to_owned());
    }
    if advisories.is_none_or(|table| toml_keys(table) != expected_set(&["ignore"])) {
        errors.push("desktop deny advisories policy keys changed".to_owned());
    }

    let expected_licenses = expected_set(&[
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "ISC",
        "LicenseRef-Slint-Royalty-free-2.0",
        "MIT",
        "Unicode-3.0",
        "Zlib",
    ]);
    let licenses = toml_table(deny, "licenses");
    if toml_string_set(licenses.and_then(|table| table.get("allow"))) != Some(expected_licenses) {
        errors.push("desktop deny license allow-list changed".to_owned());
    }
    if licenses
        .and_then(|table| table.get("confidence-threshold"))
        .and_then(TomlValue::as_float)
        != Some(0.8)
        || licenses
            .and_then(|table| table.get("unused-allowed-license"))
            .and_then(TomlValue::as_str)
            != Some("allow")
    {
        errors.push("desktop deny license thresholds changed".to_owned());
    }
    if licenses.is_none_or(|table| {
        toml_keys(table)
            != expected_set(&["allow", "confidence-threshold", "unused-allowed-license"])
    }) {
        errors.push("desktop deny license policy keys changed".to_owned());
    }

    let sources = toml_table(deny, "sources");
    if sources
        .and_then(|table| table.get("unknown-registry"))
        .and_then(TomlValue::as_str)
        != Some("deny")
        || sources
            .and_then(|table| table.get("unknown-git"))
            .and_then(TomlValue::as_str)
            != Some("deny")
    {
        errors.push("desktop deny unknown sources must be denied".to_owned());
    }
    if toml_string_set(sources.and_then(|table| table.get("allow-git")))
        .is_none_or(|allow| !allow.is_empty())
    {
        errors.push("desktop deny sources.allow-git must be empty".to_owned());
    }
    if toml_string_set(sources.and_then(|table| table.get("allow-registry")))
        != Some(expected_set(&[
            "https://github.com/rust-lang/crates.io-index",
        ]))
    {
        errors.push("desktop deny registry allow-list changed".to_owned());
    }
    if sources.is_none_or(|table| {
        toml_keys(table)
            != expected_set(&[
                "allow-git",
                "allow-registry",
                "unknown-git",
                "unknown-registry",
            ])
    }) {
        errors.push("desktop deny source policy keys changed".to_owned());
    }
    errors
}

fn validate_root_deny_toml(deny: &TomlValue) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(root) = deny.as_table() else {
        return vec!["root deny config must be a TOML table".to_owned()];
    };
    if toml_keys(root) != expected_set(&["advisories", "bans", "graph", "licenses", "sources"]) {
        errors.push("root deny top-level policy sections changed".to_owned());
    }

    let graph = toml_table(deny, "graph");
    if graph.is_none_or(|table| {
        toml_keys(table) != expected_set(&["all-features"])
            || table.get("all-features") != Some(&TomlValue::Boolean(true))
    }) {
        errors.push("root deny graph policy changed".to_owned());
    }

    let advisories = toml_table(deny, "advisories");
    if advisories.is_none_or(|table| {
        toml_keys(table) != expected_set(&["ignore"])
            || table
                .get("ignore")
                .and_then(TomlValue::as_array)
                .is_none_or(|ignore| !ignore.is_empty())
    }) {
        errors.push("root deny advisories policy changed".to_owned());
    }

    let licenses = toml_table(deny, "licenses");
    if licenses.is_none_or(|table| {
        toml_keys(table) != expected_set(&["allow", "confidence-threshold"])
            || toml_string_set(table.get("allow"))
                != Some(expected_set(&[
                    "Apache-2.0",
                    "BSD-3-Clause",
                    "ISC",
                    "MIT",
                    "Unicode-3.0",
                ]))
            || table
                .get("confidence-threshold")
                .and_then(TomlValue::as_float)
                != Some(0.8)
    }) {
        errors.push("root deny license policy changed".to_owned());
    }

    let bans = toml_table(deny, "bans");
    let skip = bans
        .and_then(|table| table.get("skip"))
        .and_then(TomlValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            Some((
                entry.get("name")?.as_str()?.to_owned(),
                entry.get("version")?.as_str()?.to_owned(),
            ))
        })
        .collect::<BTreeSet<_>>();
    let expected_skip = BTreeSet::from([
        ("rand_core".to_owned(), "0.6.4".to_owned()),
        ("windows-sys".to_owned(), "0.52.0".to_owned()),
    ]);
    if bans.is_none_or(|table| {
        toml_keys(table) != expected_set(&["highlight", "multiple-versions", "skip", "wildcards"])
            || table.get("multiple-versions").and_then(TomlValue::as_str) != Some("deny")
            || table.get("wildcards").and_then(TomlValue::as_str) != Some("deny")
            || table.get("highlight").and_then(TomlValue::as_str) != Some("all")
    }) || skip != expected_skip
    {
        errors.push("root deny bans policy changed".to_owned());
    }

    let sources = toml_table(deny, "sources");
    if sources.is_none_or(|table| {
        toml_keys(table)
            != expected_set(&[
                "allow-git",
                "allow-registry",
                "unknown-git",
                "unknown-registry",
            ])
            || table.get("unknown-registry").and_then(TomlValue::as_str) != Some("deny")
            || table.get("unknown-git").and_then(TomlValue::as_str) != Some("deny")
            || toml_string_set(table.get("allow-git")).is_none_or(|allow| !allow.is_empty())
            || toml_string_set(table.get("allow-registry"))
                != Some(expected_set(&[
                    "https://github.com/rust-lang/crates.io-index",
                ]))
    }) {
        errors.push("root deny source policy changed".to_owned());
    }
    errors
}

fn validate_audit_toml(audit: &TomlValue) -> Vec<String> {
    let Some(root) = audit.as_table() else {
        return vec!["cargo audit config must be a TOML table".to_owned()];
    };
    let advisories = toml_table(audit, "advisories");
    let mut errors = Vec::new();
    if toml_keys(root) != expected_set(&["advisories"])
        || advisories.is_none_or(|table| toml_keys(table) != expected_set(&["ignore"]))
    {
        errors.push("cargo audit config policy keys changed".to_owned());
    }
    if advisories
        .and_then(|table| table.get("ignore"))
        .and_then(TomlValue::as_array)
        .is_none_or(|ignore| !ignore.is_empty())
    {
        errors.push("cargo audit advisories.ignore must be empty".to_owned());
    }
    errors
}

fn lock_packages(lock: &TomlValue) -> BTreeMap<String, String> {
    lock.get("package")
        .and_then(TomlValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|package| {
            Some((
                package.get("name")?.as_str()?.to_owned(),
                package.get("version")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

fn validate_dependency_graph(
    desktop_manifest: &TomlValue,
    app_manifest: &TomlValue,
    desktop_lock: &TomlValue,
    root_lock: &TomlValue,
) -> Vec<String> {
    let mut errors = Vec::new();
    if desktop_manifest.get("patch").is_some() {
        errors.push("desktop must not patch registry sources".to_owned());
    }

    let target = app_manifest
        .get("target")
        .and_then(TomlValue::as_table)
        .and_then(|target| target.get(r#"cfg(any(target_os = "windows", target_os = "macos"))"#))
        .and_then(TomlValue::as_table);
    let features = toml_string_set(
        target
            .and_then(|target| target.get("dependencies"))
            .and_then(TomlValue::as_table)
            .and_then(|dependencies| dependencies.get("slint"))
            .and_then(TomlValue::as_table)
            .and_then(|slint| slint.get("features")),
    );
    if features.as_ref().is_none_or(|features| {
        !features.contains("backend-winit-x11")
            || features.contains("backend-winit")
            || features.contains("backend-winit-wayland")
    }) {
        errors.push("desktop Slint backend feature policy changed".to_owned());
    }

    let smoke_tests = app_manifest
        .get("test")
        .and_then(TomlValue::as_array)
        .into_iter()
        .flatten()
        .filter(|test| test.get("name").and_then(TomlValue::as_str) == Some("macos_winit_smoke"))
        .collect::<Vec<_>>();
    if smoke_tests.len() != 1
        || smoke_tests[0].get("path").and_then(TomlValue::as_str)
            != Some("tests/macos_winit_smoke.rs")
        || smoke_tests[0].get("harness").and_then(TomlValue::as_bool) != Some(false)
    {
        errors.push("macOS backend smoke must be the exact harness-free test target".to_owned());
    }

    let desktop_packages = lock_packages(desktop_lock);
    for required in ["slint", "i-slint-backend-winit", "winit"] {
        if !desktop_packages.contains_key(required) {
            errors.push(format!("desktop lost real GUI backend package: {required}"));
        }
    }
    let forbidden = desktop_packages
        .keys()
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
        errors.push(format!(
            "desktop lock contains unused Wayland dependency chain: {forbidden:?}"
        ));
    }

    let root_slint = lock_packages(root_lock)
        .into_keys()
        .filter(|name| name == "slint" || name == "slint-build" || name.starts_with("i-slint"))
        .collect::<Vec<_>>();
    if !root_slint.is_empty() {
        errors.push(format!(
            "root runtime lock contains Slint packages: {root_slint:?}"
        ));
    }
    errors
}

fn mutate_negative_case(
    mutation: &str,
    workflow: &mut YamlValue,
    macos_workflow: &mut YamlValue,
    root_deny: &mut TomlValue,
    deny: &mut TomlValue,
    audit: &mut TomlValue,
) {
    match mutation {
        "root-audit-continue-on-error" => {
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Audit root lockfile")
                    .expect("root audit step"),
            )
            .expect("root audit mapping")
            .insert(yaml_key("continue-on-error"), YamlValue::Bool(true));
        }
        "desktop-audit-disabled" => {
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Audit desktop lockfile")
                    .expect("desktop audit step"),
            )
            .expect("desktop audit mapping")
            .insert(yaml_key("if"), YamlValue::Bool(false));
        }
        "desktop-audit-redirected" => {
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Audit desktop lockfile")
                    .expect("desktop audit step"),
            )
            .expect("desktop audit mapping")
            .insert(
                yaml_key("working-directory"),
                YamlValue::String(".".to_owned()),
            );
            let mut unrelated = YamlMapping::new();
            unrelated.insert(
                yaml_key("name"),
                YamlValue::String("Unrelated desktop step".to_owned()),
            );
            unrelated.insert(
                yaml_key("working-directory"),
                YamlValue::String("desktop".to_owned()),
            );
            unrelated.insert(yaml_key("run"), YamlValue::String("true".to_owned()));
            job_steps_mut(workflow, "supply-chain")
                .expect("supply-chain steps")
                .push(YamlValue::Mapping(unrelated));
        }
        "cargo-audit-install-latest" => {
            yaml_mapping_mut(
                step_by_name_mut(
                    workflow,
                    "supply-chain",
                    "Bootstrap verified Rust security tools",
                )
                .expect("bootstrap tools step"),
            )
            .expect("bootstrap tools mapping")
            .insert(
                yaml_key("run"),
                YamlValue::String("cargo install cargo-audit".to_owned()),
            );
        }
        "windows-arm64-deny-missing" => {
            job_steps_mut(workflow, "supply-chain")
                .expect("supply-chain steps")
                .retain(|step| {
                    yaml_string(yaml_get(step, "name"))
                        != Some("Check Windows ARM64 desktop dependency policy")
                });
        }
        "supply-checkout-action-substitution" => {
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Checkout")
                    .expect("supply-chain checkout"),
            )
            .expect("supply-chain checkout mapping")
            .insert(
                yaml_key("uses"),
                YamlValue::String(
                    "example/checkout@0000000000000000000000000000000000000000".to_owned(),
                ),
            );
        }
        "job-checks-write" => {
            let mut permissions = YamlMapping::new();
            permissions.insert(yaml_key("checks"), YamlValue::String("write".to_owned()));
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "jobs").expect("workflow jobs"),
                    "supply-chain",
                )
                .expect("supply-chain job"),
            )
            .expect("supply-chain mapping")
            .insert(yaml_key("permissions"), YamlValue::Mapping(permissions));
        }
        "job-write-all" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "jobs").expect("workflow jobs"),
                    "supply-chain",
                )
                .expect("supply-chain job"),
            )
            .expect("supply-chain mapping")
            .insert(
                yaml_key("permissions"),
                YamlValue::String("write-all".to_owned()),
            );
        }
        "supply-job-disabled" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "jobs").expect("workflow jobs"),
                    "supply-chain",
                )
                .expect("supply-chain job"),
            )
            .expect("supply-chain mapping")
            .insert(yaml_key("if"), YamlValue::Bool(false));
        }
        "supply-job-env-shadow" => {
            let mut env = YamlMapping::new();
            env.insert(
                yaml_key("CARGO_AUDIT_BIN"),
                YamlValue::String("/tmp/fake-audit".to_owned()),
            );
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "jobs").expect("workflow jobs"),
                    "supply-chain",
                )
                .expect("supply-chain job"),
            )
            .expect("supply-chain mapping")
            .insert(yaml_key("env"), YamlValue::Mapping(env));
        }
        "supply-unknown-shadow-step" => {
            let mut shadow = YamlMapping::new();
            shadow.insert(
                yaml_key("name"),
                YamlValue::String("Shadow verified audit binary".to_owned()),
            );
            shadow.insert(
                yaml_key("run"),
                YamlValue::String(
                    "echo 'CARGO_AUDIT_BIN=/tmp/fake-audit' >> \"$GITHUB_ENV\"".to_owned(),
                ),
            );
            job_steps_mut(workflow, "supply-chain")
                .expect("supply-chain steps")
                .insert(2, YamlValue::Mapping(shadow));
        }
        "bootstrap-wrapper-env" => {
            let bootstrap = step_by_name_mut(
                workflow,
                "supply-chain",
                "Bootstrap verified Rust security tools",
            )
            .expect("bootstrap tools step");
            yaml_mapping_mut(yaml_get_mut(bootstrap, "env").expect("bootstrap environment"))
                .expect("bootstrap environment mapping")
                .insert(
                    yaml_key("RUSTC_WRAPPER"),
                    YamlValue::String("/tmp/fake-wrapper".to_owned()),
                );
        }
        "negative-desktop-path" => {
            yaml_sequence_mut(yaml_get_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "on").expect("workflow triggers"),
                    "pull_request",
                )
                .expect("pull request trigger"),
                "paths",
            ))
            .expect("pull request paths")
            .push(YamlValue::String("!desktop/**".to_owned()));
        }
        "native-matrix-runner-collapse" => {
            let jobs = yaml_get_mut(macos_workflow, "jobs").expect("macOS jobs");
            let native = yaml_get_mut(jobs, "native").expect("native macOS job");
            let strategy = yaml_get_mut(native, "strategy").expect("native strategy");
            let matrix = yaml_get_mut(strategy, "matrix").expect("native matrix");
            let include = yaml_sequence_mut(yaml_get_mut(matrix, "include"))
                .expect("native include sequence");
            yaml_mapping_mut(&mut include[1])
                .expect("Intel matrix row")
                .insert(yaml_key("runner"), YamlValue::String("macos-15".to_owned()));
        }
        "native-arch-assertion-removed" => {
            yaml_mapping_mut(
                step_by_name_mut(
                    macos_workflow,
                    "native",
                    "Test both Cargo workspaces natively",
                )
                .expect("native workspace test"),
            )
            .expect("native workspace test mapping")
            .insert(
                yaml_key("run"),
                YamlValue::String("cargo test --workspace --all-targets --locked\n".to_owned()),
            );
        }
        "source-policy-disabled" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(macos_workflow, "jobs").expect("macOS jobs"),
                    "source-policy",
                )
                .expect("source-policy job"),
            )
            .expect("source-policy mapping")
            .insert(yaml_key("if"), YamlValue::Bool(false));
        }
        "native-format-replaced" => {
            yaml_mapping_mut(
                step_by_name_mut(macos_workflow, "native", "Format both Cargo workspaces")
                    .expect("native format step"),
            )
            .expect("native format mapping")
            .insert(yaml_key("run"), YamlValue::String("true".to_owned()));
        }
        "native-arch-shell-added" => {
            yaml_mapping_mut(
                step_by_name_mut(
                    macos_workflow,
                    "native",
                    "Test both Cargo workspaces natively",
                )
                .expect("native workspace test"),
            )
            .expect("native workspace test mapping")
            .insert(yaml_key("shell"), YamlValue::String("sh".to_owned()));
        }
        "native-workflow-env-shadow" => {
            yaml_mapping_mut(yaml_get_mut(macos_workflow, "env").expect("macOS workflow env"))
                .expect("macOS workflow env mapping")
                .insert(
                    yaml_key("PATH"),
                    YamlValue::String("/tmp/shadow".to_owned()),
                );
        }
        "native-matrix-extra-key" => {
            let jobs = yaml_get_mut(macos_workflow, "jobs").expect("macOS jobs");
            let native = yaml_get_mut(jobs, "native").expect("native macOS job");
            let strategy = yaml_get_mut(native, "strategy").expect("native strategy");
            let matrix = yaml_get_mut(strategy, "matrix").expect("native matrix");
            let include = yaml_sequence_mut(yaml_get_mut(matrix, "include"))
                .expect("native include sequence");
            yaml_mapping_mut(&mut include[0])
                .expect("ARM matrix row")
                .insert(yaml_key("image"), YamlValue::String("shadow".to_owned()));
        }
        "deny-no-locked" => {
            let step = step_by_name_mut(
                workflow,
                "supply-chain",
                "Check Windows x64 desktop dependency policy",
            )
            .expect("Windows x64 deny step");
            let run = yaml_string(yaml_get(step, "run"))
                .expect("Windows x64 deny command")
                .replace(" --locked", "");
            yaml_mapping_mut(step)
                .expect("Windows x64 deny mapping")
                .insert(yaml_key("run"), YamlValue::String(run));
        }
        "deny-advisory-ignore" => {
            toml_table_mut(deny, "advisories")
                .expect("deny advisories")
                .insert(
                    "ignore".to_owned(),
                    TomlValue::Array(vec![TomlValue::String("RUSTSEC-2026-0194".to_owned())]),
                );
        }
        "audit-config-ignore" => {
            toml_table_mut(audit, "advisories")
                .expect("audit advisories")
                .insert(
                    "ignore".to_owned(),
                    TomlValue::Array(vec![TomlValue::String("RUSTSEC-2026-0194".to_owned())]),
                );
        }
        "deny-git-source" => {
            toml_table_mut(deny, "sources")
                .expect("deny sources")
                .insert(
                    "allow-git".to_owned(),
                    TomlValue::Array(vec![TomlValue::String(
                        "https://github.com/example/unpinned".to_owned(),
                    )]),
                );
        }
        "deny-license-widening" => {
            deny.get_mut("licenses")
                .and_then(|licenses| licenses.get_mut("allow"))
                .and_then(TomlValue::as_array_mut)
                .expect("deny license allow-list")
                .push(TomlValue::String("GPL-3.0-only".to_owned()));
        }
        "deny-graph-exclude" => {
            toml_table_mut(deny, "graph").expect("deny graph").insert(
                "exclude".to_owned(),
                TomlValue::Array(vec![TomlValue::String("quick-xml".to_owned())]),
            );
        }
        "root-deny-license-widening" => {
            root_deny
                .get_mut("licenses")
                .and_then(|licenses| licenses.get_mut("allow"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny license allow-list")
                .push(TomlValue::String("GPL-3.0-only".to_owned()));
        }
        "root-deny-inline-exception" => {
            let mut exception = toml::map::Map::new();
            exception.insert(
                "name".to_owned(),
                TomlValue::String("prohibited".to_owned()),
            );
            exception.insert(
                "allow".to_owned(),
                TomlValue::Array(vec![TomlValue::String("GPL-3.0-only".to_owned())]),
            );
            toml_table_mut(root_deny, "licenses")
                .expect("root deny licenses")
                .insert(
                    "exceptions".to_owned(),
                    TomlValue::Array(vec![TomlValue::Table(exception)]),
                );
        }
        "root-deny-source-widening" => {
            toml_table_mut(root_deny, "sources")
                .expect("root deny sources")
                .insert(
                    "allow-git".to_owned(),
                    TomlValue::Array(vec![TomlValue::String(
                        "https://github.com/example/unpinned".to_owned(),
                    )]),
                );
        }
        "root-deny-ban-skip" => {
            let mut skipped = toml::map::Map::new();
            skipped.insert(
                "name".to_owned(),
                TomlValue::String("prohibited".to_owned()),
            );
            skipped.insert("version".to_owned(), TomlValue::String("1.0.0".to_owned()));
            root_deny
                .get_mut("bans")
                .and_then(|bans| bans.get_mut("skip"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny ban skips")
                .push(TomlValue::Table(skipped));
        }
        other => panic!("unknown policy mutation: {other}"),
    }
}

#[test]
fn repository_policy_is_structurally_fail_closed() {
    let root = workspace_root();
    let rust_workflow = parse_yaml(&root.join(".github/workflows/rust.yml"));
    let macos_workflow = parse_yaml(&root.join(".github/workflows/macos-packaging.yml"));
    let root_deny = parse_toml(&root.join("deny.toml"));
    let deny = parse_toml(&root.join("desktop/deny.toml"));
    let audit = parse_toml(&root.join(".cargo/audit.toml"));
    let desktop_manifest = parse_toml(&root.join("desktop/Cargo.toml"));
    let app_manifest = parse_toml(&root.join("desktop/apps/gta-claw-desktop/Cargo.toml"));
    let desktop_lock = parse_toml(&root.join("desktop/Cargo.lock"));
    let root_lock = parse_toml(&root.join("Cargo.lock"));

    let mut errors = validate_rust_workflow(&rust_workflow);
    errors.extend(validate_macos_workflow(&macos_workflow));
    errors.extend(validate_root_deny_toml(&root_deny));
    errors.extend(validate_deny_toml(&deny));
    errors.extend(validate_audit_toml(&audit));
    errors.extend(validate_dependency_graph(
        &desktop_manifest,
        &app_manifest,
        &desktop_lock,
        &root_lock,
    ));
    let exception_files = deny_exception_files(&root);
    if !exception_files.is_empty() {
        errors.push(format!(
            "external cargo-deny exception files are forbidden: {exception_files:?}"
        ));
    }
    assert!(
        errors.is_empty(),
        "policy violations:\n{}",
        errors.join("\n")
    );
}

#[test]
fn negative_policy_fixtures_reject_bypasses() {
    let root = workspace_root();
    let baseline_workflow = parse_yaml(&root.join(".github/workflows/rust.yml"));
    let baseline_macos_workflow = parse_yaml(&root.join(".github/workflows/macos-packaging.yml"));
    let baseline_root_deny = parse_toml(&root.join("deny.toml"));
    let baseline_deny = parse_toml(&root.join("desktop/deny.toml"));
    let baseline_audit = parse_toml(&root.join(".cargo/audit.toml"));
    let cases = parse_toml(&root.join(
        "crates/claw-security/tests/fixtures/desktop_supply_chain_policy/negative-cases.toml",
    ));

    let cases = cases
        .get("case")
        .and_then(TomlValue::as_array)
        .expect("negative policy cases");
    assert_eq!(cases.len(), 30, "every bypass category must remain covered");
    for case in cases {
        let name = case
            .get("name")
            .and_then(TomlValue::as_str)
            .expect("case name");
        let mutation = case
            .get("mutation")
            .and_then(TomlValue::as_str)
            .expect("case mutation");
        let expected = case
            .get("expected")
            .and_then(TomlValue::as_str)
            .expect("case expected violation");

        let mut workflow = baseline_workflow.clone();
        let mut macos_workflow = baseline_macos_workflow.clone();
        let mut root_deny = baseline_root_deny.clone();
        let mut deny = baseline_deny.clone();
        let mut audit = baseline_audit.clone();
        mutate_negative_case(
            mutation,
            &mut workflow,
            &mut macos_workflow,
            &mut root_deny,
            &mut deny,
            &mut audit,
        );

        let mut violations = validate_rust_workflow(&workflow);
        violations.extend(validate_macos_workflow(&macos_workflow));
        violations.extend(validate_root_deny_toml(&root_deny));
        violations.extend(validate_deny_toml(&deny));
        violations.extend(validate_audit_toml(&audit));
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "negative case {name} did not produce {expected:?}: {violations:?}"
        );
    }
}

#[test]
fn audit_lock_fixtures_exercise_warning_and_vulnerability_states() {
    let root = workspace_root();
    let warning = lock_packages(&parse_toml(
        &root.join(".github/fixtures/cargo-audit/unmaintained/Cargo.lock"),
    ));
    let vulnerable = lock_packages(&parse_toml(
        &root.join(".github/fixtures/cargo-audit/vulnerable/Cargo.lock"),
    ));
    assert_eq!(
        warning,
        BTreeMap::from([("bincode".to_owned(), "2.0.1".to_owned())])
    );
    assert_eq!(
        vulnerable,
        BTreeMap::from([("quick-xml".to_owned(), "0.39.4".to_owned())])
    );
}

#[test]
fn every_external_deny_exception_location_is_rejected() {
    let unique = format!(
        "gta-claw-deny-exceptions-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);

    for relative in DENY_EXCEPTION_PATHS {
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove prior exception fixture");
        }
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("exception path has a parent"))
            .expect("create exception fixture directory");
        fs::write(&path, "exceptions = []\n").expect("write exception fixture");
        assert_eq!(
            deny_exception_files(&root),
            vec![relative.to_owned()],
            "exception path was not detected: {relative}"
        );
    }

    fs::remove_dir_all(root).expect("remove exception fixture");
}

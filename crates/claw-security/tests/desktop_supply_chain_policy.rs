//! Structured policy checks for the isolated desktop dependency graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};
use sha2::{Digest as _, Sha256};
use toml::Value as TomlValue;

const BOOTSTRAP_SCRIPT_SHA256: &str =
    "b4c11b68cb16c11558ca086bf8085a3ddaa294eca6cbab205e70d3dc8be9325d";
const AUDIT_EXIT_SCRIPT_SHA256: &str =
    "285cf03a038395829455b55d4fc62ab4f9384be691dc48313e4ef482489e878f";
const DENY_FIXTURE_SCRIPT_SHA256: &str =
    "06c0911ce79c90705f5b03c2b0a1d9db6997adc9deba4b1ecfec56c4301e395c";
const WILDCARD_FIXTURE_SCRIPT_SHA256: &str =
    "c0d077bd1e5fc9b0ec887cef0e51aacd773f06993c5bb03b5afac36d8b1c877b";
const POLICY_RUN_SCRIPT_SHA256: &str =
    "9904d256519d4d907ec1644dc21ce5e3d38af671dbd0e9547026f6b1f077098a";
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
const CARGO_CONFIG_PATHS: [&str; 4] = [
    ".cargo/config",
    ".cargo/config.toml",
    "desktop/.cargo/config",
    "desktop/.cargo/config.toml",
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

fn cargo_config_files(root: &Path) -> Vec<String> {
    CARGO_CONFIG_PATHS
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
    let steps = job_steps_mut(workflow, job)?;
    if steps
        .iter()
        .filter(|step| yaml_string(yaml_get(step, "name")) == Some(name))
        .count()
        != 1
    {
        return None;
    }
    steps
        .iter_mut()
        .find(|step| yaml_string(yaml_get(step, "name")) == Some(name))
}

fn write_actionlint_case(
    root: &Path,
    name: &str,
    rust: &YamlValue,
    macos: &YamlValue,
) -> [PathBuf; 2] {
    let root = root.join(name);
    fs::create_dir_all(&root).expect("create actionlint case directory");
    let rust_path = root.join("rust.yml");
    let macos_path = root.join("macos-packaging.yml");
    fs::write(
        &rust_path,
        serde_yaml_ng::to_string(rust).expect("serialize Rust workflow mutation"),
    )
    .expect("write Rust workflow mutation");
    fs::write(
        &macos_path,
        serde_yaml_ng::to_string(macos).expect("serialize macOS workflow mutation"),
    )
    .expect("write macOS workflow mutation");
    [rust_path, macos_path]
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
    if yaml_mapping_keys(Some(events))
        != Some(expected_set(&["pull_request", "push", "workflow_dispatch"]))
    {
        errors.push("rust workflow trigger events changed".to_owned());
    }
    if yaml_mapping_keys(yaml_get(events, "push")) != Some(expected_set(&["branches", "paths"])) {
        errors.push("rust push trigger keys changed".to_owned());
    }
    if yaml_mapping_keys(yaml_get(events, "pull_request")) != Some(expected_set(&["paths"])) {
        errors.push("rust pull_request trigger keys changed".to_owned());
    }
    if yaml_get(events, "workflow_dispatch") != Some(&YamlValue::Null) {
        errors.push("rust workflow_dispatch trigger must be unconditional".to_owned());
    }
    let expected_paths = [
        ".cargo/**",
        ".gitattributes",
        ".github/fixtures/cargo-audit/**",
        ".github/fixtures/security-tools/**",
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
        "Test desktop wildcard dependency policy",
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
        if yaml_string(yaml_get(step, "shell"))
            != Some(
                "/usr/bin/env -i PATH=/usr/bin:/bin /bin/bash --noprofile --norc -euo pipefail {0}",
            )
        {
            errors.push(
                "verified tool bootstrap shell must clear the startup environment".to_owned(),
            );
        }
        let expected_env = BTreeMap::from([
            (
                "BASH_ENV".to_owned(),
                "${{ github.workspace }}/.github/fixtures/security-tools/bash-env-poison.sh"
                    .to_owned(),
            ),
            (
                "BASH_ENV_POISON_MARKER".to_owned(),
                "${{ runner.temp }}/bootstrap-bash-env-poisoned".to_owned(),
            ),
            (
                "PATH".to_owned(),
                "${{ github.workspace }}/.github/fixtures/security-tools/shadow-bin".to_owned(),
            ),
            (
                "SHADOW_TOOL_POISON_MARKER".to_owned(),
                "${{ runner.temp }}/bootstrap-shadow-tool-poisoned".to_owned(),
            ),
        ]);
        if yaml_string_map(yaml_get(step, "env")) != Some(expected_env) {
            errors.push("verified tool bootstrap environment changed".to_owned());
        }
        validate_script_hash(step, bootstrap_name, BOOTSTRAP_SCRIPT_SHA256, errors);
    }

    let exact_runs = [
        (
            "Check root dependency policy",
            "\"${{ runner.temp }}/verified-rust-security-tools/bin/run-cargo-deny-clean\" --manifest-path \"${{ github.workspace }}/Cargo.toml\" --locked --all-features check --config \"${{ github.workspace }}/deny.toml\"",
        ),
        (
            "Audit root lockfile",
            "\"${{ runner.temp }}/verified-rust-security-tools/cargo-audit/bin/cargo-audit\" audit --file Cargo.lock",
        ),
        (
            "Audit desktop lockfile",
            "\"${{ runner.temp }}/verified-rust-security-tools/cargo-audit/bin/cargo-audit\" audit --file desktop/Cargo.lock --no-fetch",
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

    if let Some(step) = step_by_name(workflow, "supply-chain", "Validate supply-chain policy") {
        validate_step_keys(
            step,
            "Validate supply-chain policy",
            &["name", "shell", "run"],
            errors,
        );
        if yaml_string(yaml_get(step, "shell")) != Some("bash")
            || yaml_get(step, "env").is_some()
            || yaml_get(step, "working-directory").is_some()
        {
            errors.push("Validate supply-chain policy controls changed".to_owned());
        }
        validate_script_hash(
            step,
            "Validate supply-chain policy",
            POLICY_RUN_SCRIPT_SHA256,
            errors,
        );
    }

    for (name, hash) in [
        ("Test cargo-audit exit policy", AUDIT_EXIT_SCRIPT_SHA256),
        (
            "Test cargo-deny lock and exception policy",
            DENY_FIXTURE_SCRIPT_SHA256,
        ),
        (
            "Test desktop wildcard dependency policy",
            WILDCARD_FIXTURE_SCRIPT_SHA256,
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
            "\"${{{{ runner.temp }}}}/verified-rust-security-tools/bin/run-cargo-deny-clean\" --manifest-path \"${{{{ github.workspace }}}}/desktop/Cargo.toml\" --locked --target {target} check --config \"${{{{ github.workspace }}}}/desktop/deny.toml\" --warn unmaintained advisories bans licenses sources"
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
    if yaml_mapping_keys(Some(workflow))
        != Some(expected_set(&[
            "concurrency",
            "jobs",
            "name",
            "on",
            "permissions",
        ]))
    {
        errors.push("rust workflow top-level schema changed".to_owned());
    }
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
    if yaml_mapping_keys(Some(workflow))
        != Some(expected_set(&[
            "concurrency",
            "env",
            "jobs",
            "name",
            "on",
            "permissions",
        ]))
    {
        errors.push("macOS workflow top-level schema changed".to_owned());
    }
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
    let events = yaml_get(workflow, "on").unwrap_or(&YamlValue::Null);
    if yaml_mapping_keys(Some(events))
        != Some(expected_set(&["pull_request", "push", "workflow_dispatch"]))
    {
        errors.push("macOS workflow trigger events changed".to_owned());
    }
    let expected_paths = [
        ".github/workflows/macos-packaging.yml",
        "packaging/macos/**",
        "apps/**",
        "crates/**",
        "desktop/**",
        "Cargo.lock",
        "Cargo.toml",
        "rust-toolchain.toml",
    ]
    .map(str::to_owned)
    .to_vec();
    if yaml_mapping_keys(yaml_get(events, "push")) != Some(expected_set(&["branches", "paths"]))
        || yaml_string_list(yaml_get(
            yaml_get(events, "push").unwrap_or(&YamlValue::Null),
            "branches",
        )) != Some(vec!["main".to_owned()])
        || yaml_string_list(yaml_get(
            yaml_get(events, "push").unwrap_or(&YamlValue::Null),
            "paths",
        )) != Some(expected_paths.clone())
    {
        errors.push("macOS push trigger changed".to_owned());
    }
    if yaml_mapping_keys(yaml_get(events, "pull_request")) != Some(expected_set(&["paths"]))
        || yaml_string_list(yaml_get(
            yaml_get(events, "pull_request").unwrap_or(&YamlValue::Null),
            "paths",
        )) != Some(expected_paths)
    {
        errors.push("macOS pull_request trigger changed".to_owned());
    }
    let dispatch = yaml_get(events, "workflow_dispatch").unwrap_or(&YamlValue::Null);
    if yaml_mapping_keys(Some(dispatch)) != Some(expected_set(&["inputs"])) {
        errors.push("macOS workflow_dispatch trigger keys changed".to_owned());
    }
    let inputs = yaml_get(dispatch, "inputs").unwrap_or(&YamlValue::Null);
    if yaml_mapping_keys(Some(inputs))
        != Some(expected_set(&["release", "release_commit", "version"]))
    {
        errors.push("macOS workflow_dispatch inputs changed".to_owned());
    }
    let release = yaml_get(inputs, "release").unwrap_or(&YamlValue::Null);
    if yaml_mapping_keys(Some(release))
        != Some(expected_set(&[
            "default",
            "description",
            "required",
            "type",
        ]))
        || yaml_bool(yaml_get(release, "required")) != Some(true)
        || yaml_bool(yaml_get(release, "default")) != Some(false)
        || yaml_string(yaml_get(release, "type")) != Some("boolean")
    {
        errors.push("macOS release dispatch input changed".to_owned());
    }
    for name in ["version", "release_commit"] {
        let input = yaml_get(inputs, name).unwrap_or(&YamlValue::Null);
        if yaml_mapping_keys(Some(input))
            != Some(expected_set(&["description", "required", "type"]))
            || yaml_bool(yaml_get(input, "required")) != Some(false)
            || yaml_string(yaml_get(input, "type")) != Some("string")
        {
            errors.push(format!("macOS {name} dispatch input changed"));
        }
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

fn package_spec(name: &str, version: &str) -> TomlValue {
    TomlValue::Table(toml::map::Map::from_iter([
        ("name".to_owned(), TomlValue::String(name.to_owned())),
        ("version".to_owned(), TomlValue::String(version.to_owned())),
    ]))
}

fn validate_deny_toml(deny: &TomlValue) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(root) = deny.as_table() else {
        return vec!["desktop deny config must be a TOML table".to_owned()];
    };
    if toml_keys(root) != expected_set(&["advisories", "bans", "graph", "licenses", "sources"]) {
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

    let expected_skip = TomlValue::Array(vec![
        package_spec("bitflags", "=1.3.2"),
        package_spec("block2", "=0.5.1"),
        package_spec("core-foundation", "=0.9.4"),
        package_spec("hashbrown", "=0.14.5"),
        package_spec("hashbrown", "=0.16.1"),
        package_spec("objc2", "=0.5.2"),
        package_spec("objc2-app-kit", "=0.2.2"),
        package_spec("objc2-foundation", "=0.2.2"),
        package_spec("smol_str", "=0.2.2"),
        package_spec("windows-sys", "=0.52.0"),
    ]);
    let bans = toml_table(deny, "bans");
    if bans.is_none_or(|table| {
        toml_keys(table)
            != expected_set(&[
                "highlight",
                "multiple-versions",
                "skip",
                "skip-tree",
                "wildcards",
            ])
            || table.get("multiple-versions").and_then(TomlValue::as_str) != Some("deny")
            || table.get("wildcards").and_then(TomlValue::as_str) != Some("deny")
            || table.get("highlight").and_then(TomlValue::as_str) != Some("all")
            || table.get("skip") != Some(&expected_skip)
            || table.get("skip-tree") != Some(&TomlValue::Array(Vec::new()))
    }) {
        errors.push("desktop deny bans policy changed".to_owned());
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
    let expected_skip = TomlValue::Array(vec![
        package_spec("rand_core", "=0.6.4"),
        package_spec("windows-sys", "=0.52.0"),
    ]);
    if bans.is_none_or(|table| {
        toml_keys(table) != expected_set(&["highlight", "multiple-versions", "skip", "wildcards"])
            || table.get("multiple-versions").and_then(TomlValue::as_str) != Some("deny")
            || table.get("wildcards").and_then(TomlValue::as_str) != Some("deny")
            || table.get("highlight").and_then(TomlValue::as_str) != Some("all")
            || table.get("skip") != Some(&expected_skip)
    }) {
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

fn collect_named_toml_paths(
    value: &TomlValue,
    current: &mut Vec<String>,
    names: &[&str],
    paths: &mut BTreeSet<String>,
) {
    match value {
        TomlValue::Table(table) => {
            for (key, value) in table {
                current.push(key.clone());
                if names.contains(&key.as_str()) {
                    paths.insert(current.join("."));
                }
                collect_named_toml_paths(value, current, names, paths);
                current.pop();
            }
        }
        TomlValue::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                current.push(format!("[{index}]"));
                collect_named_toml_paths(value, current, names, paths);
                current.pop();
            }
        }
        _ => {}
    }
}

fn collect_slint_package_aliases(
    value: &TomlValue,
    current: &mut Vec<String>,
    paths: &mut BTreeSet<String>,
) {
    match value {
        TomlValue::Table(table) => {
            if matches!(
                table.get("package").and_then(TomlValue::as_str),
                Some("slint" | "slint-build")
            ) {
                paths.insert(current.join("."));
            }
            for (key, value) in table {
                current.push(key.clone());
                collect_slint_package_aliases(value, current, paths);
                current.pop();
            }
        }
        TomlValue::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                current.push(format!("[{index}]"));
                collect_slint_package_aliases(value, current, paths);
                current.pop();
            }
        }
        _ => {}
    }
}

fn validate_dependency_graph(
    desktop_manifest: &TomlValue,
    app_manifest: &TomlValue,
    desktop_lock: &TomlValue,
    root_lock: &TomlValue,
) -> Vec<String> {
    let mut errors = Vec::new();
    if desktop_manifest.get("patch").is_some() || desktop_manifest.get("replace").is_some() {
        errors.push("desktop must not patch or replace registry sources".to_owned());
    }
    let workspace_dependencies = desktop_manifest
        .get("workspace")
        .and_then(TomlValue::as_table)
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(TomlValue::as_table);
    if workspace_dependencies.is_none_or(|dependencies| {
        toml_keys(dependencies) != expected_set(&["claw-application", "claw-platform"])
    }) {
        errors.push("desktop workspace dependency keys changed".to_owned());
    }
    for (name, path) in [
        ("claw-application", "../crates/claw-application"),
        ("claw-platform", "../crates/claw-platform"),
    ] {
        let dependency = workspace_dependencies
            .and_then(|dependencies| dependencies.get(name))
            .and_then(TomlValue::as_table);
        if dependency.is_none_or(|dependency| {
            toml_keys(dependency) != expected_set(&["path", "version"])
                || dependency.get("path").and_then(TomlValue::as_str) != Some(path)
                || dependency.get("version").and_then(TomlValue::as_str) != Some("0.1.0")
        }) {
            errors.push(format!(
                "desktop workspace dependency policy changed: {name}"
            ));
        }
    }
    let mut workspace_slint_paths = BTreeSet::new();
    collect_named_toml_paths(
        desktop_manifest,
        &mut Vec::new(),
        &["slint", "slint-build"],
        &mut workspace_slint_paths,
    );
    let mut workspace_aliases = BTreeSet::new();
    collect_slint_package_aliases(desktop_manifest, &mut Vec::new(), &mut workspace_aliases);
    if !workspace_slint_paths.is_empty() || !workspace_aliases.is_empty() {
        errors.push(format!(
            "desktop workspace contains unexpected Slint declarations: keys={workspace_slint_paths:?}, aliases={workspace_aliases:?}"
        ));
    }

    let target_tables = app_manifest.get("target").and_then(TomlValue::as_table);
    let target_name = r#"cfg(any(target_os = "windows", target_os = "macos"))"#;
    if target_tables.is_none_or(|targets| toml_keys(targets) != expected_set(&[target_name])) {
        errors.push("desktop target table schema changed".to_owned());
    }
    let target = target_tables
        .and_then(|target| target.get(target_name))
        .and_then(TomlValue::as_table);
    if target.is_none_or(|target| {
        toml_keys(target) != expected_set(&["build-dependencies", "dependencies"])
    }) {
        errors.push("desktop target dependency table schema changed".to_owned());
    }
    let dependencies = target
        .and_then(|target| target.get("dependencies"))
        .and_then(TomlValue::as_table);
    if dependencies.is_none_or(|dependencies| {
        toml_keys(dependencies) != expected_set(&["claw-application", "claw-platform", "slint"])
    }) {
        errors.push("desktop target dependency keys changed".to_owned());
    }
    for name in ["claw-application", "claw-platform"] {
        let dependency = dependencies
            .and_then(|dependencies| dependencies.get(name))
            .and_then(TomlValue::as_table);
        if dependency.is_none_or(|dependency| {
            toml_keys(dependency) != expected_set(&["workspace"])
                || dependency.get("workspace").and_then(TomlValue::as_bool) != Some(true)
        }) {
            errors.push(format!(
                "desktop app workspace dependency policy changed: {name}"
            ));
        }
    }
    let build_dependencies = target
        .and_then(|target| target.get("build-dependencies"))
        .and_then(TomlValue::as_table);
    if build_dependencies
        .is_none_or(|dependencies| toml_keys(dependencies) != expected_set(&["slint-build"]))
    {
        errors.push("desktop target build-dependency keys changed".to_owned());
    }

    let slint_build = build_dependencies
        .and_then(|dependencies| dependencies.get("slint-build"))
        .and_then(TomlValue::as_table);
    if slint_build.is_none_or(|dependency| {
        toml_keys(dependency) != expected_set(&["version"])
            || dependency.get("version").and_then(TomlValue::as_str) != Some("=1.17.1")
    }) {
        errors.push("desktop slint-build dependency policy changed".to_owned());
    }

    let mut slint_paths = BTreeSet::new();
    collect_named_toml_paths(
        app_manifest,
        &mut Vec::new(),
        &["slint", "slint-build"],
        &mut slint_paths,
    );
    let expected_paths = BTreeSet::from([
        format!("target.{target_name}.dependencies.slint"),
        format!("target.{target_name}.build-dependencies.slint-build"),
    ]);
    if slint_paths != expected_paths {
        errors.push(format!(
            "desktop contains unexpected Slint declarations: {slint_paths:?}"
        ));
    }
    let mut aliases = BTreeSet::new();
    collect_slint_package_aliases(app_manifest, &mut Vec::new(), &mut aliases);
    if !aliases.is_empty() {
        errors.push(format!(
            "desktop contains unexpected Slint package aliases: {aliases:?}"
        ));
    }

    let target = app_manifest
        .get("target")
        .and_then(TomlValue::as_table)
        .and_then(|target| target.get(target_name))
        .and_then(TomlValue::as_table);
    let slint = target
        .and_then(|target| target.get("dependencies"))
        .and_then(TomlValue::as_table)
        .and_then(|dependencies| dependencies.get("slint"))
        .and_then(TomlValue::as_table);
    let expected_features = expected_set(&[
        "accessibility",
        "backend-winit-x11",
        "compat-1-2",
        "renderer-femtovg",
        "renderer-software",
        "std",
    ]);
    if slint.is_none_or(|slint| {
        toml_keys(slint) != expected_set(&["default-features", "features", "version"])
            || slint.get("version").and_then(TomlValue::as_str) != Some("=1.17.1")
            || slint.get("default-features").and_then(TomlValue::as_bool) != Some(false)
            || toml_string_set(slint.get("features")) != Some(expected_features.clone())
    }) {
        errors.push("desktop Slint dependency policy changed".to_owned());
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
    manifests: (&mut TomlValue, &mut TomlValue),
) {
    let (desktop_manifest, app_manifest) = manifests;
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
            .insert(
                yaml_key("if"),
                YamlValue::String("github.event_name == 'schedule'".to_owned()),
            );
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
            let steps = job_steps_mut(workflow, "supply-chain").expect("supply-chain steps");
            let before = steps.len();
            steps.retain(|step| {
                yaml_string(yaml_get(step, "name"))
                    != Some("Check Windows ARM64 desktop dependency policy")
            });
            assert_eq!(
                before - steps.len(),
                1,
                "remove exactly one ARM64 deny step"
            );
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
            .insert(
                yaml_key("if"),
                YamlValue::String("github.event_name == 'schedule'".to_owned()),
            );
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
        "bootstrap-inherited-shell" => {
            yaml_mapping_mut(
                step_by_name_mut(
                    workflow,
                    "supply-chain",
                    "Bootstrap verified Rust security tools",
                )
                .expect("bootstrap tools step"),
            )
            .expect("bootstrap tools mapping")
            .insert(yaml_key("shell"), YamlValue::String("bash".to_owned()));
        }
        "bootstrap-shadow-path-change" => {
            let bootstrap = step_by_name_mut(
                workflow,
                "supply-chain",
                "Bootstrap verified Rust security tools",
            )
            .expect("bootstrap tools step");
            yaml_mapping_mut(yaml_get_mut(bootstrap, "env").expect("bootstrap environment"))
                .expect("bootstrap environment mapping")
                .insert(
                    yaml_key("PATH"),
                    YamlValue::String("/tmp/shadow".to_owned()),
                );
        }
        "policy-step-runner-env" => {
            let mut env = YamlMapping::new();
            for key in [
                "CARGO",
                "PATH",
                "RUSTC_WRAPPER",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
                "Cargo_Target_X86_64_Pc_Windows_Msvc_Runner",
            ] {
                env.insert(yaml_key(key), YamlValue::String("/tmp/poison".to_owned()));
            }
            yaml_mapping_mut(
                step_by_name_mut(workflow, "supply-chain", "Validate supply-chain policy")
                    .expect("policy validation step"),
            )
            .expect("policy validation mapping")
            .insert(yaml_key("env"), YamlValue::Mapping(env));
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
        "rust-branches-ignore" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "on").expect("Rust workflow triggers"),
                    "pull_request",
                )
                .expect("Rust pull_request trigger"),
            )
            .expect("Rust pull_request mapping")
            .insert(
                yaml_key("branches-ignore"),
                YamlValue::Sequence(vec![YamlValue::String("main".to_owned())]),
            );
        }
        "rust-types-filter" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(workflow, "on").expect("Rust workflow triggers"),
                    "pull_request",
                )
                .expect("Rust pull_request trigger"),
            )
            .expect("Rust pull_request mapping")
            .insert(
                yaml_key("types"),
                YamlValue::Sequence(vec![YamlValue::String("opened".to_owned())]),
            );
        }
        "macos-branches-ignore" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(macos_workflow, "on").expect("macOS workflow triggers"),
                    "pull_request",
                )
                .expect("macOS pull_request trigger"),
            )
            .expect("macOS pull_request mapping")
            .insert(
                yaml_key("branches-ignore"),
                YamlValue::Sequence(vec![YamlValue::String("main".to_owned())]),
            );
        }
        "macos-types-filter" => {
            yaml_mapping_mut(
                yaml_get_mut(
                    yaml_get_mut(macos_workflow, "on").expect("macOS workflow triggers"),
                    "pull_request",
                )
                .expect("macOS pull_request trigger"),
            )
            .expect("macOS pull_request mapping")
            .insert(
                yaml_key("types"),
                YamlValue::Sequence(vec![YamlValue::String("opened".to_owned())]),
            );
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
            .insert(
                yaml_key("if"),
                YamlValue::String("github.event_name == 'schedule'".to_owned()),
            );
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
        "root-deny-string-skip" => {
            root_deny
                .get_mut("bans")
                .and_then(|bans| bans.get_mut("skip"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny ban skips")
                .push(TomlValue::String("prohibited".to_owned()));
        }
        "root-deny-crate-skip" => {
            root_deny
                .get_mut("bans")
                .and_then(|bans| bans.get_mut("skip"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny ban skips")
                .push(TomlValue::Table(toml::map::Map::from_iter([(
                    "crate".to_owned(),
                    TomlValue::String("prohibited".to_owned()),
                )])));
        }
        "root-deny-versionless-name-skip" => {
            root_deny
                .get_mut("bans")
                .and_then(|bans| bans.get_mut("skip"))
                .and_then(TomlValue::as_array_mut)
                .expect("root deny ban skips")
                .push(TomlValue::Table(toml::map::Map::from_iter([(
                    "name".to_owned(),
                    TomlValue::String("prohibited".to_owned()),
                )])));
        }
        "slint-wildcard-version" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .and_then(|dependencies| dependencies.get_mut("slint"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop Slint dependency")
                .insert("version".to_owned(), TomlValue::String("*".to_owned()));
        }
        "slint-build-caret-version" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("build-dependencies"))
                .and_then(TomlValue::as_table_mut)
                .and_then(|dependencies| dependencies.get_mut("slint-build"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop slint-build dependency")
                .insert("version".to_owned(), TomlValue::String("1.17.1".to_owned()));
        }
        "duplicate-target-slint-widening" => {
            let mut slint = toml::map::Map::new();
            slint.insert(
                "version".to_owned(),
                TomlValue::String("=1.17.1".to_owned()),
            );
            slint.insert("default-features".to_owned(), TomlValue::Boolean(true));
            slint.insert(
                "features".to_owned(),
                TomlValue::Array(vec![TomlValue::String("backend-winit".to_owned())]),
            );
            slint.insert(
                "registry".to_owned(),
                TomlValue::String("alternate".to_owned()),
            );
            let dependencies =
                toml::map::Map::from_iter([("slint".to_owned(), TomlValue::Table(slint))]);
            let duplicate_target = toml::map::Map::from_iter([(
                "dependencies".to_owned(),
                TomlValue::Table(dependencies),
            )]);
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .expect("desktop target tables")
                .insert(
                    r#"cfg(target_os = "windows")"#.to_owned(),
                    TomlValue::Table(duplicate_target),
                );
        }
        "renamed-slint-package" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop target dependencies")
                .insert(
                    "claw-application".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([
                        ("package".to_owned(), TomlValue::String("slint".to_owned())),
                        (
                            "version".to_owned(),
                            TomlValue::String("=1.17.1".to_owned()),
                        ),
                        ("default-features".to_owned(), TomlValue::Boolean(true)),
                    ])),
                );
        }
        "workspace-renamed-slint-package" => {
            desktop_manifest
                .get_mut("workspace")
                .and_then(TomlValue::as_table_mut)
                .and_then(|workspace| workspace.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop workspace dependencies")
                .insert(
                    "claw-application".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([
                        ("package".to_owned(), TomlValue::String("slint".to_owned())),
                        (
                            "version".to_owned(),
                            TomlValue::String("=1.17.1".to_owned()),
                        ),
                        ("default-features".to_owned(), TomlValue::Boolean(true)),
                    ])),
                );
        }
        "app-claw-application-registry" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop app dependencies")
                .insert(
                    "claw-application".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([(
                        "version".to_owned(),
                        TomlValue::String("0.1.0".to_owned()),
                    )])),
                );
        }
        "app-claw-platform-path" => {
            app_manifest
                .get_mut("target")
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| {
                    target.get_mut(r#"cfg(any(target_os = "windows", target_os = "macos"))"#)
                })
                .and_then(TomlValue::as_table_mut)
                .and_then(|target| target.get_mut("dependencies"))
                .and_then(TomlValue::as_table_mut)
                .expect("desktop app dependencies")
                .insert(
                    "claw-platform".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([(
                        "path".to_owned(),
                        TomlValue::String("../../../../untrusted".to_owned()),
                    )])),
                );
        }
        "desktop-replace-slint-build" => {
            desktop_manifest
                .as_table_mut()
                .expect("desktop manifest table")
                .insert(
                    "replace".to_owned(),
                    TomlValue::Table(toml::map::Map::from_iter([(
                        "slint-build:1.17.1".to_owned(),
                        TomlValue::Table(toml::map::Map::from_iter([(
                            "path".to_owned(),
                            TomlValue::String("vendor/slint-build".to_owned()),
                        )])),
                    )])),
                );
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
    let cargo_configs = cargo_config_files(&root);
    if !cargo_configs.is_empty() {
        errors.push(format!(
            "repository Cargo configuration is forbidden for security enforcement: {cargo_configs:?}"
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
    let desktop_manifest = parse_toml(&root.join("desktop/Cargo.toml"));
    let baseline_app_manifest = parse_toml(&root.join("desktop/apps/gta-claw-desktop/Cargo.toml"));
    let desktop_lock = parse_toml(&root.join("desktop/Cargo.lock"));
    let root_lock = parse_toml(&root.join("Cargo.lock"));
    let cases = parse_toml(&root.join(
        "crates/claw-security/tests/fixtures/desktop_supply_chain_policy/negative-cases.toml",
    ));

    let cases = cases
        .get("case")
        .and_then(TomlValue::as_array)
        .expect("negative policy cases");
    assert_eq!(cases.len(), 48, "every bypass category must remain covered");
    let require_actionlint = std::env::var("REQUIRE_ACTIONLINT").as_deref() == Ok("true");
    let actionlint = require_actionlint.then(|| {
        let path = PathBuf::from(
            std::env::var_os("ACTIONLINT_BIN")
                .expect("ACTIONLINT_BIN is required by hosted policy"),
        );
        assert!(
            path.is_absolute() && path.is_file(),
            "ACTIONLINT_BIN must be an absolute file"
        );
        path
    });
    let actionlint_root =
        std::env::temp_dir().join(format!("gta-claw-actionlint-{}", std::process::id()));
    if actionlint_root.exists() {
        fs::remove_dir_all(&actionlint_root).expect("remove prior actionlint fixtures");
    }
    if require_actionlint {
        fs::create_dir_all(&actionlint_root).expect("create actionlint fixtures");
    }
    let mut actionlint_paths = Vec::new();
    let mut mutated_cases = Vec::new();
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
        let mut desktop_manifest = desktop_manifest.clone();
        let mut app_manifest = baseline_app_manifest.clone();
        mutate_negative_case(
            mutation,
            &mut workflow,
            &mut macos_workflow,
            &mut root_deny,
            &mut deny,
            &mut audit,
            (&mut desktop_manifest, &mut app_manifest),
        );
        if require_actionlint {
            actionlint_paths.extend(write_actionlint_case(
                &actionlint_root,
                name,
                &workflow,
                &macos_workflow,
            ));
        }
        mutated_cases.push((
            name.to_owned(),
            expected.to_owned(),
            workflow,
            macos_workflow,
            root_deny,
            deny,
            audit,
            desktop_manifest,
            app_manifest,
        ));
    }

    if let Some(actionlint) = actionlint {
        let output = Command::new(actionlint)
            .args(["-shellcheck=", "-pyflakes=", "-ignore", "macos-15-intel"])
            .args(&actionlint_paths)
            .output()
            .expect("run pinned actionlint over semantic mutations");
        assert!(
            output.status.success(),
            "semantic workflow mutations were not actionlint-valid:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        fs::remove_dir_all(&actionlint_root).expect("remove actionlint fixtures");
    }

    for (
        name,
        expected,
        workflow,
        macos_workflow,
        root_deny,
        deny,
        audit,
        desktop_manifest,
        app_manifest,
    ) in mutated_cases
    {
        let mut violations = validate_rust_workflow(&workflow);
        violations.extend(validate_macos_workflow(&macos_workflow));
        violations.extend(validate_root_deny_toml(&root_deny));
        violations.extend(validate_deny_toml(&deny));
        violations.extend(validate_audit_toml(&audit));
        violations.extend(validate_dependency_graph(
            &desktop_manifest,
            &app_manifest,
            &desktop_lock,
            &root_lock,
        ));
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(&expected)),
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

#[test]
fn every_repository_cargo_config_location_is_rejected() {
    let unique = format!(
        "gta-claw-cargo-config-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);

    for relative in CARGO_CONFIG_PATHS {
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove prior Cargo config fixture");
        }
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("Cargo config path has a parent"))
            .expect("create Cargo config fixture directory");
        fs::write(&path, "[target.'cfg(all())']\nrunner = \"/bin/true\"\n")
            .expect("write Cargo config fixture");
        assert_eq!(
            cargo_config_files(&root),
            vec![relative.to_owned()],
            "Cargo config path was not detected: {relative}"
        );
    }

    fs::remove_dir_all(root).expect("remove Cargo config fixture");
}

#[test]
fn sanitized_direct_policy_execution_ignores_runner_and_path_poison() {
    let unique = format!(
        "gta-claw-sanitized-policy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock is after the epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    fs::create_dir_all(&root).expect("create sanitized policy fixture");
    let runner_marker = root.join("runner-executed");
    let cargo_marker = root.join("cargo-shadow-executed");
    let policy_marker = root.join("policy-executed");

    #[cfg(windows)]
    let (runner, cargo_shadow) = {
        let runner = root.join("runner.cmd");
        let cargo = root.join("cargo.cmd");
        fs::write(
            &runner,
            format!(
                "@echo executed>\"{}\"\r\n@exit /b 0\r\n",
                runner_marker.display()
            ),
        )
        .expect("write Windows runner poison");
        fs::write(
            &cargo,
            format!(
                "@echo executed>\"{}\"\r\n@exit /b 0\r\n",
                cargo_marker.display()
            ),
        )
        .expect("write Windows Cargo poison");
        (runner, cargo)
    };

    #[cfg(not(windows))]
    let (runner, cargo_shadow) = {
        use std::os::unix::fs::PermissionsExt as _;

        let runner = root.join("runner");
        let cargo = root.join("cargo");
        fs::write(
            &runner,
            format!(
                "#!/bin/sh\nprintf executed >'{}'\n",
                runner_marker.display()
            ),
        )
        .expect("write Unix runner poison");
        fs::write(
            &cargo,
            format!("#!/bin/sh\nprintf executed >'{}'\n", cargo_marker.display()),
        )
        .expect("write Unix Cargo poison");
        fs::set_permissions(&runner, fs::Permissions::from_mode(0o755))
            .expect("make runner poison executable");
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))
            .expect("make Cargo poison executable");
        (runner, cargo)
    };

    let current_exe = std::env::current_exe().expect("resolve absolute policy test binary");
    assert!(current_exe.is_absolute());
    let status = Command::new(&current_exe)
        .env("CARGO", &cargo_shadow)
        .env("PATH", &root)
        .env("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", &runner)
        .env("cargo_target_x86_64_pc_windows_msvc_runner", &runner)
        .env("RUSTC_WRAPPER", &runner)
        .env_clear()
        .env("SANITIZED_POLICY_MARKER", &policy_marker)
        .args([
            "--exact",
            "sanitized_environment_child",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .expect("execute absolute policy test binary");
    assert!(status.success(), "sanitized child policy test failed");
    assert!(
        policy_marker.is_file(),
        "real policy test binary did not run"
    );
    assert!(!runner_marker.exists(), "hostile target runner executed");
    assert!(!cargo_marker.exists(), "PATH/CARGO shadow executed");
    fs::remove_dir_all(root).expect("remove sanitized policy fixture");
}

#[test]
#[ignore = "direct child for sanitized process environment regression"]
fn sanitized_environment_child() {
    let marker =
        PathBuf::from(std::env::var_os("SANITIZED_POLICY_MARKER").expect("policy marker path"));
    for (key, _) in std::env::vars_os() {
        let normalized = key.to_string_lossy().to_ascii_uppercase();
        assert_ne!(normalized, "CARGO");
        assert_ne!(normalized, "RUSTC_WRAPPER");
        assert!(!normalized.starts_with("CARGO_TARGET_") || !normalized.ends_with("_RUNNER"));
    }
    fs::write(marker, "executed\n").expect("write policy execution marker");
}

//! Structured policy checks for the isolated desktop dependency graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};
use toml::Value as TomlValue;

const CARGO_DENY_ACTION: &str =
    "EmbarkStudios/cargo-deny-action@8f84122a46a358a27cb0625d85ad60ab436a1b87";
const CARGO_AUDIT_VERSION: &str = "0.22.2";
const CARGO_AUDIT_CRATE_SHA256: &str =
    "700c2b240f7fd330c24b675fe429f73a5b676531fcc6300400b2b67f155ba12a";
const DENY_COMMAND_ARGUMENTS: &str =
    "--config desktop/deny.toml --warn unmaintained advisories licenses sources";
const INSTALL_CARGO_AUDIT_SCRIPT: &str = r#"set -euo pipefail
cargo info "cargo-audit@${CARGO_AUDIT_VERSION}" --quiet
mapfile -t archives < <(
  find "${CARGO_HOME:-$HOME/.cargo}/registry/cache" \
    -type f -name "cargo-audit-${CARGO_AUDIT_VERSION}.crate"
)
test "${#archives[@]}" -gt 0
for archive in "${archives[@]}"; do
  printf '%s  %s\n' "$CARGO_AUDIT_CRATE_SHA256" "$archive" |
    sha256sum --check -
done
cargo install cargo-audit --version "=${CARGO_AUDIT_VERSION}" --locked --force
test "$(cargo audit --version)" = "cargo-audit-audit ${CARGO_AUDIT_VERSION}"
"#;
const AUDIT_EXIT_POLICY_SCRIPT: &str = r#"set -euo pipefail
for event_name in pull_request push; do
  export GITHUB_EVENT_NAME="$event_name"
  if [[ "$event_name" == "pull_request" ]]; then
    export GITHUB_HEAD_REF="audit-policy-fixture"
  else
    unset GITHUB_HEAD_REF
  fi

  warning_output="$(
    cargo audit --no-fetch \
      --file .github/fixtures/cargo-audit/unmaintained/Cargo.lock 2>&1
  )"
  printf '%s\n' "$warning_output"
  grep -F "RUSTSEC-2025-0141" <<<"$warning_output"

  set +e
  vulnerable_output="$(
    cargo audit --no-fetch \
      --file .github/fixtures/cargo-audit/vulnerable/Cargo.lock 2>&1
  )"
  vulnerable_status=$?
  set -e
  printf '%s\n' "$vulnerable_output"
  test "$vulnerable_status" -ne 0
  grep -F "RUSTSEC-2026-0194" <<<"$vulnerable_output"
  grep -F "RUSTSEC-2026-0195" <<<"$vulnerable_output"
done
"#;

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

fn parse_yaml(path: &Path) -> YamlValue {
    serde_yaml_ng::from_str(&read(path))
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

fn parse_toml(path: &Path) -> TomlValue {
    toml::from_str(&read(path)).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
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
        "deny.toml",
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

fn validate_install_step(workflow: &YamlValue, errors: &mut Vec<String>) {
    let name = "Install pinned cargo-audit";
    let Some(step) = step_by_name(workflow, "supply-chain", name) else {
        errors.push(format!("missing {name} step"));
        return;
    };
    validate_critical_step(step, name, errors);
    if yaml_string(yaml_get(step, "shell")) != Some("bash")
        || yaml_string(yaml_get(step, "run")) != Some(INSTALL_CARGO_AUDIT_SCRIPT)
    {
        errors.push("cargo-audit install command is not exact".to_owned());
    }
    let env = yaml_get(step, "env").unwrap_or(&YamlValue::Null);
    if yaml_string(yaml_get(env, "CARGO_AUDIT_VERSION")) != Some(CARGO_AUDIT_VERSION)
        || yaml_string(yaml_get(env, "CARGO_AUDIT_CRATE_SHA256")) != Some(CARGO_AUDIT_CRATE_SHA256)
    {
        errors.push("cargo-audit version and crate checksum must be exact".to_owned());
    }
}

fn validate_audit_exit_step(workflow: &YamlValue, errors: &mut Vec<String>) {
    let name = "Test cargo-audit exit policy";
    let Some(step) = step_by_name(workflow, "supply-chain", name) else {
        errors.push(format!("missing {name} step"));
        return;
    };
    validate_critical_step(step, name, errors);
    if yaml_string(yaml_get(step, "shell")) != Some("bash")
        || yaml_string(yaml_get(step, "run")) != Some(AUDIT_EXIT_POLICY_SCRIPT)
    {
        errors.push("cargo-audit push/PR exit fixture command is not exact".to_owned());
    }
}

fn validate_deny_steps(workflow: &YamlValue, errors: &mut Vec<String>) {
    let supported = expected_set(&[
        "aarch64-apple-darwin",
        "aarch64-pc-windows-msvc",
        "x86_64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ]);
    let expected_names = BTreeMap::from([
        (
            "aarch64-apple-darwin",
            "Check macOS ARM64 desktop dependency policy",
        ),
        (
            "aarch64-pc-windows-msvc",
            "Check Windows ARM64 desktop dependency policy",
        ),
        (
            "x86_64-apple-darwin",
            "Check macOS Intel desktop dependency policy",
        ),
        (
            "x86_64-pc-windows-msvc",
            "Check Windows x64 desktop dependency policy",
        ),
    ]);
    let mut actual = BTreeSet::new();
    for step in job_steps(workflow, "supply-chain").into_iter().flatten() {
        if yaml_string(yaml_get(step, "uses")) != Some(CARGO_DENY_ACTION) {
            continue;
        }
        let with = yaml_get(step, "with").unwrap_or(&YamlValue::Null);
        if yaml_string(yaml_get(with, "manifest-path")) != Some("./desktop/Cargo.toml") {
            continue;
        }
        let label = yaml_string(yaml_get(step, "name")).unwrap_or("desktop deny step");
        validate_critical_step(step, label, errors);
        let arguments = yaml_string(yaml_get(with, "arguments")).unwrap_or_default();
        let target = arguments.strip_prefix("--target ").unwrap_or_default();
        actual.insert(target.to_owned());
        if yaml_string(yaml_get(with, "command")) != Some("check")
            || yaml_string(yaml_get(with, "command-arguments")) != Some(DENY_COMMAND_ARGUMENTS)
        {
            errors.push(format!(
                "{label} must run the exact fail-closed deny checks"
            ));
        }
        if expected_names.get(target).copied() != Some(label) {
            errors.push(format!("unexpected deny step name for {target}: {label}"));
        }
    }
    if actual != supported {
        errors.push(format!(
            "desktop deny targets do not match the supported target set: {actual:?}"
        ));
    }
}

fn validate_rust_workflow(workflow: &YamlValue) -> Vec<String> {
    let mut errors = Vec::new();
    validate_permissions(workflow, &mut errors);
    validate_workflow_paths(workflow, &mut errors);
    validate_action_pins(workflow, &mut errors);
    validate_exact_run_step(
        workflow,
        "Validate supply-chain policy",
        "cargo test --locked --package claw-security --test desktop_supply_chain_policy",
        &mut errors,
    );
    validate_install_step(workflow, &mut errors);
    validate_exact_run_step(
        workflow,
        "Audit root lockfile",
        "cargo audit --file Cargo.lock",
        &mut errors,
    );
    validate_exact_run_step(
        workflow,
        "Audit desktop lockfile",
        "cargo audit --file desktop/Cargo.lock --no-fetch",
        &mut errors,
    );
    validate_audit_exit_step(workflow, &mut errors);
    validate_deny_steps(workflow, &mut errors);
    errors
}

fn validate_macos_workflow(workflow: &YamlValue) -> Vec<String> {
    let mut errors = Vec::new();
    validate_permissions(workflow, &mut errors);
    validate_action_pins(workflow, &mut errors);

    let matrix_include = yaml_sequence(yaml_get(
        yaml_get(
            yaml_get(
                yaml_get(workflow, "jobs")
                    .and_then(|jobs| yaml_get(jobs, "native"))
                    .unwrap_or(&YamlValue::Null),
                "strategy",
            )
            .unwrap_or(&YamlValue::Null),
            "matrix",
        )
        .unwrap_or(&YamlValue::Null),
        "include",
    ));
    let actual_matrix = matrix_include
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            Some((
                yaml_string(yaml_get(entry, "runner"))?.to_owned(),
                yaml_string(yaml_get(entry, "arch"))?.to_owned(),
            ))
        })
        .collect::<BTreeSet<_>>();
    let expected_matrix = BTreeSet::from([
        ("macos-15".to_owned(), "arm64".to_owned()),
        ("macos-15-intel".to_owned(), "x86_64".to_owned()),
    ]);
    if actual_matrix != expected_matrix {
        errors.push(format!(
            "native macOS matrix must cover ARM64 and Intel: {actual_matrix:?}"
        ));
    }

    let name = "Smoke-test native desktop window backend";
    let Some(step) = step_by_name(workflow, "native", name) else {
        errors.push(format!("missing {name} step"));
        return errors;
    };
    validate_critical_step(step, name, &mut errors);
    if yaml_get(step, "timeout-minutes").and_then(YamlValue::as_u64) != Some(2) {
        errors.push("macOS backend smoke must have a two-minute hard timeout".to_owned());
    }
    if yaml_string(yaml_get(
        yaml_get(step, "env").unwrap_or(&YamlValue::Null),
        "SLINT_BACKEND",
    )) != Some("winit-software")
    {
        errors.push("macOS backend smoke must select winit-software".to_owned());
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
                step_by_name_mut(workflow, "supply-chain", "Install pinned cargo-audit")
                    .expect("install audit step"),
            )
            .expect("install audit mapping")
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
        other => panic!("unknown policy mutation: {other}"),
    }
}

#[test]
fn repository_policy_is_structurally_fail_closed() {
    let root = workspace_root();
    let rust_workflow = parse_yaml(&root.join(".github/workflows/rust.yml"));
    let macos_workflow = parse_yaml(&root.join(".github/workflows/macos-packaging.yml"));
    let deny = parse_toml(&root.join("desktop/deny.toml"));
    let audit = parse_toml(&root.join(".cargo/audit.toml"));
    let desktop_manifest = parse_toml(&root.join("desktop/Cargo.toml"));
    let app_manifest = parse_toml(&root.join("desktop/apps/gta-claw-desktop/Cargo.toml"));
    let desktop_lock = parse_toml(&root.join("desktop/Cargo.lock"));
    let root_lock = parse_toml(&root.join("Cargo.lock"));

    let mut errors = validate_rust_workflow(&rust_workflow);
    errors.extend(validate_macos_workflow(&macos_workflow));
    errors.extend(validate_deny_toml(&deny));
    errors.extend(validate_audit_toml(&audit));
    errors.extend(validate_dependency_graph(
        &desktop_manifest,
        &app_manifest,
        &desktop_lock,
        &root_lock,
    ));
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
    let baseline_deny = parse_toml(&root.join("desktop/deny.toml"));
    let baseline_audit = parse_toml(&root.join(".cargo/audit.toml"));
    let cases = parse_toml(&root.join(
        "crates/claw-security/tests/fixtures/desktop_supply_chain_policy/negative-cases.toml",
    ));

    let cases = cases
        .get("case")
        .and_then(TomlValue::as_array)
        .expect("negative policy cases");
    assert_eq!(cases.len(), 13, "every bypass category must remain covered");
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
        let mut deny = baseline_deny.clone();
        let mut audit = baseline_audit.clone();
        mutate_negative_case(mutation, &mut workflow, &mut deny, &mut audit);

        let mut violations = validate_rust_workflow(&workflow);
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

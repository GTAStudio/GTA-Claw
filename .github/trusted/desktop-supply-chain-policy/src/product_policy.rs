//! Base-owned atomic transition for the sanctioned product supply-chain hardening.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_yaml_ng::Value as YamlValue;

use crate::input::{DEFAULT_FILE_LIMIT, SafeRoot};
use crate::{PolicyError, PolicyResult, error};

const PACKAGE_JSON: &str = "package.json";
const PACKAGE_LOCK: &str = "package-lock.json";
const DOCKERFILE: &str = "Dockerfile";
const TYPESCRIPT_CONFIG: &str = "src/config.ts";
const TYPESCRIPT_EXECUTOR: &str = "src/engine/toolExecutor.ts";
const TYPESCRIPT_INDEX: &str = "src/index.ts";
const TYPESCRIPT_UPDATER: &str = "src/updater/sdkUpdater.ts";
const RUST_DOMAIN_CONFIG: &str = "crates/claw-config/src/domains.rs";
const RUST_MIGRATION_CONFIG: &str = "crates/claw-config/src/migration.rs";
const PACKAGED_ENV_MAPPING: &str = "crates/claw-config/data/env-mapping.json";
const COMPAT_ENV_MAPPING: &str = "compat/legacy/config/env-mapping.json";
const COMPAT_CONTRACT: &str = "compat/legacy/contract.json";
const COMPAT_REQUIREMENTS: &str = "compat/legacy/scripts/requirements.txt";
const RUST_WORKFLOW: &str = ".github/workflows/rust.yml";
const UPSTREAM_WORKFLOW: &str = ".github/workflows/upstream-gateway-reference.yml";
const ANDROID_WORKFLOW: &str = ".github/workflows/android-packaging.yml";
const IOS_WORKFLOW: &str = ".github/workflows/ios-packaging.yml";
const DOCKER_WORKFLOW: &str = ".github/workflows/docker-publish.yml";
const DESKTOP_BUILD_SCRIPT: &str = "desktop/apps/gta-claw-desktop/build.rs";
const PRODUCT_POLICY_TEST: &str = "crates/claw-repo-policy/tests/repository_policy.rs";

const SETUP_PYTHON_ACTION: &str =
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065";
const DOCKER_ACTION_PINS: [&str; 4] = [
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
    "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9",
    "docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051",
];
const COMPAT_REVISION_DOCUMENTS: [&str; 6] = [
    COMPAT_ENV_MAPPING,
    "compat/legacy/fixtures/http/examples.json",
    "compat/legacy/inventory/bundled-skills.json",
    "compat/legacy/inventory/source-coverage.json",
    "compat/legacy/ledger/behaviors.json",
    "compat/legacy/ledger/features.json",
];

/// Every product input covered by the one-way atomic hardening transition.
pub const HARDENING_TRANSITION_PATHS: [&str; 25] = [
    PACKAGE_JSON,
    PACKAGE_LOCK,
    DOCKERFILE,
    TYPESCRIPT_CONFIG,
    TYPESCRIPT_EXECUTOR,
    TYPESCRIPT_INDEX,
    TYPESCRIPT_UPDATER,
    RUST_DOMAIN_CONFIG,
    RUST_MIGRATION_CONFIG,
    PACKAGED_ENV_MAPPING,
    COMPAT_ENV_MAPPING,
    "compat/legacy/fixtures/http/examples.json",
    "compat/legacy/inventory/bundled-skills.json",
    "compat/legacy/inventory/source-coverage.json",
    "compat/legacy/ledger/behaviors.json",
    "compat/legacy/ledger/features.json",
    COMPAT_CONTRACT,
    COMPAT_REQUIREMENTS,
    RUST_WORKFLOW,
    UPSTREAM_WORKFLOW,
    ANDROID_WORKFLOW,
    IOS_WORKFLOW,
    DOCKER_WORKFLOW,
    DESKTOP_BUILD_SCRIPT,
    "test/toolExecutorIsolation.test.mjs",
];

fn read_json(root: &SafeRoot, path: &str) -> PolicyResult<JsonValue> {
    serde_json::from_str(&root.read_text(path, DEFAULT_FILE_LIMIT)?)
        .map_err(|cause| error(&format!("parse {path}"), cause))
}

fn json_object<'a>(
    value: &'a JsonValue,
    path: &str,
    label: &str,
) -> PolicyResult<&'a JsonMap<String, JsonValue>> {
    value
        .as_object()
        .ok_or_else(|| PolicyError::new(format!("{path} {label} must be an object")))
}

fn exact_semver(version: &str) -> bool {
    if version.is_empty()
        || version.eq_ignore_ascii_case("latest")
        || version
            .chars()
            .any(|character| matches!(character, '/' | '\\' | ':' | '*' | '^' | '~' | '<' | '>' | '=' | '|' | ' '))
    {
        return false;
    }
    let without_build = version.split_once('+').map_or(version, |(core, _)| core);
    let core = without_build
        .split_once('-')
        .map_or(without_build, |(core, _)| core);
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn dependency_map(
    object: &JsonMap<String, JsonValue>,
    key: &str,
    path: &str,
) -> PolicyResult<BTreeMap<String, String>> {
    let Some(value) = object.get(key) else {
        return Ok(BTreeMap::new());
    };
    let dependencies = json_object(value, path, key)?;
    dependencies
        .iter()
        .map(|(name, value)| {
            let version = value.as_str().ok_or_else(|| {
                PolicyError::new(format!("{path} {key}.{name} version must be a string"))
            })?;
            if !exact_semver(version) {
                return Err(PolicyError::new(format!(
                    "{path} {key}.{name} must use one exact package version, not latest, a range, URL, Git, file, or workspace reference: {version:?}"
                )));
            }
            Ok((name.clone(), version.to_owned()))
        })
        .collect()
}

fn require_package_lock_coupling(
    package: &JsonMap<String, JsonValue>,
    lock: &JsonMap<String, JsonValue>,
) -> PolicyResult<(String, String)> {
    if lock.get("lockfileVersion").and_then(JsonValue::as_u64) != Some(3) {
        return Err(PolicyError::new(
            "package-lock.json lockfileVersion must remain exactly 3",
        ));
    }
    let packages = lock
        .get("packages")
        .ok_or_else(|| PolicyError::new("package-lock.json packages object is missing"))
        .and_then(|value| json_object(value, PACKAGE_LOCK, "packages"))?;
    let lock_root = packages
        .get("")
        .ok_or_else(|| PolicyError::new("package-lock.json root package is missing"))
        .and_then(|value| json_object(value, PACKAGE_LOCK, "packages[\"\"]"))?;
    for field in ["name", "version"] {
        let package_value = package.get(field).and_then(JsonValue::as_str);
        let lock_value = lock_root.get(field).and_then(JsonValue::as_str);
        if package_value.is_none() || package_value != lock_value {
            return Err(PolicyError::new(format!(
                "package.json and package-lock.json root {field} are not exactly coupled"
            )));
        }
    }
    if package
        .get("version")
        .and_then(JsonValue::as_str)
        .is_none_or(|version| !exact_semver(version))
    {
        return Err(PolicyError::new(
            "package.json root version must be exact",
        ));
    }

    for group in ["dependencies", "optionalDependencies", "devDependencies"] {
        let manifest = dependency_map(package, group, PACKAGE_JSON)?;
        let locked = dependency_map(lock_root, group, PACKAGE_LOCK)?;
        if manifest != locked {
            return Err(PolicyError::new(format!(
                "package.json and package-lock.json root {group} are not exactly coupled"
            )));
        }
    }

    for (path, package) in packages {
        if path.is_empty() {
            continue;
        }
        let package = json_object(package, PACKAGE_LOCK, path)?;
        if package.get("link").and_then(JsonValue::as_bool) == Some(true) {
            return Err(PolicyError::new(format!(
                "package-lock.json may not contain local link package {path}"
            )));
        }
        let version = package
            .get("version")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                PolicyError::new(format!(
                    "package-lock.json package {path} has no exact version"
                ))
            })?;
        if !exact_semver(version) {
            return Err(PolicyError::new(format!(
                "package-lock.json package {path} has a mutable or non-registry version: {version:?}"
            )));
        }
    }

    let sdk_version = dependency_map(package, "dependencies", PACKAGE_JSON)?
        .get("@github/copilot-sdk")
        .cloned()
        .ok_or_else(|| PolicyError::new("package.json must pin @github/copilot-sdk"))?;
    let sdk_lock = packages
        .get("node_modules/@github/copilot-sdk")
        .ok_or_else(|| PolicyError::new("package-lock.json is missing @github/copilot-sdk"))
        .and_then(|value| {
            json_object(
                value,
                PACKAGE_LOCK,
                "packages[node_modules/@github/copilot-sdk]",
            )
        })?;
    if sdk_lock.get("version").and_then(JsonValue::as_str) != Some(sdk_version.as_str()) {
        return Err(PolicyError::new(
            "package-lock.json @github/copilot-sdk version differs from package.json",
        ));
    }
    let cli_request = sdk_lock
        .get("dependencies")
        .and_then(JsonValue::as_object)
        .and_then(|dependencies| dependencies.get("@github/copilot"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            PolicyError::new("locked Copilot SDK no longer declares its Copilot CLI dependency")
        })?;
    if cli_request
        .strip_prefix('^')
        .is_none_or(|minimum| !exact_semver(minimum))
    {
        return Err(PolicyError::new(
            "locked Copilot SDK declares an unexpected CLI dependency source",
        ));
    }
    let cli_version = packages
        .get("node_modules/@github/copilot")
        .ok_or_else(|| PolicyError::new("package-lock.json is missing the SDK-locked Copilot CLI"))
        .and_then(|value| {
            json_object(
                value,
                PACKAGE_LOCK,
                "packages[node_modules/@github/copilot]",
            )
        })?
        .get("version")
        .and_then(JsonValue::as_str)
        .filter(|version| exact_semver(version))
        .ok_or_else(|| {
            PolicyError::new("package-lock.json Copilot CLI version is not an exact version")
        })?
        .to_owned();
    if cli_request
        .strip_prefix('^')
        .and_then(|minimum| minimum.split('.').next())
        != cli_version.split('.').next()
    {
        return Err(PolicyError::new(
            "SDK-locked Copilot CLI crossed the requested major version",
        ));
    }
    Ok((sdk_version, cli_version))
}

fn require_install_script_allowlist(
    package: &JsonMap<String, JsonValue>,
    lock: &JsonMap<String, JsonValue>,
) -> PolicyResult<Vec<String>> {
    let allow_scripts = package
        .get("allowScripts")
        .ok_or_else(|| PolicyError::new("package.json allowScripts is missing"))
        .and_then(|value| json_object(value, PACKAGE_JSON, "allowScripts"))?;
    let expected = BTreeMap::from([
        ("dtrace-provider".to_owned(), false),
        ("isolated-vm@7.0.0".to_owned(), true),
        ("koffi@3.1.2".to_owned(), true),
    ]);
    let actual = allow_scripts
        .iter()
        .map(|(name, value)| {
            value
                .as_bool()
                .map(|enabled| (name.clone(), enabled))
                .ok_or_else(|| {
                    PolicyError::new(format!(
                        "package.json allowScripts.{name} must be boolean"
                    ))
                })
        })
        .collect::<PolicyResult<BTreeMap<_, _>>>()?;
    if actual != expected {
        return Err(PolicyError::new(
            "package.json install-script allowlist changed from the reviewed three-entry policy",
        ));
    }

    let packages = lock
        .get("packages")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| PolicyError::new("package-lock.json packages object is missing"))?;
    for package in ["isolated-vm@7.0.0", "koffi@3.1.2"] {
        let (name, version) = package
            .split_once('@')
            .ok_or_else(|| PolicyError::new("invalid internal install-script allowlist"))?;
        let lock_path = format!("node_modules/{name}");
        if packages
            .get(&lock_path)
            .and_then(JsonValue::as_object)
            .and_then(|entry| entry.get("version"))
            .and_then(JsonValue::as_str)
            != Some(version)
        {
            return Err(PolicyError::new(format!(
                "package.json allowScripts entry {package} is not coupled to package-lock.json"
            )));
        }
    }
    Ok(expected
        .into_iter()
        .filter_map(|(package, enabled)| enabled.then_some(package))
        .collect())
}

fn validate_node_and_docker(root: &SafeRoot) -> PolicyResult<()> {
    let package_value = read_json(root, PACKAGE_JSON)?;
    let lock_value = read_json(root, PACKAGE_LOCK)?;
    let package = json_object(&package_value, PACKAGE_JSON, "root")?;
    let lock = json_object(&lock_value, PACKAGE_LOCK, "root")?;
    let (_sdk_version, _cli_version) = require_package_lock_coupling(package, lock)?;
    let allowed_scripts = require_install_script_allowlist(package, lock)?;

    let scripts = package
        .get("scripts")
        .ok_or_else(|| PolicyError::new("package.json scripts object is missing"))
        .and_then(|value| json_object(value, PACKAGE_JSON, "scripts"))?;
    let start = scripts
        .get("start")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| PolicyError::new("package.json npm start command is missing"))?;
    if !start.contains("NODE_ENV=production") {
        return Err(PolicyError::new(
            "npm start must set NODE_ENV=production and fail closed without isolated-vm",
        ));
    }
    let development = scripts
        .get("dev")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| PolicyError::new("package.json development command is missing"))?;
    if !development.contains("NODE_ENV=development")
        || !development.contains("GTA_CLAW_ALLOW_REDUCED_ISOLATION=true")
    {
        return Err(PolicyError::new(
            "development command must explicitly opt into reduced node:vm isolation",
        ));
    }
    if scripts
        .get("test:isolation-policy")
        .and_then(JsonValue::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(PolicyError::new(
            "package.json test:isolation-policy command is missing",
        ));
    }

    let docker = root
        .read_text(DOCKERFILE, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    let from_lines = docker
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("FROM "))
        .collect::<Vec<_>>();
    let images = from_lines
        .iter()
        .filter_map(|line| line.split_ascii_whitespace().nth(1))
        .collect::<Vec<_>>();
    if from_lines.len() != 2
        || images.len() != 2
        || images[0] != images[1]
        || images.iter().any(|image| {
            image
                .strip_prefix("node:26-bookworm-slim@sha256:")
                .is_none_or(|digest| !lower_hex(digest, 32))
        })
    {
        return Err(PolicyError::new(
            "Dockerfile must use one identical digest-pinned Node image for both stages",
        ));
    }
    for required in [
        "COPY package.json package-lock.json ./",
        "npm ci --ignore-scripts --no-audit --no-fund",
        "npm prune --omit=dev --ignore-scripts",
        "ENV NODE_ENV=\"production\"",
        "ENV COPILOT_CLI_PATH=\"/app/node_modules/.bin/copilot\"",
        "COPY --from=builder /app/package.json /app/package-lock.json",
        "CMD [\"node\", \"dist/index.js\"]",
    ] {
        if !docker.contains(required) {
            return Err(PolicyError::new(format!(
                "Dockerfile package-root coupling is missing: {required}"
            )));
        }
    }
    let rebuild = format!(
        "npm rebuild --foreground-scripts {}",
        allowed_scripts.join(" ")
    );
    if docker.matches("npm rebuild").count() != 1 || !docker.contains(&rebuild) {
        return Err(PolicyError::new(
            "Dockerfile install-script allowlist changed",
        ));
    }
    for forbidden in [
        "npm install",
        "npm update",
        "npx ",
        "curl ",
        "wget ",
        "corepack ",
    ] {
        if docker.contains(forbidden) {
            return Err(PolicyError::new(format!(
                "Dockerfile contains forbidden mutable installer command: {forbidden}"
            )));
        }
    }
    Ok(())
}

fn require_source_fragments(path: &str, source: &str, fragments: &[&str]) -> PolicyResult<()> {
    for fragment in fragments {
        if !source.contains(fragment) {
            return Err(PolicyError::new(format!(
                "{path} is missing fail-closed policy fragment: {fragment}"
            )));
        }
    }
    Ok(())
}

fn validate_runtime_fail_closed(root: &SafeRoot) -> PolicyResult<()> {
    let config = root.read_text(TYPESCRIPT_CONFIG, DEFAULT_FILE_LIMIT)?;
    require_source_fragments(
        TYPESCRIPT_CONFIG,
        &config,
        &[
            "if (AUTO_UPDATE)",
            "AUTO_UPDATE is unsupported",
            "package.json and package-lock.json",
        ],
    )?;

    let executor = root.read_text(TYPESCRIPT_EXECUTOR, DEFAULT_FILE_LIMIT)?;
    require_source_fragments(
        TYPESCRIPT_EXECUTOR,
        &executor,
        &[
            "from \"node:vm\"",
            "nodeEnvironment === \"development\"",
            "GTA_CLAW_ALLOW_REDUCED_ISOLATION",
            "=== \"true\"",
            "development-only",
        ],
    )?;
    if executor.contains("nodeEnvironment !== \"production\"") {
        return Err(PolicyError::new(
            "node:vm may be selected only by exact development plus reduced-isolation opt-in",
        ));
    }

    let updater = root.read_text(TYPESCRIPT_UPDATER, DEFAULT_FILE_LIMIT)?;
    for forbidden in [
        "npm update",
        "npm install",
        "curl ",
        "Invoke-WebRequest",
        "child_process",
        "exec(",
        "spawn(",
    ] {
        if updater.contains(forbidden) {
            return Err(PolicyError::new(format!(
                "TypeScript updater contains mutable update behavior: {forbidden}"
            )));
        }
    }
    let index = root.read_text(TYPESCRIPT_INDEX, DEFAULT_FILE_LIMIT)?;
    if !index.contains("checkForUpdates") {
        return Err(PolicyError::new(
            "TypeScript runtime no longer performs the sanctioned read-only version check",
        ));
    }

    for (path, identity) in [
        (RUST_DOMAIN_CONFIG, "AUTO_UPDATE"),
        (RUST_MIGRATION_CONFIG, "MappingId::AutoUpdate"),
    ] {
        let source = root.read_text(path, DEFAULT_FILE_LIMIT)?;
        if !source.contains(identity)
            || !["must remain false", "unsupported", "rejected"]
                .iter()
                .any(|diagnostic| source.contains(diagnostic))
        {
            return Err(PolicyError::new(format!(
                "{path} does not reject AUTO_UPDATE=true"
            )));
        }
    }
    Ok(())
}

fn auto_update_mapping<'a>(
    document: &'a JsonValue,
    path: &str,
) -> PolicyResult<&'a JsonMap<String, JsonValue>> {
    let mappings = document
        .get("mappings")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| PolicyError::new(format!("{path} mappings array is missing")))?;
    let matches = mappings
        .iter()
        .filter_map(JsonValue::as_object)
        .filter(|mapping| {
            mapping.get("legacy_env").and_then(JsonValue::as_str) == Some("AUTO_UPDATE")
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(PolicyError::new(format!(
            "{path} must contain exactly one AUTO_UPDATE mapping"
        )));
    }
    Ok(matches[0])
}

fn validate_env_mapping_equality(root: &SafeRoot) -> PolicyResult<()> {
    let packaged = read_json(root, PACKAGED_ENV_MAPPING)?;
    let compatibility = read_json(root, COMPAT_ENV_MAPPING)?;
    if packaged != compatibility {
        return Err(PolicyError::new(
            "both env-mapping JSON documents must be canonically equal",
        ));
    }
    let mapping = auto_update_mapping(&packaged, PACKAGED_ENV_MAPPING)?;
    if mapping.get("default").and_then(JsonValue::as_bool) != Some(false) {
        return Err(PolicyError::new(
            "AUTO_UPDATE mapping default must remain false",
        ));
    }
    let policy_text = ["validation", "known_legacy_quirk"]
        .into_iter()
        .filter_map(|key| mapping.get(key).and_then(JsonValue::as_str))
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if !(policy_text.contains("reject") || policy_text.contains("fail"))
        || !policy_text.contains("review")
    {
        return Err(PolicyError::new(
            "AUTO_UPDATE env mapping must state fail-closed review-only behavior",
        ));
    }
    Ok(())
}

fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_requirements(requirements: &str) -> PolicyResult<()> {
    let mut packages = BTreeSet::new();
    let mut current: Option<String> = None;
    let mut hashes = 0_usize;
    let finish = |package: &Option<String>, hashes: usize| -> PolicyResult<()> {
        if let Some(package) = package
            && hashes == 0
        {
            return Err(PolicyError::new(format!(
                "requirement entry has no SHA-256 hash: {package}"
            )));
        }
        Ok(())
    };
    for raw in requirements.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(hash) = line
            .trim_end_matches('\\')
            .trim()
            .strip_prefix("--hash=sha256:")
        {
            if current.is_none() || !lower_hex(hash, 32) {
                return Err(PolicyError::new(
                    "requirements.txt contains an invalid SHA-256 hash",
                ));
            }
            hashes = hashes
                .checked_add(1)
                .ok_or_else(|| PolicyError::new("requirements hash count overflow"))?;
            continue;
        }
        finish(&current, hashes)?;
        let requirement = line.trim_end_matches('\\').trim();
        let Some((name, version)) = requirement.split_once("==") else {
            return Err(PolicyError::new(format!(
                "requirement must use exact name==version syntax: {requirement}"
            )));
        };
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
            })
            || !exact_semver(version)
            || !packages.insert(name.to_ascii_lowercase())
        {
            return Err(PolicyError::new(format!(
                "requirement is duplicate, mutable, or malformed: {requirement}"
            )));
        }
        current = Some(requirement.to_owned());
        hashes = 0;
    }
    finish(&current, hashes)?;
    if packages.is_empty() {
        return Err(PolicyError::new("requirements.txt contains no packages"));
    }
    Ok(())
}

fn parse_workflow(path: &str, text: &str) -> PolicyResult<YamlValue> {
    serde_yaml_ng::from_str(text).map_err(|cause| error(&format!("parse {path}"), cause))
}

fn validate_compatibility_workflow(root: &SafeRoot) -> PolicyResult<()> {
    let workflow = root
        .read_text(RUST_WORKFLOW, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    let parsed = parse_workflow(RUST_WORKFLOW, &workflow)?;
    let root_mapping = parsed
        .as_mapping()
        .ok_or_else(|| PolicyError::new("Rust workflow root must be a mapping"))?;
    let triggers = root_mapping
        .get(YamlValue::String("on".to_owned()))
        .and_then(YamlValue::as_mapping)
        .ok_or_else(|| PolicyError::new("compatibility workflow on mapping is missing"))?;
    for event in ["pull_request", "push"] {
        let trigger = triggers
            .get(YamlValue::String(event.to_owned()))
            .ok_or_else(|| {
                PolicyError::new(format!(
                    "compatibility workflow must run on every {event} input"
                ))
            })?;
        if trigger.as_mapping().is_some_and(|mapping| {
            mapping.contains_key(YamlValue::String("paths".to_owned()))
                || mapping.contains_key(YamlValue::String("paths-ignore".to_owned()))
        }) {
            return Err(PolicyError::new(format!(
                "compatibility workflow {event} trigger must not filter compat or Node inputs"
            )));
        }
    }
    if workflow.contains("\n    paths:")
        || workflow.contains("\n    paths-ignore:")
        || workflow.lines().any(|line| {
            line.contains("pip")
                && (line.contains("--upgrade")
                    || line.split_ascii_whitespace().any(|token| token == "-U"))
        })
        || workflow.contains("python -m pip")
    {
        return Err(PolicyError::new(
            "compatibility workflow filters inputs, upgrades pip, or bypasses python3",
        ));
    }
    for required in [
        &format!("uses: {SETUP_PYTHON_ACTION}"),
        "python-version: \"3.13.5\"",
        "python3 -m pip install",
        "--require-hashes",
        "--requirement compat/legacy/scripts/requirements.txt",
        "python3 -m pip check",
        "python3 compat/legacy/scripts/validate.py",
        "git fetch",
    ] {
        if !workflow.contains(required) {
            return Err(PolicyError::new(format!(
                "compatibility workflow is missing: {required}"
            )));
        }
    }

    let contract = read_json(root, COMPAT_CONTRACT)?;
    let revision = contract
        .get("source_revision")
        .and_then(JsonValue::as_str)
        .filter(|revision| lower_hex(revision, 20))
        .ok_or_else(|| {
            PolicyError::new("compatibility contract source_revision must be 40 lowercase hex")
        })?;
    for path in COMPAT_REVISION_DOCUMENTS {
        let document = read_json(root, path)?;
        if document
            .get("source_revision")
            .and_then(JsonValue::as_str)
            != Some(revision)
        {
            return Err(PolicyError::new(format!(
                "{path} source_revision differs from the compatibility contract"
            )));
        }
    }
    let revision_env = format!("SOURCE_REVISION: {revision}");
    let fetches_revision_directly = workflow
        .lines()
        .any(|line| line.contains("git fetch") && line.contains(revision));
    let fetches_revision_from_bound_env = workflow.contains(&revision_env)
        && workflow
            .lines()
            .any(|line| line.contains("git fetch") && line.contains("SOURCE_REVISION"));
    if !fetches_revision_directly && !fetches_revision_from_bound_env {
        return Err(PolicyError::new(
            "compatibility workflow does not fetch the exact declared 40-hex source revision",
        ));
    }
    validate_requirements(&root.read_text(COMPAT_REQUIREMENTS, DEFAULT_FILE_LIMIT)?)
}

fn validate_cargo_deny_0198(path: &str, workflow: &str, config: &str) -> PolicyResult<()> {
    for required in ["0.19.8", config, "--locked", "--all-features"] {
        if !workflow.contains(required) {
            return Err(PolicyError::new(format!(
                "{path} cargo-deny 0.19.8 contract is missing: {required}"
            )));
        }
    }
    let normalized = workflow.split_whitespace().collect::<Vec<_>>().join(" ");
    let expected = format!("--locked --all-features check --config {config}");
    if !normalized.contains(&expected) {
        return Err(PolicyError::new(format!(
            "{path} must invoke cargo-deny 0.19.8 with check --config"
        )));
    }
    Ok(())
}

fn validate_mobile_workflow(root: &SafeRoot, path: &str, workspace: &str) -> PolicyResult<()> {
    let workflow = root
        .read_text(path, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    let _ = parse_workflow(path, &workflow)?;
    for required in [
        "runs-on: ubuntu-24.04",
        "libfontconfig-dev=2.15.0-1.1ubuntu2",
        "pkgconf=1.8.1-2build1",
        &format!(
            "cargo +1.94.0 check --manifest-path {workspace}/Cargo.toml --workspace --all-targets --locked"
        ),
    ] {
        if !workflow.contains(required) {
            return Err(PolicyError::new(format!(
                "{path} Linux host policy is missing: {required}"
            )));
        }
    }
    validate_cargo_deny_0198(path, &workflow, &format!("{workspace}/deny.toml"))?;
    let targets: &[&str] = match workspace {
        "android" => &["aarch64-linux-android", "x86_64-linux-android"],
        "ios" => &["aarch64-apple-ios", "aarch64-apple-ios-sim"],
        _ => return Err(PolicyError::new("unsupported mobile workspace")),
    };
    for target in targets {
        if !workflow.contains(target) {
            return Err(PolicyError::new(format!(
                "{path} lost shipped-target coverage for {target}"
            )));
        }
    }
    Ok(())
}

fn validate_rust_and_desktop_policy(root: &SafeRoot) -> PolicyResult<()> {
    let workflow = root
        .read_text(RUST_WORKFLOW, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    for required in [
        "1.94.0",
        "aarch64-pc-windows-msvc",
        "cargo +1.94.0 check",
        "--target aarch64-pc-windows-msvc",
    ] {
        if !workflow.contains(required) {
            return Err(PolicyError::new(format!(
                "{RUST_WORKFLOW} lost Rust 1.94 Windows ARM64 coverage: {required}"
            )));
        }
    }
    validate_cargo_deny_0198(RUST_WORKFLOW, &workflow, "desktop/deny.toml")?;

    let build = root
        .read_text(DESKTOP_BUILD_SCRIPT, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    require_source_fragments(
        DESKTOP_BUILD_SCRIPT,
        &build,
        &[
            "CARGO_CFG_TARGET_OS",
            "\"windows\" => \"fluent\"",
            "\"macos\" => \"cupertino\"",
            "requires a Windows or macOS build host",
        ],
    )?;
    for forbidden in ["std::env::var(\"HOST\")", "host != target"] {
        if build.contains(forbidden) {
            return Err(PolicyError::new(format!(
                "desktop build.rs retains forbidden HOST==TARGET blanket: {forbidden}"
            )));
        }
    }
    Ok(())
}

fn validate_docker_publish_workflow(root: &SafeRoot) -> PolicyResult<()> {
    let workflow = root
        .read_text(DOCKER_WORKFLOW, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    let _ = parse_workflow(DOCKER_WORKFLOW, &workflow)?;
    for action in DOCKER_ACTION_PINS {
        if workflow.matches(action).count() != 1 {
            return Err(PolicyError::new(format!(
                "Docker workflow action pin changed: {action}"
            )));
        }
    }
    if workflow.contains("docker/build-push-action@")
        || workflow.matches("docker buildx build").count() != 1
        || !workflow.contains("--load")
    {
        return Err(PolicyError::new(
            "Docker publish workflow must build exactly once and load that image",
        ));
    }
    for required in [
        "on:\n  pull_request:",
        "if: github.event_name != 'pull_request'",
        "- name: Validate exact built image",
        "EXPECTED_IMAGE_ID: ${{ steps.build.outputs.image-id }}",
        "/app/node_modules/.bin/copilot",
        "- name: Push the validated image digest",
        "docker tag \"$IMAGE_TAG\" \"$tag\"",
        "test \"$(docker image inspect --format '{{.Id}}' \"$tag\")\" = \"$EXPECTED_IMAGE_ID\"",
        "digest: sha256:",
        "test \"$digest\" = \"$pushed_digest\"",
    ] {
        if !workflow.contains(required) {
            return Err(PolicyError::new(format!(
                "Docker action/digest/build-once policy is missing: {required}"
            )));
        }
    }
    Ok(())
}

fn validate_product_policy_source(root: &SafeRoot) -> PolicyResult<()> {
    let source = root.read_text(PRODUCT_POLICY_TEST, DEFAULT_FILE_LIMIT)?;
    if !source.contains("const LEGACY_TYPESCRIPT_CEILING: usize = 18;") {
        return Err(PolicyError::new(
            "product repository policy raised or removed LEGACY_TYPESCRIPT_CEILING",
        ));
    }
    for path in crate::repository_policy::SANCTIONED_LEGACY_TESTS {
        if !source.contains(&format!("\"{path}\"")) {
            return Err(PolicyError::new(format!(
                "product repository policy does not admit sanctioned PR #227 test: {path}"
            )));
        }
    }
    root.regular_file("test/toolExecutorIsolation.test.mjs", DEFAULT_FILE_LIMIT)?;
    Ok(())
}

/// Enforces the complete sanctioned post-rotation product policy against actual repository files.
pub fn validate_hardened_product_policy(root: &SafeRoot) -> PolicyResult<()> {
    validate_node_and_docker(root)?;
    validate_runtime_fail_closed(root)?;
    validate_env_mapping_equality(root)?;
    validate_compatibility_workflow(root)?;
    validate_mobile_workflow(root, ANDROID_WORKFLOW, "android")?;
    validate_mobile_workflow(root, IOS_WORKFLOW, "ios")?;
    validate_rust_and_desktop_policy(root)?;
    validate_docker_publish_workflow(root)?;
    validate_product_policy_source(root)
}

fn transition_input_changed(
    trusted: &SafeRoot,
    candidate: &SafeRoot,
    path: &str,
) -> PolicyResult<bool> {
    let trusted_exists = trusted.exists(path)?;
    let candidate_exists = candidate.exists(path)?;
    if trusted_exists != candidate_exists {
        return Ok(true);
    }
    if !trusted_exists {
        return Ok(false);
    }
    Ok(trusted.read_bytes(path, DEFAULT_FILE_LIMIT)?
        != candidate.read_bytes(path, DEFAULT_FILE_LIMIT)?)
}

/// Allows an unchanged legacy base, but requires the first transition-input edit to move
/// atomically to the complete hardened state. Once the protected base is hardened, it stays so.
pub fn validate_product_policy_transition(
    trusted: &SafeRoot,
    candidate: &SafeRoot,
) -> PolicyResult<()> {
    let trusted_result = validate_hardened_product_policy(trusted);
    let candidate_result = validate_hardened_product_policy(candidate);
    if trusted_result.is_ok() {
        return candidate_result;
    }
    if candidate_result.is_ok() {
        return Ok(());
    }

    let mut changed = Vec::new();
    for path in HARDENING_TRANSITION_PATHS {
        if transition_input_changed(trusted, candidate, path)? {
            changed.push(path);
        }
    }
    if changed.is_empty() {
        return Ok(());
    }
    let diagnostic = candidate_result
        .expect_err("candidate result was checked as an error")
        .to_string();
    Err(PolicyError::new(format!(
        "supply-chain hardening transition must update all declared inputs atomically; changed {changed:?}; first unsatisfied rule: {diagnostic}"
    )))
}

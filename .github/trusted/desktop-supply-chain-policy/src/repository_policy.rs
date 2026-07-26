//! Base-owned shrink-only policy for the legacy Node runtime.

use std::collections::{BTreeMap, BTreeSet};

use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};
use toml::Value as TomlValue;

use crate::input::{DEFAULT_FILE_LIMIT, SafeRoot};
use crate::{PolicyError, PolicyResult, error};

const MAX_REPOSITORY_FILES: usize = 50_000;
const MAX_REPOSITORY_BYTES: u64 = 512 * 1024 * 1024;
const POLICY_CRATE: &str = "crates/claw-repo-policy";
const POLICY_MANIFEST: &str = "crates/claw-repo-policy/Cargo.toml";
const POLICY_LIBRARY: &str = "crates/claw-repo-policy/src/lib.rs";
const POLICY_TEST: &str = "crates/claw-repo-policy/tests/repository_policy.rs";
const POLICY_TEST_SOURCE: &str =
    include_str!("../../../../crates/claw-repo-policy/tests/repository_policy.rs");
const UPSTREAM_WORKFLOW: &str = ".github/workflows/upstream-gateway-reference.yml";
const RUST_WORKFLOW: &str = ".github/workflows/rust.yml";
const POLICY_TEST_STEP_NAME: &str = "Reject JavaScript toolchain artifacts";
const ALLOWED_SHELL_FIXTURE: &str = ".github/fixtures/security-tools/bash-env-poison.sh";

/// Exact historical ceiling: 18 TypeScript files and four load-bearing roots.
pub const LEGACY_RUNTIME_CEILING: [&str; 22] = [
    "Dockerfile",
    "package-lock.json",
    "package.json",
    "src/auth/deviceFlow.ts",
    "src/bot/teamsBot.ts",
    "src/channels/discordGateway.ts",
    "src/channels/messageProcessor.ts",
    "src/channels/telegramPolling.ts",
    "src/channels/whatsappWebhook.ts",
    "src/config.ts",
    "src/engine/copilotEngine.ts",
    "src/engine/sessionManager.ts",
    "src/engine/toolExecutor.ts",
    "src/index.ts",
    "src/loader/roleLoader.ts",
    "src/loader/skillLoader.ts",
    "src/server.ts",
    "src/updater/sdkUpdater.ts",
    "src/utils/logger.ts",
    "src/utils/proxy.ts",
    "src/utils/splitMessage.ts",
    "tsconfig.json",
];

const FORBIDDEN_FILE_NAMES: [&str; 9] = [
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "deno.json",
    "deno.jsonc",
];
const FORBIDDEN_DIRECTORY_NAMES: [&str; 3] = ["node_modules", ".yarn", ".pnpm-store"];
const FORBIDDEN_EXTENSIONS: [&str; 9] =
    ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "node"];
const FORBIDDEN_WORKFLOW_COMMANDS: [&str; 8] = [
    "node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "corepack",
];
const ALLOWED_INERT_WORKFLOW_LINES: [(&str, &str); 3] = [
    (
        ".github/workflows/macos-packaging.yml",
        "if grep -RInE '(^|[[:space:]])(npm|npx|node|bun|pnpm)([[:space:]]|$)' \\",
    ),
    (
        ".github/workflows/macos-packaging.yml",
        "-iname 'node' -o -iname 'npm' -o -iname 'bun' -o -iname 'pnpm' -o \\",
    ),
    (
        ".github/workflows/macos-packaging.yml",
        "-iname '*.js' -o -iname '*.mjs' -o -iname '*.cjs' -o -iname '*.node' \\",
    ),
];

fn repository_files(root: &SafeRoot) -> PolicyResult<Vec<String>> {
    Ok(root
        .list_all(MAX_REPOSITORY_FILES, MAX_REPOSITORY_BYTES)?
        .into_iter()
        .map(|file| file.relative)
        .collect())
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn extension(path: &str) -> Option<&str> {
    file_name(path)
        .rsplit_once('.')
        .map(|(_, extension)| extension)
}

fn is_forbidden_artifact(path: &str) -> bool {
    path.split('/').any(|component| {
        FORBIDDEN_DIRECTORY_NAMES
            .iter()
            .any(|forbidden| component.eq_ignore_ascii_case(forbidden))
    }) || FORBIDDEN_FILE_NAMES
        .iter()
        .any(|forbidden| file_name(path).eq_ignore_ascii_case(forbidden))
        || extension(path).is_some_and(|extension| {
            FORBIDDEN_EXTENSIONS
                .iter()
                .any(|forbidden| extension.eq_ignore_ascii_case(forbidden))
        })
}

fn legacy_artifacts(files: &[String]) -> BTreeSet<String> {
    files
        .iter()
        .filter(|path| {
            LEGACY_RUNTIME_CEILING.contains(&path.as_str()) || is_forbidden_artifact(path)
        })
        .cloned()
        .collect()
}

fn require_artifacts_within_ceiling(artifacts: &BTreeSet<String>, label: &str) -> PolicyResult<()> {
    let ceiling = LEGACY_RUNTIME_CEILING
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let outside = artifacts.difference(&ceiling).cloned().collect::<Vec<_>>();
    if outside.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "{label} contains legacy Node artifacts outside the exact ceiling: {outside:?}"
        )))
    }
}

fn require_candidate_subset(
    trusted: &BTreeSet<String>,
    candidate: &BTreeSet<String>,
) -> PolicyResult<()> {
    let additions = candidate.difference(trusted).cloned().collect::<Vec<_>>();
    if additions.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "candidate reintroduced or added legacy Node artifacts absent from the protected base: {additions:?}"
        )))
    }
}

fn decode_policy_escapes(input: &str) -> String {
    let mut decoded = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let Some(marker) = characters.next() else {
            decoded.push('\\');
            break;
        };
        let digits = match marker {
            'x' => 2,
            'u' => 4,
            'U' => 8,
            _ => {
                decoded.push('\\');
                decoded.push(marker);
                continue;
            }
        };
        let mut hexadecimal = String::with_capacity(digits);
        while hexadecimal.len() < digits {
            let Some(next) = characters.peek().copied() else {
                break;
            };
            if !next.is_ascii_hexdigit() {
                break;
            }
            hexadecimal.push(next);
            characters.next();
        }
        let value = (hexadecimal.len() == digits)
            .then(|| u32::from_str_radix(&hexadecimal, 16).ok())
            .flatten()
            .and_then(char::from_u32);
        if let Some(value) = value {
            decoded.push(value);
        } else {
            decoded.push('\\');
            decoded.push(marker);
            decoded.push_str(&hexadecimal);
        }
    }
    decoded
}

fn normalized_command_token(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    let command = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    for suffix in [".exe", ".cmd", ".bat", ".ps1"] {
        if let Some(command) = command.strip_suffix(suffix) {
            return command.to_owned();
        }
    }
    command.to_owned()
}

fn is_forbidden_workflow_token(token: &str) -> bool {
    FORBIDDEN_WORKFLOW_COMMANDS.contains(&token)
        || token.strip_prefix("node").is_some_and(|version| {
            !version.is_empty() && version.chars().all(|value| value.is_ascii_digit())
        })
}

fn record_violation(violations: &mut BTreeMap<String, usize>, key: String) -> PolicyResult<()> {
    let count = violations.entry(key).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| PolicyError::new("workflow violation count overflow"))?;
    Ok(())
}

fn scan_policy_document(
    path: &str,
    document: &str,
    violations: &mut BTreeMap<String, usize>,
) -> PolicyResult<()> {
    for line in document.lines() {
        let trimmed = line.trim();
        if ALLOWED_INERT_WORKFLOW_LINES
            .iter()
            .any(|(allowed_path, allowed_line)| path == *allowed_path && trimmed == *allowed_line)
        {
            continue;
        }
        let decoded = decode_policy_escapes(line);
        let compact = decoded
            .chars()
            .filter(|character| !matches!(character, '\'' | '"' | '`' | '\\'))
            .collect::<String>();
        if [decoded.as_str(), compact.as_str()]
            .iter()
            .any(|candidate| {
                candidate
                    .to_ascii_lowercase()
                    .contains("actions/setup-node")
            })
        {
            record_violation(violations, format!("{path}|actions/setup-node|{trimmed}"))?;
        }
        let mut commands = BTreeSet::new();
        for candidate in [decoded.as_str(), compact.as_str()] {
            for token in candidate.split(|character: char| {
                !(character.is_ascii_alphanumeric()
                    || matches!(character, '_' | '-' | '.' | '/' | '\\'))
            }) {
                let command = normalized_command_token(token);
                if is_forbidden_workflow_token(&command) {
                    commands.insert(command);
                }
            }
        }
        for command in commands {
            record_violation(
                violations,
                format!("{path}|forbidden workflow token {command}|{trimmed}"),
            )?;
        }
    }
    Ok(())
}

fn workflow_violations(root: &SafeRoot, files: &[String]) -> PolicyResult<BTreeMap<String, usize>> {
    let mut violations = BTreeMap::new();
    for path in files {
        let name = file_name(path);
        let workflow = path.starts_with(".github/workflows/")
            && extension(path).is_some_and(|extension| {
                extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
            });
        let local_action =
            name.eq_ignore_ascii_case("action.yml") || name.eq_ignore_ascii_case("action.yaml");
        if workflow || local_action {
            let document = root.read_text(path, DEFAULT_FILE_LIMIT)?;
            scan_policy_document(path, &document, &mut violations)?;
        }
    }
    Ok(violations)
}

fn require_violation_subset(
    trusted: &BTreeMap<String, usize>,
    candidate: &BTreeMap<String, usize>,
) -> PolicyResult<()> {
    let additions = candidate
        .iter()
        .filter(|(violation, count)| trusted.get(*violation).copied().unwrap_or(0) < **count)
        .map(|(violation, count)| format!("{violation} (candidate count {count})"))
        .collect::<Vec<_>>();
    if additions.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "candidate introduced new Node workflow/action violations: {additions:?}"
        )))
    }
}

fn toml_keys(table: &toml::map::Map<String, TomlValue>) -> BTreeSet<&str> {
    table.keys().map(String::as_str).collect()
}

fn expected_toml_keys<'a>(keys: &'a [&'a str]) -> BTreeSet<&'a str> {
    keys.iter().copied().collect()
}

fn require_workspace_inheritance(
    package: &toml::map::Map<String, TomlValue>,
    key: &str,
) -> PolicyResult<()> {
    let value = package.get(key).and_then(TomlValue::as_table);
    if value.is_none_or(|value| {
        value.len() != 1 || value.get("workspace").and_then(TomlValue::as_bool) != Some(true)
    }) {
        return Err(PolicyError::new(format!(
            "{POLICY_MANIFEST} package.{key} must inherit exactly from workspace"
        )));
    }
    Ok(())
}

fn validate_policy_manifest(root: &SafeRoot) -> PolicyResult<()> {
    let root_manifest: TomlValue =
        toml::from_str(&root.read_text("Cargo.toml", DEFAULT_FILE_LIMIT)?)
            .map_err(|cause| error("parse root Cargo.toml for repository policy", cause))?;
    let members = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(TomlValue::as_array)
        .ok_or_else(|| PolicyError::new("root workspace members are missing"))?;
    if !members
        .iter()
        .any(|member| member.as_str() == Some(POLICY_CRATE))
    {
        return Err(PolicyError::new(
            "claw-repo-policy must remain a declared root workspace member",
        ));
    }

    let manifest: TomlValue = toml::from_str(&root.read_text(POLICY_MANIFEST, DEFAULT_FILE_LIMIT)?)
        .map_err(|cause| error("parse claw-repo-policy manifest", cause))?;
    let root_table = manifest
        .as_table()
        .ok_or_else(|| PolicyError::new("claw-repo-policy manifest must be a table"))?;
    if toml_keys(root_table) != expected_toml_keys(&["lints", "package"]) {
        return Err(PolicyError::new(
            "claw-repo-policy manifest top-level schema changed",
        ));
    }
    let package = manifest
        .get("package")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("claw-repo-policy package table is missing"))?;
    if toml_keys(package)
        != expected_toml_keys(&[
            "description",
            "edition",
            "license",
            "name",
            "repository",
            "rust-version",
            "version",
        ])
        || package.get("name").and_then(TomlValue::as_str) != Some("claw-repo-policy")
        || package.get("description").and_then(TomlValue::as_str)
            != Some("Repository-wide architecture policy gates for GTA Claw")
    {
        return Err(PolicyError::new(
            "claw-repo-policy package identity or schema changed",
        ));
    }
    for key in [
        "version",
        "edition",
        "rust-version",
        "license",
        "repository",
    ] {
        require_workspace_inheritance(package, key)?;
    }
    let lints = manifest
        .get("lints")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("claw-repo-policy lints table is missing"))?;
    if lints.len() != 1 || lints.get("workspace").and_then(TomlValue::as_bool) != Some(true) {
        return Err(PolicyError::new(
            "claw-repo-policy lints must inherit exactly from workspace",
        ));
    }
    Ok(())
}

fn rust_string_array(source: &str, name: &str) -> PolicyResult<Vec<String>> {
    let marker = format!("const {name}:");
    let declaration = source
        .find(&marker)
        .ok_or_else(|| PolicyError::new(format!("repository policy is missing {name}")))?;
    let array = source[declaration..]
        .find("&[")
        .map(|offset| declaration + offset + 2)
        .ok_or_else(|| PolicyError::new(format!("repository policy {name} is not an array")))?;
    let end = source[array..]
        .find("];")
        .map(|offset| array + offset)
        .ok_or_else(|| PolicyError::new(format!("repository policy {name} is unterminated")))?;
    let body = &source[array..end];
    let bytes = body.as_bytes();
    let mut values = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let start = index + 1;
        index = start;
        while index < bytes.len() && bytes[index] != b'"' {
            if bytes[index] == b'\\' {
                return Err(PolicyError::new(format!(
                    "repository policy {name} contains an escaped inventory value"
                )));
            }
            index += 1;
        }
        if index == bytes.len() {
            return Err(PolicyError::new(format!(
                "repository policy {name} contains an unterminated string"
            )));
        }
        values.push(body[start..index].to_owned());
        index += 1;
    }
    Ok(values)
}

fn validate_policy_source(root: &SafeRoot) -> PolicyResult<()> {
    let library = root
        .read_text(POLICY_LIBRARY, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    if library != "//! Repository-wide architecture policy gates for GTA Claw.\n" {
        return Err(PolicyError::new(
            "claw-repo-policy library identity changed",
        ));
    }
    let source = root
        .read_text(POLICY_TEST, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    for (name, expected) in [
        ("FORBIDDEN_FILE_NAMES", FORBIDDEN_FILE_NAMES.as_slice()),
        (
            "FORBIDDEN_DIRECTORY_NAMES",
            FORBIDDEN_DIRECTORY_NAMES.as_slice(),
        ),
        ("FORBIDDEN_EXTENSIONS", FORBIDDEN_EXTENSIONS.as_slice()),
        (
            "FORBIDDEN_WORKFLOW_COMMANDS",
            FORBIDDEN_WORKFLOW_COMMANDS.as_slice(),
        ),
        (
            "LEGACY_RUNTIME_INVENTORY",
            LEGACY_RUNTIME_CEILING.as_slice(),
        ),
        ("ALLOWED_COMPAT_FIXTURES", &[]),
        (
            "ALLOWED_ADVERSARIAL_SHELL_FIXTURES",
            &[ALLOWED_SHELL_FIXTURE],
        ),
    ] {
        let values = rust_string_array(&source, name)?;
        if values.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(PolicyError::new(format!(
                "repository policy {name} changed from the base-owned contract"
            )));
        }
    }
    for required in [
        "#[test]\nfn repository_legacy_javascript_surface_does_not_grow()",
        "#[test]\nfn new_typescript_path_outside_legacy_inventory_is_rejected()",
        "fixture.write(\"src/newFeature.ts\", b\"new\");",
        "assert_eq!(violations, [\"src/newFeature.ts\"]);",
        "#[test]\nfn removing_allowlisted_legacy_entry_keeps_ratchet_green()",
        "fs::remove_file(fixture.path().join(\"src/index.ts\"))",
        "#[test]\nfn workflow_commands_are_checked_without_rejecting_inert_search_patterns()",
        "#[test]\nfn tracked_symlink_and_gitlink_modes_are_rejected()",
        "120000 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "160000 cccccccccccccccccccccccccccccccccccccccc",
    ] {
        if !source.contains(required) {
            return Err(PolicyError::new(format!(
                "repository policy self-test contract is missing: {required:?}"
            )));
        }
    }
    let expected_source = POLICY_TEST_SOURCE.replace("\r\n", "\n");
    if source != expected_source {
        return Err(PolicyError::new(
            "repository policy test source changed from the base-owned exact contract",
        ));
    }
    Ok(())
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

fn yaml_get<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    yaml_mapping(value)?.get(yaml_key(key))
}

fn yaml_string(value: Option<&YamlValue>) -> Option<&str> {
    if let Some(YamlValue::String(value)) = value {
        Some(value)
    } else {
        None
    }
}

fn normalized_command(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_policy_execution_workflows(root: &SafeRoot) -> PolicyResult<()> {
    let workflow_text = root.read_text(UPSTREAM_WORKFLOW, DEFAULT_FILE_LIMIT)?;
    let workflow: YamlValue = serde_yaml_ng::from_str(&workflow_text)
        .map_err(|cause| error("parse upstream repository-policy workflow", cause))?;
    if yaml_get(&workflow, "env").is_some() || yaml_get(&workflow, "defaults").is_some() {
        return Err(PolicyError::new(
            "upstream repository-policy workflow must not override global execution state",
        ));
    }
    let triggers = yaml_get(&workflow, "on")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("upstream repository-policy workflow has no on mapping"))?;
    let pull_request = triggers.get(yaml_key("pull_request")).ok_or_else(|| {
        PolicyError::new("upstream repository-policy workflow must run on every pull request")
    })?;
    if !matches!(pull_request, YamlValue::Null)
        && yaml_mapping(pull_request).is_none_or(|mapping| !mapping.is_empty())
    {
        return Err(PolicyError::new(
            "upstream repository-policy pull_request trigger must not use filters",
        ));
    }
    let permissions = yaml_get(&workflow, "permissions")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("upstream repository-policy permissions are missing"))?;
    if permissions.len() != 1 || yaml_string(permissions.get(yaml_key("contents"))) != Some("read")
    {
        return Err(PolicyError::new(
            "upstream repository-policy permissions must be exactly contents: read",
        ));
    }
    let jobs = yaml_get(&workflow, "jobs")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("upstream repository-policy jobs are missing"))?;
    let mut policy_jobs = 0_usize;
    for job in jobs.values() {
        let Some(steps) = yaml_get(job, "steps").and_then(YamlValue::as_sequence) else {
            continue;
        };
        let policy_positions = steps
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                yaml_string(yaml_get(step, "run")).is_some_and(|run| {
                normalized_command(run)
                    == "cargo test --locked --package claw-repo-policy --test repository_policy"
                })
                .then_some(index)
            })
            .collect::<Vec<_>>();
        if policy_positions.is_empty() {
            continue;
        }
        let job = yaml_mapping(job)
            .ok_or_else(|| PolicyError::new("repository-policy job is not a mapping"))?;
        let job_keys = job
            .keys()
            .filter_map(YamlValue::as_str)
            .collect::<BTreeSet<_>>();
        let timeout = job
            .get(yaml_key("timeout-minutes"))
            .and_then(YamlValue::as_u64);
        if policy_positions != [1]
            || job.len() != 4
            || job_keys != BTreeSet::from(["name", "runs-on", "steps", "timeout-minutes"])
            || yaml_string(job.get(yaml_key("runs-on"))) != Some("windows-latest")
            || timeout.is_none_or(|timeout| !(1..=45).contains(&timeout))
            || steps.len() < 2
        {
            return Err(PolicyError::new(
                "repository-policy test job shape or execution order changed",
            ));
        }
        let checkout = yaml_mapping(&steps[0])
            .ok_or_else(|| PolicyError::new("repository-policy checkout is not a mapping"))?;
        let checkout_with = checkout
            .get(yaml_key("with"))
            .and_then(yaml_mapping)
            .ok_or_else(|| PolicyError::new("repository-policy checkout inputs are missing"))?;
        if checkout.len() != 3
            || checkout
                .keys()
                .filter_map(YamlValue::as_str)
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(["name", "uses", "with"])
            || yaml_string(checkout.get(yaml_key("name"))) != Some("Checkout GTA Claw")
            || yaml_string(checkout.get(yaml_key("uses")))
                != Some("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
            || checkout_with.len() != 1
            || checkout_with
                .get(yaml_key("persist-credentials"))
                .and_then(YamlValue::as_bool)
                != Some(false)
        {
            return Err(PolicyError::new(
                "repository-policy test must start from the exact isolated checkout",
            ));
        }
        let policy_step = yaml_mapping(&steps[1])
            .ok_or_else(|| PolicyError::new("repository-policy test step is not a mapping"))?;
        if policy_step.len() != 2
            || policy_step
                .keys()
                .filter_map(YamlValue::as_str)
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(["name", "run"])
            || yaml_string(policy_step.get(yaml_key("name"))) != Some(POLICY_TEST_STEP_NAME)
        {
            return Err(PolicyError::new(
                "repository-policy test step or blocking semantics changed",
            ));
        }
        policy_jobs = policy_jobs
            .checked_add(1)
            .ok_or_else(|| PolicyError::new("repository-policy job count overflow"))?;
    }
    if policy_jobs != 1 {
        return Err(PolicyError::new(
            "always-on repository-policy workflow must contain exactly one policy job",
        ));
    }

    let rust = root.read_text(RUST_WORKFLOW, DEFAULT_FILE_LIMIT)?;
    if !rust
        .lines()
        .any(|line| line.trim() == "run: cargo test --workspace --all-targets --locked")
    {
        return Err(PolicyError::new(
            "Headless workspace tests no longer execute claw-repo-policy",
        ));
    }
    Ok(())
}

fn validate_policy_crate(root: &SafeRoot, files: &[String]) -> PolicyResult<()> {
    let actual = files
        .iter()
        .filter(|path| path.starts_with(&format!("{POLICY_CRATE}/")))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = [POLICY_MANIFEST, POLICY_LIBRARY, POLICY_TEST]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(PolicyError::new(format!(
            "claw-repo-policy file inventory changed: expected {expected:?}, found {actual:?}"
        )));
    }
    validate_policy_manifest(root)?;
    validate_policy_source(root)?;
    validate_policy_execution_workflows(root)?;
    if !root.exists(ALLOWED_SHELL_FIXTURE)? {
        return Err(PolicyError::new(
            "the exact inert adversarial shell fixture is missing",
        ));
    }
    Ok(())
}

fn policy_crate_is_present(files: &[String]) -> bool {
    files
        .iter()
        .any(|path| path.starts_with(&format!("{POLICY_CRATE}/")))
}

/// Enforces monotonic legacy-artifact and workflow reduction across one Final base-to-head pair.
pub fn validate_repository_policy_transition(
    trusted: &SafeRoot,
    candidate: &SafeRoot,
) -> PolicyResult<()> {
    let trusted_files = repository_files(trusted)?;
    let candidate_files = repository_files(candidate)?;
    let trusted_artifacts = legacy_artifacts(&trusted_files);
    let candidate_artifacts = legacy_artifacts(&candidate_files);
    require_artifacts_within_ceiling(&trusted_artifacts, "protected base")?;
    require_artifacts_within_ceiling(&candidate_artifacts, "candidate")?;
    require_candidate_subset(&trusted_artifacts, &candidate_artifacts)?;

    let trusted_workflow_violations = workflow_violations(trusted, &trusted_files)?;
    let candidate_workflow_violations = workflow_violations(candidate, &candidate_files)?;
    let trusted_active = policy_crate_is_present(&trusted_files);
    let candidate_active = policy_crate_is_present(&candidate_files);
    if trusted_active && !candidate_active {
        return Err(PolicyError::new(
            "candidate removed the base-owned claw-repo-policy crate",
        ));
    }
    if trusted_active {
        validate_policy_crate(trusted, &trusted_files)?;
    }
    if candidate_active {
        validate_policy_crate(candidate, &candidate_files)?;
        if !candidate_workflow_violations.is_empty() {
            return Err(PolicyError::new(format!(
                "active claw-repo-policy requires zero Node workflow/action violations: {:?}",
                candidate_workflow_violations.keys().collect::<Vec<_>>()
            )));
        }
    } else {
        require_violation_subset(&trusted_workflow_violations, &candidate_workflow_violations)?;
    }
    Ok(())
}

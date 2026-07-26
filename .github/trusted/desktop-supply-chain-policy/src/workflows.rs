//! Workflow inventory, identity, and exact P04f policy.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};

use crate::identity::spoof_identity;
use crate::input::sha256;
use crate::input::{SafeRoot, compare_trees};
use crate::ownership::CODEOWNERS_PATH;
use crate::policy::pinned_build_artifacts;
use crate::process::{CommandSpec, canonical_tool, run_checked};
use crate::{PolicyError, PolicyResult, error};

/// Base-owned authoritative workflow path.
pub const AUTHORITATIVE_PATH: &str = ".github/workflows/trusted-desktop-supply-chain-policy.yml";
/// Candidate-only bootstrap workflow path.
pub const BOOTSTRAP_PATH: &str = ".github/workflows/bootstrap-desktop-supply-chain-policy.yml";
/// Reserved authoritative workflow name.
pub const AUTHORITATIVE_WORKFLOW_NAME: &str = "GTA Claw authoritative desktop supply-chain policy";
/// Reserved authoritative job/check name.
pub const AUTHORITATIVE_JOB_NAME: &str = "[AUTHORITATIVE] Trusted desktop supply-chain policy";
/// Reserved authoritative job ID.
pub const AUTHORITATIVE_JOB_ID: &str = "trusted-desktop-supply-chain-policy";
/// Reserved non-authoritative workflow name.
pub const BOOTSTRAP_WORKFLOW_NAME: &str = "GTA Claw non-authoritative desktop policy bootstrap";
/// Reserved non-authoritative job/check name.
pub const BOOTSTRAP_JOB_NAME: &str = "[NON-AUTHORITATIVE] Candidate desktop policy validator CI";
/// Reserved non-authoritative job ID.
pub const BOOTSTRAP_JOB_ID: &str = "candidate-validator-bootstrap";

const WORKFLOW_DIRECTORY: &str = ".github/workflows";
const RUST_WORKFLOW: &str = ".github/workflows/rust.yml";
const MACOS_WORKFLOW: &str = ".github/workflows/macos-packaging.yml";
const CANONICAL_RUST: &[u8] = include_bytes!("../policy/final/.github/workflows/rust.yml");
const CANONICAL_MACOS: &[u8] =
    include_bytes!("../policy/final/.github/workflows/macos-packaging.yml");
const MAX_WORKFLOW_BYTES: u64 = 512 * 1024;
const MAX_WORKFLOW_TREE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ACTIONLINT_BYTES: u64 = 64 * 1024 * 1024;
const AUTHORITATIVE_CONCURRENCY_GROUP: &str =
    "trusted-desktop-policy-${{ github.event.pull_request.number }}";
/// Trusted actionlint 1.7.7 Linux binary SHA-256.
pub const ACTIONLINT_SHA256: &str =
    "9f7dedb4e23f89f2922073d1a6720405b7b520d4f5832ebb96f0d55a2958886c";

/// Absolute checksum-pinned actionlint tool.
#[derive(Debug, Clone)]
pub struct ActionlintTool {
    /// Absolute actionlint executable.
    pub path: PathBuf,
    /// Expected lowercase SHA-256.
    pub sha256: String,
}

/// Constructs the production Linux actionlint pin.
#[must_use]
pub fn linux_actionlint(path: PathBuf) -> ActionlintTool {
    ActionlintTool {
        path,
        sha256: ACTIONLINT_SHA256.to_owned(),
    }
}

/// Workflow files that must be present in every validated checkout.
const REQUIRED_WORKFLOWS: [&str; 8] = [
    ".github/workflows/bootstrap-desktop-supply-chain-policy.yml",
    ".github/workflows/docker-publish.yml",
    ".github/workflows/linux-packaging.yml",
    ".github/workflows/macos-packaging.yml",
    ".github/workflows/rust.yml",
    ".github/workflows/trusted-desktop-supply-chain-policy.yml",
    ".github/workflows/upstream-gateway-reference.yml",
    ".github/workflows/windows-packaging.yml",
];

/// Admitted-but-optional Android mobile packaging workflow path.
const ANDROID_PACKAGING_PATH: &str = ".github/workflows/android-packaging.yml";
/// Admitted-but-optional iOS mobile packaging workflow path.
const IOS_PACKAGING_PATH: &str = ".github/workflows/ios-packaging.yml";

/// Additional exact workflow paths admitted for the newly shipped mobile
/// platforms. Each may be absent or present; nothing else may be present, and
/// a present file is validated exactly like a required one.
const ADMITTED_WORKFLOWS: [&str; 2] = [ANDROID_PACKAGING_PATH, IOS_PACKAGING_PATH];

/// Parsed workflow identity used to prevent required-check spoofing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WorkflowIdentity {
    /// Repository-relative workflow path.
    pub path: String,
    /// Top-level workflow display name.
    pub workflow_name: String,
    /// Job IDs and effective display names.
    pub jobs: Vec<(String, String)>,
}

fn yaml_key(key: &str) -> YamlValue {
    YamlValue::String(key.to_owned())
}

fn mapping(value: &YamlValue) -> Option<&YamlMapping> {
    if let YamlValue::Mapping(mapping) = value {
        Some(mapping)
    } else {
        None
    }
}

fn get<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    mapping(value)?.get(yaml_key(key))
}

fn string(value: Option<&YamlValue>) -> Option<&str> {
    if let Some(YamlValue::String(value)) = value {
        Some(value)
    } else {
        None
    }
}

fn require_ascii_identity(value: &str, label: &str) -> PolicyResult<String> {
    if value.is_empty()
        || value.len() > 160
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        return Err(PolicyError::new(format!(
            "{label} must be bounded printable ASCII"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn reserved_spoof_identities() -> BTreeSet<String> {
    [
        AUTHORITATIVE_WORKFLOW_NAME,
        AUTHORITATIVE_JOB_NAME,
        AUTHORITATIVE_JOB_ID,
        BOOTSTRAP_WORKFLOW_NAME,
        BOOTSTRAP_JOB_NAME,
        BOOTSTRAP_JOB_ID,
    ]
    .into_iter()
    .map(spoof_identity)
    .collect()
}

fn template_chunks(value: &str, label: &str) -> PolicyResult<Option<Vec<String>>> {
    if !value.contains("${{") {
        if value.contains("}}") {
            return Err(PolicyError::new(format!(
                "{label} contains an unmatched expression terminator"
            )));
        }
        return Ok(None);
    }
    let mut chunks = Vec::new();
    let mut remaining = value;
    loop {
        let Some(start) = remaining.find("${{") else {
            if remaining.contains("}}") {
                return Err(PolicyError::new(format!(
                    "{label} contains an unmatched expression terminator"
                )));
            }
            chunks.push(spoof_identity(remaining));
            break;
        };
        let static_chunk = &remaining[..start];
        if static_chunk.contains("}}") {
            return Err(PolicyError::new(format!(
                "{label} contains malformed expression delimiters"
            )));
        }
        chunks.push(spoof_identity(static_chunk));
        let expression = &remaining[start + 3..];
        let end = expression.find("}}").ok_or_else(|| {
            PolicyError::new(format!("{label} contains an unterminated expression"))
        })?;
        let body = &expression[..end];
        if body.trim().is_empty() || body.contains("${{") {
            return Err(PolicyError::new(format!(
                "{label} contains an empty or nested expression"
            )));
        }
        remaining = &expression[end + 2..];
    }
    Ok(Some(chunks))
}

fn template_can_render(chunks: &[String], reserved: &str) -> bool {
    let Some(first) = chunks.first() else {
        return false;
    };
    if !reserved.starts_with(first) {
        return false;
    }
    let mut positions = BTreeSet::from([first.len()]);
    for chunk in &chunks[1..] {
        let mut next = BTreeSet::new();
        for previous in positions {
            for start in previous..=reserved.len() {
                if reserved
                    .get(start..)
                    .is_some_and(|suffix| suffix.starts_with(chunk))
                {
                    next.insert(start + chunk.len());
                }
            }
        }
        positions = next;
        if positions.is_empty() {
            return false;
        }
    }
    positions.contains(&reserved.len())
}

fn validate_matrix_values(
    value: &YamlValue,
    reserved: &BTreeSet<String>,
    path: &str,
) -> PolicyResult<()> {
    match value {
        YamlValue::String(value) => {
            if template_chunks(value, "matrix value")?.is_some() {
                return Err(PolicyError::new(format!(
                    "dynamic matrix value is forbidden in workflow: {path}"
                )));
            }
            if reserved.contains(&spoof_identity(value)) {
                return Err(PolicyError::new(format!(
                    "matrix value can spoof a reserved workflow identity: {path}"
                )));
            }
        }
        YamlValue::Sequence(values) => {
            for value in values {
                validate_matrix_values(value, reserved, path)?;
            }
        }
        YamlValue::Mapping(values) => {
            for value in values.values() {
                validate_matrix_values(value, reserved, path)?;
            }
        }
        YamlValue::Tagged(_) => {
            return Err(PolicyError::new(format!(
                "tagged matrix value is forbidden in workflow: {path}"
            )));
        }
        _ => {}
    }
    Ok(())
}

fn parse_identity(path: &str, workflow: &YamlValue) -> PolicyResult<WorkflowIdentity> {
    let workflow_name = string(get(workflow, "name"))
        .ok_or_else(|| PolicyError::new(format!("workflow has no string name: {path}")))?
        .to_owned();
    require_ascii_identity(&workflow_name, "workflow name")?;
    if template_chunks(&workflow_name, "workflow name")?.is_some() {
        return Err(PolicyError::new(
            "top-level workflow name must not contain expressions",
        ));
    }
    let reserved = reserved_spoof_identities();
    let jobs = mapping(
        get(workflow, "jobs")
            .ok_or_else(|| PolicyError::new(format!("workflow has no jobs mapping: {path}")))?,
    )
    .ok_or_else(|| PolicyError::new(format!("workflow jobs are not a mapping: {path}")))?;
    if jobs.is_empty() || jobs.len() > 64 {
        return Err(PolicyError::new(format!(
            "workflow job count is invalid: {path}"
        )));
    }
    let mut parsed_jobs = Vec::with_capacity(jobs.len());
    for (job_id, job) in jobs {
        let job_id = string(Some(job_id))
            .ok_or_else(|| PolicyError::new(format!("workflow job ID is not a string: {path}")))?;
        require_ascii_identity(job_id, "workflow job ID")?;
        if template_chunks(job_id, "workflow job ID")?.is_some() {
            return Err(PolicyError::new("workflow job ID must be static"));
        }
        let declared_job_name = string(get(job, "name"));
        let matrix = get(get(job, "strategy").unwrap_or(&YamlValue::Null), "matrix");
        if matrix.is_some() && declared_job_name.is_none() {
            return Err(PolicyError::new(format!(
                "matrix workflow job must declare an explicit audited name: {path}"
            )));
        }
        let job_name = declared_job_name.unwrap_or(job_id);
        require_ascii_identity(job_name, "workflow job name")?;
        if let Some(chunks) = template_chunks(job_name, "workflow job name")?
            && reserved
                .iter()
                .any(|identity| template_can_render(&chunks, identity))
        {
            return Err(PolicyError::new(format!(
                "dynamic workflow job name can render a reserved identity: {path}"
            )));
        }
        if let Some(matrix) = matrix {
            validate_matrix_values(matrix, &reserved, path)?;
        }
        parsed_jobs.push((job_id.to_owned(), job_name.to_owned()));
    }
    parsed_jobs.sort();
    Ok(WorkflowIdentity {
        path: path.to_owned(),
        workflow_name,
        jobs: parsed_jobs,
    })
}

fn reject_tagged_yaml(value: &YamlValue, path: &str) -> PolicyResult<()> {
    match value {
        YamlValue::Tagged(_) => Err(PolicyError::new(format!(
            "tagged YAML values are forbidden in repository workflow: {path}"
        ))),
        YamlValue::Mapping(values) => {
            for (key, value) in values {
                reject_tagged_yaml(key, path)?;
                reject_tagged_yaml(value, path)?;
            }
            Ok(())
        }
        YamlValue::Sequence(values) => {
            for value in values {
                reject_tagged_yaml(value, path)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn uses_cancel_in_progress(value: &YamlValue) -> bool {
    match value {
        YamlValue::Mapping(values) => {
            values
                .get(yaml_key("concurrency"))
                .is_some_and(|concurrency| get(concurrency, "cancel-in-progress").is_some())
                || values.values().any(uses_cancel_in_progress)
        }
        YamlValue::Sequence(values) => values.iter().any(uses_cancel_in_progress),
        _ => false,
    }
}

fn validate_ruleset_workflow_eligibility(workflow: &YamlValue) -> PolicyResult<()> {
    if get(
        get(workflow, "on").unwrap_or(&YamlValue::Null),
        "pull_request_target",
    )
    .is_none()
    {
        return Err(PolicyError::new(
            "authoritative ruleset workflow must use pull_request_target",
        ));
    }
    if uses_cancel_in_progress(workflow) {
        return Err(PolicyError::new(
            "authoritative ruleset workflow must not use the cancel-in-progress concurrency setting",
        ));
    }
    let concurrency = mapping(
        get(workflow, "concurrency")
            .ok_or_else(|| PolicyError::new("authoritative workflow concurrency is missing"))?,
    )
    .ok_or_else(|| PolicyError::new("authoritative workflow concurrency is not a mapping"))?;
    if concurrency.len() != 1
        || string(concurrency.get(yaml_key("group"))) != Some(AUTHORITATIVE_CONCURRENCY_GROUP)
    {
        return Err(PolicyError::new(
            "authoritative workflow concurrency must retain the exact per-PR queue group",
        ));
    }
    Ok(())
}

/// Cargo subcommands capable of running a build script and therefore fetching Skia.
///
/// Deliberately includes `cargo run` and `cargo rustc` alongside the more obvious `build`/
/// `check`/`clippy`/`test`, since each also compiles (and therefore can trigger `build.rs`) the
/// manifest it targets.
const CARGO_BUILD_COMMANDS: [&str; 6] = [
    "cargo build",
    "cargo check",
    "cargo clippy",
    "cargo test",
    "cargo run",
    "cargo rustc",
];

/// Recursively flattens every YAML string scalar under `value` (including mapping keys) into
/// `out`, one scalar per line, for the purpose of detecting what a step *executes*.
///
/// Skips the value under a `name:` key: a step's display name is never executed and is fully
/// attacker-controlled free text, so treating it as evidence a command ran (or that a target flag
/// was passed) would be a trivially gameable bypass -- e.g. a step named `resolve-build-artifact`
/// or `aarch64-apple-ios` whose `run:` does nothing of the sort. Every other key (`run`, `env`,
/// `with`, `working-directory`, ...) is still collected, mirroring `reject_tagged_yaml`'s
/// recursive-descent shape.
fn collect_yaml_strings(value: &YamlValue, out: &mut String) {
    match value {
        YamlValue::String(text) => {
            out.push_str(text);
            out.push('\n');
        }
        YamlValue::Mapping(values) => {
            for (key, value) in values {
                if matches!(key, YamlValue::String(key) if key == "name") {
                    continue;
                }
                collect_yaml_strings(key, out);
                collect_yaml_strings(value, out);
            }
        }
        YamlValue::Sequence(values) => {
            for value in values {
                collect_yaml_strings(value, out);
            }
        }
        _ => {}
    }
}

fn flattened_text(value: &YamlValue) -> String {
    let mut text = String::new();
    collect_yaml_strings(value, &mut text);
    text
}

/// Requires a present `ios-packaging.yml` to actually consume the reviewed build-artifact
/// resolver/verifier CLI contract instead of trusting `skia-bindings`' own unverified fetch, and
/// forbids the exact unsafe shape that made an earlier iOS workflow unreviewable: a Cargo
/// invocation against the iOS workspace for the host target, which carries no reviewed Skia pin
/// and would silently fall through to that unverified fetch.
///
/// This is a structural/textual check, not a shell interpreter: it inspects every workflow key
/// (`run`, `env`, `with`, `working-directory`, ...) as flattened text (excluding step `name`,
/// which is never executed), and jobs/steps only enough to order-check Cargo invocations against
/// `verify-build-artifact` within the same job. That is sound for *rejecting* an unsafe workflow
/// shape reviewers actually see -- every pattern it forbids is forbidden regardless of which key
/// or step it appears under -- but it assumes the YAML is read in good faith by a human reviewer
/// alongside it, the same trust boundary every other check in this module relies on. It is not a
/// defense against deliberate shell-level obfuscation (string concatenation that reassembles
/// `https://` only at runtime, indirection through shell variables or aliases, or a build command
/// this module's fixed allowlist does not name), nor against a later step replacing the verified
/// file on disk after `verify-build-artifact` ran (a TOCTOU the CI execution environment, not a
/// pre-merge text check, would need to close). Closing those would require either a full shell
/// interpreter or moving resolve/fetch/verify/build execution behind a base-owned composite
/// action the candidate workflow can only invoke, not inline -- out of scope for this change,
/// which is confined to the trusted crate. In particular, ordering is judged by a step's position
/// in its job's step list; a workflow that fans work across multiple jobs must give each job its
/// own prefetch/verify steps, since state does not carry across job boundaries here.
///
/// Exposed so the contract's shape is proven directly against synthetic workflow fixtures rather
/// than only indirectly through `validate_inventory`.
pub fn validate_ios_packaging_build_artifact_contract(
    workflow: &YamlValue,
    path: &str,
) -> PolicyResult<()> {
    let whole_file = flattened_text(workflow);
    if whole_file.contains("continue-on-error") {
        return Err(PolicyError::new(format!(
            "{path} must not hide a failed build-artifact prefetch/verify or Skia build behind continue-on-error"
        )));
    }
    if !whole_file.contains("resolve-build-artifact")
        || !whole_file.contains("verify-build-artifact")
    {
        return Err(PolicyError::new(format!(
            "{path} must invoke both the reviewed resolve-build-artifact and verify-build-artifact \
             commands before compiling Skia"
        )));
    }
    let skia_binaries_url_lines = whole_file
        .lines()
        .filter(|line| line.contains("SKIA_BINARIES_URL"))
        .collect::<Vec<_>>();
    if skia_binaries_url_lines.is_empty() {
        return Err(PolicyError::new(format!(
            "{path} must inject the reviewed, verified archive by setting SKIA_BINARIES_URL from \
             verify-build-artifact's output"
        )));
    }
    if skia_binaries_url_lines
        .iter()
        .any(|line| line.contains("https://"))
    {
        return Err(PolicyError::new(format!(
            "{path} must not set SKIA_BINARIES_URL to a direct network URL; export the verified \
             local file:// path verify-build-artifact prints instead"
        )));
    }
    if skia_binaries_url_lines
        .iter()
        .any(|line| !line.contains("verify-build-artifact"))
    {
        return Err(PolicyError::new(format!(
            "{path} must derive every SKIA_BINARIES_URL assignment from verify-build-artifact's \
             own output, not set it independently"
        )));
    }
    for (_, _, _, url, digest) in pinned_build_artifacts() {
        if whole_file.contains(url) {
            return Err(PolicyError::new(format!(
                "{path} must not duplicate the reviewed build-artifact URL as a YAML literal; \
                 resolve it via resolve-build-artifact instead: {url}"
            )));
        }
        if whole_file.contains(digest) {
            return Err(PolicyError::new(format!(
                "{path} must not duplicate the reviewed build-artifact digest as a YAML literal; \
                 verify-build-artifact recomputes and checks it instead"
            )));
        }
    }

    let jobs = mapping(
        get(workflow, "jobs")
            .ok_or_else(|| PolicyError::new(format!("workflow has no jobs mapping: {path}")))?,
    )
    .ok_or_else(|| PolicyError::new(format!("workflow jobs are not a mapping: {path}")))?;
    for (job_id, job) in jobs {
        let job_id = string(Some(job_id)).unwrap_or("<unknown>");
        let Some(YamlValue::Sequence(steps)) = get(job, "steps") else {
            continue;
        };
        let mut verified = false;
        for (index, step) in steps.iter().enumerate() {
            let text = flattened_text(step);
            let touches_ios_workspace =
                text.contains("ios/Cargo.toml") || text.contains("apps/gta-claw-ios-shell");
            let can_build = CARGO_BUILD_COMMANDS
                .iter()
                .any(|command| text.contains(command));
            if touches_ios_workspace && can_build {
                if !text.contains("aarch64-apple-ios") {
                    return Err(PolicyError::new(format!(
                        "{path} job {job_id} step {index} can compile the iOS workspace for the \
                         host target, which has no reviewed Skia pin and would fall through to an \
                         unverified fetch"
                    )));
                }
                if !verified {
                    return Err(PolicyError::new(format!(
                        "{path} job {job_id} step {index} compiles the iOS workspace/Skia before \
                         verify-build-artifact runs earlier in job {job_id}"
                    )));
                }
            }
            if text.contains("verify-build-artifact") {
                verified = true;
            }
        }
    }
    Ok(())
}

fn expected_workflow_files(root: &SafeRoot) -> PolicyResult<Vec<String>> {
    let files = root.list_tree(WORKFLOW_DIRECTORY, 32, MAX_WORKFLOW_TREE_BYTES)?;
    let actual = files
        .into_iter()
        .map(|file| file.relative)
        .collect::<Vec<_>>();
    let present = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = REQUIRED_WORKFLOWS
        .into_iter()
        .chain(
            ADMITTED_WORKFLOWS
                .into_iter()
                .filter(|path| present.contains(path)),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(PolicyError::new(format!(
            "workflow directory inventory changed: required {REQUIRED_WORKFLOWS:?}, \
             additionally admitted {ADMITTED_WORKFLOWS:?}, found {actual:?}"
        )));
    }
    Ok(actual)
}

fn owns_reserved_identity(identity: &WorkflowIdentity, reserved: &str) -> bool {
    let reserved = spoof_identity(reserved);
    spoof_identity(&identity.workflow_name) == reserved
        || identity
            .jobs
            .iter()
            .any(|(id, name)| spoof_identity(id) == reserved || spoof_identity(name) == reserved)
}

/// Validates the complete workflow inventory and required-check identities.
pub fn validate_inventory(root: &SafeRoot) -> PolicyResult<Vec<WorkflowIdentity>> {
    let paths = expected_workflow_files(root)?;
    let mut identities = Vec::with_capacity(paths.len());
    let mut workflow_names = BTreeMap::new();
    for path in paths {
        let text = root.read_text(&path, MAX_WORKFLOW_BYTES)?;
        let workflow: YamlValue = serde_yaml_ng::from_str(&text)
            .map_err(|cause| error(&format!("parse workflow {path}"), cause))?;
        reject_tagged_yaml(&workflow, &path)?;
        if path == AUTHORITATIVE_PATH {
            validate_ruleset_workflow_eligibility(&workflow)?;
        }
        if path == IOS_PACKAGING_PATH {
            validate_ios_packaging_build_artifact_contract(&workflow, &path)?;
        }
        let identity = parse_identity(&path, &workflow)?;
        let normalized = require_ascii_identity(&identity.workflow_name, "workflow name")?;
        if let Some(previous) = workflow_names.insert(normalized, path.clone()) {
            return Err(PolicyError::new(format!(
                "duplicate workflow identity: {previous} and {path}"
            )));
        }
        identities.push(identity);
    }

    for identity in &identities {
        let authoritative_owner = identity.path == AUTHORITATIVE_PATH;
        let bootstrap_owner = identity.path == BOOTSTRAP_PATH;
        let claims_authoritative = owns_reserved_identity(identity, AUTHORITATIVE_WORKFLOW_NAME)
            || owns_reserved_identity(identity, AUTHORITATIVE_JOB_NAME)
            || owns_reserved_identity(identity, AUTHORITATIVE_JOB_ID);
        if claims_authoritative && !authoritative_owner {
            return Err(PolicyError::new(format!(
                "authoritative workflow identity is spoofed by {}",
                identity.path
            )));
        }
        let claims_bootstrap = owns_reserved_identity(identity, BOOTSTRAP_WORKFLOW_NAME)
            || owns_reserved_identity(identity, BOOTSTRAP_JOB_NAME)
            || owns_reserved_identity(identity, BOOTSTRAP_JOB_ID);
        if claims_bootstrap && !bootstrap_owner {
            return Err(PolicyError::new(format!(
                "bootstrap workflow identity is spoofed by {}",
                identity.path
            )));
        }
    }

    let authoritative = identities
        .iter()
        .find(|identity| identity.path == AUTHORITATIVE_PATH)
        .ok_or_else(|| PolicyError::new("authoritative workflow is missing"))?;
    if authoritative.workflow_name != AUTHORITATIVE_WORKFLOW_NAME
        || authoritative.jobs
            != vec![(
                AUTHORITATIVE_JOB_ID.to_owned(),
                AUTHORITATIVE_JOB_NAME.to_owned(),
            )]
    {
        return Err(PolicyError::new(
            "authoritative workflow/job identity changed",
        ));
    }
    let bootstrap = identities
        .iter()
        .find(|identity| identity.path == BOOTSTRAP_PATH)
        .ok_or_else(|| PolicyError::new("bootstrap workflow is missing"))?;
    if bootstrap.workflow_name != BOOTSTRAP_WORKFLOW_NAME
        || bootstrap.jobs != vec![(BOOTSTRAP_JOB_ID.to_owned(), BOOTSTRAP_JOB_NAME.to_owned())]
    {
        return Err(PolicyError::new(
            "non-authoritative bootstrap workflow/job identity changed",
        ));
    }
    Ok(identities)
}

/// Requires both workflow definitions and the validator tree to match the base exactly.
pub fn validate_protected_files(trusted: &SafeRoot, candidate: &SafeRoot) -> PolicyResult<()> {
    compare_trees(
        trusted,
        candidate,
        ".github/trusted/desktop-supply-chain-policy",
    )?;
    for path in [CODEOWNERS_PATH, AUTHORITATIVE_PATH, BOOTSTRAP_PATH] {
        let trusted_bytes = trusted.read_bytes(path, MAX_WORKFLOW_BYTES)?;
        let candidate_bytes = candidate.read_bytes(path, MAX_WORKFLOW_BYTES)?;
        if trusted_bytes != candidate_bytes {
            return Err(PolicyError::new(format!(
                "protected workflow changed: {path}"
            )));
        }
    }
    Ok(())
}

/// Requires the candidate Rust and macOS workflows to be the trusted final P04f bytes.
pub fn validate_final_workflows(candidate: &SafeRoot) -> PolicyResult<()> {
    for (path, expected) in [
        (RUST_WORKFLOW, CANONICAL_RUST),
        (MACOS_WORKFLOW, CANONICAL_MACOS),
    ] {
        let actual = candidate.read_bytes(path, MAX_WORKFLOW_BYTES)?;
        if actual != expected {
            return Err(PolicyError::new(format!(
                "candidate workflow does not match trusted final P04f policy: {path}"
            )));
        }
    }
    Ok(())
}

fn copied_workflow_path(root: &Path, relative: &str) -> PolicyResult<PathBuf> {
    let file_name = Path::new(relative)
        .file_name()
        .ok_or_else(|| PolicyError::new("workflow path has no file name"))?;
    Ok(root.join(file_name))
}

/// Runs a trusted actionlint binary over isolated bounded workflow copies.
pub fn run_actionlint(
    candidate: &SafeRoot,
    tool: &ActionlintTool,
    isolation_root: &Path,
) -> PolicyResult<()> {
    let actionlint = canonical_tool(&tool.path)?;
    let metadata =
        fs::metadata(&actionlint).map_err(|cause| error("inspect trusted actionlint", cause))?;
    if metadata.len() > MAX_ACTIONLINT_BYTES {
        return Err(PolicyError::new(
            "trusted actionlint binary exceeds size limit",
        ));
    }
    let digest =
        sha256(&fs::read(&actionlint).map_err(|cause| error("read trusted actionlint", cause))?);
    if digest != tool.sha256 {
        return Err(PolicyError::new(format!(
            "trusted actionlint checksum mismatch: expected {}, found {digest}",
            tool.sha256
        )));
    }
    let version = run_checked(
        &CommandSpec::new(&actionlint, isolation_root)?
            .arg("-version")
            .env("LC_ALL", "C")
            .timeout(Duration::from_secs(10))
            .output_limits(64 * 1024, 64 * 1024),
        "trusted actionlint version",
    )?;
    let version = std::str::from_utf8(&version.stdout)
        .map_err(|cause| error("decode trusted actionlint version", cause))?
        .lines()
        .next()
        .unwrap_or_default();
    if version != "1.7.7" {
        return Err(PolicyError::new(format!(
            "trusted actionlint version mismatch: {version:?}"
        )));
    }
    let copy_root = isolation_root.join("actionlint-input");
    if copy_root.exists() {
        fs::remove_dir_all(&copy_root)
            .map_err(|cause| error("remove prior actionlint input", cause))?;
    }
    fs::create_dir_all(&copy_root).map_err(|cause| error("create actionlint input", cause))?;
    let mut copied = Vec::new();
    for path in expected_workflow_files(candidate)? {
        let destination = copied_workflow_path(&copy_root, &path)?;
        fs::write(
            &destination,
            candidate.read_bytes(&path, MAX_WORKFLOW_BYTES)?,
        )
        .map_err(|cause| error("write isolated actionlint input", cause))?;
        copied.push(destination);
    }
    let mut spec = CommandSpec::new(actionlint, &copy_root)?
        .args(["-shellcheck=", "-pyflakes=", "-ignore", "macos-15-intel"])
        .env("HOME", isolation_root.join("actionlint-home"))
        .env("LC_ALL", "C")
        .timeout(Duration::from_secs(30))
        .output_limits(2 * 1024 * 1024, 2 * 1024 * 1024);
    for path in copied {
        spec = spec.arg(path);
    }
    let output = run_checked(&spec, "trusted actionlint")?;
    if !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(PolicyError::new(format!(
            "trusted actionlint emitted unexpected output: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

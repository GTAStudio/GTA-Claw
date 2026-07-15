//! End-to-end bootstrap/final policy state machine.

use std::path::{Path, PathBuf};

use crate::changes::{ChangeManifest, has_policy_relevant_change, read_manifest};
use crate::input::SafeRoot;
use crate::metadata::{MetadataTools, validate_desktop_metadata, validate_root_metadata};
use crate::ownership::validate_codeowners;
use crate::policy::{is_bootstrap_state, validate_final_static};
use crate::workflows::{
    ActionlintTool, run_actionlint, validate_final_workflows, validate_inventory,
    validate_protected_files,
};
use crate::{PolicyError, PolicyResult};

/// Explicit trusted inputs to one authoritative validation.
#[derive(Debug, Clone)]
pub struct ValidationRequest {
    /// Exact protected base checkout after `.git` removal.
    pub trusted_root: PathBuf,
    /// Exact immutable candidate checkout after `.git` removal.
    pub candidate_root: PathBuf,
    /// Trusted Git-produced changed-path manifest.
    pub changes: PathBuf,
    /// Checksum-pinned Rust tools.
    pub metadata_tools: MetadataTools,
    /// Checksum-pinned actionlint binary.
    pub actionlint: ActionlintTool,
    /// Empty base-owned isolation root.
    pub isolation_root: PathBuf,
}

/// Effective base policy state.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BaseState {
    /// Exact short-lived pre-P04f product fingerprint.
    Bootstrap,
    /// Complete final P04f state with extensible root rules.
    Final,
}

/// Successful validation evidence.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidationEvidence {
    /// Effective base state.
    pub base_state: BaseState,
    /// Whether trusted Git found any policy-relevant changed path.
    pub relevant_change: bool,
    /// Exact base OID from the trusted manifest.
    pub base: String,
    /// Exact head OID from the trusted manifest.
    pub head: String,
    /// Complete changed path count.
    pub changed_paths: usize,
    /// Whether complete final policy was enforced for the candidate.
    pub candidate_final: bool,
}

/// Returns whether complete final policy must be enforced for the candidate.
#[must_use]
pub const fn candidate_requires_final(base_state: BaseState, relevant_change: bool) -> bool {
    matches!(base_state, BaseState::Final)
        || matches!(base_state, BaseState::Bootstrap) && relevant_change
}

fn ensure_git_removed(root: &SafeRoot, label: &str) -> PolicyResult<()> {
    if root.exists(".git")? {
        return Err(PolicyError::new(format!(
            "{label} Git metadata must be removed before policy validation"
        )));
    }
    Ok(())
}

fn validate_final(
    root: &SafeRoot,
    tools: &MetadataTools,
    actionlint: &ActionlintTool,
    isolation: &Path,
    label: &str,
) -> PolicyResult<()> {
    validate_final_workflows(root)?;
    let workspace = validate_final_static(root)?;
    let root_isolation = isolation.join(label);
    std::fs::create_dir_all(&root_isolation).map_err(|cause| {
        PolicyError::new(format!(
            "create {label} validation isolation directory: {cause}"
        ))
    })?;
    run_actionlint(root, actionlint, &root_isolation)?;
    validate_root_metadata(root, &workspace, tools, &root_isolation)?;
    validate_desktop_metadata(root, &workspace.version, tools, &root_isolation)
}

fn validate_manifest_roots(
    manifest: &ChangeManifest,
    trusted: &SafeRoot,
    candidate: &SafeRoot,
) -> PolicyResult<()> {
    if manifest.base == manifest.head {
        return Err(PolicyError::new(
            "pull request base and head OIDs must differ",
        ));
    }
    if trusted.path() == candidate.path()
        || trusted.path().starts_with(candidate.path())
        || candidate.path().starts_with(trusted.path())
    {
        return Err(PolicyError::new(
            "trusted and candidate roots must be separate non-nested directories",
        ));
    }
    Ok(())
}

/// Validates one immutable candidate against the exact protected base.
pub fn validate_request(request: &ValidationRequest) -> PolicyResult<ValidationEvidence> {
    if !request.isolation_root.is_absolute() {
        return Err(PolicyError::new(
            "validation isolation root must be absolute",
        ));
    }
    let trusted = SafeRoot::new(&request.trusted_root)?;
    let candidate = SafeRoot::new(&request.candidate_root)?;
    ensure_git_removed(&trusted, "trusted base")?;
    ensure_git_removed(&candidate, "candidate")?;
    let manifest = read_manifest(&request.changes)?;
    validate_manifest_roots(&manifest, &trusted, &candidate)?;

    validate_codeowners(&trusted)?;
    validate_codeowners(&candidate)?;
    validate_protected_files(&trusted, &candidate)?;
    validate_inventory(&trusted)?;
    validate_inventory(&candidate)?;

    let relevant_change = has_policy_relevant_change(&manifest);
    let base_state = if is_bootstrap_state(&trusted)? {
        BaseState::Bootstrap
    } else {
        validate_final(
            &trusted,
            &request.metadata_tools,
            &request.actionlint,
            &request.isolation_root,
            "trusted-base",
        )?;
        BaseState::Final
    };

    let candidate_final = if candidate_requires_final(base_state, relevant_change) {
        validate_final(
            &candidate,
            &request.metadata_tools,
            &request.actionlint,
            &request.isolation_root,
            "candidate",
        )?;
        true
    } else {
        if !is_bootstrap_state(&candidate)? {
            return Err(PolicyError::new(
                "irrelevant PR changed the exact bootstrap product-policy fingerprint",
            ));
        }
        false
    };

    Ok(ValidationEvidence {
        base_state,
        relevant_change,
        base: manifest.base,
        head: manifest.head,
        changed_paths: manifest.paths.len(),
        candidate_final,
    })
}

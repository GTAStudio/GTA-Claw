//! Fail-closed legacy JavaScript skill inspection and migration evidence.

use serde::Deserialize;
use serde_json::Value;

/// Legacy bridge recognized for migration planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyBridge {
    /// Legacy `api.httpGet` call.
    HttpGet,
    /// Legacy `api.httpPost` call.
    HttpPost,
    /// Legacy `api.log` call.
    Log,
}

/// Shape accepted by the historical loader's object check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyParameterShape {
    /// JSON object.
    Object,
    /// JSON array, historically accepted because JavaScript arrays are objects.
    Array,
}

/// Safe disposition of a valid legacy manifest.
///
/// The JavaScript source is discarded during inspection and never appears in
/// this value, debug output, or any executable enum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacySkillDisposition {
    /// Legacy skill name.
    pub name: String,
    /// Legacy description.
    pub description: String,
    /// Historical parameter value shape.
    pub parameter_shape: LegacyParameterShape,
    /// Statically recognized bridge calls for porting assistance.
    pub recognized_bridges: Vec<LegacyBridge>,
}

/// Stable legacy manifest rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySkillError {
    /// JSON is malformed or has an invalid field type.
    MalformedJson,
    /// Name fails the historical identifier pattern.
    InvalidName,
    /// Description is empty.
    EmptyDescription,
    /// Parameters are neither an object nor an array.
    InvalidParameters,
    /// `executeCode` is absent or empty.
    MissingExecuteCode,
}

#[derive(Deserialize)]
struct RawLegacySkill {
    name: String,
    description: String,
    parameters: Value,
    #[serde(rename = "executeCode")]
    execute_code: Option<String>,
}

/// Validates a legacy manifest and returns only manual-porting metadata.
///
/// This function does not evaluate, compile, persist, or return JavaScript.
pub fn inspect_legacy_manifest(json: &str) -> Result<LegacySkillDisposition, LegacySkillError> {
    let raw: RawLegacySkill =
        serde_json::from_str(json).map_err(|_| LegacySkillError::MalformedJson)?;
    if !valid_legacy_name(&raw.name) {
        return Err(LegacySkillError::InvalidName);
    }
    if raw.description.trim().is_empty() {
        return Err(LegacySkillError::EmptyDescription);
    }
    let parameter_shape = match raw.parameters {
        Value::Object(_) => LegacyParameterShape::Object,
        Value::Array(_) => LegacyParameterShape::Array,
        _ => return Err(LegacySkillError::InvalidParameters),
    };
    let execute_code = raw
        .execute_code
        .filter(|code| !code.trim().is_empty())
        .ok_or(LegacySkillError::MissingExecuteCode)?;
    let mut recognized_bridges = Vec::new();
    if contains_bridge_call(&execute_code, "api.httpGet") {
        recognized_bridges.push(LegacyBridge::HttpGet);
    }
    if contains_bridge_call(&execute_code, "api.httpPost") {
        recognized_bridges.push(LegacyBridge::HttpPost);
    }
    if contains_bridge_call(&execute_code, "api.log") {
        recognized_bridges.push(LegacyBridge::Log);
    }
    Ok(LegacySkillDisposition {
        name: raw.name,
        description: raw.description,
        parameter_shape,
        recognized_bridges,
    })
}

fn contains_bridge_call(source: &str, name: &str) -> bool {
    source
        .match_indices(name)
        .any(|(index, _)| source[index + name.len()..].trim_start().starts_with('('))
}

fn valid_legacy_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Structurally validated replacement-artifact evidence.
///
/// Cryptographic verification belongs to the plugin trust subsystem, which has
/// access to artifact bytes and trust anchors. This type proves only that the
/// migration report contains complete signature metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortArtifactEvidence {
    /// Artifact kind.
    pub kind: String,
    /// Relative artifact path.
    pub path: String,
    /// Recorded SHA-256 digest.
    pub sha256: String,
    /// Signing key identifier.
    pub key_id: String,
}

/// Frozen migration input category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationInputKind {
    /// Role data.
    Role,
    /// Legacy JavaScript skill requiring a reviewed port.
    LegacySkill,
    /// Legacy environment configuration.
    Environment,
}

/// Safe migration outcome accepted by this validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationStatus {
    /// Migration completed with no JavaScript reported.
    Migrated,
    /// A scaffold exists but JavaScript remains and cannot be executed.
    ManualPortRequired,
}

/// Structurally validated migration evidence with an explicit safe outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMigrationEvidence {
    /// Input category.
    pub input_kind: MigrationInputKind,
    /// Opaque, untrusted source reference.
    ///
    /// This value may be a path or URL and must not be passed to filesystem or
    /// network APIs without a separate policy check.
    pub source_reference: String,
    /// Validated migration outcome.
    pub status: MigrationStatus,
    /// Artifact metadata awaiting independent signature verification.
    pub artifacts: Vec<PortArtifactEvidence>,
    /// Recognized historical bridge names.
    pub recognized_bridges: Vec<String>,
    /// Number of reported JavaScript locations. This is non-zero only for
    /// [`MigrationStatus::ManualPortRequired`].
    pub remaining_javascript_count: usize,
}

/// Stable migration evidence rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationEvidenceError {
    /// Evidence JSON is malformed.
    MalformedJson,
    /// Migration did not report successful completion.
    MigrationFailed,
    /// JavaScript remains in the claimed replacement.
    RemainingJavaScript,
    /// No signed native/Wasm port evidence exists.
    MissingPortEvidence,
    /// Artifact digest, path, kind, or signature metadata is malformed.
    InvalidArtifact,
    /// Input kind, digest, bridges, or cross-field constraints are invalid.
    InvalidContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    contract_version: String,
    input: RawInput,
    status: String,
    exit_code: i32,
    recognized_bridges: Vec<String>,
    remaining_javascript: Vec<RawRemainingJavaScript>,
    artifacts: Vec<RawArtifact>,
    diagnostics: Vec<RawDiagnostic>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInput {
    kind: String,
    source: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    kind: String,
    path: String,
    sha256: String,
    signature: RawSignature,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSignature {
    algorithm: String,
    key_id: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDiagnostic {
    code: String,
    severity: String,
    message: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRemainingJavaScript {
    location: String,
    reason: String,
}

/// Structurally validates migration evidence for later cryptographic verification.
pub fn validate_migration_evidence(
    json: &str,
) -> Result<ValidatedMigrationEvidence, MigrationEvidenceError> {
    let evidence: RawEvidence =
        serde_json::from_str(json).map_err(|_| MigrationEvidenceError::MalformedJson)?;
    if evidence.contract_version != "1.0.0"
        || evidence.input.source.is_empty()
        || !valid_sha256(&evidence.input.sha256)
        || !valid_bridges(&evidence.recognized_bridges)
        || !valid_diagnostics(&evidence.diagnostics)
        || evidence
            .remaining_javascript
            .iter()
            .any(|entry| entry.location.is_empty() || entry.reason.is_empty())
    {
        return Err(MigrationEvidenceError::InvalidContract);
    }
    let input_kind = match evidence.input.kind.as_str() {
        "role" => MigrationInputKind::Role,
        "legacy_skill" => MigrationInputKind::LegacySkill,
        "environment" => MigrationInputKind::Environment,
        _ => return Err(MigrationEvidenceError::InvalidContract),
    };
    if evidence.status == "migrated" && !evidence.remaining_javascript.is_empty() {
        return Err(MigrationEvidenceError::RemainingJavaScript);
    }
    let status = match evidence.status.as_str() {
        "migrated" if evidence.exit_code == 0 => MigrationStatus::Migrated,
        "manual_port_required"
            if evidence.exit_code == 2
                && input_kind == MigrationInputKind::LegacySkill
                && !evidence.remaining_javascript.is_empty() =>
        {
            MigrationStatus::ManualPortRequired
        }
        _ => return Err(MigrationEvidenceError::MigrationFailed),
    };
    validate_artifact_contract(input_kind, status, &evidence.artifacts)?;
    let mut artifacts = Vec::with_capacity(evidence.artifacts.len());
    for artifact in evidence.artifacts {
        if artifact.path.is_empty()
            || artifact.path.starts_with(['/', '\\'])
            || artifact.path.contains("..")
            || artifact.path.contains(':')
            || artifact.sha256.len() != 64
            || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || artifact.signature.algorithm != "ed25519"
            || artifact.signature.key_id.is_empty()
            || artifact.signature.value.is_empty()
        {
            return Err(MigrationEvidenceError::InvalidArtifact);
        }
        artifacts.push(PortArtifactEvidence {
            kind: artifact.kind,
            path: artifact.path,
            sha256: artifact.sha256,
            key_id: artifact.signature.key_id,
        });
    }
    Ok(ValidatedMigrationEvidence {
        input_kind,
        source_reference: evidence.input.source,
        status,
        artifacts,
        recognized_bridges: evidence.recognized_bridges,
        remaining_javascript_count: evidence.remaining_javascript.len(),
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_bridges(bridges: &[String]) -> bool {
    bridges.iter().enumerate().all(|(index, bridge)| {
        matches!(bridge.as_str(), "httpGet" | "httpPost" | "log")
            && !bridges[..index].contains(bridge)
    })
}

fn valid_diagnostics(diagnostics: &[RawDiagnostic]) -> bool {
    diagnostics.iter().all(|diagnostic| {
        !diagnostic.code.is_empty()
            && !diagnostic.message.is_empty()
            && matches!(diagnostic.severity.as_str(), "info" | "warning" | "error")
    })
}

fn validate_artifact_contract(
    input_kind: MigrationInputKind,
    status: MigrationStatus,
    artifacts: &[RawArtifact],
) -> Result<(), MigrationEvidenceError> {
    match input_kind {
        MigrationInputKind::Role => {
            if status != MigrationStatus::Migrated
                || artifacts.len() != 1
                || artifacts[0].kind != "role"
            {
                return Err(MigrationEvidenceError::InvalidArtifact);
            }
        }
        MigrationInputKind::Environment => {
            if status != MigrationStatus::Migrated
                || artifacts.len() != 1
                || artifacts[0].kind != "json5_config"
            {
                return Err(MigrationEvidenceError::InvalidArtifact);
            }
        }
        MigrationInputKind::LegacySkill => {
            if artifacts.len() != 2 {
                return Err(MigrationEvidenceError::MissingPortEvidence);
            }
            let wasi_count = artifacts
                .iter()
                .filter(|artifact| artifact.kind == "wasi_manifest")
                .count();
            let wit_count = artifacts
                .iter()
                .filter(|artifact| artifact.kind == "wit_scaffold")
                .count();
            if wasi_count != 1 || wit_count != 1 {
                return Err(MigrationEvidenceError::InvalidArtifact);
            }
        }
    }
    Ok(())
}

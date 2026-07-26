use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Frozen migration result contract version.
pub(crate) const MIGRATION_CONTRACT_VERSION: &str = "1.0.0";

/// Kind of legacy input being migrated.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// Role or system prompt data.
    Role,
    /// Legacy skill containing inert JavaScript source.
    LegacySkill,
    /// Environment or client installation state.
    Environment,
}

/// Input identity included in every migration result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationInput {
    /// Input category.
    pub kind: InputKind,
    /// Human-readable source path or URL.
    pub source: String,
    /// Lowercase SHA-256 digest of the source.
    pub sha256: String,
}

/// Migration outcome with a fixed exit-code mapping.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    /// Migration completed without executable legacy content.
    Migrated,
    /// Safe scaffolding was produced but an explicit Rust port remains.
    ManualPortRequired,
    /// Input did not satisfy its frozen schema.
    InvalidInput,
    /// Migration failed internally or violated a safety invariant.
    Failed,
}

impl MigrationStatus {
    /// Required process exit code for this status.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Migrated => 0,
            Self::Failed => 1,
            Self::ManualPortRequired => 2,
            Self::InvalidInput => 3,
        }
    }
}

/// Recognized host bridge referenced by inert legacy skill source.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Bridge {
    /// HTTP GET bridge.
    HttpGet,
    /// HTTP POST bridge.
    HttpPost,
    /// Structured logging bridge.
    Log,
}

/// Evidence that executable legacy content remains.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemainingJavascript {
    /// Location within the source.
    pub location: String,
    /// Why an explicit port is still required.
    pub reason: String,
}

/// Kind of signed migration artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Signed WASI component manifest.
    WasiManifest,
    /// WIT world scaffold.
    WitScaffold,
    /// Migrated role data.
    Role,
    /// Migrated JSON5 configuration.
    Json5Config,
}

/// Signature metadata attached to every emitted artifact.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSignature {
    /// Signature algorithm. The frozen contract requires `ed25519`.
    pub algorithm: String,
    /// Signing key identifier.
    pub key_id: String,
    /// Encoded signature.
    pub value: String,
}

/// One signed migration output.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// Artifact category.
    pub kind: ArtifactKind,
    /// Output path relative to the migration target.
    pub path: String,
    /// Lowercase SHA-256 digest of the artifact bytes.
    pub sha256: String,
    /// Ed25519 signature over the artifact digest.
    pub signature: ArtifactSignature,
}

/// Diagnostic severity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// Informational message.
    Info,
    /// Non-fatal warning.
    Warning,
    /// Error that prevents a successful migration.
    Error,
}

/// Structured migration diagnostic.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    /// Stable diagnostic code.
    pub code: String,
    /// Severity.
    pub severity: DiagnosticSeverity,
    /// Human-readable, secret-free message.
    pub message: String,
}

/// Exact frozen migration-result shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationResult {
    /// Contract version, always `1.0.0`.
    pub contract_version: String,
    /// Source identity.
    pub input: MigrationInput,
    /// Classified outcome.
    pub status: MigrationStatus,
    /// Process exit code.
    pub exit_code: u8,
    /// Recognized host bridges.
    pub recognized_bridges: Vec<Bridge>,
    /// Remaining executable JavaScript evidence.
    pub remaining_javascript: Vec<RemainingJavascript>,
    /// Signed output artifacts.
    pub artifacts: Vec<Artifact>,
    /// Structured diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl MigrationResult {
    /// Validates all cross-field rules from the frozen JSON schema.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.contract_version != MIGRATION_CONTRACT_VERSION {
            return Err(ContractViolation::ContractVersion);
        }
        if self.input.source.is_empty() {
            return Err(ContractViolation::EmptyInputSource);
        }
        validate_digest(&self.input.sha256)?;
        if self.exit_code != self.status.exit_code() {
            return Err(ContractViolation::ExitCode {
                status: self.status,
                expected: self.status.exit_code(),
                actual: self.exit_code,
            });
        }
        if self.input.kind == InputKind::Role && !self.remaining_javascript.is_empty() {
            return Err(ContractViolation::RoleJavascriptEvidence);
        }
        if self.input.kind == InputKind::Environment && !self.remaining_javascript.is_empty() {
            return Err(ContractViolation::EnvironmentJavascriptEvidence);
        }
        if self.status == MigrationStatus::Migrated && !self.remaining_javascript.is_empty() {
            return Err(ContractViolation::MigratedWithJavascript);
        }
        let mut bridges = BTreeSet::new();
        if self
            .recognized_bridges
            .iter()
            .any(|bridge| !bridges.insert(*bridge))
        {
            return Err(ContractViolation::DuplicateBridge);
        }
        let mut artifacts = BTreeSet::new();
        for artifact in &self.artifacts {
            if !artifacts.insert(artifact) {
                return Err(ContractViolation::DuplicateArtifact);
            }
            if artifact.path.is_empty()
                || artifact.signature.algorithm != "ed25519"
                || artifact.signature.key_id.is_empty()
                || artifact.signature.value.is_empty()
            {
                return Err(ContractViolation::InvalidArtifactMetadata);
            }
            validate_digest(&artifact.sha256)?;
        }
        for remaining in &self.remaining_javascript {
            if remaining.location.is_empty() || remaining.reason.is_empty() {
                return Err(ContractViolation::InvalidJavascriptEvidence);
            }
        }
        for diagnostic in &self.diagnostics {
            if diagnostic.code.is_empty() || diagnostic.message.is_empty() {
                return Err(ContractViolation::InvalidDiagnostic);
            }
        }
        match self.input.kind {
            InputKind::Role => self.validate_role(),
            InputKind::Environment => self.validate_environment(),
            InputKind::LegacySkill => self.validate_legacy_skill(),
        }
    }

    fn validate_role(&self) -> Result<(), ContractViolation> {
        if self.status == MigrationStatus::ManualPortRequired {
            return Err(ContractViolation::StatusNotAllowedForInput);
        }
        if !self.recognized_bridges.is_empty() {
            return Err(ContractViolation::RoleBridgeEvidence);
        }
        if !self.remaining_javascript.is_empty() {
            return Err(ContractViolation::RoleJavascriptEvidence);
        }
        if self
            .artifacts
            .iter()
            .any(|artifact| artifact.kind != ArtifactKind::Role)
        {
            return Err(ContractViolation::ArtifactKindMismatch {
                input: InputKind::Role,
            });
        }
        validate_single_success_artifact(self)
    }

    fn validate_environment(&self) -> Result<(), ContractViolation> {
        if self.status == MigrationStatus::ManualPortRequired {
            return Err(ContractViolation::StatusNotAllowedForInput);
        }
        if !self.recognized_bridges.is_empty() {
            return Err(ContractViolation::EnvironmentBridgeEvidence);
        }
        if !self.remaining_javascript.is_empty() {
            return Err(ContractViolation::EnvironmentJavascriptEvidence);
        }
        if self
            .artifacts
            .iter()
            .any(|artifact| artifact.kind != ArtifactKind::Json5Config)
        {
            return Err(ContractViolation::ArtifactKindMismatch {
                input: InputKind::Environment,
            });
        }
        validate_single_success_artifact(self)
    }

    fn validate_legacy_skill(&self) -> Result<(), ContractViolation> {
        if self.artifacts.iter().any(|artifact| {
            !matches!(
                artifact.kind,
                ArtifactKind::WasiManifest | ArtifactKind::WitScaffold
            )
        }) {
            return Err(ContractViolation::ArtifactKindMismatch {
                input: InputKind::LegacySkill,
            });
        }
        match self.status {
            MigrationStatus::Migrated | MigrationStatus::ManualPortRequired => {
                if self.artifacts.len() != 2 {
                    return Err(ContractViolation::MissingPortEvidence);
                }
                let kinds: BTreeSet<_> = self
                    .artifacts
                    .iter()
                    .map(|artifact| artifact.kind)
                    .collect();
                if kinds != BTreeSet::from([ArtifactKind::WasiManifest, ArtifactKind::WitScaffold])
                {
                    return Err(ContractViolation::MissingPortEvidence);
                }
            }
            MigrationStatus::InvalidInput | MigrationStatus::Failed => {
                if !self.artifacts.is_empty() {
                    return Err(ContractViolation::UnexpectedArtifacts);
                }
            }
        }
        if self.status == MigrationStatus::ManualPortRequired
            && self.remaining_javascript.is_empty()
        {
            return Err(ContractViolation::MissingJavascriptEvidence);
        }
        if self.status == MigrationStatus::InvalidInput && !self.remaining_javascript.is_empty() {
            return Err(ContractViolation::UnexpectedJavascriptEvidence);
        }
        Ok(())
    }
}

fn validate_single_success_artifact(result: &MigrationResult) -> Result<(), ContractViolation> {
    if result.status == MigrationStatus::Migrated {
        if result.artifacts.len() != 1 {
            return Err(ContractViolation::ArtifactCount {
                expected: 1,
                actual: result.artifacts.len(),
            });
        }
    } else if !result.artifacts.is_empty() {
        return Err(ContractViolation::UnexpectedArtifacts);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ContractViolation> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ContractViolation::InvalidSha256)
    }
}

/// Precise reason a migration result violates the frozen contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractViolation {
    /// Contract version differs from `1.0.0`.
    ContractVersion,
    /// Input source is empty.
    EmptyInputSource,
    /// A SHA-256 field is not 64 lowercase hexadecimal characters.
    InvalidSha256,
    /// Status and exit code disagree.
    ExitCode {
        /// Classified status.
        status: MigrationStatus,
        /// Required exit code.
        expected: u8,
        /// Supplied exit code.
        actual: u8,
    },
    /// A successful result still reports JavaScript.
    MigratedWithJavascript,
    /// A recognized bridge is duplicated.
    DuplicateBridge,
    /// An artifact is duplicated.
    DuplicateArtifact,
    /// Artifact path or signature metadata is invalid.
    InvalidArtifactMetadata,
    /// JavaScript evidence is incomplete.
    InvalidJavascriptEvidence,
    /// A diagnostic is incomplete.
    InvalidDiagnostic,
    /// Status is forbidden for the input kind.
    StatusNotAllowedForInput,
    /// Role input reported a host bridge.
    RoleBridgeEvidence,
    /// Role input reported JavaScript.
    RoleJavascriptEvidence,
    /// Environment input reported a host bridge.
    EnvironmentBridgeEvidence,
    /// Environment input reported JavaScript.
    EnvironmentJavascriptEvidence,
    /// Artifact kind does not match the input kind.
    ArtifactKindMismatch {
        /// Input category whose artifact constraint was violated.
        input: InputKind,
    },
    /// Successful role or environment result has the wrong artifact count.
    ArtifactCount {
        /// Required count.
        expected: usize,
        /// Supplied count.
        actual: usize,
    },
    /// Failed or invalid input unexpectedly emitted artifacts.
    UnexpectedArtifacts,
    /// Legacy-skill success lacks a manifest and WIT scaffold.
    MissingPortEvidence,
    /// Manual port status lacks remaining JavaScript evidence.
    MissingJavascriptEvidence,
    /// Invalid input incorrectly reports remaining JavaScript.
    UnexpectedJavascriptEvidence,
}

impl Display for ContractViolation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractVersion => formatter.write_str("unsupported migration contract version"),
            Self::EmptyInputSource => formatter.write_str("migration input source is empty"),
            Self::InvalidSha256 => formatter.write_str("invalid lowercase SHA-256 digest"),
            Self::ExitCode {
                status,
                expected,
                actual,
            } => write!(
                formatter,
                "{status:?} requires exit code {expected}, received {actual}"
            ),
            Self::MigratedWithJavascript => {
                formatter.write_str("migrated result still contains JavaScript evidence")
            }
            Self::DuplicateBridge => formatter.write_str("recognized bridge is duplicated"),
            Self::DuplicateArtifact => formatter.write_str("migration artifact is duplicated"),
            Self::InvalidArtifactMetadata => {
                formatter.write_str("migration artifact metadata is invalid")
            }
            Self::InvalidJavascriptEvidence => {
                formatter.write_str("remaining JavaScript evidence is incomplete")
            }
            Self::InvalidDiagnostic => formatter.write_str("migration diagnostic is incomplete"),
            Self::StatusNotAllowedForInput => {
                formatter.write_str("migration status is not allowed for this input kind")
            }
            Self::RoleBridgeEvidence => {
                formatter.write_str("role input cannot report host bridges")
            }
            Self::RoleJavascriptEvidence => {
                formatter.write_str("role input cannot report JavaScript evidence")
            }
            Self::EnvironmentBridgeEvidence => {
                formatter.write_str("environment input cannot report host bridges")
            }
            Self::EnvironmentJavascriptEvidence => {
                formatter.write_str("environment input cannot report JavaScript evidence")
            }
            Self::ArtifactKindMismatch { input } => {
                write!(formatter, "artifact kind does not match {input:?} input")
            }
            Self::ArtifactCount { expected, actual } => {
                write!(
                    formatter,
                    "expected {expected} artifact(s), received {actual}"
                )
            }
            Self::UnexpectedArtifacts => {
                formatter.write_str("failed or invalid migration emitted artifacts")
            }
            Self::MissingPortEvidence => {
                formatter.write_str("legacy skill lacks signed manifest and WIT port evidence")
            }
            Self::MissingJavascriptEvidence => {
                formatter.write_str("manual port result lacks JavaScript evidence")
            }
            Self::UnexpectedJavascriptEvidence => {
                formatter.write_str("invalid input cannot report JavaScript evidence")
            }
        }
    }
}

impl Error for ContractViolation {}

/// Parsed legacy role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedRole {
    /// System prompt content.
    pub content: String,
    /// Optional model identifier.
    pub model: Option<String>,
}

/// How a role source was interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleLoadOutcome {
    /// Parsed as a JSON role.
    LoadedJson,
    /// Preserved verbatim as plain text.
    LoadedPlainText,
}

/// Legacy role parsing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleError {
    /// Input is not valid JSON.
    InvalidJson,
    /// Neither a string `content` nor fallback string `prompt` exists.
    MissingContent,
    /// Selected content is empty.
    EmptyContent,
    /// JSON role source body is neither an object nor a JSON string.
    InvalidSourceBody,
}

impl Display for RoleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => formatter.write_str("role source is not valid JSON"),
            Self::MissingContent => formatter.write_str("role content is missing or not a string"),
            Self::EmptyContent => formatter.write_str("role content must not be empty"),
            Self::InvalidSourceBody => formatter.write_str("role source body is invalid"),
        }
    }
}

impl Error for RoleError {}

/// Loads a role from its legacy JSON representation.
pub fn load_role_json(input: &str) -> Result<LoadedRole, RoleError> {
    let value: Value = serde_json::from_str(input).map_err(|_| RoleError::InvalidJson)?;
    load_role_value(&value)
}

fn load_role_value(value: &Value) -> Result<LoadedRole, RoleError> {
    let object = value.as_object().ok_or(RoleError::InvalidJson)?;
    let content = match object.get("content") {
        Some(Value::String(content)) => content,
        Some(_) | None => object
            .get("prompt")
            .and_then(Value::as_str)
            .ok_or(RoleError::MissingContent)?,
    };
    if content.is_empty() {
        return Err(RoleError::EmptyContent);
    }
    Ok(LoadedRole {
        content: content.to_owned(),
        model: object
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Loads a role response according to its content type.
pub fn load_role_source(
    content_type: &str,
    body: &Value,
) -> Result<(RoleLoadOutcome, LoadedRole), RoleError> {
    let raw = match body {
        Value::String(text) => text.clone(),
        Value::Object(_) => {
            serde_json::to_string(body).map_err(|_| RoleError::InvalidSourceBody)?
        }
        _ => return Err(RoleError::InvalidSourceBody),
    };
    let explicit_json = content_type.to_ascii_lowercase().contains("json");
    if explicit_json || raw.trim_start().starts_with('{') {
        let parsed = match body {
            Value::Object(_) => load_role_value(body),
            Value::String(_) => load_role_json(&raw),
            _ => Err(RoleError::InvalidSourceBody),
        };
        match parsed {
            Ok(role) => return Ok((RoleLoadOutcome::LoadedJson, role)),
            Err(error) if explicit_json => return Err(error),
            Err(_) => {}
        }
    }
    Ok((
        RoleLoadOutcome::LoadedPlainText,
        LoadedRole {
            content: raw,
            model: None,
        },
    ))
}

/// Validated inert legacy skill definition.
#[derive(Clone, Debug, PartialEq)]
pub struct LegacySkill {
    /// Safe identifier.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Object or array parameter schema.
    pub parameters: Value,
    /// Inert JavaScript source. This crate never evaluates it.
    pub execute_code: String,
    /// Bridges recognized by lexical inspection.
    pub recognized_bridges: Vec<Bridge>,
}

/// Legacy skill schema failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacySkillError {
    /// Input is not valid JSON.
    InvalidJson,
    /// Name is absent, empty, or unsafe.
    InvalidName,
    /// Description is absent or empty.
    InvalidDescription,
    /// Parameters are not an object or array.
    InvalidParameters,
    /// `executeCode` is absent or empty.
    MissingExecuteCode,
}

impl Display for LegacySkillError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => formatter.write_str("legacy skill is not valid JSON"),
            Self::InvalidName => formatter.write_str("legacy skill name is unsafe"),
            Self::InvalidDescription => formatter.write_str("legacy skill description is empty"),
            Self::InvalidParameters => {
                formatter.write_str("legacy skill parameters must be an object or array")
            }
            Self::MissingExecuteCode => {
                formatter.write_str("legacy skill executeCode is missing or empty")
            }
        }
    }
}

impl Error for LegacySkillError {}

/// Parses a legacy skill without evaluating its JavaScript.
pub fn parse_legacy_skill(input: &str) -> Result<LegacySkill, LegacySkillError> {
    let value: Value = serde_json::from_str(input).map_err(|_| LegacySkillError::InvalidJson)?;
    let object = value.as_object().ok_or(LegacySkillError::InvalidJson)?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| valid_skill_name(name))
        .ok_or(LegacySkillError::InvalidName)?;
    let description = object
        .get("description")
        .and_then(Value::as_str)
        .filter(|description| !description.is_empty())
        .ok_or(LegacySkillError::InvalidDescription)?;
    let parameters = object
        .get("parameters")
        .filter(|parameters| parameters.is_object() || parameters.is_array())
        .ok_or(LegacySkillError::InvalidParameters)?;
    let execute_code = object
        .get("executeCode")
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty())
        .ok_or(LegacySkillError::MissingExecuteCode)?;
    Ok(LegacySkill {
        name: name.to_owned(),
        description: description.to_owned(),
        parameters: parameters.clone(),
        execute_code: execute_code.to_owned(),
        recognized_bridges: recognize_bridges(execute_code),
    })
}

fn valid_skill_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Lexically recognizes supported bridge names in inert source.
#[must_use]
pub fn recognize_bridges(source: &str) -> Vec<Bridge> {
    let mut bridges = Vec::new();
    for (needle, bridge) in [
        ("api.httpGet", Bridge::HttpGet),
        ("api.httpPost", Bridge::HttpPost),
        ("api.log", Bridge::Log),
    ] {
        if contains_bridge(source, needle) {
            bridges.push(bridge);
        }
    }
    bridges
}

fn contains_bridge(source: &str, needle: &str) -> bool {
    source.match_indices(needle).any(|(index, matched)| {
        let before = source[..index].chars().next_back();
        let after = source[index + matched.len()..].chars().next();
        !before.is_some_and(is_word_character) && !after.is_some_and(is_word_character)
    })
}

fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

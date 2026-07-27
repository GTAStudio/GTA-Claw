//! Typed ring-zero configuration mutation and durable Crestodian settings.
//!
//! Crestodian never edits configuration ad hoc. Every write names one field of
//! a closed table, is typed and bounded before it is accepted, and is refused
//! outright when the path would reach inference-route or credential-resolution
//! state. Secret material is never carried as a value: a secret field accepts
//! only a reference such as `env:OPENCLAW_GATEWAY_TOKEN`.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use claw_config::{CrestodianRescueConfig, RescueAuto, RescueEnabled, SecretRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Current durable ring-zero settings schema.
pub const CRESTODIAN_SETTINGS_SCHEMA_VERSION: u32 = 1;

/// Gateway port used until an operator changes it.
pub const DEFAULT_GATEWAY_PORT: u16 = 18789;

/// Inclusive bounds of an accepted TCP port.
const PORT_BOUNDS: (u64, u64) = (1, 65_535);

/// Inclusive bounds of an accepted pending-approval lifetime, in minutes.
const MINUTE_BOUNDS: (u64, u64) = (1, 1_440);

/// Longest configuration path this surface will look at.
const MAX_PATH_BYTES: usize = 128;

/// Longest attacker-chosen fragment echoed back into a rejection.
const MAX_ECHOED_BYTES: usize = 48;

/// Configuration roots that own the inference route powering the session.
const INFERENCE_ROUTE_ROOTS: &[&str] = &["agents", "auth", "cli", "models", "tools"];

/// Configuration roots that own credential resolution and provider activation.
const CREDENTIAL_ROOTS: &[&str] = &["$include", "env", "plugins", "secrets"];

/// Declared type of one writable configuration field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    /// TCP port in `1..=65535`.
    Port,
    /// Whole minutes in `1..=1440`.
    Minutes,
    /// Boolean flag.
    Boolean,
    /// Rescue enablement: `auto`, `true`, or `false`.
    RescueMode,
    /// Filesystem workspace path.
    Workspace,
    /// Secret reference, never a literal secret.
    SecretReference,
}

impl ValueType {
    /// Returns the stable operator-facing name of this type.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Minutes => "minutes",
            Self::Boolean => "boolean",
            Self::RescueMode => "rescue-mode",
            Self::Workspace => "workspace-path",
            Self::SecretReference => "secret-reference",
        }
    }
}

/// Closed set of configuration fields the ring-zero surface may write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationField {
    /// `crestodian.rescue.enabled`.
    RescueEnabled,
    /// `crestodian.rescue.ownerDmOnly`.
    RescueOwnerDmOnly,
    /// `crestodian.rescue.pendingTtlMinutes`.
    RescuePendingTtlMinutes,
    /// `gateway.auth.token`.
    GatewayAuthToken,
    /// `gateway.port`.
    GatewayPort,
    /// `workspace`.
    Workspace,
}

impl MutationField {
    /// Every writable field, in stable path order.
    pub const ALL: [Self; 6] = [
        Self::RescueEnabled,
        Self::RescueOwnerDmOnly,
        Self::RescuePendingTtlMinutes,
        Self::GatewayAuthToken,
        Self::GatewayPort,
        Self::Workspace,
    ];

    /// Returns the canonical configuration path of this field.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::RescueEnabled => "crestodian.rescue.enabled",
            Self::RescueOwnerDmOnly => "crestodian.rescue.ownerDmOnly",
            Self::RescuePendingTtlMinutes => "crestodian.rescue.pendingTtlMinutes",
            Self::GatewayAuthToken => "gateway.auth.token",
            Self::GatewayPort => "gateway.port",
            Self::Workspace => "workspace",
        }
    }

    /// Returns the declared value type of this field.
    #[must_use]
    pub const fn value_type(self) -> ValueType {
        match self {
            Self::RescueEnabled => ValueType::RescueMode,
            Self::RescueOwnerDmOnly => ValueType::Boolean,
            Self::RescuePendingTtlMinutes => ValueType::Minutes,
            Self::GatewayAuthToken => ValueType::SecretReference,
            Self::GatewayPort => ValueType::Port,
            Self::Workspace => ValueType::Workspace,
        }
    }

    /// Resolves a caller-supplied path against the closed writable table.
    ///
    /// Malformed syntax, credential-resolution roots and inference-route roots
    /// are each refused with their own reason before the table is consulted, so
    /// a refusal never depends on whether a forbidden path happens to be known.
    pub fn parse(path: &str) -> Result<Self, MutationRejection> {
        validate_path_syntax(path)?;
        let root = path.split('.').next().unwrap_or(path);
        if CREDENTIAL_ROOTS.contains(&root) {
            return Err(MutationRejection::CredentialResolution {
                path: sanitize(path),
            });
        }
        if INFERENCE_ROUTE_ROOTS.contains(&root) {
            return Err(MutationRejection::InferenceRoute {
                path: sanitize(path),
            });
        }
        Self::ALL
            .into_iter()
            .find(|field| field.path() == path)
            .ok_or_else(|| MutationRejection::UnknownPath {
                path: sanitize(path),
            })
    }
}

/// One accepted, fully typed configuration mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedMutation {
    /// New rescue enablement gate.
    RescueEnabled(RescueEnabled),
    /// New owner-direct-message restriction.
    RescueOwnerDmOnly(bool),
    /// New pending-approval lifetime, in minutes.
    RescuePendingTtlMinutes(u16),
    /// New gateway authentication secret reference.
    GatewayAuthToken(SecretRef),
    /// New gateway listener port.
    GatewayPort(u16),
    /// New configured workspace.
    Workspace(PathBuf),
}

impl TypedMutation {
    /// Builds a mutation from a JSON value, refusing coercion of any kind.
    pub fn set_json(path: &str, value: &Value) -> Result<Self, MutationRejection> {
        let field = MutationField::parse(path)?;
        match field {
            MutationField::GatewayAuthToken => {
                Err(MutationRejection::SecretRequiresReference { path: field.path() })
            }
            MutationField::GatewayPort => {
                let port = bounded(field, json_integer(field, value)?, PORT_BOUNDS)?;
                Ok(Self::GatewayPort(port))
            }
            MutationField::RescuePendingTtlMinutes => {
                let minutes = bounded(field, json_integer(field, value)?, MINUTE_BOUNDS)?;
                Ok(Self::RescuePendingTtlMinutes(minutes))
            }
            MutationField::RescueOwnerDmOnly => {
                let flag = value
                    .as_bool()
                    .ok_or_else(|| MutationRejection::TypeMismatch {
                        path: field.path(),
                        expected: "boolean",
                        found: json_shape(value),
                    })?;
                Ok(Self::RescueOwnerDmOnly(flag))
            }
            MutationField::RescueEnabled => match value {
                Value::Bool(flag) => Ok(Self::RescueEnabled(RescueEnabled::Explicit(*flag))),
                Value::String(text) if text == "auto" => {
                    Ok(Self::RescueEnabled(RescueEnabled::Auto(RescueAuto::Auto)))
                }
                other => Err(MutationRejection::TypeMismatch {
                    path: field.path(),
                    expected: "boolean or \"auto\"",
                    found: json_shape(other),
                }),
            },
            MutationField::Workspace => {
                let text = value
                    .as_str()
                    .ok_or_else(|| MutationRejection::TypeMismatch {
                        path: field.path(),
                        expected: "string",
                        found: json_shape(value),
                    })?;
                Ok(Self::Workspace(workspace(field, text)?))
            }
        }
    }

    /// Builds a mutation from one rescue-grammar token, refusing coercion.
    pub fn set_text(path: &str, value: &str) -> Result<Self, MutationRejection> {
        let field = MutationField::parse(path)?;
        match field {
            MutationField::GatewayAuthToken => {
                Err(MutationRejection::SecretRequiresReference { path: field.path() })
            }
            MutationField::GatewayPort => {
                let port = bounded(field, text_integer(field, value)?, PORT_BOUNDS)?;
                Ok(Self::GatewayPort(port))
            }
            MutationField::RescuePendingTtlMinutes => {
                let minutes = bounded(field, text_integer(field, value)?, MINUTE_BOUNDS)?;
                Ok(Self::RescuePendingTtlMinutes(minutes))
            }
            MutationField::RescueOwnerDmOnly => match value {
                "true" => Ok(Self::RescueOwnerDmOnly(true)),
                "false" => Ok(Self::RescueOwnerDmOnly(false)),
                other => Err(MutationRejection::TypeMismatch {
                    path: field.path(),
                    expected: "true or false",
                    found: text_shape(other),
                }),
            },
            MutationField::RescueEnabled => match value {
                "auto" => Ok(Self::RescueEnabled(RescueEnabled::Auto(RescueAuto::Auto))),
                "true" => Ok(Self::RescueEnabled(RescueEnabled::Explicit(true))),
                "false" => Ok(Self::RescueEnabled(RescueEnabled::Explicit(false))),
                other => Err(MutationRejection::TypeMismatch {
                    path: field.path(),
                    expected: "auto, true, or false",
                    found: text_shape(other),
                }),
            },
            MutationField::Workspace => Ok(Self::Workspace(workspace(field, value)?)),
        }
    }

    /// Builds a secret-reference mutation, the only way to write a secret field.
    pub fn set_reference(path: &str, source: &str, name: &str) -> Result<Self, MutationRejection> {
        let field = MutationField::parse(path)?;
        if field.value_type() != ValueType::SecretReference {
            return Err(MutationRejection::NotASecretPath { path: field.path() });
        }
        if source != "env" {
            return Err(MutationRejection::UnsupportedSecretSource {
                source: sanitize(source),
            });
        }
        let reference = SecretRef::environment(name).map_err(|message| {
            MutationRejection::InvalidSecretReference {
                path: field.path(),
                message,
            }
        })?;
        match field {
            MutationField::GatewayAuthToken => Ok(Self::GatewayAuthToken(reference)),
            MutationField::RescueEnabled
            | MutationField::RescueOwnerDmOnly
            | MutationField::RescuePendingTtlMinutes
            | MutationField::GatewayPort
            | MutationField::Workspace => {
                Err(MutationRejection::NotASecretPath { path: field.path() })
            }
        }
    }

    /// Returns the field this mutation writes.
    #[must_use]
    pub const fn field(&self) -> MutationField {
        match self {
            Self::RescueEnabled(_) => MutationField::RescueEnabled,
            Self::RescueOwnerDmOnly(_) => MutationField::RescueOwnerDmOnly,
            Self::RescuePendingTtlMinutes(_) => MutationField::RescuePendingTtlMinutes,
            Self::GatewayAuthToken(_) => MutationField::GatewayAuthToken,
            Self::GatewayPort(_) => MutationField::GatewayPort,
            Self::Workspace(_) => MutationField::Workspace,
        }
    }

    /// Returns the canonical configuration path this mutation writes.
    #[must_use]
    pub const fn path(&self) -> &'static str {
        self.field().path()
    }

    /// Whether this mutation writes a field that carries secret material.
    #[must_use]
    pub const fn sensitive(&self) -> bool {
        matches!(self.field().value_type(), ValueType::SecretReference)
    }

    /// Renders the approval proposal.
    ///
    /// A secret field renders its reference, so no proposal, transcript, or
    /// model-visible history can ever contain the referenced secret.
    #[must_use]
    pub fn proposal(&self) -> String {
        let path = self.path();
        match self {
            Self::RescueEnabled(RescueEnabled::Auto(RescueAuto::Auto)) => {
                format!("set {path} = auto")
            }
            Self::RescueEnabled(RescueEnabled::Explicit(flag)) => format!("set {path} = {flag}"),
            Self::RescueOwnerDmOnly(flag) => format!("set {path} = {flag}"),
            Self::RescuePendingTtlMinutes(minutes) => format!("set {path} = {minutes}"),
            Self::GatewayPort(port) => format!("set {path} = {port}"),
            Self::Workspace(workspace) => format!("set {path} = {}", workspace.display()),
            Self::GatewayAuthToken(reference) => {
                format!("set-ref {path} = {}", reference.as_str())
            }
        }
    }

    /// Returns the metadata-only audit label, never the mutated value.
    #[must_use]
    pub fn audit_label(&self) -> String {
        let verb = if self.sensitive() {
            "config_set_ref"
        } else {
            "config_set"
        };
        format!("{verb}:{}", self.path())
    }
}

/// Refusal from the typed mutation surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationRejection {
    /// The path is not a syntactically valid configuration path.
    MalformedPath {
        /// Sanitized rejected path.
        path: String,
        /// Syntax diagnostic.
        message: &'static str,
    },
    /// The path owns the inference route powering the session.
    InferenceRoute {
        /// Sanitized rejected path.
        path: String,
    },
    /// The path owns credential resolution or provider activation.
    CredentialResolution {
        /// Sanitized rejected path.
        path: String,
    },
    /// The path is well formed but not ring-zero writable.
    UnknownPath {
        /// Sanitized rejected path.
        path: String,
    },
    /// The supplied value has the wrong declared type or shape.
    TypeMismatch {
        /// Canonical path.
        path: &'static str,
        /// Declared type or accepted spelling.
        expected: &'static str,
        /// Shape actually supplied.
        found: &'static str,
    },
    /// The supplied value is outside the declared inclusive bounds.
    OutOfRange {
        /// Canonical path.
        path: &'static str,
        /// Inclusive minimum.
        minimum: u64,
        /// Inclusive maximum.
        maximum: u64,
        /// Value actually supplied.
        found: u64,
    },
    /// A secret field was given a literal value instead of a reference.
    SecretRequiresReference {
        /// Canonical path.
        path: &'static str,
    },
    /// A non-secret field was given a secret reference.
    NotASecretPath {
        /// Canonical path.
        path: &'static str,
    },
    /// The secret source is not supported.
    UnsupportedSecretSource {
        /// Sanitized rejected source.
        source: String,
    },
    /// The environment reference is not a valid variable name.
    InvalidSecretReference {
        /// Canonical path.
        path: &'static str,
        /// Reference diagnostic.
        message: &'static str,
    },
}

impl Display for MutationRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedPath { path, message } => {
                write!(formatter, "configuration path {path:?} {message}")
            }
            Self::InferenceRoute { path } => write!(
                formatter,
                "configuration path {path:?} owns the inference route and cannot be written by Crestodian; run openclaw onboard"
            ),
            Self::CredentialResolution { path } => write!(
                formatter,
                "configuration path {path:?} owns credential resolution and cannot be written by Crestodian"
            ),
            Self::UnknownPath { path } => write!(
                formatter,
                "configuration path {path:?} is not ring-zero writable"
            ),
            Self::TypeMismatch {
                path,
                expected,
                found,
            } => write!(
                formatter,
                "configuration path {path} expects {expected}, but received {found}"
            ),
            Self::OutOfRange {
                path,
                minimum,
                maximum,
                found,
            } => write!(
                formatter,
                "configuration path {path} accepts {minimum}..={maximum}, but received {found}"
            ),
            Self::SecretRequiresReference { path } => write!(
                formatter,
                "configuration path {path} holds secret material; use config set-ref {path} env <NAME>"
            ),
            Self::NotASecretPath { path } => write!(
                formatter,
                "configuration path {path} holds no secret material and takes a literal value"
            ),
            Self::UnsupportedSecretSource { source } => write!(
                formatter,
                "secret source {source:?} is unsupported; only env is accepted"
            ),
            Self::InvalidSecretReference { path, message } => {
                write!(formatter, "configuration path {path}: {message}")
            }
        }
    }
}

impl Error for MutationRejection {}

/// SHA-256 digest of the canonical durable settings bytes.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigDigest(String);

impl ConfigDigest {
    /// Returns the lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ConfigDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Configuration digests recorded on both sides of an applied mutation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ConfigDigestChange {
    /// Digest before the mutation was applied.
    pub before: ConfigDigest,
    /// Digest after the mutation was applied.
    pub after: ConfigDigest,
}

/// Durable, non-secret ring-zero settings owned by Crestodian.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CrestodianSettings {
    /// Settings schema version.
    pub schema_version: u32,
    /// Gateway listener port.
    pub gateway_port: u16,
    /// Gateway authentication secret reference, never a literal secret.
    pub gateway_auth_token: Option<String>,
    /// Remote rescue policy.
    pub rescue: CrestodianRescueConfig,
    /// Configured workspace.
    pub workspace: Option<PathBuf>,
}

impl Default for CrestodianSettings {
    fn default() -> Self {
        Self {
            schema_version: CRESTODIAN_SETTINGS_SCHEMA_VERSION,
            gateway_port: DEFAULT_GATEWAY_PORT,
            gateway_auth_token: None,
            rescue: CrestodianRescueConfig::default(),
            workspace: None,
        }
    }
}

impl CrestodianSettings {
    /// Applies one already-typed mutation.
    pub fn apply(&mut self, mutation: &TypedMutation) {
        match mutation {
            TypedMutation::RescueEnabled(enabled) => self.rescue.enabled = *enabled,
            TypedMutation::RescueOwnerDmOnly(flag) => self.rescue.owner_dm_only = *flag,
            TypedMutation::RescuePendingTtlMinutes(minutes) => {
                self.rescue.pending_ttl_minutes = *minutes;
            }
            TypedMutation::GatewayAuthToken(reference) => {
                self.gateway_auth_token = Some(reference.as_str().to_owned());
            }
            TypedMutation::GatewayPort(port) => self.gateway_port = *port,
            TypedMutation::Workspace(workspace) => self.workspace = Some(workspace.clone()),
        }
    }

    /// Re-validates settings that arrived from durable storage.
    ///
    /// Bounds are re-checked rather than trusted, because a settings file can
    /// be edited by hand between two runs of the gateway.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != CRESTODIAN_SETTINGS_SCHEMA_VERSION {
            return Err(format!(
                "unsupported settings schema version {} (supported {CRESTODIAN_SETTINGS_SCHEMA_VERSION})",
                self.schema_version
            ));
        }
        if self.gateway_port == 0 {
            return Err("gateway.port accepts 1..=65535, but received 0".to_owned());
        }
        let minutes = u64::from(self.rescue.pending_ttl_minutes);
        if minutes < MINUTE_BOUNDS.0 || minutes > MINUTE_BOUNDS.1 {
            return Err(format!(
                "crestodian.rescue.pendingTtlMinutes accepts {}..={}, but received {minutes}",
                MINUTE_BOUNDS.0, MINUTE_BOUNDS.1
            ));
        }
        if let Some(reference) = &self.gateway_auth_token
            && let Err(message) = SecretRef::parse(reference.clone())
        {
            return Err(format!("gateway.auth.token: {message}"));
        }
        Ok(())
    }

    /// Returns the canonical serialized bytes of these settings.
    ///
    /// Serialization fails only for a workspace that is not valid UTF-8, which
    /// no accepted mutation can produce.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Returns the SHA-256 digest of the canonical settings encoding.
    pub fn digest(&self) -> Result<ConfigDigest, String> {
        Ok(ConfigDigest(encode_hex(&Sha256::digest(self.to_bytes()?))))
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn validate_path_syntax(path: &str) -> Result<(), MutationRejection> {
    let reject = |message: &'static str| MutationRejection::MalformedPath {
        path: sanitize(path),
        message,
    };
    if path.is_empty() {
        return Err(reject("must not be empty"));
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(reject("must not exceed 128 bytes"));
    }
    for segment in path.split('.') {
        if segment.is_empty() {
            return Err(reject("must not contain an empty segment"));
        }
        if !segment.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '$')
        }) {
            return Err(reject("accepts only [A-Za-z0-9_$-] inside a segment"));
        }
    }
    Ok(())
}

fn json_integer(field: MutationField, value: &Value) -> Result<u64, MutationRejection> {
    value
        .as_u64()
        .ok_or_else(|| MutationRejection::TypeMismatch {
            path: field.path(),
            expected: "non-negative integer",
            found: json_shape(value),
        })
}

fn text_integer(field: MutationField, value: &str) -> Result<u64, MutationRejection> {
    value
        .parse::<u64>()
        .map_err(|_| MutationRejection::TypeMismatch {
            path: field.path(),
            expected: "non-negative integer",
            found: text_shape(value),
        })
}

fn bounded(
    field: MutationField,
    value: u64,
    (minimum, maximum): (u64, u64),
) -> Result<u16, MutationRejection> {
    if value < minimum || value > maximum {
        return Err(MutationRejection::OutOfRange {
            path: field.path(),
            minimum,
            maximum,
            found: value,
        });
    }
    u16::try_from(value).map_err(|_| MutationRejection::OutOfRange {
        path: field.path(),
        minimum,
        maximum,
        found: value,
    })
}

fn workspace(field: MutationField, value: &str) -> Result<PathBuf, MutationRejection> {
    if value.is_empty() {
        return Err(MutationRejection::TypeMismatch {
            path: field.path(),
            expected: "non-empty workspace path",
            found: "empty text",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(MutationRejection::TypeMismatch {
            path: field.path(),
            expected: "workspace path without control characters",
            found: "control characters",
        });
    }
    Ok(PathBuf::from(value))
}

/// Names the JSON shape of a value without revealing any of its content.
const fn json_shape(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Names the shape of a grammar token without revealing its content.
const fn text_shape(value: &str) -> &'static str {
    if value.is_empty() {
        "empty text"
    } else {
        "text"
    }
}

/// Keeps an attacker-chosen fragment out of a diagnostic verbatim.
fn sanitize(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '$')
        })
        .take(MAX_ECHOED_BYTES)
        .collect();
    if sanitized.is_empty() {
        "<unprintable>".to_owned()
    } else {
        sanitized
    }
}

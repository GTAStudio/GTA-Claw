//! The plugin manifest: the operator-facing declaration that accompanies every
//! component.
//!
//! A manifest is strict JSON (`deny_unknown_fields` everywhere) and is fully
//! validated before the component bytes are even read. Nothing in a manifest
//! grants anything by itself: the manifest *declares* what a plugin needs, and
//! `claw-plugin-host` intersects that declaration with the operator's grant set
//! and the [`crate::trust::TrustPolicy`].

use core::fmt;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::abi::{
    ABI_VERSION, AbiIncompatibility, Version, VersionParseError, check_compatibility,
};
use crate::capability::{Capability, CapabilityGrant, CapabilitySetError, validate_relative_path};
use crate::limits::{LimitsError, ResourceLimits};
use crate::registry::DeliveryClass;

/// The only manifest schema version this host understands.
pub const MANIFEST_VERSION: u32 = 1;

/// Longest accepted plugin id.
pub const MAX_ID_LEN: usize = 64;

/// Signature algorithms the manifest format can express.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    /// Pure Ed25519 over the canonical signing payload
    /// (see [`crate::trust::signing_payload`]).
    Ed25519,
}

/// A detached signature over the manifest's component binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    /// Algorithm used to produce [`ManifestSignature::value`].
    pub algorithm: SignatureAlgorithm,
    /// Opaque identifier of the public key, resolved through the trust policy.
    pub key_id: String,
    /// Lowercase hex encoding of the raw signature bytes.
    pub value: String,
}

/// Where the component lives relative to the manifest, and what it must hash to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentRef {
    /// Relative, `/`-separated path to the `.wasm` component.
    pub path: String,
    /// Lowercase hex SHA-256 of the component bytes.
    pub sha256: String,
    /// Exact component size in bytes.
    pub size_bytes: u64,
}

/// A validated plugin manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    /// Schema version; must equal [`MANIFEST_VERSION`].
    pub manifest_version: u32,
    /// Plugin id, unique within a host.
    pub id: String,
    /// Human-readable name.
    pub display_name: String,
    /// One-paragraph description.
    pub description: String,
    /// Plugin version.
    pub version: String,
    /// ABI version the component was built against.
    pub abi_version: String,
    /// How the plugin is delivered, mirroring the frozen upstream inventory.
    pub delivery_class: DeliveryClass,
    /// The component binding.
    pub component: ComponentRef,
    /// Capabilities the plugin asks for, with the scope it asks for.
    pub capabilities: Vec<CapabilityGrant>,
    /// Resource envelope; defaults are used when omitted.
    #[serde(default)]
    pub limits: ResourceLimits,
    /// Optional detached signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ManifestSignature>,
}

impl PluginManifest {
    /// Parses and validates a manifest from JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Json`] for malformed JSON and the matching
    /// validation variant for a well-formed but invalid manifest.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let manifest: Self =
            serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
                ManifestError::Json {
                    path: error.path().to_string(),
                    message: error.into_inner().to_string(),
                }
            })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// The parsed plugin version.
    ///
    /// # Errors
    ///
    /// Returns [`VersionParseError`] when the stored string is not a strict
    /// triple. [`PluginManifest::validate`] rules this out.
    pub fn parsed_version(&self) -> Result<Version, VersionParseError> {
        Version::parse(&self.version)
    }

    /// The parsed ABI version.
    ///
    /// # Errors
    ///
    /// Returns [`VersionParseError`] when the stored string is not a strict
    /// triple. [`PluginManifest::validate`] rules this out.
    pub fn parsed_abi_version(&self) -> Result<Version, VersionParseError> {
        Version::parse(&self.abi_version)
    }

    /// The capabilities the manifest declares, deduplicated and sorted.
    #[must_use]
    pub fn declared_capabilities(&self) -> BTreeSet<Capability> {
        self.capabilities
            .iter()
            .map(CapabilityGrant::capability)
            .collect()
    }

    /// Validates every field of an already-deserialised manifest.
    ///
    /// # Errors
    ///
    /// Returns the first [`ManifestError`] encountered.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.manifest_version != MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedManifestVersion {
                found: self.manifest_version,
            });
        }
        validate_id(&self.id)?;
        if self.display_name.trim().is_empty() {
            return Err(ManifestError::EmptyField {
                field: "display_name",
            });
        }
        if self.description.trim().is_empty() {
            return Err(ManifestError::EmptyField {
                field: "description",
            });
        }
        Version::parse(&self.version).map_err(|error| ManifestError::InvalidVersion {
            field: "version",
            error,
        })?;
        let abi =
            Version::parse(&self.abi_version).map_err(|error| ManifestError::InvalidVersion {
                field: "abi_version",
                error,
            })?;
        check_compatibility(ABI_VERSION, abi).map_err(ManifestError::AbiIncompatible)?;
        self.validate_component()?;
        self.validate_capabilities()?;
        self.limits.validate().map_err(ManifestError::Limits)?;
        if self.component.size_bytes > self.limits.max_component_bytes {
            return Err(ManifestError::ComponentTooLarge {
                size_bytes: self.component.size_bytes,
                max_component_bytes: self.limits.max_component_bytes,
            });
        }
        self.validate_signature()?;
        Ok(())
    }

    fn validate_component(&self) -> Result<(), ManifestError> {
        let relative = validate_relative_path(&self.component.path).map_err(|reason| {
            ManifestError::ComponentPath {
                path: self.component.path.clone(),
                reason,
            }
        })?;
        if relative.extension().and_then(|ext| ext.to_str()) != Some("wasm") {
            return Err(ManifestError::ComponentPath {
                path: self.component.path.clone(),
                reason: "component path must end in `.wasm`".to_owned(),
            });
        }
        if !is_lowercase_hex(&self.component.sha256, 64) {
            return Err(ManifestError::ComponentDigest {
                digest: self.component.sha256.clone(),
            });
        }
        if self.component.size_bytes == 0 {
            return Err(ManifestError::EmptyComponent);
        }
        Ok(())
    }

    fn validate_capabilities(&self) -> Result<(), ManifestError> {
        let mut seen = BTreeSet::new();
        for grant in &self.capabilities {
            grant
                .validate()
                .map_err(|error| ManifestError::Capability(CapabilitySetError::Grant(error)))?;
            if !seen.insert(grant.capability()) {
                return Err(ManifestError::Capability(CapabilitySetError::Duplicate(
                    grant.capability(),
                )));
            }
        }
        Ok(())
    }

    fn validate_signature(&self) -> Result<(), ManifestError> {
        let Some(signature) = &self.signature else {
            return Ok(());
        };
        if signature.key_id.is_empty() || signature.key_id.len() > 128 {
            return Err(ManifestError::SignatureKeyId {
                key_id: signature.key_id.clone(),
            });
        }
        if !signature
            .key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(ManifestError::SignatureKeyId {
                key_id: signature.key_id.clone(),
            });
        }
        let expected_len = match signature.algorithm {
            SignatureAlgorithm::Ed25519 => 128,
        };
        if !is_lowercase_hex(&signature.value, expected_len) {
            return Err(ManifestError::SignatureEncoding {
                algorithm: signature.algorithm,
                expected_hex_len: expected_len,
                found_len: signature.value.len(),
            });
        }
        Ok(())
    }
}

fn validate_id(id: &str) -> Result<(), ManifestError> {
    let invalid = |reason: &str| ManifestError::InvalidId {
        id: id.to_owned(),
        reason: reason.to_owned(),
    };
    if id.is_empty() {
        return Err(invalid("id must not be empty"));
    }
    if id.len() > MAX_ID_LEN {
        return Err(invalid("id is longer than 64 bytes"));
    }
    if id.starts_with('-') || id.ends_with('-') {
        return Err(invalid("id must not start or end with `-`"));
    }
    if id.contains("--") {
        return Err(invalid("id must not contain consecutive `-`"));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid(
            "id may only contain lowercase ASCII letters, digits and `-`",
        ));
    }
    Ok(())
}

fn is_lowercase_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why a manifest was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestError {
    /// The document was not valid JSON for this schema.
    Json {
        /// JSON path of the offending value.
        path: String,
        /// Underlying serde message.
        message: String,
    },
    /// `manifest_version` was not [`MANIFEST_VERSION`].
    UnsupportedManifestVersion {
        /// The version found in the document.
        found: u32,
    },
    /// `id` violated the naming rules.
    InvalidId {
        /// The rejected id.
        id: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A required string field was blank.
    EmptyField {
        /// The blank field.
        field: &'static str,
    },
    /// A version field was not a strict triple.
    InvalidVersion {
        /// The offending field.
        field: &'static str,
        /// Underlying parse error.
        error: VersionParseError,
    },
    /// The component targets an ABI this host cannot run.
    AbiIncompatible(AbiIncompatibility),
    /// `component.path` was unusable.
    ComponentPath {
        /// The rejected path.
        path: String,
        /// Why it was rejected.
        reason: String,
    },
    /// `component.sha256` was not 64 lowercase hex characters.
    ComponentDigest {
        /// The rejected digest.
        digest: String,
    },
    /// `component.size_bytes` was zero.
    EmptyComponent,
    /// `component.size_bytes` exceeded `limits.max_component_bytes`.
    ComponentTooLarge {
        /// Declared component size.
        size_bytes: u64,
        /// Configured ceiling.
        max_component_bytes: u64,
    },
    /// A capability declaration was invalid or duplicated.
    Capability(CapabilitySetError),
    /// A resource limit was out of range.
    Limits(LimitsError),
    /// `signature.key_id` was unusable.
    SignatureKeyId {
        /// The rejected key id.
        key_id: String,
    },
    /// `signature.value` was not the expected hex encoding.
    SignatureEncoding {
        /// The declared algorithm.
        algorithm: SignatureAlgorithm,
        /// Number of hex characters the algorithm requires.
        expected_hex_len: usize,
        /// Number of characters found.
        found_len: usize,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json { path, message } => {
                write!(f, "manifest JSON at `{path}` is invalid: {message}")
            }
            Self::UnsupportedManifestVersion { found } => write!(
                f,
                "manifest_version {found} is not supported; expected {MANIFEST_VERSION}"
            ),
            Self::InvalidId { id, reason } => write!(f, "plugin id `{id}` is invalid: {reason}"),
            Self::EmptyField { field } => write!(f, "manifest field `{field}` must not be blank"),
            Self::InvalidVersion { field, error } => {
                write!(f, "manifest field `{field}` is invalid: {error}")
            }
            Self::AbiIncompatible(error) => write!(f, "manifest ABI is incompatible: {error}"),
            Self::ComponentPath { path, reason } => {
                write!(f, "component path `{path}` is invalid: {reason}")
            }
            Self::ComponentDigest { digest } => write!(
                f,
                "component sha256 `{digest}` must be 64 lowercase hex characters"
            ),
            Self::EmptyComponent => f.write_str("component size_bytes must be positive"),
            Self::ComponentTooLarge {
                size_bytes,
                max_component_bytes,
            } => write!(
                f,
                "component is {size_bytes} bytes, above the {max_component_bytes} byte ceiling"
            ),
            Self::Capability(error) => write!(f, "capability declaration is invalid: {error}"),
            Self::Limits(error) => error.fmt(f),
            Self::SignatureKeyId { key_id } => write!(f, "signature key_id `{key_id}` is invalid"),
            Self::SignatureEncoding {
                algorithm,
                expected_hex_len,
                found_len,
            } => write!(
                f,
                "signature for {algorithm:?} must be {expected_hex_len} lowercase hex characters, found {found_len}"
            ),
        }
    }
}

impl core::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::InvalidVersion { error, .. } => Some(error),
            Self::AbiIncompatible(error) => Some(error),
            Self::Capability(error) => Some(error),
            Self::Limits(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{ManifestError, PluginManifest, SignatureAlgorithm};
    use crate::abi::AbiIncompatibility;
    use crate::capability::{Capability, CapabilitySetError};
    use crate::registry::DeliveryClass;

    fn manifest_json() -> Value {
        json!({
            "manifest_version": 1,
            "id": "example-plugin",
            "display_name": "Example plugin",
            "description": "A manifest used by the claw-plugin-api unit tests.",
            "version": "0.3.1",
            "abi_version": "1.0.0",
            "delivery_class": "core",
            "component": {
                "path": "component/example.wasm",
                "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "size_bytes": 2048
            },
            "capabilities": [
                { "capability": "log", "min_level": "info", "max_message_bytes": 4096 },
                { "capability": "clock", "resolution_ms": 100 }
            ]
        })
    }

    fn parse(value: &Value) -> Result<PluginManifest, ManifestError> {
        PluginManifest::parse(serde_json::to_vec(value).expect("encode").as_slice())
    }

    #[test]
    fn a_well_formed_manifest_parses_with_defaults() {
        let manifest = parse(&manifest_json()).expect("valid manifest");
        assert_eq!(manifest.id, "example-plugin");
        assert_eq!(manifest.delivery_class, DeliveryClass::Core);
        assert_eq!(
            manifest.parsed_version().expect("version").to_string(),
            "0.3.1"
        );
        assert_eq!(manifest.limits, crate::limits::ResourceLimits::default());
        assert_eq!(manifest.signature, None);
        assert_eq!(
            manifest
                .declared_capabilities()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![Capability::Log, Capability::Clock]
        );
    }

    #[test]
    fn unknown_top_level_fields_are_rejected_with_their_path() {
        let mut value = manifest_json();
        value["extra"] = json!(true);
        let error = parse(&value).unwrap_err();
        match error {
            ManifestError::Json { path, message } => {
                assert_eq!(path, "extra");
                assert!(
                    message.starts_with("unknown field `extra`"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected a JSON error, got {other:?}"),
        }
    }

    #[test]
    fn a_nested_type_error_reports_its_json_path() {
        let mut value = manifest_json();
        value["component"]["size_bytes"] = json!("2048");
        let error = parse(&value).unwrap_err();
        match error {
            ManifestError::Json { path, .. } => assert_eq!(path, "component.size_bytes"),
            other => panic!("expected a JSON error, got {other:?}"),
        }
    }

    #[test]
    fn manifest_version_must_be_one() {
        let mut value = manifest_json();
        value["manifest_version"] = json!(2);
        assert_eq!(
            parse(&value).unwrap_err(),
            ManifestError::UnsupportedManifestVersion { found: 2 }
        );
    }

    #[test]
    fn plugin_ids_follow_the_upstream_naming_rules() {
        for (id, reason) in [
            ("", "id must not be empty"),
            ("-lead", "id must not start or end with `-`"),
            ("trail-", "id must not start or end with `-`"),
            ("double--dash", "id must not contain consecutive `-`"),
            (
                "Upper",
                "id may only contain lowercase ASCII letters, digits and `-`",
            ),
            (
                "under_score",
                "id may only contain lowercase ASCII letters, digits and `-`",
            ),
            (
                "space plugin",
                "id may only contain lowercase ASCII letters, digits and `-`",
            ),
        ] {
            let mut value = manifest_json();
            value["id"] = json!(id);
            assert_eq!(
                parse(&value).unwrap_err(),
                ManifestError::InvalidId {
                    id: id.to_owned(),
                    reason: reason.to_owned(),
                },
                "id `{id}`"
            );
        }
    }

    #[test]
    fn component_paths_may_not_escape_the_plugin_directory() {
        for (path, reason) in [
            (
                "../outside.wasm",
                "path must not contain `.` or `..` segments",
            ),
            ("/abs/plugin.wasm", "path must be relative"),
            ("C:/plugin.wasm", "path must not contain `:`"),
            ("dir\\plugin.wasm", "path must use `/` as its separator"),
        ] {
            let mut value = manifest_json();
            value["component"]["path"] = json!(path);
            assert_eq!(
                parse(&value).unwrap_err(),
                ManifestError::ComponentPath {
                    path: path.to_owned(),
                    reason: reason.to_owned(),
                },
                "path `{path}`"
            );
        }
    }

    #[test]
    fn the_component_must_be_a_wasm_file() {
        let mut value = manifest_json();
        value["component"]["path"] = json!("component/example.js");
        assert_eq!(
            parse(&value).unwrap_err(),
            ManifestError::ComponentPath {
                path: "component/example.js".to_owned(),
                reason: "component path must end in `.wasm`".to_owned(),
            }
        );
    }

    #[test]
    fn the_component_digest_must_be_lowercase_hex_of_the_right_length() {
        for digest in [
            "",
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefa",
            "zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            let mut value = manifest_json();
            value["component"]["sha256"] = json!(digest);
            assert_eq!(
                parse(&value).unwrap_err(),
                ManifestError::ComponentDigest {
                    digest: digest.to_owned()
                },
                "digest `{digest}`"
            );
        }
    }

    #[test]
    fn a_zero_byte_component_is_rejected() {
        let mut value = manifest_json();
        value["component"]["size_bytes"] = json!(0);
        assert_eq!(parse(&value).unwrap_err(), ManifestError::EmptyComponent);
    }

    #[test]
    fn a_component_above_the_ceiling_is_rejected() {
        let mut value = manifest_json();
        value["component"]["size_bytes"] = json!(4096);
        value["limits"] = serde_json::to_value(crate::limits::ResourceLimits {
            max_component_bytes: 1024,
            ..crate::limits::ResourceLimits::default()
        })
        .expect("encode limits");
        assert_eq!(
            parse(&value).unwrap_err(),
            ManifestError::ComponentTooLarge {
                size_bytes: 4096,
                max_component_bytes: 1024,
            }
        );
    }

    #[test]
    fn a_newer_abi_generation_is_rejected() {
        let mut value = manifest_json();
        value["abi_version"] = json!("2.0.0");
        assert_eq!(
            parse(&value).unwrap_err(),
            ManifestError::AbiIncompatible(AbiIncompatibility::MajorMismatch { host: 1, guest: 2 })
        );
    }

    #[test]
    fn a_newer_abi_revision_is_rejected() {
        let mut value = manifest_json();
        value["abi_version"] = json!("1.1.0");
        assert_eq!(
            parse(&value).unwrap_err(),
            ManifestError::AbiIncompatible(AbiIncompatibility::MinorTooNew { host: 0, guest: 1 })
        );
    }

    #[test]
    fn duplicate_capability_declarations_are_rejected() {
        let mut value = manifest_json();
        value["capabilities"] = json!([
            { "capability": "clock", "resolution_ms": 100 },
            { "capability": "clock", "resolution_ms": 250 }
        ]);
        assert_eq!(
            parse(&value).unwrap_err(),
            ManifestError::Capability(CapabilitySetError::Duplicate(Capability::Clock))
        );
    }

    #[test]
    fn an_invalid_capability_scope_is_rejected() {
        let mut value = manifest_json();
        value["capabilities"] = json!([
            { "capability": "filesystem-read", "roots": ["relative/root"], "max_file_bytes": 16 }
        ]);
        let error = parse(&value).unwrap_err();
        match error {
            ManifestError::Capability(CapabilitySetError::Grant(grant)) => {
                assert_eq!(grant.capability(), Capability::FilesystemRead);
                assert_eq!(grant.reason(), "every root must be absolute");
            }
            other => panic!("expected a grant error, got {other:?}"),
        }
    }

    #[test]
    fn an_out_of_range_limit_is_rejected() {
        let mut value = manifest_json();
        value["limits"] = serde_json::to_value(crate::limits::ResourceLimits {
            fuel: 0,
            ..crate::limits::ResourceLimits::default()
        })
        .expect("encode limits");
        let error = parse(&value).unwrap_err();
        match error {
            ManifestError::Limits(limits) => {
                assert_eq!(limits.field(), "fuel");
                assert_eq!(limits.reason(), "must be positive");
            }
            other => panic!("expected a limits error, got {other:?}"),
        }
    }

    #[test]
    fn a_signature_must_be_128_lowercase_hex_characters() {
        let mut value = manifest_json();
        value["signature"] = json!({
            "algorithm": "ed25519",
            "key_id": "release-2026",
            "value": "abcdef"
        });
        assert_eq!(
            parse(&value).unwrap_err(),
            ManifestError::SignatureEncoding {
                algorithm: SignatureAlgorithm::Ed25519,
                expected_hex_len: 128,
                found_len: 6,
            }
        );
    }

    #[test]
    fn a_well_formed_signature_is_accepted_and_round_trips() {
        let mut value = manifest_json();
        value["signature"] = json!({
            "algorithm": "ed25519",
            "key_id": "release-2026",
            "value": "ab".repeat(64)
        });
        let manifest = parse(&value).expect("valid manifest");
        let signature = manifest.signature.clone().expect("signature present");
        assert_eq!(signature.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(signature.key_id, "release-2026");

        let reencoded = serde_json::to_vec(&manifest).expect("encode");
        let reparsed = PluginManifest::parse(&reencoded).expect("re-parse");
        assert_eq!(reparsed, manifest);
    }

    #[test]
    fn a_signature_key_id_may_not_contain_separators() {
        let mut value = manifest_json();
        value["signature"] = json!({
            "algorithm": "ed25519",
            "key_id": "release/2026",
            "value": "ab".repeat(64)
        });
        assert_eq!(
            parse(&value).unwrap_err(),
            ManifestError::SignatureKeyId {
                key_id: "release/2026".to_owned()
            }
        );
    }
}

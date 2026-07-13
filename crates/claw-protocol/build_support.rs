//! Build-time validation for the externally pinned Gateway registry source.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write as _;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) const EXPECTED_BASELINE_SHA: &str = "b43e832fcc8000ed7287c7accc54e381db607f85";
pub(crate) const EXPECTED_SOURCE_SHA256: &str =
    "0ca2cf58f1a924095c1fee0af5765b61871b35d590dfb2932d459c4ca8a71996";
pub(crate) const EXPECTED_CANONICAL_SHA256: &str =
    "69c16fe2d025241e21e6c1dd1a92c7586af5cbcb26f02771b3a16b5f09cff9c9";
pub(crate) const EXPECTED_TOTAL: usize = 320;
pub(crate) const EXPECTED_METHODS: usize = 278;
pub(crate) const EXPECTED_ADVERTISED_METHODS: usize = 258;
pub(crate) const EXPECTED_EVENTS: usize = 33;
pub(crate) const EXPECTED_ROLES: usize = 3;
pub(crate) const EXPECTED_SCOPES: usize = 6;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inventory {
    pub(crate) schema_version: u8,
    pub(crate) inventory_id: String,
    pub(crate) classification: String,
    pub(crate) baseline_sha: String,
    pub(crate) counts: Counts,
    pub(crate) items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Counts {
    pub(crate) total: usize,
    pub(crate) methods: usize,
    pub(crate) advertised_methods: usize,
    pub(crate) events: usize,
    pub(crate) roles: usize,
    pub(crate) scopes: usize,
    pub(crate) dynamic_plugin_methods: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Item {
    pub(crate) record_id: String,
    pub(crate) id: String,
    pub(crate) classification: String,
    pub(crate) source_path: String,
    pub(crate) kind: String,
    pub(crate) scope: Option<String>,
    pub(crate) advertised: Option<bool>,
    pub(crate) protocol_class: Option<String>,
}

pub(crate) fn load_and_validate_registry(path: &Path) -> Result<Inventory, RegistrySourceError> {
    let source = fs::read(path).map_err(|source| RegistrySourceError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    validate_registry_bytes(&source)
}

pub(crate) fn validate_registry_bytes(source: &[u8]) -> Result<Inventory, RegistrySourceError> {
    let normalized_source = normalize_line_endings(source);
    let source_digest = sha256_hex(&normalized_source);
    if source_digest != EXPECTED_SOURCE_SHA256 {
        return Err(RegistrySourceError::SourceDigest {
            expected: EXPECTED_SOURCE_SHA256,
            actual: source_digest,
        });
    }

    let source = normalized_source
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(&normalized_source);
    let inventory: Inventory = serde_json::from_slice(source).map_err(RegistrySourceError::Json)?;
    validate_contract(&inventory)?;

    let canonical_digest = canonical_digest(&inventory)?;
    if canonical_digest != EXPECTED_CANONICAL_SHA256 {
        return Err(RegistrySourceError::CanonicalDigest {
            expected: EXPECTED_CANONICAL_SHA256,
            actual: canonical_digest,
        });
    }
    Ok(inventory)
}

fn normalize_line_endings(source: &[u8]) -> Cow<'_, [u8]> {
    if !source.windows(2).any(|pair| pair == b"\r\n") {
        return Cow::Borrowed(source);
    }
    let mut normalized = Vec::with_capacity(source.len());
    let mut index = 0;
    while index < source.len() {
        if source.get(index..index + 2) == Some(b"\r\n") {
            normalized.push(b'\n');
            index += 2;
        } else {
            normalized.push(source[index]);
            index += 1;
        }
    }
    Cow::Owned(normalized)
}

fn validate_contract(inventory: &Inventory) -> Result<(), RegistrySourceError> {
    require(inventory.schema_version == 1, "schema version drift")?;
    require(
        inventory.inventory_id == "gateway-protocol",
        "inventory identity drift",
    )?;
    require(
        inventory.classification == "gateway_core",
        "inventory classification drift",
    )?;
    require(
        inventory.baseline_sha == EXPECTED_BASELINE_SHA,
        "pinned upstream SHA drift",
    )?;
    require(
        inventory.counts.total == EXPECTED_TOTAL,
        "total count drift",
    )?;
    require(
        inventory.counts.methods == EXPECTED_METHODS,
        "method count drift",
    )?;
    require(
        inventory.counts.advertised_methods == EXPECTED_ADVERTISED_METHODS,
        "advertised method count drift",
    )?;
    require(
        inventory.counts.events == EXPECTED_EVENTS,
        "event count drift",
    )?;
    require(inventory.counts.roles == EXPECTED_ROLES, "role count drift")?;
    require(
        inventory.counts.scopes == EXPECTED_SCOPES,
        "scope count drift",
    )?;
    require(
        inventory.counts.dynamic_plugin_methods == "runtime-dependent",
        "dynamic plugin declaration drift",
    )?;
    require(
        inventory.items.len() == EXPECTED_TOTAL,
        "inventory row count drift",
    )?;

    let mut record_ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut methods = 0;
    let mut advertised = 0;
    let mut events = 0;
    let mut roles = 0;
    let mut scopes = 0;
    for item in &inventory.items {
        require(
            item.classification == "gateway_core",
            "row classification drift",
        )?;
        require(!item.id.is_empty(), "empty inventory identity")?;
        require(!item.source_path.is_empty(), "empty source path")?;
        require(
            record_ids.insert(item.record_id.as_str()),
            "duplicate record id",
        )?;
        require(
            identities.insert((item.kind.as_str(), item.id.as_str())),
            "duplicate ordinal identity",
        )?;
        require(
            item.record_id == format!("gateway_{}:{}", item.kind, item.id),
            "record identity drift",
        )?;
        match item.kind.as_str() {
            "method" => {
                methods += 1;
                require(
                    item.scope.is_some()
                        && item.advertised.is_some()
                        && item.protocol_class.is_none(),
                    "invalid method row structure",
                )?;
                advertised += usize::from(item.advertised == Some(true));
            }
            "event" => {
                events += 1;
                require(
                    item.scope.is_none()
                        && item.advertised.is_none()
                        && item.protocol_class.is_none(),
                    "invalid event row structure",
                )?;
            }
            "role" => {
                roles += 1;
                require(
                    item.scope.is_none()
                        && item.advertised.is_none()
                        && item.protocol_class.is_some(),
                    "invalid role row structure",
                )?;
            }
            "scope" => {
                scopes += 1;
                require(
                    item.scope.is_none()
                        && item.advertised.is_none()
                        && item.protocol_class.is_none(),
                    "invalid scope row structure",
                )?;
            }
            _ => return Err(RegistrySourceError::Contract("unknown row kind")),
        }
    }
    require(methods == EXPECTED_METHODS, "derived method count drift")?;
    require(
        advertised == EXPECTED_ADVERTISED_METHODS,
        "derived advertised method count drift",
    )?;
    require(events == EXPECTED_EVENTS, "derived event count drift")?;
    require(roles == EXPECTED_ROLES, "derived role count drift")?;
    require(scopes == EXPECTED_SCOPES, "derived scope count drift")
}

fn canonical_digest(inventory: &Inventory) -> Result<String, RegistrySourceError> {
    let mut rows = inventory
        .items
        .iter()
        .map(|item| {
            let mut row = BTreeMap::<&str, Value>::new();
            row.insert("record_id", Value::String(item.record_id.clone()));
            row.insert("id", Value::String(item.id.clone()));
            row.insert("classification", Value::String(item.classification.clone()));
            row.insert("source_path", Value::String(item.source_path.clone()));
            row.insert("kind", Value::String(item.kind.clone()));
            if let Some(scope) = &item.scope {
                row.insert("scope", Value::String(scope.clone()));
            }
            if let Some(advertised) = item.advertised {
                row.insert("advertised", Value::Bool(advertised));
            }
            if let Some(protocol_class) = &item.protocol_class {
                row.insert("protocol_class", Value::String(protocol_class.clone()));
            }
            serde_json::to_string(&row).map_err(RegistrySourceError::Json)
        })
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort();
    Ok(sha256_hex(format!("[{}]", rows.join(",")).as_bytes()))
}

fn require(condition: bool, message: &'static str) -> Result<(), RegistrySourceError> {
    if condition {
        Ok(())
    } else {
        Err(RegistrySourceError::Contract(message))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

#[derive(Debug)]
pub(crate) enum RegistrySourceError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    SourceDigest {
        expected: &'static str,
        actual: String,
    },
    Json(serde_json::Error),
    Contract(&'static str),
    CanonicalDigest {
        expected: &'static str,
        actual: String,
    },
}

impl Display for RegistrySourceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } if source.kind() == io::ErrorKind::NotFound => write!(
                formatter,
                "missing frozen workspace input `{}`; claw-protocol is workspace-only",
                path.display()
            ),
            Self::Read { path, source } => {
                write!(
                    formatter,
                    "cannot read frozen input `{}`: {source}",
                    path.display()
                )
            }
            Self::SourceDigest { expected, actual } => write!(
                formatter,
                "frozen registry source digest mismatch: expected {expected}, got {actual}"
            ),
            Self::Json(error) => write!(formatter, "invalid frozen registry JSON: {error}"),
            Self::Contract(message) => {
                write!(formatter, "frozen registry contract mismatch: {message}")
            }
            Self::CanonicalDigest { expected, actual } => write!(
                formatter,
                "canonical registry digest mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl Error for RegistrySourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Json(error) => Some(error),
            Self::SourceDigest { .. } | Self::Contract(_) | Self::CanonicalDigest { .. } => None,
        }
    }
}

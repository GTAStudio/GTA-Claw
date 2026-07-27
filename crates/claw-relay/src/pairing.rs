//! MV3 extension pairing.
//!
//! Upstream pairs a Chrome MV3 extension with the host-local relay by printing
//! a pairing string from `openclaw browser extension pair` and having the
//! extension popup store it. The extension then dials
//! `ws://<loopback>:<port>/extension` and carries the relay secret in its
//! WebSocket subprotocol list rather than in the request URL.
//!
//! This module owns the host side of that handshake. It validates the MV3
//! manifest a paired extension must ship, parses and renders the pairing string
//! with the exact upstream shape, and turns a completed pairing into the precise
//! [`UpgradeRequest`] the paired extension is expected to present. Anything that
//! is not an exact match is unpaired and is refused by [`RelayEndpoint`].
//!
//! [`RelayEndpoint`]: crate::RelayEndpoint

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use serde_json::Value;

use crate::endpoint::{ExtensionId, UpgradeRequest};

/// Mandatory relay subprotocol offered by a paired extension.
pub const RELAY_SUBPROTOCOL: &str = "openclaw-extension-relay";

/// Prefix of the subprotocol that carries the relay secret.
pub const RELAY_TOKEN_SUBPROTOCOL_PREFIX: &str = "openclaw-extension-token.";

/// WebSocket path served for the paired extension transport.
pub const EXTENSION_PATH: &str = "/extension";

/// Lowest Chrome milestone whose `chrome.debugger` surface the relay relies on.
pub const MINIMUM_CHROME_VERSION: u32 = 125;

const REQUIRED_PERMISSIONS: [&str; 5] = ["debugger", "tabs", "tabGroups", "storage", "alarms"];

const FORBIDDEN_MANIFEST_KEYS: [&str; 6] = [
    "host_permissions",
    "content_scripts",
    "web_accessible_resources",
    "externally_connectable",
    "optional_host_permissions",
    "optional_permissions",
];

/// Validated Chrome MV3 manifest of the extension being paired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mv3Manifest {
    name: String,
    version: String,
    service_worker: String,
    permissions: BTreeSet<String>,
    minimum_chrome_version: u32,
}

impl Mv3Manifest {
    /// Parses and validates one MV3 manifest document.
    ///
    /// The manifest is accepted only when it is manifest version 3, declares a
    /// module service worker, holds exactly the relay capability set, requests
    /// no page-injection capability at all, and targets a Chrome milestone that
    /// actually carries the debugger surface the relay drives.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::MalformedManifest`] when the bytes are not a
    /// JSON object or a required string field is missing or empty,
    /// [`PairingError::NotManifestV3`] when `manifest_version` is not `3`,
    /// [`PairingError::ForbiddenManifestKey`] for any of the page-injection
    /// keys (`host_permissions`, `content_scripts`, `web_accessible_resources`,
    /// `externally_connectable`, `optional_host_permissions`,
    /// `optional_permissions`), [`PairingError::MissingServiceWorker`] when
    /// `background` is absent, is not `type: "module"`, or names an empty
    /// worker, [`PairingError::ForbiddenPermission`] for a permission outside
    /// the relay capability set, [`PairingError::MissingPermission`] when one
    /// of `debugger`, `tabs`, `tabGroups`, `storage` or `alarms` is absent, and
    /// [`PairingError::UnsupportedChromeVersion`] when
    /// `minimum_chrome_version` is missing, unparsable, or below
    /// [`MINIMUM_CHROME_VERSION`].
    pub fn parse(bytes: &[u8]) -> Result<Self, PairingError> {
        let document: Value =
            serde_json::from_slice(bytes).map_err(|_| PairingError::MalformedManifest)?;
        let object = document
            .as_object()
            .ok_or(PairingError::MalformedManifest)?;

        if object.get("manifest_version").and_then(Value::as_u64) != Some(3) {
            return Err(PairingError::NotManifestV3);
        }
        if let Some(key) = FORBIDDEN_MANIFEST_KEYS
            .into_iter()
            .find(|key| object.contains_key(*key))
        {
            return Err(PairingError::ForbiddenManifestKey(key));
        }

        let name = required_string(object.get("name"))?;
        let version = required_string(object.get("version"))?;

        let background = object
            .get("background")
            .and_then(Value::as_object)
            .ok_or(PairingError::MissingServiceWorker)?;
        if background.get("type").and_then(Value::as_str) != Some("module") {
            return Err(PairingError::MissingServiceWorker);
        }
        let service_worker = background
            .get("service_worker")
            .and_then(Value::as_str)
            .filter(|worker| !worker.is_empty())
            .ok_or(PairingError::MissingServiceWorker)?
            .to_owned();

        let declared = object
            .get("permissions")
            .and_then(Value::as_array)
            .ok_or(PairingError::MissingPermission("permissions"))?;
        let mut permissions = BTreeSet::new();
        for entry in declared {
            let permission = entry.as_str().ok_or(PairingError::MalformedManifest)?;
            if !REQUIRED_PERMISSIONS.contains(&permission) {
                return Err(PairingError::ForbiddenPermission(permission.to_owned()));
            }
            permissions.insert(permission.to_owned());
        }
        if let Some(missing) = REQUIRED_PERMISSIONS
            .into_iter()
            .find(|required| !permissions.contains(*required))
        {
            return Err(PairingError::MissingPermission(missing));
        }

        let minimum_chrome_version = object
            .get("minimum_chrome_version")
            .and_then(Value::as_str)
            .and_then(|value| value.split('.').next())
            .and_then(|major| major.parse::<u32>().ok())
            .ok_or(PairingError::UnsupportedChromeVersion)?;
        if minimum_chrome_version < MINIMUM_CHROME_VERSION {
            return Err(PairingError::UnsupportedChromeVersion);
        }

        Ok(Self {
            name,
            version,
            service_worker,
            permissions,
            minimum_chrome_version,
        })
    }

    /// Returns the extension name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the extension version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the MV3 background service worker entry point.
    #[must_use]
    pub fn service_worker(&self) -> &str {
        &self.service_worker
    }

    /// Returns the declared permissions in stable order.
    pub fn permissions(&self) -> impl Iterator<Item = &str> {
        self.permissions.iter().map(String::as_str)
    }

    /// Returns the declared minimum Chrome milestone.
    #[must_use]
    pub const fn minimum_chrome_version(&self) -> u32 {
        self.minimum_chrome_version
    }
}

fn required_string(value: Option<&Value>) -> Result<String, PairingError> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or(PairingError::MalformedManifest)
}

/// Loopback relay address and secret handed to one extension during pairing.
///
/// Rendered and parsed as the upstream pairing string
/// `ws://<loopback-authority>/extension#<token>`.
#[derive(Clone, Eq, PartialEq)]
pub struct PairingOffer {
    authority: String,
    token: String,
}

impl PairingOffer {
    /// Builds the offer printed by the pairing command.
    ///
    /// The authority must be a loopback host with an explicit non-zero port,
    /// because the relay never listens anywhere else and never on a default
    /// port. Accepting a port-less authority would make the extension offer the
    /// relay secret to whatever unrelated service happens to hold loopback
    /// port 80. The token must be the canonical 64-lowercase-hex relay secret.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NonLoopbackRelay`] when the authority is empty,
    /// carries whitespace, does not name `localhost`, `127.0.0.1` or `[::1]`,
    /// or omits an explicit non-zero port. Returns
    /// [`PairingError::MalformedToken`] when the token is not exactly 64
    /// lowercase hex characters.
    pub fn new(authority: &str, token: &str) -> Result<Self, PairingError> {
        if !is_loopback_relay_authority(authority) {
            return Err(PairingError::NonLoopbackRelay);
        }
        if !is_canonical_token(token) {
            return Err(PairingError::MalformedToken);
        }
        Ok(Self {
            authority: authority.to_owned(),
            token: token.to_owned(),
        })
    }

    /// Parses one pairing string exactly as the extension popup parses it.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::MalformedPairingString`] when the string carries
    /// no `#` secret fragment, is not a `ws://` URL, does not end in
    /// [`EXTENSION_PATH`], or leaves an empty authority or one containing a
    /// path separator. Returns [`PairingError::NonLoopbackRelay`] or
    /// [`PairingError::MalformedToken`] for the same reasons as
    /// [`PairingOffer::new`], which validates the parsed halves.
    pub fn parse(raw: &str) -> Result<Self, PairingError> {
        let trimmed = raw.trim();
        let (url, token) = trimmed
            .split_once('#')
            .ok_or(PairingError::MalformedPairingString)?;
        let authority = url
            .strip_prefix("ws://")
            .ok_or(PairingError::MalformedPairingString)?;
        let authority = authority
            .strip_suffix(EXTENSION_PATH)
            .ok_or(PairingError::MalformedPairingString)?;
        if authority.is_empty() || authority.contains('/') {
            return Err(PairingError::MalformedPairingString);
        }
        Self::new(authority, token.trim())
    }

    /// Returns the loopback authority the extension dials.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Returns the relay WebSocket URL without the secret fragment.
    #[must_use]
    pub fn relay_url(&self) -> String {
        format!("ws://{}{EXTENSION_PATH}", self.authority)
    }

    /// Renders the complete pairing string, secret included.
    #[must_use]
    pub fn pairing_string(&self) -> String {
        format!("{}#{}", self.relay_url(), self.token)
    }

    /// Returns the ordered subprotocol list the paired extension offers.
    ///
    /// The secret travels in the subprotocol list, never in the request URL,
    /// so it is not written to any proxy or server access log.
    #[must_use]
    pub fn subprotocols(&self) -> Vec<String> {
        vec![
            RELAY_SUBPROTOCOL.to_owned(),
            format!("{RELAY_TOKEN_SUBPROTOCOL_PREFIX}{}", self.token),
        ]
    }
}

impl Debug for PairingOffer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingOffer")
            .field("authority", &self.authority)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// One completed MV3 pairing between a Chrome extension and this relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionPairing {
    extension_id: ExtensionId,
    manifest: Mv3Manifest,
    offer: PairingOffer,
}

impl ExtensionPairing {
    /// Completes a pairing for one validated MV3 extension.
    #[must_use]
    pub const fn new(
        extension_id: ExtensionId,
        manifest: Mv3Manifest,
        offer: PairingOffer,
    ) -> Self {
        Self {
            extension_id,
            manifest,
            offer,
        }
    }

    /// Returns the paired Chrome extension identity.
    #[must_use]
    pub const fn extension_id(&self) -> &ExtensionId {
        &self.extension_id
    }

    /// Returns the validated MV3 manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Mv3Manifest {
        &self.manifest
    }

    /// Returns the pairing offer this extension holds.
    #[must_use]
    pub const fn offer(&self) -> &PairingOffer {
        &self.offer
    }

    /// Returns the extension origin Chrome sends on the relay upgrade.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("chrome-extension://{}", self.extension_id.as_str())
    }

    /// Builds the exact upgrade the paired extension presents to the relay.
    #[must_use]
    pub fn upgrade_request(&self) -> UpgradeRequest {
        UpgradeRequest {
            path: EXTENSION_PATH.to_owned(),
            host: self.offer.authority.clone(),
            origin: Some(self.origin()),
            subprotocols: self.offer.subprotocols(),
            authorization_token: None,
        }
    }
}

fn is_canonical_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns whether an authority names a loopback relay on an explicit port.
///
/// Stricter than the `Host` header check: whitespace is refused outright rather
/// than trimmed, so the stored authority is exactly the bytes that were
/// validated, and the port is mandatory.
fn is_loopback_relay_authority(authority: &str) -> bool {
    if authority.is_empty() || authority.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return false;
    }
    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    let loopback = host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "[::1]";
    loopback && port.parse::<u16>().is_ok_and(|port| port != 0)
}

/// MV3 pairing failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingError {
    /// Manifest document was not a JSON object the relay understands.
    MalformedManifest,
    /// Only Chrome MV3 extensions may pair with the relay.
    NotManifestV3,
    /// Manifest requested a capability the relay refuses to pair with.
    ForbiddenManifestKey(&'static str),
    /// Manifest declared a permission outside the relay capability set.
    ForbiddenPermission(String),
    /// Manifest omitted a permission the relay transport requires.
    MissingPermission(&'static str),
    /// Manifest declared no MV3 module service worker.
    MissingServiceWorker,
    /// Manifest targets a Chrome milestone without the required debugger surface.
    UnsupportedChromeVersion,
    /// Pairing string did not have the exact upstream shape.
    MalformedPairingString,
    /// Pairing secret was not canonical lowercase hex.
    MalformedToken,
    /// Pairing string addressed a relay that is not loopback.
    NonLoopbackRelay,
}

impl Display for PairingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedManifest => formatter.write_str("extension manifest is malformed"),
            Self::NotManifestV3 => formatter.write_str("extension manifest is not manifest v3"),
            Self::ForbiddenManifestKey(key) => {
                write!(formatter, "extension manifest key '{key}' is not allowed")
            }
            Self::ForbiddenPermission(permission) => {
                write!(
                    formatter,
                    "extension permission '{permission}' is not allowed"
                )
            }
            Self::MissingPermission(permission) => {
                write!(
                    formatter,
                    "extension manifest is missing required '{permission}'"
                )
            }
            Self::MissingServiceWorker => {
                formatter.write_str("extension manifest declares no module service worker")
            }
            Self::UnsupportedChromeVersion => {
                formatter.write_str("extension manifest targets an unsupported Chrome version")
            }
            Self::MalformedPairingString => {
                formatter.write_str("relay pairing string is malformed")
            }
            Self::MalformedToken => formatter.write_str("relay pairing token is malformed"),
            Self::NonLoopbackRelay => {
                formatter.write_str("relay pairing string must address loopback")
            }
        }
    }
}

impl Error for PairingError {}

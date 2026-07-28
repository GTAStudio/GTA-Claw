//! Where components may be loaded from, who must have signed them, and which
//! identity a given key is allowed to present.
//!
//! Three independent gates run before a component's bytes are handed to the
//! engine:
//!
//! 1. [`TrustPolicy::authorize`] resolves the manifest directory and the
//!    component path through the operating system and refuses anything that
//!    does not stay inside a configured trusted root. Because both sides are
//!    canonicalised, `..` traversal, junctions and symlinks that point outside
//!    a root are rejected rather than followed.
//! 2. Identity: an [`IdentityBinding`] pins a plugin id to one delivery class,
//!    one installation directory and an exact set of signing keys. Every id in
//!    the frozen [`crate::registry`] must have one, and its declared delivery
//!    class must agree with the inventory. A key that is trusted to sign some
//!    plugin therefore cannot sign a component that claims a *different*
//!    plugin's identity and inherit that identity's namespaces.
//! 3. Integrity and provenance: [`component_sha256`] must match the manifest's
//!    pinned digest, and the configured [`SignatureVerifier`] must accept the
//!    manifest. The default verifier, [`RejectAllSignatures`], accepts only
//!    unsigned manifests, so an operator who turns on `require_signature`
//!    without installing a real verifier gets a closed door rather than an
//!    open one.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::manifest::{PluginManifest, SignatureAlgorithm};
use crate::registry::{DeliveryClass, PluginRegistry};

/// Domain separator prefixed to every signed manifest payload.
pub const SIGNING_DOMAIN: &[u8] = b"gta-claw:plugin-manifest-signature:v1\0";

/// Lowercase hex SHA-256 of `bytes`.
#[must_use]
pub fn component_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    hex
}

/// The exact bytes a manifest signature covers.
///
/// The payload is the domain separator followed by the canonical JSON encoding
/// of the manifest with its `signature` field removed. Every security-relevant
/// field - id, versions, delivery class, component digest and size, the full
/// capability list and the resource limits - is therefore covered, so a
/// signature cannot be transplanted onto a manifest that asks for more.
///
/// # Errors
///
/// Returns a [`serde_json::Error`] only if the manifest cannot be encoded,
/// which cannot happen for a validated manifest.
pub fn signing_payload(manifest: &PluginManifest) -> Result<Vec<u8>, serde_json::Error> {
    let unsigned = PluginManifest {
        signature: None,
        ..manifest.clone()
    };
    let body = serde_json::to_vec(&unsigned)?;
    let mut payload = Vec::with_capacity(SIGNING_DOMAIN.len() + body.len());
    payload.extend_from_slice(SIGNING_DOMAIN);
    payload.extend_from_slice(&body);
    Ok(payload)
}

/// Everything a [`SignatureVerifier`] gets to look at.
#[derive(Clone, Copy, Debug)]
pub struct VerificationRequest<'a> {
    /// The parsed, already schema-validated manifest.
    pub manifest: &'a PluginManifest,
    /// Lowercase hex SHA-256 actually computed over the component bytes.
    pub component_sha256: &'a str,
}

/// A pluggable manifest signature check.
pub trait SignatureVerifier: Send + Sync {
    /// Accepts or rejects the manifest's provenance.
    ///
    /// # Errors
    ///
    /// Returns [`VerificationError`] when the manifest must not be loaded.
    fn verify(&self, request: &VerificationRequest<'_>) -> Result<(), VerificationError>;
}

/// The default verifier: accepts unsigned manifests and refuses to pretend it
/// can check a signature it has no key material for.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAllSignatures;

impl SignatureVerifier for RejectAllSignatures {
    fn verify(&self, request: &VerificationRequest<'_>) -> Result<(), VerificationError> {
        let Some(signature) = &request.manifest.signature else {
            return Ok(());
        };
        Err(VerificationError::NoVerifierConfigured {
            algorithm: signature.algorithm,
        })
    }
}

/// Verifies Ed25519 manifest signatures against a fixed set of trusted keys.
#[derive(Clone, Debug, Default)]
pub struct Ed25519Verifier {
    keys: BTreeMap<String, [u8; 32]>,
}

impl Ed25519Verifier {
    /// An empty key set. It rejects every signed manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a trusted public key.
    #[must_use]
    pub fn with_key(mut self, key_id: impl Into<String>, public_key: [u8; 32]) -> Self {
        self.keys.insert(key_id.into(), public_key);
        self
    }

    /// The registered key ids.
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
}

impl SignatureVerifier for Ed25519Verifier {
    fn verify(&self, request: &VerificationRequest<'_>) -> Result<(), VerificationError> {
        let Some(signature) = &request.manifest.signature else {
            return Err(VerificationError::SignatureRequired);
        };
        if signature.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(VerificationError::NoVerifierConfigured {
                algorithm: signature.algorithm,
            });
        }
        let Some(public_key) = self.keys.get(&signature.key_id) else {
            return Err(VerificationError::UnknownKey {
                key_id: signature.key_id.clone(),
            });
        };
        if request.component_sha256 != request.manifest.component.sha256 {
            return Err(VerificationError::DigestMismatch {
                expected: request.manifest.component.sha256.clone(),
                found: request.component_sha256.to_owned(),
            });
        }
        let raw = decode_hex(&signature.value).ok_or(VerificationError::MalformedSignature)?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| VerificationError::MalformedSignature)?;
        let verifying_key =
            VerifyingKey::from_bytes(public_key).map_err(|_| VerificationError::UnusableKey {
                key_id: signature.key_id.clone(),
            })?;
        let payload =
            signing_payload(request.manifest).map_err(|_| VerificationError::MalformedSignature)?;
        verifying_key
            .verify_strict(&payload, &Signature::from_bytes(&raw))
            .map_err(|_| VerificationError::BadSignature {
                key_id: signature.key_id.clone(),
            })
    }
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(u8::try_from(hi * 16 + lo).ok()?);
    }
    Some(out)
}

/// Why a signature check failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// The manifest carried no signature but the verifier demands one.
    SignatureRequired,
    /// No verifier is installed for the declared algorithm.
    NoVerifierConfigured {
        /// The algorithm the manifest declared.
        algorithm: SignatureAlgorithm,
    },
    /// The signing key is not trusted by this host.
    UnknownKey {
        /// The rejected key id.
        key_id: String,
    },
    /// The trusted key material could not be parsed.
    UnusableKey {
        /// The offending key id.
        key_id: String,
    },
    /// The signature bytes were not a valid encoding.
    MalformedSignature,
    /// The signature did not verify.
    BadSignature {
        /// The key the signature claimed to come from.
        key_id: String,
    },
    /// The component bytes did not match the pinned digest.
    DigestMismatch {
        /// Digest pinned by the manifest.
        expected: String,
        /// Digest computed over the bytes on disk.
        found: String,
    },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureRequired => {
                f.write_str("manifest is unsigned but a signature is required")
            }
            Self::NoVerifierConfigured { algorithm } => write!(
                f,
                "no verifier is configured for signature algorithm {algorithm:?}"
            ),
            Self::UnknownKey { key_id } => write!(f, "signing key `{key_id}` is not trusted"),
            Self::UnusableKey { key_id } => write!(
                f,
                "trusted key `{key_id}` is not a valid Ed25519 public key"
            ),
            Self::MalformedSignature => f.write_str("signature bytes are malformed"),
            Self::BadSignature { key_id } => {
                write!(f, "signature does not verify under key `{key_id}`")
            }
            Self::DigestMismatch { expected, found } => write!(
                f,
                "component digest mismatch: manifest pins {expected}, bytes hash to {found}"
            ),
        }
    }
}

impl core::error::Error for VerificationError {}

/// Binds one plugin identity to the only provenance that may present it.
///
/// Trusting a key id on its own is not enough. A key that is trusted to sign
/// *some* plugin can otherwise sign a component that claims *another* plugin's
/// id and delivery class, and thereby inherit that id's configuration
/// namespace, store namespace and operator capability ceiling. A binding
/// pins the identity to a delivery class, an installation directory and an
/// exact set of signing keys, so impersonation fails before the component is
/// read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBinding {
    plugin_id: String,
    delivery_class: DeliveryClass,
    location: PathBuf,
    key_ids: BTreeSet<String>,
}

impl IdentityBinding {
    /// Binds `plugin_id` to a delivery class and a canonical install directory.
    ///
    /// No signing key is accepted until one is added, so the binding starts by
    /// permitting only an unsigned manifest - and only if the policy does not
    /// require signatures.
    #[must_use]
    pub fn new(
        plugin_id: impl Into<String>,
        delivery_class: DeliveryClass,
        location: impl Into<PathBuf>,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            delivery_class,
            location: location.into(),
            key_ids: BTreeSet::new(),
        }
    }

    /// Adds a signing key id that may present this identity.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_ids.insert(key_id.into());
        self
    }

    /// The bound plugin id.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// The only delivery class this identity may declare.
    #[must_use]
    pub const fn delivery_class(&self) -> DeliveryClass {
        self.delivery_class
    }

    /// The only directory this identity may be loaded from.
    #[must_use]
    pub fn location(&self) -> &Path {
        &self.location
    }

    /// The signing key ids that may present this identity.
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.key_ids.iter().map(String::as_str)
    }
}

/// Where components may come from and which provenance is acceptable.
///
/// [`TrustPolicy::deny_all`] is the starting point: no roots, no delivery
/// classes, signatures required. Everything must be switched on explicitly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPolicy {
    roots: Vec<PathBuf>,
    require_signature: bool,
    require_identity_binding: bool,
    trusted_key_ids: BTreeSet<String>,
    allowed_delivery_classes: BTreeSet<DeliveryClass>,
    bindings: BTreeMap<String, IdentityBinding>,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl TrustPolicy {
    /// A policy that refuses every component.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            roots: Vec::new(),
            require_signature: true,
            require_identity_binding: true,
            trusted_key_ids: BTreeSet::new(),
            allowed_delivery_classes: BTreeSet::new(),
            bindings: BTreeMap::new(),
        }
    }

    /// Adds a directory components may be loaded from.
    #[must_use]
    pub fn with_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.roots.push(root.into());
        self
    }

    /// Sets whether a manifest signature is mandatory.
    #[must_use]
    pub const fn require_signature(mut self, required: bool) -> Self {
        self.require_signature = required;
        self
    }

    /// Trusts a signing key id.
    #[must_use]
    pub fn with_trusted_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.trusted_key_ids.insert(key_id.into());
        self
    }

    /// Allows a delivery class.
    #[must_use]
    pub fn allow_delivery_class(mut self, class: DeliveryClass) -> Self {
        self.allowed_delivery_classes.insert(class);
        self
    }

    /// Sets whether *every* plugin id needs an identity binding.
    ///
    /// On by default. Turning it off only relaxes ids that are absent from the
    /// frozen [`crate::registry`]: a registry id always needs a binding, because
    /// those ids own persistent configuration and store namespaces that a
    /// component must not be able to claim merely by naming them.
    #[must_use]
    pub const fn require_identity_binding(mut self, required: bool) -> Self {
        self.require_identity_binding = required;
        self
    }

    /// Whether every plugin id needs an identity binding.
    #[must_use]
    pub const fn identity_binding_required(&self) -> bool {
        self.require_identity_binding
    }

    /// Binds a plugin identity to a delivery class, a location and its keys.
    ///
    /// Every id in the frozen [`crate::registry`] *must* have a binding before
    /// it can be loaded; there is no opt-out. Ids outside the registry may have
    /// one, and it is enforced when present.
    #[must_use]
    pub fn with_identity_binding(mut self, binding: IdentityBinding) -> Self {
        self.bindings.insert(binding.plugin_id.clone(), binding);
        self
    }

    /// The binding for `plugin_id`, if one is configured.
    #[must_use]
    pub fn identity_binding(&self, plugin_id: &str) -> Option<&IdentityBinding> {
        self.bindings.get(plugin_id)
    }

    /// Whether signatures are mandatory.
    #[must_use]
    pub const fn signature_required(&self) -> bool {
        self.require_signature
    }

    /// The configured trusted roots.
    #[must_use]
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Resolves and authorises a plugin directory.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError`] when the plugin must not be loaded.
    pub fn authorize(
        &self,
        manifest_dir: &Path,
        manifest: &PluginManifest,
    ) -> Result<TrustDecision, TrustError> {
        if !self
            .allowed_delivery_classes
            .contains(&manifest.delivery_class)
        {
            return Err(TrustError::DeliveryClassNotAllowed {
                class: manifest.delivery_class,
            });
        }

        // A component that claims a reserved id must agree with the frozen
        // inventory about what kind of plugin that id is.
        if let Some(descriptor) = PluginRegistry::get(&manifest.id)
            && descriptor.delivery_class() != manifest.delivery_class
        {
            return Err(TrustError::RegistryClassMismatch {
                plugin_id: manifest.id.clone(),
                registry: descriptor.delivery_class(),
                declared: manifest.delivery_class,
            });
        }

        let binding = self.bindings.get(&manifest.id);
        let reserved = PluginRegistry::get(&manifest.id).is_some();
        if binding.is_none() && (self.require_identity_binding || reserved) {
            return Err(TrustError::UnboundIdentity {
                plugin_id: manifest.id.clone(),
                reserved,
            });
        }
        if let Some(binding) = binding
            && binding.delivery_class != manifest.delivery_class
        {
            return Err(TrustError::BindingClassMismatch {
                plugin_id: manifest.id.clone(),
                bound: binding.delivery_class,
                declared: manifest.delivery_class,
            });
        }

        let canonical_roots = self
            .roots
            .iter()
            .map(|root| {
                std::fs::canonicalize(root).map_err(|error| TrustError::UnresolvableRoot {
                    root: root.clone(),
                    message: error.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if canonical_roots.is_empty() {
            return Err(TrustError::NoTrustedRoots);
        }

        let canonical_dir =
            std::fs::canonicalize(manifest_dir).map_err(|error| TrustError::UnresolvablePath {
                path: manifest_dir.to_path_buf(),
                message: error.to_string(),
            })?;
        let root = canonical_roots
            .iter()
            .find(|root| canonical_dir.starts_with(root))
            .ok_or_else(|| TrustError::OutsideTrustedRoots {
                path: canonical_dir.clone(),
            })?
            .clone();

        if let Some(binding) = binding {
            let bound = std::fs::canonicalize(&binding.location).map_err(|error| {
                TrustError::UnresolvablePath {
                    path: binding.location.clone(),
                    message: error.to_string(),
                }
            })?;
            if bound != canonical_dir {
                return Err(TrustError::BindingLocationMismatch {
                    plugin_id: manifest.id.clone(),
                    bound,
                    found: canonical_dir,
                });
            }
        }

        let mut component_path = canonical_dir.clone();
        for segment in manifest.component.path.split('/') {
            component_path.push(segment);
        }
        let canonical_component = std::fs::canonicalize(&component_path).map_err(|error| {
            TrustError::UnresolvablePath {
                path: component_path.clone(),
                message: error.to_string(),
            }
        })?;
        if !canonical_component.starts_with(&root) {
            return Err(TrustError::OutsideTrustedRoots {
                path: canonical_component,
            });
        }

        let key_id = match &manifest.signature {
            None => {
                if self.require_signature {
                    return Err(TrustError::SignatureRequired);
                }
                if let Some(binding) = binding
                    && !binding.key_ids.is_empty()
                {
                    return Err(TrustError::BindingKeyMismatch {
                        plugin_id: manifest.id.clone(),
                        key_id: None,
                    });
                }
                None
            }
            Some(signature) => {
                if !self.trusted_key_ids.contains(&signature.key_id) {
                    return Err(TrustError::UntrustedKeyId {
                        key_id: signature.key_id.clone(),
                    });
                }
                // Host-wide trust is necessary but not sufficient: the key must
                // also be one of the keys bound to *this* identity.
                if let Some(binding) = binding
                    && !binding.key_ids.contains(&signature.key_id)
                {
                    return Err(TrustError::BindingKeyMismatch {
                        plugin_id: manifest.id.clone(),
                        key_id: Some(signature.key_id.clone()),
                    });
                }
                Some(signature.key_id.clone())
            }
        };

        Ok(TrustDecision {
            root,
            manifest_dir: canonical_dir,
            component_path: canonical_component,
            signing_key_id: key_id,
        })
    }
}

/// The result of a successful [`TrustPolicy::authorize`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustDecision {
    root: PathBuf,
    manifest_dir: PathBuf,
    component_path: PathBuf,
    signing_key_id: Option<String>,
}

impl TrustDecision {
    /// The trusted root the plugin resolved under.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The canonical plugin directory.
    #[must_use]
    pub fn manifest_dir(&self) -> &Path {
        &self.manifest_dir
    }

    /// The canonical component path.
    #[must_use]
    pub fn component_path(&self) -> &Path {
        &self.component_path
    }

    /// The trusted key id that signed the manifest, if it was signed.
    #[must_use]
    pub fn signing_key_id(&self) -> Option<&str> {
        self.signing_key_id.as_deref()
    }
}

/// Why a plugin location or provenance was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// The policy has no usable trusted roots.
    NoTrustedRoots,
    /// A configured root does not exist.
    UnresolvableRoot {
        /// The configured root.
        root: PathBuf,
        /// Operating-system message.
        message: String,
    },
    /// A path could not be resolved.
    UnresolvablePath {
        /// The path that failed to resolve.
        path: PathBuf,
        /// Operating-system message.
        message: String,
    },
    /// The resolved path lies outside every trusted root.
    OutsideTrustedRoots {
        /// The resolved path.
        path: PathBuf,
    },
    /// This delivery class is not enabled on this host.
    DeliveryClassNotAllowed {
        /// The rejected class.
        class: DeliveryClass,
    },
    /// The policy requires signed manifests.
    SignatureRequired,
    /// The manifest was signed by a key the policy does not trust.
    UntrustedKeyId {
        /// The rejected key id.
        key_id: String,
    },
    /// The id is in the frozen inventory but declares a different class.
    RegistryClassMismatch {
        /// The plugin id that was claimed.
        plugin_id: String,
        /// The class the frozen inventory records for that id.
        registry: DeliveryClass,
        /// The class the manifest declared.
        declared: DeliveryClass,
    },
    /// The plugin id has no identity binding on this host.
    UnboundIdentity {
        /// The plugin id that was claimed.
        plugin_id: String,
        /// Whether the id is reserved by the frozen inventory.
        reserved: bool,
    },
    /// The manifest declares a class the identity binding does not allow.
    BindingClassMismatch {
        /// The plugin id that was claimed.
        plugin_id: String,
        /// The class the binding pins.
        bound: DeliveryClass,
        /// The class the manifest declared.
        declared: DeliveryClass,
    },
    /// The plugin was found somewhere other than its bound location.
    BindingLocationMismatch {
        /// The plugin id that was claimed.
        plugin_id: String,
        /// The canonical directory the binding pins.
        bound: PathBuf,
        /// The canonical directory the plugin was actually found in.
        found: PathBuf,
    },
    /// The signing key is trusted by this host but not for this identity.
    BindingKeyMismatch {
        /// The plugin id that was claimed.
        plugin_id: String,
        /// The key that signed it, or `None` when it was unsigned.
        key_id: Option<String>,
    },
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrustedRoots => f.write_str("the trust policy has no trusted roots"),
            Self::UnresolvableRoot { root, message } => {
                write!(
                    f,
                    "trusted root `{}` cannot be resolved: {message}",
                    root.display()
                )
            }
            Self::UnresolvablePath { path, message } => {
                write!(f, "`{}` cannot be resolved: {message}", path.display())
            }
            Self::OutsideTrustedRoots { path } => write!(
                f,
                "`{}` resolves outside every trusted root",
                path.display()
            ),
            Self::DeliveryClassNotAllowed { class } => {
                write!(
                    f,
                    "delivery class `{}` is not enabled on this host",
                    class.as_str()
                )
            }
            Self::SignatureRequired => f.write_str("this host only loads signed plugins"),
            Self::UntrustedKeyId { key_id } => {
                write!(f, "signing key id `{key_id}` is not trusted by this host")
            }
            Self::RegistryClassMismatch {
                plugin_id,
                registry,
                declared,
            } => write!(
                f,
                "plugin id `{plugin_id}` is a `{}` plugin in the frozen inventory but the manifest declares `{}`",
                registry.as_str(),
                declared.as_str()
            ),
            Self::UnboundIdentity {
                plugin_id,
                reserved,
            } => {
                if *reserved {
                    write!(
                        f,
                        "plugin id `{plugin_id}` is reserved by the frozen inventory and this host has no identity binding for it"
                    )
                } else {
                    write!(
                        f,
                        "plugin id `{plugin_id}` has no identity binding on this host"
                    )
                }
            }
            Self::BindingClassMismatch {
                plugin_id,
                bound,
                declared,
            } => write!(
                f,
                "plugin id `{plugin_id}` is bound to delivery class `{}` but the manifest declares `{}`",
                bound.as_str(),
                declared.as_str()
            ),
            Self::BindingLocationMismatch {
                plugin_id,
                bound,
                found,
            } => write!(
                f,
                "plugin id `{plugin_id}` is bound to `{}` but was found in `{}`",
                bound.display(),
                found.display()
            ),
            Self::BindingKeyMismatch { plugin_id, key_id } => match key_id {
                Some(key_id) => write!(
                    f,
                    "signing key id `{key_id}` is not bound to plugin id `{plugin_id}`"
                ),
                None => write!(
                    f,
                    "plugin id `{plugin_id}` is bound to a signing key but the manifest is unsigned"
                ),
            },
        }
    }
}

impl core::error::Error for TrustError {}

#[cfg(test)]
mod tests {
    use super::{
        Ed25519Verifier, RejectAllSignatures, SignatureVerifier, VerificationError,
        VerificationRequest, component_sha256, decode_hex, signing_payload,
    };
    use crate::manifest::{ManifestSignature, PluginManifest, SignatureAlgorithm};

    fn manifest() -> PluginManifest {
        let json = serde_json::json!({
            "manifest_version": 1,
            "id": "trust-fixture",
            "display_name": "Trust fixture",
            "description": "Manifest used by the trust unit tests.",
            "version": "1.0.0",
            "abi_version": "1.0.0",
            "delivery_class": "core",
            "component": {
                "path": "trust.wasm",
                "sha256": component_sha256(b"component bytes"),
                "size_bytes": 15
            },
            "capabilities": [
                { "capability": "log", "min_level": "info", "max_message_bytes": 512 }
            ]
        });
        PluginManifest::parse(&serde_json::to_vec(&json).expect("encode")).expect("valid manifest")
    }

    #[test]
    fn sha256_matches_the_published_test_vector() {
        assert_eq!(
            component_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            component_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hex_decoding_rejects_odd_and_non_hex_input() {
        assert_eq!(decode_hex("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(decode_hex("0"), None);
        assert_eq!(decode_hex("zz"), None);
    }

    #[test]
    fn the_signing_payload_is_domain_separated_and_excludes_the_signature() {
        let unsigned = manifest();
        let mut signed = unsigned.clone();
        signed.signature = Some(ManifestSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "k1".to_owned(),
            value: "cd".repeat(64),
        });
        let unsigned_payload = signing_payload(&unsigned).expect("payload");
        let signed_payload = signing_payload(&signed).expect("payload");
        assert_eq!(unsigned_payload, signed_payload);
        assert!(unsigned_payload.starts_with(super::SIGNING_DOMAIN));
        assert!(!unsigned_payload.windows(2).any(|w| w == b"cd"));
    }

    #[test]
    fn the_signing_payload_changes_when_capabilities_change() {
        let base = manifest();
        let mut escalated = base.clone();
        escalated.capabilities.push(
            serde_json::from_value(serde_json::json!({
                "capability": "filesystem-read",
                "roots": ["/srv/data"],
                "max_file_bytes": 1024
            }))
            .expect("grant"),
        );
        assert_ne!(
            signing_payload(&base).expect("payload"),
            signing_payload(&escalated).expect("payload")
        );
    }

    #[test]
    fn the_default_verifier_accepts_unsigned_and_refuses_signed_manifests() {
        let verifier = RejectAllSignatures;
        let unsigned = manifest();
        assert_eq!(
            verifier.verify(&VerificationRequest {
                manifest: &unsigned,
                component_sha256: &unsigned.component.sha256,
            }),
            Ok(())
        );

        let mut signed = unsigned;
        signed.signature = Some(ManifestSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "k1".to_owned(),
            value: "cd".repeat(64),
        });
        assert_eq!(
            verifier.verify(&VerificationRequest {
                manifest: &signed,
                component_sha256: &signed.component.sha256,
            }),
            Err(VerificationError::NoVerifierConfigured {
                algorithm: SignatureAlgorithm::Ed25519
            })
        );
    }

    #[test]
    fn the_ed25519_verifier_requires_a_signature() {
        let verifier = Ed25519Verifier::new().with_key("k1", [0_u8; 32]);
        let unsigned = manifest();
        assert_eq!(
            verifier.verify(&VerificationRequest {
                manifest: &unsigned,
                component_sha256: &unsigned.component.sha256,
            }),
            Err(VerificationError::SignatureRequired)
        );
        assert_eq!(verifier.key_ids().collect::<Vec<_>>(), vec!["k1"]);
    }
}

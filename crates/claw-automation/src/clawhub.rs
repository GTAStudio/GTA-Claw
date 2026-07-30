//! Authenticated ClawHub publishing, trust, distribution, and revocation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, KeyInit as _, Mac as _};
use secrecy::{ExposeSecret as _, SecretString};
use semver::Version;
use sha2::{Digest as _, Sha256};

const SIGNING_DOMAIN: &[u8] = b"gta-claw-clawhub-publish-v1";
const REVOCATION_DOMAIN: &[u8] = b"gta-claw-clawhub-revoke-v1";
const MIN_SECRET_BYTES: usize = 32;
const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SEARCH_RESULTS: usize = 100;
const MAX_TEMP_FILE_ATTEMPTS: u64 = 1024;

type HmacSha256 = Hmac<Sha256>;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);

/// Stable `ClawHub` package name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PackageName {
    publisher: String,
    name: String,
}

impl PackageName {
    /// Creates a validated `publisher/name` identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::InvalidPackage`] when either component is not a
    /// valid stable identifier.
    pub fn new(publisher: String, name: String) -> Result<Self, ClawHubError> {
        if !valid_component(&publisher) || !valid_component(&name) {
            return Err(ClawHubError::InvalidPackage);
        }
        Ok(Self { publisher, name })
    }

    /// Publisher identifier.
    #[must_use]
    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    /// Package slug.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Canonical `publisher/name` representation.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!("{}/{}", self.publisher, self.name)
    }
}

/// Declared package capability used for install risk decisions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PackageCapability {
    /// Read files selected by GTA-Claw.
    FilesystemRead,
    /// Write files selected by GTA-Claw.
    FilesystemWrite,
    /// Make network requests.
    Network,
    /// Start child processes.
    Process,
    /// Receive secret values.
    Secrets,
    /// Load native code.
    NativeCode,
}

/// Immutable release metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseManifest {
    /// Package identifier.
    pub package: PackageName,
    /// Semantic version.
    pub version: Version,
    /// Human-readable description.
    pub description: String,
    /// Explicit capability declaration.
    pub capabilities: BTreeSet<PackageCapability>,
}

impl ReleaseManifest {
    fn validate(&self) -> Result<(), ClawHubError> {
        if self.description.is_empty()
            || self.description.len() > 4096
            || self.description.chars().any(char::is_control)
            || !self.version.pre.is_empty()
        {
            return Err(ClawHubError::InvalidManifest);
        }
        Ok(())
    }

    /// Returns the risk classification implied by capabilities.
    #[must_use]
    pub fn risk(&self) -> RiskLevel {
        if self.capabilities.contains(&PackageCapability::NativeCode) {
            RiskLevel::Blocked
        } else if self.capabilities.iter().any(|capability| {
            matches!(
                capability,
                PackageCapability::FilesystemWrite
                    | PackageCapability::Network
                    | PackageCapability::Process
                    | PackageCapability::Secrets
            )
        }) {
            RiskLevel::AcknowledgementRequired
        } else {
            RiskLevel::Low
        }
    }
}

/// Install-time risk classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskLevel {
    /// Read-only, low-risk release.
    Low,
    /// Release requires an exact digest-bound acknowledgement.
    AcknowledgementRequired,
    /// Release cannot be installed by policy.
    Blocked,
}

/// Publisher authentication secret.
#[derive(Clone, Debug)]
pub struct PublisherSecret(SecretString);

impl PublisherSecret {
    /// Creates a secret with at least 256 bits of caller-provided material.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::WeakPublisherSecret`] when the secret is shorter
    /// than 32 bytes.
    pub fn new(secret: SecretString) -> Result<Self, ClawHubError> {
        if secret.expose_secret().len() < MIN_SECRET_BYTES {
            return Err(ClawHubError::WeakPublisherSecret);
        }
        Ok(Self(secret))
    }

    fn bytes(&self) -> &[u8] {
        self.0.expose_secret().as_bytes()
    }
}

#[derive(Clone)]
struct PublisherRegistration {
    identity: String,
    secret: PublisherSecret,
}

/// Signed publish request.
#[derive(Clone, Debug)]
pub struct PublishRequest {
    /// Release manifest.
    pub manifest: ReleaseManifest,
    /// Immutable artifact bytes.
    pub artifact: Vec<u8>,
    /// Hexadecimal HMAC over metadata and artifact digest.
    pub signature: String,
}

/// Signs one publish request without exposing the publisher secret.
///
/// # Errors
///
/// Returns [`ClawHubError`] when the manifest or artifact is invalid or the
/// signing state cannot be initialized.
pub fn sign_publish(
    secret: &PublisherSecret,
    manifest: &ReleaseManifest,
    artifact: &[u8],
) -> Result<String, ClawHubError> {
    manifest.validate()?;
    if artifact.is_empty() || artifact.len() > MAX_ARTIFACT_BYTES {
        return Err(ClawHubError::InvalidArtifact);
    }
    let digest = Sha256::digest(artifact);
    sign_fields(
        secret,
        SIGNING_DOMAIN,
        &[
            manifest.package.canonical().as_bytes(),
            manifest.version.to_string().as_bytes(),
            manifest.description.as_bytes(),
            &encode_capabilities(&manifest.capabilities),
            digest.as_slice(),
        ],
    )
}

/// Signs an exact package version revocation.
///
/// # Errors
///
/// Returns [`ClawHubError::SigningState`] when the signing state cannot be
/// initialized.
pub fn sign_revocation(
    secret: &PublisherSecret,
    package: &PackageName,
    version: &Version,
) -> Result<String, ClawHubError> {
    sign_fields(
        secret,
        REVOCATION_DOMAIN,
        &[
            package.canonical().as_bytes(),
            version.to_string().as_bytes(),
        ],
    )
}

fn sign_fields(
    secret: &PublisherSecret,
    domain: &[u8],
    fields: &[&[u8]],
) -> Result<String, ClawHubError> {
    let mut mac =
        HmacSha256::new_from_slice(secret.bytes()).map_err(|_| ClawHubError::SigningState)?;
    append_field_to_mac(&mut mac, domain)?;
    for field in fields {
        append_field_to_mac(&mut mac, field)?;
    }
    Ok(encode_hex(&mac.finalize().into_bytes()))
}

fn verify_publish(secret: &PublisherSecret, request: &PublishRequest) -> Result<(), ClawHubError> {
    let signature = decode_hex(&request.signature).ok_or(ClawHubError::InvalidSignature)?;
    let digest = Sha256::digest(&request.artifact);
    let mut mac =
        HmacSha256::new_from_slice(secret.bytes()).map_err(|_| ClawHubError::SigningState)?;
    append_field_to_mac(&mut mac, SIGNING_DOMAIN)?;
    append_field_to_mac(&mut mac, request.manifest.package.canonical().as_bytes())?;
    append_field_to_mac(&mut mac, request.manifest.version.to_string().as_bytes())?;
    append_field_to_mac(&mut mac, request.manifest.description.as_bytes())?;
    append_field_to_mac(
        &mut mac,
        &encode_capabilities(&request.manifest.capabilities),
    )?;
    append_field_to_mac(&mut mac, digest.as_slice())?;
    mac.verify_slice(&signature)
        .map_err(|_| ClawHubError::InvalidSignature)
}

fn verify_revocation(
    secret: &PublisherSecret,
    package: &PackageName,
    version: &Version,
    signature: &str,
) -> Result<(), ClawHubError> {
    let signature = decode_hex(signature).ok_or(ClawHubError::InvalidSignature)?;
    let mut mac =
        HmacSha256::new_from_slice(secret.bytes()).map_err(|_| ClawHubError::SigningState)?;
    append_field_to_mac(&mut mac, REVOCATION_DOMAIN)?;
    append_field_to_mac(&mut mac, package.canonical().as_bytes())?;
    append_field_to_mac(&mut mac, version.to_string().as_bytes())?;
    mac.verify_slice(&signature)
        .map_err(|_| ClawHubError::InvalidSignature)
}

fn append_field_to_mac(mac: &mut HmacSha256, field: &[u8]) -> Result<(), ClawHubError> {
    let length = u64::try_from(field.len()).map_err(|_| ClawHubError::InvalidArtifact)?;
    mac.update(&length.to_be_bytes());
    mac.update(field);
    Ok(())
}

fn encode_capabilities(capabilities: &BTreeSet<PackageCapability>) -> Vec<u8> {
    capabilities
        .iter()
        .map(|capability| match capability {
            PackageCapability::FilesystemRead => b"filesystem-read".as_slice(),
            PackageCapability::FilesystemWrite => b"filesystem-write".as_slice(),
            PackageCapability::Network => b"network".as_slice(),
            PackageCapability::Process => b"process".as_slice(),
            PackageCapability::Secrets => b"secrets".as_slice(),
            PackageCapability::NativeCode => b"native-code".as_slice(),
        })
        .collect::<Vec<_>>()
        .join(&0)
}

/// Immutable release distributed by `ClawHub`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HubRelease {
    /// Release metadata.
    pub manifest: ReleaseManifest,
    /// Artifact bytes.
    pub artifact: Vec<u8>,
    /// SHA-256 artifact digest.
    pub digest: [u8; 32],
    /// Registered publisher identity.
    pub publisher_identity: String,
    /// Whether the publisher revoked this version.
    pub revoked: bool,
}

impl HubRelease {
    /// Recomputes and verifies the artifact digest.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::IntegrityMismatch`] when the artifact no longer
    /// matches its immutable digest.
    pub fn verify_integrity(&self) -> Result<(), ClawHubError> {
        let actual: [u8; 32] = Sha256::digest(&self.artifact).into();
        if actual == self.digest {
            Ok(())
        } else {
            Err(ClawHubError::IntegrityMismatch)
        }
    }
}

/// Search result without artifact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResult {
    /// Package identifier.
    pub package: PackageName,
    /// Latest non-revoked version.
    pub latest_version: Version,
    /// Latest description.
    pub description: String,
    /// Latest release risk.
    pub risk: RiskLevel,
}

/// Authenticated in-process `ClawHub` registry.
#[derive(Default)]
pub struct ClawHubRegistry {
    publishers: BTreeMap<String, PublisherRegistration>,
    releases: BTreeMap<PackageName, BTreeMap<Version, HubRelease>>,
    subscriptions: BTreeMap<PackageName, BTreeSet<String>>,
}

impl ClawHubRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an immutable publisher identity and authentication secret.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when the publisher or identity is invalid or the
    /// publisher is already registered.
    pub fn register_publisher(
        &mut self,
        publisher: String,
        identity: String,
        secret: PublisherSecret,
    ) -> Result<(), ClawHubError> {
        if !valid_component(&publisher)
            || identity.is_empty()
            || identity.len() > 256
            || identity.chars().any(char::is_control)
        {
            return Err(ClawHubError::InvalidPublisher);
        }
        if self.publishers.contains_key(&publisher) {
            return Err(ClawHubError::PublisherExists);
        }
        self.publishers
            .insert(publisher, PublisherRegistration { identity, secret });
        Ok(())
    }

    /// Verifies and publishes one immutable semantic version.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when validation, authentication, or immutable
    /// version checks fail.
    pub fn publish(&mut self, request: PublishRequest) -> Result<HubRelease, ClawHubError> {
        request.manifest.validate()?;
        if request.artifact.is_empty() || request.artifact.len() > MAX_ARTIFACT_BYTES {
            return Err(ClawHubError::InvalidArtifact);
        }
        let publisher = self
            .publishers
            .get(request.manifest.package.publisher())
            .ok_or(ClawHubError::PublisherNotFound)?;
        verify_publish(&publisher.secret, &request)?;
        let package_releases = self
            .releases
            .entry(request.manifest.package.clone())
            .or_default();
        if package_releases.contains_key(&request.manifest.version) {
            return Err(ClawHubError::VersionExists);
        }
        let digest = Sha256::digest(&request.artifact).into();
        let release = HubRelease {
            manifest: request.manifest,
            artifact: request.artifact,
            digest,
            publisher_identity: publisher.identity.clone(),
            revoked: false,
        };
        package_releases.insert(release.manifest.version.clone(), release.clone());
        Ok(release)
    }

    /// Searches latest non-revoked releases in stable package order.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::InvalidSearch`] when the query is empty,
    /// oversized, or contains control characters.
    pub fn search(&self, query: &str) -> Result<Vec<SearchResult>, ClawHubError> {
        let query = query.trim();
        if query.is_empty() || query.len() > 256 || query.chars().any(char::is_control) {
            return Err(ClawHubError::InvalidSearch);
        }
        let query = query.to_ascii_lowercase();
        let mut results = Vec::new();
        for (package, releases) in &self.releases {
            let Some(release) = releases.values().rev().find(|release| !release.revoked) else {
                continue;
            };
            if package.canonical().to_ascii_lowercase().contains(&query)
                || release
                    .manifest
                    .description
                    .to_ascii_lowercase()
                    .contains(&query)
            {
                results.push(SearchResult {
                    package: package.clone(),
                    latest_version: release.manifest.version.clone(),
                    description: release.manifest.description.clone(),
                    risk: release.manifest.risk(),
                });
            }
            if results.len() == MAX_SEARCH_RESULTS {
                break;
            }
        }
        Ok(results)
    }

    /// Fetches an exact release, including revoked state.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::ReleaseNotFound`] when the exact package version
    /// is absent.
    pub fn fetch(
        &self,
        package: &PackageName,
        version: &Version,
    ) -> Result<HubRelease, ClawHubError> {
        self.releases
            .get(package)
            .and_then(|releases| releases.get(version))
            .cloned()
            .ok_or(ClawHubError::ReleaseNotFound)
    }

    /// Fetches the latest non-revoked stable release.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::ReleaseNotFound`] when no eligible release
    /// exists.
    pub fn latest(&self, package: &PackageName) -> Result<HubRelease, ClawHubError> {
        self.releases
            .get(package)
            .and_then(|releases| releases.values().rev().find(|release| !release.revoked))
            .cloned()
            .ok_or(ClawHubError::ReleaseNotFound)
    }

    /// Authenticates a publisher and revokes one exact version.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when the publisher, signature, or release cannot
    /// be verified.
    pub fn revoke(
        &mut self,
        package: &PackageName,
        version: &Version,
        signature: &str,
    ) -> Result<(), ClawHubError> {
        let publisher = self
            .publishers
            .get(package.publisher())
            .ok_or(ClawHubError::PublisherNotFound)?;
        verify_revocation(&publisher.secret, package, version, signature)?;
        let release = self
            .releases
            .get_mut(package)
            .and_then(|releases| releases.get_mut(version))
            .ok_or(ClawHubError::ReleaseNotFound)?;
        release.revoked = true;
        Ok(())
    }

    /// Subscribes a stable consumer identifier to package updates.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::InvalidSubscription`] when the subscriber is
    /// invalid or the package has no published release.
    pub fn subscribe(
        &mut self,
        subscriber_id: String,
        package: PackageName,
    ) -> Result<(), ClawHubError> {
        if !valid_component(&subscriber_id) || !self.releases.contains_key(&package) {
            return Err(ClawHubError::InvalidSubscription);
        }
        self.subscriptions
            .entry(package)
            .or_default()
            .insert(subscriber_id);
        Ok(())
    }

    /// Removes one package subscription.
    pub fn unsubscribe(&mut self, subscriber_id: &str, package: &PackageName) -> bool {
        self.subscriptions
            .get_mut(package)
            .is_some_and(|subscribers| subscribers.remove(subscriber_id))
    }

    /// Returns subscribers for release distribution.
    #[must_use]
    pub fn subscribers(&self, package: &PackageName) -> Vec<&str> {
        self.subscriptions
            .get(package)
            .map_or_else(Vec::new, |subscribers| {
                subscribers.iter().map(String::as_str).collect()
            })
    }
}

/// Exact publisher identities trusted for installation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustPolicy {
    publishers: BTreeMap<String, String>,
}

impl TrustPolicy {
    /// Creates an empty fail-closed policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pins one publisher to an exact registry identity.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::InvalidPublisher`] when either identifier is
    /// invalid.
    pub fn trust(&mut self, publisher: String, identity: String) -> Result<(), ClawHubError> {
        if !valid_component(&publisher)
            || identity.is_empty()
            || identity.len() > 256
            || identity.chars().any(char::is_control)
        {
            return Err(ClawHubError::InvalidPublisher);
        }
        self.publishers.insert(publisher, identity);
        Ok(())
    }

    fn verify(&self, release: &HubRelease) -> Result<(), ClawHubError> {
        if self
            .publishers
            .get(release.manifest.package.publisher())
            .is_some_and(|identity| identity == &release.publisher_identity)
        {
            Ok(())
        } else {
            Err(ClawHubError::UntrustedPublisher)
        }
    }
}

/// Explicit acknowledgement bound to one risky immutable release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskAcknowledgement {
    /// Package identifier.
    pub package: PackageName,
    /// Exact version.
    pub version: Version,
    /// Exact artifact digest.
    pub digest: [u8; 32],
}

/// Installed release record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRelease {
    /// Package identifier.
    pub package: PackageName,
    /// Installed version.
    pub version: Version,
    /// Installed artifact digest.
    pub digest: [u8; 32],
}

/// Artifact installation boundary.
pub trait ArtifactStore {
    /// Atomically installs an immutable artifact bundle.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when the artifact cannot be installed
    /// atomically.
    fn install(&self, release: &HubRelease) -> Result<(), ClawHubError>;
    /// Removes all installed versions of one package.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when the package artifacts cannot be removed.
    fn uninstall(&self, package: &PackageName) -> Result<(), ClawHubError>;
}

/// Filesystem bundle store that never extracts untrusted archive paths.
pub struct FilesystemArtifactStore {
    root: PathBuf,
}

impl FilesystemArtifactStore {
    /// Creates a store rooted in caller-selected application data.
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn package_root(&self, package: &PackageName) -> PathBuf {
        let digest = Sha256::digest(package.canonical().as_bytes());
        self.root.join(format!("package-{}", encode_hex(&digest)))
    }

    fn existing_artifact_matches(
        path: &std::path::Path,
        expected_digest: &[u8; 32],
    ) -> Result<bool, ClawHubError> {
        let metadata = fs::metadata(path).map_err(ClawHubError::Io)?;
        if metadata.len() > MAX_ARTIFACT_BYTES as u64 {
            return Ok(false);
        }
        let artifact = fs::read(path).map_err(ClawHubError::Io)?;
        let digest: [u8; 32] = Sha256::digest(&artifact).into();
        Ok(&digest == expected_digest)
    }

    fn create_temporary(version_root: &std::path::Path) -> Result<(PathBuf, File), ClawHubError> {
        for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
            let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
            let path = version_root.join(format!("artifact.tmp-{}-{sequence}", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(ClawHubError::Io(error)),
            }
        }
        Err(ClawHubError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate immutable artifact temporary file",
        )))
    }

    fn cleanup_after_error(path: &std::path::Path, operation: io::Error) -> ClawHubError {
        match fs::remove_file(path) {
            Ok(()) => ClawHubError::Io(operation),
            Err(cleanup) => ClawHubError::ArtifactInstallCleanup {
                operation: operation.to_string(),
                cleanup: cleanup.to_string(),
            },
        }
    }
}

impl ArtifactStore for FilesystemArtifactStore {
    fn install(&self, release: &HubRelease) -> Result<(), ClawHubError> {
        let version_root = self
            .package_root(&release.manifest.package)
            .join(release.manifest.version.to_string());
        fs::create_dir_all(&version_root).map_err(ClawHubError::Io)?;
        let final_path = version_root.join("artifact.bin");
        if final_path.exists() {
            return if Self::existing_artifact_matches(&final_path, &release.digest)? {
                Ok(())
            } else {
                Err(ClawHubError::ArtifactConflict)
            };
        }
        let (temporary_path, mut temporary) = Self::create_temporary(&version_root)?;
        if let Err(error) = temporary
            .write_all(&release.artifact)
            .and_then(|()| temporary.sync_all())
        {
            drop(temporary);
            return Err(Self::cleanup_after_error(&temporary_path, error));
        }
        drop(temporary);
        match fs::hard_link(&temporary_path, &final_path) {
            Ok(()) => {
                fs::remove_file(temporary_path).map_err(ClawHubError::Io)?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = Self::existing_artifact_matches(&final_path, &release.digest);
                let cleanup = fs::remove_file(temporary_path);
                match (existing, cleanup) {
                    (Ok(true), Ok(())) => Ok(()),
                    (Ok(false), Ok(())) => Err(ClawHubError::ArtifactConflict),
                    (Err(operation), Ok(())) => Err(operation),
                    (Ok(_), Err(cleanup)) => Err(ClawHubError::Io(cleanup)),
                    (Err(operation), Err(cleanup)) => Err(ClawHubError::ArtifactInstallCleanup {
                        operation: operation.to_string(),
                        cleanup: cleanup.to_string(),
                    }),
                }
            }
            Err(error) => Err(Self::cleanup_after_error(&temporary_path, error)),
        }
    }

    fn uninstall(&self, package: &PackageName) -> Result<(), ClawHubError> {
        let path = self.package_root(package);
        if path.exists() {
            fs::remove_dir_all(path).map_err(ClawHubError::Io)?;
        }
        Ok(())
    }
}

/// Trusted local install, update, and revocation lifecycle.
pub struct ClawHubLifecycle<S> {
    store: S,
    trust: TrustPolicy,
    installed: BTreeMap<PackageName, InstalledRelease>,
    subscriptions: BTreeSet<PackageName>,
}

impl<S: ArtifactStore> ClawHubLifecycle<S> {
    /// Creates a lifecycle manager with no installed packages.
    #[must_use]
    pub const fn new(store: S, trust: TrustPolicy) -> Self {
        Self {
            store,
            trust,
            installed: BTreeMap::new(),
            subscriptions: BTreeSet::new(),
        }
    }

    /// Installs one exact release after trust, integrity, revocation, and risk checks.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when the release fails policy checks, is already
    /// installed, or cannot be persisted.
    pub fn install(
        &mut self,
        registry: &ClawHubRegistry,
        package: &PackageName,
        version: &Version,
        acknowledgement: Option<&RiskAcknowledgement>,
    ) -> Result<InstalledRelease, ClawHubError> {
        if self.installed.contains_key(package) {
            return Err(ClawHubError::AlreadyInstalled);
        }
        let release = registry.fetch(package, version)?;
        self.install_release(release, acknowledgement)
    }

    /// Updates to the latest non-revoked version.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when the package is absent, has no newer
    /// eligible release, fails policy checks, or cannot be persisted.
    pub fn update(
        &mut self,
        registry: &ClawHubRegistry,
        package: &PackageName,
        acknowledgement: Option<&RiskAcknowledgement>,
    ) -> Result<InstalledRelease, ClawHubError> {
        let installed = self
            .installed
            .get(package)
            .ok_or(ClawHubError::NotInstalled)?;
        let release = registry.latest(package)?;
        if release.manifest.version <= installed.version {
            return Err(ClawHubError::NoUpdate);
        }
        self.install_release(release, acknowledgement)
    }

    fn install_release(
        &mut self,
        release: HubRelease,
        acknowledgement: Option<&RiskAcknowledgement>,
    ) -> Result<InstalledRelease, ClawHubError> {
        if release.revoked {
            return Err(ClawHubError::Revoked);
        }
        release.verify_integrity()?;
        self.trust.verify(&release)?;
        match release.manifest.risk() {
            RiskLevel::Low => {}
            RiskLevel::AcknowledgementRequired => {
                let valid = acknowledgement.is_some_and(|acknowledgement| {
                    acknowledgement.package == release.manifest.package
                        && acknowledgement.version == release.manifest.version
                        && acknowledgement.digest == release.digest
                });
                if !valid {
                    return Err(ClawHubError::RiskAcknowledgementRequired);
                }
            }
            RiskLevel::Blocked => return Err(ClawHubError::RiskBlocked),
        }
        self.store.install(&release)?;
        let installed = InstalledRelease {
            package: release.manifest.package.clone(),
            version: release.manifest.version,
            digest: release.digest,
        };
        self.installed
            .insert(installed.package.clone(), installed.clone());
        Ok(installed)
    }

    /// Removes one installed package.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when the package is not installed or its
    /// artifacts cannot be removed.
    pub fn uninstall(&mut self, package: &PackageName) -> Result<(), ClawHubError> {
        if !self.installed.contains_key(package) {
            return Err(ClawHubError::NotInstalled);
        }
        self.store.uninstall(package)?;
        self.installed.remove(package);
        self.subscriptions.remove(package);
        Ok(())
    }

    /// Enables latest-version update checks for an installed package.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError::NotInstalled`] when the package is not installed.
    pub fn subscribe(&mut self, package: &PackageName) -> Result<(), ClawHubError> {
        if !self.installed.contains_key(package) {
            return Err(ClawHubError::NotInstalled);
        }
        self.subscriptions.insert(package.clone());
        Ok(())
    }

    /// Returns subscribed packages with a newer non-revoked version.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when an installed subscription or registry
    /// release cannot be resolved.
    pub fn available_updates(
        &self,
        registry: &ClawHubRegistry,
    ) -> Result<Vec<(PackageName, Version)>, ClawHubError> {
        let mut updates = Vec::new();
        for package in &self.subscriptions {
            let installed = self
                .installed
                .get(package)
                .ok_or(ClawHubError::NotInstalled)?;
            let latest = registry.latest(package)?;
            if latest.manifest.version > installed.version {
                updates.push((package.clone(), latest.manifest.version));
            }
        }
        Ok(updates)
    }

    /// Uninstalls any installed release later marked revoked.
    ///
    /// # Errors
    ///
    /// Returns [`ClawHubError`] when registry state cannot be resolved or a
    /// revoked artifact cannot be removed.
    pub fn enforce_revocations(
        &mut self,
        registry: &ClawHubRegistry,
    ) -> Result<Vec<PackageName>, ClawHubError> {
        let installed = self.installed.values().cloned().collect::<Vec<_>>();
        let mut removed = Vec::new();
        for record in installed {
            if registry.fetch(&record.package, &record.version)?.revoked {
                self.uninstall(&record.package)?;
                removed.push(record.package);
            }
        }
        Ok(removed)
    }

    /// Returns one installed record.
    #[must_use]
    pub fn installed(&self, package: &PackageName) -> Option<&InstalledRelease> {
        self.installed.get(package)
    }
}

fn valid_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && !value.starts_with('-')
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `ClawHub` authentication, policy, integrity, or lifecycle failure.
#[derive(Debug)]
pub enum ClawHubError {
    /// Package identifier is malformed.
    InvalidPackage,
    /// Publisher registration is malformed.
    InvalidPublisher,
    /// Publisher is already registered.
    PublisherExists,
    /// Publisher is not registered.
    PublisherNotFound,
    /// Publisher secret is too short.
    WeakPublisherSecret,
    /// Release metadata is malformed.
    InvalidManifest,
    /// Artifact is empty or exceeds its bound.
    InvalidArtifact,
    /// Publish or revocation HMAC is malformed or incorrect.
    InvalidSignature,
    /// HMAC implementation rejected its key state.
    SigningState,
    /// Version already exists and cannot be overwritten.
    VersionExists,
    /// Search query is malformed.
    InvalidSearch,
    /// Release does not exist.
    ReleaseNotFound,
    /// Subscription is malformed.
    InvalidSubscription,
    /// Artifact digest does not match immutable metadata.
    IntegrityMismatch,
    /// An immutable package version already contains different artifact bytes.
    ArtifactConflict,
    /// Artifact installation failed and its temporary file could not be removed.
    ArtifactInstallCleanup {
        /// Installation failure.
        operation: String,
        /// Temporary-file cleanup failure.
        cleanup: String,
    },
    /// Publisher identity is not explicitly trusted.
    UntrustedPublisher,
    /// Risk acknowledgement is missing or not digest-bound.
    RiskAcknowledgementRequired,
    /// Native-code risk is blocked.
    RiskBlocked,
    /// Release was revoked.
    Revoked,
    /// Package is already installed.
    AlreadyInstalled,
    /// Package is not installed.
    NotInstalled,
    /// No newer non-revoked release exists.
    NoUpdate,
    /// Artifact storage failed.
    Io(std::io::Error),
}

impl Display for ClawHubError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPackage => formatter.write_str("invalid ClawHub package"),
            Self::InvalidPublisher => formatter.write_str("invalid ClawHub publisher"),
            Self::PublisherExists => formatter.write_str("ClawHub publisher already exists"),
            Self::PublisherNotFound => formatter.write_str("ClawHub publisher not found"),
            Self::WeakPublisherSecret => {
                formatter.write_str("ClawHub publisher secret is too short")
            }
            Self::InvalidManifest => formatter.write_str("invalid ClawHub release manifest"),
            Self::InvalidArtifact => formatter.write_str("invalid ClawHub artifact"),
            Self::InvalidSignature => formatter.write_str("invalid ClawHub publisher signature"),
            Self::SigningState => formatter.write_str("ClawHub signing unavailable"),
            Self::VersionExists => formatter.write_str("ClawHub version already exists"),
            Self::InvalidSearch => formatter.write_str("invalid ClawHub search"),
            Self::ReleaseNotFound => formatter.write_str("ClawHub release not found"),
            Self::InvalidSubscription => formatter.write_str("invalid ClawHub subscription"),
            Self::IntegrityMismatch => formatter.write_str("ClawHub artifact integrity mismatch"),
            Self::ArtifactConflict => {
                formatter.write_str("ClawHub artifact version already has different bytes")
            }
            Self::ArtifactInstallCleanup { operation, cleanup } => write!(
                formatter,
                "ClawHub artifact installation failed ({operation}) and cleanup failed ({cleanup})"
            ),
            Self::UntrustedPublisher => formatter.write_str("untrusted ClawHub publisher"),
            Self::RiskAcknowledgementRequired => {
                formatter.write_str("ClawHub risk acknowledgement required")
            }
            Self::RiskBlocked => formatter.write_str("ClawHub release risk is blocked"),
            Self::Revoked => formatter.write_str("ClawHub release is revoked"),
            Self::AlreadyInstalled => formatter.write_str("ClawHub package already installed"),
            Self::NotInstalled => formatter.write_str("ClawHub package not installed"),
            Self::NoUpdate => formatter.write_str("no ClawHub update available"),
            Self::Io(error) => write!(formatter, "ClawHub artifact storage failed: {error}"),
        }
    }
}

impl Error for ClawHubError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        installed: Mutex<BTreeMap<PackageName, Vec<u8>>>,
    }

    impl ArtifactStore for MemoryStore {
        fn install(&self, release: &HubRelease) -> Result<(), ClawHubError> {
            self.installed
                .lock()
                .expect("installed")
                .insert(release.manifest.package.clone(), release.artifact.clone());
            Ok(())
        }

        fn uninstall(&self, package: &PackageName) -> Result<(), ClawHubError> {
            self.installed.lock().expect("installed").remove(package);
            Ok(())
        }
    }

    fn publisher_secret() -> PublisherSecret {
        PublisherSecret::new(SecretString::from(
            "publisher-secret-32-bytes-minimum!".to_owned(),
        ))
        .expect("secret")
    }

    fn package() -> PackageName {
        PackageName::new("gtastudio".to_owned(), "taskflow".to_owned()).expect("package")
    }

    fn manifest(version: &str, risky: bool) -> ReleaseManifest {
        ReleaseManifest {
            package: package(),
            version: Version::parse(version).expect("version"),
            description: "TaskFlow extension distribution".to_owned(),
            capabilities: if risky {
                std::iter::once(PackageCapability::Network).collect()
            } else {
                std::iter::once(PackageCapability::FilesystemRead).collect()
            },
        }
    }

    fn publish(
        registry: &mut ClawHubRegistry,
        version: &str,
        artifact: &[u8],
        risky: bool,
    ) -> HubRelease {
        let manifest = manifest(version, risky);
        let signature = sign_publish(&publisher_secret(), &manifest, artifact).expect("signature");
        registry
            .publish(PublishRequest {
                manifest,
                artifact: artifact.to_vec(),
                signature,
            })
            .expect("publish")
    }

    fn registry() -> ClawHubRegistry {
        let mut registry = ClawHubRegistry::new();
        registry
            .register_publisher(
                "gtastudio".to_owned(),
                "publisher-key-2026".to_owned(),
                publisher_secret(),
            )
            .expect("register");
        registry
    }

    fn trust() -> TrustPolicy {
        let mut trust = TrustPolicy::new();
        trust
            .trust("gtastudio".to_owned(), "publisher-key-2026".to_owned())
            .expect("trust");
        trust
    }

    #[test]
    fn register_publish_search_install_update_subscribe_uninstall() {
        let mut registry = registry();
        let first = publish(&mut registry, "1.0.0", b"artifact-v1", false);
        assert_eq!(
            registry.search("taskflow").expect("search"),
            vec![SearchResult {
                package: package(),
                latest_version: Version::new(1, 0, 0),
                description: "TaskFlow extension distribution".to_owned(),
                risk: RiskLevel::Low,
            }]
        );
        registry
            .subscribe("desktop".to_owned(), package())
            .expect("registry subscription");
        assert_eq!(registry.subscribers(&package()), vec!["desktop"]);

        let mut lifecycle = ClawHubLifecycle::new(MemoryStore::default(), trust());
        assert_eq!(
            lifecycle
                .install(&registry, &package(), &Version::new(1, 0, 0), None)
                .expect("install"),
            InstalledRelease {
                package: package(),
                version: Version::new(1, 0, 0),
                digest: first.digest,
            }
        );
        lifecycle.subscribe(&package()).expect("subscribe");
        publish(&mut registry, "1.1.0", b"artifact-v1.1", false);
        assert_eq!(
            lifecycle.available_updates(&registry).expect("updates"),
            vec![(package(), Version::new(1, 1, 0))]
        );
        assert_eq!(
            lifecycle
                .update(&registry, &package(), None)
                .expect("update")
                .version,
            Version::new(1, 1, 0)
        );
        lifecycle.uninstall(&package()).expect("uninstall");
        assert_eq!(lifecycle.installed(&package()), None);
    }

    #[test]
    fn risk_acknowledgement_is_bound_to_version_and_digest() {
        let mut registry = registry();
        let release = publish(&mut registry, "2.0.0", b"risky-artifact", true);
        let mut lifecycle = ClawHubLifecycle::new(MemoryStore::default(), trust());
        let wrong = RiskAcknowledgement {
            package: package(),
            version: Version::new(2, 0, 0),
            digest: [0; 32],
        };
        assert!(matches!(
            lifecycle.install(&registry, &package(), &Version::new(2, 0, 0), Some(&wrong)),
            Err(ClawHubError::RiskAcknowledgementRequired)
        ));
        let exact = RiskAcknowledgement {
            package: package(),
            version: Version::new(2, 0, 0),
            digest: release.digest,
        };
        assert_eq!(
            lifecycle
                .install(&registry, &package(), &Version::new(2, 0, 0), Some(&exact))
                .expect("acknowledged")
                .digest,
            release.digest
        );
    }

    #[test]
    fn forged_publish_tampering_and_revocation_fail_closed() {
        let mut registry = registry();
        let manifest = manifest("1.0.0", false);
        let mut signature =
            sign_publish(&publisher_secret(), &manifest, b"artifact").expect("signature");
        signature.replace_range(2..3, "f");
        assert!(matches!(
            registry.publish(PublishRequest {
                manifest,
                artifact: b"artifact".to_vec(),
                signature,
            }),
            Err(ClawHubError::InvalidSignature)
        ));

        let release = publish(&mut registry, "1.0.0", b"artifact", false);
        let mut tampered = release;
        tampered.artifact[0] ^= 1;
        assert!(matches!(
            tampered.verify_integrity(),
            Err(ClawHubError::IntegrityMismatch)
        ));

        let revocation = sign_revocation(&publisher_secret(), &package(), &Version::new(1, 0, 0))
            .expect("revocation");
        registry
            .revoke(&package(), &Version::new(1, 0, 0), &revocation)
            .expect("revoke");
        let mut lifecycle = ClawHubLifecycle::new(MemoryStore::default(), trust());
        assert!(matches!(
            lifecycle.install(&registry, &package(), &Version::new(1, 0, 0), None),
            Err(ClawHubError::Revoked)
        ));
    }

    #[test]
    fn filesystem_store_separates_case_distinct_package_ids() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "gta-claw-clawhub-case-{}-{unique}",
            std::process::id()
        ));
        let store = FilesystemArtifactStore::new(root.clone());
        let upper = PackageName::new("acme".to_owned(), "Tool".to_owned()).expect("upper package");
        let lower = PackageName::new("acme".to_owned(), "tool".to_owned()).expect("lower package");
        let release = |package: PackageName, artifact: &[u8]| HubRelease {
            manifest: ReleaseManifest {
                package,
                version: Version::new(1, 0, 0),
                description: "case-sensitive fixture".to_owned(),
                capabilities: std::iter::once(PackageCapability::FilesystemRead).collect(),
            },
            artifact: artifact.to_vec(),
            digest: Sha256::digest(artifact).into(),
            publisher_identity: "publisher-key".to_owned(),
            revoked: false,
        };

        let upper_release = release(upper.clone(), b"upper-artifact");
        store.install(&upper_release).expect("install upper");
        store
            .install(&upper_release)
            .expect("idempotent immutable install");
        assert!(matches!(
            store.install(&release(upper.clone(), b"conflicting-artifact")),
            Err(ClawHubError::ArtifactConflict)
        ));
        store
            .install(&release(lower.clone(), b"lower-artifact"))
            .expect("install lower");
        let upper_root = store.package_root(&upper);
        let lower_root = store.package_root(&lower);
        assert_ne!(upper_root, lower_root);
        assert_eq!(
            fs::read(upper_root.join("1.0.0").join("artifact.bin")).expect("read upper"),
            b"upper-artifact"
        );
        assert_eq!(
            fs::read(lower_root.join("1.0.0").join("artifact.bin")).expect("read lower"),
            b"lower-artifact"
        );

        store.uninstall(&upper).expect("uninstall upper");
        assert!(!upper_root.exists());
        assert_eq!(
            fs::read(lower_root.join("1.0.0").join("artifact.bin")).expect("lower remains"),
            b"lower-artifact"
        );
        fs::remove_dir_all(root).expect("cleanup store");
    }
}

//! Signed, resumable, and rollback-safe GTA Claw updater.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use futures_util::StreamExt as _;
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use reqwest::{Client, StatusCode};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::{Host, Url};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const BUNDLE_MAGIC: &str = "gta-claw-bundle-v1";

/// Compiled maintainer-controlled Ed25519 release key.
pub const PRODUCTION_PUBLIC_KEY: [u8; 32] = [
    0x78, 0x4b, 0x3d, 0xa0, 0x7d, 0x28, 0x47, 0xf2, 0x87, 0x48, 0x2c, 0xec, 0xc4, 0x5d, 0xd3, 0x65,
    0xad, 0xe6, 0x05, 0x2f, 0x7c, 0xf3, 0x44, 0x51, 0x2c, 0xb6, 0x70, 0x54, 0x26, 0xfa, 0xd4, 0xea,
];

/// Signed release metadata. The signature covers the canonical JSON encoding of `manifest`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    /// Trusted release data.
    pub manifest: ReleaseManifest,
    /// Standard-base64 Ed25519 signature.
    pub signature: String,
}

/// Exact signed release payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    /// Semantic release version.
    pub version: String,
    /// Informational publication timestamp.
    pub published_at: String,
    /// Platform artifacts.
    pub artifacts: Vec<ReleaseArtifact>,
}

/// One signed update artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    /// Exact Rust target triple.
    pub target: String,
    /// HTTPS URL, or loopback HTTP URL for local operation and tests.
    pub url: String,
    /// Lowercase SHA-256 hex digest.
    pub sha256: String,
    /// Exact expected byte length.
    pub size: u64,
    /// Installation format.
    pub kind: ArtifactKind,
}

/// Signed artifact format.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// One native executable.
    Executable,
    /// A safe JSON bundle archive that expands to a macOS `.app` directory.
    MacOsBundle,
}

/// Verified release decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateDecision {
    /// Installed version is current.
    Current {
        /// Current version.
        version: Version,
    },
    /// A newer signed artifact is available.
    Available {
        /// New release version.
        version: Version,
        /// Matching target artifact.
        artifact: ReleaseArtifact,
    },
}

/// Local installation shape. It is never sourced from the manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallMode {
    /// Replace one executable.
    Executable,
    /// Replace one complete `.app` bundle.
    MacOsBundle,
    /// Distribution packages own updates.
    LinuxPackage,
}

/// Trusted local install destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallTarget {
    path: PathBuf,
    mode: InstallMode,
}

impl InstallTarget {
    /// Validates a caller-selected local destination.
    pub fn new(path: PathBuf, mode: InstallMode) -> Result<Self, UpdateError> {
        if path.file_name().is_none() || path.parent().is_none() {
            return Err(UpdateError::InvalidInstallTarget);
        }
        if mode == InstallMode::MacOsBundle
            && path.extension().and_then(|value| value.to_str()) != Some("app")
        {
            return Err(UpdateError::InvalidInstallTarget);
        }
        Ok(Self { path, mode })
    }

    /// Returns the trusted local destination.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the installation shape.
    #[must_use]
    pub const fn mode(&self) -> InstallMode {
        self.mode
    }
}

/// Result of a complete updater run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateOutcome {
    /// Linux package management owns updates; no network or filesystem work occurred.
    SystemManaged,
    /// The installed version was already current.
    Current(Version),
    /// The update was installed atomically.
    Installed(Version),
    /// Windows kept the target locked. The verified replacement remains staged.
    RestartRequired {
        /// New version.
        version: Version,
        /// Locally derived verified staging path.
        staged_path: PathBuf,
    },
}

/// Signed updater client.
#[derive(Clone)]
pub struct Updater {
    client: Client,
    verifying_key: VerifyingKey,
    target_triple: String,
}

impl Updater {
    /// Creates the production updater with a compiled trust root.
    pub fn production(target_triple: impl Into<String>) -> Result<Self, UpdateError> {
        Self::with_public_key(PRODUCTION_PUBLIC_KEY, target_triple)
    }

    /// Creates an updater with an explicit trust root, primarily for isolated tests.
    pub fn with_public_key(
        public_key: [u8; 32],
        target_triple: impl Into<String>,
    ) -> Result<Self, UpdateError> {
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| UpdateError::InvalidPublicKey)?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(300))
            .user_agent(concat!("gta-claw-updater/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(UpdateError::Http)?;
        Ok(Self {
            client,
            verifying_key,
            target_triple: target_triple.into(),
        })
    }

    /// Fetches, bounds, and verifies a release manifest before comparing versions.
    pub async fn check(
        &self,
        manifest_url: &Url,
        current: &Version,
    ) -> Result<UpdateDecision, UpdateError> {
        validate_network_url(manifest_url)?;
        let response = self
            .client
            .get(manifest_url.clone())
            .send()
            .await
            .map_err(UpdateError::Http)?;
        ensure_success(response.status())?;
        let bytes = read_response_limited(response, MAX_MANIFEST_BYTES).await?;
        let manifest = self.verify_manifest(&bytes)?;
        let available =
            Version::parse(&manifest.version).map_err(|_| UpdateError::InvalidVersion)?;
        if available <= *current {
            return Ok(UpdateDecision::Current {
                version: current.clone(),
            });
        }
        let artifact = manifest
            .artifacts
            .into_iter()
            .find(|artifact| artifact.target == self.target_triple)
            .ok_or(UpdateError::ArtifactUnavailable)?;
        validate_artifact(&artifact)?;
        Ok(UpdateDecision::Available {
            version: available,
            artifact,
        })
    }

    /// Strictly verifies signed manifest bytes.
    pub fn verify_manifest(&self, bytes: &[u8]) -> Result<ReleaseManifest, UpdateError> {
        if bytes.len() > usize::try_from(MAX_MANIFEST_BYTES).expect("manifest cap fits usize") {
            return Err(UpdateError::ManifestTooLarge);
        }
        let envelope: SignedManifest =
            serde_json::from_slice(bytes).map_err(UpdateError::ManifestJson)?;
        let signature_bytes = STANDARD
            .decode(envelope.signature.as_bytes())
            .map_err(|_| UpdateError::InvalidSignatureEncoding)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| UpdateError::InvalidSignatureEncoding)?;
        let canonical =
            serde_json::to_vec(&envelope.manifest).map_err(UpdateError::ManifestJson)?;
        self.verifying_key
            .verify(&canonical, &signature)
            .map_err(|_| UpdateError::ForgedManifest)?;
        Version::parse(&envelope.manifest.version).map_err(|_| UpdateError::InvalidVersion)?;
        for artifact in &envelope.manifest.artifacts {
            validate_artifact(artifact)?;
        }
        Ok(envelope.manifest)
    }

    /// Downloads one signed artifact with safe resume and verifies exact size and SHA-256.
    pub async fn download(
        &self,
        artifact: &ReleaseArtifact,
        target: &InstallTarget,
    ) -> Result<VerifiedArtifact, UpdateError> {
        validate_artifact(artifact)?;
        ensure_kind_matches(artifact.kind, target.mode)?;
        let url = Url::parse(&artifact.url).map_err(|_| UpdateError::InvalidArtifactUrl)?;
        validate_network_url(&url)?;
        let part_path = sibling_path(&target.path, "part")?;
        let staged_path = sibling_path(&target.path, "verified")?;
        let mut offset = match tokio::fs::symlink_metadata(&part_path).await {
            Ok(metadata) if metadata.is_file() && metadata.len() <= artifact.size => metadata.len(),
            Ok(_) => {
                remove_path_if_exists(&part_path).await?;
                0
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(UpdateError::Io(error)),
        };
        let mut downloaded = offset;
        if offset < artifact.size {
            let mut request = self.client.get(url);
            if offset > 0 {
                request = request.header(RANGE, format!("bytes={offset}-"));
            }
            let response = request.send().await.map_err(UpdateError::Http)?;
            if offset > 0 {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    validate_content_range(&response, offset, artifact.size)?;
                } else if response.status().is_success() {
                    offset = 0;
                    downloaded = 0;
                } else {
                    return Err(UpdateError::HttpStatus(response.status().as_u16()));
                }
            } else {
                ensure_success(response.status())?;
            }

            let mut options = tokio::fs::OpenOptions::new();
            options.create(true).write(true);
            if offset == 0 {
                options.truncate(true);
            } else {
                options.append(true);
            }
            let mut file = options.open(&part_path).await.map_err(UpdateError::Io)?;
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(UpdateError::Http)?;
                downloaded = downloaded
                    .checked_add(
                        u64::try_from(chunk.len()).map_err(|_| UpdateError::ArtifactTooLarge)?,
                    )
                    .ok_or(UpdateError::ArtifactTooLarge)?;
                if downloaded > artifact.size {
                    return Err(UpdateError::ArtifactTooLarge);
                }
                file.write_all(&chunk).await.map_err(UpdateError::Io)?;
            }
            file.flush().await.map_err(UpdateError::Io)?;
            file.sync_all().await.map_err(UpdateError::Io)?;
        }
        if downloaded != artifact.size {
            return Err(UpdateError::InterruptedDownload {
                expected: artifact.size,
                received: downloaded,
            });
        }
        let digest = hash_file(&part_path).await?;
        let expected = decode_sha256(&artifact.sha256)?;
        if digest != expected {
            let _ = tokio::fs::remove_file(&part_path).await;
            return Err(UpdateError::HashMismatch);
        }
        remove_path_if_exists(&staged_path).await?;
        tokio::fs::rename(&part_path, &staged_path)
            .await
            .map_err(UpdateError::Io)?;
        Ok(VerifiedArtifact {
            path: staged_path,
            digest,
            size: artifact.size,
            kind: artifact.kind,
        })
    }

    /// Re-verifies and atomically installs a previously downloaded artifact.
    pub async fn install(
        &self,
        verified: VerifiedArtifact,
        target: &InstallTarget,
    ) -> Result<InstallOutcome, UpdateError> {
        ensure_kind_matches(verified.kind, target.mode)?;
        let metadata = tokio::fs::metadata(&verified.path)
            .await
            .map_err(UpdateError::Io)?;
        if metadata.len() != verified.size || hash_file(&verified.path).await? != verified.digest {
            return Err(UpdateError::StagedArtifactChanged);
        }
        let prepared = match verified.kind {
            ArtifactKind::Executable => verified.path,
            ArtifactKind::MacOsBundle => prepare_bundle(&verified.path, target).await?,
        };
        atomic_swap(&RealFileOps, &prepared, &target.path, cfg!(windows))
    }

    /// Runs the full signed update flow.
    pub async fn execute(
        &self,
        manifest_url: &Url,
        current: &Version,
        target: &InstallTarget,
    ) -> Result<UpdateOutcome, UpdateError> {
        if target.mode == InstallMode::LinuxPackage {
            return Ok(UpdateOutcome::SystemManaged);
        }
        match self.check(manifest_url, current).await? {
            UpdateDecision::Current { version } => Ok(UpdateOutcome::Current(version)),
            UpdateDecision::Available { version, artifact } => {
                let verified = self.download(&artifact, target).await?;
                match self.install(verified, target).await? {
                    InstallOutcome::Installed => Ok(UpdateOutcome::Installed(version)),
                    InstallOutcome::RestartRequired { staged_path } => {
                        Ok(UpdateOutcome::RestartRequired {
                            version,
                            staged_path,
                        })
                    }
                }
            }
        }
    }
}

/// Opaque proof that one staged artifact passed signature, size, and hash checks.
#[derive(Debug)]
pub struct VerifiedArtifact {
    path: PathBuf,
    digest: [u8; 32],
    size: u64,
    kind: ArtifactKind,
}

impl VerifiedArtifact {
    /// Returns the locally derived staging path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Atomic installation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallOutcome {
    /// Replacement completed.
    Installed,
    /// A Windows lock prevented the swap; verified bytes remain staged.
    RestartRequired {
        /// Locally derived staging path.
        staged_path: PathBuf,
    },
}

/// Explicit updater failures.
#[derive(Debug)]
pub enum UpdateError {
    /// Compiled or test key is not a canonical Ed25519 public key.
    InvalidPublicKey,
    /// URL is not HTTPS or loopback HTTP.
    InsecureUrl,
    /// URL embeds credentials or a fragment.
    CredentialBearingUrl,
    /// Manifest response exceeded its fixed cap.
    ManifestTooLarge,
    /// Signed JSON was malformed.
    ManifestJson(serde_json::Error),
    /// Signature was not standard-base64 Ed25519 data.
    InvalidSignatureEncoding,
    /// Signature did not match the exact manifest.
    ForgedManifest,
    /// Release version was not valid SemVer.
    InvalidVersion,
    /// No artifact matches this exact target triple.
    ArtifactUnavailable,
    /// Artifact URL was malformed.
    InvalidArtifactUrl,
    /// Artifact SHA-256 was not 64 lowercase hex characters.
    InvalidArtifactHash,
    /// Artifact length is zero.
    InvalidArtifactSize,
    /// HTTP request failed.
    Http(reqwest::Error),
    /// Server returned a non-success status.
    HttpStatus(u16),
    /// Resume response did not exactly match the requested range.
    InvalidContentRange,
    /// More bytes arrived than the signed manifest allows.
    ArtifactTooLarge,
    /// Connection ended before the signed byte length.
    InterruptedDownload {
        /// Signed length.
        expected: u64,
        /// Persisted length.
        received: u64,
    },
    /// Downloaded bytes did not match the signed hash.
    HashMismatch,
    /// Local destination was not a safe file or `.app` path.
    InvalidInstallTarget,
    /// Signed artifact kind does not match the local installation shape.
    InstallModeMismatch,
    /// Staged bytes changed after verification.
    StagedArtifactChanged,
    /// Bundle archive was malformed or unsafe.
    InvalidBundle,
    /// Filesystem access failed. No elevation is attempted.
    Io(io::Error),
    /// New content could not be installed, but rollback restored the old target.
    InstallRolledBack(io::Error),
    /// Installation and rollback both failed.
    RollbackFailed {
        /// Installation failure.
        install: io::Error,
        /// Rollback failure.
        rollback: io::Error,
    },
}

impl Display for UpdateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKey => formatter.write_str("invalid updater public key"),
            Self::InsecureUrl => formatter.write_str("updates require HTTPS or loopback HTTP"),
            Self::CredentialBearingUrl => {
                formatter.write_str("update URLs must not embed credentials or fragments")
            }
            Self::ManifestTooLarge => formatter.write_str("release manifest exceeds 1 MiB"),
            Self::ManifestJson(_) => formatter.write_str("release manifest JSON is invalid"),
            Self::InvalidSignatureEncoding => {
                formatter.write_str("release manifest signature encoding is invalid")
            }
            Self::ForgedManifest => formatter.write_str("release manifest signature is invalid"),
            Self::InvalidVersion => formatter.write_str("release version is invalid"),
            Self::ArtifactUnavailable => formatter.write_str("no update artifact for this target"),
            Self::InvalidArtifactUrl => formatter.write_str("artifact URL is invalid"),
            Self::InvalidArtifactHash => formatter.write_str("artifact SHA-256 is invalid"),
            Self::InvalidArtifactSize => formatter.write_str("artifact size is invalid"),
            Self::Http(_) => formatter.write_str("update HTTP transfer failed"),
            Self::HttpStatus(status) => write!(formatter, "update server returned HTTP {status}"),
            Self::InvalidContentRange => formatter.write_str("resume response range is invalid"),
            Self::ArtifactTooLarge => formatter.write_str("artifact exceeded its signed size"),
            Self::InterruptedDownload { expected, received } => write!(
                formatter,
                "artifact download interrupted at {received} of {expected} bytes"
            ),
            Self::HashMismatch => formatter.write_str("artifact SHA-256 mismatch"),
            Self::InvalidInstallTarget => formatter.write_str("local install target is invalid"),
            Self::InstallModeMismatch => {
                formatter.write_str("artifact kind does not match local install target")
            }
            Self::StagedArtifactChanged => {
                formatter.write_str("verified staged artifact changed before installation")
            }
            Self::InvalidBundle => formatter.write_str("macOS bundle archive is invalid"),
            Self::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => formatter
                .write_str("update needs filesystem permission; elevation was not attempted"),
            Self::Io(_) => formatter.write_str("update filesystem operation failed"),
            Self::InstallRolledBack(_) => {
                formatter.write_str("update installation failed; previous version was restored")
            }
            Self::RollbackFailed { .. } => {
                formatter.write_str("update installation and rollback both failed")
            }
        }
    }
}

impl Error for UpdateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ManifestJson(error) => Some(error),
            Self::Http(error) => Some(error),
            Self::Io(error) | Self::InstallRolledBack(error) => Some(error),
            Self::RollbackFailed { install, .. } => Some(install),
            _ => None,
        }
    }
}

async fn read_response_limited(
    response: reqwest::Response,
    limit: u64,
) -> Result<Vec<u8>, UpdateError> {
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > limit)
    {
        return Err(UpdateError::ManifestTooLarge);
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(UpdateError::Http)?;
        if u64::try_from(bytes.len())
            .ok()
            .and_then(|length| length.checked_add(u64::try_from(chunk.len()).ok()?))
            .is_none_or(|length| length > limit)
        {
            return Err(UpdateError::ManifestTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_artifact(artifact: &ReleaseArtifact) -> Result<(), UpdateError> {
    if artifact.size == 0 {
        return Err(UpdateError::InvalidArtifactSize);
    }
    let _ = decode_sha256(&artifact.sha256)?;
    let url = Url::parse(&artifact.url).map_err(|_| UpdateError::InvalidArtifactUrl)?;
    validate_network_url(&url)
}

fn validate_network_url(url: &Url) -> Result<(), UpdateError> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(UpdateError::CredentialBearingUrl);
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() == "http" && is_loopback(url.host()) {
        return Ok(());
    }
    Err(UpdateError::InsecureUrl)
}

fn is_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn ensure_success(status: StatusCode) -> Result<(), UpdateError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(UpdateError::HttpStatus(status.as_u16()))
    }
}

fn validate_content_range(
    response: &reqwest::Response,
    offset: u64,
    size: u64,
) -> Result<(), UpdateError> {
    let expected = format!("bytes {offset}-{}/{size}", size.saturating_sub(1));
    let actual = response
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok());
    if actual == Some(expected.as_str()) {
        Ok(())
    } else {
        Err(UpdateError::InvalidContentRange)
    }
}

fn decode_sha256(value: &str) -> Result<[u8; 32], UpdateError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(UpdateError::InvalidArtifactHash);
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(UpdateError::InvalidArtifactHash)?;
        let low = hex_nibble(chunk[1]).ok_or(UpdateError::InvalidArtifactHash)?;
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

async fn hash_file(path: &Path) -> Result<[u8; 32], UpdateError> {
    let mut file = tokio::fs::File::open(path).await.map_err(UpdateError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).await.map_err(UpdateError::Io)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

fn sibling_path(target: &Path, suffix: &str) -> Result<PathBuf, UpdateError> {
    let parent = target.parent().ok_or(UpdateError::InvalidInstallTarget)?;
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(UpdateError::InvalidInstallTarget)?;
    if name.is_empty() || name == "." || name == ".." {
        return Err(UpdateError::InvalidInstallTarget);
    }
    Ok(parent.join(format!(".{name}.gta-claw.{suffix}")))
}

fn ensure_kind_matches(kind: ArtifactKind, mode: InstallMode) -> Result<(), UpdateError> {
    if matches!(
        (kind, mode),
        (ArtifactKind::Executable, InstallMode::Executable)
            | (ArtifactKind::MacOsBundle, InstallMode::MacOsBundle)
    ) {
        Ok(())
    } else {
        Err(UpdateError::InstallModeMismatch)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleArchive {
    format: String,
    files: Vec<BundleFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    path: String,
    mode: u32,
    contents: String,
}

async fn prepare_bundle(
    archive_path: &Path,
    target: &InstallTarget,
) -> Result<PathBuf, UpdateError> {
    let archive = tokio::fs::read(archive_path)
        .await
        .map_err(UpdateError::Io)?;
    let archive: BundleArchive =
        serde_json::from_slice(&archive).map_err(|_| UpdateError::InvalidBundle)?;
    if archive.format != BUNDLE_MAGIC || archive.files.is_empty() {
        return Err(UpdateError::InvalidBundle);
    }
    let prepared = sibling_path(&target.path, "bundle")?;
    remove_path_if_exists(&prepared).await?;
    tokio::fs::create_dir(&prepared)
        .await
        .map_err(UpdateError::Io)?;
    let mut seen = BTreeSet::new();
    for entry in archive.files {
        let relative = safe_relative_path(&entry.path)?;
        if !seen.insert(relative.clone()) {
            return Err(UpdateError::InvalidBundle);
        }
        let destination = prepared.join(relative);
        let parent = destination.parent().ok_or(UpdateError::InvalidBundle)?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(UpdateError::Io)?;
        let bytes = STANDARD
            .decode(entry.contents.as_bytes())
            .map_err(|_| UpdateError::InvalidBundle)?;
        tokio::fs::write(&destination, bytes)
            .await
            .map_err(UpdateError::Io)?;
        set_safe_mode(&destination, entry.mode).await?;
    }
    tokio::fs::remove_file(archive_path)
        .await
        .map_err(UpdateError::Io)?;
    Ok(prepared)
}

fn safe_relative_path(value: &str) -> Result<PathBuf, UpdateError> {
    if value.contains('\\') || value.contains(':') || value.contains('\0') {
        return Err(UpdateError::InvalidBundle);
    }
    let path = Path::new(value);
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(UpdateError::InvalidBundle);
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(UpdateError::InvalidBundle);
    }
    Ok(path.to_owned())
}

#[cfg(unix)]
async fn set_safe_mode(path: &Path, requested: u32) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = requested & 0o777;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
        .map_err(UpdateError::Io)
}

#[cfg(not(unix))]
async fn set_safe_mode(_path: &Path, _requested: u32) -> Result<(), UpdateError> {
    Ok(())
}

async fn remove_path_if_exists(path: &Path) -> Result<(), UpdateError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            tokio::fs::remove_file(path).await.map_err(UpdateError::Io)
        }
        Ok(metadata) if metadata.is_dir() => tokio::fs::remove_dir_all(path)
            .await
            .map_err(UpdateError::Io),
        Ok(_) => tokio::fs::remove_file(path).await.map_err(UpdateError::Io),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(UpdateError::Io(error)),
    }
}

trait FileOps {
    fn exists(&self, path: &Path) -> bool;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove(&self, path: &Path) -> io::Result<()>;
}

struct RealFileOps;

impl FileOps for RealFileOps {
    fn exists(&self, path: &Path) -> bool {
        path.symlink_metadata().is_ok()
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        let metadata = path.symlink_metadata()?;
        if metadata.file_type().is_symlink() {
            std::fs::remove_file(path)
        } else if metadata.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        }
    }
}

fn atomic_swap(
    operations: &impl FileOps,
    staged: &Path,
    target: &Path,
    windows_lock_behavior: bool,
) -> Result<InstallOutcome, UpdateError> {
    let backup = sibling_path(target, "rollback")?;
    if operations.exists(&backup) {
        operations.remove(&backup).map_err(UpdateError::Io)?;
    }
    let had_target = operations.exists(target);
    if had_target && let Err(error) = operations.rename(target, &backup) {
        if windows_lock_behavior && is_windows_sharing_violation(&error) {
            return Ok(InstallOutcome::RestartRequired {
                staged_path: staged.to_owned(),
            });
        }
        return Err(UpdateError::Io(error));
    }
    if let Err(install) = operations.rename(staged, target) {
        if had_target {
            return match operations.rename(&backup, target) {
                Ok(()) => Err(UpdateError::InstallRolledBack(install)),
                Err(rollback) => Err(UpdateError::RollbackFailed { install, rollback }),
            };
        }
        return Err(UpdateError::Io(install));
    }
    if had_target {
        let _ = operations.remove(&backup);
    }
    Ok(InstallOutcome::Installed)
}

fn is_windows_sharing_violation(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(32 | 33))
}

#[cfg(test)]
mod unit_tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Default)]
    struct MockOps {
        existing: Mutex<BTreeSet<PathBuf>>,
        fail_rename_call: AtomicUsize,
        fail_raw_os_error: AtomicUsize,
        fail_kind: Mutex<Option<io::ErrorKind>>,
        rename_calls: AtomicUsize,
        calls: Mutex<Vec<String>>,
    }

    impl FileOps for MockOps {
        fn exists(&self, path: &Path) -> bool {
            self.existing.lock().expect("existing lock").contains(path)
        }

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            let call = self.rename_calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.calls.lock().expect("calls lock").push(format!(
                "rename:{}->{}",
                from.display(),
                to.display()
            ));
            if self.fail_rename_call.load(Ordering::SeqCst) == call {
                let raw = self.fail_raw_os_error.load(Ordering::SeqCst);
                if raw != 0 {
                    return Err(io::Error::from_raw_os_error(
                        i32::try_from(raw).expect("small raw OS error"),
                    ));
                }
                return Err(io::Error::from(
                    self.fail_kind
                        .lock()
                        .expect("failure kind lock")
                        .unwrap_or(io::ErrorKind::Other),
                ));
            }
            let mut existing = self.existing.lock().expect("existing lock");
            existing.remove(from);
            existing.insert(to.to_owned());
            Ok(())
        }

        fn remove(&self, path: &Path) -> io::Result<()> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("remove:{}", path.display()));
            self.existing.lock().expect("existing lock").remove(path);
            Ok(())
        }
    }

    #[test]
    fn second_rename_failure_rolls_back_exactly() {
        let target = PathBuf::from("app").join("gta-claw");
        let staged = PathBuf::from("app").join(".gta-claw.gta-claw.verified");
        let backup = PathBuf::from("app").join(".gta-claw.gta-claw.rollback");
        let operations = MockOps::default();
        operations
            .existing
            .lock()
            .expect("existing lock")
            .extend([target.clone(), staged.clone()]);
        operations.fail_rename_call.store(2, Ordering::SeqCst);

        let error = atomic_swap(&operations, &staged, &target, false)
            .expect_err("install failure must be reported");
        assert_eq!(
            error.to_string(),
            "update installation failed; previous version was restored"
        );
        assert_eq!(
            operations.calls.lock().expect("calls lock").as_slice(),
            [
                format!("rename:{}->{}", target.display(), backup.display()),
                format!("rename:{}->{}", staged.display(), target.display()),
                format!("rename:{}->{}", backup.display(), target.display()),
            ]
        );
        assert_eq!(
            operations.existing.lock().expect("existing lock").clone(),
            BTreeSet::from([target, staged])
        );
    }

    #[test]
    fn windows_locked_target_preserves_verified_staging() {
        let target = PathBuf::from("app").join("gta-claw");
        let staged = PathBuf::from("app").join(".gta-claw.gta-claw.verified");
        let operations = MockOps::default();
        operations
            .existing
            .lock()
            .expect("existing lock")
            .extend([target.clone(), staged.clone()]);
        operations.fail_rename_call.store(1, Ordering::SeqCst);
        operations.fail_raw_os_error.store(32, Ordering::SeqCst);

        let outcome =
            atomic_swap(&operations, &staged, &target, true).expect("lock is restart-required");
        assert_eq!(
            outcome,
            InstallOutcome::RestartRequired {
                staged_path: staged.clone(),
            }
        );
        assert_eq!(
            operations.existing.lock().expect("existing lock").clone(),
            BTreeSet::from([target, staged])
        );
    }

    #[test]
    fn bundle_paths_reject_parent_absolute_and_prefix_components() {
        assert_eq!(
            safe_relative_path("Contents/MacOS/gta-claw").expect("safe path"),
            PathBuf::from("Contents/MacOS/gta-claw")
        );
        assert_eq!(
            safe_relative_path("../outside")
                .expect_err("parent path rejected")
                .to_string(),
            "macOS bundle archive is invalid"
        );
        assert_eq!(
            safe_relative_path("C:\\outside")
                .expect_err("Windows prefix rejected")
                .to_string(),
            "macOS bundle archive is invalid"
        );
    }
}

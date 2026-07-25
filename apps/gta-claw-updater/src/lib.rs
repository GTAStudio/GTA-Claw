//! Signed, resumable, and rollback-safe GTA Claw updater.

use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::StreamExt as _;
use futures_util::stream::BoxStream;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::header::{CONNECTION, CONTENT_LENGTH, CONTENT_RANGE, HOST, RANGE, USER_AGENT};
use hyper::{HeaderMap, Request, StatusCode};
use hyper_util::client::proxy::matcher::Matcher as ProxyMatcher;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeekExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use unicode_casefold::UnicodeCaseFold as _;
use unicode_normalization::UnicodeNormalization as _;
use url::{Host, Position, Url};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PROXY_RESPONSE_HEAD_BYTES: usize = 32 * 1024;
const MAX_CLOCK_SKEW_SECONDS: u64 = 5 * 60;
const MAX_BUNDLE_FILES: usize = 4096;
const MAX_BUNDLE_PATH_BYTES: usize = 1024;
const MAX_BUNDLE_DEPTH: usize = 64;
const MAX_BUNDLE_ENTRY_BYTES: usize = 256 * 1024 * 1024;
const MAX_BUNDLE_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BUNDLE_EXPANDED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const BUNDLE_MAGIC: &str = "gta-claw-bundle-v1";
const STAGED_PART: &str = "artifact.part";
const STAGED_VERIFIED: &str = "artifact.verified";
const RESUME_BINDING: &str = "artifact.resume.json";
const SWAP_JOURNAL: &str = "swap-journal.json";

trait UpdateIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> UpdateIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

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
    /// Strictly increasing signed release sequence.
    pub sequence: u64,
    /// Signed publication time as Unix seconds.
    pub published_at_unix: u64,
    /// Signed expiration time as Unix seconds.
    pub expires_at_unix: u64,
    /// Versions positively withdrawn by this signed release.
    pub revoked_versions: Vec<String>,
    /// Platform artifacts.
    pub artifacts: Vec<ReleaseArtifact>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RollbackState {
    highest_sequence: u64,
    highest_version: String,
    manifest_sha256: String,
    revoked_versions: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResumeBinding {
    target: String,
    url: String,
    size: u64,
    sha256: String,
    kind: ArtifactKind,
    release_sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SwapJournal {
    recovery_digest: String,
}

/// One signed update artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    /// Signed release sequence this artifact belongs to.
    pub release_sequence: u64,
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

fn discard_backup(stage: &SecureStaging) -> Result<(), UpdateError> {
    let retired = OsString::from(format!(".retired-backup-{}", unique_nonce()?));
    stage
        .parent
        .rename_to(&stage.backup_name, &stage.directory, &retired)
        .map_err(UpdateError::Io)?;
    stage.directory.remove_entry_recursive(&retired)
}

fn cleanup_retired_backups(stage: &SecureStaging) -> Result<(), UpdateError> {
    for name in stage.directory.list_names()? {
        if name
            .to_str()
            .is_some_and(|name| name.starts_with(".retired-backup-"))
        {
            stage.directory.remove_entry_recursive(&name)?;
        }
    }
    Ok(())
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
    proxy: Arc<ProxyMatcher>,
    tls_config: Arc<ClientConfig>,
    verifying_key: VerifyingKey,
    target_triple: String,
    state_dir: PathBuf,
    allow_loopback_http: bool,
}

impl Updater {
    /// Creates the production updater with a compiled trust root.
    pub fn production(target_triple: impl Into<String>) -> Result<Self, UpdateError> {
        Self::build(
            PRODUCTION_PUBLIC_KEY,
            target_triple.into(),
            default_state_dir()?,
            false,
        )
    }

    /// Creates an updater with an explicit trust root, primarily for isolated tests.
    pub fn with_public_key(
        public_key: [u8; 32],
        target_triple: impl Into<String>,
    ) -> Result<Self, UpdateError> {
        Self::build(public_key, target_triple.into(), default_state_dir()?, true)
    }

    /// Creates an isolated updater with an explicit trust root and protected state directory.
    pub fn with_public_key_and_state(
        public_key: [u8; 32],
        target_triple: impl Into<String>,
        state_dir: PathBuf,
    ) -> Result<Self, UpdateError> {
        Self::build(public_key, target_triple.into(), state_dir, true)
    }

    fn build(
        public_key: [u8; 32],
        target_triple: String,
        state_dir: PathBuf,
        allow_loopback_http: bool,
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
            proxy: Arc::new(ProxyMatcher::from_env()),
            tls_config: Arc::new(native_root_tls_config()?),
            verifying_key,
            target_triple,
            state_dir,
            allow_loopback_http,
        })
    }

    /// Fetches, bounds, and verifies a release manifest before comparing versions.
    pub async fn check(
        &self,
        manifest_url: &Url,
        current: &Version,
    ) -> Result<UpdateDecision, UpdateError> {
        validate_network_url(manifest_url, self.allow_loopback_http)?;
        let response = self.get(manifest_url, None).await?;
        ensure_success(response.status())?;
        let bytes = tokio::time::timeout(
            Duration::from_secs(300),
            read_response_limited(response, MAX_MANIFEST_BYTES),
        )
        .await
        .map_err(|_| UpdateError::HttpTimeout)??;
        let manifest = self.verify_manifest(&bytes)?;
        let rollback_state = self.accept_manifest(&manifest)?;
        let available =
            Version::parse(&manifest.version).map_err(|_| UpdateError::InvalidVersion)?;
        let current_revoked = rollback_state
            .revoked_versions
            .contains(&current.to_string());
        if available <= *current {
            if current_revoked {
                return Err(UpdateError::CurrentReleaseRevoked);
            }
            return Ok(UpdateDecision::Current {
                version: current.clone(),
            });
        }
        if rollback_state
            .revoked_versions
            .contains(&available.to_string())
        {
            return Err(UpdateError::RevokedRelease);
        }
        let artifact = manifest
            .artifacts
            .into_iter()
            .find(|artifact| artifact.target == self.target_triple);
        let artifact = match artifact {
            Some(artifact) => artifact,
            None if current_revoked => return Err(UpdateError::CurrentReleaseRevoked),
            None => return Err(UpdateError::ArtifactUnavailable),
        };
        validate_artifact(&artifact, self.allow_loopback_http)?;
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
            .verify_strict(&canonical, &signature)
            .map_err(|_| UpdateError::ForgedManifest)?;
        validate_manifest_metadata(&envelope.manifest, unix_time_now()?)?;
        for artifact in &envelope.manifest.artifacts {
            if artifact.release_sequence != envelope.manifest.sequence {
                return Err(UpdateError::InvalidReleaseMetadata);
            }
            validate_artifact(artifact, self.allow_loopback_http)?;
        }
        Ok(envelope.manifest)
    }

    fn accept_manifest(&self, manifest: &ReleaseManifest) -> Result<RollbackState, UpdateError> {
        let state_root = SecureDirectory::open_or_create(&self.state_dir, true)?;
        let state_directory =
            state_root.create_child(&rollback_state_directory(&self.target_triple), true)?;
        let mut state = RollbackState::default();
        for name in state_directory.list_names()? {
            let Some(sequence) = rollback_sequence_from_name(&name) else {
                continue;
            };
            let candidate = state_directory
                .read_json::<RollbackState>(&name)?
                .ok_or(UpdateError::CorruptState)?;
            if candidate.highest_sequence != sequence
                || validate_rollback_state(&candidate).is_err()
            {
                return Err(UpdateError::CorruptState);
            }
            if candidate.highest_sequence > state.highest_sequence {
                state = candidate;
            } else if candidate.highest_sequence == state.highest_sequence && candidate != state {
                return Err(UpdateError::CorruptState);
            }
        }
        let available =
            Version::parse(&manifest.version).map_err(|_| UpdateError::InvalidVersion)?;
        let manifest_sha256 = encode_hex(&Sha256::digest(
            serde_json::to_vec(manifest).map_err(UpdateError::ManifestJson)?,
        ));

        if manifest.sequence < state.highest_sequence {
            return Err(UpdateError::RollbackManifest {
                observed: state.highest_sequence,
                received: manifest.sequence,
            });
        }
        if manifest.sequence == state.highest_sequence
            && state.highest_sequence != 0
            && (state.highest_version != manifest.version
                || state.manifest_sha256 != manifest_sha256)
        {
            return Err(UpdateError::ReleaseSequenceConflict);
        }
        if !state.highest_version.is_empty() {
            let highest =
                Version::parse(&state.highest_version).map_err(|_| UpdateError::CorruptState)?;
            if available < highest {
                return Err(UpdateError::RollbackVersion {
                    observed: state.highest_version,
                    received: manifest.version.clone(),
                });
            }
        }

        let previous = state.clone();
        if manifest.sequence > state.highest_sequence {
            state.highest_sequence = manifest.sequence;
            state.highest_version.clone_from(&manifest.version);
            state.manifest_sha256 = manifest_sha256;
        }
        state
            .revoked_versions
            .extend(manifest.revoked_versions.iter().cloned());
        if state != previous {
            let state_name = rollback_state_name(state.highest_sequence);
            state_directory.write_json_atomic(&state_name, &state)?;
        }
        Ok(state)
    }

    /// Downloads one signed artifact with safe resume and verifies exact size and SHA-256.
    pub async fn download(
        &self,
        artifact: &ReleaseArtifact,
        target: &InstallTarget,
    ) -> Result<VerifiedArtifact, UpdateError> {
        validate_artifact(artifact, self.allow_loopback_http)?;
        ensure_kind_matches(artifact.kind, target.mode)?;
        let url = Url::parse(&artifact.url).map_err(|_| UpdateError::InvalidArtifactUrl)?;
        validate_network_url(&url, self.allow_loopback_http)?;
        let stage = Arc::new(SecureStaging::open(target)?);
        recover_interrupted_swap(&stage)?;
        let expected_binding = stage.resume_binding(artifact, target);
        let binding_matches = match stage
            .directory
            .read_json::<ResumeBinding>(OsStr::new(RESUME_BINDING))
        {
            Ok(Some(binding)) => binding == expected_binding,
            Ok(None) | Err(UpdateError::CorruptState) => false,
            Err(error) => return Err(error),
        };
        if !binding_matches {
            stage
                .directory
                .remove_file_if_exists(OsStr::new(STAGED_PART))?;
            stage
                .directory
                .remove_file_if_exists(OsStr::new(STAGED_VERIFIED))?;
            stage
                .directory
                .remove_file_if_exists(OsStr::new(RESUME_BINDING))?;
            stage
                .directory
                .write_json_atomic(OsStr::new(RESUME_BINDING), &expected_binding)?;
        }

        let retained = match stage.directory.open_regular(OsStr::new(STAGED_PART), false) {
            Ok(file) => file,
            Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => stage
                .directory
                .open_regular(OsStr::new(STAGED_PART), true)?,
            Err(error) => return Err(error),
        };
        let mut offset = retained.metadata().map_err(UpdateError::Io)?.len();
        if offset > artifact.size {
            retained.set_len(0).map_err(UpdateError::Io)?;
            offset = 0;
        }
        let mut downloaded = offset;
        if offset < artifact.size {
            let mut response = self.get(&url, (offset > 0).then_some(offset)).await?;
            if offset > 0 {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    validate_content_range(&response, offset, artifact.size)?;
                } else if response.status().is_success() {
                    retained.set_len(0).map_err(UpdateError::Io)?;
                    offset = 0;
                    downloaded = 0;
                } else {
                    return Err(UpdateError::HttpStatus(response.status().as_u16()));
                }
            } else {
                ensure_success(response.status())?;
            }

            let mut file =
                tokio::fs::File::from_std(retained.try_clone().map_err(UpdateError::Io)?);
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(UpdateError::Io)?;
            downloaded = tokio::time::timeout(Duration::from_secs(300), async {
                while let Some(chunk) = response.next_chunk().await? {
                    downloaded = downloaded
                        .checked_add(
                            u64::try_from(chunk.len())
                                .map_err(|_| UpdateError::ArtifactTooLarge)?,
                        )
                        .ok_or(UpdateError::ArtifactTooLarge)?;
                    if downloaded > artifact.size {
                        return Err(UpdateError::ArtifactTooLarge);
                    }
                    file.write_all(&chunk).await.map_err(UpdateError::Io)?;
                }
                response.finish().await?;
                Ok(downloaded)
            })
            .await
            .map_err(|_| UpdateError::HttpTimeout)??;
            file.flush().await.map_err(UpdateError::Io)?;
            file.sync_all().await.map_err(UpdateError::Io)?;
        }
        if downloaded != artifact.size {
            return Err(UpdateError::InterruptedDownload {
                expected: artifact.size,
                received: downloaded,
            });
        }
        let digest = hash_handle(&retained).await?;
        let expected = decode_sha256(&artifact.sha256)?;
        if digest != expected {
            drop(retained);
            let _ = stage.directory.remove_file(OsStr::new(STAGED_PART));
            let _ = stage.directory.remove_file(OsStr::new(RESUME_BINDING));
            return Err(UpdateError::HashMismatch);
        }
        stage
            .directory
            .remove_file_if_exists(OsStr::new(STAGED_VERIFIED))?;
        stage
            .directory
            .rename_to(
                OsStr::new(STAGED_PART),
                &stage.directory,
                OsStr::new(STAGED_VERIFIED),
            )
            .map_err(UpdateError::Io)?;
        stage
            .directory
            .remove_file_if_exists(OsStr::new(RESUME_BINDING))?;
        ensure_entry_identity(&stage.directory, OsStr::new(STAGED_VERIFIED), &retained)?;
        let staged_path = stage.directory.path.join(STAGED_VERIFIED);
        Ok(VerifiedArtifact {
            path: staged_path,
            file: retained,
            stage,
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
        let metadata = verified.file.metadata().map_err(UpdateError::Io)?;
        if metadata.len() != verified.size || hash_handle(&verified.file).await? != verified.digest
        {
            return Err(UpdateError::StagedArtifactChanged);
        }
        ensure_entry_identity(
            &verified.stage.directory,
            OsStr::new(STAGED_VERIFIED),
            &verified.file,
        )?;
        let prepared = match verified.kind {
            ArtifactKind::Executable => PreparedArtifact {
                path: verified.path.clone(),
                source_name: OsString::from(STAGED_VERIFIED),
                handle: verified.file.try_clone().map_err(UpdateError::Io)?,
                stage: Arc::clone(&verified.stage),
            },
            ArtifactKind::MacOsBundle => prepare_bundle(&verified).await?,
        };
        atomic_swap_verified(&prepared, cfg!(windows))
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

    async fn get(
        &self,
        url: &Url,
        range_offset: Option<u64>,
    ) -> Result<UpdateResponse, UpdateError> {
        if url.scheme() == "https" {
            return self.https_get(url, range_offset).await;
        }
        let mut request = self.client.get(url.clone());
        if let Some(offset) = range_offset {
            request = request.header(RANGE, format!("bytes={offset}-"));
        }
        let response = request.send().await.map_err(UpdateError::Http)?;
        let status = response.status();
        let headers = response.headers().clone();
        Ok(UpdateResponse {
            status,
            headers,
            body: ResponseBody::Reqwest(response.bytes_stream().boxed()),
        })
    }

    async fn https_get(
        &self,
        url: &Url,
        range_offset: Option<u64>,
    ) -> Result<UpdateResponse, UpdateError> {
        let host = url.host_str().ok_or(UpdateError::InvalidArtifactUrl)?;
        let stream = self.connect_https_stream(url).await?;
        let server_name =
            ServerName::try_from(host.to_owned()).map_err(|_| UpdateError::InvalidArtifactUrl)?;
        let tls = tokio::time::timeout(
            Duration::from_secs(15),
            TlsConnector::from(Arc::clone(&self.tls_config)).connect(server_name, stream),
        )
        .await
        .map_err(|_| UpdateError::HttpTimeout)?
        .map_err(UpdateError::HttpsIo)?;
        let mut request = Request::builder()
            .method("GET")
            .uri(&url[Position::BeforePath..Position::AfterQuery])
            .header(HOST, url_authority(url)?)
            .header(CONNECTION, "close")
            .header(
                USER_AGENT,
                concat!("gta-claw-updater/", env!("CARGO_PKG_VERSION")),
            );
        if let Some(offset) = range_offset {
            request = request.header(RANGE, format!("bytes={offset}-"));
        }
        let request = request
            .body(Empty::<Bytes>::new())
            .map_err(|_| UpdateError::InvalidHttpRequest)?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(tls))
            .await
            .map_err(UpdateError::HttpsProtocol)?;
        let connection = tokio::spawn(connection);
        let response = match tokio::time::timeout(
            Duration::from_secs(300),
            sender.send_request(request),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                connection.abort();
                return Err(UpdateError::HttpsProtocol(error));
            }
            Err(_) => {
                connection.abort();
                return Err(UpdateError::HttpTimeout);
            }
        };
        let status = response.status();
        let headers = response.headers().clone();
        Ok(UpdateResponse {
            status,
            headers,
            body: ResponseBody::Https {
                body: response.into_body(),
                connection: Some(connection),
            },
        })
    }

    async fn connect_https_stream(&self, url: &Url) -> Result<Box<dyn UpdateIo>, UpdateError> {
        let destination_host = url.host_str().ok_or(UpdateError::InvalidArtifactUrl)?;
        let destination_port = url
            .port_or_known_default()
            .ok_or(UpdateError::InvalidArtifactUrl)?;
        let uri = url
            .as_str()
            .parse::<hyper::Uri>()
            .map_err(|_| UpdateError::InvalidArtifactUrl)?;
        let Some(proxy) = self.proxy.intercept(&uri) else {
            return connect_tcp(destination_host, destination_port)
                .await
                .map(|stream| Box::new(stream) as Box<dyn UpdateIo>);
        };
        let proxy_host = proxy.uri().host().ok_or(UpdateError::UnsupportedProxy)?;
        let proxy_scheme = proxy
            .uri()
            .scheme_str()
            .ok_or(UpdateError::UnsupportedProxy)?;
        let proxy_port = proxy
            .uri()
            .port_u16()
            .unwrap_or(if proxy_scheme == "https" { 443 } else { 80 });
        let tcp = connect_tcp(proxy_host, proxy_port).await?;
        let mut stream: Box<dyn UpdateIo> = match proxy_scheme {
            "http" => Box::new(tcp),
            "https" => {
                let server_name = ServerName::try_from(proxy_host.to_owned())
                    .map_err(|_| UpdateError::UnsupportedProxy)?;
                let tls = tokio::time::timeout(
                    Duration::from_secs(15),
                    TlsConnector::from(Arc::clone(&self.tls_config)).connect(server_name, tcp),
                )
                .await
                .map_err(|_| UpdateError::HttpTimeout)?
                .map_err(UpdateError::HttpsIo)?;
                Box::new(tls)
            }
            _ => return Err(UpdateError::UnsupportedProxy),
        };
        tokio::time::timeout(
            Duration::from_secs(15),
            establish_http_tunnel(
                stream.as_mut(),
                &connect_authority(url)?,
                proxy.basic_auth(),
            ),
        )
        .await
        .map_err(|_| UpdateError::HttpTimeout)??;
        Ok(stream)
    }
}

/// Opaque proof that one staged artifact passed signature, size, and hash checks.
#[derive(Debug)]
pub struct VerifiedArtifact {
    path: PathBuf,
    file: File,
    stage: Arc<SecureStaging>,
    digest: [u8; 32],
    size: u64,
    kind: ArtifactKind,
}

#[derive(Debug)]
struct PreparedArtifact {
    path: PathBuf,
    source_name: OsString,
    handle: File,
    stage: Arc<SecureStaging>,
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
    /// Signed publication, expiration, sequence, or revocation metadata was invalid.
    InvalidReleaseMetadata,
    /// Signed manifest has expired.
    ExpiredManifest,
    /// A previously observed newer signed sequence forbids this manifest.
    RollbackManifest {
        /// Highest sequence already persisted.
        observed: u64,
        /// Replayed lower sequence.
        received: u64,
    },
    /// A release sequence was reused for a different version.
    ReleaseSequenceConflict,
    /// A signed release version is older than the persisted verified version.
    RollbackVersion {
        /// Highest verified version.
        observed: String,
        /// Replayed lower version.
        received: String,
    },
    /// Protected anti-rollback state is malformed.
    CorruptState,
    /// The protected per-user updater state directory could not be located.
    StateDirectoryUnavailable,
    /// A staging or state path resolved to a symlink, reparse point, or unsafe owner/mode.
    UnsafeFilesystemObject,
    /// The installed release has been positively withdrawn.
    CurrentReleaseRevoked,
    /// The offered release has been positively withdrawn.
    RevokedRelease,
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
    /// HTTPS socket or TLS I/O failed.
    HttpsIo(io::Error),
    /// HTTPS HTTP/1 framing failed.
    HttpsProtocol(hyper::Error),
    /// HTTPS connection driver failed.
    HttpTask(tokio::task::JoinError),
    /// A validated URL could not be represented as an HTTP request.
    InvalidHttpRequest,
    /// An HTTP connection or transfer exceeded its fixed timeout.
    HttpTimeout,
    /// Configured proxy transport is not a supported HTTP CONNECT proxy.
    UnsupportedProxy,
    /// An HTTP CONNECT proxy returned an invalid or unsuccessful response.
    InvalidProxyResponse,
    /// No usable platform root certificates were available.
    NativeRootsUnavailable,
    /// The pinned TLS provider could not construct a safe client configuration.
    TlsConfiguration,
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
    /// An interrupted swap cannot be recovered without overwriting an unknown object.
    SwapRecoveryConflict,
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
            Self::InvalidReleaseMetadata => {
                formatter.write_str("signed release control metadata is invalid")
            }
            Self::ExpiredManifest => formatter.write_str("signed release manifest has expired"),
            Self::RollbackManifest { observed, received } => write!(
                formatter,
                "signed release sequence {received} is below verified floor {observed}"
            ),
            Self::ReleaseSequenceConflict => {
                formatter.write_str("signed release sequence was reused for another version")
            }
            Self::RollbackVersion { observed, received } => write!(
                formatter,
                "signed release version {received} is below verified floor {observed}"
            ),
            Self::CorruptState => {
                formatter.write_str("protected updater anti-rollback state is invalid")
            }
            Self::StateDirectoryUnavailable => {
                formatter.write_str("protected updater state directory is unavailable")
            }
            Self::UnsafeFilesystemObject => {
                formatter.write_str("updater refused an unsafe filesystem object")
            }
            Self::CurrentReleaseRevoked => {
                formatter.write_str("installed release has been withdrawn")
            }
            Self::RevokedRelease => formatter.write_str("offered release has been withdrawn"),
            Self::ArtifactUnavailable => formatter.write_str("no update artifact for this target"),
            Self::InvalidArtifactUrl => formatter.write_str("artifact URL is invalid"),
            Self::InvalidArtifactHash => formatter.write_str("artifact SHA-256 is invalid"),
            Self::InvalidArtifactSize => formatter.write_str("artifact size is invalid"),
            Self::Http(_)
            | Self::HttpsIo(_)
            | Self::HttpsProtocol(_)
            | Self::HttpTask(_)
            | Self::InvalidHttpRequest => formatter.write_str("update HTTP transfer failed"),
            Self::HttpTimeout => formatter.write_str("update HTTP transfer timed out"),
            Self::UnsupportedProxy => formatter.write_str("configured update proxy is unsupported"),
            Self::InvalidProxyResponse => formatter.write_str("update proxy connection failed"),
            Self::NativeRootsUnavailable => {
                formatter.write_str("no usable platform root certificates are available")
            }
            Self::TlsConfiguration => formatter.write_str("update TLS configuration failed"),
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
            Self::SwapRecoveryConflict => {
                formatter.write_str("interrupted update conflicts with an unknown local object")
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
            Self::HttpsIo(error) => Some(error),
            Self::HttpsProtocol(error) => Some(error),
            Self::HttpTask(error) => Some(error),
            Self::Io(error) | Self::InstallRolledBack(error) => Some(error),
            Self::RollbackFailed { install, .. } => Some(install),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
struct SecureDirectory {
    path: PathBuf,
    handle: Arc<File>,
}

impl SecureDirectory {
    fn open_or_create(path: &Path, owner_only: bool) -> Result<Self, UpdateError> {
        reject_reparse_components(path)?;
        fs::create_dir_all(path).map_err(UpdateError::Io)?;
        #[cfg(unix)]
        {
            let directory = Self::open_existing(path, false)?;
            if owner_only {
                directory
                    .handle
                    .set_permissions(fs::Permissions::from_mode(0o700))
                    .map_err(UpdateError::Io)?;
            }
            directory.validate_directory(owner_only)?;
            Ok(directory)
        }
        #[cfg(windows)]
        {
            if owner_only {
                lock_down_windows_directory(path)?;
            }
            Self::open_existing(path, owner_only)
        }
    }

    fn open_existing(path: &Path, owner_only: bool) -> Result<Self, UpdateError> {
        reject_reparse_components(path)?;
        #[cfg(windows)]
        if owner_only {
            verify_windows_directory_acl(path)?;
        }
        #[cfg(unix)]
        let handle = {
            let descriptor = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(rustix_open_error)?;
            File::from(descriptor)
        };
        #[cfg(windows)]
        let handle = {
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            let handle = OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .map_err(UpdateError::Io)?;
            if is_windows_reparse(&handle.metadata().map_err(UpdateError::Io)?) {
                return Err(UpdateError::UnsafeFilesystemObject);
            }
            handle
        };
        let directory = Self {
            path: path.to_path_buf(),
            handle: Arc::new(handle),
        };
        directory.validate_directory(owner_only)?;
        Ok(directory)
    }

    fn create_child(&self, name: &OsStr, owner_only: bool) -> Result<Self, UpdateError> {
        validate_single_component(name)?;
        #[cfg(unix)]
        {
            let mode = rustix::fs::Mode::from_raw_mode(0o700);
            if let Err(error) = rustix::fs::mkdirat(&*self.handle, name, mode)
                && error != rustix::io::Errno::EXIST
            {
                return Err(UpdateError::Io(rustix_error(error)));
            }
            let descriptor = rustix::fs::openat(
                &*self.handle,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(rustix_open_error)?;
            let child = Self {
                path: self.path.join(name),
                handle: Arc::new(File::from(descriptor)),
            };
            if owner_only {
                child
                    .handle
                    .set_permissions(fs::Permissions::from_mode(0o700))
                    .map_err(UpdateError::Io)?;
            }
            child.validate_directory(owner_only)?;
            Ok(child)
        }
        #[cfg(windows)]
        {
            let path = self.path.join(name);
            if owner_only {
                verify_windows_parent_not_shared(&self.path)?;
            }
            let created = match fs::create_dir(&path) {
                Ok(()) => true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                Err(error) => return Err(UpdateError::Io(error)),
            };
            if owner_only && created {
                lock_down_windows_directory(&path)?;
            }
            Self::open_existing(&path, owner_only)
        }
    }

    fn create_child_new(&self, name: &OsStr) -> Result<Self, UpdateError> {
        validate_single_component(name)?;
        #[cfg(unix)]
        rustix::fs::mkdirat(&*self.handle, name, rustix::fs::Mode::from_raw_mode(0o700))
            .map_err(rustix_error)
            .map_err(UpdateError::Io)?;
        #[cfg(windows)]
        {
            let path = self.path.join(name);
            verify_windows_parent_not_shared(&self.path)?;
            fs::create_dir(&path).map_err(UpdateError::Io)?;
            lock_down_windows_directory(&path)?;
            Self::open_existing(&path, true)
        }
        #[cfg(unix)]
        self.create_child(name, true)
    }

    fn open_regular(&self, name: &OsStr, create_new: bool) -> Result<File, UpdateError> {
        validate_single_component(name)?;
        #[cfg(unix)]
        let file = {
            let mut flags = rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC;
            if create_new {
                flags |= rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL;
            }
            let descriptor = rustix::fs::openat(
                &*self.handle,
                name,
                flags,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(rustix_open_error)?;
            File::from(descriptor)
        };
        #[cfg(windows)]
        let file = {
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            if create_new {
                options.create_new(true);
            }
            options
                .open(self.path.join(name))
                .map_err(UpdateError::Io)?
        };
        let metadata = file.metadata().map_err(UpdateError::Io)?;
        if !metadata.is_file() {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        #[cfg(unix)]
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        #[cfg(windows)]
        if is_windows_reparse(&metadata) {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        Ok(file)
    }

    fn open_object(&self, name: &OsStr) -> Result<File, UpdateError> {
        validate_single_component(name)?;
        #[cfg(unix)]
        let file = {
            let descriptor = rustix::fs::openat(
                &*self.handle,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(rustix_open_error)?;
            File::from(descriptor)
        };
        #[cfg(windows)]
        let file = {
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.path.join(name))
                .map_err(UpdateError::Io)?
        };
        let metadata = file.metadata().map_err(UpdateError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        #[cfg(windows)]
        if is_windows_reparse(&metadata) {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        Ok(file)
    }

    fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        name: &OsStr,
    ) -> Result<Option<T>, UpdateError> {
        let file = match self.open_regular(name, false) {
            Ok(file) => file,
            Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST_BYTES)
            .read_to_end(&mut bytes)
            .map_err(UpdateError::Io)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| UpdateError::CorruptState)
    }

    fn write_json_atomic<T: Serialize>(&self, name: &OsStr, value: &T) -> Result<(), UpdateError> {
        validate_single_component(name)?;
        let bytes = serde_json::to_vec(value).map_err(UpdateError::ManifestJson)?;
        let temporary =
            OsString::from(format!(".state-{}-{}", std::process::id(), unique_nonce()?));
        let mut file = self.open_regular(&temporary, true)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            self.rename_to(&temporary, self, name)?;
            self.sync()?;
            Ok::<(), io::Error>(())
        })();
        if result.is_err() {
            let _ = self.remove_file(&temporary);
        }
        result.map_err(UpdateError::Io)
    }

    fn rename_to(
        &self,
        source_name: &OsStr,
        destination: &Self,
        destination_name: &OsStr,
    ) -> Result<(), io::Error> {
        validate_single_component_io(source_name)?;
        validate_single_component_io(destination_name)?;
        #[cfg(unix)]
        {
            rustix::fs::renameat(
                &*self.handle,
                source_name,
                &*destination.handle,
                destination_name,
            )
            .map_err(rustix_error)
        }
        #[cfg(windows)]
        {
            fs::rename(
                self.path.join(source_name),
                destination.path.join(destination_name),
            )
        }
    }

    fn remove_file(&self, name: &OsStr) -> Result<(), io::Error> {
        validate_single_component_io(name)?;
        #[cfg(unix)]
        {
            rustix::fs::unlinkat(&*self.handle, name, rustix::fs::AtFlags::empty())
                .map_err(rustix_error)
        }
        #[cfg(windows)]
        {
            fs::remove_file(self.path.join(name))
        }
    }

    fn remove_file_if_exists(&self, name: &OsStr) -> Result<(), UpdateError> {
        match self.remove_file(name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(UpdateError::Io(error)),
        }
    }

    fn object_exists(&self, name: &OsStr) -> Result<bool, UpdateError> {
        #[cfg(windows)]
        {
            validate_single_component(name)?;
            match fs::symlink_metadata(self.path.join(name)) {
                Ok(metadata) if is_windows_reparse(&metadata) => {
                    Err(UpdateError::UnsafeFilesystemObject)
                }
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(UpdateError::Io(error)),
            }
        }
        #[cfg(unix)]
        match self.open_object(name) {
            Ok(_) => Ok(true),
            Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn list_names(&self) -> Result<Vec<OsString>, UpdateError> {
        #[cfg(target_os = "linux")]
        {
            use std::mem::MaybeUninit;
            use std::os::unix::ffi::OsStrExt as _;

            let descriptor = rustix::fs::openat(
                &*self.handle,
                ".",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(rustix_open_error)?;
            let mut buffer = [MaybeUninit::uninit(); 8192];
            let mut entries = Vec::new();
            let mut raw = rustix::fs::RawDir::new(&descriptor, &mut buffer);
            while let Some(entry) = raw.next() {
                let entry = entry.map_err(rustix_error).map_err(UpdateError::Io)?;
                let bytes = entry.file_name().to_bytes();
                if bytes != b"." && bytes != b".." {
                    entries.push(OsStr::from_bytes(bytes).to_owned());
                }
            }
            Ok(entries)
        }
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            use std::os::fd::AsRawFd as _;

            fs::read_dir(format!("/dev/fd/{}", self.handle.as_raw_fd()))
                .map_err(UpdateError::Io)?
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name())
                        .map_err(UpdateError::Io)
                })
                .collect()
        }
        #[cfg(windows)]
        {
            fs::read_dir(&self.path)
                .map_err(UpdateError::Io)?
                .map(|entry| {
                    entry
                        .map(|entry| entry.file_name())
                        .map_err(UpdateError::Io)
                })
                .collect()
        }
    }

    fn remove_entry_recursive(&self, name: &OsStr) -> Result<(), UpdateError> {
        validate_single_component(name)?;
        let object = match self.open_object(name) {
            Ok(object) => object,
            Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let metadata = object.metadata().map_err(UpdateError::Io)?;
        if metadata.is_file() {
            return self.remove_file(name).map_err(UpdateError::Io);
        }
        if !metadata.is_dir() {
            return Err(UpdateError::UnsafeFilesystemObject);
        }

        #[cfg(unix)]
        {
            let directory = Self {
                path: self.path.join(name),
                handle: Arc::new(object),
            };
            for entry in directory.list_names()? {
                directory.remove_entry_recursive(&entry)?;
            }
            rustix::fs::unlinkat(&*self.handle, name, rustix::fs::AtFlags::REMOVEDIR)
                .map_err(rustix_error)
                .map_err(UpdateError::Io)
        }
        #[cfg(windows)]
        {
            remove_tree_windows(&self.path.join(name))
        }
    }

    fn sync(&self) -> Result<(), io::Error> {
        #[cfg(unix)]
        {
            self.handle.sync_all()
        }
        #[cfg(windows)]
        {
            Ok(())
        }
    }

    fn validate_directory(&self, owner_only: bool) -> Result<(), UpdateError> {
        #[cfg(windows)]
        let _ = owner_only;
        let metadata = self.handle.metadata().map_err(UpdateError::Io)?;
        if !metadata.is_dir() {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        #[cfg(unix)]
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || owner_only && metadata.mode() & 0o077 != 0
        {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        #[cfg(windows)]
        if is_windows_reparse(&metadata) {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct SecureStaging {
    directory: SecureDirectory,
    parent: SecureDirectory,
    target_name: OsString,
    backup_name: OsString,
}

impl SecureStaging {
    fn open(target: &InstallTarget) -> Result<Self, UpdateError> {
        let parent_path = target
            .path
            .parent()
            .ok_or(UpdateError::InvalidInstallTarget)?;
        let target_name = target
            .path
            .file_name()
            .and_then(OsStr::to_str)
            .filter(|name| !name.is_empty())
            .ok_or(UpdateError::InvalidInstallTarget)?;
        let parent = SecureDirectory::open_existing(parent_path, false)?;
        let stage_name = OsString::from(format!(".{target_name}.gta-claw-stage"));
        let directory = parent.create_child(&stage_name, true)?;
        Ok(Self {
            directory,
            parent,
            target_name: OsString::from(target_name),
            backup_name: OsString::from(format!(".{target_name}.gta-claw.rollback")),
        })
    }

    fn resume_binding(&self, artifact: &ReleaseArtifact, target: &InstallTarget) -> ResumeBinding {
        ResumeBinding {
            target: target.path.to_string_lossy().into_owned(),
            url: artifact.url.clone(),
            size: artifact.size,
            sha256: artifact.sha256.clone(),
            kind: artifact.kind,
            release_sequence: artifact.release_sequence,
        }
    }
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<(u64, u64), UpdateError> {
    let metadata = file.metadata().map_err(UpdateError::Io)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn ensure_entry_identity(
    directory: &SecureDirectory,
    name: &OsStr,
    retained: &File,
) -> Result<(), UpdateError> {
    let entry = directory.open_object(name)?;
    #[cfg(windows)]
    {
        let entry = same_file::Handle::from_file(entry).map_err(UpdateError::Io)?;
        let retained = same_file::Handle::from_file(retained.try_clone().map_err(UpdateError::Io)?)
            .map_err(UpdateError::Io)?;
        if entry == retained {
            Ok(())
        } else {
            Err(UpdateError::StagedArtifactChanged)
        }
    }
    #[cfg(unix)]
    if file_identity(&entry)? == file_identity(retained)? {
        Ok(())
    } else {
        Err(UpdateError::StagedArtifactChanged)
    }
}

fn object_digest(directory: &SecureDirectory, name: &OsStr) -> Result<String, UpdateError> {
    let object = directory.open_object(name)?;
    let mut digest = Sha256::new();
    update_object_digest(object, &directory.path.join(name), None, &mut digest)?;
    Ok(encode_hex(&digest.finalize()))
}

fn update_object_digest(
    object: File,
    path: &Path,
    name: Option<&str>,
    digest: &mut Sha256,
) -> Result<(), UpdateError> {
    if let Some(name) = name {
        digest.update(
            u64::try_from(name.len())
                .map_err(|_| UpdateError::StagedArtifactChanged)?
                .to_be_bytes(),
        );
        digest.update(name.as_bytes());
    }
    let metadata = object.metadata().map_err(UpdateError::Io)?;
    #[cfg(unix)]
    digest.update((metadata.mode() & 0o777).to_be_bytes());
    if metadata.is_file() {
        digest.update(b"file");
        digest.update(metadata.len().to_be_bytes());
        let mut file = object;
        file.seek(SeekFrom::Start(0)).map_err(UpdateError::Io)?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(UpdateError::Io)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(UpdateError::UnsafeFilesystemObject);
    }
    digest.update(b"directory");
    let child = SecureDirectory {
        path: path.to_owned(),
        handle: Arc::new(object),
    };
    let mut entries = child
        .list_names()?
        .into_iter()
        .map(|name| {
            name.into_string()
                .map_err(|_| UpdateError::StagedArtifactChanged)
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_unstable();
    for entry in entries {
        let object = child.open_object(OsStr::new(&entry))?;
        update_object_digest(object, &child.path.join(&entry), Some(&entry), digest)?;
    }
    Ok(())
}

fn recover_interrupted_swap(stage: &SecureStaging) -> Result<(), UpdateError> {
    cleanup_retired_backups(stage)?;
    let journal = stage
        .directory
        .read_json::<SwapJournal>(OsStr::new(SWAP_JOURNAL))?;
    let target_exists = stage.parent.object_exists(&stage.target_name)?;
    let backup_exists = stage.parent.object_exists(&stage.backup_name)?;

    match (journal, target_exists, backup_exists) {
        (None, _, false) => Ok(()),
        (None, false, true) => {
            stage
                .parent
                .rename_to(&stage.backup_name, &stage.parent, &stage.target_name)
                .map_err(UpdateError::Io)?;
            stage.parent.sync().map_err(UpdateError::Io)
        }
        (None, true, true) => Err(UpdateError::SwapRecoveryConflict),
        (Some(_), false, true) => {
            stage
                .parent
                .rename_to(&stage.backup_name, &stage.parent, &stage.target_name)
                .map_err(UpdateError::Io)?;
            stage
                .directory
                .remove_file_if_exists(OsStr::new(SWAP_JOURNAL))?;
            stage.parent.sync().map_err(UpdateError::Io)
        }
        (Some(journal), true, has_backup) => {
            if object_digest(&stage.parent, &stage.target_name)? != journal.recovery_digest {
                return Err(UpdateError::SwapRecoveryConflict);
            }
            if has_backup {
                discard_backup(stage)?;
            }
            stage
                .directory
                .remove_file_if_exists(OsStr::new(SWAP_JOURNAL))?;
            stage.parent.sync().map_err(UpdateError::Io)
        }
        (Some(_), false, false) => Err(UpdateError::SwapRecoveryConflict),
    }
}

fn default_state_dir() -> Result<PathBuf, UpdateError> {
    #[cfg(windows)]
    let path = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or(UpdateError::StateDirectoryUnavailable)?
        .join("GTA-Claw")
        .join("updater");
    #[cfg(target_os = "macos")]
    let path = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(UpdateError::StateDirectoryUnavailable)?
        .join("Library")
        .join("Application Support")
        .join("GTA-Claw")
        .join("updater");
    #[cfg(all(unix, not(target_os = "macos")))]
    let path = if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(path).join("gta-claw").join("updater")
    } else {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(UpdateError::StateDirectoryUnavailable)?
            .join(".local")
            .join("state")
            .join("gta-claw")
            .join("updater")
    };
    Ok(path)
}

fn rollback_state_directory(target: &str) -> OsString {
    let digest = Sha256::digest(target.as_bytes());
    OsString::from(format!("target-{}", encode_hex(&digest[..8])))
}

fn rollback_state_name(sequence: u64) -> OsString {
    OsString::from(format!("release-floor-{sequence:020}.json"))
}

fn rollback_sequence_from_name(name: &OsStr) -> Option<u64> {
    name.to_str()?
        .strip_prefix("release-floor-")?
        .strip_suffix(".json")?
        .parse()
        .ok()
}

fn validate_rollback_state(state: &RollbackState) -> Result<(), UpdateError> {
    if state.highest_sequence == 0
        || Version::parse(&state.highest_version).is_err()
        || decode_sha256(&state.manifest_sha256).is_err()
        || state
            .revoked_versions
            .iter()
            .any(|version| Version::parse(version).is_err())
    {
        return Err(UpdateError::CorruptState);
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn reject_reparse_components(path: &Path) -> Result<(), UpdateError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if !matches!(component, Component::Normal(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(UpdateError::UnsafeFilesystemObject);
                }
                #[cfg(windows)]
                if is_windows_reparse(&metadata) {
                    return Err(UpdateError::UnsafeFilesystemObject);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(UpdateError::Io(error)),
        }
    }
    Ok(())
}

fn validate_single_component(name: &OsStr) -> Result<(), UpdateError> {
    validate_single_component_io(name).map_err(|_| UpdateError::UnsafeFilesystemObject)
}

fn validate_single_component_io(name: &OsStr) -> Result<(), io::Error> {
    let mut components = Path::new(name).components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected one filesystem component",
        ))
    }
}

#[cfg(unix)]
fn rustix_error(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(unix)]
fn rustix_open_error(error: rustix::io::Errno) -> UpdateError {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        UpdateError::UnsafeFilesystemObject
    } else {
        UpdateError::Io(rustix_error(error))
    }
}

#[cfg(windows)]
fn is_windows_reparse(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn lock_down_windows_directory(path: &Path) -> Result<(), UpdateError> {
    use windows_acl::acl::{ACL, AceType};
    use windows_acl::helper::{current_user, name_to_sid, sid_to_string};

    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    let path = path.to_str().ok_or(UpdateError::InvalidInstallTarget)?;
    let user = current_user().ok_or(UpdateError::UnsafeFilesystemObject)?;
    let current_sid = name_to_sid(&user, None).map_err(windows_acl_error)?;
    let current_sid_pointer = current_sid.as_ptr().cast_mut().cast();
    let current_sid_string = sid_to_string(current_sid_pointer).map_err(windows_acl_error)?;
    let mut acl = ACL::from_file_path(path, false).map_err(windows_acl_error)?;
    acl.remove(current_sid_pointer, Some(AceType::AccessDeny), None)
        .map_err(windows_acl_error)?;
    if !acl
        .allow(current_sid_pointer, true, FILE_ALL_ACCESS)
        .map_err(windows_acl_error)?
    {
        return Err(UpdateError::UnsafeFilesystemObject);
    }
    for entry in acl.all().map_err(windows_acl_error)? {
        if entry.string_sid == current_sid_string {
            continue;
        }
        let sid = entry.sid.ok_or(UpdateError::UnsafeFilesystemObject)?;
        acl.remove(sid.as_ptr().cast_mut().cast(), None, None)
            .map_err(windows_acl_error)?;
    }

    verify_windows_directory_acl(Path::new(path))
}

#[cfg(windows)]
fn verify_windows_directory_acl(path: &Path) -> Result<(), UpdateError> {
    use windows_acl::acl::{ACL, AceType};
    use windows_acl::helper::{current_user, name_to_sid, sid_to_string};

    const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
    let path = path.to_str().ok_or(UpdateError::InvalidInstallTarget)?;
    let user = current_user().ok_or(UpdateError::UnsafeFilesystemObject)?;
    let current_sid = name_to_sid(&user, None).map_err(windows_acl_error)?;
    let current_sid_string =
        sid_to_string(current_sid.as_ptr().cast_mut().cast()).map_err(windows_acl_error)?;
    let entries = ACL::from_file_path(path, false)
        .map_err(windows_acl_error)?
        .all()
        .map_err(windows_acl_error)?;
    if entries.is_empty()
        || entries.iter().any(|entry| {
            entry.string_sid != current_sid_string || entry.entry_type == AceType::AccessDeny
        })
        || !entries.iter().any(|entry| {
            entry.entry_type == AceType::AccessAllow
                && entry.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
        })
    {
        return Err(UpdateError::UnsafeFilesystemObject);
    }
    Ok(())
}

#[cfg(windows)]
fn verify_windows_parent_not_shared(path: &Path) -> Result<(), UpdateError> {
    use windows_acl::acl::{ACL, AceType};
    use windows_acl::helper::{current_user, name_to_sid, sid_to_string};

    const UNTRUSTED_WRITE: u32 = 0x0000_0002
        | 0x0000_0004
        | 0x0000_0040
        | 0x0001_0000
        | 0x0004_0000
        | 0x0008_0000
        | 0x1000_0000
        | 0x4000_0000;
    const SYSTEM_SID: &str = "S-1-5-18";
    const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
    const CREATOR_OWNER_SID: &str = "S-1-3-0";

    let path = path.to_str().ok_or(UpdateError::InvalidInstallTarget)?;
    let user = current_user().ok_or(UpdateError::UnsafeFilesystemObject)?;
    let current_sid = name_to_sid(&user, None).map_err(windows_acl_error)?;
    let current_sid_string =
        sid_to_string(current_sid.as_ptr().cast_mut().cast()).map_err(windows_acl_error)?;
    let entries = ACL::from_file_path(path, false)
        .map_err(windows_acl_error)?
        .all()
        .map_err(windows_acl_error)?;
    if entries.is_empty()
        || entries.iter().any(|entry| {
            entry.entry_type == AceType::AccessAllow
                && entry.mask & UNTRUSTED_WRITE != 0
                && entry.string_sid != current_sid_string
                && entry.string_sid != SYSTEM_SID
                && entry.string_sid != ADMINISTRATORS_SID
                && entry.string_sid != CREATOR_OWNER_SID
        })
    {
        return Err(UpdateError::UnsafeFilesystemObject);
    }
    Ok(())
}

#[cfg(windows)]
fn windows_acl_error(error: u32) -> UpdateError {
    UpdateError::Io(io::Error::from_raw_os_error(
        i32::try_from(error).unwrap_or(i32::MAX),
    ))
}

#[cfg(windows)]
fn remove_tree_windows(path: &Path) -> Result<(), UpdateError> {
    for entry in fs::read_dir(path).map_err(UpdateError::Io)? {
        let entry = entry.map_err(UpdateError::Io)?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(UpdateError::Io)?;
        if is_windows_reparse(&metadata) || metadata.file_type().is_symlink() {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
        if metadata.is_dir() {
            remove_tree_windows(&entry.path())?;
        } else if metadata.is_file() {
            fs::remove_file(entry.path()).map_err(UpdateError::Io)?;
        } else {
            return Err(UpdateError::UnsafeFilesystemObject);
        }
    }
    fs::remove_dir(path).map_err(UpdateError::Io)
}

struct UpdateResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: ResponseBody,
}

impl UpdateResponse {
    const fn status(&self) -> StatusCode {
        self.status
    }

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    async fn next_chunk(&mut self) -> Result<Option<Bytes>, UpdateError> {
        self.body.next_chunk().await
    }

    async fn finish(&mut self) -> Result<(), UpdateError> {
        self.body.finish().await
    }
}

enum ResponseBody {
    Reqwest(BoxStream<'static, Result<Bytes, reqwest::Error>>),
    Https {
        body: Incoming,
        connection: Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>,
    },
}

impl ResponseBody {
    async fn next_chunk(&mut self) -> Result<Option<Bytes>, UpdateError> {
        match self {
            Self::Reqwest(stream) => stream.next().await.transpose().map_err(UpdateError::Http),
            Self::Https { body, .. } => {
                while let Some(frame) = body.frame().await {
                    let frame = frame.map_err(UpdateError::HttpsProtocol)?;
                    if let Ok(bytes) = frame.into_data() {
                        return Ok(Some(bytes));
                    }
                }
                Ok(None)
            }
        }
    }

    async fn finish(&mut self) -> Result<(), UpdateError> {
        if let Self::Https { connection, .. } = self
            && let Some(connection) = connection.take()
        {
            connection
                .await
                .map_err(UpdateError::HttpTask)?
                .map_err(UpdateError::HttpsProtocol)?;
        }
        Ok(())
    }
}

impl Drop for ResponseBody {
    fn drop(&mut self) {
        if let Self::Https {
            connection: Some(connection),
            ..
        } = self
        {
            connection.abort();
        }
    }
}

fn native_root_tls_config() -> Result<ClientConfig, UpdateError> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err(UpdateError::NativeRootsUnavailable);
    }
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        return Err(UpdateError::NativeRootsUnavailable);
    }
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| UpdateError::TlsConfiguration)
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

fn url_authority(url: &Url) -> Result<String, UpdateError> {
    let host = match url.host().ok_or(UpdateError::InvalidArtifactUrl)? {
        Host::Domain(domain) => domain.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn connect_authority(url: &Url) -> Result<String, UpdateError> {
    let host = match url.host().ok_or(UpdateError::InvalidArtifactUrl)? {
        Host::Domain(domain) => domain.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    let port = url
        .port_or_known_default()
        .ok_or(UpdateError::InvalidArtifactUrl)?;
    Ok(format!("{host}:{port}"))
}

async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, UpdateError> {
    tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host, port)))
        .await
        .map_err(|_| UpdateError::HttpTimeout)?
        .map_err(UpdateError::HttpsIo)
}

async fn establish_http_tunnel<S>(
    stream: &mut S,
    authority: &str,
    basic_auth: Option<&hyper::header::HeaderValue>,
) -> Result<(), UpdateError>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(value) = basic_auth {
        let value = value.to_str().map_err(|_| UpdateError::UnsupportedProxy)?;
        request.push_str("Proxy-Authorization: ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(UpdateError::HttpsIo)?;
    stream.flush().await.map_err(UpdateError::HttpsIo)?;

    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        if response.len() >= MAX_PROXY_RESPONSE_HEAD_BYTES {
            return Err(UpdateError::InvalidProxyResponse);
        }
        let remaining = MAX_PROXY_RESPONSE_HEAD_BYTES - response.len();
        let read_limit = remaining.min(buffer.len());
        let count = stream
            .read(&mut buffer[..read_limit])
            .await
            .map_err(UpdateError::HttpsIo)?;
        if count == 0 {
            return Err(UpdateError::InvalidProxyResponse);
        }
        response.extend_from_slice(&buffer[..count]);
        if let Some(index) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            if index + 4 != response.len() {
                return Err(UpdateError::InvalidProxyResponse);
            }
            break;
        }
    }

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut parsed = httparse::Response::new(&mut headers);
    match parsed
        .parse(&response)
        .map_err(|_| UpdateError::InvalidProxyResponse)?
    {
        httparse::Status::Complete(length)
            if length == response.len() && parsed.version.is_some() && parsed.code == Some(200) =>
        {
            Ok(())
        }
        httparse::Status::Complete(_) | httparse::Status::Partial => {
            Err(UpdateError::InvalidProxyResponse)
        }
    }
}

async fn read_response_limited(
    mut response: UpdateResponse,
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
    while let Some(chunk) = response.next_chunk().await? {
        if u64::try_from(bytes.len())
            .ok()
            .and_then(|length| length.checked_add(u64::try_from(chunk.len()).ok()?))
            .is_none_or(|length| length > limit)
        {
            return Err(UpdateError::ManifestTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    response.finish().await?;
    Ok(bytes)
}

fn validate_manifest_metadata(manifest: &ReleaseManifest, now: u64) -> Result<(), UpdateError> {
    let _version = Version::parse(&manifest.version).map_err(|_| UpdateError::InvalidVersion)?;
    if manifest.sequence == 0
        || manifest.published_at_unix > manifest.expires_at_unix
        || manifest.published_at_unix > now.saturating_add(MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(UpdateError::InvalidReleaseMetadata);
    }
    if manifest.expires_at_unix <= now {
        return Err(UpdateError::ExpiredManifest);
    }

    let mut revoked = BTreeSet::new();
    for revoked_version in &manifest.revoked_versions {
        let revoked_version =
            Version::parse(revoked_version).map_err(|_| UpdateError::InvalidReleaseMetadata)?;
        if !revoked.insert(revoked_version) {
            return Err(UpdateError::InvalidReleaseMetadata);
        }
    }
    Ok(())
}

fn validate_artifact(
    artifact: &ReleaseArtifact,
    allow_loopback_http: bool,
) -> Result<(), UpdateError> {
    if artifact.size == 0 {
        return Err(UpdateError::InvalidArtifactSize);
    }
    let _ = decode_sha256(&artifact.sha256)?;
    let url = Url::parse(&artifact.url).map_err(|_| UpdateError::InvalidArtifactUrl)?;
    validate_network_url(&url, allow_loopback_http)
}

fn validate_network_url(url: &Url, allow_loopback_http: bool) -> Result<(), UpdateError> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(UpdateError::CredentialBearingUrl);
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    if allow_loopback_http && url.scheme() == "http" && is_literal_loopback(url.host()) {
        return Ok(());
    }
    Err(UpdateError::InsecureUrl)
}

fn is_literal_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) => false,
        None => false,
    }
}

fn unix_time_now() -> Result<u64, UpdateError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| UpdateError::InvalidReleaseMetadata)
}

fn ensure_success(status: StatusCode) -> Result<(), UpdateError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(UpdateError::HttpStatus(status.as_u16()))
    }
}

fn validate_content_range(
    response: &UpdateResponse,
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

async fn hash_handle(file: &File) -> Result<[u8; 32], UpdateError> {
    let mut file = tokio::fs::File::from_std(file.try_clone().map_err(UpdateError::Io)?);
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(UpdateError::Io)?;
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

async fn read_handle_limited(file: &File, limit: u64) -> Result<Vec<u8>, UpdateError> {
    let length = file.metadata().map_err(UpdateError::Io)?.len();
    if length > limit {
        return Err(UpdateError::InvalidBundle);
    }
    let mut file = tokio::fs::File::from_std(file.try_clone().map_err(UpdateError::Io)?);
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(UpdateError::Io)?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(length).map_err(|_| UpdateError::InvalidBundle)?);
    file.read_to_end(&mut bytes)
        .await
        .map_err(UpdateError::Io)?;
    if u64::try_from(bytes.len()).map_err(|_| UpdateError::InvalidBundle)? != length {
        return Err(UpdateError::StagedArtifactChanged);
    }
    Ok(bytes)
}

fn unique_nonce() -> Result<u128, UpdateError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|_| UpdateError::InvalidReleaseMetadata)
}

#[cfg(test)]
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

async fn prepare_bundle(verified: &VerifiedArtifact) -> Result<PreparedArtifact, UpdateError> {
    let archive = read_handle_limited(&verified.file, MAX_BUNDLE_ARCHIVE_BYTES).await?;
    let archive: BundleArchive =
        serde_json::from_slice(&archive).map_err(|_| UpdateError::InvalidBundle)?;
    if archive.format != BUNDLE_MAGIC
        || archive.files.is_empty()
        || archive.files.len() > MAX_BUNDLE_FILES
    {
        return Err(UpdateError::InvalidBundle);
    }
    let prepared_name =
        OsString::from(format!("bundle-{}-{}", std::process::id(), unique_nonce()?));
    let prepared = verified.stage.directory.create_child_new(&prepared_name)?;
    if let Err(error) = extract_bundle_files(archive.files, &prepared) {
        let _ = verified
            .stage
            .directory
            .remove_entry_recursive(&prepared_name);
        return Err(error);
    }
    prepared.sync().map_err(UpdateError::Io)?;
    Ok(PreparedArtifact {
        path: prepared.path.clone(),
        source_name: prepared_name,
        handle: prepared.handle.try_clone().map_err(UpdateError::Io)?,
        stage: Arc::clone(&verified.stage),
    })
}

fn extract_bundle_files(
    files: Vec<BundleFile>,
    prepared: &SecureDirectory,
) -> Result<(), UpdateError> {
    let mut seen = BTreeSet::new();
    let mut expanded = 0_u64;
    for entry in files {
        let relative = safe_relative_path(&entry.path)?;
        let collision_key = bundle_collision_key(&entry.path);
        if !seen.insert(collision_key) {
            return Err(UpdateError::InvalidBundle);
        }
        let bytes = STANDARD
            .decode(entry.contents.as_bytes())
            .map_err(|_| UpdateError::InvalidBundle)?;
        if bytes.len() > MAX_BUNDLE_ENTRY_BYTES {
            return Err(UpdateError::InvalidBundle);
        }
        expanded = expanded
            .checked_add(u64::try_from(bytes.len()).map_err(|_| UpdateError::InvalidBundle)?)
            .ok_or(UpdateError::InvalidBundle)?;
        if expanded > MAX_BUNDLE_EXPANDED_BYTES {
            return Err(UpdateError::InvalidBundle);
        }

        let components: Vec<OsString> = relative
            .components()
            .map(|component| component.as_os_str().to_owned())
            .collect();
        let (file_name, directories) = components.split_last().ok_or(UpdateError::InvalidBundle)?;
        let mut directory = prepared.clone();
        for component in directories {
            directory = directory.create_child(component, true)?;
        }
        let mut file = directory.open_regular(file_name, true)?;
        file.write_all(&bytes).map_err(UpdateError::Io)?;
        set_safe_mode(&file, entry.mode)?;
        file.sync_all().map_err(UpdateError::Io)?;
    }
    Ok(())
}

fn bundle_collision_key(path: &str) -> String {
    path.nfc().case_fold().nfc().collect()
}

fn safe_relative_path(value: &str) -> Result<PathBuf, UpdateError> {
    if value.len() > MAX_BUNDLE_PATH_BYTES
        || value.contains('\\')
        || value.contains(':')
        || value.contains('\0')
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(UpdateError::InvalidBundle);
    }
    let path = Path::new(value);
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(UpdateError::InvalidBundle);
    }
    let components: Vec<_> = path.components().collect();
    if components.len() > MAX_BUNDLE_DEPTH
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(UpdateError::InvalidBundle);
    }
    Ok(path.to_owned())
}

#[cfg(unix)]
fn set_safe_mode(file: &File, requested: u32) -> Result<(), UpdateError> {
    let mode = requested & 0o777;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(UpdateError::Io)
}

#[cfg(not(unix))]
fn set_safe_mode(_file: &File, _requested: u32) -> Result<(), UpdateError> {
    Ok(())
}

fn atomic_swap_verified(
    prepared: &PreparedArtifact,
    windows_lock_behavior: bool,
) -> Result<InstallOutcome, UpdateError> {
    let stage = &prepared.stage;
    recover_interrupted_swap(stage)?;
    ensure_entry_identity(&stage.directory, &prepared.source_name, &prepared.handle)?;
    let journal = SwapJournal {
        recovery_digest: object_digest(&stage.directory, &prepared.source_name)?,
    };
    stage
        .directory
        .write_json_atomic(OsStr::new(SWAP_JOURNAL), &journal)?;

    let had_target = stage.parent.object_exists(&stage.target_name)?;
    if had_target
        && let Err(error) =
            stage
                .parent
                .rename_to(&stage.target_name, &stage.parent, &stage.backup_name)
    {
        stage
            .directory
            .remove_file_if_exists(OsStr::new(SWAP_JOURNAL))?;
        if windows_lock_behavior && is_windows_sharing_violation(&error) {
            return Ok(InstallOutcome::RestartRequired {
                staged_path: prepared.path.clone(),
            });
        }
        return Err(UpdateError::Io(error));
    }
    stage.parent.sync().map_err(UpdateError::Io)?;

    if let Err(install) =
        stage
            .directory
            .rename_to(&prepared.source_name, &stage.parent, &stage.target_name)
    {
        return rollback_secure_swap(stage, had_target, install);
    }
    stage.parent.sync().map_err(UpdateError::Io)?;
    if let Err(identity_error) =
        ensure_entry_identity(&stage.parent, &stage.target_name, &prepared.handle)
    {
        let install = io::Error::other(identity_error.to_string());
        return rollback_secure_swap(stage, had_target, install);
    }

    if had_target {
        discard_backup(stage)?;
    }
    stage
        .directory
        .remove_file_if_exists(OsStr::new(STAGED_VERIFIED))?;
    stage
        .directory
        .remove_file_if_exists(OsStr::new(SWAP_JOURNAL))?;
    stage.parent.sync().map_err(UpdateError::Io)?;
    stage.directory.sync().map_err(UpdateError::Io)?;
    Ok(InstallOutcome::Installed)
}

fn rollback_secure_swap(
    stage: &SecureStaging,
    had_target: bool,
    install: io::Error,
) -> Result<InstallOutcome, UpdateError> {
    if !had_target {
        stage
            .directory
            .remove_file_if_exists(OsStr::new(SWAP_JOURNAL))?;
        return Err(UpdateError::Io(install));
    }
    stage.parent.remove_entry_recursive(&stage.target_name)?;
    match stage
        .parent
        .rename_to(&stage.backup_name, &stage.parent, &stage.target_name)
    {
        Ok(()) => {
            stage
                .directory
                .remove_file_if_exists(OsStr::new(SWAP_JOURNAL))?;
            stage.parent.sync().map_err(UpdateError::Io)?;
            Err(UpdateError::InstallRolledBack(install))
        }
        Err(rollback) => Err(UpdateError::RollbackFailed { install, rollback }),
    }
}

#[cfg(test)]
trait FileOps {
    fn exists(&self, path: &Path) -> bool;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove(&self, path: &Path) -> io::Result<()>;
}

#[cfg(test)]
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

    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    const TEST_CERTIFICATE: &str = "MIIBQTCB9KADAgECAgECMAUGAytlcDApMScwJQYDVQQDDB5HVEEgQ2xhdyB1cGRhdGVyIGxvb3BiYWNrIHRlc3QwHhcNMjAwMTAxMDAwMDAwWhcNNDAwMTAxMDAwMDAwWjApMScwJQYDVQQDDB5HVEEgQ2xhdyB1cGRhdGVyIGxvb3BiYWNrIHRlc3QwKjAFBgMrZXADIQARrhPTfditsU9TEgEUTTgu9MLOxHQTU2Ozj2StvH5tJKNBMD8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwBQYDK2VwA0EAzE79rkVmUtNws2e50/SurA89Cb9F0vAGlWc0l8wlh15Tbm09gbrqeW1IH+47zJP8ZT/5yW8XvphiG+ZJ704ACQ==";
    const TEST_PRIVATE_KEY: &str =
        "MC4CAQAwBQYDK2VwBCIEICA2Blt/M1Zjk7maaA54FIXAlRGZAI9sCYJcTQx1ptxh";
    static UNIT_TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

    struct UnitTestDir {
        path: PathBuf,
    }

    impl UnitTestDir {
        fn new(label: &str) -> Self {
            let sequence = UNIT_TEMP_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "gta-claw-updater-unit-{label}-{}-{sequence}",
                std::process::id()
            ));
            if path.exists() {
                fs::remove_dir_all(&path).expect("remove stale unit test directory");
            }
            fs::create_dir(&path).expect("create unit test directory");
            #[cfg(unix)]
            let path = fs::canonicalize(path).expect("resolve system temporary directory aliases");
            #[cfg(windows)]
            lock_down_windows_directory(&path).expect("protect unit test directory");
            Self { path }
        }
    }

    impl Drop for UnitTestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

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

    #[tokio::test]
    async fn https_uses_pinned_native_root_transport_and_exact_request_target() {
        let certificate = CertificateDer::from(
            STANDARD
                .decode(TEST_CERTIFICATE)
                .expect("decode test certificate"),
        );
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            STANDARD
                .decode(TEST_PRIVATE_KEY)
                .expect("decode test private key"),
        ));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("test server protocols")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .expect("test server certificate");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS test server");
        let address = listener.local_addr().expect("TLS test address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS test client");
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .expect("accept TLS handshake");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.expect("read TLS request");
                assert_ne!(count, 0, "request headers must be complete");
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .expect("write TLS response");
            stream.flush().await.expect("flush TLS response");
            String::from_utf8(request).expect("request is ASCII")
        });

        let mut roots = RootCertStore::empty();
        roots.add(certificate).expect("trust test certificate");
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("test client protocols")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let updater = Updater {
            client: Client::builder().build().expect("loopback HTTP client"),
            proxy: Arc::new(ProxyMatcher::builder().build()),
            tls_config: Arc::new(client_config),
            verifying_key: VerifyingKey::from_bytes(&PRODUCTION_PUBLIC_KEY)
                .expect("production key is canonical"),
            target_triple: "test-target".to_owned(),
            state_dir: std::env::temp_dir().join("gta-claw-updater-tls-test"),
            allow_loopback_http: false,
        };
        let url = Url::parse(&format!(
            "https://127.0.0.1:{}/release?channel=stable",
            address.port()
        ))
        .expect("TLS test URL");
        let response = updater.get(&url, None).await.expect("HTTPS GET");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            read_response_limited(response, 5)
                .await
                .expect("read HTTPS response"),
            b"hello"
        );

        let request = server.await.expect("TLS server task");
        let mut sections = request.split("\r\n\r\n");
        let head = sections.next().expect("request head");
        assert_eq!(sections.next(), Some(""));
        assert_eq!(sections.next(), None);
        let mut lines = head.split("\r\n");
        assert_eq!(lines.next(), Some("GET /release?channel=stable HTTP/1.1"));
        let headers = lines
            .map(|line| {
                let (name, value) = line.split_once(": ").expect("valid request header");
                (name.to_ascii_lowercase(), value.to_owned())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            headers,
            BTreeSet::from([
                ("connection".to_owned(), "close".to_owned()),
                ("host".to_owned(), format!("127.0.0.1:{}", address.port())),
                (
                    "user-agent".to_owned(),
                    concat!("gta-claw-updater/", env!("CARGO_PKG_VERSION")).to_owned()
                ),
            ])
        );
    }

    #[tokio::test]
    async fn https_proxy_uses_exact_authenticated_connect_tunnel() {
        let certificate = CertificateDer::from(
            STANDARD
                .decode(TEST_CERTIFICATE)
                .expect("decode test certificate"),
        );
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            STANDARD
                .decode(TEST_PRIVATE_KEY)
                .expect("decode test private key"),
        ));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("proxy server protocols")
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .expect("proxy server certificate");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind proxy test server");
        let address = listener.local_addr().expect("proxy test address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept proxy client");
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .expect("accept proxy TLS handshake");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.expect("read CONNECT");
                assert_ne!(count, 0, "CONNECT headers must be complete");
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("write CONNECT response");
            stream.flush().await.expect("flush CONNECT response");
            String::from_utf8(request).expect("CONNECT request is ASCII")
        });
        let proxy = ProxyMatcher::builder()
            .https(format!(
                "https://Aladdin:opensesame@127.0.0.1:{}",
                address.port()
            ))
            .build();
        let mut roots = RootCertStore::empty();
        roots.add(certificate).expect("trust proxy certificate");
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("proxy client protocols")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let updater = Updater {
            client: Client::builder().build().expect("loopback HTTP client"),
            proxy: Arc::new(proxy),
            tls_config: Arc::new(client_config),
            verifying_key: VerifyingKey::from_bytes(&PRODUCTION_PUBLIC_KEY)
                .expect("production key is canonical"),
            target_triple: "test-target".to_owned(),
            state_dir: std::env::temp_dir().join("gta-claw-updater-proxy-test"),
            allow_loopback_http: false,
        };
        let url = Url::parse("https://updates.example.invalid/release").expect("proxy target URL");
        let stream = updater
            .connect_https_stream(&url)
            .await
            .expect("CONNECT tunnel");
        drop(stream);
        assert_eq!(
            server.await.expect("proxy server task"),
            concat!(
                "CONNECT updates.example.invalid:443 HTTP/1.1\r\n",
                "Host: updates.example.invalid:443\r\n",
                "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuc2VzYW1l\r\n",
                "\r\n"
            )
        );
    }

    #[test]
    fn real_filesystem_commit_and_crash_recovery_preserve_object_identity() {
        let directory = UnitTestDir::new("real-commit");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"old executable").expect("write old executable");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = Arc::new(SecureStaging::open(&target).expect("secure stage"));
        let mut staged = stage
            .directory
            .open_regular(OsStr::new(STAGED_VERIFIED), true)
            .expect("create staged executable");
        staged
            .write_all(b"new executable")
            .expect("write staged executable");
        staged.sync_all().expect("sync staged executable");
        let prepared = PreparedArtifact {
            path: stage.directory.path.join(STAGED_VERIFIED),
            source_name: OsString::from(STAGED_VERIFIED),
            handle: staged,
            stage: Arc::clone(&stage),
        };

        let outcome = atomic_swap_verified(&prepared, false).expect("real commit succeeds");
        assert_eq!(outcome, InstallOutcome::Installed);
        assert_eq!(
            fs::read(&target_path).expect("read installed executable"),
            b"new executable"
        );
        assert!(
            !stage
                .parent
                .object_exists(&stage.backup_name)
                .expect("backup state")
        );

        let mut next = stage
            .directory
            .open_regular(OsStr::new(STAGED_VERIFIED), true)
            .expect("create next staged executable");
        next.write_all(b"third executable")
            .expect("write next executable");
        next.sync_all().expect("sync next executable");
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    recovery_digest: object_digest(&stage.directory, OsStr::new(STAGED_VERIFIED))
                        .expect("staged digest"),
                },
            )
            .expect("write swap journal");
        stage
            .parent
            .rename_to(&stage.target_name, &stage.parent, &stage.backup_name)
            .expect("simulate first rename before crash");
        assert!(!target_path.exists());

        recover_interrupted_swap(&stage).expect("recover interrupted rename");
        assert_eq!(
            fs::read(&target_path).expect("read recovered executable"),
            b"new executable"
        );
        assert!(
            !stage
                .parent
                .object_exists(&stage.backup_name)
                .expect("backup state")
        );
        assert!(
            !stage
                .directory
                .object_exists(OsStr::new(SWAP_JOURNAL))
                .expect("journal state")
        );
    }

    #[test]
    fn real_filesystem_rollback_removes_failed_object_and_restores_backup() {
        let directory = UnitTestDir::new("real-rollback");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"known good").expect("write old executable");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        stage
            .parent
            .rename_to(&stage.target_name, &stage.parent, &stage.backup_name)
            .expect("move target to backup");
        let mut failed = stage
            .parent
            .open_regular(&stage.target_name, true)
            .expect("create failed replacement");
        failed
            .write_all(b"untrusted replacement")
            .expect("write failed replacement");
        failed.sync_all().expect("sync failed replacement");
        drop(failed);

        let error = rollback_secure_swap(
            &stage,
            true,
            io::Error::other("simulated real rename failure"),
        )
        .expect_err("real rollback is reported");
        assert_eq!(
            error.to_string(),
            "update installation failed; previous version was restored"
        );
        assert_eq!(
            fs::read(&target_path).expect("read restored executable"),
            b"known good"
        );
        assert!(
            !stage
                .parent
                .object_exists(&stage.backup_name)
                .expect("backup state")
        );
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_sharing_lock_keeps_verified_object_staged() {
        use std::os::windows::fs::OpenOptionsExt as _;

        let directory = UnitTestDir::new("windows-lock");
        let target_path = directory.path.join("gta-claw.exe");
        fs::write(&target_path, b"running executable").expect("write running executable");
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&target_path)
            .expect("lock running executable");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = Arc::new(SecureStaging::open(&target).expect("secure stage"));
        let mut staged = stage
            .directory
            .open_regular(OsStr::new(STAGED_VERIFIED), true)
            .expect("create staged executable");
        staged
            .write_all(b"verified replacement")
            .expect("write staged executable");
        staged.sync_all().expect("sync staged executable");
        let staged_path = stage.directory.path.join(STAGED_VERIFIED);
        let prepared = PreparedArtifact {
            path: staged_path.clone(),
            source_name: OsString::from(STAGED_VERIFIED),
            handle: staged,
            stage,
        };

        let outcome =
            atomic_swap_verified(&prepared, true).expect("sharing lock is restart-required");
        assert_eq!(
            outcome,
            InstallOutcome::RestartRequired {
                staged_path: staged_path.clone(),
            }
        );
        drop(lock);
        assert_eq!(
            fs::read(&target_path).expect("read locked executable"),
            b"running executable"
        );
        assert_eq!(
            fs::read(staged_path).expect("read retained staged executable"),
            b"verified replacement"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_shared_parent_is_rejected_before_staging_creation() {
        use windows_acl::acl::ACL;
        use windows_acl::helper::string_to_sid;

        const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
        let directory = UnitTestDir::new("shared-parent");
        let target_path = directory.path.join("gta-claw.exe");
        fs::write(&target_path, b"old executable").expect("write target");
        let everyone = string_to_sid("S-1-1-0").expect("Everyone SID");
        let mut acl =
            ACL::from_file_path(directory.path.to_str().expect("Unicode test path"), false)
                .expect("open parent ACL");
        assert!(
            acl.allow(everyone.as_ptr().cast_mut().cast(), true, FILE_ALL_ACCESS)
                .expect("make parent shared"),
            "Everyone ACE must be applied"
        );
        let target = InstallTarget::new(target_path, InstallMode::Executable).expect("target");

        let error = SecureStaging::open(&target).expect_err("shared parent rejected");
        assert_eq!(
            error.to_string(),
            "updater refused an unsafe filesystem object"
        );
        assert!(!directory.path.join(".gta-claw.exe.gta-claw-stage").exists());
    }

    #[cfg(unix)]
    #[test]
    fn real_symlink_staging_and_partial_objects_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = UnitTestDir::new("symlink");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"old").expect("write target");
        let target = InstallTarget::new(target_path, InstallMode::Executable).expect("target");
        let outside = directory.path.join("outside");
        fs::create_dir(&outside).expect("create outside directory");
        let stage_path = directory.path.join(".gta-claw.gta-claw-stage");
        symlink(&outside, &stage_path).expect("create stage symlink");
        let stage_error = SecureStaging::open(&target).expect_err("stage symlink rejected");
        assert_eq!(
            stage_error.to_string(),
            "updater refused an unsafe filesystem object"
        );
        fs::remove_file(&stage_path).expect("remove stage symlink");

        let stage = SecureStaging::open(&target).expect("create secure stage");
        let outside_file = outside.join("victim");
        fs::write(&outside_file, b"unchanged").expect("write outside file");
        symlink(&outside_file, stage.directory.path.join(STAGED_PART))
            .expect("create partial symlink");
        let part_error = stage
            .directory
            .open_regular(OsStr::new(STAGED_PART), false)
            .expect_err("partial symlink rejected");
        assert_eq!(
            part_error.to_string(),
            "updater refused an unsafe filesystem object"
        );
        assert_eq!(
            fs::read(outside_file).expect("read outside file"),
            b"unchanged"
        );
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
        assert_eq!(
            safe_relative_path(&"a".repeat(MAX_BUNDLE_PATH_BYTES + 1))
                .expect_err("oversized bundle path rejected")
                .to_string(),
            "macOS bundle archive is invalid"
        );
        assert_eq!(
            bundle_collision_key("Contents/Info.plist"),
            bundle_collision_key("contents/info.plist")
        );
        assert_eq!(
            bundle_collision_key("Contents/Caf\u{00e9}"),
            bundle_collision_key("contents/Cafe\u{0301}")
        );
        assert_eq!(
            bundle_collision_key("Contents/STRA\u{00df}E"),
            bundle_collision_key("contents/strasse")
        );
    }

    #[test]
    fn production_http_and_loopback_names_are_rejected() {
        let literal = Url::parse("http://127.0.0.1:8080/release").expect("literal loopback URL");
        validate_network_url(&literal, true).expect("literal test loopback accepted");
        assert_eq!(
            validate_network_url(&literal, false)
                .expect_err("production HTTP rejected")
                .to_string(),
            "updates require HTTPS or loopback HTTP"
        );
        let localhost = Url::parse("http://localhost:8080/release").expect("localhost URL");
        assert_eq!(
            validate_network_url(&localhost, true)
                .expect_err("loopback name rejected")
                .to_string(),
            "updates require HTTPS or loopback HTTP"
        );
    }
}

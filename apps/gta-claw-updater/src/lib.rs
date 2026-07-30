//! Signed, resumable, and rollback-safe GTA Claw updater.
//!
//! A verified artifact remains bound to its signed release until installation
//! succeeds, so a restart-required retry reuses local bytes instead of fetching
//! them again. Successful installs remove staging artifacts and obsolete
//! anti-rollback floor files.

use std::cell::{Cell, RefCell};
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
use url::{Host, Position, Url};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_PROXY_RESPONSE_HEAD_BYTES: usize = 32 * 1024;
const MAX_CLOCK_SKEW_SECONDS: u64 = 5 * 60;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const STAGED_PART: &str = "artifact.part";
const STAGED_VERIFIED: &str = "artifact.verified";
const RESUME_BINDING: &str = "artifact.resume.json";
const SWAP_JOURNAL: &str = "swap-journal.json";
const ROLLBACK_LOCK: &str = "release-floor.lock";
const STAGE_LOCK: &str = "stage.lock";
const DURABLE_MARKER: &str = ".gta-claw-durable";
const QUARANTINE_PREFIX: &str = ".retired-backup-";
const DURABLE_MARKER_CONTENTS: &[u8] = b"gta-claw-updater-durable-v1";

trait UpdateIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> UpdateIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Exit status of a process stopped by an armed [`InjectedFault`].
#[doc(hidden)]
pub const INJECTED_FAULT_EXIT_CODE: i32 = 91;

/// A durability step that this crate's own crash tests can stop or fail.
///
/// Every fault is inert until the running thread arms it with
/// [`arm_injected_fault`], and the updater itself never arms one. They exist
/// because a power-loss window between two durable filesystem steps cannot be
/// reproduced from outside the process: the child has to stop *inside* the
/// swap, not between two library calls.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InjectedFault {
    /// Stop the process once the swap journal records the prepared phase.
    ExitAfterSwapPrepared,
    /// Stop the process once the swap journal records the committed phase.
    ExitAfterSwapCommitted,
    /// Fail the parent sync that makes a newly created state directory durable.
    FailNewStateDirectorySync,
    /// Fail the first parent sync after the installed target is renamed aside.
    FailParentSyncAfterSwap,
    /// Stop the process once the target has been moved aside durably, before
    /// the journal records the committed phase.
    ExitAfterTargetMovedAside,
    /// Stop the process once a recovery restore is durable, before its journal
    /// is removed.
    ExitAfterRecoveryRestore,
    /// Fail the read-back of the installation this run just moved aside.
    FailMovedAsideDigest,
    /// Fail the parent sync that follows removing a failed replacement.
    FailParentSyncDuringRollback,
    /// Stop the process once the durability marker exists but is still empty.
    ExitAfterEmptyDurabilityMarker,
    /// Stop the process once a quarantine is journalled but nothing has moved.
    ExitAfterQuarantinePlanned,
    /// Stop the process once a quarantined object has moved but not been deleted.
    ExitAfterQuarantineMoved,
    /// Fail the identity re-check that publication depends on.
    FailPublishedIdentity,
}

impl InjectedFault {
    const fn code(self) -> u8 {
        match self {
            Self::ExitAfterSwapPrepared => 1,
            Self::ExitAfterSwapCommitted => 2,
            Self::FailNewStateDirectorySync => 3,
            Self::FailParentSyncAfterSwap => 4,
            Self::ExitAfterTargetMovedAside => 5,
            Self::ExitAfterRecoveryRestore => 6,
            Self::FailMovedAsideDigest => 8,
            Self::FailParentSyncDuringRollback => 10,
            Self::ExitAfterEmptyDurabilityMarker => 11,
            Self::ExitAfterQuarantinePlanned => 12,
            Self::ExitAfterQuarantineMoved => 13,
            Self::FailPublishedIdentity => 14,
        }
    }
}

thread_local! {
    static ARMED_FAULT: Cell<u8> = const { Cell::new(0) };
    static FAULT_SKIPS: Cell<u32> = const { Cell::new(0) };
    /// Faults queued behind the armed one, consumed in order as each fires.
    static FAULT_SCRIPT: RefCell<Vec<(u8, u32)>> = const { RefCell::new(Vec::new()) };
}

/// Arms one fault for the rest of this thread.
///
/// Every step an updater run makes through these points happens on the thread
/// that called it, and keeping the arming thread-local means one armed test
/// cannot reach another thread's run.
#[doc(hidden)]
pub fn arm_injected_fault(fault: InjectedFault) {
    arm_injected_fault_after(fault, 0);
}

/// Arms one fault to fire only after `skips` earlier chances to fire.
///
/// A durability step that runs several times per call — confirming each level
/// of a directory tree, say — needs the failure aimed at one specific
/// occurrence. Without that, a fault on the first occurrence stops the run
/// before the state a test is about to inspect has been created at all.
#[doc(hidden)]
pub fn arm_injected_fault_after(fault: InjectedFault, skips: u32) {
    arm_injected_fault_script(&[(fault, skips)]);
}

/// Arms an ordered script of faults, each firing after its own skip count.
///
/// A single armed fault can only describe one crash. Recovery behaviour needs
/// more: stop a run mid-move, let the next run get further, stop it again. The
/// script advances as each entry fires, so one process can walk a sequence of
/// boundaries in order instead of the test having to guess which call a lone
/// counter will land on.
#[doc(hidden)]
pub fn arm_injected_fault_script(script: &[(InjectedFault, u32)]) {
    let mut queued: Vec<(u8, u32)> = script
        .iter()
        .map(|(fault, skips)| (fault.code(), *skips))
        .collect();
    let (code, skips) = if queued.is_empty() {
        (0, 0)
    } else {
        queued.remove(0)
    };
    ARMED_FAULT.with(|armed| armed.set(code));
    FAULT_SKIPS.with(|remaining| remaining.set(skips));
    FAULT_SCRIPT.with(|rest| rest.replace(queued));
}

/// Clears any fault, and any queued script, armed on this thread.
#[doc(hidden)]
pub fn disarm_injected_fault() {
    ARMED_FAULT.with(|armed| armed.set(0));
    FAULT_SKIPS.with(|remaining| remaining.set(0));
    FAULT_SCRIPT.with(|rest| rest.borrow_mut().clear());
}

/// Moves to the next entry of an armed script once the current one has fired.
fn advance_fault_script() {
    let next = FAULT_SCRIPT.with(|rest| {
        let mut rest = rest.borrow_mut();
        if rest.is_empty() {
            None
        } else {
            Some(rest.remove(0))
        }
    });
    let (code, skips) = next.unwrap_or((0, 0));
    ARMED_FAULT.with(|armed| armed.set(code));
    FAULT_SKIPS.with(|remaining| remaining.set(skips));
}

fn fault_is_armed(fault: InjectedFault) -> bool {
    if ARMED_FAULT.with(Cell::get) != fault.code() {
        return false;
    }
    let remaining = FAULT_SKIPS.with(Cell::get);
    if remaining > 0 {
        FAULT_SKIPS.with(|skips| skips.set(remaining - 1));
        return false;
    }
    advance_fault_script();
    true
}

/// Stops the process at `fault` when it is armed, leaving the disk exactly as
/// the durable steps before it left it.
fn exit_at_armed_fault(fault: InjectedFault) {
    if fault_is_armed(fault) {
        std::process::exit(INJECTED_FAULT_EXIT_CODE);
    }
}

#[cfg(not(windows))]
fn armed_fault_error(fault: InjectedFault) -> Option<io::Error> {
    fault_is_armed(fault).then(|| io::Error::other("injected updater durability fault"))
}

/// Runs blocking updater work on the blocking pool instead of the runtime thread.
///
/// Taking the staging or anti-rollback lock waits for whatever other updater run
/// currently holds it, and on Windows that wait is a retry loop that can last
/// minutes. Doing it inline would stall a current-thread runtime completely and
/// starve a multi-thread one, so every lock-taking step is moved off the runtime.
///
/// An armed [`InjectedFault`] is thread-local, so it is carried over to the
/// blocking thread explicitly; nothing else observes it.
async fn run_off_runtime<T, F>(work: F) -> Result<T, UpdateError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, UpdateError> + Send + 'static,
{
    let armed = ARMED_FAULT.with(Cell::get);
    let skips = FAULT_SKIPS.with(Cell::get);
    let script = FAULT_SCRIPT.with(|rest| rest.borrow().clone());
    tokio::task::spawn_blocking(move || {
        ARMED_FAULT.with(|fault| fault.set(armed));
        FAULT_SKIPS.with(|remaining| remaining.set(skips));
        FAULT_SCRIPT.with(|rest| rest.replace(script));
        work()
    })
    .await
    .map_err(UpdateError::BlockingTask)?
}

/// Opens the staging directory, and waits for its lock, off the runtime thread.
async fn open_staging_off_runtime(target: InstallTarget) -> Result<SecureStaging, UpdateError> {
    run_off_runtime(move || SecureStaging::open(&target)).await
}

/// Refuses to run where the durability primitives this crate depends on are absent.
///
/// Every persistent decision the updater makes — the anti-rollback floor, the
/// staging journal, the install swap — is only sound if a directory entry can be
/// forced to disk before the next step depends on it. That needs a
/// directory-metadata flush.
///
/// Windows has none reachable from here: `File::sync_all` on a directory handle
/// is not a supported operation, and the volume flush that would substitute for
/// it needs a raw handle and administrative rights. This crate's Windows
/// directory syncs were therefore `Ok(())` — the ordering was never enforced,
/// and every guarantee built on it was a claim rather than a fact.
///
/// Telling one filesystem object from another is blocked by the same wall:
/// `MetadataExt::file_index`/`volume_serial_number` are unstable
/// (`windows_by_handle`, rust-lang/rust#63010), the raw
/// `GetFileInformationByHandle` call and handle-relative `NtCreateFile`
/// operations need `unsafe`, which this workspace sets to `forbid` — a level a
/// crate cannot override — and `--locked` builds rule out adding a wrapper.
///
/// So this refuses **before touching anything**: no anti-rollback floor is
/// written or pruned, no staging directory is created, no target is moved.
/// Refusing to start is the honest outcome; mutating state whose ordering
/// cannot be enforced, and reporting it as durable, is not.
///
/// [`Updater::verify_manifest`] is unaffected: it only inspects bytes.
const fn ensure_durable_platform() -> Result<(), UpdateError> {
    if cfg!(windows) {
        Err(UpdateError::PlatformDurabilityUnsupported)
    } else {
        Ok(())
    }
}

/// Streaming scratch space kept on the heap.
///
/// `update_object_digest` recurses once per bundle directory level and
/// `hash_handle` is held across an `await`, so a stack array of this size would
/// both multiply the recursion frame and inflate every download future.
fn stream_buffer() -> Vec<u8> {
    vec![0_u8; STREAM_BUFFER_BYTES]
}

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

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ResumeBinding {
    target: String,
    url: String,
    size: u64,
    sha256: String,
    kind: ArtifactKind,
    release_sequence: u64,
}

impl fmt::Debug for ResumeBinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResumeBinding")
            .field("target", &self.target)
            .field("url", &"<redacted>")
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .field("kind", &self.kind)
            .field("release_sequence", &self.release_sequence)
            .finish()
    }
}

/// Progress of one `target` -> `rollback` -> `target` swap.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SwapPhase {
    /// The journal is durable and nothing on disk has been moved yet.
    Prepared,
    /// The target slot belongs to this run: any previous install is in the rollback object.
    Swapped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SwapJournal {
    phase: SwapPhase,
    recovery_digest: String,
    original_digest: Option<String>,
    /// Rollback object moved into staging and not yet resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quarantine: Option<Quarantine>,
}

/// An object this run is moving out of the install directory to delete it.
///
/// Written before the move, so a restart always knows what a leftover
/// quarantined object is and where it belongs. Without it a restart would find
/// an unexplained object under a name it invented and could only guess — and
/// the only safe guess is never to delete.
///
/// The record names both endpoints and the phase, because the move has three
/// observable outcomes and they are not distinguishable from the filesystem
/// alone: nothing moved, both names present, or only the quarantine present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Quarantine {
    /// What the quarantine is for, which decides where a rejected object goes.
    operation: QuarantineKind,
    /// The name in the install directory the object was taken from.
    source: String,
    /// The name inside the private staging directory it was moved to.
    destination: String,
    /// The identity the object must still have to be deleted.
    digest: String,
    /// How far the move had got when this record was last written.
    phase: QuarantinePhase,
}

/// Which object a quarantine is retiring.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum QuarantineKind {
    /// The superseded installation, once the replacement is in place.
    RetiredBackup,
    /// A replacement this run placed and then had to withdraw.
    WithdrawnInstall,
}

impl QuarantineKind {
    /// Whether a quarantined object may be put back under the name it came from.
    ///
    /// A retired backup came from the rollback slot, where it is inert, so
    /// putting it back is the safe outcome when it cannot be verified for
    /// deletion. A withdrawn install came from the **target name**: restoring
    /// it would republish the very replacement this run already decided not to
    /// keep, as the live installation. It stays quarantined instead, where the
    /// journal still describes it and a later run can identify it.
    const fn may_return_to_source(self) -> bool {
        matches!(self, Self::RetiredBackup)
    }
}

/// How far a quarantine move had progressed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum QuarantinePhase {
    /// The record is durable; the object is still under its source name.
    Planned,
    /// The object has been moved to the quarantine name.
    Moved,
}

/// One signed update artifact.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    /// Signed release sequence this artifact belongs to.
    pub release_sequence: u64,
    /// Exact Rust target triple.
    pub target: String,
    /// HTTPS URL, or loopback HTTP URL for local operation and tests. Debug output redacts it.
    pub url: String,
    /// Lowercase SHA-256 hex digest.
    pub sha256: String,
    /// Exact expected byte length.
    pub size: u64,
    /// Installation format.
    pub kind: ArtifactKind,
}

impl fmt::Debug for ReleaseArtifact {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleaseArtifact")
            .field("release_sequence", &self.release_sequence)
            .field("target", &self.target)
            .field("url", &"<redacted>")
            .field("sha256", &self.sha256)
            .field("size", &self.size)
            .field("kind", &self.kind)
            .finish()
    }
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
        /// Matching artifact bound to its signed release authorization.
        update: AvailableUpdate,
    },
}

/// Opaque signed authorization for one available artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailableUpdate {
    artifact: ReleaseArtifact,
    authorization: ReleaseAuthorization,
}

impl AvailableUpdate {
    /// Returns the signed artifact metadata.
    #[must_use]
    pub const fn artifact(&self) -> &ReleaseArtifact {
        &self.artifact
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleaseAuthorization {
    sequence: u64,
    version: String,
    published_at_unix: u64,
    expires_at_unix: u64,
    manifest_sha256: String,
    artifact_sha256: String,
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
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidInstallTarget`] when `path` has no file
    /// name or no parent directory, or when `mode` is
    /// [`InstallMode::MacOsBundle`] and `path` does not end in `.app`. Nothing
    /// is read from or written to disk, so this cannot fail for I/O reasons.
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

/// Retires the rollback object once the replacement is installed.
///
/// `original_digest` is the identity the run recorded before it moved the
/// installation aside, and it is required: an object with no recorded identity
/// was never this run's to retire. Deleting one that no longer matches would
/// discard an installation this run never measured, so a mismatch is reported.
fn discard_backup(
    stage: &SecureStaging,
    journal: &SwapJournal,
    original_digest: &str,
) -> Result<(), UpdateError> {
    // Quarantine first, then verify. Hashing the object under its public name
    // and deleting it afterwards leaves a window in which the thing that was
    // measured is not the thing that is removed; moving it into the private
    // staging directory first closes that window, because nothing outside this
    // run knows the quarantine name and the staging directory is owner-only.
    //
    // The quarantine name and the identity it is expected to hold are journalled
    // *before* the move, so a crash in the middle leaves a leftover that the
    // next run can identify instead of guess at.
    quarantine_and_delete(
        stage,
        journal,
        QuarantineKind::RetiredBackup,
        &stage.backup_name,
        original_digest,
    )
}

/// Resolves a rollback object an interrupted run had moved into staging.
///
/// A quarantined object is only ever removed when the journal says it is the
/// recorded original *and* it still hashes to that identity; anything else goes
/// back under the rollback name. A leftover with no journal entry describing it
/// is not this run's to interpret, so it is reported rather than deleted: a
/// blind sweep is exactly how an installation nobody can recover gets thrown
/// away after a restart.
fn resolve_quarantine(
    stage: &SecureStaging,
    quarantine: Option<&Quarantine>,
) -> Result<(), UpdateError> {
    // Any quarantined object the journal does not describe belongs to something
    // this run cannot identify, so it is reported rather than swept.
    let recorded = quarantine.map(|record| OsString::from(&record.destination));
    for name in stage.directory.list_names()? {
        let Some(text) = name.to_str() else {
            continue;
        };
        if text.starts_with(QUARANTINE_PREFIX) && recorded.as_deref() != Some(name.as_os_str()) {
            return Err(UpdateError::SwapRecoveryConflict);
        }
    }

    let Some(record) = quarantine else {
        return Ok(());
    };
    let source = OsString::from(&record.source);
    let destination = OsString::from(&record.destination);
    let source_present = stage.parent.object_exists(&source)?;
    let destination_present = stage.directory.object_exists(&destination)?;

    match (record.phase, source_present, destination_present) {
        // Recorded but never moved: the object is still where it started and
        // nothing is owed. Deleting from here would be acting on a plan that
        // never began.
        (QuarantinePhase::Planned, true, false) => Ok(()),

        // The move landed; the phase update did not. Finish the deletion the
        // record describes, which re-verifies identity before removing anything.
        (QuarantinePhase::Planned | QuarantinePhase::Moved, false, true) => {
            finish_quarantine(
                stage,
                &destination,
                &record.digest,
                record.operation.may_return_to_source().then_some(&*source),
            )
        }

        // Both names present. On a filesystem with an atomic no-replace rename
        // this cannot arise from the move itself, so something else took the
        // source name and the two objects cannot be told apart by role.
        (_, true, true) => Err(UpdateError::SwapRecoveryConflict),

        // Neither name present. The deletion completed and the source was never
        // meant to come back, so there is nothing left to do — but only when the
        // record says the move had actually happened. A `Planned` record with
        // its source gone means the object vanished before this run touched it,
        // which is not a state to call success.
        (QuarantinePhase::Moved, false, false) => Ok(()),
        (QuarantinePhase::Planned, false, false) => Err(UpdateError::SwapRecoveryConflict),

        // Moved away, yet the source name is occupied again. Whatever is there
        // cannot be the quarantined object — that one was moved out and, with
        // the destination gone, deleted. So an independent object took the name
        // while this run was interrupted.
        //
        // Reporting it matters more than it looks: recovery reads the rollback
        // name straight after this, and a bare `Ok` would let that foreign
        // object be measured and restored as the installation.
        (QuarantinePhase::Moved, true, false) => Err(UpdateError::SwapRecoveryConflict),
    }
}

/// Moves an object out of the install directory and deletes it, recoverably.
///
/// The record naming both endpoints, the identity and the phase is made durable
/// *before* the move and updated after it, so a restart can tell "nothing moved"
/// from "moved but not yet deleted" instead of inferring it from which names
/// happen to exist.
fn quarantine_and_delete(
    stage: &SecureStaging,
    journal: &SwapJournal,
    operation: QuarantineKind,
    source: &OsStr,
    expected: &str,
) -> Result<(), UpdateError> {
    let destination = OsString::from(format!("{QUARANTINE_PREFIX}{}", unique_nonce()?));
    let mut record = Quarantine {
        operation,
        source: source.to_string_lossy().into_owned(),
        destination: destination.to_string_lossy().into_owned(),
        digest: expected.to_owned(),
        phase: QuarantinePhase::Planned,
    };
    let mut pending = journal.clone();
    pending.quarantine = Some(record.clone());
    stage
        .directory
        .write_json_atomic(OsStr::new(SWAP_JOURNAL), &pending)?;
    exit_at_armed_fault(InjectedFault::ExitAfterQuarantinePlanned);

    stage
        .parent
        .rename_to_new(source, &stage.directory, &destination)?;

    record.phase = QuarantinePhase::Moved;
    pending.quarantine = Some(record);
    stage
        .directory
        .write_json_atomic(OsStr::new(SWAP_JOURNAL), &pending)?;
    exit_at_armed_fault(InjectedFault::ExitAfterQuarantineMoved);

    finish_quarantine(
        stage,
        &destination,
        expected,
        operation.may_return_to_source().then_some(source),
    )
}

/// Deletes a quarantined object, but only while it is still the one measured.
///
/// The object is opened once and that handle is held across the digest and the
/// unlink, and the directory entry is re-checked against it immediately before
/// the unlink. Digesting a name and then deleting that name leaves a window in
/// which the two are not the same object; holding the handle and re-verifying
/// closes it as tightly as POSIX allows, since the unlink itself goes through
/// the retained directory handle rather than a resolved path.
///
/// An object that fails any of those checks is put back under `restore_to`
/// rather than left stranded in the private staging directory, where no later
/// run would look for it.
fn finish_quarantine(
    stage: &SecureStaging,
    retired: &OsStr,
    expected: &str,
    restore_to: Option<&OsStr>,
) -> Result<(), UpdateError> {
    let kept = match stage.directory.open_object(retired) {
        Ok(object) => object,
        Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(restore_quarantined(stage, retired, restore_to, error)),
    };
    let measured = match kept.try_clone() {
        Ok(handle) => handle,
        Err(error) => {
            return Err(restore_quarantined(
                stage,
                retired,
                restore_to,
                UpdateError::Io(error),
            ));
        }
    };
    let path = stage.directory.path.join(retired);
    match object_digest_of(measured, &path) {
        Ok(digest) if digest == expected => {}
        Ok(_) => {
            return Err(restore_quarantined(
                stage,
                retired,
                restore_to,
                UpdateError::SwapRecoveryConflict,
            ));
        }
        Err(error) => return Err(restore_quarantined(stage, retired, restore_to, error)),
    }

    // Re-checked against the very handle that was digested, so the entry about
    // to be unlinked is provably the object that was measured.
    if let Err(error) = ensure_entry_identity(&stage.directory, retired, &kept) {
        return Err(restore_quarantined(stage, retired, restore_to, error));
    }
    drop(kept);
    stage.directory.remove_entry_recursive(retired)?;
    stage.directory.sync().map_err(UpdateError::Io)
}

/// Puts a quarantined object back under the name it came from.
fn restore_quarantined(
    stage: &SecureStaging,
    retired: &OsStr,
    restore_to: Option<&OsStr>,
    reason: UpdateError,
) -> UpdateError {
    // No name to go back to means the object must not become live again. It
    // stays under its quarantine name, which the journal still records, so the
    // next run can identify it instead of finding an unexplained object.
    let Some(restore_to) = restore_to else {
        return reason;
    };
    match stage
        .directory
        .rename_to_new(retired, &stage.parent, restore_to)
    {
        Ok(()) => reason,
        Err(error) => error,
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
    /// The target was locked by a running process, so nothing was installed.
    ///
    /// No staging path is reported. Close the application and run the update
    /// again: the rerun re-fetches and re-verifies the release from scratch,
    /// because bytes left on disk across a restart are not trustworthy enough
    /// to install from. See [`InstallOutcome::RestartRequired`].
    RestartRequired {
        /// New version.
        version: Version,
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
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidPublicKey`] if [`PRODUCTION_PUBLIC_KEY`]
    /// is not a canonical Ed25519 point,
    /// [`UpdateError::StateDirectoryUnavailable`] if the per-user state
    /// directory cannot be derived from the environment,
    /// [`UpdateError::NativeRootsUnavailable`] or
    /// [`UpdateError::TlsConfiguration`] if no usable platform root
    /// certificates exist, and [`UpdateError::Http`] if the HTTP client itself
    /// cannot be constructed. All of these are configuration faults: retrying
    /// without changing the environment will fail the same way.
    pub fn production(target_triple: impl Into<String>) -> Result<Self, UpdateError> {
        Self::build(
            PRODUCTION_PUBLIC_KEY,
            target_triple.into(),
            default_state_dir()?,
            false,
        )
    }

    /// Creates an updater with an explicit trust root, primarily for isolated tests.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Updater::production`], except that
    /// [`UpdateError::InvalidPublicKey`] now reports a caller-supplied
    /// `public_key` that is not a canonical Ed25519 point.
    pub fn with_public_key(
        public_key: [u8; 32],
        target_triple: impl Into<String>,
    ) -> Result<Self, UpdateError> {
        Self::build(public_key, target_triple.into(), default_state_dir()?, true)
    }

    /// Creates an isolated updater with an explicit trust root and protected state directory.
    ///
    /// # Errors
    ///
    /// Same conditions as [`Updater::with_public_key`], except that the
    /// caller-supplied `state_dir` replaces the derived one, so
    /// [`UpdateError::StateDirectoryUnavailable`] cannot occur here.
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
            .timeout(Duration::from_mins(5))
            .user_agent(concat!("gta-claw-updater/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(redact_http_error)?;
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
    ///
    /// An up-to-date installation is **not** an error: it is reported as an
    /// `Ok` value holding [`UpdateDecision::Current`].
    ///
    /// # Errors
    ///
    /// Transient, safe to retry later: [`UpdateError::Http`],
    /// [`UpdateError::HttpsIo`], [`UpdateError::HttpsProtocol`],
    /// [`UpdateError::HttpTask`], [`UpdateError::HttpTimeout`],
    /// [`UpdateError::HttpStatus`], [`UpdateError::InvalidProxyResponse`] and
    /// [`UpdateError::UnsupportedProxy`] all mean the release server, proxy or
    /// network could not be reached within the fixed 5 minute transfer budget.
    /// [`UpdateError::NativeRootsUnavailable`] and
    /// [`UpdateError::TlsConfiguration`] mean the platform trust store is
    /// unusable.
    ///
    /// Do not retry, and do not install anything: [`UpdateError::ForgedManifest`]
    /// means the served bytes are not signed by the trusted release key,
    /// [`UpdateError::InvalidSignatureEncoding`] that the signature field is not
    /// decodable Ed25519 data, and [`UpdateError::RollbackManifest`],
    /// [`UpdateError::RollbackVersion`] or
    /// [`UpdateError::ReleaseSequenceConflict`] that a validly signed but
    /// *older or conflicting* release was replayed at this client. Treat these
    /// as an attack on the update channel.
    ///
    /// Also possible: [`UpdateError::InsecureUrl`] or
    /// [`UpdateError::CredentialBearingUrl`] for a rejected `manifest_url`,
    /// [`UpdateError::ManifestTooLarge`] above the 1 MiB cap,
    /// [`UpdateError::ManifestJson`], [`UpdateError::InvalidVersion`],
    /// [`UpdateError::InvalidReleaseMetadata`], [`UpdateError::ExpiredManifest`],
    /// the artifact validation errors listed on
    /// [`Updater::verify_manifest`], [`UpdateError::CurrentReleaseRevoked`] or
    /// [`UpdateError::RevokedRelease`] for a withdrawn release,
    /// [`UpdateError::ArtifactUnavailable`] when no artifact matches this target
    /// triple, and [`UpdateError::CorruptState`],
    /// [`UpdateError::UnsafeFilesystemObject`],
    /// [`UpdateError::BlockingTask`] or [`UpdateError::Io`] while persisting the
    /// anti-rollback floor.
    pub async fn check(
        &self,
        manifest_url: &Url,
        current: &Version,
    ) -> Result<UpdateDecision, UpdateError> {
        // Before the network, because accepting a manifest persists the
        // anti-rollback floor and prunes older ones.
        ensure_durable_platform()?;
        validate_network_url(manifest_url, self.allow_loopback_http)?;
        let response = self.get(manifest_url, None).await?;
        ensure_success(response.status())?;
        let bytes = tokio::time::timeout(
            Duration::from_mins(5),
            read_response_limited(response, MAX_MANIFEST_BYTES),
        )
        .await
        .map_err(|_| UpdateError::HttpTimeout)??;
        // Accepting the manifest takes the anti-rollback lock, which waits on
        // any other updater run holding it, so it is kept off the runtime thread.
        let updater = self.clone();
        let current = current.clone();
        run_off_runtime(move || updater.check_manifest_bytes(&bytes, &current)).await
    }

    /// Verifies and accepts already-fetched manifest bytes before comparing versions.
    ///
    /// An up-to-date installation is **not** an error: it is reported as an
    /// `Ok` value holding [`UpdateDecision::Current`].
    ///
    /// # Errors
    ///
    /// Every non-transport error listed on [`Updater::check`] applies here,
    /// because this is the half of `check` that runs once the bytes are in
    /// hand. In particular [`UpdateError::ForgedManifest`] means the bytes are
    /// not signed by the trusted release key and must never be installed.
    pub fn check_manifest_bytes(
        &self,
        bytes: &[u8],
        current: &Version,
    ) -> Result<UpdateDecision, UpdateError> {
        ensure_durable_platform()?;
        let (manifest, manifest_sha256) = self.verify_manifest_with_digest(bytes)?;
        let rollback_state = self.accept_manifest_with_digest(&manifest, &manifest_sha256)?;
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
            .iter()
            .find(|artifact| artifact.target == self.target_triple)
            .cloned();
        let artifact = match artifact {
            Some(artifact) => artifact,
            None if current_revoked => return Err(UpdateError::CurrentReleaseRevoked),
            None => return Err(UpdateError::ArtifactUnavailable),
        };
        validate_artifact(&artifact, self.allow_loopback_http)?;
        let authorization =
            release_authorization_with_digest(&manifest, &artifact, &manifest_sha256)?;
        Ok(UpdateDecision::Available {
            version: available,
            update: AvailableUpdate {
                artifact,
                authorization,
            },
        })
    }

    /// Strictly verifies signed manifest bytes.
    ///
    /// # Errors
    ///
    /// Do not retry and do not install anything:
    /// [`UpdateError::ForgedManifest`] means `bytes` are not signed by this
    /// updater's trusted release key, and [`UpdateError::InvalidSignatureEncoding`]
    /// means the `signature` field is not standard-base64 Ed25519 data. Either
    /// one is a tampered or substituted manifest.
    ///
    /// Malformed but unsigned-tampering-free input reports
    /// [`UpdateError::ManifestTooLarge`] above the 1 MiB cap,
    /// [`UpdateError::ManifestJson`] for JSON that does not match the exact
    /// envelope shape, [`UpdateError::InvalidVersion`] for a non-`SemVer`
    /// version, [`UpdateError::InvalidReleaseMetadata`] for a zero sequence, a
    /// publication time beyond the 5 minute skew allowance, an artifact whose
    /// `release_sequence` disagrees with the manifest, or duplicate revocation
    /// entries, and [`UpdateError::ExpiredManifest`] once `expires_at_unix` has
    /// passed. Per-artifact validation adds
    /// [`UpdateError::InvalidArtifactSize`] for a zero length,
    /// [`UpdateError::InvalidArtifactHash`] for a digest that is not 64
    /// lowercase hex characters, [`UpdateError::InvalidArtifactUrl`] for an
    /// unparseable URL, and [`UpdateError::InsecureUrl`] or
    /// [`UpdateError::CredentialBearingUrl`] for a non-HTTPS or
    /// credential-bearing one.
    pub fn verify_manifest(&self, bytes: &[u8]) -> Result<ReleaseManifest, UpdateError> {
        self.verify_manifest_with_digest(bytes)
            .map(|(manifest, _)| manifest)
    }

    fn verify_manifest_with_digest(
        &self,
        bytes: &[u8],
    ) -> Result<(ReleaseManifest, String), UpdateError> {
        let length = u64::try_from(bytes.len()).map_err(|_| UpdateError::ManifestTooLarge)?;
        if length > MAX_MANIFEST_BYTES {
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
        let manifest_sha256 = encode_hex(&Sha256::digest(&canonical));
        validate_manifest_metadata(&envelope.manifest, unix_time_now()?)?;
        for artifact in &envelope.manifest.artifacts {
            if artifact.release_sequence != envelope.manifest.sequence {
                return Err(UpdateError::InvalidReleaseMetadata);
            }
            validate_artifact(artifact, self.allow_loopback_http)?;
        }
        Ok((envelope.manifest, manifest_sha256))
    }

    #[cfg(test)]
    fn accept_manifest(&self, manifest: &ReleaseManifest) -> Result<RollbackState, UpdateError> {
        let manifest_sha256 = manifest_digest(manifest)?;
        self.accept_manifest_with_digest(manifest, &manifest_sha256)
    }

    fn accept_manifest_with_digest(
        &self,
        manifest: &ReleaseManifest,
        manifest_sha256: &str,
    ) -> Result<RollbackState, UpdateError> {
        let guard = self.lock_rollback_state()?;
        accept_manifest_locked_with_digest(manifest, manifest_sha256, &guard)
    }

    fn lock_rollback_state(&self) -> Result<RollbackGuard, UpdateError> {
        let state_root = SecureDirectory::open_or_create(&self.state_dir, true)?;
        let directory =
            state_root.create_child_durable(&rollback_state_directory(&self.target_triple))?;
        let lock = directory.lock_file(OsStr::new(ROLLBACK_LOCK))?;
        Ok(RollbackGuard {
            directory,
            _lock: lock,
        })
    }

    #[cfg(test)]
    fn rollback_lock_for_test(&self) -> Result<RollbackGuard, UpdateError> {
        self.lock_rollback_state()
    }

    /// Downloads one signed artifact with safe resume and verifies exact size and SHA-256.
    ///
    /// The bytes are streamed into a private staging directory next to the
    /// install target and are only renamed to the verified name once both the
    /// exact signed length and the exact signed SHA-256 match. The live
    /// installation is never touched by this call.
    ///
    /// Staging is exclusive: this call takes the staging lock for `target` and
    /// holds it until the returned [`VerifiedArtifact`] is dropped or installed,
    /// so concurrent runs against the same destination serialize instead of
    /// interleaving writes to the shared partial and verified objects. A run
    /// that waits still resumes from whatever the previous run persisted.
    ///
    /// # Errors
    ///
    /// Transient, safe to retry later: [`UpdateError::Http`],
    /// [`UpdateError::HttpsIo`], [`UpdateError::HttpsProtocol`],
    /// [`UpdateError::HttpTask`], [`UpdateError::HttpStatus`],
    /// [`UpdateError::UnsupportedProxy`], [`UpdateError::InvalidProxyResponse`],
    /// [`UpdateError::HttpTimeout`] when the transfer exceeds its fixed 5 minute
    /// budget, and [`UpdateError::InterruptedDownload`] when the connection ends
    /// early. A retry resumes from the persisted offset instead of restarting.
    ///
    /// Do not retry, and do not install anything: [`UpdateError::HashMismatch`]
    /// means the fully received bytes do not hash to the signed digest, so the
    /// mirror served something other than the signed release. The partial
    /// artifact and its resume binding are deleted before this is returned.
    /// [`UpdateError::ArtifactTooLarge`] (more bytes than the manifest signed
    /// for) and [`UpdateError::InvalidContentRange`] (a resume response that
    /// does not match the requested range) are the same class of finding.
    ///
    /// Also possible: [`UpdateError::InvalidReleaseMetadata`] when `update` was
    /// not produced by this updater's own [`Updater::check`],
    /// [`UpdateError::InstallModeMismatch`] when the signed artifact kind does
    /// not match `target`, the artifact and URL validation errors listed on
    /// [`Updater::verify_manifest`], [`UpdateError::SwapRecoveryConflict`] when
    /// an earlier interrupted swap cannot be resolved without overwriting an
    /// unknown object, and [`UpdateError::UnsafeFilesystemObject`],
    /// [`UpdateError::CorruptState`], [`UpdateError::BlockingTask`] or
    /// [`UpdateError::Io`] for staging failures. No elevation is attempted, so a
    /// read-only or foreign-owned install directory surfaces as
    /// [`UpdateError::Io`].
    pub async fn download(
        &self,
        update: &AvailableUpdate,
        target: &InstallTarget,
    ) -> Result<VerifiedArtifact, UpdateError> {
        ensure_durable_platform()?;
        // Refused before the staging directory exists, so an install shape this
        // crate cannot publish never creates state it would have to clean up.
        ensure_supported_install(target.mode)?;
        validate_update_binding(update)?;
        let artifact = &update.artifact;
        validate_artifact(artifact, self.allow_loopback_http)?;
        ensure_kind_matches(artifact.kind, target.mode)?;
        let url = Url::parse(&artifact.url).map_err(|_| UpdateError::InvalidArtifactUrl)?;
        validate_network_url(&url, self.allow_loopback_http)?;
        let stage = Arc::new(open_staging_off_runtime(target.clone()).await?);
        // Recovery reads, hashes and renames whole objects. That is blocking
        // work, so it belongs on the blocking pool rather than on the caller's
        // runtime thread, which a current-thread runtime needs to drive its own
        // timers and every other task.
        let recovering = Arc::clone(&stage);
        run_off_runtime(move || recover_interrupted_swap(&recovering)).await?;
        let expected_binding = resume_binding(artifact, target);
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
        let expected_digest = decode_sha256(&artifact.sha256)?;
        if binding_matches {
            match stage
                .directory
                .open_regular(OsStr::new(STAGED_VERIFIED), false)
            {
                Ok(verified) => {
                    let metadata = verified.metadata().map_err(UpdateError::Io)?;
                    let digest = hash_handle(&verified).await?;
                    if metadata.len() == artifact.size && digest == expected_digest {
                        #[cfg(unix)]
                        ensure_entry_identity(
                            &stage.directory,
                            OsStr::new(STAGED_VERIFIED),
                            &verified,
                        )?;
                        let staged_path = stage.directory.path.join(STAGED_VERIFIED);
                        return Ok(VerifiedArtifact {
                            path: staged_path,
                            file: verified,
                            stage,
                            digest,
                            size: artifact.size,
                            kind: artifact.kind,
                            authorization: update.authorization.clone(),
                        });
                    }
                    drop(verified);
                    stage
                        .directory
                        .remove_file_if_exists(OsStr::new(STAGED_VERIFIED))?;
                }
                Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
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
            downloaded = tokio::time::timeout(Duration::from_mins(5), async {
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
        if digest != expected_digest {
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
        #[cfg(unix)]
        ensure_entry_identity(&stage.directory, OsStr::new(STAGED_VERIFIED), &retained)?;
        let staged_path = stage.directory.path.join(STAGED_VERIFIED);
        Ok(VerifiedArtifact {
            path: staged_path,
            file: retained,
            stage,
            digest,
            size: artifact.size,
            kind: artifact.kind,
            authorization: update.authorization.clone(),
        })
    }

    /// Re-verifies and atomically installs a previously downloaded artifact.
    ///
    /// The staged bytes are re-hashed and, on Unix, re-checked for object
    /// identity immediately before the swap, so a racing writer cannot
    /// substitute the artifact between [`Updater::download`] and this call.
    /// `target` must name the same destination the artifact was verified for;
    /// it cannot redirect the staged bytes somewhere else. The previous
    /// installation is moved aside, not deleted, until the new one is in place.
    ///
    /// # Errors
    ///
    /// Do not retry, and treat as an attack on the update channel:
    /// [`UpdateError::StagedArtifactChanged`] means the verified staging file
    /// changed size, digest, or filesystem identity after it was verified.
    /// [`UpdateError::InstallTargetMismatch`] means `target` is not the
    /// destination the staged bytes were verified for.
    /// [`UpdateError::SwapRecoveryConflict`] means the object this run moved
    /// aside is no longer the installation it measured, so something replaced
    /// the target mid-swap; the previous installation is put back.
    /// [`UpdateError::RollbackManifest`], [`UpdateError::ReleaseSequenceConflict`]
    /// or [`UpdateError::RevokedRelease`] mean the persisted anti-rollback floor
    /// moved past this artifact — most benignly because another updater run
    /// installed something newer — and this artifact must be discarded.
    /// [`UpdateError::ExpiredManifest`] or
    /// [`UpdateError::InvalidReleaseMetadata`] mean the signed authorization is
    /// no longer valid at the current clock.
    ///
    /// The installation itself is fail-safe:
    /// [`UpdateError::InstallRolledBack`] means the replacement failed and the
    /// previous version was fully restored, so the install is still usable.
    /// [`UpdateError::RollbackFailed`] is the one serious case — replacement
    /// *and* restore both failed, so the target may be missing and the previous
    /// version is in the sibling `.gta-claw.rollback` object; it carries both
    /// underlying [`io::Error`] values.
    ///
    /// Also possible: [`UpdateError::InstallModeMismatch`],
    /// [`UpdateError::BundleInstallUnsupported`] for a directory bundle, which
    /// this crate refuses before staging anything,
    /// [`UpdateError::SwapRecoveryConflict`],
    /// [`UpdateError::CorruptState`], [`UpdateError::UnsafeFilesystemObject`],
    /// [`UpdateError::BlockingTask`] and [`UpdateError::Io`]. A sharing lock is
    /// not an error: it is reported as an `Ok` value holding
    /// [`InstallOutcome::RestartRequired`], which names no staging path and
    /// discards the verified staging, so the rerun downloads and verifies the
    /// release again rather than installing bytes left behind on disk.
    pub async fn install(
        &self,
        verified: VerifiedArtifact,
        target: &InstallTarget,
    ) -> Result<InstallOutcome, UpdateError> {
        ensure_durable_platform()?;
        // Before the staging lock and before anything is measured: a bundle can
        // never be published by this crate, so refusing here keeps the failure
        // away from any state at all.
        ensure_supported_install(target.mode)?;
        verified.stage.ensure_verified_destination(target)?;
        ensure_kind_matches(verified.kind, target.mode)?;
        let metadata = verified.file.metadata().map_err(UpdateError::Io)?;
        if metadata.len() != verified.size || hash_handle(&verified.file).await? != verified.digest
        {
            return Err(UpdateError::StagedArtifactChanged);
        }
        #[cfg(unix)]
        ensure_entry_identity(
            &verified.stage.directory,
            OsStr::new(STAGED_VERIFIED),
            &verified.file,
        )?;
        let prepared = PreparedArtifact {
            path: verified.path.clone(),
            source_name: OsString::from(STAGED_VERIFIED),
            handle: verified.file.try_clone().map_err(UpdateError::Io)?,
            stage: Arc::clone(&verified.stage),
            signed: SignedContent {
                digest: verified.digest,
                size: verified.size,
            },
        };
        // The rollback lock and the swap are blocking filesystem work that waits
        // on other updater runs, so they must not occupy the caller's runtime
        // thread: a current-thread runtime would otherwise stop driving every
        // other task, including its own timers, until the lock came free.
        let updater = self.clone();
        let authorization = verified.authorization.clone();
        run_off_runtime(move || {
            let guard = updater.lock_rollback_state()?;
            authorize_install(&authorization, &guard)?;
            atomic_swap_verified(&prepared, cfg!(windows))
        })
        .await
    }

    /// Runs the full signed update flow.
    ///
    /// An up-to-date installation is **not** an error: it is reported as an
    /// `Ok` value holding [`UpdateOutcome::Current`]. On Linux, where
    /// distribution packages own updates, no network or filesystem work happens
    /// at all and the result is an `Ok` value holding
    /// [`UpdateOutcome::SystemManaged`].
    ///
    /// # Errors
    ///
    /// Returns any error documented on [`Updater::check`],
    /// [`Updater::download`] and [`Updater::install`], in that order; the flow
    /// stops at the first failure. Until [`Updater::install`] reaches its final
    /// rename the existing installation is untouched, so every error before
    /// that point leaves a working install behind.
    pub async fn execute(
        &self,
        manifest_url: &Url,
        current: &Version,
        target: &InstallTarget,
    ) -> Result<UpdateOutcome, UpdateError> {
        if target.mode == InstallMode::LinuxPackage {
            return Ok(UpdateOutcome::SystemManaged);
        }
        ensure_durable_platform()?;
        match self.check(manifest_url, current).await? {
            UpdateDecision::Current { version } => Ok(UpdateOutcome::Current(version)),
            UpdateDecision::Available { version, update } => {
                let verified = self.download(&update, target).await?;
                match self.install(verified, target).await? {
                    InstallOutcome::Installed => Ok(UpdateOutcome::Installed(version)),
                    InstallOutcome::RestartRequired => {
                        Ok(UpdateOutcome::RestartRequired { version })
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
        let response = request.send().await.map_err(redact_http_error)?;
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
            Duration::from_mins(5),
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

#[cfg(test)]
fn accept_manifest_locked(
    manifest: &ReleaseManifest,
    guard: &RollbackGuard,
) -> Result<RollbackState, UpdateError> {
    let manifest_sha256 = manifest_digest(manifest)?;
    accept_manifest_locked_with_digest(manifest, &manifest_sha256, guard)
}

fn accept_manifest_locked_with_digest(
    manifest: &ReleaseManifest,
    manifest_sha256: &str,
    guard: &RollbackGuard,
) -> Result<RollbackState, UpdateError> {
    let state_directory = &guard.directory;
    let mut state = load_rollback_state(state_directory)?;
    let available = Version::parse(&manifest.version).map_err(|_| UpdateError::InvalidVersion)?;

    if manifest.sequence < state.highest_sequence {
        return Err(UpdateError::RollbackManifest {
            observed: state.highest_sequence,
            received: manifest.sequence,
        });
    }
    if manifest.sequence == state.highest_sequence
        && state.highest_sequence != 0
        && (state.highest_version != manifest.version || state.manifest_sha256 != manifest_sha256)
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
        manifest_sha256.clone_into(&mut state.manifest_sha256);
    }
    state
        .revoked_versions
        .extend(manifest.revoked_versions.iter().cloned());
    let state_name = rollback_state_name(state.highest_sequence);
    if state != previous {
        state_directory.write_json_atomic(&state_name, &state)?;
    }
    prune_rollback_states(state_directory, &state_name)?;
    Ok(state)
}

fn prune_rollback_states(
    state_directory: &SecureDirectory,
    retained: &OsStr,
) -> Result<(), UpdateError> {
    for name in state_directory.list_names()? {
        if name != retained && rollback_sequence_from_name(&name).is_some() {
            state_directory.remove_file_if_exists(&name)?;
        }
    }
    state_directory.sync().map_err(UpdateError::Io)
}

fn authorize_install(
    authorization: &ReleaseAuthorization,
    guard: &RollbackGuard,
) -> Result<(), UpdateError> {
    validate_authorization_time(authorization, unix_time_now()?)?;
    let state = load_rollback_state(&guard.directory)?;
    if state.highest_sequence > authorization.sequence {
        return Err(UpdateError::RollbackManifest {
            observed: state.highest_sequence,
            received: authorization.sequence,
        });
    }
    if state.highest_sequence < authorization.sequence {
        return Err(UpdateError::CorruptState);
    }
    #[expect(
        clippy::suspicious_operation_groupings,
        reason = "the persisted floor and the signed authorization name the same two values \
                  with different field names: RollbackState::highest_version is deliberately \
                  compared against ReleaseAuthorization::version, and the type has no \
                  `highest_version` field for clippy's suggested symmetry to refer to"
    )]
    if state.highest_version != authorization.version
        || state.manifest_sha256 != authorization.manifest_sha256
    {
        return Err(UpdateError::ReleaseSequenceConflict);
    }
    if state.revoked_versions.contains(&authorization.version) {
        return Err(UpdateError::RevokedRelease);
    }
    Ok(())
}

fn validate_update_binding(update: &AvailableUpdate) -> Result<(), UpdateError> {
    if artifact_digest(&update.artifact)? != update.authorization.artifact_sha256
        || update.artifact.release_sequence != update.authorization.sequence
    {
        return Err(UpdateError::InvalidReleaseMetadata);
    }
    Ok(())
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
    authorization: ReleaseAuthorization,
}

#[derive(Debug)]
struct PreparedArtifact {
    path: PathBuf,
    source_name: OsString,
    handle: File,
    stage: Arc<SecureStaging>,
    /// What the signed release says this artifact must contain.
    ///
    /// Carried all the way to publication so the bytes can be re-checked
    /// against the *signature*, not merely against themselves. Identity alone
    /// is not enough: an attacker who can write through an existing descriptor
    /// mutates the object in place, leaving the inode — and therefore every
    /// identity check — unchanged while the content becomes something else.
    signed: SignedContent,
}

/// The exact content a signed release authorises.
#[derive(Clone, Debug, Eq, PartialEq)]
/// What the signed release says this artifact must contain.
///
/// Only single-file artifacts are installable, so this is always the signed
/// bytes at the signed length. Both are checked: length alone is trivially
/// forged, and a digest without a length lets a truncated read pass when the
/// object is replaced mid-verification.
struct SignedContent {
    digest: [u8; 32],
    size: u64,
}

impl SignedContent {
    /// Confirms the object behind `handle` still holds exactly this content.
    ///
    /// Read through the retained descriptor rather than by reopening a name, so
    /// what is measured is the object this run owns.
    #[cfg(not(windows))]
    fn verify(&self, handle: &File) -> Result<(), UpdateError> {
        let length = handle.metadata().map_err(UpdateError::Io)?.len();
        if length != self.size || handle_content_digest(handle)? != self.digest {
            return Err(UpdateError::StagedArtifactChanged);
        }
        Ok(())
    }
}

/// Digests the bytes an open handle refers to, without reopening its name.
#[cfg(not(windows))]
fn handle_content_digest(handle: &File) -> Result<[u8; 32], UpdateError> {
    let mut handle = handle.try_clone().map_err(UpdateError::Io)?;
    handle.seek(SeekFrom::Start(0)).map_err(UpdateError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = stream_buffer();
    loop {
        let count = handle.read(&mut buffer).map_err(UpdateError::Io)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

impl VerifiedArtifact {
    /// Returns the locally derived staging path, for diagnostics only.
    ///
    /// This is a name, not a handle, and names are not identities: by the time
    /// anything acts on it the path may resolve to a different object. Nothing
    /// may be installed, verified or trusted on the strength of it — the
    /// installation reads through the descriptor this artifact retains. It is
    /// exposed for logs and error messages.
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
    /// A sharing lock prevented the swap, so nothing was installed.
    ///
    /// # The restart contract
    ///
    /// This outcome deliberately carries **no staging path**, and the verified
    /// staging it would have named is discarded before it is returned.
    ///
    /// Naming a staged file to a caller invites exactly the attack the
    /// signature checks exist to stop: the caller reports "restart to finish
    /// installing from this path", and anything that can write that pathname
    /// between the two runs chooses what gets installed. Re-verifying on the
    /// second run does not help either, because a pathname is not an identity —
    /// the object checked and the object installed need not be the same one.
    ///
    /// So a restart is not a resumption. The next run fetches the release
    /// again, checks its signature, its size and its digest, and installs only
    /// what it verified itself.
    RestartRequired,
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
    /// Release version was not valid `SemVer`.
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
    /// A verified artifact was offered for a destination it was not verified for.
    InstallTargetMismatch,
    /// A blocking updater step could not be run to completion.
    BlockingTask(tokio::task::JoinError),
    /// This filesystem cannot claim a name without risking replacing it.
    NoReplaceRenameUnsupported(io::Error),
    /// This platform cannot provide the durability the updater depends on.
    ///
    /// Nothing was written, moved or pruned. Signature verification still
    /// works; use a mechanism that has the guarantee — a platform installer or
    /// a restart helper — to deliver the update itself.
    PlatformDurabilityUnsupported,
    /// Staged bytes changed after verification.
    StagedArtifactChanged,
    /// An interrupted swap cannot be recovered without overwriting an unknown object.
    SwapRecoveryConflict,
    /// Installing an expanded directory bundle is not supported.
    ///
    /// Publishing a tree needs guarantees this crate does not yet have: the
    /// signed bytes must be hashed once and extracted from that same immutable
    /// buffer, every nested directory must be made durable, and the tree digest
    /// must distinguish shapes that a flat walk cannot. Nothing was written,
    /// moved or pruned. Manifests describing bundles still verify.
    BundleInstallUnsupported,
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
            Self::InstallTargetMismatch => {
                formatter.write_str("verified artifact belongs to a different install target")
            }
            Self::BlockingTask(_) => formatter.write_str("update filesystem step did not complete"),
            Self::NoReplaceRenameUnsupported(_) => formatter
                .write_str("this filesystem cannot install without risking an existing file"),
            Self::PlatformDurabilityUnsupported => formatter
                .write_str("this platform cannot store updater state safely; nothing was changed"),
            Self::StagedArtifactChanged => {
                formatter.write_str("verified staged artifact changed before installation")
            }
            Self::SwapRecoveryConflict => {
                formatter.write_str("interrupted update conflicts with an unknown local object")
            }
            Self::BundleInstallUnsupported => {
                formatter.write_str("this updater cannot install directory bundles safely")
            }
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
            Self::HttpsProtocol(error) => Some(error),
            Self::HttpTask(error) | Self::BlockingTask(error) => Some(error),
            Self::HttpsIo(error)
            | Self::Io(error)
            | Self::NoReplaceRenameUnsupported(error)
            | Self::InstallRolledBack(error)
            | Self::RollbackFailed { install: error, .. } => Some(error),
            _ => None,
        }
    }
}

struct RollbackGuard {
    directory: SecureDirectory,
    _lock: File,
}

#[derive(Clone, Debug)]
struct SecureDirectory {
    path: PathBuf,
    handle: Arc<File>,
}

impl SecureDirectory {
    fn open_or_create(path: &Path, owner_only: bool) -> Result<Self, UpdateError> {
        reject_reparse_components(path)?;
        ensure_directory_tree_durable(path)?;
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

    /// Creates an owner-only child, and confirms its directory entry is durable.
    ///
    /// Confirmation is recorded by a marker inside the child, for the same
    /// reason [`ensure_directory_tree_durable`] does it: an unconfirmed
    /// directory is indistinguishable from a confirmed one after a crash, so
    /// "sync only when this call created it" would let a run build on an entry
    /// that never reached the disk. With the marker, a run that finds no marker
    /// syncs again, and no caller sees the child until the marker is durable.
    fn create_child_durable(&self, name: &OsStr) -> Result<Self, UpdateError> {
        let child = self.create_child(name, true)?;
        if directory_tree_is_confirmed(&child.path)? {
            return Ok(child);
        }
        sync_directory_handle(&self.handle)?;
        record_directory_tree_confirmed(&child.path)?;
        Ok(child)
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
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_DELETE: u32 = 0x0000_0004;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
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


    fn lock_file(&self, name: &OsStr) -> Result<File, UpdateError> {
        validate_single_component(name)?;
        #[cfg(unix)]
        {
            let descriptor = rustix::fs::openat(
                &*self.handle,
                name,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .map_err(rustix_open_error)?;
            let file = File::from(descriptor);
            rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)
                .map_err(rustix_error)
                .map_err(UpdateError::Io)?;
            Ok(file)
        }
        #[cfg(windows)]
        {
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            let path = self.path.join(name);
            let started = std::time::Instant::now();
            loop {
                let result = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .share_mode(0)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&path);
                match result {
                    Ok(file) => {
                        let metadata = file.metadata().map_err(UpdateError::Io)?;
                        if !metadata.is_file() || is_windows_reparse(&metadata) {
                            return Err(UpdateError::UnsafeFilesystemObject);
                        }
                        return Ok(file);
                    }
                    Err(error)
                        if is_windows_sharing_violation(&error)
                            && started.elapsed() < Duration::from_mins(5) =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(UpdateError::Io(error)),
                }
            }
        }
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
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_DELETE: u32 = 0x0000_0004;
            OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
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

    /// Renames, replacing the destination if it exists.
    ///
    /// Only for names inside this run's own owner-only staging directory, held
    /// under the staging lock, where the object being replaced is this run's
    /// own scratch state. Anything that claims a name another installation
    /// could occupy must use [`SecureDirectory::rename_to_new`] instead.
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

    /// Renames onto a destination name that must not already exist.
    ///
    /// Plain POSIX `rename` replaces the destination atomically, which is the
    /// wrong operation every time this updater claims a slot it believes is
    /// empty. An independent reinstall that appeared between the check and the
    /// rename would be silently overwritten, and the swap journal would then
    /// describe an installation nobody can recover. `renameat2`/`renameatx_np`
    /// refuse instead, so the race surfaces as
    /// [`UpdateError::SwapRecoveryConflict`] and the other installation is left
    /// exactly as it is.
    ///
    /// A platform or filesystem with no no-replace rename is reported as
    /// unsupported rather than served by a check-then-replace fallback, which
    /// would reintroduce the race this exists to remove.
    fn rename_to_new(
        &self,
        source_name: &OsStr,
        destination: &Self,
        destination_name: &OsStr,
    ) -> Result<(), UpdateError> {
        validate_single_component(source_name)?;
        validate_single_component(destination_name)?;
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        ))]
        {
            match rustix::fs::renameat_with(
                &*self.handle,
                source_name,
                &*destination.handle,
                destination_name,
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => Ok(()),
                Err(rustix::io::Errno::EXIST | rustix::io::Errno::NOTEMPTY) => {
                    Err(UpdateError::SwapRecoveryConflict)
                }
                Err(
                    error @ (rustix::io::Errno::NOSYS
                    | rustix::io::Errno::INVAL
                    | rustix::io::Errno::OPNOTSUPP),
                ) => Err(UpdateError::NoReplaceRenameUnsupported(rustix_error(error))),
                Err(error) => Err(UpdateError::Io(rustix_error(error))),
            }
        }
        // Everything else, Windows included, has no atomic no-replace rename
        // reachable from here: `fs::rename` maps to `MoveFileEx` *with*
        // `REPLACE_EXISTING`, and the flag-free call needs `unsafe`. Reporting
        // that is the whole point — a check-then-replace stand-in would
        // reintroduce the race this exists to remove.
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        )))]
        {
            let _ = destination;
            Err(UpdateError::NoReplaceRenameUnsupported(io::Error::from(
                io::ErrorKind::Unsupported,
            )))
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
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;

            let mut directory = rustix::fs::Dir::read_from(&*self.handle)
                .map_err(rustix_error)
                .map_err(UpdateError::Io)?;
            let mut entries = Vec::new();
            for entry in &mut directory {
                let entry = entry.map_err(rustix_error).map_err(UpdateError::Io)?;
                let bytes = entry.file_name().to_bytes();
                if bytes != b"." && bytes != b".." {
                    entries.push(OsStr::from_bytes(bytes).to_owned());
                }
            }
            Ok(entries)
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

#[derive(Debug)]
struct SecureStaging {
    directory: SecureDirectory,
    parent: SecureDirectory,
    target_name: OsString,
    backup_name: OsString,
    mode: InstallMode,
    _lock: File,
}

impl SecureStaging {
    /// Opens the staging directory beside `target` and takes its exclusive lock.
    ///
    /// The lock is held for as long as the returned value lives, which spans
    /// the whole download and install of one run. Concurrent runs against the
    /// same target therefore serialize instead of interleaving writes to the
    /// shared partial, verified, resume and journal objects.
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
        // The swap journal lives *inside* this directory, so the directory's own
        // entry has to reach the disk before anything is written into it.
        // Otherwise a crash can lose the entry and take the journal with it,
        // and the "journal before the target moves" ordering that all recovery
        // depends on would be describing a directory that no longer exists.
        parent.sync().map_err(UpdateError::Io)?;
        let lock = directory.lock_file(OsStr::new(STAGE_LOCK))?;
        Ok(Self {
            directory,
            parent,
            target_name: OsString::from(target_name),
            backup_name: OsString::from(format!(".{target_name}.gta-claw.rollback")),
            mode: target.mode,
            _lock: lock,
        })
    }

    /// Rejects a destination that is not the one the staged bytes were verified for.
    ///
    /// The staging directory, the object the swap replaces and the rollback
    /// object were all derived from the destination passed to
    /// [`Updater::download`]. A later caller may name the same destination
    /// again, but it may not name a different one.
    fn ensure_verified_destination(&self, target: &InstallTarget) -> Result<(), UpdateError> {
        if target.mode != self.mode {
            return Err(UpdateError::InstallTargetMismatch);
        }
        let target_name = target
            .path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(UpdateError::InvalidInstallTarget)?;
        if target_name != self.target_name {
            return Err(UpdateError::InstallTargetMismatch);
        }
        let parent_path = target
            .path
            .parent()
            .ok_or(UpdateError::InvalidInstallTarget)?;
        let parent = SecureDirectory::open_existing(parent_path, false)?;
        self.ensure_same_parent(&parent)
    }

    /// Confirms `candidate` is the directory this run's staging area lives in.
    ///
    /// Unix compares the identity of the two open directory objects, which no
    /// path substitution can forge.
    #[cfg(unix)]
    fn ensure_same_parent(&self, candidate: &SecureDirectory) -> Result<(), UpdateError> {
        if file_identity(&candidate.handle)? == file_identity(&self.parent.handle)? {
            Ok(())
        } else {
            Err(UpdateError::InstallTargetMismatch)
        }
    }

    /// Confirms `candidate` is the directory this run's staging area lives in.
    ///
    /// # Platform limitation, stated plainly
    ///
    /// On Windows this is **not** an object-identity check and must not be
    /// relied on as one. By-handle identity needs
    /// `MetadataExt::file_index`/`volume_serial_number`, which are unstable
    /// (`windows_by_handle`, rust-lang/rust#63010); the raw
    /// `GetFileInformationByHandle` call needs `unsafe`, which this workspace
    /// sets to `forbid` — a level a crate cannot override — and `--locked`
    /// builds rule out adding a wrapper crate. Handle-relative directory
    /// operations (`NtCreateFile` with a root directory handle) are unreachable
    /// for the same reason, so the Windows arm of [`SecureDirectory`] resolves
    /// names under a retained path. An earlier attempt to synthesise identity
    /// from a held anchor file was removed because it was forgeable.
    ///
    /// What this therefore is: a check that rejects a *different* destination,
    /// which is what a caller mistake looks like. It does not detect a parent
    /// replaced under the same pathname.
    ///
    /// # Why the swap is still safe
    ///
    /// Nothing in the swap reads this argument. Every object the swap touches —
    /// the staging directory, the target name, the rollback name — comes from
    /// the [`SecureStaging`] built during [`Updater::download`] and held open
    /// since, so a caller cannot redirect the installation whatever this check
    /// answers. That is the property under test in
    /// `the_swap_uses_only_the_staging_state_never_the_callers_path`, and it is
    /// what carries the guarantee on Windows.
    #[cfg(windows)]
    fn ensure_same_parent(&self, candidate: &SecureDirectory) -> Result<(), UpdateError> {
        if candidate.path == self.parent.path {
            Ok(())
        } else {
            Err(UpdateError::InstallTargetMismatch)
        }
    }
}

fn resume_binding(artifact: &ReleaseArtifact, target: &InstallTarget) -> ResumeBinding {
    ResumeBinding {
        target: target.path.to_string_lossy().into_owned(),
        url: artifact.url.clone(),
        size: artifact.size,
        sha256: artifact.sha256.clone(),
        kind: artifact.kind,
        release_sequence: artifact.release_sequence,
    }
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<(u64, u64), UpdateError> {
    let metadata = file.metadata().map_err(UpdateError::Io)?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Confirms a directory entry still names the object behind `retained`.
///
/// There is no by-handle object identity on Windows reachable from stable Rust
/// without `unsafe`, so this cannot be answered there. It refuses rather than
/// approximating with a path comparison: every caller uses the answer to decide
/// whether it may delete or replace something, and a wrong "yes" destroys an
/// installation. The public API already refuses on that platform before any of
/// these callers can run — see [`ensure_durable_platform`] — so this is a
/// second, structural guard rather than the first line of defence.
#[cfg(not(unix))]
const fn ensure_entry_identity(
    _directory: &SecureDirectory,
    _name: &OsStr,
    _retained: &File,
) -> Result<(), UpdateError> {
    Err(UpdateError::PlatformDurabilityUnsupported)
}

#[cfg(unix)]
fn ensure_entry_identity(
    directory: &SecureDirectory,
    name: &OsStr,
    retained: &File,
) -> Result<(), UpdateError> {
    let entry = directory.open_object(name)?;
    if file_identity(&entry)? == file_identity(retained)? {
        Ok(())
    } else {
        Err(UpdateError::StagedArtifactChanged)
    }
}

fn object_digest(directory: &SecureDirectory, name: &OsStr) -> Result<String, UpdateError> {
    let object = directory.open_object(name)?;
    object_digest_of(object, &directory.path.join(name))
}

/// Digests the object an already-open handle refers to.
///
/// Callers that must be sure they measured the same object they are about to
/// act on hold the handle across both steps and use this.
fn object_digest_of(object: File, path: &Path) -> Result<String, UpdateError> {
    let mut digest = Sha256::new();
    update_object_digest(object, path, None, &mut digest)?;
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
        let mut buffer = stream_buffer();
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
    // The child count is what makes the encoding unambiguous. Without it a
    // directory's children run straight into whatever follows, so
    // `{a: {b: file}}` and `{a: {}, b: file}` produce byte-for-byte identical
    // input: the same digest for two different trees. Length-prefixed names
    // alone do not separate them, because the ambiguity is in the *nesting*,
    // not in where a name ends.
    digest.update(
        u64::try_from(entries.len())
            .map_err(|_| UpdateError::StagedArtifactChanged)?
            .to_be_bytes(),
    );
    for entry in entries {
        let object = child.open_object(OsStr::new(&entry))?;
        update_object_digest(object, &child.path.join(&entry), Some(&entry), digest)?;
    }
    Ok(())
}

/// Resolves an interrupted swap using the journal that was made durable before
/// anything moved.
///
/// The journal names the phase the interrupted run reached and the identity of
/// the installation that occupied the target when it started, so recovery can
/// tell "crashed before the target was moved aside" from "crashed while the
/// target slot was owned by that run". It never deletes a target object: it
/// restores the recorded original, discards a superseded backup, drops a
/// journal with nothing left to do, or reports
/// [`UpdateError::SwapRecoveryConflict`] when the evidence does not identify
/// what is on disk.
fn recover_interrupted_swap(stage: &SecureStaging) -> Result<(), UpdateError> {
    let journal = match stage
        .directory
        .read_json::<SwapJournal>(OsStr::new(SWAP_JOURNAL))
    {
        Ok(journal) => journal,
        Err(UpdateError::CorruptState) => return Err(UpdateError::SwapRecoveryConflict),
        Err(error) => return Err(error),
    };
    // Resolved against what the journal recorded, never by sweeping names, so a
    // restart can tell its own leftovers from anything else.
    resolve_quarantine(stage, journal.as_ref().and_then(|j| j.quarantine.as_ref()))?;
    let target_exists = stage.parent.object_exists(&stage.target_name)?;
    let backup_exists = stage.parent.object_exists(&stage.backup_name)?;

    let Some(journal) = journal else {
        return match (target_exists, backup_exists) {
            (_, false) => Ok(()),
            // A rollback object with no journal describing it was not put there
            // by this updater: the journal is made durable *before* the target
            // is moved aside, so every rollback object this crate creates has a
            // record naming it and its identity. Measuring one now and adopting
            // it would install an object of unknown provenance under the
            // application's own name — the same mistake as sweeping an
            // unjournalled quarantine, and unrecoverable once it is live.
            (_, true) => Err(UpdateError::SwapRecoveryConflict),
        };
    };
    let has_original = journal.original_digest.is_some();

    match (journal.phase, target_exists, backup_exists, has_original) {
        // Nothing is pending. Either the swap had not started, so whatever
        // occupies the target is the untouched installation this run found, or
        // the run had nothing to move aside and never filled the target slot.
        // The journal is all that is left to clean up.
        (SwapPhase::Prepared, true, false, _)
        | (SwapPhase::Prepared | SwapPhase::Swapped, false, false, false) => {
            clear_journal_after_durable_parent(stage)
        }
        // The target was moved aside, so the recorded original is the rollback
        // object. The phase may still read `Prepared` when the crash landed
        // between the rename and the phase update.
        (SwapPhase::Prepared | SwapPhase::Swapped, false, true, true) => {
            restore_original(stage, &journal)
        }
        (SwapPhase::Swapped, true, has_backup, has_original) => {
            // A run that found nothing at the target never created a rollback
            // object, so one existing here belongs to something else and must
            // not be retired, whatever the target holds.
            if has_backup && !has_original {
                return Err(UpdateError::SwapRecoveryConflict);
            }
            let installed = object_digest(&stage.parent, &stage.target_name)?;
            if installed == journal.recovery_digest {
                if has_backup {
                    let Some(expected) = journal.original_digest.as_deref() else {
                        return Err(UpdateError::SwapRecoveryConflict);
                    };
                    discard_backup(stage, &journal, expected)?;
                }
                return clear_journal_after_durable_parent(stage);
            }
            // The target still holds the installation this run measured before
            // it started, so the move aside never reached the disk even though
            // the phase did. Nothing was replaced and nothing is pending.
            if !has_backup && journal.original_digest.as_deref() == Some(installed.as_str()) {
                return clear_journal_after_durable_parent(stage);
            }
            // The target slot belonged to the interrupted run, but it holds
            // neither that run's replacement nor the installation it measured.
            // Nothing here identifies the object, so it must not be deleted.
            Err(UpdateError::SwapRecoveryConflict)
        }
        // Every remaining shape contradicts the journal: a rollback object the
        // run never created, an original that is gone with nothing to restore
        // it from, or a target that reappeared before the swap started.
        _ => Err(UpdateError::SwapRecoveryConflict),
    }
}

/// Moves the rollback object back into the target slot, which must be empty.
///
/// The identity checked is the journal's own `original_digest`: what the
/// interrupted run recorded before it moved the installation aside. Taking it
/// from the journal rather than an argument means a caller cannot ask for a
/// restore verified against some other identity, and a record without one is
/// refused rather than restored — an object this crate never measured must not
/// be published under the application's own name.
fn restore_original(stage: &SecureStaging, journal: &SwapJournal) -> Result<(), UpdateError> {
    // Opened once and held across the whole restore. Digesting the object under
    // its name, dropping the handle and then renaming that name would let a
    // different object be restored than the one that was verified; keeping the
    // descriptor lets the arrival be compared against the very object measured.
    let kept = stage.parent.open_object(&stage.backup_name)?;
    // A rollback object this run cannot verify is never put back. The journal is
    // written before the target moves, so a record without an identity does not
    // describe anything this crate moved aside, and restoring on that evidence
    // would install an unmeasured object under the application's own name.
    let Some(expected) = journal.original_digest.as_deref() else {
        return Err(UpdateError::SwapRecoveryConflict);
    };
    let measured = kept.try_clone().map_err(UpdateError::Io)?;
    let path = stage.parent.path.join(&stage.backup_name);
    if object_digest_of(measured, &path)? != expected {
        return Err(UpdateError::SwapRecoveryConflict);
    }

    // The target slot must still be empty. A reinstall that appeared while this
    // recovery was deciding is an independent installation, and restoring over
    // it would destroy it, so the conflict is reported instead.
    stage.parent.rename_to_new(
        &stage.backup_name,
        &stage.parent,
        &stage.target_name,
    )?;

    // What now occupies the target must be the object that was just verified,
    // not something that raced into the name.
    let restored = ensure_entry_identity(&stage.parent, &stage.target_name, &kept);
    drop(kept);
    restored?;

    stage.parent.sync().map_err(UpdateError::Io)?;
    exit_at_armed_fault(InjectedFault::ExitAfterRecoveryRestore);
    retire_journal(stage)
}

/// Retires the swap journal once, and only once, the install directory is durable.
///
/// The journal is the only record of how to finish or undo an interrupted swap,
/// so it may not be removed while the restored or completed installation could
/// still be lost: the parent is synced first.
fn clear_journal_after_durable_parent(stage: &SecureStaging) -> Result<(), UpdateError> {
    stage.parent.sync().map_err(UpdateError::Io)?;
    retire_journal(stage)
}

/// Removes the journal and makes that removal itself durable.
///
/// Without the staging sync a crash would resurrect a journal that no longer
/// describes anything on disk, and the next run would try to recover a swap
/// that has already been settled.
fn retire_journal(stage: &SecureStaging) -> Result<(), UpdateError> {
    stage
        .directory
        .remove_file_if_exists(OsStr::new(SWAP_JOURNAL))?;
    stage.directory.sync().map_err(UpdateError::Io)
}

/// The directories [`ensure_directory_tree_durable`] confirms, shallowest first.
///
/// Only `Normal` components name a directory this updater can create or sync;
/// a root or prefix component is part of the path but not a level of its own.
fn state_tree_levels(path: &Path) -> Vec<PathBuf> {
    let mut levels = Vec::new();
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Normal(_)) {
            levels.push(current.clone());
        }
    }
    levels
}

/// How many directory syncs confirming `path` performs before the marker's own.
///
/// Tests aim an injected sync failure at one specific occurrence, and counting
/// path components by hand gets it wrong — `Path::components` yields a root or
/// prefix component that is never synced. Deriving the number from the same
/// function the implementation uses keeps the two from drifting apart.
#[doc(hidden)]
#[must_use]
pub fn state_tree_sync_points(path: &Path) -> u32 {
    u32::try_from(state_tree_levels(path).len()).unwrap_or(u32::MAX)
}

/// Creates `path` and every missing ancestor, and confirms the whole tree is
/// durable before it is reported as usable.
///
/// The confirmation cannot be limited to the levels *this* call created. After
/// a crash a directory whose entry never reached the disk is indistinguishable
/// from one whose entry did, so a run that found a level present and skipped
/// its sync would build on an entry that may not exist after the next power
/// loss. Confirming every level on every run would fix that but would fsync
/// directories the updater does not own, up to and including the filesystem
/// root.
///
/// So the fact of confirmation is recorded instead: a marker file written and
/// synced inside the deepest directory *after* every level's parent has been
/// synced. Its presence is durable evidence that some run confirmed the whole
/// chain, so later runs need only stat it. Its absence — including after a run
/// whose sync failed — forces the full confirmation again. A level is never
/// removed on failure, because a removal is exactly the step a crash can also
/// lose.
///
/// Returns the directories this call created, shallowest first.
fn ensure_directory_tree_durable(path: &Path) -> Result<Vec<PathBuf>, UpdateError> {
    let levels = state_tree_levels(path);
    let Some(deepest) = levels.last().cloned() else {
        return Err(UpdateError::InvalidInstallTarget);
    };

    let mut created = Vec::new();
    let mut confirmed = directory_tree_is_confirmed(&deepest)?;
    for level in &levels {
        // Existence is checked before creating: `create_dir` on an ancestor the
        // updater does not own can report a permission failure instead of the
        // "already there" it really means.
        match fs::symlink_metadata(level) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(UpdateError::UnsafeFilesystemObject),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(level) {
                    Ok(()) => {
                        // A level that had to be created cannot have been part
                        // of whatever an earlier run confirmed.
                        confirmed = false;
                        created.push(level.clone());
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(UpdateError::Io(error)),
                }
            }
            Err(error) => return Err(UpdateError::Io(error)),
        }
    }
    if confirmed {
        return Ok(created);
    }

    for level in &levels {
        let parent = level
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_directory_path(parent)?;
    }
    record_directory_tree_confirmed(&deepest)?;
    Ok(created)
}

/// Reports whether some earlier run recorded this tree as fully confirmed.
///
/// Where directory entries cannot be flushed there is nothing a marker could
/// honestly record, so confirmation is never claimed and the syncs — themselves
/// no-ops there — are simply repeated. See [`sync_directory_path`].
#[cfg(windows)]
fn directory_tree_is_confirmed(_deepest: &Path) -> Result<bool, UpdateError> {
    Ok(false)
}

/// Records, durably, that every level of this tree has been synced.
#[cfg(windows)]
fn record_directory_tree_confirmed(_deepest: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(not(windows))]
fn directory_tree_is_confirmed(deepest: &Path) -> Result<bool, UpdateError> {
    let marker = deepest.join(DURABLE_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(metadata) if !metadata.is_file() => Err(UpdateError::UnsafeFilesystemObject),
        Ok(metadata) => {
            if metadata.len() != DURABLE_MARKER_CONTENTS.len() as u64 {
                return Ok(false);
            }
            match fs::read(&marker) {
                Ok(contents) => Ok(contents == DURABLE_MARKER_CONTENTS),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(UpdateError::Io(error)),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(UpdateError::Io(error)),
    }
}

/// Records, durably, that every level of this tree has been synced.
///
/// The marker is published in two steps so that no intermediate state can be
/// mistaken for confirmation. It is created **empty**, which
/// [`directory_tree_is_confirmed`] reads as "not confirmed", and its directory
/// entry is made durable while it is still empty. Only then are the contents
/// written and synced. A crash or failure at any point therefore leaves either
/// no marker or an empty one, and both mean unconfirmed — there is no window in
/// which a marker that says "confirmed" exists without its own entry being
/// durable.
///
/// This ordering is why a failed publication needs no retraction: the durable
/// state it leaves behind is already the unconfirmed one. A retraction that
/// itself failed could not be trusted, which is exactly the trap the previous
/// write-then-retract shape fell into.
#[cfg(not(windows))]
fn record_directory_tree_confirmed(deepest: &Path) -> Result<(), UpdateError> {
    let directory = SecureDirectory::open_existing(deepest, false)?;
    let mut marker = match directory.open_regular(OsStr::new(DURABLE_MARKER), true) {
        Ok(marker) => marker,
        Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
            // A leftover empty marker from an interrupted publication is
            // reopened and finished, never assumed complete.
            directory.open_regular(OsStr::new(DURABLE_MARKER), false)?
        }
        Err(error) => return Err(error),
    };
    // The empty marker's own entry becomes durable first. Until this succeeds
    // the tree reads as unconfirmed no matter what happens next.
    marker.sync_all().map_err(UpdateError::Io)?;
    sync_directory_handle(&directory.handle)?;
    exit_at_armed_fault(InjectedFault::ExitAfterEmptyDurabilityMarker);

    marker.set_len(0).map_err(UpdateError::Io)?;
    marker
        .write_all(DURABLE_MARKER_CONTENTS)
        .map_err(UpdateError::Io)?;
    marker.sync_all().map_err(UpdateError::Io)
}

#[cfg(unix)]
fn sync_directory_path(path: &Path) -> Result<(), UpdateError> {
    if let Some(error) = armed_fault_error(InjectedFault::FailNewStateDirectorySync) {
        return Err(UpdateError::Io(error));
    }
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(rustix_open_error)?;
    File::from(descriptor).sync_all().map_err(UpdateError::Io)
}

/// Windows cannot flush a directory entry, so this confirms nothing.
///
/// `File::sync_all` on a directory handle is not a supported operation there,
/// and the volume flush that would substitute for it needs a raw handle and
/// administrative rights.
///
/// Nothing depends on it any more. Because no ordering can be enforced here,
/// [`ensure_durable_platform`] refuses at every public entry point before any
/// state is written, so on Windows this is never reached with work to do: no
/// anti-rollback floor is created, accepted or pruned, nothing is staged, and
/// no target is moved. It is kept, rather than deleted, so that the Windows
/// build of [`SecureDirectory`] still type-checks against one shared
/// implementation instead of a second path-based copy.
#[cfg(windows)]
fn sync_directory_path(_path: &Path) -> Result<(), UpdateError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory_handle(handle: &File) -> Result<(), UpdateError> {
    if let Some(error) = armed_fault_error(InjectedFault::FailNewStateDirectorySync) {
        return Err(UpdateError::Io(error));
    }
    handle.sync_all().map_err(UpdateError::Io)
}

/// Windows cannot flush a directory entry; see [`sync_directory_path`].
#[cfg(windows)]
fn sync_directory_handle(_handle: &File) -> Result<(), UpdateError> {
    Ok(())
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

fn load_rollback_state(state_directory: &SecureDirectory) -> Result<RollbackState, UpdateError> {
    let mut state = RollbackState::default();
    for name in state_directory.list_names()? {
        let Some(sequence) = rollback_sequence_from_name(&name) else {
            continue;
        };
        let candidate = state_directory
            .read_json::<RollbackState>(&name)?
            .ok_or(UpdateError::CorruptState)?;
        if candidate.highest_sequence != sequence || validate_rollback_state(&candidate).is_err() {
            return Err(UpdateError::CorruptState);
        }
        if candidate.highest_sequence > state.highest_sequence {
            state = candidate;
        } else if candidate.highest_sequence == state.highest_sequence && candidate != state {
            return Err(UpdateError::CorruptState);
        }
    }
    Ok(state)
}

#[cfg(test)]
fn manifest_digest(manifest: &ReleaseManifest) -> Result<String, UpdateError> {
    let bytes = serde_json::to_vec(manifest).map_err(UpdateError::ManifestJson)?;
    Ok(encode_hex(&Sha256::digest(bytes)))
}

fn artifact_digest(artifact: &ReleaseArtifact) -> Result<String, UpdateError> {
    let bytes = serde_json::to_vec(artifact).map_err(UpdateError::ManifestJson)?;
    Ok(encode_hex(&Sha256::digest(bytes)))
}

#[cfg(test)]
fn release_authorization(
    manifest: &ReleaseManifest,
    artifact: &ReleaseArtifact,
) -> Result<ReleaseAuthorization, UpdateError> {
    let manifest_sha256 = manifest_digest(manifest)?;
    release_authorization_with_digest(manifest, artifact, &manifest_sha256)
}

fn release_authorization_with_digest(
    manifest: &ReleaseManifest,
    artifact: &ReleaseArtifact,
    manifest_sha256: &str,
) -> Result<ReleaseAuthorization, UpdateError> {
    Ok(ReleaseAuthorization {
        sequence: manifest.sequence,
        version: manifest.version.clone(),
        published_at_unix: manifest.published_at_unix,
        expires_at_unix: manifest.expires_at_unix,
        manifest_sha256: manifest_sha256.to_owned(),
        artifact_sha256: artifact_digest(artifact)?,
    })
}

const fn validate_authorization_time(
    authorization: &ReleaseAuthorization,
    now: u64,
) -> Result<(), UpdateError> {
    if authorization.published_at_unix > now.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        || authorization.expires_at_unix <= authorization.published_at_unix
    {
        return Err(UpdateError::InvalidReleaseMetadata);
    }
    if authorization.expires_at_unix < now {
        return Err(UpdateError::ExpiredManifest);
    }
    Ok(())
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

    const fn headers(&self) -> &HeaderMap {
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
            Self::Reqwest(stream) => stream.next().await.transpose().map_err(redact_http_error),
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

fn redact_http_error(error: reqwest::Error) -> UpdateError {
    UpdateError::Http(error.without_url())
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
    if allow_loopback_http && url.scheme() == "http" && is_literal_loopback(url.host().as_ref()) {
        return Ok(());
    }
    Err(UpdateError::InsecureUrl)
}

const fn is_literal_loopback(host: Option<&Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
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

const fn hex_nibble(value: u8) -> Option<u8> {
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
    let mut buffer = stream_buffer();
    loop {
        let count = file.read(&mut buffer).await.map_err(UpdateError::Io)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
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

/// Refuses installs whose shape this crate cannot publish with its guarantees.
///
/// A directory bundle needs the signed archive hashed once and expanded from
/// that same immutable buffer, every nested directory made durable, and a tree
/// digest that separates shapes a flat walk conflates. None of that is in place,
/// so the bundle is refused before anything is staged rather than published on
/// weaker evidence than the executable path gets.
const fn ensure_supported_install(mode: InstallMode) -> Result<(), UpdateError> {
    match mode {
        InstallMode::Executable | InstallMode::LinuxPackage => Ok(()),
        InstallMode::MacOsBundle => Err(UpdateError::BundleInstallUnsupported),
    }
}

const fn ensure_kind_matches(kind: ArtifactKind, mode: InstallMode) -> Result<(), UpdateError> {    if matches!(
        (kind, mode),
        (ArtifactKind::Executable, InstallMode::Executable)
            | (ArtifactKind::MacOsBundle, InstallMode::MacOsBundle)
    ) {
        Ok(())
    } else {
        Err(UpdateError::InstallModeMismatch)
    }
}

#[cfg(not(windows))]
fn atomic_swap_verified(
    prepared: &PreparedArtifact,
    windows_lock_behavior: bool,
) -> Result<InstallOutcome, UpdateError> {
    let stage = &prepared.stage;
    recover_interrupted_swap(stage)?;
    ensure_entry_identity(&stage.directory, &prepared.source_name, &prepared.handle)?;

    // Content, not just identity, immediately before publication. An attacker
    // holding a descriptor on the staged object rewrites it in place: the inode
    // never changes, so every identity check still passes while the bytes have
    // become something the release never signed.
    prepared
        .signed
        .verify(&prepared.handle)
        .map_err(|_| UpdateError::StagedArtifactChanged)?;

    let recovery_digest = object_digest(&stage.directory, &prepared.source_name)?;
    // The ownership proof is duplicated before anything moves, so a failure to
    // duplicate it cannot leave a placed object the guard does not own.
    let placed_proof = prepared.handle.try_clone().map_err(UpdateError::Io)?;
    let Some(guard) = enter_swap(stage, recovery_digest, windows_lock_behavior)? else {
        // The target is locked, so nothing was installed. The verified staging
        // is discarded here rather than kept for a second attempt: bytes that
        // outlive this process are bytes something else can rewrite while no
        // updater run holds the staging lock, and the next run must not install
        // them on the strength of a check this run made. It re-downloads and
        // re-verifies instead.
        discard_verified_staging(stage)?;
        return Ok(InstallOutcome::RestartRequired);
    };

    // The slot this run emptied must still be empty: an independent reinstall
    // that arrived in between is somebody's working installation, not something
    // to replace.
    if let Err(install) =
        stage
            .directory
            .rename_to_new(&prepared.source_name, &stage.parent, &stage.target_name)
    {
        return Err(guard.roll_back(install));
    }
    guard.mark_target_placed(placed_proof);
    // Destination first: the object must be reachable under its new name before
    // the old name's removal becomes durable, or a crash between the two could
    // leave it reachable from neither.
    if let Err(error) = stage.parent.sync() {
        return Err(guard.roll_back(UpdateError::Io(error)));
    }
    // Then the source. The rename removed an entry from the staging directory
    // too, and until that removal is durable a crash can resurrect the staged
    // name alongside the installed one, leaving two names for one object and a
    // journal that describes neither.
    if let Err(error) = stage.directory.sync() {
        return Err(guard.roll_back(UpdateError::Io(error)));
    }
    let published = match armed_fault_error(InjectedFault::FailPublishedIdentity) {
        Some(error) => Err(UpdateError::Io(error)),
        None => ensure_entry_identity(&stage.parent, &stage.target_name, &prepared.handle),
    };
    if let Err(identity_error) = published {
        return Err(guard.roll_back(identity_error));
    }

    // And again immediately after publication, through the same retained
    // descriptor. Between the two checks the object became reachable under the
    // installed name, which is exactly the window in which an in-place rewrite
    // would otherwise be published as if it were signed. Failing here rolls the
    // previous installation back rather than leaving unsigned bytes installed.
    if let Err(error) = prepared.signed.verify(&prepared.handle) {
        return Err(guard.roll_back(error));
    }

    complete_swap(stage, &prepared.source_name, &guard)
}

/// Removes the verified staging so a later run cannot install from it.
///
/// Used when an install stops without publishing anything. Everything the next
/// run would otherwise resume from goes together: the verified artifact, the
/// partial download and the resume binding that ties them to a release. Leaving
/// any one behind would let a rerun skip the network and install bytes that sat
/// on disk, unguarded by the staging lock, while this process was gone.
///
/// The removal is made durable before it is reported, so a crash cannot bring
/// the discarded artifact back.
#[cfg(not(windows))]
fn discard_verified_staging(stage: &SecureStaging) -> Result<(), UpdateError> {
    stage
        .directory
        .remove_file_if_exists(OsStr::new(STAGED_VERIFIED))?;
    stage
        .directory
        .remove_file_if_exists(OsStr::new(STAGED_PART))?;
    stage
        .directory
        .remove_file_if_exists(OsStr::new(RESUME_BINDING))?;
    stage.directory.sync().map_err(UpdateError::Io)
}

/// Retires the rollback object and staging artifacts of a completed swap.
///
/// The journal outlives every other artifact and is removed last, only once the
/// installed target and the retired rollback object are durable.
#[cfg(not(windows))]
fn complete_swap(
    stage: &SecureStaging,
    source_name: &OsStr,
    guard: &SwapGuard<'_>,
) -> Result<InstallOutcome, UpdateError> {
    if guard.had_target {
        let Some(expected) = guard.original_digest.as_deref() else {
            return Err(UpdateError::SwapRecoveryConflict);
        };
        discard_backup(stage, &guard.journal.borrow(), expected)?;
    }
    stage.directory.remove_file_if_exists(source_name)?;
    stage
        .directory
        .remove_file_if_exists(OsStr::new(STAGED_VERIFIED))?;
    stage
        .directory
        .remove_file_if_exists(OsStr::new(STAGED_PART))?;
    stage
        .directory
        .remove_file_if_exists(OsStr::new(RESUME_BINDING))?;
    clear_journal_after_durable_parent(stage)?;
    Ok(InstallOutcome::Installed)
}

/// Refuses to swap on a platform whose durability primitives are unavailable.
///
/// # Why Windows fails closed instead of installing
///
/// Every guarantee the swap makes rests on ordering two things against a crash:
/// a journal must reach the disk *before* an object moves, and a moved object
/// must reach the disk *before* the journal describing it is retired. Enforcing
/// that needs a directory-metadata flush, and none is reachable here —
/// `File::sync_all` on a directory handle is not a supported operation on
/// Windows, and the volume-level flush that would substitute for it needs a raw
/// handle and administrative rights. The previous shape returned `Ok(())` from
/// every directory sync, which meant the ordering was never enforced and the
/// code claimed a durability it did not provide.
///
/// The same wall blocks the other half. Telling one filesystem object from
/// another needs `MetadataExt::file_index`/`volume_serial_number`, which are
/// unstable (`windows_by_handle`, rust-lang/rust#63010); the raw
/// `GetFileInformationByHandle` call and handle-relative `NtCreateFile`
/// operations need `unsafe`, which this workspace sets to `forbid` — a level a
/// crate cannot override — and `--locked` builds rule out adding a wrapper
/// crate. Without object identity, every recovery decision would have to be
/// made by re-resolving a pathname, which is exactly what a replaced parent or
/// a changed working directory redirects.
///
/// Layering more path-based recovery on those two gaps produces machinery that
/// cannot be shown correct. So this refuses, and
/// [`UpdateError::PlatformDurabilityUnsupported`] tells the caller to complete
/// the replacement through a mechanism that does have the guarantees, such as a
/// platform installer or a restart helper.
///
/// In practice no Windows caller reaches this: [`ensure_durable_platform`]
/// already refuses at every public entry point, before the network and before
/// any state, staging or target is touched. This is the second line of that
/// defence, so that removing the boundary check cannot silently re-enable a
/// swap whose ordering nothing enforces.
#[cfg(windows)]
fn atomic_swap_verified(
    prepared: &PreparedArtifact,
    _windows_lock_behavior: bool,
) -> Result<InstallOutcome, UpdateError> {
    let _ = &prepared.stage;
    Err(UpdateError::PlatformDurabilityUnsupported)
}

/// Reads the identity of whatever currently occupies the target name.
///
/// Both the existence probe and the digest can hit a sharing violation on
/// Windows, so they are done together and the error is left typed for the
/// caller to classify.
#[cfg(not(windows))]
fn measure_existing_target(stage: &SecureStaging) -> Result<Option<String>, UpdateError> {
    if !stage.parent.object_exists(&stage.target_name)? {
        return Ok(None);
    }
    object_digest(&stage.parent, &stage.target_name).map(Some)
}

/// Reports whether an updater error is a Windows sharing violation underneath.
#[cfg(not(windows))]
fn is_sharing_violation_error(error: &UpdateError) -> bool {
    match error {
        UpdateError::Io(error) => is_windows_sharing_violation(error),
        _ => false,
    }
}

/// Journals the swap, moves any installed target aside, and returns the guard
/// that restores it if a later step fails.
///
/// The journal is durable before anything moves and records both the phase the
/// run reached and the identity of the installation it found, which is what
/// recovery needs to tell an untouched previous install from a target slot this
/// run already owns. `Ok(None)` means a Windows sharing lock kept the current
/// target in place and nothing was journalled or moved.
#[cfg(not(windows))]
fn enter_swap(
    stage: &SecureStaging,
    recovery_digest: String,
    windows_lock_behavior: bool,
) -> Result<Option<SwapGuard<'_>>, UpdateError> {
    // Discovery happens before anything is written. A running installation on
    // Windows refuses to be opened for reading, and that is the ordinary
    // "close the app and try again" case, not a failure: it has to surface as
    // `RestartRequired` *here*, while the journal does not yet exist and
    // nothing on disk has been touched. Journalling first and discovering the
    // lock afterwards would leave a journal describing a swap that never began.
    let original_digest = match measure_existing_target(stage) {
        Ok(digest) => digest,
        Err(error) => {
            if windows_lock_behavior && is_sharing_violation_error(&error) {
                return Ok(None);
            }
            return Err(error);
        }
    };
    let had_target = original_digest.is_some();
    let mut journal = SwapJournal {
        phase: SwapPhase::Prepared,
        recovery_digest,
        original_digest: original_digest.clone(),
        quarantine: None,
    };
    stage
        .directory
        .write_json_atomic(OsStr::new(SWAP_JOURNAL), &journal)?;
    exit_at_armed_fault(InjectedFault::ExitAfterSwapPrepared);

    if had_target
        && let Err(error) = stage.parent.rename_to_new(
            &stage.target_name,
            &stage.parent,
            &stage.backup_name,
        )
    {
        stage
            .directory
            .remove_file_if_exists(OsStr::new(SWAP_JOURNAL))?;
        stage.directory.sync().map_err(UpdateError::Io)?;
        if windows_lock_behavior && is_sharing_violation_error(&error) {
            return Ok(None);
        }
        return Err(error);
    }

    let guard = SwapGuard {
        stage,
        had_target,
        original_digest,
        journal: RefCell::new(journal.clone()),
        placed: RefCell::new(None),
    };

    // The committed phase asserts that the target slot belongs to this run, so
    // the rename that made it so has to be durable first. Recording the phase
    // ahead of the sync would let a crash leave a journal claiming a move the
    // filesystem never kept.
    if let Some(error) = armed_fault_error(InjectedFault::FailParentSyncAfterSwap) {
        return Err(guard.roll_back(UpdateError::Io(error)));
    }
    if let Err(error) = stage.parent.sync() {
        return Err(guard.roll_back(UpdateError::Io(error)));
    }
    exit_at_armed_fault(InjectedFault::ExitAfterTargetMovedAside);

    // The object now in the rollback slot must be the installation that was
    // measured, or something replaced the target between the measurement and
    // the rename. Completing the swap would then retire an install this run
    // never saw, so the previous state is put back instead. Every outcome here,
    // including a failure to read the object at all, runs through the guard:
    // the target slot is empty at this point, so nothing may return without it.
    if let Some(expected) = guard.original_digest.as_deref() {
        let moved = match armed_fault_error(InjectedFault::FailMovedAsideDigest) {
            Some(error) => Err(UpdateError::Io(error)),
            None => object_digest(&stage.parent, &stage.backup_name),
        };
        match moved {
            Ok(moved) if moved == expected => {}
            Ok(_) => {
                // Something replaced the installation between the measurement
                // and the rename: a conflict, not an I/O fault.
                return Err(guard.roll_back(UpdateError::SwapRecoveryConflict));
            }
            Err(error) => {
                return Err(guard.roll_back(error));
            }
        }
    }

    journal.phase = SwapPhase::Swapped;
    if let Err(error) = stage
        .directory
        .write_json_atomic(OsStr::new(SWAP_JOURNAL), &journal)
    {
        return Err(guard.roll_back(error));
    }
    // The guard writes further records on top of whatever is on disk, so it has
    // to hold the record that is actually there. Keeping the `Prepared` clone
    // would make the next write revert the phase, and recovery would then read
    // a journal claiming the target had never been moved aside.
    guard.adopt_journal(journal);
    exit_at_armed_fault(InjectedFault::ExitAfterSwapCommitted);
    Ok(Some(guard))
}

/// Proof that this run is the one that put the object now at the target name there.
///
/// Rollback removes a partially installed object only while this proof still
/// holds, so a failure can never delete an installation the run did not create.
#[cfg(not(windows))]
#[derive(Debug)]
struct PlacedTarget {
    handle: File,
}

#[cfg(not(windows))]
impl PlacedTarget {
    /// Reports whether the object at the target name is still the one this run placed.
    ///
    /// Compares the identity of the retained open file against the entry the
    /// name resolves to now, so a replacement is visible as a different object
    /// rather than as an equal path. Platforms without by-handle identity
    /// cannot answer and refuse; see [`ensure_entry_identity`].
    fn is_still_owned(&self, stage: &SecureStaging) -> Result<bool, UpdateError> {
        match ensure_entry_identity(&stage.parent, &stage.target_name, &self.handle) {
            Ok(()) => Ok(true),
            Err(UpdateError::StagedArtifactChanged) => Ok(false),
            Err(UpdateError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }


    /// The identity the owned object has right now, measured through the
    /// handle that owns it.
    ///
    /// Taken with the ownership handle still open, so it describes the object
    /// this run placed rather than whatever a name resolves to later. It is
    /// computed with the same routine that re-verifies the object after it has
    /// been quarantined, so the two are directly comparable.
    fn owned_identity(&self, path: &Path) -> Result<String, UpdateError> {
        let handle = self.handle.try_clone().map_err(UpdateError::Io)?;
        object_digest_of(handle, path)
    }
}

/// Restores the previous installation when a step after the target was moved
/// aside fails, so no failure path can return with the target missing.
#[cfg(not(windows))]
struct SwapGuard<'stage> {
    stage: &'stage SecureStaging,
    had_target: bool,
    original_digest: Option<String>,
    journal: RefCell<SwapJournal>,
    placed: RefCell<Option<PlacedTarget>>,
}

#[cfg(not(windows))]
impl SwapGuard<'_> {
    /// Replaces the guard's record with the one now on disk.
    ///
    /// Every later write derives from this, so it must never lag behind the
    /// journal the filesystem actually holds.
    fn adopt_journal(&self, journal: SwapJournal) {
        self.journal.replace(journal);
    }

    /// Takes ownership of the object this run has just put at the target name.
    ///
    /// This is called with the handle the creating call returned, before any
    /// content is written through it, so the guard owns the object from the
    /// moment it exists.
    fn mark_target_placed(&self, handle: File) {
        self.placed.replace(Some(PlacedTarget { handle }));
    }

    fn roll_back(&self, install: UpdateError) -> UpdateError {
        let placed = self.placed.borrow_mut().take();
        rollback_secure_swap(
            self.stage,
            self.had_target,
            &self.journal.borrow(),
            placed,
            install,
        )
    }
}

/// Puts the previous installation back and reports why the swap was undone.
///
/// An object this run placed at the target is removed, and that removal is made
/// durable, before the journal is cleared, so a fresh install that failed midway
/// never leaves a truncated executable a later run would take for a complete
/// one. An object that is no longer the one this run placed is left alone and
/// reported as [`UpdateError::SwapRecoveryConflict`].
///
/// The returned error is always a failure: [`UpdateError::InstallRolledBack`]
/// when the previous installation is in place again,
/// [`UpdateError::RollbackFailed`] when it could not be restored, and the
/// underlying filesystem error when the rollback itself could not run.
#[cfg(not(windows))]
fn rollback_secure_swap(
    stage: &SecureStaging,
    had_target: bool,
    journal: &SwapJournal,
    placed: Option<PlacedTarget>,
    install: UpdateError,
) -> UpdateError {
    // Removing the failed replacement and restoring the previous installation
    // are separate obligations. A durability failure in the first must not skip
    // the second: the target being empty is the state this whole guard exists to
    // avoid, so a restore is always attempted and any deferred failure is
    // reported only once the installation is back.
    let mut deferred: Option<UpdateError> = None;
    if let Some(placed) = placed
        && let Err(error) = remove_placed_target(stage, journal, placed)
    {
        if !had_target {
            return error;
        }
        deferred = Some(error);
    }

    if !had_target {
        if let Err(error) = clear_journal_after_durable_parent(stage) {
            return error;
        }
        return install;
    }

    match stage.parent.rename_to_new(
        &stage.backup_name,
        &stage.parent,
        &stage.target_name,
    ) {
        Ok(()) => {
            // The installation is back, so the journal no longer describes
            // anything pending and must not outlive this run: a journal left
            // behind here would make the next run try to recover a swap that is
            // already settled, against a target it can no longer explain. It is
            // cleared even when a durability failure is already owed, and only
            // then is that failure reported.
            let settled = clear_journal_after_durable_parent(stage);
            if let Some(deferred) = deferred {
                return deferred;
            }
            if let Err(error) = settled {
                return error;
            }
            // A cause that already has a type keeps it: flattening
            // `SwapRecoveryConflict` or `NoReplaceRenameUnsupported` into a
            // string would tell the caller "the install failed" while hiding
            // *which* failure it was, and those two carry different guidance.
            // `InstallRolledBack` is for causes that are genuinely just I/O.
            match install {
                UpdateError::Io(install) => UpdateError::InstallRolledBack(install),
                typed => typed,
            }
        }
        Err(restore) => match (install, restore) {
            (UpdateError::Io(install), UpdateError::Io(rollback)) => {
                UpdateError::RollbackFailed { install, rollback }
            }
            // The restore failing is the more serious of the two, so its type
            // is the one that survives when both cannot be represented.
            (_, restore) => restore,
        },
    }
}

/// Removes the object this run placed, keeping the ownership proof until it is gone.
///
/// The handle is never released before the name is mutated on a platform where
/// releasing it would let something else take the name: Unix unlinks through the
/// retained directory handle while still holding the file handle, so the entry
/// that goes is the entry this run owns. Windows cannot unlink a name held with
/// no sharing, so the object is first truncated through the owning handle and
/// then atomically moved into the private staging directory, where it is
/// re-verified as this run's before being deleted. Either way nothing is
/// deleted by pathname after ownership has been given up.
#[cfg(not(windows))]
fn remove_placed_target(
    stage: &SecureStaging,
    journal: &SwapJournal,
    placed: PlacedTarget,
) -> Result<(), UpdateError> {
    if !placed.is_still_owned(stage)? {
        return Err(UpdateError::SwapRecoveryConflict);
    }
    // Measured through the ownership handle, so it describes the object this run
    // placed rather than whatever the name resolves to later. The handle stays
    // open across the move so the object that arrives can be compared against
    // it directly.
    let expected = placed.owned_identity(&stage.parent.path.join(&stage.target_name))?;
    drop(placed);

    quarantine_and_delete(
        stage,
        journal,
        QuarantineKind::WithdrawnInstall,
        &stage.target_name,
        &expected,
    )?;
    if let Some(error) = armed_fault_error(InjectedFault::FailParentSyncDuringRollback) {
        return Err(UpdateError::Io(error));
    }
    stage.parent.sync().map_err(UpdateError::Io)
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
            return Ok(InstallOutcome::RestartRequired);
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
    #[cfg(not(windows))]
    use std::sync::{Barrier, mpsc};

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

    /// A journal with no pending records, for tests that only need the identity.
    #[cfg(not(windows))]
    fn plain_journal(recovery: &[u8], original: Option<&[u8]>) -> SwapJournal {
        SwapJournal {
            phase: SwapPhase::Swapped,
            recovery_digest: encode_hex(&Sha256::digest(recovery)),
            original_digest: original.map(|bytes| encode_hex(&Sha256::digest(bytes))),
            quarantine: None,
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
            drop(existing);
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

    // The swap only exists where its durability primitives do.
    #[cfg(not(windows))]
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
            signed: SignedContent {
                digest: Sha256::digest(b"new executable").into(),
                size: u64::try_from(b"new executable".len()).expect("small executable"),
            },
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
        let recovery_digest =
            object_digest(&stage.directory, OsStr::new(STAGED_VERIFIED)).expect("staged digest");
        let original_digest =
            object_digest(&stage.parent, &stage.target_name).expect("installed digest");
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest,
                    original_digest: Some(original_digest),
                    quarantine: None,
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

    #[cfg(not(windows))]
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

        let error = rollback_secure_swap(
            &stage,
            true,
            &plain_journal(b"a replacement", Some(b"previous")),
            Some(PlacedTarget { handle: failed }),
            UpdateError::Io(io::Error::other("simulated real rename failure")),
        );
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

    /// A rollback object nobody journalled must never become the installation.
    ///
    /// The journal is made durable before the target is moved aside, so every
    /// rollback object this crate creates has a record naming it. One without a
    /// record came from somewhere else, and adopting it would publish an object
    /// of unknown provenance under the application's own name.
    #[cfg(not(windows))]
    #[test]
    fn a_rollback_object_with_no_journal_is_never_adopted_as_the_installation() {
        let directory = UnitTestDir::new("unjournalled-backup");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let rollback_path = directory.path.join(".gta-claw.gta-claw.rollback");
        fs::write(&rollback_path, b"an object nobody journalled").expect("write rollback object");

        let error = recover_interrupted_swap(&stage)
            .expect_err("an unjournalled rollback object is not this run's to publish");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(&rollback_path).expect("the object is left exactly where it was"),
            b"an object nobody journalled"
        );
        assert!(
            !target_path.exists(),
            "a conflict must never install the unidentified object"
        );
    }

    /// A withdrawn replacement stays quarantined instead of going back live.
    ///
    /// Its quarantine source *is* the target name, so putting it back would
    /// republish the very object the run already decided not to keep.
    #[cfg(not(windows))]
    #[test]
    fn a_withdrawn_install_is_never_returned_to_the_target_name() {
        let directory = UnitTestDir::new("withdrawn-quarantine");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let retired = OsString::from(format!("{QUARANTINE_PREFIX}91"));
        let mut quarantined = stage
            .directory
            .open_regular(&retired, true)
            .expect("create quarantined object");
        quarantined
            .write_all(b"the withdrawn replacement")
            .expect("write quarantined object");
        quarantined.sync_all().expect("sync quarantined object");
        drop(quarantined);
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest: encode_hex(&Sha256::digest(b"a replacement")),
                    original_digest: Some(encode_hex(&Sha256::digest(b"the original"))),
                    quarantine: Some(Quarantine {
                        operation: QuarantineKind::WithdrawnInstall,
                        source: stage.target_name.to_string_lossy().into_owned(),
                        // Recorded identity deliberately does not match what is
                        // on disk, which is what drives the restore path.
                        digest: encode_hex(&Sha256::digest(b"something else")),
                        destination: retired.to_string_lossy().into_owned(),
                        phase: QuarantinePhase::Moved,
                    }),
                },
            )
            .expect("write swap journal");

        let error = recover_interrupted_swap(&stage)
            .expect_err("a withdrawn install that cannot be verified is not deleted either");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert!(
            !target_path.exists(),
            "a withdrawn replacement must never be restored as the live installation"
        );
        assert!(
            stage
                .directory
                .object_exists(&retired)
                .expect("quarantine state"),
            "it stays quarantined, where the journal still describes it"
        );
    }

    /// Two trees a flat walk cannot tell apart must not share a digest.
    #[cfg(not(windows))]
    #[test]
    fn nested_and_sibling_trees_of_the_same_names_digest_differently() {
        let directory = UnitTestDir::new("tree-digest");
        // `nested/a/b` is a file inside a directory; `sibling/a` is an empty
        // directory with `sibling/b` beside it. Same names, same contents, and
        // without a child count the two walks emit identical bytes.
        let nested = directory.path.join("nested");
        fs::create_dir(&nested).expect("create nested root");
        fs::create_dir(nested.join("a")).expect("create nested child");
        fs::write(nested.join("a").join("b"), b"").expect("write nested leaf");

        let sibling = directory.path.join("sibling");
        fs::create_dir(&sibling).expect("create sibling root");
        fs::create_dir(sibling.join("a")).expect("create sibling directory");
        fs::write(sibling.join("b"), b"").expect("write sibling leaf");

        let root = SecureDirectory::open_existing(&directory.path, false).expect("open root");
        let nested_digest = object_digest(&root, OsStr::new("nested")).expect("nested digest");
        let sibling_digest = object_digest(&root, OsStr::new("sibling")).expect("sibling digest");

        assert_ne!(
            nested_digest, sibling_digest,
            "a tree digest that conflates nesting with siblings cannot detect a swapped tree"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn fresh_install_recovery_refuses_to_delete_an_unidentified_target() {
        let directory = UnitTestDir::new("fresh-crash");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut staged = stage
            .directory
            .open_regular(OsStr::new(STAGED_VERIFIED), true)
            .expect("create staged executable");
        staged
            .write_all(b"complete replacement")
            .expect("write staged executable");
        staged.sync_all().expect("sync staged executable");
        let recovery_digest =
            object_digest(&stage.directory, OsStr::new(STAGED_VERIFIED)).expect("staged digest");
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest,
                    original_digest: None,
                    quarantine: None,
                },
            )
            .expect("write swap journal");
        let mut independent = stage
            .parent
            .open_regular(&stage.target_name, true)
            .expect("create independent install");
        independent
            .write_all(b"independent reinstall")
            .expect("write independent install");
        independent.sync_all().expect("sync independent install");
        drop(independent);

        let error = recover_interrupted_swap(&stage)
            .expect_err("an unidentified target must not be deleted");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(&target_path).expect("read untouched target"),
            b"independent reinstall"
        );
        assert!(
            stage
                .directory
                .object_exists(OsStr::new(SWAP_JOURNAL))
                .expect("journal state")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn recovery_before_the_swap_keeps_the_installation_it_found() {
        let directory = UnitTestDir::new("pre-swap-crash");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"known good").expect("write existing install");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut staged = stage
            .directory
            .open_regular(OsStr::new(STAGED_VERIFIED), true)
            .expect("create staged executable");
        staged
            .write_all(b"complete replacement")
            .expect("write staged executable");
        staged.sync_all().expect("sync staged executable");
        let recovery_digest =
            object_digest(&stage.directory, OsStr::new(STAGED_VERIFIED)).expect("staged digest");
        let original_digest =
            object_digest(&stage.parent, &stage.target_name).expect("installed digest");
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Prepared,
                    recovery_digest,
                    original_digest: Some(original_digest),
                    quarantine: None,
                },
            )
            .expect("write swap journal");

        recover_interrupted_swap(&stage).expect("a journal written before the swap is discarded");

        assert_eq!(
            fs::read(&target_path).expect("read untouched install"),
            b"known good"
        );
        assert!(
            !stage
                .directory
                .object_exists(OsStr::new(SWAP_JOURNAL))
                .expect("journal state")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn recovery_rejects_a_rollback_object_that_is_not_the_recorded_original() {
        let directory = UnitTestDir::new("foreign-rollback");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create rollback object");
        backup
            .write_all(b"foreign rollback")
            .expect("write rollback object");
        backup.sync_all().expect("sync rollback object");
        drop(backup);
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest: encode_hex(&Sha256::digest(b"replacement")),
                    original_digest: Some(encode_hex(&Sha256::digest(b"a different original"))),
                    quarantine: None,
                },
            )
            .expect("write swap journal");

        let error = recover_interrupted_swap(&stage)
            .expect_err("a rollback object with another identity is not restored");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert!(!target_path.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn first_use_creates_and_syncs_every_new_state_directory() {
        let directory = UnitTestDir::new("durable-state");
        let root = directory
            .path
            .join("state")
            .join("gta-claw")
            .join("updater");

        let created = ensure_directory_tree_durable(&root).expect("create protected state tree");

        assert_eq!(
            created,
            vec![
                directory.path.join("state"),
                directory.path.join("state").join("gta-claw"),
                root.clone()
            ]
        );
        assert!(root.is_dir());
        assert!(
            ensure_directory_tree_durable(&root)
                .expect("reopen protected state tree")
                .is_empty(),
            "an existing state tree must not be recreated"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_state_path_blocked_by_a_file_is_refused() {
        let directory = UnitTestDir::new("state-blocked");
        fs::write(directory.path.join("state"), b"not a directory").expect("write blocking file");

        let error = ensure_directory_tree_durable(&directory.path.join("state").join("updater"))
            .expect_err("a state path blocked by a file is refused");

        assert_eq!(
            error.to_string(),
            "updater refused an unsafe filesystem object"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_selected_level_sync_failure_leaves_the_tree_unconfirmed_and_retried() {
        let directory = UnitTestDir::new("unsynced-state");
        let root = directory.path.join("state").join("gta-claw").join("updater");
        let syncs = state_tree_sync_points(&root);

        // Aimed at the *last* level's sync, so every level exists and only the
        // final one fails. A fault on the first sync would stop the run before
        // the state this test inspects had been created at all.
        arm_injected_fault_after(InjectedFault::FailNewStateDirectorySync, syncs - 1);
        let error = ensure_directory_tree_durable(&root)
            .expect_err("an unconfirmed state tree is not usable");
        assert_eq!(error.to_string(), "update filesystem operation failed");

        // Every level was created before any of them was confirmed, so the
        // directories are on disk but the tree is not marked durable.
        assert!(root.is_dir(), "the levels are created before they are confirmed");
        assert!(
            !root.join(DURABLE_MARKER).exists(),
            "a tree with a failed sync must not be recorded as confirmed"
        );

        // The directories are left alone on purpose: after a crash they are
        // indistinguishable from confirmed ones, so the guarantee comes from
        // the missing marker, not from cleaning up. A retry must therefore
        // confirm again and fail the same way while the sync keeps failing.
        // Aimed at the last level's parent sync: skip the ones before it.
        arm_injected_fault_after(InjectedFault::FailNewStateDirectorySync, syncs - 1);
        let repeated = ensure_directory_tree_durable(&root)
            .expect_err("an existing unconfirmed tree must be confirmed again, not skipped");
        assert_eq!(repeated.to_string(), "update filesystem operation failed");

        disarm_injected_fault();
        ensure_directory_tree_durable(&root).expect("confirmation succeeds once the sync can run");
        assert!(
            root.join(DURABLE_MARKER).is_file(),
            "a confirmed tree records the fact durably"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_confirmed_state_tree_is_not_synced_again() {
        let directory = UnitTestDir::new("confirmed-state");
        let root = directory.path.join("state").join("gta-claw");
        ensure_directory_tree_durable(&root).expect("confirm the state tree");

        // Every sync would now fail, so a run that still reached one would be
        // reported. Reaching none is what the recorded confirmation buys.
        arm_injected_fault(InjectedFault::FailNewStateDirectorySync);
        let created = ensure_directory_tree_durable(&root)
            .expect("a confirmed tree needs no further syncs");
        disarm_injected_fault();

        assert!(created.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_state_child_is_confirmed_again_and_never_skips_its_sync() {
        let directory = UnitTestDir::new("unsynced-child");
        let root =
            SecureDirectory::open_or_create(&directory.path.join("state"), true).expect("root");
        let child = OsStr::new("target-abcdef");

        arm_injected_fault(InjectedFault::FailNewStateDirectorySync);
        let error = root
            .create_child_durable(child)
            .expect_err("an unconfirmed child is not usable");
        assert_eq!(error.to_string(), "update filesystem operation failed");
        assert!(
            !directory
                .path
                .join("state")
                .join("target-abcdef")
                .join(DURABLE_MARKER)
                .exists()
        );

        // Still armed: an existing but unconfirmed child must be confirmed
        // again rather than accepted because it is already there.
        let repeated = root
            .create_child_durable(child)
            .expect_err("an existing unconfirmed child must be confirmed again, not skipped");
        assert_eq!(repeated.to_string(), "update filesystem operation failed");

        disarm_injected_fault();
        root.create_child_durable(child)
            .expect("confirmation succeeds once the sync can run");
        assert!(
            directory
                .path
                .join("state")
                .join("target-abcdef")
                .join(DURABLE_MARKER)
                .is_file()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn recovery_keeps_a_target_that_still_matches_the_recorded_original() {
        let directory = UnitTestDir::new("lost-rename");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"known good").expect("write existing install");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let original_digest =
            object_digest(&stage.parent, &stage.target_name).expect("installed digest");
        // A journal that claims the swap phase while the target still holds the
        // installation it measured: the move aside never reached the disk.
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest: encode_hex(&Sha256::digest(b"a replacement never installed")),
                    original_digest: Some(original_digest),
                    quarantine: None,
                },
            )
            .expect("write swap journal");

        recover_interrupted_swap(&stage).expect("an untouched original is not a conflict");

        assert_eq!(
            fs::read(&target_path).expect("read untouched install"),
            b"known good"
        );
        assert!(
            !stage
                .directory
                .object_exists(OsStr::new(SWAP_JOURNAL))
                .expect("journal state")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_rollback_object_that_is_not_the_recorded_original_is_never_deleted() {
        let directory = UnitTestDir::new("foreign-backup-discard");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"installed replacement").expect("write installed replacement");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create rollback object");
        backup
            .write_all(b"an independent replacement")
            .expect("write rollback object");
        backup.sync_all().expect("sync rollback object");
        drop(backup);

        let measured = encode_hex(&Sha256::digest(b"measured"));
        let journal = plain_journal(b"a replacement", Some(b"measured"));
        let error = discard_backup(&stage, &journal, &measured)
            .expect_err("a rollback object with another identity is not retired");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(directory.path.join(".gta-claw.gta-claw.rollback"))
                .expect("read retained rollback object"),
            b"an independent replacement"
        );
    }

    // The swap only exists where its durability primitives do.
    #[cfg(not(windows))]
    #[test]
    fn an_unreadable_moved_aside_object_rolls_back_instead_of_escaping() {
        let directory = UnitTestDir::new("unreadable-backup");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"known good").expect("write existing install");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = Arc::new(SecureStaging::open(&target).expect("secure stage"));
        let replacement = b"verified replacement";
        let mut staged = stage
            .directory
            .open_regular(OsStr::new(STAGED_VERIFIED), true)
            .expect("create staged executable");
        staged.write_all(replacement).expect("write staged bytes");
        staged.sync_all().expect("sync staged bytes");
        let prepared = PreparedArtifact {
            path: stage.directory.path.join(STAGED_VERIFIED),
            source_name: OsString::from(STAGED_VERIFIED),
            handle: staged.try_clone().expect("clone staged handle"),
            stage: Arc::clone(&stage),
            signed: SignedContent {
                digest: Sha256::digest(replacement).into(),
                size: u64::try_from(replacement.len()).expect("small replacement"),
            },
        };

        // Reading the moved-aside object back fails while the target slot is
        // empty. That failure must go through the guard, not escape.
        arm_injected_fault(InjectedFault::FailMovedAsideDigest);
        let error =
            atomic_swap_verified(&prepared, false).expect_err("an unreadable move aside is caught");
        disarm_injected_fault();

        assert_eq!(
            error.to_string(),
            "update installation failed; previous version was restored",
            "an unreadable moved-aside object must roll back, not escape with the target missing"
        );
        assert_eq!(
            fs::read(&target_path).expect("read restored install"),
            b"known good",
            "the install must never return with the target missing"
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

    #[cfg(not(windows))]
    #[test]
    fn a_fresh_install_journal_never_retires_a_rollback_object_it_did_not_create() {
        let directory = UnitTestDir::new("unowned-backup");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let replacement = b"this run's replacement";
        let mut installed = stage
            .parent
            .open_regular(&stage.target_name, true)
            .expect("create installed target");
        installed.write_all(replacement).expect("write target");
        installed.sync_all().expect("sync target");
        drop(installed);
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create unrelated rollback object");
        backup
            .write_all(b"an unrelated rollback object")
            .expect("write rollback object");
        backup.sync_all().expect("sync rollback object");
        drop(backup);
        // A fresh install records no original, so any rollback object present
        // belongs to something else even when the target holds this run's
        // replacement.
        let recovery_digest =
            object_digest(&stage.parent, &stage.target_name).expect("installed digest");
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest,
                    original_digest: None,
                    quarantine: None,
                },
            )
            .expect("write swap journal");

        let error = recover_interrupted_swap(&stage)
            .expect_err("a fresh-install journal cannot retire an unowned rollback object");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(directory.path.join(".gta-claw.gta-claw.rollback"))
                .expect("read retained rollback object"),
            b"an unrelated rollback object"
        );
        assert_eq!(fs::read(&target_path).expect("read target"), replacement);
    }

    #[cfg(not(windows))]
    #[test]
    fn recovery_refuses_to_restore_over_an_independent_reinstall() {
        let directory = UnitTestDir::new("reinstall-race");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");

        // The state a crash leaves right after the move aside...
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create rollback object");
        backup.write_all(b"previous install").expect("write backup");
        backup.sync_all().expect("sync backup");
        drop(backup);
        let original_digest =
            object_digest(&stage.parent, &stage.backup_name).expect("backup digest");
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest: encode_hex(&Sha256::digest(b"a replacement")),
                    original_digest: Some(original_digest),
                    quarantine: None,
                },
            )
            .expect("write swap journal");

        // ...and an independent reinstall that arrived before recovery ran.
        // Restoring over it would destroy a working installation, so a
        // replacing rename is exactly the wrong operation here.
        let mut reinstall = stage
            .parent
            .open_regular(&stage.target_name, true)
            .expect("create independent reinstall");
        reinstall
            .write_all(b"independent reinstall")
            .expect("write reinstall");
        reinstall.sync_all().expect("sync reinstall");
        drop(reinstall);

        let error = recover_interrupted_swap(&stage)
            .expect_err("recovery must not restore over an independent reinstall");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(&target_path).expect("read the independent reinstall"),
            b"independent reinstall",
            "the independent installation must survive untouched"
        );
        assert_eq!(
            fs::read(directory.path.join(".gta-claw.gta-claw.rollback"))
                .expect("read retained rollback object"),
            b"previous install"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn claiming_an_occupied_target_reports_a_conflict_instead_of_replacing() {
        let directory = UnitTestDir::new("no-replace");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut occupant = stage
            .parent
            .open_regular(&stage.target_name, true)
            .expect("create occupant");
        occupant.write_all(b"an occupant").expect("write occupant");
        occupant.sync_all().expect("sync occupant");
        drop(occupant);
        let mut staged = stage
            .directory
            .open_regular(OsStr::new(STAGED_VERIFIED), true)
            .expect("create staged object");
        staged.write_all(b"a claimant").expect("write staged object");
        staged.sync_all().expect("sync staged object");
        drop(staged);

        let error = stage
            .directory
            .rename_to_new(
                OsStr::new(STAGED_VERIFIED),
                &stage.parent,
                &stage.target_name,
            )
            .expect_err("claiming an occupied name is refused");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(&target_path).expect("read the occupant"),
            b"an occupant",
            "a no-replace claim must leave the occupant exactly as it was"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_rollback_object_that_changed_after_quarantine_is_put_back() {
        let directory = UnitTestDir::new("quarantine-restore");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create rollback object");
        backup
            .write_all(b"not what was measured")
            .expect("write rollback object");
        backup.sync_all().expect("sync rollback object");
        drop(backup);

        let journal = plain_journal(b"a replacement", Some(b"measured"));
        let error = discard_backup(&stage, &journal, &encode_hex(&Sha256::digest(b"measured")))
            .expect_err("an object that is not the recorded original is not discarded");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(directory.path.join(".gta-claw.gta-claw.rollback"))
                .expect("the quarantined object is put back under its own name"),
            b"not what was measured"
        );
        assert!(
            !stage
                .directory
                .list_names()
                .expect("staging entries")
                .iter()
                .any(|name| name.to_string_lossy().starts_with(".retired-backup-")),
            "nothing may be left stranded in the private staging directory"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn an_unjournalled_quarantine_leftover_is_never_blindly_deleted() {
        let directory = UnitTestDir::new("stray-quarantine");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"an installation").expect("write installation");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");

        // A quarantined object left by something this run has no record of.
        let stray = OsString::from(format!("{QUARANTINE_PREFIX}999"));
        let mut leftover = stage
            .directory
            .open_regular(&stray, true)
            .expect("create stray quarantined object");
        leftover
            .write_all(b"somebody else's installation")
            .expect("write leftover");
        leftover.sync_all().expect("sync leftover");
        drop(leftover);

        let error = recover_interrupted_swap(&stage)
            .expect_err("an unexplained quarantined object is not this run's to delete");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(stage.directory.path.join(&stray)).expect("read retained leftover"),
            b"somebody else's installation",
            "a restart must never sweep a quarantined object it cannot identify"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_journalled_quarantine_that_no_longer_matches_is_put_back() {
        let directory = UnitTestDir::new("journalled-quarantine");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"an installation").expect("write installation");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let retired = OsString::from(format!("{QUARANTINE_PREFIX}42"));
        let mut quarantined = stage
            .directory
            .open_regular(&retired, true)
            .expect("create quarantined object");
        quarantined
            .write_all(b"not what was recorded")
            .expect("write quarantined object");
        quarantined.sync_all().expect("sync quarantined object");
        drop(quarantined);
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest: encode_hex(&Sha256::digest(b"a replacement")),
                    original_digest: Some(encode_hex(&Sha256::digest(b"the original"))),
                    quarantine: Some(Quarantine {
                        operation: QuarantineKind::RetiredBackup,
                        source: stage.backup_name.to_string_lossy().into_owned(),
                        destination: retired.to_string_lossy().into_owned(),
                        digest: encode_hex(&Sha256::digest(b"the original")),
                        phase: QuarantinePhase::Moved,
                    }),
                },
            )
            .expect("write swap journal");

        let error = recover_interrupted_swap(&stage)
            .expect_err("a quarantined object that changed is not deleted");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(directory.path.join(".gta-claw.gta-claw.rollback"))
                .expect("the quarantined object is restored under the rollback name"),
            b"not what was recorded"
        );
    }

    /// The quarantine completed, but something else now holds the source name.
    ///
    /// Recovery reads the rollback name immediately after resolving the
    /// quarantine, so treating this as "nothing left to do" would let the
    /// foreign object be measured and restored as the installation.
    #[cfg(not(windows))]
    #[test]
    fn a_finished_quarantine_never_adopts_an_object_that_took_the_source_name() {
        let directory = UnitTestDir::new("quarantine-source-retaken");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let rollback_path = directory.path.join(".gta-claw.gta-claw.rollback");

        // The retirement finished: the quarantined object is gone. An
        // independent run then created something under the rollback name.
        fs::write(&rollback_path, b"an independent object").expect("write independent object");
        let retired = OsString::from(format!("{QUARANTINE_PREFIX}77"));
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest: encode_hex(&Sha256::digest(b"a replacement")),
                    original_digest: Some(encode_hex(&Sha256::digest(b"the original"))),
                    quarantine: Some(Quarantine {
                        operation: QuarantineKind::RetiredBackup,
                        source: stage.backup_name.to_string_lossy().into_owned(),
                        destination: retired.to_string_lossy().into_owned(),
                        digest: encode_hex(&Sha256::digest(b"the original")),
                        phase: QuarantinePhase::Moved,
                    }),
                },
            )
            .expect("write swap journal");

        let error = recover_interrupted_swap(&stage)
            .expect_err("an object that took the source name is not this run's to interpret");

        assert_eq!(
            error.to_string(),
            "interrupted update conflicts with an unknown local object"
        );
        assert_eq!(
            fs::read(&rollback_path).expect("the independent object is left alone"),
            b"an independent object",
            "an object this run never measured must never be restored or deleted"
        );
        assert!(
            !target_path.exists(),
            "a conflict must not install anything into the target slot"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_whose_directory_sync_failed_is_not_accepted_as_evidence() {
        let directory = UnitTestDir::new("retracted-marker");
        let root = directory.path.join("state").join("gta-claw");
        let syncs = state_tree_sync_points(&root);

        // One past every level: each level is created and synced, and only the
        // marker's own directory sync fails — the step that makes it believable.
        arm_injected_fault_after(InjectedFault::FailNewStateDirectorySync, syncs);
        let error = ensure_directory_tree_durable(&root)
            .expect_err("a marker that is not itself durable is not confirmation");
        disarm_injected_fault();

        assert_eq!(error.to_string(), "update filesystem operation failed");
        assert!(
            !directory_tree_is_confirmed(&root).expect("read marker state"),
            "a marker whose entry was never made durable must not read as confirmation"
        );

        ensure_directory_tree_durable(&root).expect("a later run confirms the tree");
        assert!(directory_tree_is_confirmed(&root).expect("read marker state"));
    }

    #[cfg(unix)]
    #[test]
    fn an_empty_marker_is_treated_as_no_marker() {
        let directory = UnitTestDir::new("empty-marker");
        let root = directory.path.join("state");
        ensure_directory_tree_durable(&root).expect("confirm the tree");
        assert!(directory_tree_is_confirmed(&root).expect("read marker state"));

        fs::write(root.join(DURABLE_MARKER), b"").expect("empty the marker");

        assert!(
            !directory_tree_is_confirmed(&root).expect("read marker state"),
            "an empty marker stands in for 'unconfirmed' and must not be believed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_rollback_restores_the_backup_even_when_the_removal_sync_fails() {
        let directory = UnitTestDir::new("deferred-durability");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create rollback object");
        backup
            .write_all(b"previous install")
            .expect("write rollback object");
        backup.sync_all().expect("sync rollback object");
        drop(backup);
        let mut failed = stage
            .parent
            .open_regular(&stage.target_name, true)
            .expect("create failed replacement");
        failed
            .write_all(b"a failed replacement")
            .expect("write failed replacement");
        failed.sync_all().expect("sync failed replacement");

        // The removal of the failed replacement cannot be made durable. The
        // restore must still happen: leaving the target empty is the one
        // outcome this guard exists to prevent.
        arm_injected_fault(InjectedFault::FailParentSyncDuringRollback);
        let error = rollback_secure_swap(
            &stage,
            true,
            &plain_journal(b"a replacement", Some(b"previous")),
            Some(PlacedTarget { handle: failed }),
            UpdateError::Io(io::Error::other("simulated install failure")),
        );
        disarm_injected_fault();

        assert_eq!(
            fs::read(&target_path).expect("read restored installation"),
            b"previous install",
            "the previous installation must be restored even when a sync failed"
        );
        assert_eq!(
            error.to_string(),
            "update filesystem operation failed",
            "the deferred durability failure is reported once the target is back"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_rolled_back_conflict_keeps_its_type_instead_of_becoming_an_io_error() {
        let directory = UnitTestDir::new("typed-rollback");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create rollback object");
        backup.write_all(b"previous").expect("write rollback object");
        backup.sync_all().expect("sync rollback object");
        drop(backup);

        // A conflict cause must arrive at the caller as a conflict: flattening
        // it into `InstallRolledBack` would hide which failure occurred, and
        // the two carry different guidance.
        let error = rollback_secure_swap(
            &stage,
            true,
            &plain_journal(b"a replacement", Some(b"previous")),
            None,
            UpdateError::SwapRecoveryConflict,
        );

        assert!(
            matches!(error, UpdateError::SwapRecoveryConflict),
            "a typed cause must survive rollback, got: {error}"
        );
        assert_eq!(
            fs::read(&target_path).expect("read restored installation"),
            b"previous",
            "the installation is still restored while the type is preserved"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn a_rolled_back_io_failure_is_reported_as_rolled_back() {
        let directory = UnitTestDir::new("io-rollback");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create rollback object");
        backup.write_all(b"previous").expect("write rollback object");
        backup.sync_all().expect("sync rollback object");
        drop(backup);

        let error = rollback_secure_swap(
            &stage,
            true,
            &plain_journal(b"a replacement", Some(b"previous")),
            None,
            UpdateError::Io(io::Error::other("a genuine io fault")),
        );

        assert_eq!(
            error.to_string(),
            "update installation failed; previous version was restored"
        );
        assert_eq!(
            fs::read(&target_path).expect("read restored installation"),
            b"previous"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn claiming_an_occupied_name_reports_a_conflict_not_a_replacement() {
        let directory = UnitTestDir::new("no-replace-restore");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let mut occupant = stage
            .parent
            .open_regular(&stage.target_name, true)
            .expect("create occupant");
        occupant
            .write_all(b"an independent reinstall")
            .expect("write occupant");
        occupant.sync_all().expect("sync occupant");
        drop(occupant);
        let mut backup = stage
            .parent
            .open_regular(&stage.backup_name, true)
            .expect("create rollback object");
        backup.write_all(b"previous").expect("write rollback object");
        backup.sync_all().expect("sync rollback object");
        drop(backup);

        // The restore cannot happen, and its typed reason is what the caller
        // must see: a conflict, not a stringified rollback failure.
        let error = rollback_secure_swap(
            &stage,
            true,
            &plain_journal(b"a replacement", Some(b"previous")),
            None,
            UpdateError::Io(io::Error::other("an install failure")),
        );

        assert!(
            matches!(error, UpdateError::SwapRecoveryConflict),
            "a blocked restore must report the conflict, got: {error}"
        );
        assert_eq!(
            fs::read(&target_path).expect("read the independent reinstall"),
            b"an independent reinstall",
            "the occupant must survive untouched"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_marker_is_published_empty_before_it_is_believed() {
        let directory = UnitTestDir::new("two-phase-marker");
        let root = directory.path.join("state");
        fs::create_dir(&root).expect("create state directory");

        // The state a crash leaves during the first publication phase: the
        // marker exists and its entry is durable, but it is still empty. The
        // child-process test drives the real fault; this pins the reading.
        let marker = root.join(DURABLE_MARKER);
        fs::write(&marker, b"").expect("write the empty published marker");

        assert!(
            !directory_tree_is_confirmed(&root).expect("read marker state"),
            "an empty marker is the durable 'unconfirmed' state and must not be believed"
        );

        // Finishing publication over the leftover empty marker must work, so an
        // interrupted publication is completed rather than blocking the tree.
        record_directory_tree_confirmed(&root).expect("finish the interrupted publication");
        assert!(directory_tree_is_confirmed(&root).expect("read marker state"));
    }

    #[cfg(not(windows))]
    #[test]
    fn a_failed_fresh_install_removes_the_object_it_placed() {
        let directory = UnitTestDir::new("fresh-partial");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        stage
            .directory
            .write_json_atomic(
                OsStr::new(SWAP_JOURNAL),
                &SwapJournal {
                    phase: SwapPhase::Swapped,
                    recovery_digest: encode_hex(&Sha256::digest(b"replacement")),
                    original_digest: None,
                    quarantine: None,
                },
            )
            .expect("write swap journal");
        let mut partial = stage
            .parent
            .open_regular(&stage.target_name, true)
            .expect("create partial target");
        partial.write_all(b"half a c").expect("write partial target");
        partial.sync_all().expect("sync partial target");

        let error = rollback_secure_swap(
            &stage,
            false,
            &plain_journal(b"a replacement", Some(b"previous")),
            Some(PlacedTarget { handle: partial }),
            UpdateError::Io(io::Error::other("simulated fresh install failure")),
        );

        assert_eq!(error.to_string(), "update filesystem operation failed");
        assert!(
            !target_path.exists(),
            "a fresh install that failed midway must not leave a partial object behind"
        );
        assert!(
            !stage
                .directory
                .object_exists(OsStr::new(SWAP_JOURNAL))
                .expect("journal state")
        );
    }


    #[cfg(windows)]
    #[test]
    fn windows_destination_check_rejects_an_unrelated_parent() {
        let directory = UnitTestDir::new("windows-destination");
        let real_parent = directory.path.join("real");
        let other_parent = directory.path.join("other");
        fs::create_dir(&real_parent).expect("create real parent");
        fs::create_dir(&other_parent).expect("create other parent");
        lock_down_windows_directory(&real_parent).expect("protect real parent");
        lock_down_windows_directory(&other_parent).expect("protect other parent");
        let target = InstallTarget::new(real_parent.join("gta-claw.exe"), InstallMode::Executable)
            .expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        let elsewhere =
            InstallTarget::new(other_parent.join("gta-claw.exe"), InstallMode::Executable)
                .expect("other target");

        let error = stage
            .ensure_verified_destination(&elsewhere)
            .expect_err("an unrelated destination is rejected");
        assert_eq!(
            error.to_string(),
            "verified artifact belongs to a different install target"
        );

        stage
            .ensure_verified_destination(&target)
            .expect("the verified destination is accepted");
    }

    /// The swap must never read the destination out of the caller's argument.
    ///
    /// This is the property that actually protects the install on Windows,
    /// where object identity is unavailable: even a destination check that
    /// answered wrongly could not redirect anything, because every object the
    /// swap touches comes from the staging state built during `download`.
    // The swap only exists where its durability primitives do.
    #[cfg(not(windows))]
    #[test]
    fn the_swap_uses_only_the_staging_state_never_the_callers_path() {
        let directory = UnitTestDir::new("structural-destination");
        let target_path = directory.path.join("gta-claw");
        fs::write(&target_path, b"previous install").expect("write previous install");
        let target =
            InstallTarget::new(target_path.clone(), InstallMode::Executable).expect("target");
        let stage = Arc::new(SecureStaging::open(&target).expect("secure stage"));
        let replacement = b"verified replacement";
        let mut staged = stage
            .directory
            .open_regular(OsStr::new(STAGED_VERIFIED), true)
            .expect("create staged executable");
        staged.write_all(replacement).expect("write staged bytes");
        staged.sync_all().expect("sync staged bytes");
        let prepared = PreparedArtifact {
            path: stage.directory.path.join(STAGED_VERIFIED),
            source_name: OsString::from(STAGED_VERIFIED),
            handle: staged,
            stage: Arc::clone(&stage),
            signed: SignedContent {
                digest: Sha256::digest(replacement).into(),
                size: u64::try_from(replacement.len()).expect("small replacement"),
            },
        };

        // A decoy that a redirected swap would land in.
        let decoy = directory.path.join("decoy");
        fs::create_dir(&decoy).expect("create decoy directory");

        assert_eq!(
            atomic_swap_verified(&prepared, false).expect("swap"),
            InstallOutcome::Installed
        );

        assert_eq!(
            fs::read(&target_path).expect("read installed object"),
            replacement
        );
        assert_eq!(
            fs::read_dir(&decoy).expect("read decoy directory").count(),
            0,
            "the swap must not touch anything outside the staging state"
        );
    }


    // The swap only exists where its durability primitives do.
    #[cfg(not(windows))]
    #[test]
    fn stale_install_contends_with_and_yields_to_a_higher_floor() {
        let directory = UnitTestDir::new("floor-race");
        let updater = Arc::new(
            Updater::with_public_key_and_state(
                PRODUCTION_PUBLIC_KEY,
                "race-target",
                directory.path.join("state"),
            )
            .expect("race updater"),
        );

        for iteration in 0_u64..32 {
            let stale_sequence = iteration * 2 + 1;
            let high_sequence = stale_sequence + 1;
            let replacement = format!("verified replacement {iteration}").into_bytes();
            let artifact = ReleaseArtifact {
                release_sequence: stale_sequence,
                target: "race-target".to_owned(),
                url: "https://updates.example.invalid/gta-claw.exe".to_owned(),
                sha256: encode_hex(&Sha256::digest(&replacement)),
                size: u64::try_from(replacement.len()).expect("small replacement"),
                kind: ArtifactKind::Executable,
            };
            let stale_manifest = ReleaseManifest {
                version: format!("1.0.{stale_sequence}"),
                sequence: stale_sequence,
                published_at_unix: 1_700_000_000,
                expires_at_unix: 4_102_444_800,
                revoked_versions: Vec::new(),
                artifacts: vec![artifact.clone()],
            };
            updater
                .accept_manifest(&stale_manifest)
                .expect("persist stale floor before racing");
            let authorization =
                release_authorization(&stale_manifest, &artifact).expect("authorization");

            let target_path = directory.path.join(format!("gta-claw-{iteration}.exe"));
            fs::write(&target_path, b"known good").expect("write existing target");
            let target = InstallTarget::new(target_path.clone(), InstallMode::Executable)
                .expect("install target");
            let stage = Arc::new(SecureStaging::open(&target).expect("secure stage"));
            let mut staged = stage
                .directory
                .open_regular(OsStr::new(STAGED_VERIFIED), true)
                .expect("create staged replacement");
            staged
                .write_all(&replacement)
                .expect("write staged replacement");
            staged.sync_all().expect("sync staged replacement");
            let verified = VerifiedArtifact {
                path: stage.directory.path.join(STAGED_VERIFIED),
                file: staged,
                stage,
                digest: Sha256::digest(&replacement).into(),
                size: u64::try_from(replacement.len()).expect("small replacement"),
                kind: ArtifactKind::Executable,
                authorization,
            };

            let high_manifest = ReleaseManifest {
                version: format!("1.0.{high_sequence}"),
                sequence: high_sequence,
                published_at_unix: 1_700_000_000,
                expires_at_unix: 4_102_444_800,
                revoked_versions: Vec::new(),
                artifacts: vec![ReleaseArtifact {
                    release_sequence: high_sequence,
                    ..artifact
                }],
            };
            let high_ready = Arc::new(Barrier::new(2));
            let release_high = Arc::new(Barrier::new(2));
            let high_updater = Arc::clone(&updater);
            let high_ready_thread = Arc::clone(&high_ready);
            let release_high_thread = Arc::clone(&release_high);
            let high_thread = std::thread::spawn(move || {
                let guard = high_updater
                    .rollback_lock_for_test()
                    .expect("higher floor lock");
                accept_manifest_locked(&high_manifest, &guard).expect("persist higher floor");
                high_ready_thread.wait();
                release_high_thread.wait();
            });
            high_ready.wait();

            let stale_updater = Arc::clone(&updater);
            let (completed_tx, completed_rx) = mpsc::channel();
            let stale_thread = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("stale installer runtime");
                let result = runtime.block_on(stale_updater.install(verified, &target));
                completed_tx.send(()).expect("report stale completion");
                result
            });
            let completed_while_high_floor_locked =
                completed_rx.recv_timeout(Duration::from_millis(50)).is_ok();
            release_high.wait();
            high_thread.join().expect("higher floor thread");
            let stale_error = stale_thread
                .join()
                .expect("stale installer thread")
                .expect_err("stale install must be rejected");

            assert!(!completed_while_high_floor_locked);
            assert_eq!(
                stale_error.to_string(),
                format!(
                    "signed release sequence {stale_sequence} is below verified floor {high_sequence}"
                )
            );
            assert_eq!(
                fs::read(&target_path).expect("read untouched target"),
                b"known good"
            );
        }
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

    /// Nothing a rerun could resume from survives the discard.
    ///
    /// The verified artifact is the obvious one, but the partial download and
    /// the resume binding matter just as much: either one left behind lets the
    /// next run rebuild a "verified" artifact from bytes that sat on disk while
    /// no updater run held the staging lock.
    #[cfg(not(windows))]
    #[test]
    fn discarding_staging_leaves_nothing_to_resume_from() {
        let directory = UnitTestDir::new("discard-staging");
        let target_path = directory.path.join("gta-claw");
        let target =
            InstallTarget::new(target_path, InstallMode::Executable).expect("target");
        let stage = SecureStaging::open(&target).expect("secure stage");
        for name in [STAGED_VERIFIED, STAGED_PART, RESUME_BINDING] {
            let mut staged = stage
                .directory
                .open_regular(OsStr::new(name), true)
                .expect("create staged artifact");
            staged.write_all(b"resumable").expect("write staged artifact");
            staged.sync_all().expect("sync staged artifact");
        }

        discard_verified_staging(&stage).expect("discard the staging");

        for name in [STAGED_VERIFIED, STAGED_PART, RESUME_BINDING] {
            assert!(
                !stage
                    .directory
                    .object_exists(OsStr::new(name))
                    .expect("staging state"),
                "{name} must not survive a discard"
            );
        }
    }

    /// A locked target reports a restart without naming any staging path.
    ///
    /// The old contract handed the caller the staged pathname so a rerun could
    /// finish from it. That is the hole: whatever can write that name between
    /// the two runs decides what gets installed. The outcome carries no path
    /// now, and the swap leaves the installation untouched.
    #[test]
    fn a_locked_target_reports_a_restart_that_names_no_staging_path() {
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

        assert_eq!(outcome, InstallOutcome::RestartRequired);
        assert_eq!(
            operations.existing.lock().expect("existing lock").clone(),
            BTreeSet::from([target, staged]),
            "a locked target must be left exactly as it was found"
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

    #[test]
    fn debug_output_redacts_download_credentials() {
        let artifact = ReleaseArtifact {
            release_sequence: 7,
            target: "x86_64-test-target".to_owned(),
            url: "https://user:password@updates.invalid/release?token=secret#fragment".to_owned(),
            sha256: "0123456789abcdef".to_owned(),
            size: 4,
            kind: ArtifactKind::Executable,
        };
        assert_eq!(
            format!("{artifact:?}"),
            concat!(
                "ReleaseArtifact { release_sequence: 7, target: \"x86_64-test-target\", ",
                "url: \"<redacted>\", sha256: \"0123456789abcdef\", size: 4, ",
                "kind: Executable }"
            )
        );

        let binding = ResumeBinding {
            target: "trusted-target".to_owned(),
            url: artifact.url.clone(),
            size: artifact.size,
            sha256: artifact.sha256.clone(),
            kind: artifact.kind,
            release_sequence: artifact.release_sequence,
        };
        assert_eq!(
            format!("{binding:?}"),
            concat!(
                "ResumeBinding { target: \"trusted-target\", url: \"<redacted>\", size: 4, ",
                "sha256: \"0123456789abcdef\", kind: Executable, release_sequence: 7 }"
            )
        );

        let envelope = SignedManifest {
            manifest: ReleaseManifest {
                version: "2.0.0".to_owned(),
                sequence: 7,
                published_at_unix: 100,
                expires_at_unix: 200,
                revoked_versions: Vec::new(),
                artifacts: vec![artifact],
            },
            signature: "public-signature".to_owned(),
        };
        assert_eq!(
            format!("{envelope:?}"),
            concat!(
                "SignedManifest { manifest: ReleaseManifest { version: \"2.0.0\", sequence: 7, ",
                "published_at_unix: 100, expires_at_unix: 200, revoked_versions: [], artifacts: ",
                "[ReleaseArtifact { release_sequence: 7, target: \"x86_64-test-target\", ",
                "url: \"<redacted>\", sha256: \"0123456789abcdef\", size: 4, ",
                "kind: Executable }] }, signature: \"public-signature\" }"
            )
        );
    }

    #[tokio::test]
    async fn reqwest_errors_discard_sensitive_request_urls() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind error endpoint");
        let address = listener.local_addr().expect("error endpoint address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept error request");
            drop(stream);
        });
        let error = Client::new()
            .get(format!(
                "http://{address}/release?authorization=secret-query-value"
            ))
            .send()
            .await
            .expect_err("closed connection produces a request error");
        server.await.expect("error endpoint task");

        let UpdateError::Http(error) = redact_http_error(error) else {
            panic!("request error must retain its typed updater variant");
        };
        assert_eq!(error.url(), None);
    }
}

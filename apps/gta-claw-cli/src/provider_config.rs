use std::ffi::OsString;
#[cfg(windows)]
use std::io::Read as _;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::AsyncReadExt as _;
use zeroize::Zeroizing;

use super::{ParseFailure, RenderedResult, option_value, parse_failure};

#[cfg(windows)]
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SELECTION_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Inspect,
    Prepare,
    Apply,
    Restore,
}

impl Mode {
    const fn modifies_source(self) -> bool {
        matches!(self, Self::Apply | Self::Restore)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WritePhase {
    Preflight,
    Candidate,
    #[cfg(windows)]
    Backup,
    Source,
}

impl WritePhase {
    const fn backup_started(self) -> bool {
        match self {
            Self::Source => true,
            #[cfg(windows)]
            Self::Backup => true,
            Self::Preflight | Self::Candidate => false,
        }
    }
}

struct Failure {
    message: &'static str,
    phase: WritePhase,
}

impl Failure {
    const fn preflight(message: &'static str) -> Self {
        Self {
            message,
            phase: WritePhase::Preflight,
        }
    }
}

pub(super) struct ProviderConfigCommand {
    mode: Mode,
    source: PathBuf,
    destination: Option<PathBuf>,
    expected_sha256: Option<String>,
    candidate: Option<PathBuf>,
    backup: Option<PathBuf>,
    candidate_sha256: Option<String>,
    model: Option<String>,
}

pub(super) fn parse(arguments: &[OsString]) -> Result<ProviderConfigCommand, ParseFailure> {
    let invalid = || {
        parse_failure(
            "invalid config provider command; use inspect, prepare, apply or restore with explicit local paths",
            arguments,
        )
    };
    if arguments.get(1).and_then(|value| value.to_str()) != Some("provider") {
        return Err(invalid());
    }
    let mode = match arguments.get(2).and_then(|value| value.to_str()) {
        Some("inspect") => Mode::Inspect,
        Some("prepare") => Mode::Prepare,
        Some("apply") => Mode::Apply,
        Some("restore") => Mode::Restore,
        _ => return Err(invalid()),
    };
    let mut source = None;
    let mut destination = None;
    let mut expected_sha256 = None;
    let mut candidate = None;
    let mut backup = None;
    let mut candidate_sha256 = None;
    let mut confirm_apply = false;
    let mut confirm_offline = false;
    let mut model = None;
    let mut selection_stdin = false;
    let mut json_seen = false;
    let mut index = 3;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--source" | "--destination" | "--candidate" | "--backup") => {
                let target = match arguments[index].to_str() {
                    Some("--source") => &mut source,
                    Some("--destination") if mode == Mode::Prepare => &mut destination,
                    Some("--candidate") if mode.modifies_source() => &mut candidate,
                    Some("--backup") if mode.modifies_source() => &mut backup,
                    _ => return Err(invalid()),
                };
                if target.is_some() {
                    return Err(invalid());
                }
                index += 1;
                let path = PathBuf::from(option_value(
                    arguments,
                    index,
                    "missing configuration path",
                )?);
                if !super::state_snapshot::local_absolute(&path) {
                    return Err(invalid());
                }
                *target = Some(path);
            }
            Some("--expected-sha256" | "--candidate-sha256") if mode != Mode::Inspect => {
                let target = match arguments[index].to_str() {
                    Some("--expected-sha256") => &mut expected_sha256,
                    Some("--candidate-sha256") if mode.modifies_source() => &mut candidate_sha256,
                    _ => return Err(invalid()),
                };
                if target.is_some() {
                    return Err(invalid());
                }
                index += 1;
                let value = option_value(arguments, index, "missing source SHA256")?
                    .to_str()
                    .ok_or_else(invalid)?;
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(invalid());
                }
                *target = Some(value.to_owned());
            }
            Some("--selection-stdin") if mode == Mode::Prepare && !selection_stdin => {
                selection_stdin = true;
            }
            Some("--model") if mode == Mode::Prepare && model.is_none() => {
                index += 1;
                let value = option_value(arguments, index, "missing exact model ID")?
                    .to_str()
                    .ok_or_else(invalid)?;
                if value.is_empty()
                    || value.len() > 256
                    || value
                        .chars()
                        .any(|character| character.is_control() || character.is_whitespace())
                {
                    return Err(invalid());
                }
                model = Some(value.to_owned());
            }
            Some("--confirm-apply") if mode == Mode::Apply && !confirm_apply => {
                confirm_apply = true;
            }
            Some("--confirm-restore") if mode == Mode::Restore && !confirm_apply => {
                confirm_apply = true;
            }
            Some("--confirm-offline") if mode.modifies_source() && !confirm_offline => {
                confirm_offline = true;
            }
            Some("--json") if !json_seen => json_seen = true,
            _ => return Err(invalid()),
        }
        index += 1;
    }
    let source = source.ok_or_else(invalid)?;
    if mode == Mode::Prepare
        && (selection_stdin == model.is_some()
            || expected_sha256.is_none()
            || destination.is_none())
        || mode.modifies_source()
            && (!confirm_apply
                || !confirm_offline
                || candidate.is_none()
                || backup.is_none()
                || expected_sha256.is_none()
                || candidate_sha256.is_none())
        || destination.as_ref() == Some(&source)
        || candidate.as_ref() == Some(&source)
        || backup.as_ref() == Some(&source)
        || candidate
            .as_ref()
            .is_some_and(|path| backup.as_ref() == Some(path))
    {
        return Err(invalid());
    }
    Ok(ProviderConfigCommand {
        mode,
        source,
        destination,
        expected_sha256,
        candidate,
        backup,
        candidate_sha256,
        model,
    })
}

#[cfg(windows)]
fn sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut digest = String::with_capacity(64);
    for byte in ring::digest::digest(&ring::digest::SHA256, bytes).as_ref() {
        write!(digest, "{byte:02x}").expect("bounded digest");
    }
    digest
}

fn provider_summary(config: &claw_config::ConfigSnapshot) -> Value {
    config.core().provider().map_or(Value::Null, |provider| json!({
        "kind":provider.kind(),"model":provider.model(),"baseUrl":provider.base_url(),
        "credentialOrigin":provider.credential_origin(),"apiKeyConfigured":provider.api_key().is_some(),
        "requestTimeoutMs":provider.request_timeout_ms(),"completionApi":provider.completion_api(),
        "catalogueMaxAgeMs":provider.catalogue_max_age_ms(),
        "maxObservedTurnTokens":provider.max_observed_turn_tokens(),
    }))
}

fn perform(command: &ProviderConfigCommand, selection: Option<&[u8]>) -> Result<Value, Failure> {
    let early = Failure::preflight;
    if command.mode.modifies_source() {
        return apply_candidate(command);
    }
    let failed = |error: claw_platform::configuration::ConfigurationFileError| Failure {
        message: error.message,
        phase: if error.output_may_exist {
            WritePhase::Candidate
        } else {
            WritePhase::Preflight
        },
    };
    let (digest, snapshot, candidate_digest) = if command.mode == Mode::Inspect {
        let source =
            claw_platform::configuration::inspect_provider(&command.source).map_err(failed)?;
        (source.source_sha256, source.snapshot, None)
    } else {
        let edit = if let Some(model) = &command.model {
            claw_platform::configuration::ProviderEdit::ExactModel(model)
        } else {
            claw_platform::configuration::ProviderEdit::SelectionJson(
                std::str::from_utf8(
                    selection.ok_or_else(|| early("provider selection input is missing"))?,
                )
                .map_err(|_| early("provider selection input must be UTF-8"))?,
            )
        };
        let candidate = claw_platform::configuration::prepare_provider(
            &command.source,
            command.destination.as_ref().expect("parsed destination"),
            command
                .expected_sha256
                .as_deref()
                .expect("parsed source digest"),
            edit,
        )
        .map_err(failed)?;
        (
            candidate.source_sha256,
            candidate.snapshot,
            Some(candidate.candidate_sha256),
        )
    };
    let mut receipt = json!({"sourceSha256":digest,"selection":provider_summary(&snapshot),"sourceModified":false,
        "environmentApplied":false,"credentialsResolved":false,"credentialReferencesIncluded":false,
        "networkContacted":false,"applied":false,"liveReadinessVerified":false,"fileCreated":false,
        "automaticRetry":false,"directoryDurabilityVerified":false});
    if command.mode == Mode::Inspect {
        return Ok(receipt);
    }
    receipt["candidateSha256"] = json!(candidate_digest.expect("prepared file digest"));
    receipt["restartRequired"] = json!(true);
    receipt["plaintextReferences"] = json!(true);
    receipt["catalogueVerified"] = json!(false);
    receipt["modelOnly"] = json!(command.model.is_some());
    receipt["fileCreated"] = json!(true);
    Ok(receipt)
}

#[cfg(not(windows))]
fn apply_candidate(command: &ProviderConfigCommand) -> Result<Value, Failure> {
    let _ = (
        &command.candidate,
        &command.backup,
        &command.candidate_sha256,
    );
    Err(Failure::preflight(
        "protected configuration application is currently supported only on Windows; no file was changed",
    ))
}

#[cfg(windows)]
fn read_held_file(file: &mut std::fs::File) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    use std::io::Seek as _;
    if file
        .metadata()
        .map_err(|_| "configuration metadata is unavailable")?
        .len()
        > MAX_CONFIG_BYTES
    {
        return Err("configuration exceeds 4 MiB");
    }
    file.rewind()
        .map_err(|_| "configuration could not be rewound")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "configuration read did not complete")?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("configuration exceeds 4 MiB");
    }
    Ok(bytes)
}

#[cfg(windows)]
trait ConfigFile: std::io::Read + std::io::Write + std::io::Seek {
    fn sync_contents(&mut self) -> std::io::Result<()>;
    fn set_length(&mut self, length: u64) -> std::io::Result<()>;
}

#[cfg(windows)]
impl ConfigFile for std::fs::File {
    fn sync_contents(&mut self) -> std::io::Result<()> {
        self.sync_all()
    }
    fn set_length(&mut self, length: u64) -> std::io::Result<()> {
        self.set_len(length)
    }
}

#[cfg(windows)]
fn write_verified(file: &mut impl ConfigFile, bytes: &[u8]) -> Result<(), &'static str> {
    file.rewind()
        .map_err(|_| "file positioning was not confirmed")?;
    file.write_all(bytes)
        .map_err(|_| "file write did not complete")?;
    file.set_length(bytes.len() as u64)
        .map_err(|_| "file length update was not confirmed")?;
    file.sync_contents()
        .map_err(|_| "file synchronization was not confirmed")?;
    file.rewind()
        .map_err(|_| "file readback positioning was not confirmed")?;
    let mut observed = Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut observed)
        .map_err(|_| "file readback failed")?;
    if observed.as_slice() != bytes {
        return Err("file readback did not match the reviewed bytes");
    }
    Ok(())
}

#[cfg(windows)]
fn save_after_backup(
    source: &mut impl ConfigFile,
    backup: &mut impl ConfigFile,
    original: &[u8],
    candidate: &[u8],
    before_source_write: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), Failure> {
    let backup_failed = |message| Failure {
        message,
        phase: WritePhase::Backup,
    };
    write_verified(backup, original).map_err(backup_failed)?;
    before_source_write().map_err(backup_failed)?;
    write_verified(source, candidate).map_err(|message| Failure {
        message,
        phase: WritePhase::Source,
    })
}

#[cfg(windows)]
fn apply_candidate(command: &ProviderConfigCommand) -> Result<Value, Failure> {
    let early = Failure::preflight;
    let (source_root, source_path) =
        super::state_snapshot::pinned_parent(&command.source).map_err(early)?;
    let source_resolved = source_root
        .resolve_file(&source_path)
        .map_err(|_| early("configuration source is absent or unsafe"))?;
    let mut source_file = source_root.open_existing_exclusive(&source_resolved)
        .map_err(|_| early("configuration source is read-only, unsafe or in use; stop its readers and writers before applying"))?;
    let (candidate_root, candidate_path) =
        super::state_snapshot::pinned_parent(command.candidate.as_ref().expect("parsed candidate"))
            .map_err(early)?;
    let candidate_resolved = candidate_root
        .resolve_file(&candidate_path)
        .map_err(|_| early("candidate configuration is absent or unsafe"))?;
    let mut candidate_file = candidate_root
        .open_read_exclusive(&candidate_resolved)
        .map_err(|_| early("candidate configuration is unsafe or in use"))?;
    let source_bytes = read_held_file(&mut source_file).map_err(early)?;
    let candidate_bytes = read_held_file(&mut candidate_file).map_err(early)?;
    let source_sha256 = sha256(&source_bytes);
    let candidate_sha256 = sha256(&candidate_bytes);
    if command.expected_sha256.as_deref() != Some(&source_sha256)
        || command.candidate_sha256.as_deref() != Some(&candidate_sha256)
    {
        return Err(early(
            "source or candidate SHA256 changed; review both files before applying",
        ));
    }
    let candidate_text =
        std::str::from_utf8(&candidate_bytes).map_err(|_| early("candidate must be UTF-8"))?;
    let candidate = claw_config::parse_json5(candidate_text, "<provider-config-candidate>")
        .map_err(|_| early("candidate configuration does not match the validated native schema"))?;
    if command.mode == Mode::Apply {
        let original = claw_config::parse_json5(std::str::from_utf8(&source_bytes).map_err(|_| early("source must be UTF-8"))?, "<provider-config-source>")
            .map_err(|_| early("source configuration is invalid; use reviewed restore instead of provider-only application"))?;
        let mut review = claw_config::ReloadManager::new(original);
        let change = review
            .reload_json5(candidate_text, "<provider-config-candidate>")
            .map_err(|_| {
                early("candidate configuration does not match the validated native schema")
            })?;
        if change.changed_domains.as_slice() != [claw_config::ConfigDomain::Provider] {
            return Err(early(
                "application requires a provider-only configuration change; unrelated settings and unchanged selections are refused",
            ));
        }
    }
    let (backup_root, backup_path) =
        super::state_snapshot::pinned_parent(command.backup.as_ref().expect("parsed backup"))
            .map_err(early)?;
    source_root
        .validate_root()
        .map_err(|_| early("source directory changed"))?;
    candidate_root
        .validate_root()
        .map_err(|_| early("candidate directory changed"))?;
    let mut backup_file = backup_root
        .create_new_exclusive_file(&backup_path)
        .map_err(|_| {
            early("backup exists or cannot be created safely; choose a new backup path")
        })?;
    save_after_backup(
        &mut source_file,
        &mut backup_file,
        &source_bytes,
        &candidate_bytes,
        || {
            backup_root
                .validate_root()
                .map_err(|_| "backup directory changed; source was not modified")?;
            source_root
                .validate_root()
                .map_err(|_| "source directory changed before write")?;
            candidate_root
                .validate_root()
                .map_err(|_| "candidate directory changed before write")
        },
    )?;
    let source_failed = |message| Failure {
        message,
        phase: WritePhase::Source,
    };
    source_root
        .validate_root()
        .map_err(|_| source_failed("source directory changed after write"))?;
    backup_root
        .validate_root()
        .map_err(|_| source_failed("backup directory changed after write"))?;
    Ok(
        json!({"sourceSha256":source_sha256,"candidateSha256":candidate_sha256,"savedSha256":candidate_sha256,
        "backupSha256":source_sha256,"selection":provider_summary(&candidate),"sourceModified":true,
        "sourceMayHaveChanged":true,"configurationSaved":true,"backupCreated":true,"backupVerified":true,
        "candidateModified":false,"environmentApplied":false,"credentialsResolved":false,"credentialReferencesIncluded":false,
        "networkContacted":false,"applied":false,"liveReadinessVerified":false,"restartRequired":true,"restartPerformed":false,
        "atomicPublication":false,"fileCreated":true,"automaticRetry":false,"automaticRollback":false,
        "offlineConfirmed":true,"offlineIndependentlyVerified":false,"fullSnapshotRestored":command.mode == Mode::Restore,
        "plaintextReferences":true,"directoryDurabilityVerified":false}),
    )
}

pub(super) async fn run(command: ProviderConfigCommand) -> RenderedResult {
    let mode = command.mode;
    let method = match command.mode {
        Mode::Inspect => "config.provider.inspect",
        Mode::Prepare => "config.provider.prepare",
        Mode::Apply => "config.provider.apply",
        Mode::Restore => "config.provider.restore",
    };
    let operation = async {
        let selection = if command.mode == Mode::Prepare && command.model.is_none() {
            let mut bytes = Zeroizing::new(Vec::new());
            let input = tokio::time::timeout(
                Duration::from_secs(30),
                tokio::io::stdin()
                    .take(MAX_SELECTION_BYTES + 1)
                    .read_to_end(&mut bytes),
            )
            .await;
            if !matches!(input, Ok(Ok(_))) || bytes.len() as u64 > MAX_SELECTION_BYTES {
                return Err(Failure::preflight(
                    "provider selection must end within 30 seconds and 16 KiB",
                ));
            }
            Some(bytes)
        } else {
            None
        };
        tokio::task::spawn_blocking(move || {
            perform(&command, selection.as_ref().map(|bytes| bytes.as_slice()))
        })
        .await
        .map_err(|_| Failure {
            message: "configuration task ended without a confirmed result; preserve source, candidate and any backup",
            phase: match mode { Mode::Inspect => WritePhase::Preflight, Mode::Prepare => WritePhase::Candidate, Mode::Apply | Mode::Restore => WritePhase::Source },
        })?
    };
    let (exit_code, mut document) = match operation.await {
        Ok(value) => (0, value),
        Err(Failure { message, phase }) => (
            2,
            json!({"ok":false,"message":message,"targetMayExist":!matches!(phase,WritePhase::Preflight),
            "sourceModified":if matches!(phase,WritePhase::Source) {Value::Null} else {json!(false)},
            "sourceMayHaveChanged":matches!(phase,WritePhase::Source),"backupMayHaveBeenCreated":phase.backup_started(),
            "backupMayExist":mode.modifies_source(),"preserveRecoveryFiles":mode.modifies_source(),
            "configurationSaved":false,"candidateModified":false,"environmentApplied":false,"credentialsResolved":false,
            "networkContacted":false,"applied":false,"automaticRetry":false,"automaticRollback":false}),
        ),
    };
    document["schema_version"] = json!(1);
    document["method"] = json!(method);
    document["ok"] = json!(exit_code == 0);
    RenderedResult {
        exit_code,
        stdout: format!("{document}\n"),
        stderr: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    #[ignore = "isolated child process invoked by the maintenance recovery test"]
    fn provider_config_interruption_child() {
        use std::io::{self, Read, Seek, SeekFrom, Write};
        struct InterruptedFile {
            file: std::fs::File,
            stage: String,
        }
        impl Read for InterruptedFile {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                Read::read(&mut self.file, bytes)
            }
        }
        impl Write for InterruptedFile {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.stage == "partial-source" {
                    self.file.write_all(&bytes[..bytes.len().min(12)])?;
                    self.file.sync_all()?;
                    std::process::exit(42);
                }
                self.file.write(bytes)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.file.flush()
            }
        }
        impl Seek for InterruptedFile {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                self.file.seek(position)
            }
        }
        impl ConfigFile for InterruptedFile {
            fn set_length(&mut self, length: u64) -> io::Result<()> {
                self.file.set_len(length)
            }
            fn sync_contents(&mut self) -> io::Result<()> {
                self.file.sync_all()?;
                if self.stage == "synced-source" {
                    std::process::exit(43);
                }
                Ok(())
            }
        }
        let root = PathBuf::from(
            std::env::var_os("GTA_CLAW_TEST_CONFIG_APPLY_ROOT").expect("parent-owned root"),
        );
        let stage = std::env::var("GTA_CLAW_TEST_CONFIG_APPLY_STAGE").expect("parent-owned stage");
        let (sandbox, relative) =
            super::super::state_snapshot::pinned_parent(&root.join("source.json5"))
                .expect("pinned source");
        let source = sandbox.resolve_file(&relative).expect("source");
        let mut source = InterruptedFile {
            file: sandbox
                .open_existing_exclusive(&source)
                .expect("exclusive source"),
            stage: stage.clone(),
        };
        let mut original = Zeroizing::new(Vec::new());
        Read::read_to_end(&mut source, &mut original).expect("source read");
        let candidate_relative = sandbox.relative("candidate.json5").expect("candidate path");
        let candidate_resolved = sandbox
            .resolve_file(&candidate_relative)
            .expect("candidate");
        let mut candidate_file = sandbox
            .open_read_exclusive(&candidate_resolved)
            .expect("exclusive candidate");
        let candidate = read_held_file(&mut candidate_file).expect("candidate read");
        let mut backup = sandbox
            .create_new_exclusive_file(&sandbox.relative("backup.json5").expect("backup path"))
            .expect("exclusive backup");
        let result = save_after_backup(&mut source, &mut backup, &original, &candidate, || {
            if stage == "backup-ready" {
                std::process::exit(41);
            }
            Ok(())
        });
        assert!(result.is_ok());
        panic!("child should have exited at its owned boundary");
    }

    #[cfg(windows)]
    #[test]
    fn provider_config_process_interruptions_keep_exact_backup_and_support_reviewed_restore() {
        struct OwnedRoot(PathBuf);
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = OwnedRoot(std::env::temp_dir().join(format!(
                "claw-config-interrupt-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned root");
        let initial = claw_config::ConfigLayers::new()
            .with_workspace_json5(
                json!({"core":{"role":{"source_url":"http://127.0.0.1:9/role"},
            "channels":{"teams":{"enabled":false}},"provider":{"kind":"disabled"}}})
                .to_string(),
            )
            .resolve()
            .expect("initial")
            .config;
        let changed = claw_config::with_provider_json(
            &initial,
            r#"{"kind":"openai","model":"new-model","api_key":"env:TEST_NOT_RESOLVED"}"#,
        )
        .expect("candidate");
        let original = format!(
            "/* original source identity */\n{}",
            claw_config::to_json5(&initial).expect("original config")
        );
        let candidate = claw_config::to_json5(&changed).expect("candidate config");
        for (stage, exit) in [
            ("backup-ready", 41),
            ("partial-source", 42),
            ("synced-source", 43),
        ] {
            let directory = root.0.join(stage);
            std::fs::create_dir(&directory).expect("case directory");
            std::fs::write(directory.join("source.json5"), &original).expect("source");
            std::fs::write(directory.join("candidate.json5"), &candidate).expect("candidate");
            let output =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--ignored",
                        "--exact",
                        "provider_config::tests::provider_config_interruption_child",
                    ])
                    .env("GTA_CLAW_TEST_CONFIG_APPLY_ROOT", &directory)
                    .env("GTA_CLAW_TEST_CONFIG_APPLY_STAGE", stage)
                    .output()
                    .expect("isolated maintenance child");
            assert_eq!(output.status.code(), Some(exit), "{stage}");
            let backup =
                std::fs::read(directory.join("backup.json5")).expect("durable original backup");
            let residue = std::fs::read(directory.join("source.json5")).expect("retained residue");
            assert_eq!(backup, original.as_bytes());
            match stage {
                "backup-ready" => assert_eq!(residue, original.as_bytes()),
                "synced-source" => assert_eq!(residue, candidate.as_bytes()),
                _ => {
                    assert_ne!(residue, original.as_bytes());
                    assert_ne!(residue, candidate.as_bytes());
                }
            }
            let command = ProviderConfigCommand {
                mode: Mode::Restore,
                source: directory.join("source.json5"),
                destination: None,
                expected_sha256: Some(sha256(&residue)),
                candidate: Some(directory.join("backup.json5")),
                backup: Some(directory.join("residue.json5")),
                candidate_sha256: Some(sha256(&backup)),
                model: None,
            };
            let receipt = perform(&command, None)
                .unwrap_or_else(|failure| panic!("restore failed: {}", failure.message));
            assert_eq!(receipt["fullSnapshotRestored"], true);
            assert_eq!(receipt["applied"], false);
            assert_eq!(
                std::fs::read(directory.join("source.json5")).expect("restored"),
                original.as_bytes()
            );
            assert_eq!(
                std::fs::read(directory.join("residue.json5")).expect("preserved residue"),
                residue
            );
            assert_eq!(
                std::fs::read(directory.join("backup.json5")).expect("original backup untouched"),
                backup
            );
            assert_eq!(
                std::fs::read(directory.join("candidate.json5")).expect("candidate untouched"),
                candidate.as_bytes()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn provider_config_write_failures_preserve_backup_and_report_source_uncertainty() {
        use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
        struct FaultFile {
            cursor: Cursor<Vec<u8>>,
            fault: &'static str,
            written: usize,
            synced: bool,
        }
        impl FaultFile {
            fn new(bytes: &[u8], fault: &'static str) -> Self {
                Self {
                    cursor: Cursor::new(bytes.to_vec()),
                    fault,
                    written: 0,
                    synced: false,
                }
            }
        }
        impl Read for FaultFile {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if self.synced && self.fault == "read-error" {
                    return Err(io::Error::other("injected read failure"));
                }
                let read = Read::read(&mut self.cursor, bytes)?;
                if self.synced && self.fault == "read-changed" && read > 0 {
                    bytes[0] ^= 1;
                }
                Ok(read)
            }
        }
        impl Write for FaultFile {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.fault == "short-write" && self.written > 0 {
                    return Err(io::Error::other("injected short write"));
                }
                let count = if self.fault == "short-write" {
                    bytes.len().min(2)
                } else {
                    bytes.len()
                };
                let written = self.cursor.write(&bytes[..count])?;
                self.written += written;
                Ok(written)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl Seek for FaultFile {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                self.cursor.seek(position)
            }
        }
        impl ConfigFile for FaultFile {
            fn sync_contents(&mut self) -> io::Result<()> {
                self.synced = true;
                if self.fault == "sync" {
                    Err(io::Error::other("injected sync failure"))
                } else {
                    Ok(())
                }
            }
            fn set_length(&mut self, length: u64) -> io::Result<()> {
                if self.fault == "length" {
                    return Err(io::Error::other("injected length failure"));
                }
                self.cursor
                    .get_mut()
                    .resize(usize::try_from(length).expect("bounded fixture"), 0);
                Ok(())
            }
        }
        for stage in ["backup", "source"] {
            for fault in [
                "short-write",
                "length",
                "sync",
                "read-error",
                "read-changed",
            ] {
                let mut source = FaultFile::new(
                    b"original-source",
                    if stage == "source" { fault } else { "none" },
                );
                let mut backup =
                    FaultFile::new(b"", if stage == "backup" { fault } else { "none" });
                let error = save_after_backup(
                    &mut source,
                    &mut backup,
                    b"original-source",
                    b"new-candidate",
                    || Ok(()),
                )
                .expect_err("injected failure");
                if stage == "backup" {
                    assert_eq!(error.phase, WritePhase::Backup);
                    assert_eq!(source.written, 0);
                    assert_eq!(source.cursor.get_ref(), b"original-source");
                } else {
                    assert_eq!(error.phase, WritePhase::Source);
                    assert!(source.written > 0);
                    assert_eq!(backup.cursor.get_ref(), b"original-source");
                    assert!(backup.synced);
                }
            }
        }
        let mut source = FaultFile::new(b"original-source", "none");
        let mut backup = FaultFile::new(b"", "none");
        let error = save_after_backup(
            &mut source,
            &mut backup,
            b"original-source",
            b"new-candidate",
            || Err("changed pinned input"),
        )
        .expect_err("pre-write failure");
        assert_eq!(error.phase, WritePhase::Backup);
        assert_eq!(source.written, 0);
        assert!(backup.synced);
        assert_eq!(backup.cursor.get_ref(), b"original-source");
    }

    #[test]
    fn provider_config_apply_requires_two_digests_backup_and_explicit_confirmation() {
        let root = std::env::temp_dir();
        let arguments: Vec<OsString> = vec![
            "config".into(),
            "provider".into(),
            "apply".into(),
            "--source".into(),
            root.join("source.json5").into_os_string(),
            "--candidate".into(),
            root.join("candidate.json5").into_os_string(),
            "--backup".into(),
            root.join("source.backup.json5").into_os_string(),
            "--expected-sha256".into(),
            "a".repeat(64).into(),
            "--candidate-sha256".into(),
            "b".repeat(64).into(),
            "--confirm-apply".into(),
            "--confirm-offline".into(),
        ];
        assert!(
            parse(&arguments).is_ok(),
            "a reviewed local apply must be accepted"
        );
        assert!(
            parse(&arguments[..14]).is_err(),
            "offline maintenance confirmation is mandatory"
        );
        assert!(
            parse(&arguments[..13]).is_err(),
            "confirmation is mandatory"
        );
        for position in [3, 5, 7, 9, 11] {
            let mut missing = arguments.clone();
            missing.drain(position..position + 2);
            assert!(parse(&missing).is_err(), "missing flag at {position}");
        }
        for position in [4, 6, 8] {
            let mut relative = arguments.clone();
            relative[position] = "relative.json5".into();
            assert!(parse(&relative).is_err(), "relative path at {position}");
        }
        for (left, right) in [(4, 6), (4, 8), (6, 8)] {
            let mut aliases = arguments.clone();
            aliases[right] = aliases[left].clone();
            assert!(parse(&aliases).is_err(), "paths must be distinct");
        }
        for extras in [
            vec!["--confirm-apply"],
            vec!["--confirm-offline"],
            vec!["--confirm-restore"],
            vec!["--selection-stdin"],
            vec!["--overwrite"],
            vec!["--candidate-sha256", &"c".repeat(64)],
        ] {
            let mut duplicate = arguments.clone();
            duplicate.extend(extras.into_iter().map(OsString::from));
            assert!(parse(&duplicate).is_err());
        }
        let mut restore = arguments;
        restore[2] = "restore".into();
        assert!(
            parse(&restore).is_err(),
            "restore needs a separate confirmation"
        );
        restore[13] = "--confirm-restore".into();
        assert!(parse(&restore).is_ok());
    }

    #[test]
    fn provider_config_commands_require_local_paths_explicit_digest_and_stdin_selection() {
        let source = std::env::temp_dir().join("source.json5");
        let destination = std::env::temp_dir().join("candidate.json5");
        let base = vec![
            "config".into(),
            "provider".into(),
            "prepare".into(),
            "--source".into(),
            source.into_os_string(),
            "--destination".into(),
            destination.into_os_string(),
            "--expected-sha256".into(),
            "a".repeat(64).into(),
            "--selection-stdin".into(),
        ];
        assert!(parse(&base).is_ok());
        assert!(parse(&base[..9]).is_err());
        let mut model = base[..9].to_vec();
        model.extend(["--model".into(), "Exact-Model:2026-09".into()]);
        assert!(parse(&model).is_ok());
        let mut mixed = model.clone();
        mixed.push("--selection-stdin".into());
        assert!(parse(&mixed).is_err());
        let mut repeated = model.clone();
        repeated.extend(["--model".into(), "other".into()]);
        assert!(parse(&repeated).is_err());
        for invalid in ["", "two models", &"m".repeat(257)] {
            model[10] = invalid.into();
            assert!(parse(&model).is_err());
        }
        for extra in [
            vec!["--selection-stdin"],
            vec!["--overwrite"],
            vec!["--token-stdin"],
            vec!["--endpoint", "https://example.test"],
        ] {
            let mut invalid = base.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid).is_err());
        }
        let mut relative = base.clone();
        relative[4] = "relative.json5".into();
        assert!(parse(&relative).is_err());
        let mut same = base;
        same[6] = same[4].clone();
        assert!(parse(&same).is_err());
    }
}

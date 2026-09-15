//! Explicit offline encrypted state snapshots; no record contents or secrets on stdout.

use std::ffi::OsString;
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use claw_state::{SnapshotReceipt, StateDatabase};
use claw_tools::sandbox::{RelativePath, Sandbox, SandboxLimits};
use serde_json::json;
use tokio::io::AsyncReadExt as _;
use zeroize::Zeroizing;

use super::{ParseFailure, RenderedResult, parse_failure};

const MAX_ENCRYPTED_BYTES: u64 = 272 * 1024 * 1024;
const SCRYPT_WORK_FACTOR: u8 = 18;

#[derive(Clone, Copy)]
enum Mode {
    Export,
    Restore,
}

pub(super) struct SnapshotCommand {
    mode: Mode,
    source: PathBuf,
    destination: PathBuf,
}

pub(super) fn parse(arguments: &[OsString]) -> Result<SnapshotCommand, ParseFailure> {
    let invalid = || {
        parse_failure(
            "expected state snapshot <export|restore> --source <absolute-file> --destination <new-absolute-file> --passphrase-stdin",
            arguments,
        )
    };
    if arguments.get(1).and_then(|value| value.to_str()) != Some("snapshot") {
        return Err(invalid());
    }
    let mode = match arguments.get(2).and_then(|value| value.to_str()) {
        Some("export") => Mode::Export,
        Some("restore") => Mode::Restore,
        _ => return Err(invalid()),
    };
    let mut source = None;
    let mut destination = None;
    let mut stdin = false;
    let mut index = 3;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--json") => index += 1,
            Some("--passphrase-stdin") if !stdin => {
                stdin = true;
                index += 1;
            }
            Some("--source") if source.is_none() => {
                source = arguments.get(index + 1).map(PathBuf::from);
                index += 2;
            }
            Some("--destination") if destination.is_none() => {
                destination = arguments.get(index + 1).map(PathBuf::from);
                index += 2;
            }
            _ => return Err(invalid()),
        }
    }
    let source = source
        .filter(|path| local_absolute(path))
        .ok_or_else(invalid)?;
    let destination = destination
        .filter(|path| local_absolute(path))
        .ok_or_else(invalid)?;
    if !stdin || source == destination {
        return Err(invalid());
    }
    Ok(SnapshotCommand {
        mode,
        source,
        destination,
    })
}

pub(super) fn local_absolute(path: &Path) -> bool {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    #[cfg(windows)]
    if !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)))
    {
        return false;
    }
    true
}

fn pinned_parent(path: &Path) -> Result<(Sandbox, RelativePath), &'static str> {
    if !local_absolute(path) {
        return Err("snapshot paths must be explicit local absolute files");
    }
    let parent = path.parent().ok_or("snapshot parent is unavailable")?;
    let sandbox = Sandbox::new_pinned(
        parent,
        SandboxLimits {
            max_file_bytes: MAX_ENCRYPTED_BYTES,
            ..SandboxLimits::default()
        },
    )
    .map_err(|_| "snapshot parent could not be pinned safely")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("snapshot filename must be UTF-8")?;
    let relative = sandbox
        .relative(name)
        .map_err(|_| "snapshot filename violates local path policy")?;
    Ok((sandbox, relative))
}

fn perform(
    command: &SnapshotCommand,
    passphrase: age::secrecy::SecretString,
) -> Result<SnapshotReceipt, &'static str> {
    let (source_root, source_path) = pinned_parent(&command.source)?;
    let (destination_root, destination_path) = pinned_parent(&command.destination)?;
    let resolved = source_root
        .resolve_file(&source_path)
        .map_err(|_| "snapshot source is absent or unsafe")?;
    let receipt = match command.mode {
        Mode::Export => {
            let source = source_root.open_existing_for_update(&resolved).map_err(
                |_| "source state file cannot be opened safely; stop its owner before exporting",
            )?;
            let database = StateDatabase::from_existing_file(source).map_err(|_| "source database is locked, invalid or incompatible; no empty fallback was used")?;
            let mut recipient = age::scrypt::Recipient::new(passphrase);
            recipient.set_work_factor(SCRYPT_WORK_FACTOR);
            let encryptor =
                age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                    .map_err(|_| "snapshot encryption could not be initialized")?;
            let file = destination_root
                .create_new_file(&destination_path)
                .map_err(|_| "snapshot destination exists or cannot be created safely")?;
            let mut encrypted = encryptor.wrap_output(file).map_err(
                |_| "snapshot encryption output failed; retain any partial target for inspection",
            )?;
            let receipt = database.export_snapshot(&mut encrypted).map_err(
                |_| "state snapshot was not completed; partial encrypted output is not a backup",
            )?;
            let file = encrypted
                .finish()
                .map_err(|_| "encrypted snapshot finalization failed; output is not confirmed")?;
            file.sync_all().map_err(
                |_| "snapshot file synchronization failed; output must be verified before use",
            )?;
            receipt
        }
        Mode::Restore => {
            let source = source_root
                .open_no_follow(&resolved)
                .map_err(|_| "encrypted snapshot source is unsafe")?;
            if source
                .metadata()
                .map_err(|_| "snapshot source metadata is unavailable")?
                .len()
                > MAX_ENCRYPTED_BYTES
            {
                return Err("encrypted snapshot exceeds its byte limit");
            }
            let decryptor = age::Decryptor::new(source.take(MAX_ENCRYPTED_BYTES + 1))
                .map_err(|_| "encrypted snapshot header is invalid")?;
            let mut identity = age::scrypt::Identity::new(passphrase);
            identity.set_max_work_factor(SCRYPT_WORK_FACTOR);
            let decrypted = decryptor
                .decrypt(std::iter::once(&identity as &dyn age::Identity))
                .map_err(|_| "snapshot passphrase or encryption header was refused")?;
            let file = destination_root
                .create_new_file(&destination_path)
                .map_err(|_| "restore destination exists or cannot be created safely")?;
            let database = StateDatabase::from_new_file(file)
                .map_err(|_| "independent restore database could not be initialized")?;
            database.restore_snapshot(&mut BufReader::new(decrypted)).map_err(|_| "snapshot authentication, integrity or schema failed; no complete restore was published")?
        }
    };
    source_root
        .validate_root()
        .map_err(|_| "source directory identity changed during snapshot operation")?;
    destination_root
        .validate_root()
        .map_err(|_| "target directory identity changed; inspect the isolated output before use")?;
    Ok(receipt)
}

pub(super) fn write_partial_export(destination: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() > 4 * 1024 * 1024 || std::str::from_utf8(bytes).is_err() {
        return Err("partial export exceeds its UTF-8 byte limit");
    }
    let (root, path) = pinned_parent(destination)?;
    let mut file = root
        .create_new_file(&path)
        .map_err(|_| "partial export destination exists or cannot be created safely")?;
    file.write_all(bytes)
        .map_err(|_| "partial export write is unconfirmed; preserve any output file")?;
    file.sync_all()
        .map_err(|_| "partial export synchronization is unconfirmed; preserve the output file")?;
    root.validate_root()
        .map_err(|_| "partial export directory identity changed; inspect the output file")
}

pub(super) fn seal_memory_archive(
    destination: &Path,
    bytes: &[u8],
    passphrase: age::secrecy::SecretString,
) -> Result<(), &'static str> {
    if bytes.len() > claw_state::MAX_MEMORY_ARCHIVE_BYTES {
        return Err("memory archive exceeds its byte limit");
    }
    let (root, path) = pinned_parent(destination)?;
    let mut recipient = age::scrypt::Recipient::new(passphrase);
    recipient.set_work_factor(SCRYPT_WORK_FACTOR);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|_| "memory archive encryption could not be initialized")?;
    let file = root
        .create_new_file(&path)
        .map_err(|_| "memory archive destination exists or cannot be created safely")?;
    let mut encrypted = encryptor
        .wrap_output(file)
        .map_err(|_| "memory archive encryption output failed; preserve any partial file")?;
    encrypted
        .write_all(bytes)
        .map_err(|_| "memory archive encryption did not complete")?;
    let file = encrypted
        .finish()
        .map_err(|_| "memory archive encryption finalization failed")?;
    file.sync_all()
        .map_err(|_| "memory archive file synchronization failed")?;
    root.validate_root()
        .map_err(|_| "memory archive target directory changed during export")
}

pub(super) fn read_memory_archive(
    source: &Path,
    passphrase: age::secrecy::SecretString,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    const MAX_CIPHERTEXT: u64 = 4 * 1024 * 1024 + 128 * 1024;
    let (root, path) = pinned_parent(source)?;
    let resolved = root
        .resolve_file(&path)
        .map_err(|_| "encrypted memory archive source is absent or unsafe")?;
    let file = root
        .open_no_follow(&resolved)
        .map_err(|_| "encrypted memory archive cannot be opened safely")?;
    if file
        .metadata()
        .map_err(|_| "memory archive metadata is unavailable")?
        .len()
        > MAX_CIPHERTEXT
    {
        return Err("encrypted memory archive exceeds its byte limit");
    }
    let decryptor = age::Decryptor::new(file.take(MAX_CIPHERTEXT + 1))
        .map_err(|_| "encrypted memory archive header is invalid")?;
    let mut identity = age::scrypt::Identity::new(passphrase);
    identity.set_max_work_factor(SCRYPT_WORK_FACTOR);
    let decrypted = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| "memory archive passphrase or encryption header was refused")?;
    let mut bytes = Zeroizing::new(Vec::new());
    decrypted
        .take((claw_state::MAX_MEMORY_ARCHIVE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "memory archive authentication or complete read failed")?;
    if bytes.len() > claw_state::MAX_MEMORY_ARCHIVE_BYTES {
        return Err("memory archive plaintext exceeds its byte limit");
    }
    root.validate_root()
        .map_err(|_| "memory archive source directory changed")?;
    Ok(bytes)
}

pub(super) fn parse_passphrase(bytes: &[u8]) -> Result<age::secrecy::SecretString, &'static str> {
    if bytes.len() > 1024 {
        return Err("passphrase input exceeds 1024 bytes");
    }
    let bytes = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    let passphrase = std::str::from_utf8(bytes).map_err(|_| "passphrase must be valid UTF-8")?;
    if passphrase.len() < 16
        || passphrase.trim().is_empty()
        || passphrase.chars().any(char::is_control)
    {
        return Err(
            "passphrase must be at least 16 bytes, not blank and without control characters",
        );
    }
    Ok(age::secrecy::SecretString::from(passphrase.to_owned()))
}

fn failure(message: &str) -> RenderedResult {
    RenderedResult {
        exit_code: 2,
        stdout: format!(
            "{}\n",
            json!({"schema_version":1,"method":"state.snapshot","ok":false,"targetMayExist":true,"automaticRetry":false,"error":{"code":"snapshot_refused","message":message}})
        ),
        stderr: String::new(),
    }
}

pub(super) async fn run(command: SnapshotCommand) -> RenderedResult {
    let mut bytes = Zeroizing::new(Vec::new());
    let input = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::io::stdin().take(1025).read_to_end(&mut bytes),
    )
    .await;
    if !matches!(input, Ok(Ok(_))) || bytes.len() > 1024 {
        return failure("passphrase input must end within 30 seconds and 1024 bytes");
    }
    let passphrase = match parse_passphrase(&bytes) {
        Ok(passphrase) => passphrase,
        Err(message) => return failure(message),
    };
    let mode = match command.mode {
        Mode::Export => "export",
        Mode::Restore => "restore",
    };
    drop(bytes);
    match tokio::task::spawn_blocking(move || perform(&command, passphrase)).await {
        Ok(Ok(receipt)) => RenderedResult {
            exit_code: 0,
            stdout: format!(
                "{}\n",
                json!({"schema_version":1,"method":format!("state.snapshot.{mode}"),"ok":true,"records":receipt.records,"snapshotBytes":receipt.bytes,"sha256":receipt.sha256,"encryption":"age-scrypt","scryptWorkFactor":SCRYPT_WORK_FACTOR,"restoredDatabaseIsPlaintext":mode == "restore","sourceRecoveryMayWrite":mode == "export","contentIncluded":false,"externalStoresIncluded":false,"automaticResume":false,"runtimeCompatibilityVerified":false,"directoryDurabilityVerified":false})
            ),
            stderr: String::new(),
        },
        Ok(Err(message)) => failure(message),
        Err(_) => failure(
            "snapshot task ended without a confirmed result; inspect the isolated output before retrying",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_arguments_require_explicit_local_paths_and_stdin_secrets() {
        let root = std::env::temp_dir();
        let valid = [
            OsString::from("state"),
            OsString::from("snapshot"),
            OsString::from("export"),
            OsString::from("--source"),
            root.join("source.redb").into_os_string(),
            OsString::from("--destination"),
            root.join("target.age").into_os_string(),
            OsString::from("--passphrase-stdin"),
        ];
        assert!(parse(&valid).is_ok());
        assert!(parse(&valid[..7]).is_err());
        let mut duplicate = valid.to_vec();
        duplicate.push(OsString::from("--passphrase-stdin"));
        assert!(parse(&duplicate).is_err());
        let mut overwrite = valid.to_vec();
        overwrite.push(OsString::from("--overwrite"));
        assert!(parse(&overwrite).is_err());
        let mut relative = valid.to_vec();
        relative[4] = OsString::from("relative.redb");
        assert!(parse(&relative).is_err());
        let mut same = valid.to_vec();
        same[6] = same[4].clone();
        assert!(parse(&same).is_err());
        #[cfg(windows)]
        for path in [
            r"\\example.invalid\share\source.redb",
            r"\\.\PhysicalDrive0",
        ] {
            let mut remote = valid.to_vec();
            remote[4] = OsString::from(path);
            assert!(parse(&remote).is_err());
        }
    }
}

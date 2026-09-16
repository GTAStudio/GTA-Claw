//! Explicit local provider configuration inspection and new-file candidate preparation.

use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path};

use claw_config::ConfigSnapshot;
use claw_tools::sandbox::{RelativePath, Sandbox, SandboxLimits};
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// Validated local source, without secret resolution, environment layers or network access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConfiguration {
    /// Digest of the exact source bytes, including JSON5 formatting and comments.
    pub source_sha256: String,
    /// Fully validated configuration containing only credential references.
    pub snapshot: ConfigSnapshot,
}

/// One explicit candidate edit; neither variant changes a running provider.
#[derive(Clone, Copy)]
pub enum ProviderEdit<'a> {
    /// Replace the complete provider object using closed JSON with credential references.
    SelectionJson(&'a str),
    /// Keep all other settings and change only an active provider's exact model ID.
    ExactModel(&'a str),
}

/// A verified new local candidate file, not a live daemon configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedProviderConfiguration {
    /// Original source digest retained for a later explicit application.
    pub source_sha256: String,
    /// Digest of the candidate bytes read back from the created file.
    pub candidate_sha256: String,
    /// Validated candidate settings; model availability and credentials remain unchecked.
    pub snapshot: ConfigSnapshot,
}

/// Content-free local configuration failure; never includes a credential reference or value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigurationFileError {
    /// Static diagnostic suitable for an untrusted-output boundary.
    pub message: &'static str,
    /// An existing or partially created output must be preserved for inspection.
    pub output_may_exist: bool,
}

impl std::fmt::Display for ConfigurationFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ConfigurationFileError {}

const fn refused(message: &'static str) -> ConfigurationFileError {
    ConfigurationFileError {
        message,
        output_may_exist: false,
    }
}

fn digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn pinned_parent(path: &Path) -> Result<(Sandbox, RelativePath), ConfigurationFileError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(refused(
            "configuration paths must be explicit local absolute files",
        ));
    }
    #[cfg(windows)]
    if !matches!(path.components().next(),Some(Component::Prefix(prefix)) if matches!(prefix.kind(),std::path::Prefix::Disk(_)|std::path::Prefix::VerbatimDisk(_)))
    {
        return Err(refused(
            "configuration paths must not use a network or device namespace",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| refused("configuration parent is unavailable"))?;
    let root = Sandbox::new_pinned(
        parent,
        SandboxLimits {
            max_file_bytes: MAX_CONFIG_BYTES,
            ..SandboxLimits::default()
        },
    )
    .map_err(|_| refused("configuration parent is unsafe or cannot be pinned"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| refused("configuration filename must be UTF-8"))?;
    let relative = root
        .relative(name)
        .map_err(|_| refused("configuration filename violates local path policy"))?;
    Ok((root, relative))
}

fn read_bounded(file: &mut File) -> Result<Zeroizing<Vec<u8>>, ConfigurationFileError> {
    if file
        .metadata()
        .map_err(|_| refused("configuration metadata is unavailable"))?
        .len()
        > MAX_CONFIG_BYTES
    {
        return Err(refused("configuration exceeds 4 MiB"));
    }
    file.rewind()
        .map_err(|_| refused("configuration cannot be positioned for reading"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused("configuration read did not complete"))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(refused("configuration exceeds 4 MiB"));
    }
    Ok(bytes)
}

fn open_source(
    path: &Path,
) -> Result<(Sandbox, File, ProviderConfiguration), ConfigurationFileError> {
    let (root, relative) = pinned_parent(path)?;
    let resolved = root
        .resolve_file(&relative)
        .map_err(|_| refused("configuration source is absent or unsafe"))?;
    #[cfg(windows)]
    let mut file = root
        .open_read_exclusive(&resolved)
        .map_err(|_| refused("configuration source is unsafe or in use"))?;
    #[cfg(not(windows))]
    let mut file = root
        .open_no_follow(&resolved)
        .map_err(|_| refused("configuration source could not be opened safely"))?;
    let bytes = read_bounded(&mut file)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| refused("configuration source must be UTF-8"))?;
    let snapshot = claw_config::parse_json5(text, "<local-provider-config>")
        .map_err(|_| refused("configuration source does not match the validated native schema"))?;
    root.validate_root()
        .map_err(|_| refused("configuration source directory changed"))?;
    Ok((
        root,
        file,
        ProviderConfiguration {
            source_sha256: digest(&bytes),
            snapshot,
        },
    ))
}

/// Reads one explicit local configuration, ignoring environment overrides and credentials.
///
/// # Errors
/// Refuses unsafe, linked, oversized, invalid or inaccessible files.
pub fn inspect_provider(source: &Path) -> Result<ProviderConfiguration, ConfigurationFileError> {
    open_source(source).map(|(_, _, configuration)| configuration)
}

/// Creates and verifies a new candidate after checking the original source digest.
///
/// The source is not modified; no daemon, provider, credential store or browser is
/// contacted. Windows keeps both input and output under exclusive handles. The
/// caller must treat the resulting file as a candidate requiring review and restart.
///
/// # Errors
/// Refuses a changed source, invalid edit, identical paths or an existing output.
/// Once output creation is attempted a local I/O failure may leave a file; no
/// automatic deletion, overwrite, rollback or directory-durability guarantee is made.
pub fn prepare_provider(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
    edit: ProviderEdit<'_>,
) -> Result<PreparedProviderConfiguration, ConfigurationFileError> {
    if source == destination {
        return Err(refused("candidate destination must differ from its source"));
    }
    let (source_root, _source_file, original) = open_source(source)?;
    if original.source_sha256 != expected_sha256 {
        return Err(refused(
            "configuration source SHA256 changed; inspect again before preparing a candidate",
        ));
    }
    let snapshot = match edit {
        ProviderEdit::SelectionJson(selection) => {
            claw_config::with_provider_json(&original.snapshot, selection)
        }
        ProviderEdit::ExactModel(model) => {
            claw_config::with_provider_model(&original.snapshot, model)
        }
    }
    .map_err(|_| refused("provider edit or the resulting full configuration is invalid"))?;
    let encoded = Zeroizing::new(
        claw_config::to_json5(&snapshot)
            .map_err(|_| refused("candidate configuration could not be encoded"))?,
    );
    if encoded.len() as u64 > MAX_CONFIG_BYTES {
        return Err(refused("candidate configuration exceeds 4 MiB"));
    }
    let (destination_root, destination_path) = pinned_parent(destination)?;
    let writing = |message| ConfigurationFileError {
        message,
        output_may_exist: true,
    };
    #[cfg(windows)]
    let mut output = destination_root
        .create_new_exclusive_file(&destination_path)
        .map_err(|_| writing("candidate exists or cannot be created safely"))?;
    #[cfg(not(windows))]
    let mut output = destination_root
        .create_new_file(&destination_path)
        .map_err(|_| writing("candidate exists or cannot be created safely"))?;
    output
        .write_all(encoded.as_bytes())
        .map_err(|_| writing("candidate write did not complete; preserve the output"))?;
    output
        .sync_all()
        .map_err(|_| writing("candidate synchronization is unconfirmed; preserve the output"))?;
    let observed = read_bounded(&mut output)
        .map_err(|_| writing("candidate readback failed; preserve the output"))?;
    if observed.as_slice() != encoded.as_bytes() {
        return Err(writing("candidate readback changed; preserve the output"));
    }
    source_root
        .validate_root()
        .map_err(|_| writing("source directory changed; preserve the candidate"))?;
    destination_root
        .validate_root()
        .map_err(|_| writing("candidate directory changed; preserve the output"))?;
    Ok(PreparedProviderConfiguration {
        source_sha256: original.source_sha256,
        candidate_sha256: digest(&observed),
        snapshot,
    })
}

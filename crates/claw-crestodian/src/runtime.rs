//! Restart-durable ring-zero control state.
//!
//! Everything a gateway restart must preserve lives in one atomically written
//! settings file; everything a restart must drop — above all a pending approval
//! for a mutation nobody has confirmed since — lives only in memory.

use std::path::{Path, PathBuf};

use claw_config::{WriteWarning, write_bytes_atomically};

use crate::CrestodianError;
use crate::mutation::{ConfigDigest, ConfigDigestChange, CrestodianSettings, TypedMutation};
use crate::rescue::RescueSession;
use crate::setup::read_optional_file;
use crate::state::ensure_parent_directory;

/// Owner of the durable ring-zero settings for one gateway process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrestodianRuntime {
    settings_path: PathBuf,
    settings: CrestodianSettings,
    last_write_warnings: Vec<WriteWarning>,
}

impl CrestodianRuntime {
    /// Starts from durable settings, publishing defaults on the first start.
    ///
    /// Settings that fail re-validation are refused rather than repaired in
    /// place, because a ring-zero surface must never silently widen itself back
    /// to a default after a hand edit.
    ///
    /// # Errors
    ///
    /// Returns [`CrestodianError::Io`] when the settings file exists but cannot
    /// be read, or when publishing the first-start defaults fails;
    /// [`CrestodianError::SettingsDecode`], naming the exact JSON path, when the
    /// file is empty, truncated by an interrupted write, or otherwise not a
    /// settings object; and [`CrestodianError::InvalidSettings`] when decoded
    /// settings record an unsupported schema version, a zero gateway port, a
    /// pending-approval lifetime outside `1..=1440` minutes, or a plaintext
    /// gateway token instead of an `env:<NAME>` reference. A refused settings
    /// file is never rewritten.
    ///
    /// Publishing first-start defaults can succeed while reporting a non-fatal
    /// durability limitation; [`Self::last_write_warnings`] carries it, and a
    /// caller that depends on crash durability must read it rather than treat
    /// success as a guarantee.
    pub fn start(settings_path: impl Into<PathBuf>) -> Result<Self, CrestodianError> {
        let settings_path = settings_path.into();
        let mut last_write_warnings = Vec::new();
        let (settings, publish_defaults) = if let Some(bytes) = read_optional_file(&settings_path)?
        {
            (decode(&settings_path, &bytes)?, false)
        } else {
            (CrestodianSettings::default(), true)
        };
        settings
            .validate()
            .map_err(|message| CrestodianError::InvalidSettings {
                path: settings_path.clone(),
                message,
            })?;
        if publish_defaults {
            last_write_warnings = write_settings(&settings_path, &settings)?;
        }
        Ok(Self {
            settings_path,
            settings,
            last_write_warnings,
        })
    }

    /// Returns the durable settings path.
    #[must_use]
    pub fn settings_path(&self) -> &Path {
        &self.settings_path
    }

    /// Returns the non-fatal durability limitations of the most recent write.
    ///
    /// This is empty when the settings were loaded from an existing file, and
    /// after every write that was fully durable.
    ///
    /// [`WriteWarning::DirectorySyncFailed`] means the new bytes were published
    /// by rename but the containing directory entry could not be synchronized,
    /// so on Unix that rename may not survive sudden power loss even though the
    /// write returned success. It is reported here rather than as an error
    /// because the bytes are already in place and the previous settings are
    /// already gone; there is nothing to roll back and nothing to retry. A
    /// caller that must not confuse "written" with "will still be there after a
    /// power cut" has to check this, because no other signal carries it.
    #[must_use]
    pub fn last_write_warnings(&self) -> &[WriteWarning] {
        &self.last_write_warnings
    }

    /// Returns the settings currently in effect.
    #[must_use]
    pub const fn settings(&self) -> &CrestodianSettings {
        &self.settings
    }

    /// Returns the digest of the settings currently in effect.
    ///
    /// # Errors
    ///
    /// Returns [`CrestodianError::InvalidSettings`] when the in-effect settings
    /// cannot be encoded into their canonical bytes, which only a workspace path
    /// that is not valid UTF-8 can cause.
    pub fn digest(&self) -> Result<ConfigDigest, CrestodianError> {
        self.settings
            .digest()
            .map_err(|message| CrestodianError::InvalidSettings {
                path: self.settings_path.clone(),
                message,
            })
    }

    /// Applies one typed mutation, persisting it before it takes effect.
    ///
    /// The in-memory settings are replaced only after the durable write
    /// succeeds, so a failed write can never leave a running gateway enforcing
    /// a policy that is not on disk.
    ///
    /// # Errors
    ///
    /// Returns [`CrestodianError::InvalidSettings`] when the mutated settings
    /// fail re-validation or cannot be encoded, and [`CrestodianError::Io`] or
    /// [`CrestodianError::Config`] when the durable write fails — the settings
    /// path is not a regular file, its directory cannot be created or written,
    /// or the temporary file cannot be written, `fsync`-ed, or renamed into
    /// place. In every one of those cases the previous settings remain both in
    /// effect and on disk.
    ///
    /// A returned [`ConfigDigestChange`] means the new bytes are published, not
    /// that the rename is guaranteed to survive a power cut: check
    /// [`Self::last_write_warnings`] for the one non-fatal case where it is not.
    pub fn apply(
        &mut self,
        mutation: &TypedMutation,
    ) -> Result<ConfigDigestChange, CrestodianError> {
        let before = self.digest()?;
        let mut updated = self.settings.clone();
        updated.apply(mutation);
        updated
            .validate()
            .map_err(|message| CrestodianError::InvalidSettings {
                path: self.settings_path.clone(),
                message,
            })?;
        let warnings = write_settings(&self.settings_path, &updated)?;
        let after = updated
            .digest()
            .map_err(|message| CrestodianError::InvalidSettings {
                path: self.settings_path.clone(),
                message,
            })?;
        self.settings = updated;
        self.last_write_warnings = warnings;
        Ok(ConfigDigestChange { before, after })
    }

    /// Opens a rescue session bound to the durable policy.
    ///
    /// The session starts with no pending approval, which is exactly why an
    /// approval never survives a restart.
    #[must_use]
    pub fn open_rescue_session(&self) -> RescueSession {
        RescueSession::new(self.settings.rescue.clone())
    }
}

fn decode(path: &Path, bytes: &[u8]) -> Result<CrestodianSettings, CrestodianError> {
    let refuse = |json_path: String, message: String| CrestodianError::SettingsDecode {
        path: path.to_owned(),
        json_path,
        message,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let settings = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let json_path = error.path().to_string();
        refuse(
            if json_path.is_empty() {
                "<root>".to_owned()
            } else {
                json_path
            },
            error.inner().to_string(),
        )
    })?;
    // A settings object followed by anything else is not a settings file this
    // build ever wrote. Accepting the leading object would let a torn or
    // hand-appended file take effect as if it were intact.
    deserializer
        .end()
        .map_err(|error| refuse("<root>".to_owned(), error.to_string()))?;
    Ok(settings)
}

fn write_settings(
    path: &Path,
    settings: &CrestodianSettings,
) -> Result<Vec<WriteWarning>, CrestodianError> {
    ensure_parent_directory(path)?;
    let bytes = settings
        .to_bytes()
        .map_err(|message| CrestodianError::InvalidSettings {
            path: path.to_owned(),
            message,
        })?;
    let outcome = write_bytes_atomically(path, &bytes).map_err(CrestodianError::Config)?;
    Ok(outcome.warnings)
}

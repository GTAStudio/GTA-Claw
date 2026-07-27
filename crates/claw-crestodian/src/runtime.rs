//! Restart-durable ring-zero control state.
//!
//! Everything a gateway restart must preserve lives in one atomically written
//! settings file; everything a restart must drop — above all a pending approval
//! for a mutation nobody has confirmed since — lives only in memory.

use std::path::{Path, PathBuf};

use claw_config::write_bytes_atomically;

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
}

impl CrestodianRuntime {
    /// Starts from durable settings, publishing defaults on the first start.
    ///
    /// Settings that fail re-validation are refused rather than repaired in
    /// place, because a ring-zero surface must never silently widen itself back
    /// to a default after a hand edit.
    pub fn start(settings_path: impl Into<PathBuf>) -> Result<Self, CrestodianError> {
        let settings_path = settings_path.into();
        let settings = match read_optional_file(&settings_path)? {
            Some(bytes) => decode(&settings_path, &bytes)?,
            None => {
                let settings = CrestodianSettings::default();
                write_settings(&settings_path, &settings)?;
                settings
            }
        };
        settings
            .validate()
            .map_err(|message| CrestodianError::InvalidSettings {
                path: settings_path.clone(),
                message,
            })?;
        Ok(Self {
            settings_path,
            settings,
        })
    }

    /// Returns the durable settings path.
    #[must_use]
    pub fn settings_path(&self) -> &Path {
        &self.settings_path
    }

    /// Returns the settings currently in effect.
    #[must_use]
    pub const fn settings(&self) -> &CrestodianSettings {
        &self.settings
    }

    /// Returns the digest of the settings currently in effect.
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
        write_settings(&self.settings_path, &updated)?;
        let after = updated
            .digest()
            .map_err(|message| CrestodianError::InvalidSettings {
                path: self.settings_path.clone(),
                message,
            })?;
        self.settings = updated;
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
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        let json_path = error.path().to_string();
        CrestodianError::SettingsDecode {
            path: path.to_owned(),
            json_path: if json_path.is_empty() {
                "<root>".to_owned()
            } else {
                json_path
            },
            message: error.inner().to_string(),
        }
    })
}

fn write_settings(path: &Path, settings: &CrestodianSettings) -> Result<(), CrestodianError> {
    ensure_parent_directory(path)?;
    let bytes = settings
        .to_bytes()
        .map_err(|message| CrestodianError::InvalidSettings {
            path: path.to_owned(),
            message,
        })?;
    write_bytes_atomically(path, &bytes).map_err(CrestodianError::Config)?;
    Ok(())
}

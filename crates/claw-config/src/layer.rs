use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::migration::{MigrationError, apply_legacy_environment_layer};
use crate::wire::EnvelopeWire;
use crate::{ConfigError, ConfigSnapshot, parse_json5};

/// Configuration source order, from lowest to highest precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigLayerKind {
    /// Compile-time defaults.
    BuiltIn,
    /// Machine-wide configuration.
    System,
    /// Per-user configuration.
    User,
    /// Workspace or project configuration.
    Workspace,
    /// Frozen legacy environment-variable mappings.
    Environment,
    /// Explicit command-line overrides.
    CommandLine,
}

/// Result of resolving all configured layers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedConfig {
    /// Validated typed result.
    pub config: ConfigSnapshot,
    /// Sources that contributed an explicit value, in precedence order.
    pub applied_layers: Vec<ConfigLayerKind>,
}

/// Failure to read, merge, migrate, or validate one configuration layer.
#[derive(Debug)]
pub enum LayeredConfigError {
    /// A layer file could not be read.
    Io {
        /// Layer being read.
        layer: ConfigLayerKind,
        /// Underlying typed I/O error.
        error: ConfigError,
    },
    /// A partial JSON5 layer was malformed or not an object.
    Layer {
        /// Layer being decoded.
        layer: ConfigLayerKind,
        /// Specific configuration error.
        error: ConfigError,
    },
    /// A frozen environment conversion failed.
    Environment(MigrationError),
    /// The merged result was invalid.
    Result(ConfigError),
}

impl Display for LayeredConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { layer, error } => write!(formatter, "{layer:?} config: {error}"),
            Self::Layer { layer, error } => write!(formatter, "{layer:?} config: {error}"),
            Self::Environment(error) => write!(formatter, "environment config: {error}"),
            Self::Result(error) => write!(formatter, "resolved config: {error}"),
        }
    }
}

impl Error for LayeredConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { error, .. } | Self::Layer { error, .. } | Self::Result(error) => Some(error),
            Self::Environment(error) => Some(error),
        }
    }
}

/// Additive builder for deterministic configuration resolution.
///
/// Object layers are merged recursively. Arrays and scalar values replace the
/// lower-precedence value, so overriding one nested field does not discard its
/// siblings.
#[derive(Clone, Debug, Default)]
pub struct ConfigLayers {
    system: Option<String>,
    user: Option<String>,
    workspace: Option<String>,
    environment: BTreeMap<String, String>,
    command_line: Option<String>,
}

impl ConfigLayers {
    /// Creates an empty resolver using only built-in defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a partial machine-wide JSON5 layer.
    #[must_use]
    pub fn with_system_json5(mut self, source: impl Into<String>) -> Self {
        self.system = Some(source.into());
        self
    }

    /// Reads and sets a partial machine-wide JSON5 layer.
    pub fn with_system_file(mut self, path: impl AsRef<Path>) -> Result<Self, LayeredConfigError> {
        self.system = Some(read_layer(path.as_ref(), ConfigLayerKind::System)?);
        Ok(self)
    }

    /// Sets a partial per-user JSON5 layer.
    #[must_use]
    pub fn with_user_json5(mut self, source: impl Into<String>) -> Self {
        self.user = Some(source.into());
        self
    }

    /// Reads and sets a partial per-user JSON5 layer.
    pub fn with_user_file(mut self, path: impl AsRef<Path>) -> Result<Self, LayeredConfigError> {
        self.user = Some(read_layer(path.as_ref(), ConfigLayerKind::User)?);
        Ok(self)
    }

    /// Sets a partial workspace/project JSON5 layer.
    #[must_use]
    pub fn with_workspace_json5(mut self, source: impl Into<String>) -> Self {
        self.workspace = Some(source.into());
        self
    }

    /// Reads and sets a partial workspace/project JSON5 layer.
    pub fn with_workspace_file(
        mut self,
        path: impl AsRef<Path>,
    ) -> Result<Self, LayeredConfigError> {
        self.workspace = Some(read_layer(path.as_ref(), ConfigLayerKind::Workspace)?);
        Ok(self)
    }

    /// Replaces the supplied environment map.
    #[must_use]
    pub fn with_environment<K, V, I>(mut self, variables: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        self.environment = variables
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        self
    }

    /// Sets a partial command-line JSON5 override.
    #[must_use]
    pub fn with_command_line_json5(mut self, source: impl Into<String>) -> Self {
        self.command_line = Some(source.into());
        self
    }

    /// Resolves defaults, system, user, workspace, environment, then CLI.
    pub fn resolve(&self) -> Result<ResolvedConfig, LayeredConfigError> {
        let mut merged = serde_json::to_value(EnvelopeWire::default())
            .map_err(ConfigError::from_serialize)
            .map_err(LayeredConfigError::Result)?;
        let mut applied_layers = vec![ConfigLayerKind::BuiltIn];
        for (kind, source) in [
            (ConfigLayerKind::System, self.system.as_deref()),
            (ConfigLayerKind::User, self.user.as_deref()),
            (ConfigLayerKind::Workspace, self.workspace.as_deref()),
        ] {
            if let Some(source) = source {
                merge_layer(&mut merged, source, kind)?;
                applied_layers.push(kind);
            }
        }
        if !self.environment.is_empty() {
            let base = decode_envelope(&merged, "<lower-precedence-layers>")
                .map_err(LayeredConfigError::Result)?;
            let resolved = apply_legacy_environment_layer(
                base,
                self.environment
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            )
            .map_err(LayeredConfigError::Environment)?;
            merged = serde_json::to_value(resolved)
                .map_err(ConfigError::from_serialize)
                .map_err(LayeredConfigError::Result)?;
            applied_layers.push(ConfigLayerKind::Environment);
        }

        fn decode_envelope(value: &Value, source_name: &str) -> Result<EnvelopeWire, ConfigError> {
            let bytes = serde_json::to_vec(value).map_err(ConfigError::from_serialize)?;
            let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
            serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
                let path = error.path().to_string();
                ConfigError::Decode {
                    source_name: source_name.to_owned(),
                    path: if path.is_empty() {
                        "<root>".to_owned()
                    } else {
                        path
                    },
                    message: error.inner().to_string(),
                }
            })
        }
        if let Some(source) = &self.command_line {
            merge_layer(&mut merged, source, ConfigLayerKind::CommandLine)?;
            applied_layers.push(ConfigLayerKind::CommandLine);
        }
        let source = serde_json::to_string(&merged)
            .map_err(ConfigError::from_serialize)
            .map_err(LayeredConfigError::Result)?;
        let config =
            parse_json5(&source, "<layered-config>").map_err(LayeredConfigError::Result)?;
        Ok(ResolvedConfig {
            config,
            applied_layers,
        })
    }
}

fn read_layer(path: &Path, layer: ConfigLayerKind) -> Result<String, LayeredConfigError> {
    fs::read_to_string(path).map_err(|source| LayeredConfigError::Io {
        layer,
        error: ConfigError::io(path, source),
    })
}

fn merge_layer(
    merged: &mut Value,
    source: &str,
    layer: ConfigLayerKind,
) -> Result<(), LayeredConfigError> {
    let candidate =
        json5::from_str::<Value>(source).map_err(|error| LayeredConfigError::Layer {
            layer,
            error: ConfigError::Syntax {
                source_name: format!("{layer:?}"),
                message: error.to_string(),
            },
        })?;
    if !candidate.is_object() {
        return Err(LayeredConfigError::Layer {
            layer,
            error: ConfigError::Validation {
                path: "<root>".to_owned(),
                message: "configuration layer must be an object".to_owned(),
            },
        });
    }
    merge_value(merged, candidate);
    Ok(())
}

fn merge_value(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(&key) {
                    Some(existing) => merge_value(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

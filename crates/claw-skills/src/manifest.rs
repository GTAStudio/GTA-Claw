//! Modern skill manifest parsing.

use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

use serde::Deserialize;
use serde_json::Value;

use crate::schema::{SchemaError, validate_schema};

/// A validated modern skill manifest.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SkillManifest {
    id: String,
    description: String,
    parameters: Value,
    execution: SkillExecution,
}

impl SkillManifest {
    /// Returns the skill identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the human-readable description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the parameter JSON Schema.
    #[must_use]
    pub const fn parameters(&self) -> &Value {
        &self.parameters
    }

    /// Returns the selected execution backend.
    #[must_use]
    pub const fn execution(&self) -> &SkillExecution {
        &self.execution
    }

    pub(crate) fn validate(&self) -> Result<(), ManifestError> {
        if !valid_skill_id(&self.id) {
            return Err(ManifestError::InvalidId);
        }
        if self.description.trim().is_empty() {
            return Err(ManifestError::EmptyDescription);
        }
        validate_schema(&self.parameters).map_err(ManifestError::InvalidParameterSchema)?;
        self.execution.validate()
    }
}

/// Closed executable forms. JavaScript is deliberately not representable.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SkillExecution {
    /// Rust-native handler registered in the process.
    Native {
        /// Exact handler identifier.
        handler: String,
    },
    /// Declarative request delegated to an injected HTTP bridge.
    Http {
        /// Validated HTTP request definition.
        request: HttpSkillDefinition,
    },
    /// Sandboxed component delegated to the separately owned Wasm host.
    Wasm {
        /// Installed plugin identifier.
        plugin_id: String,
        /// Exported function name.
        export: String,
    },
}

impl SkillExecution {
    fn validate(&self) -> Result<(), ManifestError> {
        match self {
            Self::Native { handler } if !valid_skill_id(handler) => {
                Err(ManifestError::InvalidNativeHandler)
            }
            Self::Http { request } => request.validate(),
            Self::Wasm { plugin_id, export }
                if !valid_skill_id(plugin_id) || !valid_export(export) =>
            {
                Err(ManifestError::InvalidWasmTarget)
            }
            Self::Native { .. } | Self::Wasm { .. } => Ok(()),
        }
    }
}

/// Declarative HTTP request with no executable source code.
#[derive(Clone, Deserialize, PartialEq)]
pub struct HttpSkillDefinition {
    /// HTTP method.
    pub method: HttpMethod,
    /// Absolute HTTP(S) URL without user information.
    pub url: String,
    /// Static non-sensitive headers.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Parameter encoding and placement.
    #[serde(default)]
    pub parameters: HttpParameterEncoding,
    /// Response decoding mode.
    #[serde(default)]
    pub response: HttpResponseMode,
}

impl HttpSkillDefinition {
    fn validate(&self) -> Result<(), ManifestError> {
        let remainder = self
            .url
            .strip_prefix("https://")
            .or_else(|| self.url.strip_prefix("http://"))
            .ok_or(ManifestError::InvalidHttpUrl)?;
        let authority = remainder.split('/').next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') || self.url.chars().any(char::is_control)
        {
            return Err(ManifestError::InvalidHttpUrl);
        }
        for (name, value) in &self.headers {
            if !valid_header_name(name)
                || value
                    .chars()
                    .any(|character| matches!(character, '\r' | '\n' | '\0'))
                || sensitive_header(name)
            {
                return Err(ManifestError::InvalidHttpHeader);
            }
        }
        if matches!(self.method, HttpMethod::Get | HttpMethod::Delete)
            && self.parameters == HttpParameterEncoding::JsonBody
        {
            return Err(ManifestError::InvalidHttpParameterEncoding);
        }
        if let HttpParameterEncoding::QueryParameter { name } = &self.parameters
            && !valid_query_name(name)
        {
            return Err(ManifestError::InvalidHttpParameterEncoding);
        }
        Ok(())
    }
}

impl Debug for HttpSkillDefinition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpSkillDefinition")
            .field("method", &self.method)
            .field("url", &redact_url_query(&self.url))
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("parameters", &self.parameters)
            .field("response", &self.response)
            .finish()
    }
}

/// Declarative placement of validated parameters.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HttpParameterEncoding {
    /// Serialize parameters as a JSON request body.
    #[default]
    JsonBody,
    /// Serialize the complete parameter document as one percent-encoded query value.
    QueryParameter {
        /// Query parameter name.
        name: String,
    },
}

/// Supported declarative HTTP methods.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// Read a resource.
    Get,
    /// Submit a JSON body.
    Post,
    /// Replace a resource with a JSON body.
    Put,
    /// Partially update a resource with a JSON body.
    Patch,
    /// Delete a resource.
    Delete,
}

/// HTTP response decoding mode.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HttpResponseMode {
    /// Decode response bytes as JSON.
    #[default]
    Json,
    /// Decode response bytes as UTF-8 text.
    Text,
}

/// Modern manifest loading failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestError {
    /// JSON cannot be decoded into the closed modern manifest model.
    MalformedJson,
    /// Identifier is empty or contains unsafe characters.
    InvalidId,
    /// Description is empty.
    EmptyDescription,
    /// Parameter schema is invalid.
    InvalidParameterSchema(SchemaError),
    /// Native handler identifier is invalid.
    InvalidNativeHandler,
    /// HTTP URL is relative, malformed, or contains user information.
    InvalidHttpUrl,
    /// HTTP header is malformed or would carry a static credential.
    InvalidHttpHeader,
    /// Parameter encoding is incompatible with the HTTP method or malformed.
    InvalidHttpParameterEncoding,
    /// Wasm plugin or export identifier is invalid.
    InvalidWasmTarget,
}

/// Parses and validates a modern manifest.
pub fn load_manifest(json: &str) -> Result<SkillManifest, ManifestError> {
    let manifest: SkillManifest =
        serde_json::from_str(json).map_err(|_| ManifestError::MalformedJson)?;
    manifest.validate()?;
    Ok(manifest)
}

fn valid_skill_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn valid_export(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn sensitive_header(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "proxy-authorization" | "x-api-key"
    )
}

fn valid_query_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn redact_url_query(url: &str) -> String {
    url.split_once('?')
        .map_or_else(|| url.to_owned(), |(base, _)| format!("{base}?[REDACTED]"))
}

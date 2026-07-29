//! Modern skill manifest parsing.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use serde::Deserialize;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::schema::{
    ExactJsonDocument, ExactNode, SchemaError, ValidationLimits, validate_schema_with_exact,
};

/// A validated modern skill manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillManifest {
    id: String,
    description: String,
    parameters: Value,
    exact_parameters: Option<ExactNode>,
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

    pub(crate) const fn exact_parameters(&self) -> Option<&ExactNode> {
        self.exact_parameters.as_ref()
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
        let fallback_exact = self
            .exact_parameters
            .is_none()
            .then(|| ExactNode::from_value(&self.parameters));
        let exact_parameters = self
            .exact_parameters
            .as_ref()
            .or(fallback_exact.as_ref())
            .expect("manifest parameters always have an exact representation");
        validate_schema_with_exact(
            &self.parameters,
            exact_parameters,
            ValidationLimits::default(),
        )
        .map_err(ManifestError::InvalidParameterSchema)?;
        self.execution.validate()
    }
}

/// Closed executable forms. JavaScript is deliberately not representable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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
        /// Plugin-local tool name passed to the component's `invoke-tool` export.
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
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
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
        let parsed = url::Url::parse(&self.url).map_err(|_| ManifestError::InvalidHttpUrl)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || self.url.chars().any(char::is_control)
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
    MalformedJson {
        /// One-based source line.
        line: usize,
        /// One-based source column.
        column: usize,
        /// Serde diagnostic, including unknown-field and type information.
        message: String,
    },
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
///
/// # Errors
///
/// Returns [`ManifestError::MalformedJson`] when `json` is not JSON or does not
/// decode into the closed model, which includes any `execution.kind` other than
/// `native`, `http` or `wasm`: JavaScript is not representable, so it is
/// rejected by the parser rather than by a later check.
///
/// Returns [`ManifestError::InvalidId`] when the identifier is empty, longer
/// than 128 bytes, or uses a byte outside `[A-Za-z0-9]` plus `-`, `_` and `.`
/// after the first, and [`ManifestError::EmptyDescription`] when the
/// description is blank. [`ManifestError::InvalidParameterSchema`] carries the
/// exact path and reason the parameter schema left the supported JSON Schema
/// subset.
///
/// The remaining variants name what the selected backend rejected:
/// [`ManifestError::InvalidNativeHandler`] for a handler identifier outside the
/// identifier alphabet; [`ManifestError::InvalidHttpUrl`] for a URL that is not
/// `http(s)://`, carries no authority, embeds user information before an `@`,
/// or contains a control character; [`ManifestError::InvalidHttpHeader`] for a
/// header whose name is malformed, whose value would inject `CR`, `LF` or `NUL`,
/// or that is one of the credential-bearing names (`authorization`, `cookie`,
/// `proxy-authorization`, `x-api-key`);
/// [`ManifestError::InvalidHttpParameterEncoding`] for a JSON body on `GET` or
/// `DELETE` or a malformed query parameter name; and
/// [`ManifestError::InvalidWasmTarget`] for an invalid plugin identifier or
/// export name.
pub fn load_manifest(json: &str) -> Result<SkillManifest, ManifestError> {
    let raw: RawSkillManifest<'_> =
        serde_json::from_str(json).map_err(|error| ManifestError::MalformedJson {
            line: error.line(),
            column: error.column(),
            message: error.to_string(),
        })?;
    let parameters = ExactJsonDocument::parse(raw.parameters.get()).map_err(|error| {
        ManifestError::MalformedJson {
            line: error.line(),
            column: error.column(),
            message: error.to_string(),
        }
    })?;
    let (parameters, exact_parameters) = parameters.into_parts();
    let manifest = SkillManifest {
        id: raw.id,
        description: raw.description,
        parameters,
        exact_parameters: Some(exact_parameters),
        execution: raw.execution,
    };
    manifest.validate()?;
    Ok(manifest)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSkillManifest<'a> {
    id: String,
    description: String,
    #[serde(borrow)]
    parameters: &'a RawValue,
    execution: SkillExecution,
}

impl Display for ManifestError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedJson {
                line,
                column,
                message,
            } => write!(
                formatter,
                "skill manifest JSON is invalid at line {line}, column {column}: {message}"
            ),
            Self::InvalidId => formatter.write_str("skill id is invalid"),
            Self::EmptyDescription => formatter.write_str("skill description must not be blank"),
            Self::InvalidParameterSchema(error) => write!(
                formatter,
                "skill parameter schema at `{}` is invalid: {:?}",
                error.path, error.kind
            ),
            Self::InvalidNativeHandler => formatter.write_str("native skill handler id is invalid"),
            Self::InvalidHttpUrl => formatter.write_str("skill HTTP URL is invalid"),
            Self::InvalidHttpHeader => formatter.write_str("skill HTTP header is invalid"),
            Self::InvalidHttpParameterEncoding => {
                formatter.write_str("skill HTTP parameter encoding is invalid")
            }
            Self::InvalidWasmTarget => {
                formatter.write_str("skill plugin id or tool name is invalid")
            }
        }
    }
}

impl Error for ManifestError {}

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

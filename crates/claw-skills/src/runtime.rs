//! Skill execution dispatch.

use std::collections::{BTreeMap, btree_map::Entry};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};

use serde_json::Value;

use crate::manifest::{
    HttpMethod, HttpParameterEncoding, HttpResponseMode, SkillExecution, SkillManifest,
};
use crate::schema::{ParameterValidationError, validate_parameters};

const MAX_HTTP_RESPONSE_BYTES: usize = 1024 * 1024;

/// One HTTP request emitted by a declarative skill.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpRequest {
    /// HTTP method.
    pub method: HttpMethod,
    /// Absolute validated URL.
    pub url: String,
    /// Static non-sensitive request headers.
    pub headers: BTreeMap<String, String>,
    /// JSON-encoded parameters.
    pub body: Vec<u8>,
}

impl Debug for HttpRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &redact_url_query(&self.url))
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .finish()
    }
}

/// HTTP response returned by an injected bridge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Bounded response bytes.
    pub body: Vec<u8>,
}

/// Declarative HTTP bridge port.
pub trait HttpBridge {
    /// Executes one validated request without logging its body.
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpBridgeError>;
}

/// Credential-safe HTTP bridge failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpBridgeError {
    /// Connection could not be established.
    Connection,
    /// Request timed out.
    Timeout,
    /// TLS validation failed.
    Tls,
    /// Response framing was malformed.
    Protocol,
}

/// A native Rust skill implementation.
pub trait NativeSkillHandler: Send + Sync {
    /// Executes validated parameters.
    fn execute(&self, parameters: Value) -> Result<Value, SkillExecutionError>;
}

/// Process-local registry of reviewed Rust handlers.
#[derive(Default)]
pub struct NativeSkillRegistry {
    handlers: BTreeMap<String, Box<dyn NativeSkillHandler>>,
}

impl NativeSkillRegistry {
    /// Creates an empty handler registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            handlers: BTreeMap::new(),
        }
    }

    /// Registers a handler exactly once.
    pub fn register(
        &mut self,
        id: impl Into<String>,
        handler: impl NativeSkillHandler + 'static,
    ) -> Result<(), NativeRegistryError> {
        let id = id.into();
        if id.is_empty()
            || !id.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.'))
            })
        {
            return Err(NativeRegistryError::InvalidId);
        }
        match self.handlers.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(Box::new(handler));
                Ok(())
            }
            Entry::Occupied(_) => Err(NativeRegistryError::DuplicateId),
        }
    }

    fn execute(&self, id: &str, parameters: Value) -> Result<Value, SkillExecutionError> {
        self.handlers
            .get(id)
            .ok_or(SkillExecutionError::NativeHandlerNotFound)?
            .execute(parameters)
    }
}

impl Debug for NativeSkillRegistry {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeSkillRegistry")
            .field("handler_ids", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Native registry mutation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRegistryError {
    /// Handler identifier is invalid.
    InvalidId,
    /// Handler identifier was already registered.
    DuplicateId,
}

/// Port supplied by the separately owned sandboxed Wasm plugin host.
pub trait WasmSkillHost {
    /// Invokes one installed component export with validated parameters.
    fn invoke(
        &self,
        plugin_id: &str,
        export: &str,
        parameters: Value,
    ) -> Result<Value, WasmHostError>;
}

/// Stable Wasm host failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WasmHostError {
    /// Plugin is not installed.
    PluginNotFound,
    /// Export is absent.
    ExportNotFound,
    /// Sandbox policy denied the invocation.
    PolicyDenied,
    /// Component trapped.
    Trap,
}

/// Runtime dispatcher with explicit backend ports.
pub struct SkillRuntime<'a> {
    native: &'a NativeSkillRegistry,
    http: &'a dyn HttpBridge,
    wasm: &'a dyn WasmSkillHost,
}

impl<'a> SkillRuntime<'a> {
    /// Creates a dispatcher from explicit backend implementations.
    #[must_use]
    pub const fn new(
        native: &'a NativeSkillRegistry,
        http: &'a dyn HttpBridge,
        wasm: &'a dyn WasmSkillHost,
    ) -> Self {
        Self { native, http, wasm }
    }

    /// Validates parameters and dispatches the manifest's closed execution form.
    pub fn execute(
        &self,
        manifest: &SkillManifest,
        parameters: Value,
    ) -> Result<Value, SkillExecutionError> {
        manifest
            .validate()
            .map_err(SkillExecutionError::InvalidManifest)?;
        validate_parameters(manifest.parameters(), &parameters)
            .map_err(SkillExecutionError::InvalidParameters)?;
        match manifest.execution() {
            SkillExecution::Native { handler } => self.native.execute(handler, parameters),
            SkillExecution::Http { request } => {
                let mut headers = request.headers.clone();
                let encoded = serde_json::to_vec(&parameters)
                    .map_err(|_| SkillExecutionError::ParameterEncoding)?;
                let (url, body) = match &request.parameters {
                    HttpParameterEncoding::JsonBody => {
                        headers.insert("content-type".to_owned(), "application/json".to_owned());
                        (request.url.clone(), encoded)
                    }
                    HttpParameterEncoding::QueryParameter { name } => {
                        let encoded = String::from_utf8(encoded)
                            .map_err(|_| SkillExecutionError::ParameterEncoding)?;
                        (
                            append_query_parameter(&request.url, name, &encoded),
                            Vec::new(),
                        )
                    }
                };
                let response = self
                    .http
                    .send(HttpRequest {
                        method: request.method,
                        url,
                        headers,
                        body,
                    })
                    .map_err(SkillExecutionError::HttpBridge)?;
                decode_http_response(response, request.response)
            }
            SkillExecution::Wasm { plugin_id, export } => self
                .wasm
                .invoke(plugin_id, export, parameters)
                .map_err(SkillExecutionError::WasmHost),
        }
    }
}

fn append_query_parameter(url: &str, name: &str, value: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!(
        "{url}{separator}{}={}",
        percent_encode(name),
        percent_encode(value)
    )
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn redact_url_query(url: &str) -> String {
    url.split_once('?')
        .map_or_else(|| url.to_owned(), |(base, _)| format!("{base}?[REDACTED]"))
}

fn decode_http_response(
    response: HttpResponse,
    mode: HttpResponseMode,
) -> Result<Value, SkillExecutionError> {
    if response.body.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err(SkillExecutionError::HttpResponseTooLarge);
    }
    if !(200..=299).contains(&response.status) {
        return Err(SkillExecutionError::HttpStatus(response.status));
    }
    match mode {
        HttpResponseMode::Json => serde_json::from_slice(&response.body)
            .map_err(|_| SkillExecutionError::InvalidHttpResponse),
        HttpResponseMode::Text => String::from_utf8(response.body)
            .map(Value::String)
            .map_err(|_| SkillExecutionError::InvalidHttpResponse),
    }
}

/// Typed skill execution failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SkillExecutionError {
    /// Manifest invariants were violated after construction.
    InvalidManifest(crate::manifest::ManifestError),
    /// Parameters did not match the declared schema.
    InvalidParameters(ParameterValidationError),
    /// Native handler is not registered.
    NativeHandlerNotFound,
    /// Parameters could not be encoded.
    ParameterEncoding,
    /// HTTP bridge failed.
    HttpBridge(HttpBridgeError),
    /// HTTP endpoint returned a non-success status; body is deliberately omitted.
    HttpStatus(u16),
    /// HTTP response exceeded the one MiB limit.
    HttpResponseTooLarge,
    /// HTTP response could not be decoded as declared.
    InvalidHttpResponse,
    /// Wasm host failed.
    WasmHost(WasmHostError),
    /// A native handler rejected or failed its operation.
    NativeFailure,
}

impl Display for SkillExecutionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(_) => formatter.write_str("skill manifest is invalid"),
            Self::InvalidParameters(_) => formatter.write_str("skill parameters are invalid"),
            Self::NativeHandlerNotFound => formatter.write_str("native skill handler not found"),
            Self::ParameterEncoding => formatter.write_str("skill parameter encoding failed"),
            Self::HttpBridge(error) => write!(formatter, "skill HTTP bridge failed: {error:?}"),
            Self::HttpStatus(status) => write!(formatter, "skill HTTP endpoint returned {status}"),
            Self::HttpResponseTooLarge => formatter.write_str("skill HTTP response is too large"),
            Self::InvalidHttpResponse => formatter.write_str("skill HTTP response decoding failed"),
            Self::WasmHost(error) => write!(formatter, "skill Wasm host failed: {error:?}"),
            Self::NativeFailure => formatter.write_str("native skill handler failed"),
        }
    }
}

impl Error for SkillExecutionError {}

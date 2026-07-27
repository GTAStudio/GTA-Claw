//! Skill execution dispatch.

use std::collections::{BTreeMap, btree_map::Entry};
use std::error::Error;
use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
    ///
    /// # Errors
    ///
    /// Returns [`HttpBridgeError::Connection`] when the endpoint cannot be
    /// reached, [`HttpBridgeError::Timeout`] when the implementation's deadline
    /// expires, [`HttpBridgeError::Tls`] when certificate or hostname
    /// validation fails, and [`HttpBridgeError::Protocol`] when the response
    /// framing is malformed. The category carries no detail on purpose: the
    /// request body and headers may hold caller data, and an error is the most
    /// likely value to be logged.
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
    ///
    /// # Errors
    ///
    /// Returns [`SkillExecutionError::NativeFailure`] when the handler cannot
    /// complete its operation. `parameters` has already been validated against
    /// the manifest's schema before this is called, so a handler does not have
    /// to re-report shape problems the schema already covers.
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
    ///
    /// # Errors
    ///
    /// Returns [`NativeRegistryError::InvalidId`] when `id` is empty or uses a
    /// byte outside `[A-Za-z0-9]` plus `-`, `_` and `.` after the first, and
    /// [`NativeRegistryError::DuplicateId`] when the identifier is already
    /// registered. A duplicate never replaces the handler already in place, so
    /// a late registration cannot silently take over a reviewed skill.
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

/// Cooperative cancellation shared with a skill caller.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates an uncancelled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reuses the flag supplied by another runtime boundary.
    #[must_use]
    pub const fn from_shared_flag(cancelled: Arc<AtomicBool>) -> Self {
        Self { cancelled }
    }

    /// Returns the flag a plugin-host adapter should observe.
    #[must_use]
    pub fn shared_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Reports whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Typed invocation passed to the sandboxed component host.
#[derive(Clone, Debug)]
pub struct WasmSkillInvocation<'a> {
    /// Installed plugin identity.
    pub plugin_id: &'a str,
    /// Plugin-local tool name.
    pub tool: &'a str,
    /// Parameters already validated against the skill schema.
    pub parameters: Value,
    /// Optional signal that the host must observe during guest execution.
    pub cancellation: Option<&'a CancellationToken>,
}

/// Port supplied by the separately owned sandboxed Wasm plugin host.
pub trait WasmSkillHost {
    /// Invokes one installed component export with validated parameters.
    ///
    /// # Errors
    ///
    /// Returns a [`WasmHostError`] whose [`WasmHostError::kind`] distinguishes
    /// an absent or inactive plugin, an unknown tool, policy refusal, payload or
    /// resource exhaustion, cancellation, timeout, trap, invalid response, and
    /// an uncategorized host failure.
    fn invoke(&mut self, invocation: WasmSkillInvocation<'_>) -> Result<Value, WasmHostError>;
}

/// Stable Wasm host failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WasmHostErrorKind {
    /// Plugin is not installed.
    PluginNotFound,
    /// Plugin is installed but not active.
    PluginUnavailable,
    /// Plugin-local tool is absent.
    ToolNotFound,
    /// Sandbox policy denied the invocation.
    PolicyDenied,
    /// A request or response crossed its payload ceiling.
    PayloadTooLarge,
    /// Caller cancellation stopped the component.
    Cancelled,
    /// Fuel, memory, table, instance, or host-call quota was exhausted.
    ResourceExhausted,
    /// Wall-clock deadline expired.
    Timeout,
    /// Component trapped for another reason.
    Trap,
    /// Component returned a response outside the typed JSON contract.
    InvalidResponse,
    /// Host failed outside a category the caller can act on.
    Internal,
}

/// Actionable Wasm host failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmHostError {
    kind: WasmHostErrorKind,
    detail: String,
}

impl WasmHostError {
    /// Builds a categorized host failure.
    #[must_use]
    pub fn new(kind: WasmHostErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Stable category for programmatic handling.
    #[must_use]
    pub const fn kind(&self) -> WasmHostErrorKind {
        self.kind
    }

    /// Operator-facing detail supplied by the sandbox host.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl Display for WasmHostError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl Error for WasmHostError {}

/// Runtime dispatcher with explicit backend ports.
pub struct SkillRuntime<'a> {
    native: &'a NativeSkillRegistry,
    http: &'a dyn HttpBridge,
    wasm: &'a mut dyn WasmSkillHost,
}

impl<'a> SkillRuntime<'a> {
    /// Creates a dispatcher from explicit backend implementations.
    #[must_use]
    pub const fn new(
        native: &'a NativeSkillRegistry,
        http: &'a dyn HttpBridge,
        wasm: &'a mut dyn WasmSkillHost,
    ) -> Self {
        Self { native, http, wasm }
    }

    /// Validates parameters and dispatches the manifest's closed execution form.
    ///
    /// # Errors
    ///
    /// Returns [`SkillExecutionError::InvalidManifest`] when the manifest no
    /// longer satisfies its own invariants — it is re-validated here, so a
    /// manifest mutated after construction cannot reach a backend — and
    /// [`SkillExecutionError::InvalidParameters`] when `parameters` does not
    /// match the declared schema. Both are decided before any backend is
    /// touched.
    ///
    /// A native skill returns [`SkillExecutionError::NativeHandlerNotFound`]
    /// when the manifest names a handler this registry does not hold, or
    /// whatever the handler itself reports.
    ///
    /// An HTTP skill returns [`SkillExecutionError::ParameterEncoding`] when the
    /// validated parameters cannot be encoded for the declared placement,
    /// [`SkillExecutionError::HttpBridge`] when the injected bridge fails,
    /// [`SkillExecutionError::HttpResponseTooLarge`] when the response body
    /// exceeds one MiB, [`SkillExecutionError::HttpStatus`] for any status
    /// outside 200-299 (the body is deliberately dropped), and
    /// [`SkillExecutionError::InvalidHttpResponse`] when the body does not
    /// decode as the declared JSON or UTF-8 text.
    ///
    /// A Wasm skill returns [`SkillExecutionError::WasmHost`] carrying the
    /// sandboxed host's own refusal.
    pub fn execute(
        &mut self,
        manifest: &SkillManifest,
        parameters: Value,
    ) -> Result<Value, SkillExecutionError> {
        self.execute_inner(manifest, parameters, None)
    }

    /// Executes a skill while propagating cancellation to its Wasm host.
    ///
    /// Native and declarative HTTP backends are checked before dispatch. The
    /// Wasm backend additionally receives the token so it can interrupt an
    /// already-running guest.
    ///
    /// # Errors
    ///
    /// Returns [`SkillExecutionError::Cancelled`] before touching any backend
    /// when cancellation was already requested, plus every error documented by
    /// [`SkillRuntime::execute`].
    pub fn execute_cancellable(
        &mut self,
        manifest: &SkillManifest,
        parameters: Value,
        cancellation: &CancellationToken,
    ) -> Result<Value, SkillExecutionError> {
        self.execute_inner(manifest, parameters, Some(cancellation))
    }

    fn execute_inner(
        &mut self,
        manifest: &SkillManifest,
        parameters: Value,
        cancellation: Option<&CancellationToken>,
    ) -> Result<Value, SkillExecutionError> {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Err(SkillExecutionError::Cancelled);
        }
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
                .invoke(WasmSkillInvocation {
                    plugin_id,
                    tool: export,
                    parameters,
                    cancellation,
                })
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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut encoded = String::with_capacity(value.len());
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
    /// Caller cancelled the skill before backend dispatch.
    Cancelled,
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
            Self::WasmHost(error) => write!(formatter, "skill Wasm host failed: {error}"),
            Self::Cancelled => formatter.write_str("skill execution was cancelled"),
            Self::NativeFailure => formatter.write_str("native skill handler failed"),
        }
    }
}

impl Error for SkillExecutionError {}

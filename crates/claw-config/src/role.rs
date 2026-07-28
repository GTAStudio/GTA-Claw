use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::str;

use serde_json::Value;

use crate::model::RoleConfig;

/// Largest role document this crate accepts, in bytes.
///
/// The frozen GTA legacy loader capped a role body at `MAX_ROLE_SIZE`, one
/// mebibyte, and `compat/legacy/ledger/behaviors.json` records that cap as
/// `behavior.role.fetch`. The same number is reused here so a document that the
/// legacy runtime accepted is not rejected by the replacement, and so no
/// transport is ever asked to buffer an unbounded response.
///
/// The legacy limit counted UTF-16 code units of the decoded body. This crate
/// counts UTF-8 bytes, which is never larger in code-unit terms, so the bound
/// is identical for ASCII documents and marginally stricter for documents that
/// are mostly non-ASCII.
pub const ROLE_DOCUMENT_MAX_BYTES: usize = 1_048_576;

/// `Accept` header value the frozen role contract requires.
pub const ROLE_FETCH_ACCEPT: &str = "application/json, text/plain";

/// Role fetch timeout in milliseconds required by the frozen role contract.
pub const ROLE_FETCH_TIMEOUT_MS: u64 = 10_000;

/// How a role body was interpreted.
///
/// The variants mirror the frozen `outcome` enumeration in
/// `compat/legacy/schemas/role-source.schema.json`, whose third value, `error`,
/// is represented here by a failed [`Result`] instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleDocumentOutcome {
    /// The body was parsed as a JSON role object.
    LoadedJson,
    /// The body was taken verbatim as the system prompt.
    LoadedPlainText,
}

/// A non-fatal observation recorded while interpreting a role document.
///
/// Every variant describes information the legacy loader logged or silently
/// discarded. Returning it instead of logging keeps this crate free of a
/// logging backend while still letting a composed daemon emit the same
/// diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleDiagnostic {
    /// A `content` member was present but was not a string, so it was ignored.
    NonStringContentIgnored,
    /// Content was taken from the `prompt` alias rather than from `content`.
    PromptAliasUsed,
    /// A `model` member was present but was not a string, so it was ignored.
    NonStringModelIgnored,
    /// A JSON parse attempt failed for a body that did not declare a JSON
    /// content type, so the whole body became the prompt.
    PlainTextFallback(RoleJsonRejection),
}

impl Display for RoleDiagnostic {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonStringContentIgnored => {
                formatter.write_str("content: ignored because it is not a string")
            }
            Self::PromptAliasUsed => {
                formatter.write_str("prompt: used because content is absent or not a string")
            }
            Self::NonStringModelIgnored => {
                formatter.write_str("model: ignored because it is not a string")
            }
            Self::PlainTextFallback(rejection) => write!(
                formatter,
                "body: used verbatim as plain text after {rejection}"
            ),
        }
    }
}

/// A role document interpreted under the frozen legacy rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleDocument {
    content: String,
    model: Option<String>,
    outcome: RoleDocumentOutcome,
    diagnostics: Vec<RoleDiagnostic>,
}

impl RoleDocument {
    /// Returns the system prompt, which is never empty for a JSON role.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Returns the optional model override exactly as the document spelled it.
    ///
    /// The value is not checked against any provider catalog, because this
    /// crate has none. A composed daemon that owns a catalog is the component
    /// that can reproduce the legacy unknown-model warning, which never
    /// rejected the role.
    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// Reports whether the body was read as JSON or as plain text.
    #[must_use]
    pub const fn outcome(&self) -> RoleDocumentOutcome {
        self.outcome
    }

    /// Returns the ordered non-fatal observations made while interpreting.
    #[must_use]
    pub fn diagnostics(&self) -> &[RoleDiagnostic] {
        &self.diagnostics
    }
}

/// Reason a JSON role body was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleJsonRejection {
    /// The body is not well-formed JSON.
    InvalidJson {
        /// Serde field path, or `<root>` for a whole-document failure.
        path: String,
        /// Decoder diagnostic including line and column.
        message: String,
    },
    /// The body is well-formed JSON but is not an object.
    NotAnObject,
    /// Neither a string `content` nor a string `prompt` member is present.
    MissingContent,
    /// The selected `content` or `prompt` value is an empty string.
    EmptyContent,
}

impl Display for RoleJsonRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson { path, message } => {
                write!(formatter, "field {path}: invalid JSON: {message}")
            }
            Self::NotAnObject => formatter.write_str("role document must be a JSON object"),
            Self::MissingContent => {
                formatter.write_str("role document must contain a string content or prompt member")
            }
            Self::EmptyContent => formatter.write_str("role content must not be an empty string"),
        }
    }
}

impl Error for RoleJsonRejection {}

/// Failure to interpret an already-fetched role body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleParseError {
    /// The body exceeds [`ROLE_DOCUMENT_MAX_BYTES`].
    TooLarge {
        /// Size of the rejected body in bytes.
        bytes: usize,
        /// Bound that was exceeded.
        limit: usize,
    },
    /// A body that declared a JSON content type is not a usable JSON role.
    Json(RoleJsonRejection),
}

impl Display for RoleParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, limit } => write!(
                formatter,
                "role document too large: {bytes} bytes exceeds the {limit} byte limit"
            ),
            Self::Json(rejection) => Display::fmt(rejection, formatter),
        }
    }
}

impl Error for RoleParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TooLarge { .. } => None,
            Self::Json(rejection) => Some(rejection),
        }
    }
}

/// Failure to load a role document through a [`RoleSourceFetcher`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleLoadError<E> {
    /// The transport adapter failed before a response existed.
    Transport(E),
    /// The response status is outside 200..=299.
    Status {
        /// Status the transport reported.
        status: u16,
    },
    /// The declared response length already exceeds [`ROLE_DOCUMENT_MAX_BYTES`].
    DeclaredTooLarge {
        /// Length the response declared, in bytes.
        declared: u64,
        /// Bound that was exceeded.
        limit: usize,
    },
    /// The response body is not UTF-8.
    NotUtf8 {
        /// Number of leading bytes that did decode.
        valid_up_to: usize,
    },
    /// The body was received but could not be interpreted as a role.
    Parse(RoleParseError),
}

impl<E: Display> Display for RoleLoadError<E> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "role fetch failed: {error}"),
            Self::Status { status } => {
                write!(formatter, "role fetch returned status {status}")
            }
            Self::DeclaredTooLarge { declared, limit } => write!(
                formatter,
                "role response declares {declared} bytes, exceeding the {limit} byte limit"
            ),
            Self::NotUtf8 { valid_up_to } => write!(
                formatter,
                "role response is not UTF-8 after {valid_up_to} bytes"
            ),
            Self::Parse(error) => Display::fmt(error, formatter),
        }
    }
}

impl<E: Error + 'static> Error for RoleLoadError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Status { .. } | Self::DeclaredTooLarge { .. } | Self::NotUtf8 { .. } => None,
            Self::Parse(error) => Some(error),
        }
    }
}

/// The single bounded role fetch that [`load_role`] delegates.
///
/// The request carries every limit the frozen contract fixes, so an adapter
/// never has to rediscover them and this crate never has to own a transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleFetchRequest<'a> {
    url: &'a str,
    accept: &'static str,
    timeout_ms: u64,
    max_bytes: usize,
}

impl<'a> RoleFetchRequest<'a> {
    /// Describes the fetch of one role URL under the frozen contract limits.
    #[must_use]
    pub const fn new(url: &'a str) -> Self {
        Self {
            url,
            accept: ROLE_FETCH_ACCEPT,
            timeout_ms: ROLE_FETCH_TIMEOUT_MS,
            max_bytes: ROLE_DOCUMENT_MAX_BYTES,
        }
    }

    /// Returns the validated absolute HTTP(S) role URL to request.
    #[must_use]
    pub const fn url(&self) -> &'a str {
        self.url
    }

    /// Returns the `Accept` header value the adapter must send.
    #[must_use]
    pub const fn accept(&self) -> &'static str {
        self.accept
    }

    /// Returns the whole-request timeout the adapter must apply.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Returns the number of response bytes the adapter may buffer.
    ///
    /// An adapter that streams more than this has already broken the bound;
    /// [`load_role`] re-checks the delivered body so an over-long response is
    /// still rejected rather than interpreted.
    #[must_use]
    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

/// A role response produced by a [`RoleSourceFetcher`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleResponse {
    status: u16,
    content_type: Option<String>,
    declared_length: Option<u64>,
    body: Vec<u8>,
}

impl RoleResponse {
    /// Creates a response with no `Content-Type` and no declared length.
    #[must_use]
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: None,
            declared_length: None,
            body: body.into(),
        }
    }

    /// Records the `Content-Type` header the origin returned.
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Records the `Content-Length` header the origin returned.
    #[must_use]
    pub const fn with_declared_length(mut self, declared_length: u64) -> Self {
        self.declared_length = Some(declared_length);
        self
    }
}

/// Transport adapter that performs the one bounded role fetch.
///
/// This crate deliberately has no HTTP client: the workspace keeps outbound
/// I/O in reviewed transport adapters. An implementation must send a GET to
/// [`RoleFetchRequest::url`] with the given `Accept` header, apply the given
/// timeout, and refuse to buffer more than [`RoleFetchRequest::max_bytes`].
pub trait RoleSourceFetcher {
    /// Transport error, which must not carry credential material.
    type Error: Error + Send + Sync + 'static;

    /// Performs one bounded role fetch.
    ///
    /// # Errors
    ///
    /// Returns the implementation's [`Self::Error`] when no response could be
    /// obtained at all, for example on DNS failure, TLS rejection, a timeout,
    /// or a response that exceeded [`RoleFetchRequest::max_bytes`] mid-stream.
    /// A response that arrived complete is returned as a [`RoleResponse`] even
    /// when its status is an error status, so status handling stays in one
    /// place.
    fn fetch(&mut self, request: RoleFetchRequest<'_>) -> Result<RoleResponse, Self::Error>;
}

/// Loads the configured role document through a transport adapter.
///
/// The URL comes from the validated [`RoleConfig`], so it is already known to
/// be an absolute HTTP(S) URL. The response status, declared length, encoding,
/// and body are all checked here, and the body is interpreted by
/// [`parse_role_document`].
///
/// # Errors
///
/// Returns [`RoleLoadError::Transport`] wrapping the adapter's own error when
/// no response was produced, [`RoleLoadError::Status`] when the response status
/// is outside 200..=299, [`RoleLoadError::DeclaredTooLarge`] when the response
/// declares more than [`ROLE_DOCUMENT_MAX_BYTES`] before the body is read,
/// [`RoleLoadError::NotUtf8`] when the delivered bytes are not UTF-8, and
/// [`RoleLoadError::Parse`] when the body is too large or is a JSON role that
/// carries no usable content. The role URL is deliberately never echoed into an
/// error, because a role URL can carry a query credential and the caller
/// already knows which URL it asked for.
pub fn load_role<F: RoleSourceFetcher>(
    fetcher: &mut F,
    role: &RoleConfig,
) -> Result<RoleDocument, RoleLoadError<F::Error>> {
    let response = fetcher
        .fetch(RoleFetchRequest::new(role.source_url()))
        .map_err(RoleLoadError::Transport)?;

    if !(200..300).contains(&response.status) {
        return Err(RoleLoadError::Status {
            status: response.status,
        });
    }

    if let Some(declared) = response.declared_length
        && usize::try_from(declared).map_or(true, |declared| declared > ROLE_DOCUMENT_MAX_BYTES)
    {
        return Err(RoleLoadError::DeclaredTooLarge {
            declared,
            limit: ROLE_DOCUMENT_MAX_BYTES,
        });
    }

    let body = str::from_utf8(&response.body).map_err(|error| RoleLoadError::NotUtf8 {
        valid_up_to: error.valid_up_to(),
    })?;

    parse_role_document(response.content_type.as_deref(), body).map_err(RoleLoadError::Parse)
}

/// Interprets an already-fetched role body under the frozen legacy rules.
///
/// A JSON parse is attempted when `content_type` names JSON or when the body
/// starts with `{`. A string `content` member wins over `prompt`; an absent or
/// non-string `content` falls back to a string `prompt`; the selected value
/// must not be empty; and a `model` member is kept only when it is a string.
/// When the JSON attempt fails and the content type did not name JSON, the
/// entire body becomes the prompt with no model, which is the legacy plain-text
/// fallback. A body that never looked like JSON takes the same plain-text path
/// without a diagnostic. A plain-text body is accepted even when it is empty,
/// which is the frozen asymmetry: only the JSON path rejects empty content.
///
/// # Errors
///
/// Returns [`RoleParseError::TooLarge`] when `body` exceeds
/// [`ROLE_DOCUMENT_MAX_BYTES`], which is fatal for both encodings because the
/// legacy loader also refused to fall back on an over-long body. When
/// `content_type` names JSON, returns [`RoleParseError::Json`] carrying
/// [`RoleJsonRejection::InvalidJson`] for a body that is not well-formed JSON,
/// [`RoleJsonRejection::NotAnObject`] for JSON that is not an object,
/// [`RoleJsonRejection::MissingContent`] when neither a string `content` nor a
/// string `prompt` member exists, and [`RoleJsonRejection::EmptyContent`] when
/// the selected member is `""`. Those four are reported instead of being
/// silently downgraded to plain text, exactly as the frozen
/// `fixtures/role/sources/json-error.json` case requires; serve the document
/// with a non-JSON content type if a verbatim body is what was intended.
pub fn parse_role_document(
    content_type: Option<&str>,
    body: &str,
) -> Result<RoleDocument, RoleParseError> {
    if body.len() > ROLE_DOCUMENT_MAX_BYTES {
        return Err(RoleParseError::TooLarge {
            bytes: body.len(),
            limit: ROLE_DOCUMENT_MAX_BYTES,
        });
    }

    let names_json = content_type.is_some_and(names_json);
    if names_json || body.trim_start().starts_with('{') {
        match parse_json_role(body) {
            Ok(document) => return Ok(document),
            Err(rejection) if names_json => return Err(RoleParseError::Json(rejection)),
            Err(rejection) => {
                return Ok(plain_text_role(
                    body,
                    Some(RoleDiagnostic::PlainTextFallback(rejection)),
                ));
            }
        }
    }

    Ok(plain_text_role(body, None))
}

/// Case-insensitive `json` substring test that does not allocate a lowercased
/// copy of the header. Content types are short, so the win is the allocation,
/// not the scan; the first-byte guard keeps the negative case (every header that
/// is not JSON) at one comparison per position rather than four.
fn names_json(content_type: &str) -> bool {
    content_type
        .as_bytes()
        .windows(4)
        .any(|window| window[0].eq_ignore_ascii_case(&b'j') && window.eq_ignore_ascii_case(b"json"))
}

/// Normalizes the two paths `serde_path_to_error` reports for a failure that it
/// could not attribute to any field, so a whole-document rejection always reads
/// the same as it does elsewhere in this crate.
fn located_path(path: &str) -> String {
    if path.is_empty() || path == "?" {
        "<root>".to_owned()
    } else {
        path.to_owned()
    }
}

fn plain_text_role(body: &str, diagnostic: Option<RoleDiagnostic>) -> RoleDocument {
    RoleDocument {
        content: body.to_owned(),
        model: None,
        outcome: RoleDocumentOutcome::LoadedPlainText,
        diagnostics: diagnostic.into_iter().collect(),
    }
}

fn parse_json_role(body: &str) -> Result<RoleDocument, RoleJsonRejection> {
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let value: Value = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        RoleJsonRejection::InvalidJson {
            path: located_path(&error.path().to_string()),
            message: error.inner().to_string(),
        }
    })?;
    deserializer
        .end()
        .map_err(|error| RoleJsonRejection::InvalidJson {
            path: "<root>".to_owned(),
            message: error.to_string(),
        })?;

    let Value::Object(mut members) = value else {
        return Err(RoleJsonRejection::NotAnObject);
    };

    let mut diagnostics = Vec::new();
    // Taken out of the map rather than borrowed and cloned: the selected member
    // is the whole system prompt, which the frozen contract lets run to
    // `ROLE_DOCUMENT_MAX_BYTES`, so cloning it doubled the peak footprint of
    // every JSON role fetch for nothing.
    let content = match members.remove("content") {
        Some(Value::String(content)) => content,
        present => {
            if present.is_some() {
                diagnostics.push(RoleDiagnostic::NonStringContentIgnored);
            }
            match members.remove("prompt") {
                Some(Value::String(prompt)) => {
                    diagnostics.push(RoleDiagnostic::PromptAliasUsed);
                    prompt
                }
                _ => return Err(RoleJsonRejection::MissingContent),
            }
        }
    };
    if content.is_empty() {
        return Err(RoleJsonRejection::EmptyContent);
    }

    let model = match members.remove("model") {
        Some(Value::String(model)) => Some(model),
        Some(_) => {
            diagnostics.push(RoleDiagnostic::NonStringModelIgnored);
            None
        }
        None => None,
    };

    Ok(RoleDocument {
        content,
        model,
        outcome: RoleDocumentOutcome::LoadedJson,
        diagnostics,
    })
}

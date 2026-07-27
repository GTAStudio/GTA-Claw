//! GitHub Copilot, implemented in pure Rust.
//!
//! Neither `github-copilot-sdk` nor the Copilot CLI appears anywhere in this
//! crate's dependency graph. Authentication is an RFC 8628 OAuth 2.0 device
//! authorization grant spoken directly over `hyper`/`rustls`, followed by the
//! Copilot token exchange; the chat surface is the `OpenAI` dialect with the
//! editor headers Copilot requires.
//!
//! The flow is:
//!
//! 1. `POST https://github.com/login/device/code` returns a user code and a
//!    verification URI the human visits.
//! 2. `POST https://github.com/login/oauth/access_token` is polled at the
//!    server-dictated interval until it yields a GitHub OAuth token.
//! 3. `GET https://api.github.com/copilot_internal/v2/token` exchanges that
//!    long-lived token for a short-lived Copilot token plus the API endpoint.
//! 4. `POST {endpoint}/chat/completions` serves completions and streams.
//!
//! Steps 1-3 are separated from step 4 so an application can persist only the
//! GitHub OAuth token and let this client refresh the short-lived one.

use std::sync::Arc;
use std::time::Duration;

use claw_provider_sdk::cancel::CancelToken;
use claw_provider_sdk::clock::Clock;
use claw_provider_sdk::error::{ErrorKind, Operation, ProviderError};
use claw_provider_sdk::http::{Body, HttpRequest, Method, TlsPolicy, is_loopback};
use claw_provider_sdk::model::{
    Capability, CapabilitySet, CompletionRequest, CompletionResponse, ContentPart, ModelDescriptor,
    ModelId, ProviderId,
};
use claw_provider_sdk::origin::{BoundSecret, Origin, OriginApproval, TrustedOrigins};
use claw_provider_sdk::provider::{BoxFuture, Provider, RequestContext};
use claw_provider_sdk::secret::SecretString;
use claw_provider_sdk::stream::CompletionStream;
use serde::Deserialize;
use tokio::sync::RwLock;
use url::Url;

use crate::openai_compatible::{decode_completion, events_from_chunks};
use crate::runtime::{ProviderRuntime, ReliabilityConfig};

/// Device authorization endpoint.
pub const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";

/// Device access-token endpoint.
pub const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";

/// Copilot token exchange endpoint.
pub const COPILOT_TOKEN_URL: &str = "https://api.github.com/copilot_internal/v2/token";

/// Fallback Copilot API endpoint, used when the exchange omits `endpoints.api`.
pub const DEFAULT_API_BASE_URL: &str = "https://api.githubcopilot.com";

/// Public OAuth client identifier published by the GitHub Copilot editor
/// integration.
///
/// This is a public client id, not a secret: RFC 8628 device flow clients have
/// no client secret. It is configurable because GitHub can rotate it.
pub const DEFAULT_CLIENT_ID: &str = "Iv1.b507a08c87ecfe98";

/// Scope requested by the device flow.
pub const DEFAULT_SCOPE: &str = "read:user";

/// Grant type constant from RFC 8628 section 3.4.
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Default `Copilot-Integration-Id` header value.
pub const DEFAULT_INTEGRATION_ID: &str = "vscode-chat";

/// Default `Editor-Version` header value.
pub const DEFAULT_EDITOR_VERSION: &str = "GTAClaw/0.1.0";

/// Default `Editor-Plugin-Version` header value.
pub const DEFAULT_EDITOR_PLUGIN_VERSION: &str = "claw-providers/0.1.0";

/// Seconds of headroom applied before a Copilot token's stated expiry.
pub const TOKEN_REFRESH_SKEW_SECONDS: u64 = 120;

/// Minimum poll interval enforced regardless of what the server reports.
pub const MIN_POLL_INTERVAL_SECONDS: u64 = 1;

/// Extra seconds added to the poll interval when the server says `slow_down`.
pub const SLOW_DOWN_INCREMENT_SECONDS: u64 = 5;

/// Capabilities the Copilot client can drive.
const CAPABILITIES: CapabilitySet = crate::descriptor::COPILOT_CAPABILITIES;

const PROVIDER: &str = "github-copilot";

fn provider_error(kind: ErrorKind, operation: Operation, detail: impl AsRef<str>) -> ProviderError {
    ProviderError::new(kind, PROVIDER, operation, detail)
}

fn parse_url(raw: &str, operation: Operation) -> Result<Url, ProviderError> {
    raw.parse().map_err(|error| {
        provider_error(
            ErrorKind::InvalidRequest,
            operation,
            format!("`{raw}` is not a valid URL: {error}"),
        )
    })
}

// ---------------------------------------------------------------------------
// Device authorization grant
// ---------------------------------------------------------------------------

/// The pending authorization returned by the device-code endpoint.
///
/// `device_code` is credential material and is therefore held as a
/// [`SecretString`]; `user_code` and `verification_uri` are meant to be shown to
/// the human and are plain strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceAuthorization {
    /// Secret code the client presents when polling.
    pub device_code: SecretString,
    /// Short code the human types into `verification_uri`.
    pub user_code: String,
    /// Page the human opens to approve the request.
    pub verification_uri: String,
    /// Lifetime of the authorization, in seconds.
    pub expires_in: u64,
    /// Server-requested polling interval, in seconds.
    pub interval: u64,
}

/// Raw wire shape. Deliberately has no `Debug`: every one of these carries a
/// credential in cleartext, and a derived `Debug` would print it.
#[derive(Deserialize)]
struct WireDeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    expires_in: u64,
    #[serde(default)]
    interval: u64,
}

/// Decodes a device-code response.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the payload is not a device
/// authorization, or the typed OAuth error the server reported.
pub fn decode_device_authorization(body: &[u8]) -> Result<DeviceAuthorization, ProviderError> {
    if let Some(error) = decode_oauth_error(body, Operation::Authorize) {
        return Err(error);
    }
    let wire: WireDeviceAuthorization = serde_json::from_slice(body).map_err(|error| {
        provider_error(
            ErrorKind::Protocol,
            Operation::Authorize,
            format!("the device authorization response could not be parsed: {error}"),
        )
    })?;
    if wire.device_code.is_empty() || wire.user_code.is_empty() {
        return Err(provider_error(
            ErrorKind::Protocol,
            Operation::Authorize,
            "the device authorization response omitted a code",
        ));
    }
    Ok(DeviceAuthorization {
        device_code: SecretString::new(wire.device_code),
        user_code: wire.user_code,
        verification_uri: wire.verification_uri,
        expires_in: wire.expires_in,
        interval: wire.interval.max(MIN_POLL_INTERVAL_SECONDS),
    })
}

/// Outcome of a single poll of the access-token endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DevicePollOutcome {
    /// The human has not approved the request yet.
    Pending,
    /// The client polled too fast; the interval must grow.
    SlowDown,
    /// Authorization completed and produced a GitHub OAuth token.
    Granted(SecretString),
}

#[derive(Debug, Deserialize)]
struct WireOauthError {
    error: String,
    #[serde(default)]
    error_description: String,
}

/// Raw wire shape. Deliberately has no `Debug`: every one of these carries a
/// credential in cleartext, and a derived `Debug` would print it.
#[derive(Deserialize)]
struct WireAccessToken {
    access_token: String,
}

fn decode_oauth_error(body: &[u8], operation: Operation) -> Option<ProviderError> {
    let wire: WireOauthError = serde_json::from_slice(body).ok()?;
    if wire.error.is_empty() {
        return None;
    }
    let detail = if wire.error_description.is_empty() {
        wire.error.clone()
    } else {
        wire.error_description.clone()
    };
    Some(
        provider_error(oauth_error_kind(&wire.error), operation, detail)
            .with_upstream_code(&wire.error),
    )
}

/// Maps an OAuth 2.0 `error` code onto the portable taxonomy.
#[must_use]
pub fn oauth_error_kind(code: &str) -> ErrorKind {
    match code {
        "authorization_pending" | "slow_down" => ErrorKind::RateLimit,
        "access_denied"
        | "device_flow_disabled"
        | "expired_token"
        | "incorrect_client_credentials"
        | "incorrect_device_code"
        | "invalid_client"
        | "invalid_grant"
        | "unauthorized_client" => ErrorKind::Authentication,
        "unsupported_grant_type" | "invalid_request" => ErrorKind::InvalidRequest,
        _ => ErrorKind::Protocol,
    }
}

/// Decodes one poll of the access-token endpoint.
///
/// `authorization_pending` and `slow_down` are protocol-level "keep waiting"
/// signals rather than failures, so they are returned as
/// [`DevicePollOutcome`] values instead of errors.
///
/// # Errors
///
/// Returns the typed error for any terminal OAuth error code, and
/// [`ErrorKind::Protocol`] when the payload is neither an error nor a token.
pub fn decode_device_poll(body: &[u8]) -> Result<DevicePollOutcome, ProviderError> {
    if let Ok(wire) = serde_json::from_slice::<WireOauthError>(body) {
        match wire.error.as_str() {
            "" => {}
            "authorization_pending" => return Ok(DevicePollOutcome::Pending),
            "slow_down" => return Ok(DevicePollOutcome::SlowDown),
            code => {
                let detail = if wire.error_description.is_empty() {
                    code.to_owned()
                } else {
                    wire.error_description.clone()
                };
                return Err(
                    provider_error(oauth_error_kind(code), Operation::Authorize, detail)
                        .with_upstream_code(code),
                );
            }
        }
    }
    let wire: WireAccessToken = serde_json::from_slice(body).map_err(|error| {
        provider_error(
            ErrorKind::Protocol,
            Operation::Authorize,
            format!("the access-token response could not be parsed: {error}"),
        )
    })?;
    if wire.access_token.is_empty() {
        return Err(provider_error(
            ErrorKind::Protocol,
            Operation::Authorize,
            "the access-token response carried an empty token",
        ));
    }
    Ok(DevicePollOutcome::Granted(SecretString::new(
        wire.access_token,
    )))
}

/// Builds the form body of the device-code request.
#[must_use]
pub fn encode_device_code_form(client_id: &str, scope: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("scope", scope)
        .finish()
}

/// Builds the form body of an access-token poll.
#[must_use]
pub fn encode_device_poll_form(client_id: &str, device_code: &SecretString) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", client_id)
        .append_pair("device_code", device_code.expose())
        .append_pair("grant_type", DEVICE_CODE_GRANT_TYPE)
        .finish()
}

/// Origins GitHub Copilot may present a credential to without enrollment.
///
/// A long-lived GitHub OAuth token is exchanged at
/// [`COPILOT_TOKEN_URL`] and the resulting Copilot token is spent at
/// [`DEFAULT_API_BASE_URL`]. Both URLs used to be free-form configuration, and
/// TLS only proves that the named host owns its certificate — it does not prove
/// the host is GitHub. Pinning the origins is what stops a tampered
/// configuration from exfiltrating those credentials.
///
/// GitHub Enterprise and other self-hosted deployments are supported through
/// [`GitHubCopilotConfig::approved_origins`].
pub const TRUSTED_ORIGINS: [&str; 3] = [
    "https://github.com",
    "https://api.github.com",
    "https://api.githubcopilot.com",
];

/// Builds the pinned trust set, widened by any enrolled origins.
fn trust_set(approvals: &[OriginApproval]) -> Result<TrustedOrigins, ProviderError> {
    let mut trusted = TrustedOrigins::pinned(&TRUSTED_ORIGINS).map_err(|error| {
        provider_error(
            ErrorKind::InvalidRequest,
            Operation::Authorize,
            format!("a pinned Copilot origin does not parse: {error}"),
        )
    })?;
    for approval in approvals {
        trusted = trusted.enrolled(approval);
    }
    Ok(trusted)
}

/// Authorizes `url` against `trusted`, naming the credential that is at risk.
fn authorize_origin(
    trusted: &TrustedOrigins,
    url: &Url,
    what: &str,
) -> Result<Origin, ProviderError> {
    trusted.authorize(url).map_err(|error| {
        provider_error(
            ErrorKind::Authentication,
            Operation::Authorize,
            format!("refusing to send the {what} to an untrusted origin: {error}"),
        )
    })
}

/// Configuration of the device authorization grant.
#[derive(Debug)]
pub struct DeviceFlowConfig {
    /// Public OAuth client identifier.
    pub client_id: String,
    /// Requested scope.
    pub scope: String,
    /// Device-code endpoint.
    pub device_code_url: Url,
    /// Access-token endpoint.
    pub access_token_url: Url,
    /// Origins the operator deliberately enrolled beyond [`TRUSTED_ORIGINS`].
    ///
    /// The device flow mints a GitHub OAuth token, so the endpoints that mint
    /// it are as sensitive as the ones that spend it.
    pub approved_origins: Vec<OriginApproval>,
    /// Reliability policies applied to both endpoints.
    pub reliability: ReliabilityConfig,
}

impl DeviceFlowConfig {
    /// Builds the configuration for github.com.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidRequest`] if the pinned endpoint constants
    /// ever stop parsing, which the accompanying test rules out.
    pub fn github() -> Result<Self, ProviderError> {
        Ok(Self {
            client_id: DEFAULT_CLIENT_ID.to_owned(),
            scope: DEFAULT_SCOPE.to_owned(),
            device_code_url: parse_url(DEVICE_CODE_URL, Operation::Authorize)?,
            access_token_url: parse_url(ACCESS_TOKEN_URL, Operation::Authorize)?,
            approved_origins: Vec::new(),
            reliability: ReliabilityConfig::default(),
        })
    }
}

/// Drives the OAuth 2.0 device authorization grant against GitHub.
#[derive(Debug)]
pub struct DeviceFlow {
    client_id: String,
    scope: String,
    device_code_url: Url,
    access_token_url: Url,
    runtime: ProviderRuntime,
}

impl DeviceFlow {
    /// Builds a device flow.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when either endpoint is not a
    /// [`TRUSTED_ORIGINS`] entry or an enrolled origin, and
    /// [`ErrorKind::Transport`] when the TLS stack cannot be built.
    pub fn new(config: DeviceFlowConfig) -> Result<Self, ProviderError> {
        let trusted = trust_set(&config.approved_origins)?;
        authorize_origin(
            &trusted,
            &config.device_code_url,
            "device authorization request",
        )?;
        authorize_origin(&trusted, &config.access_token_url, "device code")?;
        let policy = tls_policy_for(&[&config.device_code_url, &config.access_token_url]);
        Ok(Self {
            runtime: ProviderRuntime::new(PROVIDER, policy, config.reliability)?,
            client_id: config.client_id,
            scope: config.scope,
            device_code_url: config.device_code_url,
            access_token_url: config.access_token_url,
        })
    }

    /// Builds a device flow against github.com.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidRequest`] if the pinned github.com endpoint
    /// constants ever stop parsing, and [`ErrorKind::Transport`] when the TLS
    /// stack cannot be built.
    pub fn github() -> Result<Self, ProviderError> {
        Self::new(DeviceFlowConfig::github()?)
    }

    /// Returns the configured client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Replaces the reliability runtime.
    ///
    /// This is the seam tests use to drive polling with a
    /// [`claw_provider_sdk::clock::ManualClock`] instead of real time.
    #[must_use]
    pub fn with_runtime(mut self, runtime: ProviderRuntime) -> Self {
        self.runtime = runtime;
        self
    }

    /// Requests a device code the human can approve.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Transport`] when the device-code endpoint cannot be
    /// reached, [`ErrorKind::Cancelled`] when `cancel` fires, the typed error
    /// for the OAuth `error` code the server returned, and
    /// [`ErrorKind::Protocol`] when the reply is not a device authorization.
    pub async fn start(&self, cancel: &CancelToken) -> Result<DeviceAuthorization, ProviderError> {
        let form = encode_device_code_form(&self.client_id, &self.scope);
        let response = self
            .runtime
            .execute(Operation::Authorize, cancel, || {
                Ok(HttpRequest::new(Method::Post, self.device_code_url.clone())
                    .header("accept", "application/json")
                    .body(Body::Form(form.clone())))
            })
            .await?;
        decode_device_authorization(response.body())
    }

    /// Polls the access-token endpoint exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Transport`] when the access-token endpoint cannot
    /// be reached, [`ErrorKind::Cancelled`] when `cancel` fires, the typed
    /// error for a terminal OAuth `error` code such as `access_denied` or
    /// `expired_token`, and [`ErrorKind::Protocol`] when the reply is neither
    /// an error nor a token. `authorization_pending` and `slow_down` are
    /// reported as [`DevicePollOutcome`] values, not errors.
    pub async fn poll_once(
        &self,
        device_code: &SecretString,
        cancel: &CancelToken,
    ) -> Result<DevicePollOutcome, ProviderError> {
        let form = encode_device_poll_form(&self.client_id, device_code);
        let response = self
            .runtime
            .execute(Operation::Authorize, cancel, || {
                Ok(
                    HttpRequest::new(Method::Post, self.access_token_url.clone())
                        .header("accept", "application/json")
                        .body(Body::Form(form.clone())),
                )
            })
            .await?;
        decode_device_poll(response.body())
    }

    /// Polls until the human approves, the grant expires, or `cancel` fires.
    ///
    /// The interval starts at the server-dictated value and grows by
    /// [`SLOW_DOWN_INCREMENT_SECONDS`] each time the server answers `slow_down`,
    /// as RFC 8628 section 3.5 requires.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Cancelled`] when `cancel` fires, an
    /// [`ErrorKind::Authentication`] error when the grant expires, or the typed
    /// OAuth error.
    pub async fn wait_for_token(
        &self,
        authorization: &DeviceAuthorization,
        cancel: &CancelToken,
    ) -> Result<SecretString, ProviderError> {
        let clock = self.runtime.clock();
        let deadline = clock
            .now_millis()
            .saturating_add(authorization.expires_in.saturating_mul(1_000));
        let mut interval = authorization.interval.max(MIN_POLL_INTERVAL_SECONDS);
        loop {
            if cancel.is_cancelled() {
                return Err(provider_error(
                    ErrorKind::Cancelled,
                    Operation::Authorize,
                    "the device authorization was cancelled",
                ));
            }
            if authorization.expires_in > 0 && clock.now_millis() >= deadline {
                return Err(provider_error(
                    ErrorKind::Authentication,
                    Operation::Authorize,
                    "the device authorization expired before it was approved",
                )
                .with_upstream_code("expired_token"));
            }
            clock.sleep(Duration::from_secs(interval)).await;
            match self.poll_once(&authorization.device_code, cancel).await? {
                DevicePollOutcome::Granted(token) => return Ok(token),
                DevicePollOutcome::Pending => {}
                DevicePollOutcome::SlowDown => {
                    interval = interval.saturating_add(SLOW_DOWN_INCREMENT_SECONDS);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Copilot token exchange
// ---------------------------------------------------------------------------

/// A short-lived Copilot API token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopilotToken {
    /// Bearer value sent to the Copilot API.
    pub token: SecretString,
    /// Absolute expiry, in seconds since the Unix epoch.
    pub expires_at: u64,
    /// Endpoint the exchange nominated for chat traffic, if any.
    pub api_endpoint: Option<Url>,
}

impl CopilotToken {
    /// Returns `true` when the token is within
    /// [`TOKEN_REFRESH_SKEW_SECONDS`] of expiry at `now_seconds`.
    #[must_use]
    pub const fn is_expired(&self, now_seconds: u64) -> bool {
        now_seconds.saturating_add(TOKEN_REFRESH_SKEW_SECONDS) >= self.expires_at
    }
}

#[derive(Debug, Deserialize)]
struct WireEndpoints {
    #[serde(default)]
    api: Option<String>,
}

/// Raw wire shape. Deliberately has no `Debug`: every one of these carries a
/// credential in cleartext, and a derived `Debug` would print it.
#[derive(Deserialize)]
struct WireCopilotToken {
    token: String,
    #[serde(default)]
    expires_at: u64,
    #[serde(default)]
    endpoints: Option<WireEndpoints>,
}

/// Decodes a Copilot token-exchange response.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the payload is not a token document and
/// [`ErrorKind::InvalidRequest`] when the nominated endpoint is not a URL.
pub fn decode_copilot_token(body: &[u8]) -> Result<CopilotToken, ProviderError> {
    let wire: WireCopilotToken = serde_json::from_slice(body).map_err(|error| {
        provider_error(
            ErrorKind::Protocol,
            Operation::Authorize,
            format!("the Copilot token response could not be parsed: {error}"),
        )
    })?;
    if wire.token.is_empty() {
        return Err(provider_error(
            ErrorKind::Protocol,
            Operation::Authorize,
            "the Copilot token response carried an empty token",
        ));
    }
    let api_endpoint = match wire.endpoints.and_then(|endpoints| endpoints.api) {
        Some(raw) if !raw.is_empty() => Some(parse_url(&raw, Operation::Authorize)?),
        _ => None,
    };
    Ok(CopilotToken {
        token: SecretString::new(wire.token),
        expires_at: wire.expires_at,
        api_endpoint,
    })
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

fn tls_policy_for(urls: &[&Url]) -> TlsPolicy {
    if urls
        .iter()
        .any(|url| url.scheme() == "http" && is_loopback(url))
    {
        TlsPolicy::AllowLoopbackPlaintext
    } else {
        TlsPolicy::RequireHttps
    }
}

/// Configuration of the Copilot chat client.
#[derive(Debug)]
pub struct GitHubCopilotConfig {
    /// GitHub OAuth token produced by [`DeviceFlow::wait_for_token`].
    pub github_token: SecretString,
    /// Token-exchange endpoint.
    pub token_exchange_url: Url,
    /// Overrides the chat endpoint the exchange nominates.
    pub api_base_url: Option<Url>,
    /// Origins the operator deliberately enrolled beyond [`TRUSTED_ORIGINS`].
    ///
    /// This is how a GitHub Enterprise deployment authorises its own
    /// token-exchange and chat hosts. An approval must come from a human
    /// decision; deriving one from the same configuration that supplies
    /// `token_exchange_url` or `api_base_url` defeats the check entirely.
    pub approved_origins: Vec<OriginApproval>,
    /// `Copilot-Integration-Id` header value.
    pub integration_id: String,
    /// `Editor-Version` header value.
    pub editor_version: String,
    /// `Editor-Plugin-Version` header value.
    pub editor_plugin_version: String,
    /// Reliability policies.
    pub reliability: ReliabilityConfig,
}

impl GitHubCopilotConfig {
    /// Builds the default configuration for a GitHub OAuth token.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidRequest`] if the pinned endpoint constant
    /// ever stops parsing, which the accompanying test rules out.
    pub fn new(github_token: SecretString) -> Result<Self, ProviderError> {
        Ok(Self {
            github_token,
            token_exchange_url: parse_url(COPILOT_TOKEN_URL, Operation::Authorize)?,
            api_base_url: None,
            approved_origins: Vec::new(),
            integration_id: DEFAULT_INTEGRATION_ID.to_owned(),
            editor_version: DEFAULT_EDITOR_VERSION.to_owned(),
            editor_plugin_version: DEFAULT_EDITOR_PLUGIN_VERSION.to_owned(),
            reliability: ReliabilityConfig::default(),
        })
    }
}

/// The GitHub Copilot chat provider.
#[derive(Debug)]
pub struct GitHubCopilot {
    id: ProviderId,
    github_token: BoundSecret,
    token_exchange_url: Url,
    configured_api_base_url: Option<Url>,
    fallback_api_base_url: Url,
    trusted: TrustedOrigins,
    integration_id: String,
    editor_version: String,
    editor_plugin_version: String,
    cached: RwLock<Option<CopilotToken>>,
    runtime: ProviderRuntime,
}

impl GitHubCopilot {
    /// Builds a Copilot client.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when the GitHub token is empty or
    /// when the token-exchange or chat endpoint is not a
    /// [`TRUSTED_ORIGINS`] entry or an enrolled origin, and
    /// [`ErrorKind::Transport`] when the TLS stack cannot be built.
    pub fn new(config: GitHubCopilotConfig) -> Result<Self, ProviderError> {
        if config.github_token.is_empty() {
            return Err(provider_error(
                ErrorKind::Authentication,
                Operation::Authorize,
                "GitHub Copilot requires a GitHub OAuth token",
            ));
        }
        let trusted = trust_set(&config.approved_origins)?;
        // The GitHub OAuth token is the credential at risk here: it is
        // long-lived and grants far more than chat. Bind it to the exchange
        // origin so it is unusable anywhere else.
        let exchange_origin =
            authorize_origin(&trusted, &config.token_exchange_url, "GitHub OAuth token")?;
        if let Some(base) = config.api_base_url.as_ref() {
            authorize_origin(&trusted, base, "Copilot token")?;
        }
        let fallback_api_base_url = parse_url(DEFAULT_API_BASE_URL, Operation::Authorize)?;
        let mut urls: Vec<&Url> = vec![&config.token_exchange_url];
        if let Some(base) = config.api_base_url.as_ref() {
            urls.push(base);
        }
        let policy = tls_policy_for(&urls);
        Ok(Self {
            id: ProviderId::new(PROVIDER).map_err(|error| {
                provider_error(
                    ErrorKind::InvalidRequest,
                    Operation::Authorize,
                    error.to_string(),
                )
            })?,
            github_token: BoundSecret::new(exchange_origin, config.github_token),
            token_exchange_url: config.token_exchange_url,
            configured_api_base_url: config.api_base_url,
            fallback_api_base_url,
            trusted,
            integration_id: config.integration_id,
            editor_version: config.editor_version,
            editor_plugin_version: config.editor_plugin_version,
            cached: RwLock::new(None),
            runtime: ProviderRuntime::new(PROVIDER, policy, config.reliability)?,
        })
    }

    /// Builds a Copilot client from a GitHub OAuth token.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when `github_token` is empty once
    /// trimmed, and [`ErrorKind::Transport`] when the TLS stack cannot be
    /// built.
    pub fn with_github_token(github_token: SecretString) -> Result<Self, ProviderError> {
        Self::new(GitHubCopilotConfig::new(github_token)?)
    }

    /// Returns the cached Copilot token, if one has been fetched and is fresh.
    pub async fn cached_token(&self) -> Option<CopilotToken> {
        let now = self.now_seconds();
        self.cached
            .read()
            .await
            .clone()
            .filter(|token| !token.is_expired(now))
    }

    /// Discards any cached Copilot token, forcing the next call to re-exchange.
    pub async fn invalidate_token(&self) {
        *self.cached.write().await = None;
    }

    /// Replaces the reliability runtime.
    ///
    /// This is the seam tests use to drive token expiry and retry policies with
    /// a [`claw_provider_sdk::clock::ManualClock`] instead of real time.
    #[must_use]
    pub fn with_runtime(mut self, runtime: ProviderRuntime) -> Self {
        self.runtime = runtime;
        self
    }

    fn now_seconds(&self) -> u64 {
        self.runtime.clock().now_millis() / 1_000
    }

    /// Exchanges the GitHub OAuth token for a Copilot token, bypassing the cache.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Authentication`] when GitHub rejects the token,
    /// [`ErrorKind::Transport`] when the exchange endpoint cannot be reached,
    /// [`ErrorKind::Cancelled`] when `cancel` fires, and
    /// [`ErrorKind::Protocol`] when the reply is not a Copilot token
    /// document.
    pub async fn exchange_token(
        &self,
        cancel: &CancelToken,
    ) -> Result<CopilotToken, ProviderError> {
        let response = self
            .runtime
            .execute(Operation::Authorize, cancel, || {
                HttpRequest::new(Method::Get, self.token_exchange_url.clone())
                    .header("accept", "application/json")
                    .header("editor-version", self.editor_version.clone())
                    .header("editor-plugin-version", self.editor_plugin_version.clone())
                    .bound_secret_header("authorization", "token ", &self.github_token)
                    .map_err(|error| {
                        provider_error(
                            ErrorKind::Authentication,
                            Operation::Authorize,
                            format!(
                                "the GitHub OAuth token is not authorised for this \
                                 exchange endpoint: {error}"
                            ),
                        )
                    })
            })
            .await?;
        decode_copilot_token(response.body())
    }

    async fn token(&self, cancel: &CancelToken) -> Result<CopilotToken, ProviderError> {
        if let Some(token) = self.cached_token().await {
            return Ok(token);
        }
        let fetched = self.exchange_token(cancel).await?;
        *self.cached.write().await = Some(fetched.clone());
        Ok(fetched)
    }

    /// Resolves the chat endpoint and binds the Copilot token to it.
    ///
    /// The endpoint can come from configuration or from the exchange
    /// response, so both are checked against the trust set. A compromised or
    /// impersonated exchange could otherwise nominate any host and the
    /// Copilot token would follow it there.
    fn api_base(&self, token: &CopilotToken) -> Result<(Url, BoundSecret), ProviderError> {
        let base = self
            .configured_api_base_url
            .clone()
            .or_else(|| token.api_endpoint.clone())
            .unwrap_or_else(|| self.fallback_api_base_url.clone());
        let origin = authorize_origin(&self.trusted, &base, "Copilot token")?;
        Ok((base, BoundSecret::new(origin, token.token.clone())))
    }

    fn endpoint(&self, token: &CopilotToken, path: &str) -> Result<Url, ProviderError> {
        let (base, _) = self.api_base(token)?;
        let trimmed = base.as_str().trim_end_matches('/');
        parse_url(&format!("{trimmed}/{path}"), Operation::Transport)
    }

    fn request(
        &self,
        method: Method,
        url: Url,
        token: &CopilotToken,
        vision: bool,
    ) -> Result<HttpRequest, ProviderError> {
        let (_, bound) = self.api_base(token)?;
        let mut request = HttpRequest::new(method, url)
            .header("accept", "application/json")
            .header("copilot-integration-id", self.integration_id.clone())
            .header("editor-version", self.editor_version.clone())
            .header("editor-plugin-version", self.editor_plugin_version.clone())
            .bound_secret_header("authorization", "Bearer ", &bound)
            .map_err(|error| {
                provider_error(
                    ErrorKind::Authentication,
                    Operation::Authorize,
                    format!("the Copilot token is not authorised for this endpoint: {error}"),
                )
            })?;
        if vision {
            request = request.header("copilot-vision-request", "true");
        }
        Ok(request)
    }
}

/// Returns `true` when any user turn carries an image part.
///
/// Copilot gates multimodal prompts behind the `Copilot-Vision-Request` header,
/// so the header is sent only when the payload actually needs it.
#[must_use]
pub fn requires_vision(request: &CompletionRequest) -> bool {
    request.messages.iter().any(|message| match message {
        claw_provider_sdk::model::ChatMessage::User(parts) => parts
            .iter()
            .any(|part| matches!(part, ContentPart::Image(_))),
        claw_provider_sdk::model::ChatMessage::Assistant(assistant) => assistant
            .content
            .iter()
            .any(|part| matches!(part, ContentPart::Image(_))),
        _ => false,
    })
}

impl Provider for GitHubCopilot {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn capabilities(&self) -> CapabilitySet {
        CAPABILITIES
    }

    fn complete<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionResponse, ProviderError>> {
        Box::pin(async move {
            let token = self.token(context.cancel()).await?;
            let url = self.endpoint(&token, "chat/completions")?;
            let body = crate::openai_compatible::encode_completion(request, false, false)?;
            let vision = requires_vision(request);
            let response = self
                .runtime
                .execute(Operation::Complete, context.cancel(), || {
                    Ok(self
                        .request(Method::Post, url.clone(), &token, vision)?
                        .body(Body::Json(body.clone())))
                })
                .await?;
            decode_completion(PROVIDER, response.body())
        })
    }

    fn stream<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionStream, ProviderError>> {
        Box::pin(async move {
            let token = self.token(context.cancel()).await?;
            let url = self.endpoint(&token, "chat/completions")?;
            let body = crate::openai_compatible::encode_completion(request, true, true)?;
            let vision = requires_vision(request);
            let cancel = context.cancel().clone();
            let stream = self
                .runtime
                .execute_streaming(Operation::StreamCompletion, &cancel, || {
                    Ok(self
                        .request(Method::Post, url.clone(), &token, vision)?
                        .replace_header("accept", "text/event-stream")
                        .body(Body::Json(body.clone())))
                })
                .await?;
            Ok(events_from_chunks(PROVIDER, cancel, stream.into_chunks()))
        })
    }

    fn list_models<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<Vec<ModelDescriptor>, ProviderError>> {
        Box::pin(async move {
            let token = self.token(context.cancel()).await?;
            let url = self.endpoint(&token, "models")?;
            let response = self
                .runtime
                .execute(Operation::ListModels, context.cancel(), || {
                    self.request(Method::Get, url.clone(), &token, false)
                })
                .await?;
            decode_models(response.body())
        })
    }
}

// ---------------------------------------------------------------------------
// Model catalogue
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "this mirrors Copilot's `capabilities.supports` object one field per \
              wire key; the flags are independent booleans upstream, so folding \
              them into an enum would invent a state machine the API does not have"
)]
struct WireSupports {
    #[serde(default)]
    streaming: bool,
    #[serde(default)]
    tool_calls: bool,
    #[serde(default)]
    vision: bool,
    #[serde(default)]
    structured_outputs: bool,
}

#[derive(Debug, Default, Deserialize)]
struct WireLimits {
    #[serde(default)]
    max_context_window_tokens: Option<u32>,
    #[serde(default)]
    max_output_tokens: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct WireCapabilities {
    #[serde(default)]
    supports: WireSupports,
    #[serde(default)]
    limits: WireLimits,
}

#[derive(Debug, Deserialize)]
struct WireModel {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    capabilities: WireCapabilities,
}

#[derive(Debug, Deserialize)]
struct WireModelList {
    data: Vec<WireModel>,
}

/// Decodes the Copilot model catalogue.
///
/// Copilot publishes per-model capability and limit metadata, so unlike the
/// plain `OpenAI` catalogue these descriptors carry real capability bits rather
/// than an empty set.
///
/// # Errors
///
/// Returns [`ErrorKind::Protocol`] when the document does not match the dialect.
pub fn decode_models(body: &[u8]) -> Result<Vec<ModelDescriptor>, ProviderError> {
    let wire: WireModelList = serde_json::from_slice(body).map_err(|error| {
        provider_error(
            ErrorKind::Protocol,
            Operation::ListModels,
            format!("the model list could not be parsed: {error}"),
        )
    })?;
    wire.data
        .into_iter()
        .map(|model| {
            let mut capabilities = vec![Capability::Completion];
            if model.capabilities.supports.streaming {
                capabilities.push(Capability::Streaming);
            }
            if model.capabilities.supports.tool_calls {
                capabilities.push(Capability::ToolCalling);
            }
            if model.capabilities.supports.vision {
                capabilities.push(Capability::Vision);
            }
            if model.capabilities.supports.structured_outputs {
                capabilities.push(Capability::JsonMode);
            }
            Ok(ModelDescriptor {
                id: ModelId::new(model.id).map_err(|error| {
                    provider_error(
                        ErrorKind::Protocol,
                        Operation::ListModels,
                        format!("the catalogue contained an invalid model id: {error}"),
                    )
                })?,
                display_name: model.name,
                context_window: model.capabilities.limits.max_context_window_tokens,
                max_output_tokens: model.capabilities.limits.max_output_tokens,
                capabilities: CapabilitySet::from_slice(&capabilities),
            })
        })
        .collect()
}

/// Returns the clock handle used for token expiry, for tests and diagnostics.
#[must_use]
pub fn clock_of(provider: &GitHubCopilot) -> &Arc<dyn Clock> {
    provider.runtime.clock()
}

#[cfg(test)]
mod tests {
    use claw_provider_sdk::clock::ManualClock;
    use claw_provider_sdk::model::{ChatMessage, ImageMediaType, ImagePart, ImageSource};

    use super::*;

    fn secret(value: &str) -> SecretString {
        SecretString::new(value)
    }

    #[test]
    fn the_pinned_endpoints_parse_and_stay_on_the_expected_hosts() {
        for (raw, host, path) in [
            (DEVICE_CODE_URL, "github.com", "/login/device/code"),
            (ACCESS_TOKEN_URL, "github.com", "/login/oauth/access_token"),
            (
                COPILOT_TOKEN_URL,
                "api.github.com",
                "/copilot_internal/v2/token",
            ),
            (DEFAULT_API_BASE_URL, "api.githubcopilot.com", "/"),
        ] {
            let url: Url = raw.parse().expect("endpoint must parse");
            assert_eq!(url.scheme(), "https", "{raw}");
            assert_eq!(url.host_str(), Some(host), "{raw}");
            assert_eq!(url.path(), path, "{raw}");
        }
    }

    #[test]
    fn the_device_code_form_is_percent_encoded() {
        assert_eq!(
            encode_device_code_form("Iv1.abc", "read:user"),
            "client_id=Iv1.abc&scope=read%3Auser"
        );
    }

    #[test]
    fn the_poll_form_carries_the_rfc_8628_grant_type() {
        assert_eq!(
            encode_device_poll_form("Iv1.abc", &secret("dc-123")),
            "client_id=Iv1.abc&device_code=dc-123&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
    }

    #[test]
    fn a_device_authorization_decodes_and_hides_the_device_code() {
        let authorization = decode_device_authorization(
            br#"{
                "device_code": "3584d83530557fdd1f46af8289938c8ef79f9dc5",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 5
            }"#,
        )
        .expect("decode");
        assert_eq!(authorization.user_code, "WDJB-MJHT");
        assert_eq!(
            authorization.verification_uri,
            "https://github.com/login/device"
        );
        assert_eq!(authorization.expires_in, 900);
        assert_eq!(authorization.interval, 5);
        assert_eq!(
            authorization.device_code.expose(),
            "3584d83530557fdd1f46af8289938c8ef79f9dc5"
        );
        let rendered = format!("{authorization:?}");
        assert!(
            !rendered.contains("3584d83530557fdd1f46af8289938c8ef79f9dc5"),
            "debug output leaked the device code: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_zero_interval_is_clamped_to_the_minimum() {
        let authorization = decode_device_authorization(
            br#"{"device_code":"a","user_code":"b","verification_uri":"c","expires_in":10,"interval":0}"#,
        )
        .expect("decode");
        assert_eq!(authorization.interval, MIN_POLL_INTERVAL_SECONDS);
    }

    #[test]
    fn a_device_code_error_response_is_a_typed_error() {
        let error = decode_device_authorization(
            br#"{"error":"device_flow_disabled","error_description":"Device flow is disabled"}"#,
        )
        .expect_err("typed error");
        assert_eq!(error.kind(), ErrorKind::Authentication);
        assert_eq!(error.detail(), "Device flow is disabled");
        assert_eq!(error.upstream_code(), Some("device_flow_disabled"));
    }

    #[test]
    fn polling_reports_pending_slow_down_and_grant_distinctly() {
        assert_eq!(
            decode_device_poll(br#"{"error":"authorization_pending"}"#).expect("pending"),
            DevicePollOutcome::Pending
        );
        assert_eq!(
            decode_device_poll(br#"{"error":"slow_down","interval":10}"#).expect("slow down"),
            DevicePollOutcome::SlowDown
        );
        assert_eq!(
            decode_device_poll(
                br#"{"access_token":"gho_16C7e42F292c6912E7710c838347Ae178B4a","token_type":"bearer","scope":"read:user"}"#
            )
            .expect("granted"),
            DevicePollOutcome::Granted(secret("gho_16C7e42F292c6912E7710c838347Ae178B4a"))
        );
    }

    #[test]
    fn a_granted_token_is_not_printed_by_debug() {
        let outcome =
            decode_device_poll(br#"{"access_token":"gho_supersecret","token_type":"bearer"}"#)
                .expect("granted");
        let rendered = format!("{outcome:?}");
        assert!(
            !rendered.contains("gho_supersecret"),
            "debug output leaked the token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn terminal_poll_errors_carry_the_oauth_code() {
        let error = decode_device_poll(
            br#"{"error":"expired_token","error_description":"The device code has expired"}"#,
        )
        .expect_err("terminal");
        assert_eq!(error.kind(), ErrorKind::Authentication);
        assert_eq!(error.detail(), "The device code has expired");
        assert_eq!(error.upstream_code(), Some("expired_token"));

        let denied = decode_device_poll(br#"{"error":"access_denied"}"#).expect_err("terminal");
        assert_eq!(denied.kind(), ErrorKind::Authentication);
        assert_eq!(denied.detail(), "access_denied");

        let unknown = decode_device_poll(br#"{"error":"teapot"}"#).expect_err("terminal");
        assert_eq!(unknown.kind(), ErrorKind::Protocol);
    }

    #[test]
    fn an_empty_access_token_is_rejected() {
        let error = decode_device_poll(br#"{"access_token":""}"#).expect_err("empty");
        assert_eq!(error.kind(), ErrorKind::Protocol);
        assert_eq!(
            error.detail(),
            "the access-token response carried an empty token"
        );
    }

    #[test]
    fn oauth_error_codes_map_onto_the_portable_taxonomy() {
        assert_eq!(
            oauth_error_kind("authorization_pending"),
            ErrorKind::RateLimit
        );
        assert_eq!(oauth_error_kind("slow_down"), ErrorKind::RateLimit);
        assert_eq!(oauth_error_kind("access_denied"), ErrorKind::Authentication);
        assert_eq!(oauth_error_kind("expired_token"), ErrorKind::Authentication);
        assert_eq!(oauth_error_kind("invalid_grant"), ErrorKind::Authentication);
        assert_eq!(
            oauth_error_kind("unsupported_grant_type"),
            ErrorKind::InvalidRequest
        );
        assert_eq!(oauth_error_kind("something_new"), ErrorKind::Protocol);
    }

    #[test]
    fn a_copilot_token_decodes_with_its_endpoint() {
        let token = decode_copilot_token(
            br#"{
                "annotations_enabled": false,
                "chat_enabled": true,
                "expires_at": 1735689600,
                "refresh_in": 1500,
                "token": "tid=abc;exp=1735689600;sku=copilot",
                "endpoints": {
                    "api": "https://api.enterprise.githubcopilot.com",
                    "proxy": "https://proxy.enterprise.githubcopilot.com"
                }
            }"#,
        )
        .expect("decode");
        assert_eq!(token.expires_at, 1_735_689_600);
        assert_eq!(token.token.expose(), "tid=abc;exp=1735689600;sku=copilot");
        assert_eq!(
            token.api_endpoint.as_ref().map(Url::as_str),
            Some("https://api.enterprise.githubcopilot.com/")
        );
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("tid=abc"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_token_without_endpoints_falls_back_to_the_public_api() {
        let token = decode_copilot_token(br#"{"token":"tid=x","expires_at":10}"#).expect("decode");
        assert_eq!(token.api_endpoint, None);

        let client =
            GitHubCopilot::with_github_token(secret("gho_token_value")).expect("build client");
        assert_eq!(
            client.api_base(&token).expect("api base").0.as_str(),
            "https://api.githubcopilot.com/"
        );
        assert_eq!(
            client
                .endpoint(&token, "chat/completions")
                .expect("endpoint")
                .as_str(),
            "https://api.githubcopilot.com/chat/completions"
        );
    }

    #[test]
    fn the_nominated_endpoint_wins_over_the_fallback() {
        let token = decode_copilot_token(
            br#"{"token":"tid=x","expires_at":10,"endpoints":{"api":"https://api.enterprise.example/x"}}"#,
        )
        .expect("decode");
        let unenrolled =
            GitHubCopilot::with_github_token(secret("gho_token")).expect("build client");
        let error = unenrolled
            .endpoint(&token, "models")
            .expect_err("an unenrolled nominated endpoint must be refused");
        assert_eq!(error.kind(), ErrorKind::Authentication);

        let mut config = GitHubCopilotConfig::new(secret("gho_token")).expect("config");
        config.approved_origins = vec![OriginApproval::enroll(
            Origin::parse("https://api.enterprise.example").expect("origin"),
        )];
        let client = GitHubCopilot::new(config).expect("build client");
        assert_eq!(
            client
                .endpoint(&token, "models")
                .expect("endpoint")
                .as_str(),
            "https://api.enterprise.example/x/models"
        );
    }

    #[test]
    fn an_explicit_base_url_wins_over_the_nominated_endpoint() {
        let token = decode_copilot_token(
            br#"{"token":"tid=x","expires_at":10,"endpoints":{"api":"https://api.enterprise.example"}}"#,
        )
        .expect("decode");
        let mut config = GitHubCopilotConfig::new(secret("gho_token")).expect("config");
        config.api_base_url = Some("http://127.0.0.1:9/base".parse().expect("url"));
        config.approved_origins = vec![OriginApproval::enroll(
            Origin::parse("http://127.0.0.1:9").expect("origin"),
        )];
        let client = GitHubCopilot::new(config).expect("build client");
        assert_eq!(
            client
                .endpoint(&token, "models")
                .expect("endpoint")
                .as_str(),
            "http://127.0.0.1:9/base/models"
        );
    }

    #[test]
    fn an_empty_copilot_token_is_rejected() {
        let error = decode_copilot_token(br#"{"token":"","expires_at":1}"#).expect_err("empty");
        assert_eq!(error.kind(), ErrorKind::Protocol);
        assert_eq!(
            error.detail(),
            "the Copilot token response carried an empty token"
        );
    }

    #[test]
    fn token_expiry_applies_the_refresh_skew() {
        let token = CopilotToken {
            token: secret("tid=x"),
            expires_at: 1_000,
            api_endpoint: None,
        };
        assert!(!token.is_expired(1_000 - TOKEN_REFRESH_SKEW_SECONDS - 1));
        assert!(token.is_expired(1_000 - TOKEN_REFRESH_SKEW_SECONDS));
        assert!(token.is_expired(1_000));
        assert!(token.is_expired(2_000));
    }

    #[tokio::test]
    async fn a_cached_token_is_dropped_once_the_clock_passes_its_expiry() {
        let clock = Arc::new(ManualClock::new(0));
        let mut config = GitHubCopilotConfig::new(secret("gho_token")).expect("config");
        config.api_base_url = Some("http://127.0.0.1:9".parse().expect("url"));
        config.approved_origins = vec![OriginApproval::enroll(
            Origin::parse("http://127.0.0.1:9").expect("origin"),
        )];
        let mut client = GitHubCopilot::new(config).expect("build client");
        client.runtime = ProviderRuntime::with_parts(
            PROVIDER,
            claw_provider_sdk::http::HttpTransport::new().expect("transport"),
            ReliabilityConfig::default(),
            clock.clone(),
            Arc::new(claw_provider_sdk::clock::FixedJitter::new(0.0)),
        );
        *client.cached.write().await = Some(CopilotToken {
            token: secret("tid=cached"),
            expires_at: 600,
            api_endpoint: None,
        });

        let fresh = client.cached_token().await.expect("token is still fresh");
        assert_eq!(fresh.expires_at, 600);

        clock.advance(Duration::from_secs(600 - TOKEN_REFRESH_SKEW_SECONDS));
        assert_eq!(client.cached_token().await, None);

        client.invalidate_token().await;
        assert_eq!(*client.cached.read().await, None);
    }

    #[test]
    fn a_client_requires_a_github_token() {
        let error = GitHubCopilot::with_github_token(secret("")).expect_err("empty token");
        assert_eq!(error.kind(), ErrorKind::Authentication);
        assert_eq!(
            error.detail(),
            "GitHub Copilot requires a GitHub OAuth token"
        );
    }

    #[test]
    fn chat_requests_carry_the_editor_headers_and_never_leak_the_token() {
        let client =
            GitHubCopilot::with_github_token(secret("gho_super_secret_value")).expect("client");
        let token = CopilotToken {
            token: secret("tid=copilot_secret_value"),
            expires_at: u64::MAX,
            api_endpoint: None,
        };
        let url = client
            .endpoint(&token, "chat/completions")
            .expect("endpoint");
        let request = client
            .request(Method::Post, url, &token, false)
            .expect("request");
        assert_eq!(
            request.header_names(),
            vec![
                "accept",
                "copilot-integration-id",
                "editor-version",
                "editor-plugin-version",
                "authorization",
            ]
        );
        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains("tid=copilot_secret_value"),
            "debug output leaked the Copilot token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !format!("{client:?}").contains("gho_super_secret_value"),
            "client debug output leaked the GitHub token"
        );
    }

    #[test]
    fn the_vision_header_is_added_only_for_image_payloads() {
        let client = GitHubCopilot::with_github_token(secret("gho_token")).expect("client");
        let token = CopilotToken {
            token: secret("tid=x"),
            expires_at: u64::MAX,
            api_endpoint: None,
        };
        let url = client.endpoint(&token, "chat/completions").expect("url");
        assert!(
            !client
                .request(Method::Post, url.clone(), &token, false)
                .expect("request")
                .header_names()
                .contains(&"copilot-vision-request")
        );
        assert!(
            client
                .request(Method::Post, url, &token, true)
                .expect("request")
                .header_names()
                .contains(&"copilot-vision-request")
        );
    }

    #[test]
    fn vision_is_detected_from_the_message_content() {
        let model = ModelId::new("gpt-4o").expect("model");
        let text = CompletionRequest::new(model.clone(), vec![ChatMessage::user_text("hei")]);
        assert!(!requires_vision(&text));

        let image = CompletionRequest::new(
            model,
            vec![ChatMessage::User(vec![
                ContentPart::text("what is this"),
                ContentPart::Image(ImagePart {
                    media_type: ImageMediaType::Png,
                    source: ImageSource::Base64("AAAA".to_owned()),
                }),
            ])],
        );
        assert!(requires_vision(&image));
    }

    #[test]
    fn the_model_catalogue_decodes_capabilities_and_limits() {
        let models = decode_models(
            br#"{
                "object": "list",
                "data": [
                    {
                        "id": "gpt-4o",
                        "name": "GPT-4o",
                        "object": "model",
                        "vendor": "Azure OpenAI",
                        "version": "gpt-4o-2024-11-20",
                        "capabilities": {
                            "family": "gpt-4o",
                            "type": "chat",
                            "tokenizer": "o200k_base",
                            "limits": {
                                "max_context_window_tokens": 128000,
                                "max_output_tokens": 16384,
                                "max_prompt_tokens": 128000
                            },
                            "supports": {
                                "streaming": true,
                                "tool_calls": true,
                                "parallel_tool_calls": true,
                                "structured_outputs": true,
                                "vision": true
                            }
                        }
                    },
                    {
                        "id": "text-embedding-3-small",
                        "name": "Embedding V3 small",
                        "object": "model",
                        "capabilities": {
                            "type": "embeddings",
                            "limits": {"max_inputs": 256},
                            "supports": {}
                        }
                    }
                ]
            }"#,
        )
        .expect("decode");

        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id.as_str(), "gpt-4o");
        assert_eq!(models[0].display_name.as_deref(), Some("GPT-4o"));
        assert_eq!(models[0].context_window, Some(128_000));
        assert_eq!(models[0].max_output_tokens, Some(16_384));
        assert_eq!(
            models[0].capabilities,
            CapabilitySet::from_slice(&[
                Capability::Completion,
                Capability::Streaming,
                Capability::ToolCalling,
                Capability::Vision,
                Capability::JsonMode,
            ])
        );

        assert_eq!(models[1].id.as_str(), "text-embedding-3-small");
        assert_eq!(models[1].context_window, None);
        assert_eq!(models[1].max_output_tokens, None);
        assert_eq!(
            models[1].capabilities,
            CapabilitySet::from_slice(&[Capability::Completion])
        );
    }

    #[test]
    fn a_malformed_model_catalogue_is_a_protocol_error() {
        let error = decode_models(br#"{"object":"list"}"#).expect_err("missing data");
        assert_eq!(error.kind(), ErrorKind::Protocol);
        assert_eq!(error.operation(), Operation::ListModels);
    }

    #[test]
    fn the_device_flow_defaults_target_github_dot_com() {
        let flow = DeviceFlow::github().expect("flow");
        assert_eq!(flow.client_id(), DEFAULT_CLIENT_ID);
        assert_eq!(flow.device_code_url.as_str(), DEVICE_CODE_URL);
        assert_eq!(flow.access_token_url.as_str(), ACCESS_TOKEN_URL);
    }

    #[test]
    fn a_loopback_endpoint_relaxes_the_tls_policy_but_a_public_one_does_not() {
        let loopback: Url = "http://127.0.0.1:8080/x".parse().expect("url");
        let public: Url = "https://github.com/login".parse().expect("url");
        let plaintext_public: Url = "http://example.invalid/x".parse().expect("url");
        assert_eq!(
            tls_policy_for(&[&loopback, &public]),
            TlsPolicy::AllowLoopbackPlaintext
        );
        assert_eq!(tls_policy_for(&[&public]), TlsPolicy::RequireHttps);
        assert_eq!(
            tls_policy_for(&[&plaintext_public]),
            TlsPolicy::RequireHttps
        );
    }

    #[test]
    fn the_clock_accessor_returns_the_runtime_clock() {
        let client = GitHubCopilot::with_github_token(secret("gho_token")).expect("client");
        let now = clock_of(&client).now_millis();
        assert!(now > 1_600_000_000_000, "system clock looks wrong: {now}");
    }
}

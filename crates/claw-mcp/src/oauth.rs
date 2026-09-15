//! OAuth 2.1 authorization for remote MCP servers.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{
    HeaderMap, HeaderValue, Method, StatusCode,
    header::{AUTHORIZATION, CONTENT_TYPE},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;
use zeroize::Zeroize;

use crate::{
    error::{McpError, Result},
    http_client::{HttpClient, HttpRoutePolicy},
};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const EXPIRY_SKEW: Duration = Duration::from_secs(30);
const AUTHORIZATION_LIFETIME: Duration = Duration::from_mins(10);
const MAX_CREDENTIAL_BINDINGS: usize = 256;
const MAX_OAUTH_ROUTES: usize = 16;

mod keyring;
mod loopback;
pub use keyring::{NativeTokenStatus, NativeTokenStore};
pub use loopback::LoopbackAuthorizationListener;

/// OAuth authorization-server metadata required by an MCP client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AuthorizationServerMetadata {
    /// Authorization server issuer.
    pub issuer: String,
    /// Browser authorization endpoint.
    pub authorization_endpoint: String,
    /// Access-token endpoint.
    pub token_endpoint: String,
    /// Optional dynamic client registration endpoint.
    pub registration_endpoint: Option<String>,
    /// Supported PKCE challenge methods.
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
}

/// OAuth protected-resource metadata advertised by an MCP server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ProtectedResourceMetadata {
    /// Protected MCP resource identifier.
    pub resource: String,
    /// Candidate authorization server issuers.
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    /// Resource-supported scopes.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

/// Stable credential identity binding an OAuth profile to one MCP resource origin.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialBinding {
    profile: String,
    resource_origin: String,
}

impl CredentialBinding {
    /// Creates a credential binding for a configured MCP resource.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the profile name is empty or only
    /// whitespace, when the resource URL is plain HTTP at a non-loopback host (a
    /// credential must never be bound to an origin that would carry it in clear
    /// text), or when the URL has no network origin — a `data:` or `file:` URL
    /// serializes its origin as `null` and cannot own a credential.
    pub fn new(profile: impl Into<String>, resource: &Url) -> Result<Self> {
        let profile = profile.into();
        if profile.trim().is_empty() {
            return Err(McpError::Protocol(
                "OAuth credential profile must not be empty".into(),
            ));
        }
        validate_secure_endpoint(resource, "OAuth protected resource")?;
        Ok(Self {
            profile,
            resource_origin: endpoint_origin(resource)?,
        })
    }

    /// Returns the user-visible credential profile.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns the canonical origin authorized to receive the credential.
    #[must_use]
    pub fn resource_origin(&self) -> &str {
        &self.resource_origin
    }

    /// Returns a dedicated native-keystore reference scoped to this profile and resource origin.
    #[must_use]
    pub fn keyring_reference(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut digest = Sha256::new();
        digest.update(b"gta-claw.mcp-keyring-binding.v1\0");
        for component in [&self.profile, &self.resource_origin] {
            digest.update(component.len().to_string().as_bytes());
            digest.update(b":");
            digest.update(component.as_bytes());
        }
        let encoded: String = digest
            .finalize()
            .iter()
            .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
            .map(char::from)
            .collect();
        format!("keyring://gta-claw.mcp-outbound/{encoded}")
    }
}

impl Debug for CredentialBinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialBinding")
            .field("profile", &self.profile)
            .field("resource_origin", &self.resource_origin)
            .finish()
    }
}

/// Authorization-server endpoints from issuer metadata or explicit operator enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredAuthorizationServer {
    metadata: AuthorizationServerMetadata,
    issuer: Url,
    authorization_endpoint: Url,
    token_endpoint: Url,
    registration_endpoint: Option<Url>,
}

impl DiscoveredAuthorizationServer {
    /// Pins locally reviewed endpoints without discovery or network access.
    ///
    /// This supplies identity for validating an existing credential; it does not
    /// prove issuer ownership, PKCE support or a resource/issuer relationship.
    ///
    /// # Errors
    /// Rejects unsafe, ambiguous or oversized endpoint URLs.
    pub fn reviewed(issuer: Url, authorization_endpoint: Url, token_endpoint: Url) -> Result<Self> {
        for endpoint in [&issuer, &authorization_endpoint, &token_endpoint] {
            validate_secure_endpoint(endpoint, "OAuth reviewed endpoint")?;
            if endpoint.as_str().len() > 2048
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
            {
                return Err(McpError::Protocol(
                    "OAuth reviewed endpoint is ambiguous".into(),
                ));
            }
        }
        Ok(Self {
            metadata: AuthorizationServerMetadata {
                issuer: issuer.to_string(),
                authorization_endpoint: authorization_endpoint.to_string(),
                token_endpoint: token_endpoint.to_string(),
                registration_endpoint: None,
                code_challenge_methods_supported: Vec::new(),
            },
            issuer,
            authorization_endpoint,
            token_endpoint,
            registration_endpoint: None,
        })
    }

    /// Returns the validated metadata document.
    #[must_use]
    pub const fn metadata(&self) -> &AuthorizationServerMetadata {
        &self.metadata
    }

    /// Returns the validated issuer URL.
    #[must_use]
    pub const fn issuer(&self) -> &Url {
        &self.issuer
    }

    /// Returns the metadata-authorized browser endpoint.
    #[must_use]
    pub const fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    /// Returns the metadata-authorized token endpoint.
    #[must_use]
    pub const fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// Returns the metadata-authorized dynamic registration endpoint.
    #[must_use]
    pub const fn registration_endpoint(&self) -> Option<&Url> {
        self.registration_endpoint.as_ref()
    }
}

/// Public metadata submitted during dynamic client registration.
#[derive(Clone, Debug, Serialize)]
pub struct ClientMetadata {
    /// Human-readable client name.
    pub client_name: String,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// OAuth grant types.
    pub grant_types: Vec<String>,
    /// OAuth response types.
    pub response_types: Vec<String>,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: String,
    /// Optional requested scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl ClientMetadata {
    /// Creates the native GTA-Claw public-client registration metadata.
    #[must_use]
    pub fn native(redirect_uri: impl Into<String>, scope: Option<String>) -> Self {
        Self {
            client_name: "GTA-Claw MCP".into(),
            redirect_uris: vec![redirect_uri.into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: "none".into(),
            scope,
        }
    }
}

#[derive(Deserialize)]
struct RegisteredClientWire {
    client_id: String,
    client_secret: Option<String>,
}

/// Dynamically registered OAuth client credentials.
#[derive(Clone)]
pub struct RegisteredClient {
    client_id: String,
    client_secret: Option<SecretString>,
}

impl RegisteredClient {
    /// Selects an explicitly provisioned public client for a PKCE authorization flow.
    ///
    /// # Errors
    /// Rejects empty, oversized or whitespace/control-containing client identifiers.
    pub fn public(client_id: impl Into<String>) -> Result<Self> {
        let client_id = client_id.into();
        if client_id.is_empty()
            || client_id.len() > 256
            || !client_id.is_ascii()
            || client_id
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(McpError::Protocol(
                "OAuth public client identifier is invalid".into(),
            ));
        }
        Ok(Self {
            client_id,
            client_secret: None,
        })
    }

    /// Returns the public client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    fn client_secret(&self) -> Option<&str> {
        self.client_secret.as_ref().map(SecretString::expose_secret)
    }
}

impl Debug for RegisteredClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisteredClient")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// PKCE verifier and challenge for an authorization attempt.
pub struct PkcePair {
    verifier: SecretString,
    challenge: String,
}

impl PkcePair {
    /// Generates a high-entropy S256 PKCE pair from operating-system randomness.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the operating system refuses to supply
    /// randomness. A PKCE verifier derived from a weakened source would let anyone
    /// who observes the authorization code redeem it, so this fails rather than
    /// falling back.
    pub fn generate() -> Result<Self> {
        let mut random = crate::secure_random::bytes::<48>()?;
        let mut verifier = URL_SAFE_NO_PAD.encode(random);
        random.zeroize();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let secret = SecretString::from(verifier.clone());
        verifier.zeroize();
        Ok(Self {
            verifier: secret,
            challenge,
        })
    }

    /// Returns the public S256 code challenge.
    #[must_use]
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    fn verifier(&self) -> &str {
        self.verifier.expose_secret()
    }
}

impl Debug for PkcePair {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PkcePair")
            .field("verifier", &"[REDACTED]")
            .field("challenge", &self.challenge)
            .finish()
    }
}

/// Browser authorization request and the retained PKCE verifier.
pub struct AuthorizationRequest {
    /// URL to open in the user's browser.
    pub url: Url,
    /// CSRF state that must match the callback.
    pub state: String,
    /// PKCE values retained for the token exchange.
    pub pkce: PkcePair,
    context: [u8; 32],
    expires_at: Instant,
    attempted: AtomicBool,
    redirect_uri: Url,
    issuer: Url,
}

impl AuthorizationRequest {
    /// Validates an exact browser redirect without contacting the token endpoint.
    ///
    /// State and query fields must be unique. An optional RFC 9207 issuer must
    /// match the original issuer. Error descriptions and URIs are never echoed
    /// or followed. A valid denial consumes the request; a code is consumed by
    /// the subsequent exchange, not by parsing alone.
    ///
    /// # Errors
    /// Rejects expired/consumed requests, ambiguous encoding, another callback
    /// target, invalid state/issuer, mixed code/error responses and denied access.
    pub fn parse_redirect(&self, returned_url: &str) -> Result<RedirectAuthorizationCallback<'_>> {
        let invalid = || McpError::Protocol("OAuth callback is invalid or ambiguous".into());
        if self.attempted.load(Ordering::Acquire) || self.expires_at <= Instant::now() {
            return Err(McpError::Protocol(
                "OAuth authorization request is expired or consumed".into(),
            ));
        }
        if returned_url.len() > 16 * 1024
            || returned_url
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(invalid());
        }
        for (index, byte) in returned_url.bytes().enumerate() {
            if byte == b'%'
                && !returned_url
                    .as_bytes()
                    .get(index + 1..index + 3)
                    .is_some_and(|escape| escape.iter().all(u8::is_ascii_hexdigit))
            {
                return Err(invalid());
            }
        }
        let returned = Url::parse(returned_url).map_err(|_| invalid())?;
        let mut target = returned.clone();
        target.set_query(None);
        if target != self.redirect_uri {
            return Err(invalid());
        }
        let mut parameters = BTreeMap::new();
        for (name, value) in returned.query_pairs() {
            if !matches!(
                name.as_ref(),
                "code" | "state" | "iss" | "error" | "error_description" | "error_uri"
            ) || value.len() > 4096
                || value.contains('\u{fffd}')
                || value.chars().any(char::is_control)
                || parameters
                    .insert(name.into_owned(), SecretString::from(value.into_owned()))
                    .is_some()
            {
                return Err(invalid());
            }
        }
        if parameters.get("state").map(ExposeSecret::expose_secret) != Some(self.state.as_str()) {
            return Err(McpError::Protocol("OAuth callback state mismatch".into()));
        }
        if parameters
            .get("iss")
            .is_some_and(|issuer| issuer.expose_secret() != self.issuer.as_str())
        {
            return Err(McpError::Protocol("OAuth callback issuer mismatch".into()));
        }
        let code = parameters.remove("code");
        let error = parameters.remove("error");
        match (code, error) {
            (Some(code), None)
                if !code.expose_secret().is_empty()
                    && !code.expose_secret().chars().any(char::is_whitespace)
                    && !parameters.contains_key("error_description")
                    && !parameters.contains_key("error_uri") =>
            {
                Ok(RedirectAuthorizationCallback {
                    request: self,
                    code,
                })
            }
            (None, Some(error))
                if !error.expose_secret().is_empty()
                    && error.expose_secret().len() <= 128
                    && !error.expose_secret().chars().any(char::is_whitespace) =>
            {
                self.attempted.store(true, Ordering::Release);
                Err(McpError::Protocol("OAuth authorization was denied".into()))
            }
            _ => Err(invalid()),
        }
    }
}

/// A validated redirect retaining its authorization code in a redacted wrapper.
pub struct RedirectAuthorizationCallback<'a> {
    request: &'a AuthorizationRequest,
    code: SecretString,
}

impl RedirectAuthorizationCallback<'_> {
    /// Borrows the validated values for the one-time authorization exchange.
    #[must_use]
    pub fn as_callback(&self) -> AuthorizationCallback<'_> {
        AuthorizationCallback {
            code: self.code.expose_secret(),
            state: &self.request.state,
            request: self.request,
            redirect_uri: &self.request.redirect_uri,
        }
    }
}

impl Debug for RedirectAuthorizationCallback<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedirectAuthorizationCallback")
            .field("code", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Debug for AuthorizationRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequest")
            .field("url", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("pkce", &"[REDACTED]")
            .field("attempted", &self.attempted.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

/// Values a browser redirect hands back, redeemed by [`OAuthClient::exchange_code`].
///
/// Grouping them keeps the authorization-code half of the exchange together and
/// makes it impossible to swap the code and the state at a call site.
pub struct AuthorizationCallback<'a> {
    /// `code` query parameter returned on the redirect.
    pub code: &'a str,
    /// `state` query parameter echoed by the authorization server.
    pub state: &'a str,
    /// Request this callback answers, holding the PKCE verifier to present.
    pub request: &'a AuthorizationRequest,
    /// Redirect URI that was sent with the authorization request.
    pub redirect_uri: &'a Url,
}

impl Debug for AuthorizationCallback<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCallback")
            .field("code", &"[REDACTED]")
            .field("state", &"[REDACTED]")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// OAuth tokens stored behind a secure platform port.
#[derive(Clone)]
pub struct TokenSet {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    token_type: String,
    scope: Option<String>,
    expires_at: Option<SystemTime>,
    authority: Option<[u8; 32]>,
}

/// Sensitive bearer header bound to the only resource origin that may receive it.
pub struct BoundBearerHeader {
    binding: CredentialBinding,
    value: HeaderValue,
}

impl Debug for BoundBearerHeader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundBearerHeader")
            .field("binding", &self.binding)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl TokenSet {
    /// Returns a domain-separated digest of the complete credential generation.
    ///
    /// The digest binds secrets, authority, scope, type and expiry without exporting
    /// token fields. It is intended for publication identity, not user-visible logs.
    #[must_use]
    pub fn generation_fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"gta-claw.mcp-oauth-token-generation.v1\0");
        for field in [
            Some(self.access_token()),
            self.refresh_token(),
            Some(self.token_type.as_str()),
            self.scope(),
        ] {
            match field {
                Some(field) => {
                    digest.update([1]);
                    digest.update(field.len().to_string().as_bytes());
                    digest.update(b":");
                    digest.update(field.as_bytes());
                }
                None => {
                    digest.update([0]);
                }
            }
        }
        match self.expires_at {
            Some(expiry) => {
                digest.update([1]);
                let duration = match expiry.duration_since(SystemTime::UNIX_EPOCH) {
                    Ok(duration) => {
                        digest.update([0]);
                        duration
                    }
                    Err(before) => {
                        digest.update([1]);
                        before.duration()
                    }
                };
                digest.update(duration.as_nanos().to_be_bytes());
            }
            None => {
                digest.update([0]);
            }
        }
        match self.authority {
            Some(authority) => {
                digest.update([1]);
                digest.update(authority);
            }
            None => {
                digest.update([0]);
            }
        }
        digest.finalize().into()
    }

    /// Compares complete credential generations without revealing either token.
    #[must_use]
    pub fn same_generation_as(&self, other: &Self) -> bool {
        same_token_generation(self, other)
    }

    /// Obtains a redacted bearer snapshot only for its original, still-fresh enrollment.
    ///
    /// This never refreshes, writes a store or opens a connection. The caller must
    /// retain the approved resource route when passing the secret to a transport.
    ///
    /// # Errors
    /// Rejects changed issuer/client/resource identity, missing authority and
    /// expired credentials. Reauthorization or explicitly controlled refresh is required.
    pub fn fresh_bearer_token(
        &self,
        binding: &CredentialBinding,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        resource: Option<&Url>,
    ) -> Result<SecretString> {
        validate_resource_matches_binding(resource, binding)?;
        self.require_authority(&token_authority(binding, server, client, resource))?;
        if !self.is_fresh(SystemTime::now()) {
            return Err(McpError::Protocol(
                "OAuth credential is expired or requires refresh".into(),
            ));
        }
        Ok(self.access_token.clone())
    }

    /// Returns true when the access token is usable beyond the refresh skew.
    #[must_use]
    pub fn is_fresh(&self, now: SystemTime) -> bool {
        self.expires_at.is_none_or(|expiry| {
            now.checked_add(EXPIRY_SKEW)
                .is_some_and(|refresh_after| expiry > refresh_after)
        })
    }

    /// Returns whether the authorization server supplied a refresh token.
    #[must_use]
    pub const fn can_refresh(&self) -> bool {
        self.refresh_token.is_some()
    }

    /// Returns the granted scope without exposing credential bytes.
    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    fn access_token(&self) -> &str {
        self.access_token.expose_secret()
    }

    fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_ref().map(SecretString::expose_secret)
    }

    fn require_authority(&self, expected: &[u8; 32]) -> Result<()> {
        if !self.authority.is_some_and(|authority| {
            authority
                .iter()
                .zip(expected)
                .fold(0_u8, |different, (left, right)| different | (left ^ right))
                == 0
        }) {
            return Err(McpError::Protocol(
                "OAuth token authority differs from its issuer, client or resource enrollment"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl Debug for TokenSet {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenSet")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .field("authority_bound", &self.authority.is_some())
            .finish()
    }
}

#[derive(Deserialize)]
struct TokenWire {
    access_token: String,
    refresh_token: Option<String>,
    #[serde(default = "default_bearer")]
    token_type: String,
    scope: Option<String>,
    expires_in: Option<u64>,
}

fn default_bearer() -> String {
    "Bearer".into()
}

impl TokenWire {
    fn into_token_set(
        mut self,
        now: SystemTime,
        previous_refresh: Option<&str>,
    ) -> Result<TokenSet> {
        let bounded_secret = |value: &str| {
            !value.is_empty()
                && value.len() <= 4096
                && value.trim() == value
                && !value.chars().any(char::is_control)
        };
        if !self.token_type.eq_ignore_ascii_case("Bearer")
            || !bounded_secret(&self.access_token)
            || !self.access_token.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
            })
            || self
                .refresh_token
                .as_deref()
                .or(previous_refresh)
                .is_some_and(|value| !bounded_secret(value))
            || self
                .scope
                .as_ref()
                .is_some_and(|scope| scope.len() > 4096 || scope.chars().any(char::is_control))
        {
            return Err(McpError::Protocol(
                "OAuth token response contains unsupported or invalid credential fields".into(),
            ));
        }
        let expires_at = self
            .expires_in
            .map(|seconds| {
                now.checked_add(Duration::from_secs(seconds))
                    .ok_or_else(|| {
                        McpError::Protocol(
                            "OAuth token expiry exceeds the system time range".into(),
                        )
                    })
            })
            .transpose()?;
        Ok(TokenSet {
            access_token: SecretString::from(std::mem::take(&mut self.access_token)),
            refresh_token: self
                .refresh_token
                .take()
                .map(SecretString::from)
                .or_else(|| previous_refresh.map(|value| SecretString::from(value.to_owned()))),
            token_type: std::mem::take(&mut self.token_type),
            scope: self.scope.take(),
            expires_at,
            authority: None,
        })
    }
}

impl Drop for TokenWire {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// Error returned by a platform credential-store adapter.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct CredentialStoreError {
    message: String,
}

impl CredentialStoreError {
    /// Creates a non-sensitive adapter error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Secure persistence port for OAuth token sets.
pub trait TokenStore: Send + Sync {
    /// Loads credentials for an origin-bound profile key.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError`] when the backing secure store is
    /// unreachable, locked, or returns an entry this adapter cannot decode. A
    /// profile that simply has no stored credential is `Ok(None)`, not an error.
    fn load(
        &self,
        binding: &CredentialBinding,
    ) -> std::result::Result<Option<TokenSet>, CredentialStoreError>;

    /// Marks a credential update before any token request is sent.
    ///
    /// Persistent adapters should durably refuse old credentials until a new
    /// token set is saved. `previous` identifies a refresh generation; `None`
    /// denotes an explicit new authorization. The compatibility default does
    /// nothing and provides no restart-durable fence.
    ///
    /// # Errors
    /// Fails before network I/O if the previous generation changed or the adapter
    /// could not record the pending update. This is not a cross-store transaction.
    fn begin_update(
        &self,
        binding: &CredentialBinding,
        previous: Option<&TokenSet>,
    ) -> std::result::Result<(), CredentialStoreError> {
        let _ = (binding, previous);
        Ok(())
    }

    /// Replaces credentials for an origin-bound profile key.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError`] when the backing secure store rejects
    /// the write — unreachable or locked keychain, denied permission, or an
    /// entry larger than the platform allows.
    fn save(
        &self,
        binding: &CredentialBinding,
        tokens: TokenSet,
    ) -> std::result::Result<(), CredentialStoreError>;
    /// Deletes credentials for an origin-bound profile key.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError`] when the backing secure store is
    /// unreachable or refuses the deletion. Deleting a profile that holds no
    /// credential is `Ok(())`.
    fn delete(&self, binding: &CredentialBinding) -> std::result::Result<(), CredentialStoreError>;
}

/// In-memory token store suitable for ephemeral runtimes and tests.
#[derive(Debug, Default)]
pub struct MemoryTokenStore {
    tokens: Mutex<BTreeMap<CredentialBinding, TokenSet>>,
}

impl TokenStore for MemoryTokenStore {
    fn load(
        &self,
        binding: &CredentialBinding,
    ) -> std::result::Result<Option<TokenSet>, CredentialStoreError> {
        self.tokens
            .lock()
            .map_err(|_| CredentialStoreError::new("credential store lock poisoned"))
            .map(|tokens| tokens.get(binding).cloned())
    }

    fn save(
        &self,
        binding: &CredentialBinding,
        tokens: TokenSet,
    ) -> std::result::Result<(), CredentialStoreError> {
        self.tokens
            .lock()
            .map_err(|_| CredentialStoreError::new("credential store lock poisoned"))?
            .insert(binding.clone(), tokens);
        Ok(())
    }

    fn delete(&self, binding: &CredentialBinding) -> std::result::Result<(), CredentialStoreError> {
        self.tokens
            .lock()
            .map_err(|_| CredentialStoreError::new("credential store lock poisoned"))?
            .remove(binding);
        Ok(())
    }
}

/// Buffered response from an origin-authorized HTTP request.
pub struct AuthorizedHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Debug for AuthorizedHttpResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedHttpResponse")
            .field("status", &self.status)
            .field("headers", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl AuthorizedHttpResponse {
    /// Returns the HTTP status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the response headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the bounded response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// MCP OAuth 2.1 client with bounded local-only-testable HTTP operations.
#[derive(Clone)]
pub struct OAuthClient {
    http: OAuthHttp,
    refresh_locks: Arc<AsyncMutex<HashMap<CredentialBinding, Arc<AsyncMutex<RefreshState>>>>>,
}

#[derive(Clone)]
enum OAuthHttp {
    Compatible(Box<HttpClient>),
    Reviewed(Arc<BTreeMap<Url, HttpClient>>),
}

#[derive(Default)]
struct RefreshState {
    reauthorization_required: bool,
}

impl RefreshState {
    fn require_usable(&self) -> Result<()> {
        if self.reauthorization_required {
            return Err(McpError::Protocol(
                "OAuth credential requires new authorization after an unconfirmed operation or logout".into(),
            ));
        }
        Ok(())
    }
}

impl Debug for OAuthClient {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthClient")
            .finish_non_exhaustive()
    }
}

impl OAuthClient {
    /// Creates an OAuth client with redirects disabled and a bounded timeout.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Http`] when the HTTPS client cannot be built — no usable
    /// platform trust anchors, or a `rustls` crypto provider already installed with
    /// an incompatible configuration.
    pub fn new(timeout: Duration) -> Result<Self> {
        let http = HttpClient::new(timeout)?;
        Ok(Self {
            http: OAuthHttp::Compatible(Box::new(http)),
            refresh_locks: Arc::new(AsyncMutex::new(HashMap::new())),
        })
    }

    /// Creates a client with at most sixteen explicitly enrolled HTTP routes.
    ///
    /// Every requested URL must match one route exactly, including path. Routes
    /// never consult ambient proxy variables or fall back to direct remote access.
    /// Browser authorization and token endpoints must also be enrolled before an
    /// authorization URL is returned. Callers remain responsible for approving
    /// resource/issuer relationships and the proxy's DNS policy.
    ///
    /// # Errors
    /// Rejects empty, duplicate or oversized route sets and invalid TLS configuration.
    pub fn with_routes(
        timeout: Duration,
        routes: impl IntoIterator<Item = HttpRoutePolicy>,
    ) -> Result<Self> {
        let mut clients = BTreeMap::new();
        for route in routes {
            let endpoint = route.endpoint().clone();
            if clients.len() >= MAX_OAUTH_ROUTES || clients.contains_key(&endpoint) {
                return Err(McpError::Protocol(
                    "OAuth routes must be unique and within the route limit".into(),
                ));
            }
            clients.insert(endpoint, HttpClient::with_route(timeout, route)?);
        }
        if clients.is_empty() {
            return Err(McpError::Protocol("OAuth routes must not be empty".into()));
        }
        Ok(Self {
            http: OAuthHttp::Reviewed(Arc::new(clients)),
            refresh_locks: Arc::new(AsyncMutex::new(HashMap::new())),
        })
    }

    fn http_for(&self, endpoint: &Url) -> Result<&HttpClient> {
        match &self.http {
            OAuthHttp::Compatible(client) => Ok(client.as_ref()),
            OAuthHttp::Reviewed(clients) => clients.get(endpoint).ok_or_else(|| {
                McpError::Protocol("OAuth endpoint is outside its enrolled route policy".into())
            }),
        }
    }

    /// Reads protected-resource metadata from an explicit URL.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the metadata URL is cleartext HTTP at a
    /// non-loopback host or the server answers with a non-2xx status (the status is
    /// included). Returns [`McpError::Http`] when the request fails, times out, or
    /// the body exceeds the client's response limit, and [`McpError::Json`] when the
    /// document is not a protected-resource metadata object.
    pub async fn discover_resource(&self, metadata_url: &Url) -> Result<ProtectedResourceMetadata> {
        validate_secure_endpoint(metadata_url, "OAuth resource metadata")?;
        let response = self
            .http_for(metadata_url)?
            .request(Method::GET, metadata_url, HeaderMap::new(), Vec::new())
            .await?;
        if !response.status.is_success() {
            return Err(McpError::Protocol(format!(
                "OAuth resource metadata returned HTTP {}",
                response.status
            )));
        }
        response.json().await
    }

    /// Reads authorization-server metadata from an issuer.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the issuer is cleartext HTTP at a
    /// non-loopback host, the metadata request answers with a non-2xx status, the
    /// document's `issuer` does not match the URL it was fetched from (a mix-up
    /// attack), the server advertises PKCE methods but not `S256`, or an advertised
    /// authorization, token, or registration endpoint is itself cleartext. Returns
    /// [`McpError::Url`] when an advertised endpoint is not a valid absolute URL,
    /// [`McpError::Http`] when the request fails or times out, and
    /// [`McpError::Json`] when the document cannot be parsed.
    pub async fn discover_authorization_server(
        &self,
        issuer: &Url,
    ) -> Result<DiscoveredAuthorizationServer> {
        validate_secure_endpoint(issuer, "OAuth issuer")?;
        let metadata_url = authorization_server_metadata_url(issuer);
        let response = self
            .http_for(&metadata_url)?
            .request(Method::GET, &metadata_url, HeaderMap::new(), Vec::new())
            .await?;
        if !response.status.is_success() {
            return Err(McpError::Protocol(format!(
                "OAuth server metadata returned HTTP {}",
                response.status
            )));
        }
        let metadata: AuthorizationServerMetadata = response.json().await?;
        if metadata.issuer.trim_end_matches('/') != issuer.as_str().trim_end_matches('/') {
            return Err(McpError::Protocol(
                "OAuth metadata issuer does not match discovery issuer".into(),
            ));
        }
        if !metadata.code_challenge_methods_supported.is_empty()
            && !metadata
                .code_challenge_methods_supported
                .iter()
                .any(|method| method == "S256")
        {
            return Err(McpError::Protocol(
                "OAuth authorization server does not support PKCE S256".into(),
            ));
        }
        let discovered = DiscoveredAuthorizationServer {
            issuer: issuer.clone(),
            authorization_endpoint: validated_metadata_endpoint(
                &metadata.authorization_endpoint,
                "OAuth authorization endpoint",
            )?,
            token_endpoint: validated_metadata_endpoint(
                &metadata.token_endpoint,
                "OAuth token endpoint",
            )?,
            registration_endpoint: metadata
                .registration_endpoint
                .as_deref()
                .map(|endpoint| {
                    validated_metadata_endpoint(endpoint, "OAuth registration endpoint")
                })
                .transpose()?,
            metadata,
        };
        self.http_for(discovered.authorization_endpoint())?;
        self.http_for(discovered.token_endpoint())?;
        Ok(discovered)
    }

    /// Dynamically registers a public OAuth client at the discovered endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the discovered metadata advertises no
    /// registration endpoint, or the endpoint answers with a non-2xx status (the
    /// status is included; a 401 or 403 usually means the server requires a
    /// pre-provisioned client). Returns [`McpError::Http`] when the request fails or
    /// times out, and [`McpError::Json`] when the response omits `client_id`.
    pub async fn register(
        &self,
        server: &DiscoveredAuthorizationServer,
        metadata: &ClientMetadata,
    ) -> Result<RegisteredClient> {
        let registration_endpoint = server.registration_endpoint().ok_or_else(|| {
            McpError::Protocol("OAuth server does not advertise dynamic registration".into())
        })?;
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let response = self
            .http_for(registration_endpoint)?
            .request(
                Method::POST,
                registration_endpoint,
                headers,
                serde_json::to_vec(metadata)?,
            )
            .await?;
        if !response.status.is_success() {
            return Err(McpError::Protocol(format!(
                "OAuth client registration returned HTTP {}",
                response.status
            )));
        }
        let wire: RegisteredClientWire = response.json().await?;
        Ok(RegisteredClient {
            client_id: wire.client_id,
            client_secret: wire.client_secret.map(SecretString::from),
        })
    }

    /// Builds an authorization-code request with PKCE and CSRF state.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] for unsafe redirect/resource URLs, conflicting
    /// authorization parameters, or failure to obtain secure randomness. The
    /// returned request expires in ten minutes and permits only one exchange attempt.
    pub fn authorization_request(
        &self,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        redirect_uri: &Url,
        scope: Option<&str>,
        resource: Option<&Url>,
    ) -> Result<AuthorizationRequest> {
        self.http_for(server.authorization_endpoint())?;
        self.http_for(server.token_endpoint())?;
        validate_secure_endpoint(redirect_uri, "OAuth redirect")?;
        if redirect_uri.as_str().len() > 2048
            || !redirect_uri.username().is_empty()
            || redirect_uri.password().is_some()
            || redirect_uri.query().is_some()
            || redirect_uri.fragment().is_some()
            || server.authorization_endpoint().as_str().len() > 2048
            || server.authorization_endpoint().fragment().is_some()
            || server
                .authorization_endpoint()
                .query_pairs()
                .any(|(name, _)| {
                    [
                        "response_type",
                        "client_id",
                        "redirect_uri",
                        "state",
                        "code_challenge",
                        "code_challenge_method",
                        "scope",
                        "resource",
                    ]
                    .iter()
                    .any(|reserved| name.eq_ignore_ascii_case(reserved))
                })
        {
            return Err(McpError::Protocol(
                "OAuth authorization parameters are unsafe or ambiguous".into(),
            ));
        }
        if let Some(resource) = resource {
            validate_secure_endpoint(resource, "OAuth protected resource")?;
        }
        let pkce = PkcePair::generate()?;
        let state = URL_SAFE_NO_PAD.encode(crate::secure_random::bytes::<24>()?);
        let mut url = server.authorization_endpoint().clone();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", client.client_id())
                .append_pair("redirect_uri", redirect_uri.as_str())
                .append_pair("state", &state)
                .append_pair("code_challenge", pkce.challenge())
                .append_pair("code_challenge_method", "S256");
            if let Some(scope) = scope {
                query.append_pair("scope", scope);
            }
            if let Some(resource) = resource {
                query.append_pair("resource", resource.as_str());
            }
        }
        let mut request = AuthorizationRequest {
            url,
            state,
            pkce,
            context: [0; 32],
            expires_at: Instant::now() + AUTHORIZATION_LIFETIME,
            attempted: AtomicBool::new(false),
            redirect_uri: redirect_uri.clone(),
            issuer: server.issuer().clone(),
        };
        request.context = authorization_context(server, client, redirect_uri, resource, &request);
        Ok(request)
    }

    /// Exchanges an authorization code and persists the returned tokens.
    ///
    /// The callback `state` is compared against the one minted by
    /// [`OAuthClient::authorization_request`] before anything is sent, so a
    /// forged redirect never reaches the token endpoint. The original context and
    /// deadline are checked, then the request is consumed before awaiting I/O.
    /// Failed, cancelled or ambiguous exchanges cannot reuse that request.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the callback `state` does not match
    /// the authorization request (a CSRF-injected redirect), when `resource`
    /// names an origin other than the one the credential is bound to, when the
    /// token endpoint is cleartext HTTP at a non-loopback host, when it answers
    /// with a non-2xx status — `invalid_grant` here means the code expired, was
    /// already redeemed, or the PKCE verifier did not match — or when the
    /// returned `expires_in` overflows the system clock. Returns
    /// [`McpError::CredentialStore`] when the new tokens cannot be persisted,
    /// [`McpError::Http`] when the request fails or times out, and
    /// [`McpError::Json`] when the token response cannot be parsed.
    pub async fn exchange_code(
        &self,
        binding: &CredentialBinding,
        store: &dyn TokenStore,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        callback: AuthorizationCallback<'_>,
        resource: Option<&Url>,
    ) -> Result<TokenSet> {
        if callback.state != callback.request.state {
            return Err(McpError::Protocol("OAuth callback state mismatch".into()));
        }
        validate_resource_matches_binding(resource, binding)?;
        let context = authorization_context(
            server,
            client,
            callback.redirect_uri,
            resource,
            callback.request,
        );
        if context
            .iter()
            .zip(callback.request.context)
            .fold(0_u8, |different, (left, right)| different | (left ^ right))
            != 0
        {
            return Err(McpError::Protocol(
                "OAuth authorization context changed".into(),
            ));
        }
        if callback.request.expires_at <= Instant::now() {
            return Err(McpError::Protocol(
                "OAuth authorization request expired".into(),
            ));
        }
        if callback.code.is_empty()
            || callback.code.len() > 4096
            || callback.code.trim() != callback.code
            || callback.code.chars().any(char::is_control)
        {
            return Err(McpError::Protocol(
                "OAuth authorization code is invalid".into(),
            ));
        }
        validate_secure_endpoint(server.token_endpoint(), "OAuth token endpoint")?;
        self.http_for(server.token_endpoint())?;
        if callback
            .request
            .attempted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(McpError::Protocol(
                "OAuth authorization request was already attempted".into(),
            ));
        }
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("client_id", client.client_id()),
            ("code", callback.code),
            ("redirect_uri", callback.redirect_uri.as_str()),
            ("code_verifier", callback.request.pkce.verifier()),
        ];
        if let Some(secret) = client.client_secret() {
            fields.push(("client_secret", secret));
        }
        if let Some(resource) = resource {
            fields.push(("resource", resource.as_str()));
        }
        let refresh_lock = self.refresh_lock(binding).await?;
        let mut state = refresh_lock.lock().await;
        if callback.request.expires_at <= Instant::now() {
            return Err(McpError::Protocol(
                "OAuth authorization request expired".into(),
            ));
        }
        state.reauthorization_required = true;
        store.begin_update(binding, None).map_err(store_error)?;
        let wire = self.post_token(server.token_endpoint(), &fields).await?;
        let mut tokens = wire.into_token_set(SystemTime::now(), None)?;
        tokens.authority = Some(token_authority(binding, server, client, resource));
        store.save(binding, tokens.clone()).map_err(store_error)?;
        state.reauthorization_required = false;
        drop(state);
        Ok(tokens)
    }

    /// Refreshes a token while coalescing concurrent refreshes for this client and profile.
    ///
    /// Concurrent callers for the same binding queue on one lock, and a caller
    /// that finds the token already rotated while it waited returns the newer
    /// token instead of spending the (often single-use) refresh token again.
    /// Unconfirmed or cancelled exchanges fence this binding for this client and
    /// its clones until a new authorization-code exchange is saved successfully.
    /// This in-memory fence is not a restart-durable credential journal.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when `resource` names an origin other than the
    /// one the credential is bound to, when the store holds no credential for the
    /// binding, when the stored credential has no refresh token, when the token
    /// endpoint is cleartext HTTP at a non-loopback host, or when it answers with a
    /// non-2xx status — which for `invalid_grant` means the refresh token was
    /// revoked or already redeemed and the user must authorize again. Returns
    /// [`McpError::CredentialStore`] when the rotated token cannot be persisted,
    /// [`McpError::Http`] when the request fails or times out, and
    /// [`McpError::Json`] when the token response cannot be parsed.
    pub async fn refresh(
        &self,
        binding: &CredentialBinding,
        store: &dyn TokenStore,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        resource: Option<&Url>,
    ) -> Result<TokenSet> {
        validate_resource_matches_binding(resource, binding)?;
        let observed = load_tokens(binding, store)?;
        let authority = token_authority(binding, server, client, resource);
        observed.require_authority(&authority)?;
        let refresh_lock = self.refresh_lock(binding).await?;
        let mut state = refresh_lock.lock().await;
        state.require_usable()?;
        let current = load_tokens(binding, store)?;
        current.require_authority(&authority)?;
        if !same_token_generation(&observed, &current) {
            return Ok(current);
        }
        state.reauthorization_required = true;
        let tokens = self
            .refresh_current(binding, store, server, client, resource, current)
            .await?;
        state.reauthorization_required = false;
        drop(state);
        Ok(tokens)
    }

    async fn refresh_current(
        &self,
        binding: &CredentialBinding,
        store: &dyn TokenStore,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        resource: Option<&Url>,
        current: TokenSet,
    ) -> Result<TokenSet> {
        validate_secure_endpoint(server.token_endpoint(), "OAuth token endpoint")?;
        self.http_for(server.token_endpoint())?;
        let refresh = current
            .refresh_token()
            .ok_or_else(|| McpError::Protocol("OAuth refresh token is not available".into()))?;
        let mut fields = vec![
            ("grant_type", "refresh_token"),
            ("client_id", client.client_id()),
            ("refresh_token", refresh),
        ];
        if let Some(secret) = client.client_secret() {
            fields.push(("client_secret", secret));
        }
        if let Some(resource) = resource {
            fields.push(("resource", resource.as_str()));
        }
        store
            .begin_update(binding, Some(&current))
            .map_err(store_error)?;
        let wire = self.post_token(server.token_endpoint(), &fields).await?;
        let mut tokens = wire.into_token_set(SystemTime::now(), Some(refresh))?;
        if tokens.scope.is_none() {
            tokens.scope = current.scope;
        }
        tokens.authority = current.authority;
        store.save(binding, tokens.clone()).map_err(store_error)?;
        Ok(tokens)
    }

    async fn refresh_lock(
        &self,
        binding: &CredentialBinding,
    ) -> Result<Arc<AsyncMutex<RefreshState>>> {
        let mut locks = self.refresh_locks.lock().await;
        if let Some(existing) = locks.get(binding) {
            return Ok(Arc::clone(existing));
        }
        if locks.len() >= MAX_CREDENTIAL_BINDINGS {
            return Err(McpError::Protocol(
                "OAuth credential binding capacity reached".into(),
            ));
        }
        let state = Arc::new(AsyncMutex::new(RefreshState::default()));
        locks.insert(binding.clone(), Arc::clone(&state));
        drop(locks);
        Ok(state)
    }

    async fn post_token(&self, endpoint: &Url, fields: &[(&str, &str)]) -> Result<TokenWire> {
        validate_secure_endpoint(endpoint, "OAuth token endpoint")?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let response = self
            .http_for(endpoint)?
            .request(Method::POST, endpoint, headers, body.into_bytes())
            .await?;
        if !response.status.is_success() {
            return Err(McpError::Protocol(format!(
                "OAuth token endpoint returned HTTP {}",
                response.status
            )));
        }
        response.json().await
    }

    /// Returns a bearer header, refreshing first when required.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when `resource` names an origin other than the
    /// one the credential is bound to, when the store holds no credential for the
    /// binding, when an expired credential cannot be refreshed (see
    /// [`OAuthClient::refresh`]), or when the access token contains bytes that are
    /// not valid in an HTTP header value. Returns [`McpError::CredentialStore`],
    /// [`McpError::Http`], or [`McpError::Json`] for the same reasons a refresh
    /// does.
    pub async fn bearer_header(
        &self,
        binding: &CredentialBinding,
        store: &dyn TokenStore,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        resource: Option<&Url>,
    ) -> Result<BoundBearerHeader> {
        validate_resource_matches_binding(resource, binding)?;
        let refresh_lock = self.refresh_lock(binding).await?;
        let mut state = refresh_lock.lock().await;
        state.require_usable()?;
        let current = load_tokens(binding, store)?;
        current.require_authority(&token_authority(binding, server, client, resource))?;
        let tokens = if current.is_fresh(SystemTime::now()) {
            current
        } else {
            state.reauthorization_required = true;
            let tokens = self
                .refresh_current(binding, store, server, client, resource, current)
                .await?;
            state.reauthorization_required = false;
            tokens
        };
        let mut value = HeaderValue::from_str(&format!("Bearer {}", tokens.access_token()))
            .map_err(|_| McpError::Protocol("OAuth token cannot be encoded as a header".into()))?;
        value.set_sensitive(true);
        drop(state);
        Ok(BoundBearerHeader {
            binding: binding.clone(),
            value,
        })
    }

    /// Injects a sensitive bearer header into one HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Protocol`] when the request URL is cleartext HTTP at a
    /// non-loopback host, has no network origin, or has an origin other than the one
    /// `bearer` is bound to — the check that stops a redirect or a misconfigured
    /// server from collecting another origin's token. Returns [`McpError::Http`]
    /// when the request fails, times out, or the response body exceeds the client's
    /// buffering limit.
    pub async fn send_authorized(
        &self,
        method: Method,
        request_url: Url,
        mut headers: HeaderMap,
        body: Vec<u8>,
        bearer: BoundBearerHeader,
    ) -> Result<AuthorizedHttpResponse> {
        validate_secure_endpoint(&request_url, "authorized HTTP endpoint")?;
        if endpoint_origin(&request_url)? != bearer.binding.resource_origin {
            return Err(McpError::Protocol(
                "OAuth credential is not authorized for the request origin".into(),
            ));
        }
        headers.insert(AUTHORIZATION, bearer.value);
        let response = self
            .http_for(&request_url)?
            .request(method, &request_url, headers, body)
            .await?;
        let (status, headers, body) = response.buffered().await?;
        Ok(AuthorizedHttpResponse {
            status,
            headers,
            body,
        })
    }

    /// Removes credentials for one origin-bound OAuth profile.
    ///
    /// Waits for any in-flight refresh or code exchange for the same binding, so
    /// a concurrent credential write cannot complete after this deletion. The
    /// binding remains fenced, including if the platform deletion fails.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::CredentialStore`] when the platform store refuses the
    /// deletion — an unreachable or locked keychain. Deleting a profile that holds
    /// no credential succeeds.
    pub async fn logout(&self, binding: &CredentialBinding, store: &dyn TokenStore) -> Result<()> {
        let refresh_lock = self.refresh_lock(binding).await?;
        let mut state = refresh_lock.lock().await;
        state.reauthorization_required = true;
        let result = store.delete(binding).map_err(store_error);
        drop(state);
        result
    }
}

impl Default for OAuthClient {
    fn default() -> Self {
        Self::new(DEFAULT_HTTP_TIMEOUT).expect("default OAuth HTTP client must build")
    }
}

fn store_error(error: CredentialStoreError) -> McpError {
    let CredentialStoreError { message } = error;
    McpError::CredentialStore(message)
}

fn token_authority(
    binding: &CredentialBinding,
    server: &DiscoveredAuthorizationServer,
    client: &RegisteredClient,
    resource: Option<&Url>,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gta-claw.mcp-oauth-token-authority.v1\0");
    for field in [
        binding.profile(),
        binding.resource_origin(),
        server.issuer().as_str(),
        server.authorization_endpoint().as_str(),
        server.token_endpoint().as_str(),
        client.client_id(),
        client.client_secret().unwrap_or(""),
        resource.map_or("", Url::as_str),
    ] {
        digest.update(field.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(field.as_bytes());
    }
    digest.finalize().into()
}

fn authorization_context(
    server: &DiscoveredAuthorizationServer,
    client: &RegisteredClient,
    redirect_uri: &Url,
    resource: Option<&Url>,
    request: &AuthorizationRequest,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"gta-claw.mcp-oauth-authorization.v1\0");
    for field in [
        server.issuer().as_str(),
        server.authorization_endpoint().as_str(),
        server.token_endpoint().as_str(),
        client.client_id(),
        client.client_secret().unwrap_or(""),
        redirect_uri.as_str(),
        resource.map_or("", Url::as_str),
        request.url.as_str(),
        &request.state,
        request.pkce.challenge(),
        request.pkce.verifier(),
    ] {
        digest.update(field.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(field.as_bytes());
    }
    digest.finalize().into()
}

/// Computes the RFC 8414 metadata URL for a caller-reviewed issuer without network access.
///
/// This projection is not a route grant. Callers must validate and enroll the
/// returned URL before discovery; the issuer's query and fragment are removed.
#[must_use]
pub fn authorization_server_metadata_url(issuer: &Url) -> Url {
    let mut metadata = issuer.clone();
    metadata.set_query(None);
    metadata.set_fragment(None);
    let issuer_path = issuer.path().trim_matches('/');
    let path = if issuer_path.is_empty() {
        "/.well-known/oauth-authorization-server".to_owned()
    } else {
        format!("/.well-known/oauth-authorization-server/{issuer_path}")
    };
    metadata.set_path(&path);
    metadata
}

fn validate_secure_endpoint(endpoint: &Url, label: &str) -> Result<()> {
    if crate::endpoint_allows_credentials(endpoint) {
        return Ok(());
    }
    Err(McpError::Protocol(format!(
        "{label} must use HTTPS unless it is a loopback HTTP URL"
    )))
}

fn endpoint_origin(endpoint: &Url) -> Result<String> {
    let origin = endpoint.origin().ascii_serialization();
    if origin == "null" {
        return Err(McpError::Protocol(
            "OAuth endpoint must have a network origin".into(),
        ));
    }
    Ok(origin)
}

fn validated_metadata_endpoint(endpoint: &str, label: &str) -> Result<Url> {
    let endpoint = Url::parse(endpoint)?;
    validate_secure_endpoint(&endpoint, label)?;
    Ok(endpoint)
}

fn validate_resource_matches_binding(
    resource: Option<&Url>,
    binding: &CredentialBinding,
) -> Result<()> {
    if let Some(resource) = resource
        && endpoint_origin(resource)? != binding.resource_origin
    {
        return Err(McpError::Protocol(
            "OAuth resource does not match the credential-bound origin".into(),
        ));
    }
    Ok(())
}

fn load_tokens(binding: &CredentialBinding, store: &dyn TokenStore) -> Result<TokenSet> {
    store
        .load(binding)
        .map_err(store_error)?
        .ok_or_else(|| McpError::Protocol("OAuth credentials are not available".into()))
}

fn same_token_generation(left: &TokenSet, right: &TokenSet) -> bool {
    left.generation_fingerprint()
        .iter()
        .zip(right.generation_fingerprint())
        .fold(0_u8, |different, (left, right)| different | (left ^ right))
        == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn keyring_references_are_architecture_stable_and_bound_to_profile_and_origin() {
        use super::CredentialBinding;
        use sha2::{Digest as _, Sha256};
        use url::Url;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let binding = CredentialBinding::new(
            "fixture",
            &Url::parse("http://127.0.0.1:32109/mcp").expect("endpoint"),
        )
        .expect("binding");
        let expected: String = Sha256::digest(
            b"gta-claw.mcp-keyring-binding.v1\x007:fixture22:http://127.0.0.1:32109",
        )
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect();
        assert_eq!(
            binding.keyring_reference(),
            format!("keyring://gta-claw.mcp-outbound/{expected}")
        );
        let same_origin = CredentialBinding::new(
            "fixture",
            &Url::parse("http://127.0.0.1:32109/other").expect("other path"),
        )
        .expect("binding");
        assert_eq!(binding.keyring_reference(), same_origin.keyring_reference());
        let other_origin = CredentialBinding::new(
            "fixture",
            &Url::parse("http://127.0.0.1:32110/mcp").expect("other origin"),
        )
        .expect("binding");
        let other_profile = CredentialBinding::new(
            "other",
            &Url::parse("http://127.0.0.1:32109/mcp").expect("endpoint"),
        )
        .expect("binding");
        assert_ne!(
            binding.keyring_reference(),
            other_origin.keyring_reference()
        );
        assert_ne!(
            binding.keyring_reference(),
            other_profile.keyring_reference()
        );
        assert!(!binding.keyring_reference().contains("fixture"));
        assert!(!binding.keyring_reference().contains("127.0.0.1"));
    }

    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[cfg(windows)]
    struct OwnedNativeTokens {
        store: NativeTokenStore,
        binding: CredentialBinding,
    }

    #[cfg(windows)]
    impl Drop for OwnedNativeTokens {
        fn drop(&mut self) {
            let _ = self.store.delete(&self.binding);
        }
    }

    pub(super) fn discovered_server(base: &Url) -> DiscoveredAuthorizationServer {
        let authorization_endpoint = base.join("authorize").expect("authorization endpoint");
        let token_endpoint = base.join("token").expect("token endpoint");
        let registration_endpoint = base.join("register").expect("registration endpoint");
        DiscoveredAuthorizationServer {
            metadata: AuthorizationServerMetadata {
                issuer: base.as_str().into(),
                authorization_endpoint: authorization_endpoint.as_str().into(),
                token_endpoint: token_endpoint.as_str().into(),
                registration_endpoint: Some(registration_endpoint.as_str().into()),
                code_challenge_methods_supported: vec!["S256".into()],
            },
            issuer: base.clone(),
            authorization_endpoint,
            token_endpoint,
            registration_endpoint: Some(registration_endpoint),
        }
    }

    #[test]
    fn overflowing_token_expiry_is_rejected_without_panicking() {
        let wire = TokenWire {
            access_token: "short-lived".into(),
            refresh_token: None,
            token_type: "Bearer".into(),
            scope: None,
            expires_in: Some(u64::MAX),
        };

        let error = wire
            .into_token_set(SystemTime::now(), None)
            .expect_err("overflowing expiry must fail");

        assert_eq!(
            error.to_string(),
            "MCP protocol violation: OAuth token expiry exceeds the system time range"
        );
    }

    #[test]
    fn token_responses_require_bounded_bearer_credentials_before_persistence() {
        let fixture = || TokenWire {
            access_token: "private-access-token".into(),
            refresh_token: Some("private-refresh-token".into()),
            token_type: "Bearer".into(),
            scope: Some("tools:read tools:write".into()),
            expires_in: Some(3600),
        };
        for mode in 0..11 {
            let mut wire = fixture();
            match mode {
                0 => wire.access_token.clear(),
                1 => wire.access_token = "private token".into(),
                2 => wire.access_token = "private-token\n".into(),
                3 => wire.access_token = "x".repeat(4097),
                4 => wire.access_token = "private\"token".into(),
                5 => wire.token_type = "MAC".into(),
                6 => wire.refresh_token = Some(String::new()),
                7 => wire.refresh_token = Some("x".repeat(4097)),
                8 => wire.refresh_token = Some("private-refresh\0".into()),
                9 => wire.scope = Some("x".repeat(4097)),
                10 => wire.scope = Some("scope\nprivate-token".into()),
                _ => unreachable!(),
            }
            let error = wire
                .into_token_set(SystemTime::now(), None)
                .expect_err("invalid credential response");
            assert!(error.to_string().contains("invalid credential fields"));
            assert!(!error.to_string().contains("private"));
        }
        let mut boundary = fixture();
        boundary.access_token = "a".repeat(4096);
        boundary.refresh_token = None;
        boundary.token_type = "bearer".into();
        let token = boundary
            .into_token_set(SystemTime::now(), Some("retained-refresh"))
            .expect("valid boundary");
        assert_eq!(token.access_token().len(), 4096);
        assert_eq!(token.refresh_token(), Some("retained-refresh"));
        assert!(token.is_fresh(SystemTime::now()));
    }

    #[test]
    fn fresh_oauth_snapshots_require_original_authority_and_never_refresh_expired_tokens() {
        let issuer = Url::parse("https://auth.example/").expect("issuer");
        let authorization = issuer.join("authorize").expect("authorization");
        let endpoint = issuer.join("token").expect("token endpoint");
        let reviewed = DiscoveredAuthorizationServer::reviewed(
            issuer.clone(),
            authorization.clone(),
            endpoint,
        )
        .expect("reviewed identity");
        assert!(
            reviewed
                .metadata()
                .code_challenge_methods_supported
                .is_empty()
        );
        assert!(reviewed.registration_endpoint().is_none());
        let client = RegisteredClient::public("fixture").expect("public client");
        let resource = Url::parse("https://mcp.example/rpc").expect("resource");
        let binding = CredentialBinding::new("fixture", &resource).expect("binding");
        let mut tokens = TokenWire {
            access_token: "private-fresh-oauth".into(),
            refresh_token: Some("private-refresh".into()),
            token_type: "Bearer".into(),
            scope: None,
            expires_in: Some(3600),
        }
        .into_token_set(SystemTime::now(), None)
        .expect("tokens");
        tokens.authority = Some(token_authority(
            &binding,
            &reviewed,
            &client,
            Some(&resource),
        ));
        let snapshot = tokens
            .fresh_bearer_token(&binding, &reviewed, &client, Some(&resource))
            .expect("fresh snapshot");
        assert_eq!(snapshot.expose_secret(), "private-fresh-oauth");
        assert!(!format!("{snapshot:?}").contains("private-fresh-oauth"));
        let mut changed = tokens.clone();
        assert!(tokens.same_generation_as(&changed));
        changed.scope = Some("expanded-scope".into());
        assert!(!tokens.same_generation_as(&changed));
        changed = tokens.clone();
        changed.refresh_token = Some(SecretString::from("different-refresh".to_owned()));
        assert!(!tokens.same_generation_as(&changed));
        let different = RegisteredClient::public("different-client").expect("client");
        assert!(
            tokens
                .fresh_bearer_token(&binding, &reviewed, &different, Some(&resource))
                .is_err()
        );
        tokens.expires_at = Some(SystemTime::UNIX_EPOCH);
        assert!(
            tokens
                .fresh_bearer_token(&binding, &reviewed, &client, Some(&resource))
                .expect_err("no implicit refresh")
                .to_string()
                .contains("expired")
        );
        for unsafe_url in [
            "http://remote.example/token",
            "https://secret@auth.example/token",
            "https://auth.example/token?secret=value",
            "https://auth.example/token#fragment",
        ] {
            assert!(
                DiscoveredAuthorizationServer::reviewed(
                    issuer.clone(),
                    authorization.clone(),
                    Url::parse(unsafe_url).expect("URL")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn secrets_are_redacted_from_debug_output() {
        let client = RegisteredClient {
            client_id: "public-client".into(),
            client_secret: Some(SecretString::from("registration-secret".to_owned())),
        };
        let tokens = TokenSet {
            access_token: SecretString::from("access-secret".to_owned()),
            refresh_token: Some(SecretString::from("refresh-secret".to_owned())),
            token_type: "Bearer".into(),
            scope: Some("tools:read".into()),
            expires_at: None,
            authority: None,
        };
        let pkce = PkcePair {
            verifier: SecretString::from("verifier-secret".to_owned()),
            challenge: "public-challenge".into(),
        };
        let binding = CredentialBinding::new(
            "redaction-profile",
            &Url::parse("https://mcp.example/rpc").expect("resource URL"),
        )
        .expect("credential binding");
        let bound_header = BoundBearerHeader {
            binding,
            value: HeaderValue::from_static("Bearer header-secret"),
        };
        let authorized_response = AuthorizedHttpResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: b"response-secret".to_vec(),
        };
        let rendered =
            format!("{client:?}\n{tokens:?}\n{pkce:?}\n{bound_header:?}\n{authorized_response:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("registration-secret"));
        assert!(!rendered.contains("access-secret"));
        assert!(!rendered.contains("refresh-secret"));
        assert!(!rendered.contains("verifier-secret"));
        assert!(!rendered.contains("header-secret"));
        assert!(!rendered.contains("response-secret"));
    }

    #[test]
    fn authorization_url_contains_pkce_state_scope_and_resource() {
        let oauth = OAuthClient::default();
        let client = RegisteredClient::public("gta-client").expect("reviewed public client");
        for invalid in [
            String::new(),
            " ".to_owned(),
            "client\nsecret".to_owned(),
            "a".repeat(257),
        ] {
            assert!(RegisteredClient::public(invalid).is_err());
        }
        let server = discovered_server(&Url::parse("https://auth.example/").expect("issuer URL"));
        let redirect = Url::parse("http://127.0.0.1:8989/callback").expect("redirect URL");
        let resource = Url::parse("https://mcp.example/rpc").expect("resource URL");

        let request = oauth
            .authorization_request(
                &server,
                &client,
                &redirect,
                Some("tools:read"),
                Some(&resource),
            )
            .expect("secure authorization URL");
        let query: BTreeMap<_, _> = request.url.query_pairs().into_owned().collect();

        assert_eq!(query.get("response_type"), Some(&"code".to_owned()));
        assert_eq!(query.get("client_id"), Some(&"gta-client".to_owned()));
        assert_eq!(query.get("scope"), Some(&"tools:read".to_owned()));
        assert_eq!(
            query.get("resource"),
            Some(&"https://mcp.example/rpc".to_owned())
        );
        assert_eq!(query.get("code_challenge_method"), Some(&"S256".to_owned()));
        assert_eq!(query.get("code_challenge"), Some(&request.pkce.challenge));
        assert_eq!(query.get("state"), Some(&request.state));
        assert_eq!(request.pkce.verifier().len(), 64);
    }

    #[tokio::test]
    async fn authorization_context_changes_and_expiry_are_refused_before_network() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("owned listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let base = Url::parse(&format!(
            "http://{}/",
            listener.local_addr().expect("address")
        ))
        .expect("base");
        let server = discovered_server(&base);
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: Some(SecretString::from("fixture-client-secret".to_owned())),
        };
        let redirect = base.join("callback").expect("redirect");
        let resource = base.join("mcp").expect("resource");
        let binding = CredentialBinding::new("fixture", &resource).expect("binding");
        let store = MemoryTokenStore::default();
        let oauth = OAuthClient::new(Duration::from_secs(1)).expect("client");
        for mode in 0..12 {
            let mut request = oauth
                .authorization_request(
                    &server,
                    &client,
                    &redirect,
                    Some("tools:read"),
                    Some(&resource),
                )
                .expect("authorization");
            let mut server_argument = server.clone();
            let mut client_argument = client.clone();
            let mut redirect_argument = redirect.clone();
            let mut resource_argument = Some(resource.clone());
            match mode {
                0 => server_argument.issuer = base.join("other-issuer").expect("issuer"),
                1 => {
                    server_argument.authorization_endpoint =
                        base.join("other-authorize").expect("authorization");
                }
                2 => server_argument.token_endpoint = base.join("other-token").expect("token"),
                3 => client_argument.client_id = "other-client".into(),
                4 => {
                    client_argument.client_secret =
                        Some(SecretString::from("other-secret".to_owned()));
                }
                5 => redirect_argument = base.join("other-callback").expect("redirect"),
                6 => resource_argument = Some(base.join("other-resource").expect("resource")),
                7 => resource_argument = None,
                8 => request.url.set_query(Some("state=changed")),
                9 => request.state = "changed-state".into(),
                10 => request.pkce = PkcePair::generate().expect("different PKCE"),
                11 => request.expires_at = Instant::now(),
                _ => unreachable!(),
            }
            let callback = AuthorizationCallback {
                code: "private-authorization-code",
                state: &request.state,
                request: &request,
                redirect_uri: &redirect_argument,
            };
            let debug = format!("{callback:?}");
            assert!(
                !debug.contains("private-authorization-code")
                    && !debug.contains(&request.state)
                    && !debug.contains(request.pkce.verifier())
            );
            let error = oauth
                .exchange_code(
                    &binding,
                    &store,
                    &server_argument,
                    &client_argument,
                    callback,
                    resource_argument.as_ref(),
                )
                .await
                .expect_err("altered or expired authorization");
            assert!(error.to_string().contains(if mode == 11 {
                "request expired"
            } else {
                "context changed"
            }));
            assert!(!request.attempted.load(Ordering::Acquire));
            assert!(store.load(&binding).expect("no tokens").is_none());
        }
        for query in [
            "client_id=other",
            "STATE=other",
            "redirect_uri=https://other.example",
            "code_challenge=other",
            "resource=https://other.example",
        ] {
            let mut changed = server.clone();
            changed.authorization_endpoint.set_query(Some(query));
            assert!(
                oauth
                    .authorization_request(&changed, &client, &redirect, None, Some(&resource))
                    .is_err()
            );
        }
        for redirect in [
            "http://remote.example/callback",
            "http://127.0.0.1/callback?state=other",
            "http://127.0.0.1/callback#fragment",
        ] {
            assert!(
                oauth
                    .authorization_request(
                        &server,
                        &client,
                        &Url::parse(redirect).expect("redirect"),
                        None,
                        Some(&resource)
                    )
                    .is_err()
            );
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[tokio::test]
    async fn authorization_exchange_never_replays_after_send_cancel_or_store_failure() {
        struct ExchangeStore {
            inner: MemoryTokenStore,
            fail_save: bool,
            saves: std::sync::atomic::AtomicUsize,
        }
        impl TokenStore for ExchangeStore {
            fn load(
                &self,
                binding: &CredentialBinding,
            ) -> std::result::Result<Option<TokenSet>, CredentialStoreError> {
                self.inner.load(binding)
            }
            fn save(
                &self,
                binding: &CredentialBinding,
                tokens: TokenSet,
            ) -> std::result::Result<(), CredentialStoreError> {
                self.saves.fetch_add(1, Ordering::SeqCst);
                if self.fail_save {
                    return Err(CredentialStoreError::new("fixture store unavailable"));
                }
                self.inner.save(binding, tokens)
            }
            fn delete(
                &self,
                binding: &CredentialBinding,
            ) -> std::result::Result<(), CredentialStoreError> {
                self.inner.delete(binding)
            }
        }
        for mode in [
            "success",
            "http-error",
            "lost-response",
            "cancel",
            "store-error",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("fixture listener");
            let base = Url::parse(&format!(
                "http://{}/",
                listener.local_addr().expect("address")
            ))
            .expect("base");
            let (observed, request_seen) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel();
            let transport = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("one exchange");
                let request = read_http_request(&mut stream).await;
                assert_eq!(request_line(&request), "POST /token HTTP/1.1");
                assert_eq!(
                    form_body(&request).get("code").map(String::as_str),
                    Some("private-single-use-code")
                );
                observed.send(()).expect("exchange observed");
                released.await.expect("fixture released");
                if mode == "lost-response" || mode == "cancel" {
                    return;
                }
                let (status, body) = if mode == "http-error" {
                    (
                        "400 Bad Request",
                        r#"{"error":"invalid_grant","error_description":"private-response-marker"}"#,
                    )
                } else {
                    (
                        "200 OK",
                        r#"{"access_token":"private-exchange-token","token_type":"Bearer","expires_in":3600}"#,
                    )
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("fixture response");
            });
            let oauth = OAuthClient::new(Duration::from_secs(2)).expect("client");
            let server = discovered_server(&base);
            let client = RegisteredClient {
                client_id: "single-use-client".into(),
                client_secret: None,
            };
            let redirect = base.join("callback").expect("redirect");
            let binding = CredentialBinding::new("single-use", &base).expect("binding");
            let store = ExchangeStore {
                inner: MemoryTokenStore::default(),
                fail_save: mode == "store-error",
                saves: std::sync::atomic::AtomicUsize::new(0),
            };
            let request = oauth
                .authorization_request(&server, &client, &redirect, None, Some(&base))
                .expect("authorization");
            let callback = || AuthorizationCallback {
                code: "private-single-use-code",
                state: &request.state,
                request: &request,
                redirect_uri: &redirect,
            };
            {
                let exchange = oauth.exchange_code(
                    &binding,
                    &store,
                    &server,
                    &client,
                    callback(),
                    Some(&base),
                );
                tokio::pin!(exchange);
                tokio::select! {
                    result = &mut exchange => panic!("exchange finished before fixture release: {result:?}"),
                    seen = request_seen => seen.expect("request sent"),
                }
                let duplicate = oauth
                    .exchange_code(&binding, &store, &server, &client, callback(), Some(&base))
                    .await
                    .expect_err("concurrent exchange is refused");
                assert!(duplicate.to_string().contains("already attempted"));
                release.send(()).expect("release fixture");
                if mode != "cancel" {
                    let result = exchange.await;
                    assert_eq!(result.is_ok(), mode == "success");
                    if let Err(error) = result {
                        assert!(!error.to_string().contains("private-response-marker"));
                    }
                }
            }
            let replay = oauth
                .exchange_code(&binding, &store, &server, &client, callback(), Some(&base))
                .await
                .expect_err("completed or abandoned exchange remains consumed");
            assert!(replay.to_string().contains("already attempted"));
            assert_eq!(
                store.saves.load(Ordering::SeqCst),
                usize::from(matches!(mode, "success" | "store-error"))
            );
            assert_eq!(
                store.load(&binding).expect("store state").is_some(),
                mode == "success"
            );
            transport.await.expect("owned server joined");
        }
    }

    #[tokio::test]
    async fn oauth_refresh_lost_response_fences_fresh_tokens_and_keeps_a_bounded_registry() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture listener");
        let base = Url::parse(&format!(
            "http://{}/",
            listener.local_addr().expect("address")
        ))
        .expect("base");
        let transport = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("one refresh");
            let request = read_http_request(&mut stream).await;
            assert_eq!(
                form_body(&request).get("grant_type").map(String::as_str),
                Some("refresh_token")
            );
        });
        let oauth = OAuthClient::new(Duration::from_secs(2)).expect("OAuth client");
        let server = discovered_server(&base);
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        };
        let binding = CredentialBinding::new("fixture", &base).expect("binding");
        let store = MemoryTokenStore::default();
        store
            .save(
                &binding,
                TokenSet {
                    access_token: SecretString::from("still-fresh-access".to_owned()),
                    refresh_token: Some(SecretString::from("single-use-refresh".to_owned())),
                    token_type: "Bearer".into(),
                    scope: None,
                    expires_at: None,
                    authority: Some(token_authority(&binding, &server, &client, Some(&base))),
                },
            )
            .expect("initial tokens");
        assert!(
            oauth
                .refresh(&binding, &store, &server, &client, Some(&base))
                .await
                .is_err()
        );
        transport.await.expect("owned server joined");
        let clone = oauth.clone();
        let retry = clone
            .refresh(&binding, &store, &server, &client, Some(&base))
            .await
            .expect_err("old refresh cannot be retried");
        assert!(retry.to_string().contains("requires new authorization"));
        let bearer = oauth
            .bearer_header(&binding, &store, &server, &client, Some(&base))
            .await
            .expect_err("fresh access cannot bypass an uncertain rotation");
        assert!(bearer.to_string().contains("requires new authorization"));
        assert_eq!(
            store
                .load(&binding)
                .expect("store")
                .expect("old tokens preserved")
                .access_token(),
            "still-fresh-access"
        );
        for index in 1..MAX_CREDENTIAL_BINDINGS {
            let other = CredentialBinding::new(format!("fixture-{index}"), &base).expect("binding");
            assert!(oauth.refresh_lock(&other).await.is_ok());
        }
        let overflow = CredentialBinding::new("overflow", &base).expect("binding");
        assert!(oauth.refresh_lock(&overflow).await.is_err());
        assert!(oauth.refresh_lock(&binding).await.is_ok());
        oauth
            .logout(&binding, &store)
            .await
            .expect("logout remains possible at capacity");
        assert!(store.load(&binding).expect("removed").is_none());
        assert_eq!(
            oauth.refresh_locks.lock().await.len(),
            MAX_CREDENTIAL_BINDINGS
        );
    }

    #[tokio::test]
    async fn uncertain_refresh_blocks_waiters_until_new_authorization_and_failed_logout_stays_closed()
     {
        struct RefreshStore {
            inner: MemoryTokenStore,
            fail_save: AtomicBool,
            fail_delete: AtomicBool,
        }
        impl TokenStore for RefreshStore {
            fn load(
                &self,
                binding: &CredentialBinding,
            ) -> std::result::Result<Option<TokenSet>, CredentialStoreError> {
                self.inner.load(binding)
            }
            fn save(
                &self,
                binding: &CredentialBinding,
                tokens: TokenSet,
            ) -> std::result::Result<(), CredentialStoreError> {
                if self.fail_save.load(Ordering::SeqCst) {
                    return Err(CredentialStoreError::new("fixture write failed"));
                }
                self.inner.save(binding, tokens)
            }
            fn delete(
                &self,
                binding: &CredentialBinding,
            ) -> std::result::Result<(), CredentialStoreError> {
                if self.fail_delete.load(Ordering::SeqCst) {
                    return Err(CredentialStoreError::new("fixture deletion failed"));
                }
                self.inner.delete(binding)
            }
        }
        for mode in [
            "http-error",
            "lost-response",
            "invalid-json",
            "invalid-token",
            "cancel",
            "store-error",
        ] {
            for automatic in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("fixture listener");
                let base = Url::parse(&format!(
                    "http://{}/",
                    listener.local_addr().expect("address")
                ))
                .expect("base");
                let (observed, request_seen) = tokio::sync::oneshot::channel();
                let (release, released) = tokio::sync::oneshot::channel();
                let transport = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.expect("one refresh");
                    let request = read_http_request(&mut stream).await;
                    assert_eq!(
                        form_body(&request).get("grant_type").map(String::as_str),
                        Some("refresh_token")
                    );
                    observed.send(()).expect("refresh observed");
                    released.await.expect("fixture released");
                    if mode != "lost-response" && mode != "cancel" {
                        let (status, body) = match mode {
                            "http-error" => ("400 Bad Request", r#"{"error":"invalid_grant"}"#),
                            "invalid-json" => {
                                ("200 OK", r#"{"access_token":"private-malformed-marker""#)
                            }
                            "invalid-token" => (
                                "200 OK",
                                r#"{"access_token":"private-invalid-token","token_type":"MAC"}"#,
                            ),
                            _ => (
                                "200 OK",
                                r#"{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}"#,
                            ),
                        };
                        stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("refresh response");
                    }
                    drop(stream);
                    let (mut stream, _) =
                        tokio::time::timeout(Duration::from_secs(2), listener.accept())
                            .await
                            .expect("new authorization arrives")
                            .expect("new exchange");
                    let request = read_http_request(&mut stream).await;
                    assert_eq!(
                        form_body(&request).get("grant_type").map(String::as_str),
                        Some("authorization_code"),
                        "old refresh was not replayed"
                    );
                    let body = r#"{"access_token":"new-authorized-access","refresh_token":"new-authorized-refresh","expires_in":3600}"#;
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("new authorization response");
                });
                let oauth = OAuthClient::new(Duration::from_secs(2)).expect("OAuth client");
                let clone = oauth.clone();
                let server = discovered_server(&base);
                let client = RegisteredClient {
                    client_id: "fixture-client".into(),
                    client_secret: None,
                };
                let binding = CredentialBinding::new("fixture", &base).expect("binding");
                let store = RefreshStore {
                    inner: MemoryTokenStore::default(),
                    fail_save: AtomicBool::new(mode == "store-error"),
                    fail_delete: AtomicBool::new(false),
                };
                store
                    .inner
                    .save(
                        &binding,
                        TokenSet {
                            access_token: SecretString::from("original-access".to_owned()),
                            refresh_token: Some(SecretString::from("original-refresh".to_owned())),
                            token_type: "Bearer".into(),
                            scope: None,
                            expires_at: automatic.then(SystemTime::now),
                            authority: Some(token_authority(
                                &binding,
                                &server,
                                &client,
                                Some(&base),
                            )),
                        },
                    )
                    .expect("initial tokens");
                let mut first = Box::pin(async {
                    if automatic {
                        oauth
                            .bearer_header(&binding, &store, &server, &client, Some(&base))
                            .await
                            .map(|_| ())
                    } else {
                        oauth
                            .refresh(&binding, &store, &server, &client, Some(&base))
                            .await
                            .map(|_| ())
                    }
                });
                tokio::select! {
                    result = &mut first => panic!("refresh completed before fixture release: {result:?}"),
                    seen = request_seen => seen.expect("refresh sent"),
                }
                let mut queued =
                    Box::pin(clone.refresh(&binding, &store, &server, &client, Some(&base)));
                assert!(futures_util::poll!(queued.as_mut()).is_pending());
                release.send(()).expect("release fixture");
                if mode != "cancel" {
                    let error = first.as_mut().await.expect_err("unconfirmed refresh");
                    assert!(!error.to_string().contains("private-malformed-marker"));
                }
                drop(first);
                let error = queued.await.expect_err("queued refresh must not replay");
                assert!(error.to_string().contains("requires new authorization"));
                let error = oauth
                    .bearer_header(&binding, &store, &server, &client, Some(&base))
                    .await
                    .expect_err("no stale bearer");
                assert!(error.to_string().contains("requires new authorization"));
                assert_eq!(
                    store
                        .load(&binding)
                        .expect("preserved store")
                        .expect("old tokens")
                        .refresh_token(),
                    Some("original-refresh")
                );
                store.fail_save.store(false, Ordering::SeqCst);
                let redirect = base.join("callback").expect("redirect");
                let request = oauth
                    .authorization_request(&server, &client, &redirect, None, Some(&base))
                    .expect("new authorization");
                oauth
                    .exchange_code(
                        &binding,
                        &store,
                        &server,
                        &client,
                        AuthorizationCallback {
                            code: "new-authorization-code",
                            state: &request.state,
                            request: &request,
                            redirect_uri: &redirect,
                        },
                        Some(&base),
                    )
                    .await
                    .expect("explicit new authorization restores this binding");
                let bearer = clone
                    .bearer_header(&binding, &store, &server, &client, Some(&base))
                    .await
                    .expect("new access token");
                assert_eq!(
                    bearer.value.to_str().expect("header"),
                    "Bearer new-authorized-access"
                );
                store.fail_delete.store(true, Ordering::SeqCst);
                assert!(oauth.logout(&binding, &store).await.is_err());
                let error = clone
                    .bearer_header(&binding, &store, &server, &client, Some(&base))
                    .await
                    .expect_err("failed deletion stays closed");
                assert!(error.to_string().contains("requires new authorization"));
                store.fail_delete.store(false, Ordering::SeqCst);
                oauth
                    .logout(&binding, &store)
                    .await
                    .expect("explicit retry removes local entry");
                assert!(store.load(&binding).expect("removed").is_none());
                transport.await.expect("owned fixture joined");
            }
        }
    }

    #[tokio::test]
    async fn explicit_oauth_routes_refuse_unenrolled_targets_before_network() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("owned listener");
        listener.set_nonblocking(true).expect("nonblocking witness");
        let base = Url::parse(&format!(
            "http://{}/",
            listener.local_addr().expect("address")
        ))
        .expect("base");
        let route = HttpRoutePolicy::direct_loopback(base.join("token").expect("token endpoint"))
            .expect("route");
        assert!(OAuthClient::with_routes(Duration::from_secs(1), []).is_err());
        assert!(
            OAuthClient::with_routes(Duration::from_secs(1), [route.clone(), route.clone()])
                .is_err()
        );
        let routes = (0..=MAX_OAUTH_ROUTES).map(|index| {
            HttpRoutePolicy::direct_loopback(
                base.join(&format!("endpoint-{index}")).expect("endpoint"),
            )
            .expect("route")
        });
        assert!(OAuthClient::with_routes(Duration::from_secs(1), routes).is_err());
        let oauth =
            OAuthClient::with_routes(Duration::from_secs(1), [route]).expect("reviewed client");
        let server = discovered_server(&base);
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        };
        assert!(
            oauth
                .discover_resource(&base)
                .await
                .expect_err("unreviewed resource metadata")
                .to_string()
                .contains("enrolled route")
        );
        assert!(
            oauth
                .discover_authorization_server(&base)
                .await
                .expect_err("unreviewed issuer metadata")
                .to_string()
                .contains("enrolled route")
        );
        assert!(
            oauth
                .register(
                    &server,
                    &ClientMetadata::native(
                        base.join("callback").expect("redirect").as_str(),
                        None
                    )
                )
                .await
                .expect_err("unreviewed registration")
                .to_string()
                .contains("enrolled route")
        );
        assert!(
            oauth
                .authorization_request(
                    &server,
                    &client,
                    &base.join("callback").expect("redirect"),
                    None,
                    Some(&base)
                )
                .expect_err("unreviewed browser endpoint")
                .to_string()
                .contains("enrolled route")
        );
        let bearer = BoundBearerHeader {
            binding: CredentialBinding::new("fixture", &base).expect("binding"),
            value: HeaderValue::from_static("Bearer private-route-token"),
        };
        let error = oauth
            .send_authorized(
                Method::POST,
                base.join("mcp").expect("resource"),
                HeaderMap::new(),
                Vec::new(),
                bearer,
            )
            .await
            .expect_err("unreviewed resource path");
        assert!(
            error.to_string().contains("enrolled route")
                && !error.to_string().contains("private-route-token")
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[tokio::test]
    async fn explicit_oauth_discovery_cannot_enroll_replaced_authorization_or_token_endpoints() {
        for replaced in ["authorize", "token"] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("owned metadata server");
            let base = Url::parse(&format!(
                "http://{}/",
                listener.local_addr().expect("address")
            ))
            .expect("base");
            let unreviewed =
                std::net::TcpListener::bind("127.0.0.1:0").expect("unreviewed target witness");
            unreviewed
                .set_nonblocking(true)
                .expect("nonblocking witness");
            let unreviewed_url = format!(
                "http://{}/{replaced}",
                unreviewed.local_addr().expect("unreviewed address")
            );
            let body = serde_json::to_string(&serde_json::json!({
                "issuer":base.as_str(),
                "authorization_endpoint":if replaced == "authorize" { unreviewed_url.clone() } else { base.join("authorize").expect("authorization endpoint").to_string() },
                "token_endpoint":if replaced == "token" { unreviewed_url } else { base.join("token").expect("token endpoint").to_string() },
                "code_challenge_methods_supported":["S256"]
            })).expect("metadata");
            let transport = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("one discovery request");
                let request = read_http_request(&mut stream).await;
                assert_eq!(
                    request_line(&request),
                    "GET /.well-known/oauth-authorization-server HTTP/1.1"
                );
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("metadata response");
            });
            let routes = [
                ".well-known/oauth-authorization-server",
                "authorize",
                "token",
            ]
            .map(|path| {
                HttpRoutePolicy::direct_loopback(base.join(path).expect("endpoint")).expect("route")
            });
            let oauth = OAuthClient::with_routes(Duration::from_secs(2), routes)
                .expect("reviewed OAuth client");
            let error = oauth
                .discover_authorization_server(&base)
                .await
                .expect_err("unreviewed metadata target rejected");
            assert!(error.to_string().contains("enrolled route"));
            transport.await.expect("owned server joined");
            assert!(
                matches!(unreviewed.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        }
    }

    #[tokio::test]
    async fn explicit_oauth_https_exchange_uses_only_the_owned_connect_proxy_without_secrets() {
        let proxy = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned CONNECT proxy");
        let proxy_url = Url::parse(&format!(
            "http://{}/",
            proxy.local_addr().expect("proxy address")
        ))
        .expect("proxy URL");
        let transport = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.expect("explicit proxy connection");
            let request = read_http_request(&mut stream).await;
            assert_eq!(
                request_line(&request),
                "CONNECT approved-oauth.example:443 HTTP/1.1"
            );
            let headers = request_headers(&request);
            assert!(
                !headers.contains_key("authorization")
                    && !headers.contains_key("proxy-authorization")
            );
            assert!(
                !request.contains("private-oauth")
                    && !request.contains("code_verifier")
                    && !request.contains("client_secret")
            );
            stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("proxy refusal");
        });
        let base = Url::parse("https://approved-oauth.example/").expect("explicit fixture origin");
        let routes = ["authorize", "token"].map(|path| {
            HttpRoutePolicy::https_via_proxy(
                base.join(path).expect("OAuth endpoint"),
                proxy_url.clone(),
            )
            .expect("enrolled proxy route")
        });
        let oauth =
            OAuthClient::with_routes(Duration::from_secs(2), routes).expect("OAuth route client");
        let server = discovered_server(&base);
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: Some(SecretString::from("private-oauth-client-secret".to_owned())),
        };
        let redirect = Url::parse("http://127.0.0.1:8989/callback").expect("redirect");
        let binding = CredentialBinding::new("fixture", &base).expect("binding");
        let store = MemoryTokenStore::default();
        let request = oauth
            .authorization_request(&server, &client, &redirect, None, Some(&base))
            .expect("authorization URL only");
        let error = oauth
            .exchange_code(
                &binding,
                &store,
                &server,
                &client,
                AuthorizationCallback {
                    code: "private-oauth-authorization-code",
                    state: &request.state,
                    request: &request,
                    redirect_uri: &redirect,
                },
                Some(&base),
            )
            .await
            .expect_err("failed proxy cannot fall back to remote direct access");
        assert!(!error.to_string().contains("private-oauth"));
        assert!(store.load(&binding).expect("store remains empty").is_none());
        transport.await.expect("owned proxy joined");
    }

    #[test]
    fn callback_redirects_require_exact_unique_state_target_and_optional_issuer() {
        let oauth = OAuthClient::default();
        let server = discovered_server(&Url::parse("https://auth.example/").expect("issuer"));
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        };
        let redirect = Url::parse("http://127.0.0.1:32109/callback").expect("callback");
        let resource = Url::parse("https://mcp.example/rpc").expect("resource");
        let request = oauth
            .authorization_request(&server, &client, &redirect, None, Some(&resource))
            .expect("authorization");
        let mut returned = redirect.clone();
        returned
            .query_pairs_mut()
            .append_pair("code", "private-callback-code")
            .append_pair("state", &request.state)
            .append_pair("iss", server.issuer().as_str());
        let parsed = request
            .parse_redirect(returned.as_str())
            .expect("bound callback");
        assert_eq!(parsed.as_callback().code, "private-callback-code");
        assert_eq!(parsed.as_callback().redirect_uri, &redirect);
        assert!(!format!("{parsed:?}").contains("private-callback-code"));
        for mode in 0..16 {
            let mut invalid = returned.clone();
            match mode {
                0 => {
                    invalid.set_path("/different");
                }
                1 => {
                    invalid.set_port(Some(32110)).expect("port");
                }
                2 => {
                    invalid.set_host(Some("localhost")).expect("host");
                }
                3 => {
                    invalid.set_fragment(Some("fragment"));
                }
                4 => {
                    invalid.set_username("user").expect("userinfo");
                }
                5 => {
                    invalid.query_pairs_mut().append_pair("code", "second-code");
                }
                6 => {
                    invalid
                        .query_pairs_mut()
                        .append_pair("state", &request.state);
                }
                7 => {
                    invalid
                        .query_pairs_mut()
                        .append_pair("iss", server.issuer().as_str());
                }
                8 => {
                    invalid
                        .query_pairs_mut()
                        .append_pair("error", "access_denied");
                }
                9 => {
                    invalid
                        .query_pairs_mut()
                        .append_pair("error_description", "private-provider-description");
                }
                10 => {
                    invalid.query_pairs_mut().append_pair("scope", "unreviewed");
                }
                11 => {
                    invalid.set_query(Some("code=private-code&state=wrong"));
                }
                12 => {
                    invalid.set_query(Some(&format!(
                        "code=private-code&state={}&iss=https%3A%2F%2Fother.example%2F",
                        request.state
                    )));
                }
                13 => {
                    invalid.set_query(Some(&format!("code=%FF&state={}", request.state)));
                }
                14 => {
                    invalid.set_query(Some(&format!("code=bad%ZZ&state={}", request.state)));
                }
                15 => {
                    invalid.set_query(Some(&format!("code=bad%0Acode&state={}", request.state)));
                }
                _ => unreachable!(),
            }
            let error = request
                .parse_redirect(invalid.as_str())
                .expect_err("invalid callback");
            assert!(!error.to_string().contains("private-"));
            assert!(!request.attempted.load(Ordering::Acquire));
        }
        let mut without_issuer = redirect.clone();
        without_issuer
            .query_pairs_mut()
            .append_pair("code", "private-callback-code")
            .append_pair("state", &request.state);
        assert!(request.parse_redirect(without_issuer.as_str()).is_ok());
        let mut denied = redirect.clone();
        denied
            .query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("state", &request.state)
            .append_pair("error_description", "private-provider-description")
            .append_pair("error_uri", "https://unreviewed.example/error");
        let error = request
            .parse_redirect(denied.as_str())
            .expect_err("explicit denial");
        assert!(
            error.to_string().contains("was denied")
                && !error.to_string().contains("private-provider-description")
        );
        assert!(request.parse_redirect(returned.as_str()).is_err());
        let mut expired = oauth
            .authorization_request(&server, &client, &redirect, None, Some(&resource))
            .expect("another authorization");
        expired.expires_at = Instant::now();
        assert!(expired.parse_redirect(returned.as_str()).is_err());
    }

    #[test]
    fn authorization_server_discovery_preserves_path_based_issuers() {
        let root = Url::parse("https://auth.example/").expect("root issuer");
        let tenant =
            Url::parse("https://auth.example/realms/tenant?ignored=1").expect("path issuer");

        assert_eq!(
            authorization_server_metadata_url(&root).as_str(),
            "https://auth.example/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            authorization_server_metadata_url(&tenant).as_str(),
            "https://auth.example/.well-known/oauth-authorization-server/realms/tenant"
        );
    }

    #[test]
    fn remote_cleartext_authorization_endpoint_is_rejected() {
        let error = validated_metadata_endpoint(
            "http://auth.example/authorize",
            "OAuth authorization endpoint",
        )
        .expect_err("remote cleartext authorization must fail");

        assert_eq!(
            error.to_string(),
            "MCP protocol violation: OAuth authorization endpoint must use HTTPS unless it is a loopback HTTP URL"
        );
    }

    #[tokio::test]
    async fn local_authorization_server_covers_registration_exchange_and_refresh() {
        let (base, requests, server) = start_authorization_fixture().await;
        let routes = [
            ".well-known/oauth-protected-resource",
            ".well-known/oauth-authorization-server",
            "authorize",
            "register",
            "token",
            "mcp",
        ]
        .map(|path| {
            HttpRoutePolicy::direct_loopback(base.join(path).expect("fixture endpoint"))
                .expect("fixture route")
        });
        let oauth = OAuthClient::with_routes(Duration::from_secs(2), routes).expect("OAuth client");
        let resource_metadata = oauth
            .discover_resource(
                &base
                    .join(".well-known/oauth-protected-resource")
                    .expect("resource metadata URL"),
            )
            .await
            .expect("protected resource discovery");
        assert_eq!(resource_metadata.resource, base.as_str());
        assert_eq!(
            resource_metadata.authorization_servers,
            vec![base.as_str().to_owned()]
        );
        assert_eq!(resource_metadata.scopes_supported, vec!["tools:read"]);
        let server_metadata = oauth
            .discover_authorization_server(&base)
            .await
            .expect("authorization server discovery");
        assert_eq!(server_metadata.issuer(), &base);
        assert_eq!(
            server_metadata.authorization_endpoint(),
            &base.join("authorize").expect("authorize URL")
        );
        assert_eq!(
            server_metadata.token_endpoint(),
            &base.join("token").expect("token URL")
        );
        assert_eq!(
            server_metadata.registration_endpoint(),
            Some(&base.join("register").expect("register URL"))
        );
        assert_eq!(
            server_metadata.metadata().code_challenge_methods_supported,
            vec!["S256"]
        );
        let callback_listener =
            LoopbackAuthorizationListener::bind("127.0.0.1:0".parse().expect("callback address"))
                .await
                .expect("owned callback receiver");
        let redirect_uri = callback_listener.redirect_uri().clone();
        let metadata = ClientMetadata::native(redirect_uri.as_str(), Some("tools:read".into()));
        let client = oauth
            .register(&server_metadata, &metadata)
            .await
            .expect("dynamic registration");
        assert_eq!(client.client_id(), "fixture-client");

        let authorization = oauth
            .authorization_request(
                &server_metadata,
                &client,
                &redirect_uri,
                Some("tools:read"),
                Some(&base),
            )
            .expect("loopback authorization URL");
        let binding = CredentialBinding::new(
            format!(
                "oauth-local-{}-{}",
                std::process::id(),
                base.port().expect("fixture port")
            ),
            &base,
        )
        .expect("credential binding");
        #[cfg(windows)]
        let store = NativeTokenStore::new().expect("native token store required");
        #[cfg(not(windows))]
        let store = MemoryTokenStore::default();
        assert!(
            store
                .load(&binding)
                .expect("unique fixture credential preflight")
                .is_none()
        );
        #[cfg(windows)]
        let _owned = OwnedNativeTokens {
            store: store.clone(),
            binding: binding.clone(),
        };
        let state_error = oauth
            .exchange_code(
                &binding,
                &store,
                &server_metadata,
                &client,
                AuthorizationCallback {
                    code: "authorization-code",
                    state: "wrong-state",
                    request: &authorization,
                    redirect_uri: &redirect_uri,
                },
                Some(&base),
            )
            .await
            .expect_err("a mismatched callback state must fail before token exchange");
        assert_eq!(
            state_error.to_string(),
            "MCP protocol violation: OAuth callback state mismatch"
        );
        let mut returned = redirect_uri.clone();
        returned
            .query_pairs_mut()
            .append_pair("code", "authorization-code")
            .append_pair("state", &authorization.state)
            .append_pair("iss", server_metadata.issuer().as_str());
        let callback_sender = tokio::spawn(async move {
            let address = returned
                .socket_addrs(|| None)
                .expect("literal callback address")[0];
            let mut stream = tokio::net::TcpStream::connect(address)
                .await
                .expect("owned callback connection");
            stream
                .write_all(
                    format!(
                        "GET {} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",
                        &returned[url::Position::BeforePath..]
                    )
                    .as_bytes(),
                )
                .await
                .expect("callback redirect");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("callback response");
            let response = String::from_utf8(response).expect("response text");
            assert!(
                response.starts_with("HTTP/1.1 200") && !response.contains("authorization-code")
            );
        });
        let captured = callback_listener
            .receive(&authorization, &tokio_util::sync::CancellationToken::new())
            .await
            .expect("validated HTTP callback");
        callback_sender.await.expect("callback sender joined");
        let exchanged = oauth
            .exchange_code(
                &binding,
                &store,
                &server_metadata,
                &client,
                captured.as_callback(),
                Some(&base),
            )
            .await
            .expect("token exchange");
        assert!(!exchanged.is_fresh(SystemTime::now()));
        assert!(exchanged.can_refresh());

        let replay = oauth
            .exchange_code(
                &binding,
                &store,
                &server_metadata,
                &client,
                AuthorizationCallback {
                    code: "authorization-code",
                    state: &authorization.state,
                    request: &authorization,
                    redirect_uri: &redirect_uri,
                },
                Some(&base),
            )
            .await
            .expect_err("the same request is locally single-use");
        assert!(replay.to_string().contains("already attempted"));

        let header = oauth
            .bearer_header(&binding, &store, &server_metadata, &client, Some(&base))
            .await
            .expect("refresh and bearer");
        assert_eq!(
            header.value.to_str().expect("header text"),
            "Bearer refreshed-access"
        );
        assert!(header.value.is_sensitive());
        assert_eq!(
            store
                .load(&binding)
                .expect("refreshed record")
                .expect("stored tokens")
                .scope(),
            Some("tools:read"),
            "omitted refresh scope retains the original grant"
        );
        let authorized = oauth
            .send_authorized(
                Method::POST,
                base.join("mcp").expect("MCP resource URL"),
                HeaderMap::new(),
                b"{\"operation\":\"tools/list\"}".to_vec(),
                header,
            )
            .await
            .expect("authorized MCP request");
        assert_eq!(authorized.status(), StatusCode::OK);
        assert_eq!(authorized.body(), b"{\"authorized\":true}");

        #[cfg(windows)]
        {
            let reopened = NativeTokenStore::new().expect("independent native store");
            let restored = reopened
                .load(&binding)
                .expect("persisted OAuth record")
                .expect("refreshed token");
            assert_eq!(restored.access_token(), "refreshed-access");
            restored
                .require_authority(&token_authority(
                    &binding,
                    &server_metadata,
                    &client,
                    Some(&base),
                ))
                .expect("authority survives native storage");
        }
        oauth.logout(&binding, &store).await.expect("logout");
        assert!(store.load(&binding).expect("load after logout").is_none());

        server.await.expect("fixture server task");
        let requests = std::mem::take(&mut *requests.lock().expect("request log"));
        assert_eq!(requests.len(), 6);
        assert_eq!(
            request_line(&requests[0]),
            "GET /.well-known/oauth-protected-resource HTTP/1.1"
        );
        assert_eq!(
            request_line(&requests[1]),
            "GET /.well-known/oauth-authorization-server HTTP/1.1"
        );
        assert_eq!(request_line(&requests[2]), "POST /register HTTP/1.1");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(request_body(&requests[2]))
                .expect("registration body JSON"),
            serde_json::json!({
                "client_name": "GTA-Claw MCP",
                "redirect_uris": [redirect_uri.as_str()],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "scope": "tools:read"
            })
        );
        assert_eq!(request_line(&requests[3]), "POST /token HTTP/1.1");
        assert_eq!(
            form_body(&requests[3]),
            BTreeMap::from([
                ("client_id".into(), "fixture-client".into()),
                ("client_secret".into(), "fixture-client-secret".into()),
                ("code".into(), "authorization-code".into()),
                ("code_verifier".into(), authorization.pkce.verifier().into()),
                ("grant_type".into(), "authorization_code".into()),
                ("redirect_uri".into(), redirect_uri.as_str().into()),
                ("resource".into(), base.as_str().into()),
            ])
        );
        assert_eq!(request_line(&requests[4]), "POST /token HTTP/1.1");
        assert_eq!(
            form_body(&requests[4]),
            BTreeMap::from([
                ("client_id".into(), "fixture-client".into()),
                ("client_secret".into(), "fixture-client-secret".into()),
                ("grant_type".into(), "refresh_token".into()),
                ("refresh_token".into(), "fixture-refresh".into()),
                ("resource".into(), base.as_str().into()),
            ])
        );
        assert_eq!(request_line(&requests[5]), "POST /mcp HTTP/1.1");
        let expected_authorization = ["Bearer", "refreshed-access"].join(" ");
        assert_eq!(
            request_headers(&requests[5]).get("authorization"),
            Some(&expected_authorization)
        );
        assert_eq!(request_body(&requests[5]), "{\"operation\":\"tools/list\"}");
    }

    #[tokio::test]
    async fn token_authority_prevents_issuer_client_and_resource_substitution_without_network() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("owned listener");
        listener.set_nonblocking(true).expect("nonblocking witness");
        let base = Url::parse(&format!(
            "http://{}/",
            listener.local_addr().expect("address")
        ))
        .expect("base");
        let oauth = OAuthClient::with_routes(
            Duration::from_secs(1),
            ["authorize", "token", "other-token"].map(|path| {
                HttpRoutePolicy::direct_loopback(base.join(path).expect("endpoint"))
                    .expect("reviewed route")
            }),
        )
        .expect("OAuth client");
        let server = discovered_server(&base);
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: Some(SecretString::from("private-client-secret".to_owned())),
        };
        let resource = base.join("mcp").expect("resource");
        let binding = CredentialBinding::new("fixture", &resource).expect("binding");
        let tokens = TokenSet {
            access_token: SecretString::from("private-authority-access".to_owned()),
            refresh_token: Some(SecretString::from("private-authority-refresh".to_owned())),
            token_type: "Bearer".into(),
            scope: None,
            expires_at: None,
            authority: Some(token_authority(&binding, &server, &client, Some(&resource))),
        };
        for mode in 0..9 {
            let mut altered_server = server.clone();
            let mut altered_client = client.clone();
            let mut altered_resource = Some(resource.clone());
            let mut altered_binding = binding.clone();
            let mut retained = tokens.clone();
            match mode {
                0 => altered_server.issuer = base.join("other-issuer").expect("issuer"),
                1 => {
                    altered_server.token_endpoint =
                        base.join("other-token").expect("token endpoint");
                }
                2 => {
                    altered_server.authorization_endpoint =
                        base.join("other-authorize").expect("authorize endpoint");
                }
                3 => altered_client.client_id = "different-client".into(),
                4 => {
                    altered_client.client_secret =
                        Some(SecretString::from("different-secret".to_owned()));
                }
                5 => altered_resource = Some(base.join("different-resource").expect("resource")),
                6 => altered_resource = None,
                7 => {
                    altered_binding =
                        CredentialBinding::new("other-profile", &resource).expect("other binding");
                }
                8 => retained.authority = None,
                _ => unreachable!(),
            }
            let store = MemoryTokenStore::default();
            store
                .save(&altered_binding, retained)
                .expect("retained token");
            let refresh = oauth
                .refresh(
                    &altered_binding,
                    &store,
                    &altered_server,
                    &altered_client,
                    altered_resource.as_ref(),
                )
                .await
                .expect_err("token cannot cross enrolled authority");
            let bearer = oauth
                .bearer_header(
                    &altered_binding,
                    &store,
                    &altered_server,
                    &altered_client,
                    altered_resource.as_ref(),
                )
                .await
                .expect_err("fresh token cannot bypass authority binding");
            for error in [refresh, bearer] {
                assert!(error.to_string().contains("token authority"));
                assert!(!error.to_string().contains("private-"));
            }
            store
                .save(&binding, tokens.clone())
                .expect("original token under original key");
            assert!(
                oauth
                    .bearer_header(&binding, &store, &server, &client, Some(&resource))
                    .await
                    .is_ok(),
                "rejected metadata does not disable unchanged original enrollment"
            );
        }
        let store = MemoryTokenStore::default();
        for automatic in [false, true] {
            store
                .save(&binding, tokens.clone())
                .expect("original enrollment");
            let lock = oauth.refresh_lock(&binding).await.expect("binding lock");
            let guard = lock.lock().await;
            let mut pending = Box::pin(async {
                if automatic {
                    oauth
                        .bearer_header(&binding, &store, &server, &client, Some(&resource))
                        .await
                        .map(|_| ())
                } else {
                    oauth
                        .refresh(&binding, &store, &server, &client, Some(&resource))
                        .await
                        .map(|_| ())
                }
            });
            assert!(futures_util::poll!(pending.as_mut()).is_pending());
            let mut replacement = tokens.clone();
            replacement.authority = None;
            store
                .save(&binding, replacement)
                .expect("replacement during lock wait");
            drop(guard);
            assert!(
                pending
                    .await
                    .expect_err("resumed operation rechecks token authority")
                    .to_string()
                    .contains("token authority")
            );
        }
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[tokio::test]
    async fn refused_update_markers_prevent_token_requests_before_network() {
        struct RefusingStore {
            tokens: TokenSet,
            markers: std::sync::atomic::AtomicUsize,
        }
        impl TokenStore for RefusingStore {
            fn load(
                &self,
                _: &CredentialBinding,
            ) -> std::result::Result<Option<TokenSet>, CredentialStoreError> {
                Ok(Some(self.tokens.clone()))
            }
            fn begin_update(
                &self,
                _: &CredentialBinding,
                _: Option<&TokenSet>,
            ) -> std::result::Result<(), CredentialStoreError> {
                self.markers.fetch_add(1, Ordering::SeqCst);
                Err(CredentialStoreError::new("fixture pending marker refused"))
            }
            fn save(
                &self,
                _: &CredentialBinding,
                _: TokenSet,
            ) -> std::result::Result<(), CredentialStoreError> {
                panic!("refused marker cannot reach credential save")
            }
            fn delete(
                &self,
                _: &CredentialBinding,
            ) -> std::result::Result<(), CredentialStoreError> {
                Ok(())
            }
        }
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("owned no-network witness");
        listener.set_nonblocking(true).expect("nonblocking witness");
        let base = Url::parse(&format!(
            "http://{}/",
            listener.local_addr().expect("address")
        ))
        .expect("base");
        let oauth = OAuthClient::new(Duration::from_secs(1)).expect("OAuth client");
        let server = discovered_server(&base);
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        };
        let binding = CredentialBinding::new("fixture", &base).expect("binding");
        let store = RefusingStore {
            tokens: TokenSet {
                access_token: SecretString::from("private-marker-access".to_owned()),
                refresh_token: Some(SecretString::from("private-marker-refresh".to_owned())),
                token_type: "Bearer".into(),
                scope: None,
                expires_at: None,
                authority: Some(token_authority(&binding, &server, &client, Some(&base))),
            },
            markers: std::sync::atomic::AtomicUsize::new(0),
        };
        let error = oauth
            .refresh(&binding, &store, &server, &client, Some(&base))
            .await
            .expect_err("refused refresh marker");
        assert!(error.to_string().contains("fixture pending marker refused"));
        let redirect = base.join("callback").expect("redirect");
        let request = oauth
            .authorization_request(&server, &client, &redirect, None, Some(&base))
            .expect("new authorization");
        let error = oauth
            .exchange_code(
                &binding,
                &store,
                &server,
                &client,
                AuthorizationCallback {
                    code: "private-authorization-code",
                    state: &request.state,
                    request: &request,
                    redirect_uri: &redirect,
                },
                Some(&base),
            )
            .await
            .expect_err("refused code exchange marker");
        assert!(error.to_string().contains("fixture pending marker refused"));
        let restricted = OAuthClient::with_routes(
            Duration::from_secs(1),
            [
                HttpRoutePolicy::direct_loopback(base.join("other").expect("other route"))
                    .expect("route"),
            ],
        )
        .expect("restricted client");
        let error = restricted
            .refresh(&binding, &store, &server, &client, Some(&base))
            .await
            .expect_err("unreviewed token route");
        assert!(error.to_string().contains("enrolled route"));
        let request = oauth
            .authorization_request(&server, &client, &redirect, None, Some(&base))
            .expect("fresh authorization");
        let error = restricted
            .exchange_code(
                &binding,
                &store,
                &server,
                &client,
                AuthorizationCallback {
                    code: "private-authorization-code",
                    state: &request.state,
                    request: &request,
                    redirect_uri: &redirect,
                },
                Some(&base),
            )
            .await
            .expect_err("unreviewed exchange route");
        assert!(error.to_string().contains("enrolled route"));
        assert!(!request.attempted.load(Ordering::Acquire));
        assert_eq!(store.markers.load(Ordering::SeqCst), 2);
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn native_oauth_lost_response_survives_client_reopen_without_reusing_old_credentials() {
        for refresh in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("owned token server");
            let base = Url::parse(&format!(
                "http://{}/",
                listener.local_addr().expect("address")
            ))
            .expect("base");
            let transport = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("first token request");
                let request = read_http_request(&mut stream).await;
                assert_eq!(
                    form_body(&request).get("grant_type").map(String::as_str),
                    Some(if refresh {
                        "refresh_token"
                    } else {
                        "authorization_code"
                    })
                );
                drop(stream);
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(3), listener.accept())
                        .await
                        .expect("explicit new authorization")
                        .expect("new token request");
                let request = read_http_request(&mut stream).await;
                assert_eq!(
                    form_body(&request).get("grant_type").map(String::as_str),
                    Some("authorization_code")
                );
                assert_eq!(
                    form_body(&request).get("code").map(String::as_str),
                    Some("new-authorization-code")
                );
                let body = r#"{"access_token":"new-native-access","refresh_token":"new-native-refresh","expires_in":3600}"#;
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("new token response");
            });
            let routes = ["authorize", "token"].map(|path| {
                HttpRoutePolicy::direct_loopback(base.join(path).expect("endpoint")).expect("route")
            });
            let oauth = OAuthClient::with_routes(Duration::from_secs(2), routes.clone())
                .expect("OAuth client");
            let server = discovered_server(&base);
            let client = RegisteredClient {
                client_id: "native-fixture-client".into(),
                client_secret: None,
            };
            let binding = CredentialBinding::new(
                format!(
                    "native-lost-{}-{}",
                    std::process::id(),
                    base.port().expect("fixture port")
                ),
                &base,
            )
            .expect("binding");
            let store = NativeTokenStore::new().expect("native token store required");
            assert!(
                store
                    .load(&binding)
                    .expect("unique owned key preflight")
                    .is_none()
            );
            let owned = OwnedNativeTokens {
                store: store.clone(),
                binding: binding.clone(),
            };
            store
                .save(
                    &binding,
                    TokenSet {
                        access_token: SecretString::from("private-original-access".to_owned()),
                        refresh_token: Some(SecretString::from(
                            "private-original-refresh".to_owned(),
                        )),
                        token_type: "Bearer".into(),
                        scope: None,
                        expires_at: None,
                        authority: Some(token_authority(&binding, &server, &client, Some(&base))),
                    },
                )
                .expect("initial token fixture");
            let redirect = base.join("callback").expect("redirect");
            let result = if refresh {
                oauth
                    .refresh(&binding, &store, &server, &client, Some(&base))
                    .await
            } else {
                let request = oauth
                    .authorization_request(&server, &client, &redirect, None, Some(&base))
                    .expect("authorization");
                oauth
                    .exchange_code(
                        &binding,
                        &store,
                        &server,
                        &client,
                        AuthorizationCallback {
                            code: "original-authorization-code",
                            state: &request.state,
                            request: &request,
                            redirect_uri: &redirect,
                        },
                        Some(&base),
                    )
                    .await
            };
            assert!(result.is_err());
            drop(store);
            drop(oauth);
            let reopened = NativeTokenStore::new().expect("new native store handle");
            let oauth = OAuthClient::with_routes(Duration::from_secs(2), routes)
                .expect("independent OAuth client");
            let error = oauth
                .refresh(&binding, &reopened, &server, &client, Some(&base))
                .await
                .expect_err("old refresh is fenced across client reopening");
            assert!(error.to_string().contains("new authorization"));
            assert!(
                oauth
                    .bearer_header(&binding, &reopened, &server, &client, Some(&base))
                    .await
                    .is_err()
            );
            let request = oauth
                .authorization_request(&server, &client, &redirect, None, Some(&base))
                .expect("explicit new authorization");
            oauth
                .exchange_code(
                    &binding,
                    &reopened,
                    &server,
                    &client,
                    AuthorizationCallback {
                        code: "new-authorization-code",
                        state: &request.state,
                        request: &request,
                        redirect_uri: &redirect,
                    },
                    Some(&base),
                )
                .await
                .expect("explicit recovery persists new token");
            let bearer = oauth
                .bearer_header(&binding, &reopened, &server, &client, Some(&base))
                .await
                .expect("new bearer");
            assert_eq!(
                bearer.value.to_str().expect("header"),
                "Bearer new-native-access"
            );
            oauth
                .logout(&binding, &reopened)
                .await
                .expect("explicit native cleanup");
            assert!(
                owned
                    .store
                    .load(&binding)
                    .expect("cleanup verified")
                    .is_none()
            );
            transport.await.expect("owned token server joined");
        }
    }

    #[tokio::test]
    async fn credentials_cannot_cross_resource_origins() {
        let oauth = OAuthClient::new(Duration::from_secs(1)).expect("OAuth client");
        let first_resource = Url::parse("http://127.0.0.1:43101/mcp").expect("first resource URL");
        let second_resource =
            Url::parse("http://127.0.0.1:43102/mcp").expect("second resource URL");
        let first_binding =
            CredentialBinding::new("shared-profile", &first_resource).expect("first binding");
        let second_binding =
            CredentialBinding::new("shared-profile", &second_resource).expect("second binding");
        let store = MemoryTokenStore::default();
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        };
        let first_server =
            discovered_server(&Url::parse("http://127.0.0.1:43101/").expect("issuer URL"));
        let second_server =
            discovered_server(&Url::parse("http://127.0.0.1:43102/").expect("issuer URL"));
        store
            .save(
                &first_binding,
                TokenSet {
                    access_token: SecretString::from("origin-bound-access".to_owned()),
                    refresh_token: None,
                    token_type: "Bearer".into(),
                    scope: None,
                    expires_at: None,
                    authority: Some(token_authority(
                        &first_binding,
                        &first_server,
                        &client,
                        Some(&first_resource),
                    )),
                },
            )
            .expect("seed first-origin token");

        let missing = oauth
            .bearer_header(
                &second_binding,
                &store,
                &second_server,
                &client,
                Some(&second_resource),
            )
            .await
            .expect_err("same profile at another origin must not load the token");
        assert_eq!(
            missing.to_string(),
            "MCP protocol violation: OAuth credentials are not available"
        );

        let bearer = oauth
            .bearer_header(
                &first_binding,
                &store,
                &first_server,
                &client,
                Some(&first_resource),
            )
            .await
            .expect("first-origin bearer");
        let cross_origin = oauth
            .send_authorized(
                Method::GET,
                second_resource,
                HeaderMap::new(),
                Vec::new(),
                bearer,
            )
            .await
            .expect_err("bound bearer must not be attached cross-origin");
        assert_eq!(
            cross_origin.to_string(),
            "MCP protocol violation: OAuth credential is not authorized for the request origin"
        );
        assert!(!cross_origin.to_string().contains("origin-bound-access"));
    }

    #[tokio::test]
    async fn concurrent_bearer_requests_share_one_rotating_refresh() {
        let (token_endpoint, requests, server) = start_refresh_fixture().await;
        let oauth = OAuthClient::new(Duration::from_secs(2)).expect("OAuth client");
        let store = Arc::new(MemoryTokenStore::default());
        let mut base = token_endpoint.clone();
        base.set_path("/");
        let authorization_server = Arc::new(discovered_server(&base));
        let binding =
            Arc::new(CredentialBinding::new("shared-profile", &base).expect("credential binding"));
        let client = Arc::new(RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        });
        store
            .save(
                binding.as_ref(),
                TokenSet {
                    access_token: SecretString::from("expired-access".to_owned()),
                    refresh_token: Some(SecretString::from("single-use-refresh".to_owned())),
                    token_type: "Bearer".into(),
                    scope: Some("tools:read".into()),
                    expires_at: Some(SystemTime::UNIX_EPOCH),
                    authority: Some(token_authority(
                        &binding,
                        &authorization_server,
                        &client,
                        None,
                    )),
                },
            )
            .expect("seed expired token");
        let barrier = Arc::new(tokio::sync::Barrier::new(9));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let oauth = oauth.clone();
            let store = Arc::clone(&store);
            let client = Arc::clone(&client);
            let authorization_server = Arc::clone(&authorization_server);
            let binding = Arc::clone(&binding);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                oauth
                    .bearer_header(
                        binding.as_ref(),
                        store.as_ref(),
                        authorization_server.as_ref(),
                        client.as_ref(),
                        None,
                    )
                    .await
            }));
        }
        barrier.wait().await;

        let mut shared_header = None;
        for task in tasks {
            let header = task
                .await
                .expect("bearer task must join")
                .expect("bearer request must succeed");
            assert!(header.value.is_sensitive());
            if let Some(expected) = shared_header.as_ref() {
                assert_eq!(&header.value, expected);
            } else {
                shared_header = Some(header.value);
            }
        }
        server.await.expect("refresh fixture task");
        let requests = std::mem::take(&mut *requests.lock().expect("request log"));
        assert_eq!(requests.len(), 1);
        assert_eq!(request_line(&requests[0]), "POST /token HTTP/1.1");
        assert_eq!(
            form_body(&requests[0]),
            BTreeMap::from([
                ("client_id".into(), "fixture-client".into()),
                ("grant_type".into(), "refresh_token".into()),
                ("refresh_token".into(), "single-use-refresh".into()),
            ])
        );
    }

    #[tokio::test]
    async fn logout_waits_for_in_flight_refresh_and_removes_the_rotated_token() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind logout race fixture");
        let address = listener.local_addr().expect("logout fixture address");
        let token_endpoint =
            Url::parse(&format!("http://{address}/token")).expect("token endpoint");
        let (request_seen, request_received) = tokio::sync::oneshot::channel();
        let (release_response, response_released) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept refresh");
            let _request = read_http_request(&mut stream).await;
            request_seen.send(()).expect("signal refresh request");
            response_released.await.expect("release refresh response");
            let body = r#"{"access_token":"rotated-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write refresh response");
        });

        let oauth = OAuthClient::new(Duration::from_secs(2)).expect("OAuth client");
        let store = Arc::new(MemoryTokenStore::default());
        let mut base = token_endpoint.clone();
        base.set_path("/");
        let authorization_server = Arc::new(discovered_server(&base));
        let binding =
            Arc::new(CredentialBinding::new("logout-race", &base).expect("credential binding"));
        let client = Arc::new(RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        });
        store
            .save(
                binding.as_ref(),
                TokenSet {
                    access_token: SecretString::from("expired-access".to_owned()),
                    refresh_token: Some(SecretString::from("single-use-refresh".to_owned())),
                    token_type: "Bearer".into(),
                    scope: None,
                    expires_at: Some(SystemTime::UNIX_EPOCH),
                    authority: Some(token_authority(
                        &binding,
                        &authorization_server,
                        &client,
                        None,
                    )),
                },
            )
            .expect("seed expired token");

        let refresh_oauth = oauth.clone();
        let refresh_store = Arc::clone(&store);
        let refresh_client = Arc::clone(&client);
        let refresh_server = Arc::clone(&authorization_server);
        let refresh_binding = Arc::clone(&binding);
        let refresh = tokio::spawn(async move {
            refresh_oauth
                .bearer_header(
                    refresh_binding.as_ref(),
                    refresh_store.as_ref(),
                    refresh_server.as_ref(),
                    refresh_client.as_ref(),
                    None,
                )
                .await
        });
        request_received.await.expect("refresh request observed");

        let logout_oauth = oauth.clone();
        let logout_store = Arc::clone(&store);
        let logout_binding = Arc::clone(&binding);
        let mut logout = tokio::spawn(async move {
            logout_oauth
                .logout(logout_binding.as_ref(), logout_store.as_ref())
                .await
        });
        tokio::time::timeout(Duration::from_millis(50), &mut logout)
            .await
            .expect_err("logout must wait for the profile refresh lock");
        release_response.send(()).expect("release token response");

        refresh
            .await
            .expect("refresh task joins")
            .expect("refresh succeeds");
        logout
            .await
            .expect("logout task joins")
            .expect("logout succeeds");
        server.await.expect("logout race fixture joins");
        assert!(
            store
                .load(binding.as_ref())
                .expect("load after logout")
                .is_none()
        );
    }

    fn request_line(request: &str) -> &str {
        request.lines().next().expect("request line")
    }

    fn request_body(request: &str) -> &str {
        request
            .split_once("\r\n\r\n")
            .expect("HTTP request body separator")
            .1
    }

    fn form_body(request: &str) -> BTreeMap<String, String> {
        url::form_urlencoded::parse(request_body(request).as_bytes())
            .into_owned()
            .collect()
    }

    fn request_headers(request: &str) -> BTreeMap<String, String> {
        request
            .lines()
            .skip(1)
            .take_while(|line| !line.is_empty())
            .map(|line| {
                let (name, value) = line.split_once(':').expect("HTTP header");
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect()
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = stream.read(&mut chunk).await.expect("read request");
            bytes.extend_from_slice(&chunk[..read]);
            let headers_end = bytes
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4);
            let Some(headers_end) = headers_end else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length: ")
                        .or_else(|| line.strip_prefix("Content-Length: "))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= headers_end + content_length {
                return String::from_utf8(bytes).expect("request UTF-8");
            }
        }
    }

    async fn start_refresh_fixture() -> (Url, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>)
    {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind refresh fixture");
        let address = listener.local_addr().expect("refresh fixture address");
        let endpoint = Url::parse(&format!("http://{address}/token")).expect("token URL");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept refresh");
            let request = read_http_request(&mut stream).await;
            request_log.lock().expect("request log").push(request);
            tokio::time::sleep(Duration::from_millis(100)).await;
            let body = r#"{"access_token":"shared-refreshed-access","refresh_token":"rotated-refresh","token_type":"Bearer","expires_in":3600,"scope":"tools:read"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write refresh response");
        });
        (endpoint, requests, server)
    }

    async fn start_authorization_fixture()
    -> (Url, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        let base = Url::parse(&format!("http://{address}/")).expect("base URL");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let resource_metadata = serde_json::json!({
            "resource": base.as_str(),
            "authorization_servers": [base.as_str()],
            "scopes_supported": ["tools:read"]
        })
        .to_string();
        let server_metadata = serde_json::json!({
            "issuer": base.as_str(),
            "authorization_endpoint": base.join("authorize").expect("authorize URL").to_string(),
            "token_endpoint": base.join("token").expect("token URL").to_string(),
            "registration_endpoint": base.join("register").expect("register URL").to_string(),
            "code_challenge_methods_supported": ["S256"]
        })
        .to_string();
        let server = tokio::spawn(async move {
            let mut token_response = 0;
            for _ in 0..6 {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let request = read_http_request(&mut stream).await;
                let path = request_line(&request)
                    .split_whitespace()
                    .nth(1)
                    .expect("request path");
                let body = match path {
                    "/.well-known/oauth-protected-resource" => resource_metadata.clone(),
                    "/.well-known/oauth-authorization-server" => server_metadata.clone(),
                    "/register" => {
                        r#"{"client_id":"fixture-client","client_secret":"fixture-client-secret"}"#
                            .into()
                    }
                    "/token" if token_response == 0 => {
                        token_response += 1;
                        r#"{"access_token":"initial-access","refresh_token":"fixture-refresh","token_type":"Bearer","expires_in":0,"scope":"tools:read"}"#.into()
                    }
                    "/token" => {
                        token_response += 1;
                        r#"{"access_token":"refreshed-access","token_type":"Bearer","expires_in":3600}"#.into()
                    }
                    "/mcp" => r#"{"authorized":true}"#.into(),
                    _ => panic!("unexpected fixture request path: {path}"),
                };
                request_log.lock().expect("request log").push(request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
        });
        (base, requests, server)
    }
}

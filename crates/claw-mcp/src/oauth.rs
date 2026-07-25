//! OAuth 2.1 authorization for remote MCP servers.

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::error::{McpError, Result};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const EXPIRY_SKEW: Duration = Duration::from_secs(30);

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

/// Authorization-server endpoints obtained from validated issuer metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredAuthorizationServer {
    metadata: AuthorizationServerMetadata,
    issuer: Url,
    authorization_endpoint: Url,
    token_endpoint: Url,
    registration_endpoint: Option<Url>,
}

impl DiscoveredAuthorizationServer {
    /// Returns the validated metadata document.
    #[must_use]
    pub fn metadata(&self) -> &AuthorizationServerMetadata {
        &self.metadata
    }

    /// Returns the validated issuer URL.
    #[must_use]
    pub fn issuer(&self) -> &Url {
        &self.issuer
    }

    /// Returns the metadata-authorized browser endpoint.
    #[must_use]
    pub fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    /// Returns the metadata-authorized token endpoint.
    #[must_use]
    pub fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// Returns the metadata-authorized dynamic registration endpoint.
    #[must_use]
    pub fn registration_endpoint(&self) -> Option<&Url> {
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
    #[must_use]
    pub fn generate() -> Self {
        let mut verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let secret = SecretString::from(verifier.clone());
        verifier.zeroize();
        Self {
            verifier: secret,
            challenge,
        }
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
#[derive(Debug)]
pub struct AuthorizationRequest {
    /// URL to open in the user's browser.
    pub url: Url,
    /// CSRF state that must match the callback.
    pub state: String,
    /// PKCE values retained for the token exchange.
    pub pkce: PkcePair,
}

/// OAuth tokens stored behind a secure platform port.
#[derive(Clone)]
pub struct TokenSet {
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    token_type: String,
    scope: Option<String>,
    expires_at: Option<SystemTime>,
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
    /// Returns true when the access token is usable beyond the refresh skew.
    #[must_use]
    pub fn is_fresh(&self, now: SystemTime) -> bool {
        self.expires_at
            .is_none_or(|expiry| expiry > now + EXPIRY_SKEW)
    }

    /// Returns whether the authorization server supplied a refresh token.
    #[must_use]
    pub fn can_refresh(&self) -> bool {
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
    fn into_token_set(self, now: SystemTime, previous_refresh: Option<&str>) -> Result<TokenSet> {
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
            access_token: SecretString::from(self.access_token),
            refresh_token: self
                .refresh_token
                .as_deref()
                .or(previous_refresh)
                .map(|value| SecretString::from(value.to_owned())),
            token_type: self.token_type,
            scope: self.scope,
            expires_at,
        })
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
    fn load(
        &self,
        binding: &CredentialBinding,
    ) -> std::result::Result<Option<TokenSet>, CredentialStoreError>;
    /// Replaces credentials for an origin-bound profile key.
    fn save(
        &self,
        binding: &CredentialBinding,
        tokens: TokenSet,
    ) -> std::result::Result<(), CredentialStoreError>;
    /// Deletes credentials for an origin-bound profile key.
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

/// MCP OAuth 2.1 client with bounded local-only-testable HTTP operations.
#[derive(Clone, Debug)]
pub struct OAuthClient {
    http: reqwest::Client,
    refresh_locks: Arc<AsyncMutex<HashMap<CredentialBinding, Arc<AsyncMutex<()>>>>>,
}

impl OAuthClient {
    /// Creates an OAuth client with redirects disabled and a bounded timeout.
    pub fn new(timeout: Duration) -> Result<Self> {
        crate::install_tls_provider();
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            http,
            refresh_locks: Arc::new(AsyncMutex::new(HashMap::new())),
        })
    }

    /// Reads protected-resource metadata from an explicit URL.
    pub async fn discover_resource(&self, metadata_url: &Url) -> Result<ProtectedResourceMetadata> {
        validate_secure_endpoint(metadata_url, "OAuth resource metadata")?;
        let response = self.http.get(metadata_url.clone()).send().await?;
        if !response.status().is_success() {
            return Err(McpError::Protocol(format!(
                "OAuth resource metadata returned HTTP {}",
                response.status()
            )));
        }
        Ok(response.json().await?)
    }

    /// Reads authorization-server metadata from an issuer.
    pub async fn discover_authorization_server(
        &self,
        issuer: &Url,
    ) -> Result<DiscoveredAuthorizationServer> {
        validate_secure_endpoint(issuer, "OAuth issuer")?;
        let metadata_url = authorization_server_metadata_url(issuer)?;
        let response = self.http.get(metadata_url).send().await?;
        if !response.status().is_success() {
            return Err(McpError::Protocol(format!(
                "OAuth server metadata returned HTTP {}",
                response.status()
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
        Ok(DiscoveredAuthorizationServer {
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
        })
    }

    /// Dynamically registers a public OAuth client at the discovered endpoint.
    pub async fn register(
        &self,
        server: &DiscoveredAuthorizationServer,
        metadata: &ClientMetadata,
    ) -> Result<RegisteredClient> {
        let registration_endpoint = server.registration_endpoint().ok_or_else(|| {
            McpError::Protocol("OAuth server does not advertise dynamic registration".into())
        })?;
        let response = self
            .http
            .post(registration_endpoint.clone())
            .json(metadata)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(McpError::Protocol(format!(
                "OAuth client registration returned HTTP {}",
                response.status()
            )));
        }
        let wire: RegisteredClientWire = response.json().await?;
        Ok(RegisteredClient {
            client_id: wire.client_id,
            client_secret: wire.client_secret.map(SecretString::from),
        })
    }

    /// Builds an authorization-code request with PKCE and CSRF state.
    pub fn authorization_request(
        &self,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        redirect_uri: &Url,
        scope: Option<&str>,
        resource: Option<&Url>,
    ) -> Result<AuthorizationRequest> {
        let pkce = PkcePair::generate();
        let state = Uuid::new_v4().simple().to_string();
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
        Ok(AuthorizationRequest { url, state, pkce })
    }

    /// Exchanges an authorization code and persists the returned tokens.
    #[allow(clippy::too_many_arguments)]
    pub async fn exchange_code(
        &self,
        binding: &CredentialBinding,
        store: &dyn TokenStore,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        code: &str,
        callback_state: &str,
        authorization: &AuthorizationRequest,
        redirect_uri: &Url,
        resource: Option<&Url>,
    ) -> Result<TokenSet> {
        if callback_state != authorization.state {
            return Err(McpError::Protocol("OAuth callback state mismatch".into()));
        }
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("client_id", client.client_id()),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", authorization.pkce.verifier()),
        ];
        if let Some(secret) = client.client_secret() {
            fields.push(("client_secret", secret));
        }
        if let Some(resource) = resource {
            fields.push(("resource", resource.as_str()));
        }
        validate_resource_matches_binding(resource, binding)?;
        let wire = self.post_token(server.token_endpoint(), &fields).await?;
        let tokens = wire.into_token_set(SystemTime::now(), None)?;
        store.save(binding, tokens.clone()).map_err(store_error)?;
        Ok(tokens)
    }

    /// Refreshes a token while coalescing concurrent refreshes for this client and profile.
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
        let refresh_lock = self.refresh_lock(binding).await;
        let _guard = refresh_lock.lock().await;
        let current = load_tokens(binding, store)?;
        if !same_token_generation(&observed, &current) {
            return Ok(current);
        }
        self.refresh_current(binding, store, server, client, resource, current)
            .await
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
        let wire = self.post_token(server.token_endpoint(), &fields).await?;
        let tokens = wire.into_token_set(SystemTime::now(), Some(refresh))?;
        store.save(binding, tokens.clone()).map_err(store_error)?;
        Ok(tokens)
    }

    async fn refresh_lock(&self, binding: &CredentialBinding) -> Arc<AsyncMutex<()>> {
        let mut locks = self.refresh_locks.lock().await;
        Arc::clone(
            locks
                .entry(binding.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
        )
    }

    async fn post_token(&self, endpoint: &Url, fields: &[(&str, &str)]) -> Result<TokenWire> {
        validate_secure_endpoint(endpoint, "OAuth token endpoint")?;
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish();
        let response = self
            .http
            .post(endpoint.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(McpError::Protocol(format!(
                "OAuth token endpoint returned HTTP {}",
                response.status()
            )));
        }
        Ok(response.json().await?)
    }

    /// Returns a bearer header, refreshing first when required.
    pub async fn bearer_header(
        &self,
        binding: &CredentialBinding,
        store: &dyn TokenStore,
        server: &DiscoveredAuthorizationServer,
        client: &RegisteredClient,
        resource: Option<&Url>,
    ) -> Result<BoundBearerHeader> {
        validate_resource_matches_binding(resource, binding)?;
        let current = load_tokens(binding, store)?;
        let tokens = if current.is_fresh(SystemTime::now()) {
            current
        } else {
            let refresh_lock = self.refresh_lock(binding).await;
            let _guard = refresh_lock.lock().await;
            let current = load_tokens(binding, store)?;
            if current.is_fresh(SystemTime::now()) {
                current
            } else {
                self.refresh_current(binding, store, server, client, resource, current)
                    .await?
            }
        };
        let mut value = HeaderValue::from_str(&format!("Bearer {}", tokens.access_token()))
            .map_err(|_| McpError::Protocol("OAuth token cannot be encoded as a header".into()))?;
        value.set_sensitive(true);
        Ok(BoundBearerHeader {
            binding: binding.clone(),
            value,
        })
    }

    /// Injects a sensitive bearer header into one HTTP request.
    pub async fn send_authorized(
        &self,
        request: reqwest::RequestBuilder,
        bearer: BoundBearerHeader,
    ) -> Result<reqwest::Response> {
        let request_url = request
            .try_clone()
            .ok_or_else(|| McpError::Protocol("authorized HTTP request cannot be cloned".into()))?
            .build()?
            .url()
            .clone();
        validate_secure_endpoint(&request_url, "authorized HTTP endpoint")?;
        if endpoint_origin(&request_url)? != bearer.binding.resource_origin {
            return Err(McpError::Protocol(
                "OAuth credential is not authorized for the request origin".into(),
            ));
        }
        Ok(request.header(AUTHORIZATION, bearer.value).send().await?)
    }

    /// Removes credentials for one origin-bound OAuth profile.
    pub async fn logout(&self, binding: &CredentialBinding, store: &dyn TokenStore) -> Result<()> {
        let refresh_lock = self.refresh_lock(binding).await;
        let _guard = refresh_lock.lock().await;
        store.delete(binding).map_err(store_error)
    }
}

impl Default for OAuthClient {
    fn default() -> Self {
        Self::new(DEFAULT_HTTP_TIMEOUT).expect("default OAuth HTTP client must build")
    }
}

fn store_error(error: CredentialStoreError) -> McpError {
    McpError::CredentialStore(error.to_string())
}

fn authorization_server_metadata_url(issuer: &Url) -> Result<Url> {
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
    Ok(metadata)
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
    left.access_token.expose_secret() == right.access_token.expose_secret()
        && left
            .refresh_token
            .as_ref()
            .map(|secret| secret.expose_secret())
            == right
                .refresh_token
                .as_ref()
                .map(|secret| secret.expose_secret())
        && left.expires_at == right.expires_at
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn discovered_server(base: &Url) -> DiscoveredAuthorizationServer {
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
        let rendered = format!("{client:?}\n{tokens:?}\n{pkce:?}\n{bound_header:?}");

        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("registration-secret"));
        assert!(!rendered.contains("access-secret"));
        assert!(!rendered.contains("refresh-secret"));
        assert!(!rendered.contains("verifier-secret"));
        assert!(!rendered.contains("header-secret"));
    }

    #[test]
    fn authorization_url_contains_pkce_state_scope_and_resource() {
        let oauth = OAuthClient::default();
        let client = RegisteredClient {
            client_id: "gta-client".into(),
            client_secret: None,
        };
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

    #[test]
    fn authorization_server_discovery_preserves_path_based_issuers() {
        let root = Url::parse("https://auth.example/").expect("root issuer");
        let tenant =
            Url::parse("https://auth.example/realms/tenant?ignored=1").expect("path issuer");

        assert_eq!(
            authorization_server_metadata_url(&root)
                .expect("root metadata URL")
                .as_str(),
            "https://auth.example/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            authorization_server_metadata_url(&tenant)
                .expect("tenant metadata URL")
                .as_str(),
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
        let oauth = OAuthClient::new(Duration::from_secs(2)).expect("OAuth client");
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
        let metadata =
            ClientMetadata::native("http://127.0.0.1:8989/callback", Some("tools:read".into()));
        let client = oauth
            .register(&server_metadata, &metadata)
            .await
            .expect("dynamic registration");
        assert_eq!(client.client_id(), "fixture-client");

        let authorization = oauth
            .authorization_request(
                &server_metadata,
                &client,
                &Url::parse("http://127.0.0.1:8989/callback").expect("redirect URL"),
                Some("tools:read"),
                Some(&base),
            )
            .expect("loopback authorization URL");
        let store = MemoryTokenStore::default();
        let binding = CredentialBinding::new("fixture", &base).expect("credential binding");
        let state_error = oauth
            .exchange_code(
                &binding,
                &store,
                &server_metadata,
                &client,
                "authorization-code",
                "wrong-state",
                &authorization,
                &Url::parse("http://127.0.0.1:8989/callback").expect("redirect URL"),
                Some(&base),
            )
            .await
            .expect_err("a mismatched callback state must fail before token exchange");
        assert_eq!(
            state_error.to_string(),
            "MCP protocol violation: OAuth callback state mismatch"
        );
        let exchanged = oauth
            .exchange_code(
                &binding,
                &store,
                &server_metadata,
                &client,
                "authorization-code",
                &authorization.state,
                &authorization,
                &Url::parse("http://127.0.0.1:8989/callback").expect("redirect URL"),
                Some(&base),
            )
            .await
            .expect("token exchange");
        assert!(!exchanged.is_fresh(SystemTime::now()));
        assert!(exchanged.can_refresh());

        let header = oauth
            .bearer_header(&binding, &store, &server_metadata, &client, Some(&base))
            .await
            .expect("refresh and bearer");
        assert_eq!(
            header.value.to_str().expect("header text"),
            "Bearer refreshed-access"
        );
        assert!(header.value.is_sensitive());

        oauth.logout(&binding, &store).await.expect("logout");
        assert!(store.load(&binding).expect("load after logout").is_none());

        server.await.expect("fixture server task");
        let requests = requests.lock().expect("request log");
        assert_eq!(requests.len(), 5);
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
                "redirect_uris": ["http://127.0.0.1:8989/callback"],
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
                (
                    "redirect_uri".into(),
                    "http://127.0.0.1:8989/callback".into()
                ),
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
        store
            .save(
                &first_binding,
                TokenSet {
                    access_token: SecretString::from("origin-bound-access".to_owned()),
                    refresh_token: None,
                    token_type: "Bearer".into(),
                    scope: None,
                    expires_at: None,
                },
            )
            .expect("seed first-origin token");
        let client = RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        };
        let first_server =
            discovered_server(&Url::parse("http://127.0.0.1:43101/").expect("issuer URL"));
        let second_server =
            discovered_server(&Url::parse("http://127.0.0.1:43102/").expect("issuer URL"));

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
            .send_authorized(oauth.http.get(second_resource), bearer)
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
        store
            .save(
                binding.as_ref(),
                TokenSet {
                    access_token: SecretString::from("expired-access".to_owned()),
                    refresh_token: Some(SecretString::from("single-use-refresh".to_owned())),
                    token_type: "Bearer".into(),
                    scope: Some("tools:read".into()),
                    expires_at: Some(SystemTime::UNIX_EPOCH),
                },
            )
            .expect("seed expired token");
        let client = Arc::new(RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        });
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
        let requests = requests.lock().expect("request log");
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
        store
            .save(
                binding.as_ref(),
                TokenSet {
                    access_token: SecretString::from("expired-access".to_owned()),
                    refresh_token: Some(SecretString::from("single-use-refresh".to_owned())),
                    token_type: "Bearer".into(),
                    scope: None,
                    expires_at: Some(SystemTime::UNIX_EPOCH),
                },
            )
            .expect("seed expired token");
        let client = Arc::new(RegisteredClient {
            client_id: "fixture-client".into(),
            client_secret: None,
        });

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
            for _ in 0..5 {
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
                        r#"{"access_token":"refreshed-access","token_type":"Bearer","expires_in":3600,"scope":"tools:read"}"#.into()
                    }
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

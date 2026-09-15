use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_application::ports::PortError;
use claw_application::ports::tool::{
    InternalToolAuditPhase, InvocationAuthority, ToolBinding, ToolInvocation, ToolOutcome,
    ToolStatus,
};
use claw_http_api::ToolDefinition;
use claw_mcp::client::{
    ClientEventSink, HttpClientConfig, McpClient, McpClientEvent, RejectSampling, StdioClientConfig,
};
use claw_mcp::oauth::{
    CredentialBinding, DiscoveredAuthorizationServer, NativeTokenStore, RegisteredClient, TokenSet,
    TokenStore as _,
};
use claw_tools::exec::{ArgvPolicy, ExecPolicy, PinnedExecutable};
use claw_tools::sandbox::{Sandbox, SandboxLimits};
use futures_util::FutureExt as _;
use iri_string::{
    spec::UriSpec,
    template::{UriTemplateStr, simple_context::SimpleContext},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::http_api::DurableSecurityAudit;

const POLICY_BYTES: usize = 64 * 1024;
const ARGUMENT_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Policy {
    schema_version: u32,
    servers: Vec<ServerPolicy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ServerPolicy {
    id: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    http_proxy: Option<String>,
    #[serde(default)]
    stdio: Option<StdioPolicy>,
    #[serde(default = "initial_review_revision")]
    review_revision: u64,
    #[serde(default)]
    token_env: Option<String>,
    #[serde(default)]
    token_ref: Option<String>,
    #[serde(default)]
    oauth: Option<OAuthPolicy>,
    tools: Vec<ToolPolicy>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OAuthPolicy {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    client_id: String,
    credential_ref: String,
}

struct EnrolledOAuth {
    configured: OAuthPolicy,
    binding: CredentialBinding,
    server: DiscoveredAuthorizationServer,
    client: RegisteredClient,
    resource: url::Url,
    tokens: TokenSet,
}

impl EnrolledOAuth {
    fn load_fresh(&self) -> Result<SecretString, String> {
        let tokens = NativeTokenStore::new()
            .map_err(|_| "MCP native OAuth store is unavailable".to_owned())?
            .load(&self.binding)
            .map_err(|_| "MCP OAuth record is unavailable, incomplete or invalid".to_owned())?
            .ok_or_else(|| "MCP OAuth record is absent".to_owned())?;
        if !tokens.same_generation_as(&self.tokens) {
            return Err("MCP OAuth credential generation changed".to_owned());
        }
        tokens
            .fresh_bearer_token(
                &self.binding,
                &self.server,
                &self.client,
                Some(&self.resource),
            )
            .map_err(|_| {
                "MCP OAuth credential is expired or belongs to another enrollment".to_owned()
            })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ToolPolicy {
    name: String,
    #[serde(default)]
    kind: OperationKind,
    remote: Value,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum OperationKind {
    #[default]
    Tool,
    Resource,
    ResourceTemplate,
    ResourceWatch,
    Prompt,
}

impl OperationKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Resource => "resource",
            Self::ResourceTemplate => "resource_template",
            Self::ResourceWatch => "resource_watch",
            Self::Prompt => "prompt",
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StdioPolicy {
    program: PathBuf,
    sha256: String,
    working_directory: PathBuf,
    allow_host_permissions: bool,
    #[serde(default)]
    arguments: Vec<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    environment_refs: BTreeMap<String, String>,
}

struct StdioCredential {
    reference: String,
    value: SecretString,
}

struct ReviewedStdio {
    policy: ExecPolicy,
    configured: StdioPolicy,
    directory: Sandbox,
    credentials: BTreeMap<String, StdioCredential>,
}

enum ServerTransport {
    Http {
        endpoint: url::Url,
        token: Option<SecretString>,
        route: Box<claw_mcp::HttpRoutePolicy>,
        proxy: Option<Box<url::Url>>,
        keyring_ref: Option<Arc<str>>,
        oauth: Option<Arc<EnrolledOAuth>>,
    },
    Stdio(Arc<ReviewedStdio>),
}

impl ServerTransport {
    const fn label(&self) -> &'static str {
        match self {
            Self::Http { proxy: None, .. } => "http-loopback",
            Self::Http { proxy: Some(_), .. } => "https-proxy",
            Self::Stdio(_) => "stdio-windows",
        }
    }

    fn resource(&self) -> String {
        match self {
            Self::Http {
                endpoint,
                proxy,
                oauth,
                ..
            } => format!(
                "endpoint={endpoint}; proxy={}; proxyResolvesTarget={}; directFallback=false; oauthIssuer={}; oauthClient={}; automaticRefresh=false",
                proxy.as_deref().map_or("none", url::Url::as_str),
                proxy.is_some(),
                oauth
                    .as_ref()
                    .map_or("none", |oauth| oauth.configured.issuer.as_str()),
                oauth
                    .as_ref()
                    .map_or("none", |oauth| oauth.configured.client_id.as_str())
            ),
            Self::Stdio(program) => format!(
                "executable={}; sha256={}; workingDirectory={}; argumentCount={}; environmentKeys={:?}; credentialEnvironmentKeys={:?}; hostOsPermissions=true",
                program.configured.program.display(),
                program.configured.sha256,
                program.configured.working_directory.display(),
                program.configured.arguments.len(),
                program.configured.environment.keys().collect::<Vec<_>>(),
                program.credentials.keys().collect::<Vec<_>>()
            ),
        }
    }
}

struct PreparedStdio {
    config: Option<StdioClientConfig>,
    directory: PathBuf,
    _executable: PinnedExecutable,
}

struct Server {
    id: String,
    transport: ServerTransport,
    review_revision: u64,
    review_identity: String,
    revoked: AtomicBool,
    revocation: CancellationToken,
}

impl Server {
    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
        self.revocation.cancel();
    }
}

const fn initial_review_revision() -> u64 {
    1
}

struct PublishedTool {
    server: Arc<Server>,
    definition: ToolDefinition,
    remote_name: String,
    remote_descriptor: Value,
    kind: OperationKind,
    publication: String,
    validator: jsonschema::Validator,
}

fn digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect()
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn invalid(message: &str) -> PortError {
    PortError::Invalid(message.to_owned())
}

fn keyring_key(reference: &str) -> Result<claw_provider_sdk::secret::CredentialKey, String> {
    use claw_security::secret::{SecretRef, SecretScheme};
    let parsed: SecretRef = reference
        .parse()
        .map_err(|_| "MCP keyring reference is invalid".to_owned())?;
    if parsed.scheme() != SecretScheme::Keyring {
        return Err("MCP credentials require the native keyring scheme".to_owned());
    }
    let (service, account) = parsed
        .identifier()
        .split_once('/')
        .ok_or_else(|| "MCP keyring identifier is invalid".to_owned())?;
    if !matches!(service, "gta-claw.mcp-outbound" | "gta-claw.mcp-stdio")
        || account.len() != 64
        || !account
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("MCP keyring reference must use its dedicated bound namespace".to_owned());
    }
    claw_provider_sdk::secret::CredentialKey::new(service, account)
        .map_err(|_| "MCP credential key is invalid".to_owned())
}

fn read_configured_credential(reference: &str) -> Result<String, String> {
    if !reference.starts_with("keyring://") {
        return std::env::var(reference).map_err(|_| "MCP credential is unavailable".to_owned());
    }
    let key = keyring_key(reference)?;
    read_keyring_credential(&key)
}

fn read_keyring_credential(
    key: &claw_provider_sdk::secret::CredentialKey,
) -> Result<String, String> {
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        use claw_provider_sdk::secret::SecretStore as _;
        #[cfg(target_os = "windows")]
        let store = claw_provider_sdk::secret::WindowsCredentialManagerStore::new();
        #[cfg(target_os = "macos")]
        let store = claw_provider_sdk::secret::AppleKeychainStore::new();
        let secret = store
            .map_err(|_| "MCP native credential store is unavailable".to_owned())?
            .get(key)
            .map_err(|_| "MCP native credential lookup failed".to_owned())?
            .ok_or_else(|| "MCP native credential is absent".to_owned())?;
        Ok(secret.expose().to_owned())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = key;
        Err("MCP native keyring is unsupported on this platform; no fallback is allowed".to_owned())
    }
}

fn credential_matches(reference: &str, expected: &[u8; 32]) -> Result<bool, String> {
    let secret = SecretString::new(read_configured_credential(reference)?.into());
    let actual = Sha256::digest(secret.expose_secret().as_bytes());
    Ok(expected
        .iter()
        .zip(actual.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0)
}

async fn verify_keyring_credential(server: &Server) -> Result<(), PortError> {
    if let ServerTransport::Http {
        oauth: Some(oauth), ..
    } = &server.transport
    {
        let oauth = Arc::clone(oauth);
        let checked = tokio::task::spawn_blocking(move || oauth.load_fresh()).await;
        if !matches!(checked, Ok(Ok(_))) {
            server.revoke();
            return Err(unknown(
                "MCP OAuth credential changed, expired or is unavailable; review must be re-enrolled",
            ));
        }
        return Ok(());
    }
    let credentials: Vec<(String, [u8; 32])> = match &server.transport {
        ServerTransport::Http {
            keyring_ref: Some(reference),
            token: Some(enrolled),
            ..
        } => {
            vec![(
                reference.to_string(),
                Sha256::digest(enrolled.expose_secret().as_bytes()).into(),
            )]
        }
        ServerTransport::Stdio(program) => program
            .credentials
            .values()
            .map(|credential| {
                (
                    credential.reference.clone(),
                    Sha256::digest(credential.value.expose_secret().as_bytes()).into(),
                )
            })
            .collect(),
        ServerTransport::Http { .. } => Vec::new(),
    };
    if credentials.is_empty() {
        return Ok(());
    }
    let checked = tokio::task::spawn_blocking(move || {
        for (reference, expected) in credentials {
            if !credential_matches(&reference, &expected)? {
                return Ok(false);
            }
        }
        Ok::<_, String>(true)
    })
    .await;
    if !matches!(checked, Ok(Ok(true))) {
        server.revoke();
        return Err(unknown(
            "MCP native credential changed or is unavailable; review must be re-enrolled",
        ));
    }
    Ok(())
}

fn reviewed_oauth_endpoint(value: &str, proxy: Option<&url::Url>) -> Result<url::Url, String> {
    if value.len() > 2048
        || value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("MCP OAuth endpoint is invalid".to_owned());
    }
    let endpoint = url::Url::parse(value).map_err(|_| "MCP OAuth URL is invalid".to_owned())?;
    let route = match endpoint.scheme() {
        "http" => claw_mcp::HttpRoutePolicy::direct_loopback(endpoint.clone()),
        "https" => {
            let host = endpoint
                .host_str()
                .ok_or_else(|| "MCP OAuth host is absent".to_owned())?;
            let port = endpoint
                .port_or_known_default()
                .ok_or_else(|| "MCP OAuth port is absent".to_owned())?;
            claw_tools::net::UrlPolicy::exact_hosts([host])
                .map_err(|_| "MCP OAuth host violates policy".to_owned())?
                .with_allowed_ports([port])
                .validate(endpoint.as_str())
                .map_err(|_| "MCP OAuth target violates public destination policy".to_owned())?;
            claw_mcp::HttpRoutePolicy::https_via_proxy(
                endpoint.clone(),
                proxy
                    .ok_or_else(|| "MCP OAuth HTTPS requires an explicit proxy".to_owned())?
                    .clone(),
            )
        }
        _ => return Err("MCP OAuth endpoint scheme is invalid".to_owned()),
    };
    route.map_err(|_| "MCP OAuth endpoint violates route policy".to_owned())?;
    Ok(endpoint)
}

fn enroll_oauth(
    id: &str,
    resource: &url::Url,
    policy: OAuthPolicy,
    proxy: Option<&url::Url>,
) -> Result<(Arc<EnrolledOAuth>, SecretString), String> {
    let binding = CredentialBinding::new(id, resource)
        .map_err(|_| "MCP OAuth binding is invalid".to_owned())?;
    if policy.credential_ref != NativeTokenStore::keyring_reference(&binding) {
        return Err(
            "MCP OAuth credential reference does not match this server and resource origin"
                .to_owned(),
        );
    }
    let issuer = reviewed_oauth_endpoint(&policy.issuer, proxy)?;
    let authorization = reviewed_oauth_endpoint(&policy.authorization_endpoint, proxy)?;
    let endpoint = reviewed_oauth_endpoint(&policy.token_endpoint, proxy)?;
    let server = DiscoveredAuthorizationServer::reviewed(issuer, authorization, endpoint)
        .map_err(|_| "MCP OAuth issuer identity is invalid".to_owned())?;
    let client = RegisteredClient::public(&policy.client_id)
        .map_err(|_| "MCP OAuth public client is invalid".to_owned())?;
    let tokens = NativeTokenStore::new()
        .map_err(|_| "MCP native OAuth store is unavailable".to_owned())?
        .load(&binding)
        .map_err(|_| "MCP OAuth record is unavailable, incomplete or invalid".to_owned())?
        .ok_or_else(|| "MCP OAuth login is required".to_owned())?;
    let token = tokens
        .fresh_bearer_token(&binding, &server, &client, Some(resource))
        .map_err(|_| {
            "MCP OAuth credential is expired or belongs to another enrollment".to_owned()
        })?;
    Ok((
        Arc::new(EnrolledOAuth {
            configured: policy,
            binding,
            server,
            client,
            resource: resource.clone(),
            tokens,
        }),
        token,
    ))
}

fn parse_transport(
    server: &mut ServerPolicy,
    read_token: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<(ServerTransport, String), String> {
    match (server.url.take(), server.stdio.take()) {
        (Some(url), None) => {
            if url.len() > 2048
                || url.contains('\\')
                || url
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                return Err("MCP endpoint must be bounded unambiguous URL text".to_owned());
            }
            let endpoint =
                url::Url::parse(&url).map_err(|_| "MCP endpoint is invalid".to_owned())?;
            let proxy = server
                .http_proxy
                .take()
                .map(|proxy| {
                    if proxy.len() > 2048
                        || proxy.contains('\\')
                        || proxy
                            .chars()
                            .any(|character| character.is_control() || character.is_whitespace())
                    {
                        return Err("MCP proxy must be bounded unambiguous URL text".to_owned());
                    }
                    url::Url::parse(&proxy).map_err(|_| "MCP proxy URL is invalid".to_owned())
                })
                .transpose()?;
            let route = match (endpoint.scheme(), &proxy) {
                ("http", None) => claw_mcp::HttpRoutePolicy::direct_loopback(endpoint.clone()),
                ("https", Some(proxy)) => {
                    let host = endpoint.host_str().ok_or_else(|| "MCP HTTPS host is missing".to_owned())?;
                    let port = endpoint.port_or_known_default().ok_or_else(|| "MCP HTTPS port is invalid".to_owned())?;
                    claw_tools::net::UrlPolicy::exact_hosts([host])
                        .map_err(|_| "MCP HTTPS host is outside the public destination policy".to_owned())?
                        .with_allowed_ports([port]).with_max_redirects(0).validate(&url)
                        .map_err(|_| "MCP HTTPS endpoint violates the public destination policy".to_owned())?;
                    claw_mcp::HttpRoutePolicy::https_via_proxy(endpoint.clone(), proxy.clone())
                }
                _ => return Err("MCP endpoints require direct literal-loopback HTTP or explicit HTTPS with a loopback HTTP proxy".to_owned()),
            }.map_err(|_| "MCP endpoint or proxy violates its explicit route policy".to_owned())?;
            if usize::from(server.token_env.is_some())
                + usize::from(server.token_ref.is_some())
                + usize::from(server.oauth.is_some())
                > 1
            {
                return Err("MCP tokenEnv, tokenRef and oauth are mutually exclusive".to_owned());
            }
            let (oauth, oauth_token) = match server.oauth.take() {
                Some(policy) => {
                    let (enrollment, token) =
                        enroll_oauth(&server.id, &endpoint, policy, proxy.as_ref())?;
                    (Some(enrollment), Some(token))
                }
                None => (None, None),
            };
            let keyring_ref = server
                .token_ref
                .take()
                .map(|reference| {
                    let binding = claw_mcp::oauth::CredentialBinding::new(&server.id, &endpoint)
                        .map_err(|_| "MCP credential origin is invalid".to_owned())?;
                    if reference != binding.keyring_reference() {
                        return Err(
                            "MCP keyring reference does not match this server and resource origin"
                                .to_owned(),
                        );
                    }
                    keyring_key(&reference)?;
                    Ok(Arc::<str>::from(reference))
                })
                .transpose()?;
            let reference = if let Some(reference) = &keyring_ref {
                Some(reference.to_string())
            } else {
                server.token_env.take()
            };
            let token = reference
                .map(|name| {
                    if keyring_ref.is_none()
                        && (!name.starts_with("GTA_CLAW_MCP_OUTBOUND_")
                            || name.len() > 96
                            || !name.bytes().all(|byte| {
                                byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                            }))
                    {
                        return Err("MCP credential environment reference is invalid".to_owned());
                    }
                    let token = SecretString::new(
                        read_token(&name)
                            .map_err(|_| "MCP referenced credential is unavailable".to_owned())?
                            .into(),
                    );
                    let value = token.expose_secret();
                    if !(16..=4096).contains(&value.len())
                        || value.trim() != value
                        || value.chars().any(char::is_control)
                    {
                        return Err("MCP referenced credential is invalid".to_owned());
                    }
                    Ok(token)
                })
                .transpose()?
                .or(oauth_token);
            let credential = token
                .as_ref()
                .map(|token| digest(token.expose_secret().as_bytes()));
            let identity = digest(
                &serde_json::to_vec(&(
                    "http",
                    endpoint.as_str(),
                    proxy.as_ref().map(url::Url::as_str),
                    credential,
                    keyring_ref.as_deref(),
                    oauth
                        .as_ref()
                        .map(|oauth| (&oauth.configured, oauth.tokens.generation_fingerprint())),
                ))
                .map_err(|_| "MCP transport cannot be encoded".to_owned())?,
            );
            Ok((
                ServerTransport::Http {
                    endpoint,
                    token,
                    route: Box::new(route),
                    proxy: proxy.map(Box::new),
                    keyring_ref,
                    oauth,
                },
                identity,
            ))
        }
        (None, Some(stdio)) => {
            if !cfg!(windows) {
                return Err(
                    "Native MCP stdio executable pinning is currently supported only on Windows"
                        .to_owned(),
                );
            }
            if server.token_env.is_some()
                || server.token_ref.is_some()
                || server.oauth.is_some()
                || server.http_proxy.is_some()
                || !stdio.allow_host_permissions
                || !stdio.working_directory.is_absolute()
                || stdio.arguments.len() > 32
                || stdio
                    .arguments
                    .iter()
                    .any(|value| value.len() > 2048 || value.chars().any(char::is_control))
                || stdio.arguments.iter().map(String::len).sum::<usize>() > 8192
                || stdio.environment.len() + stdio.environment_refs.len() > 16
                || stdio.environment.values().map(String::len).sum::<usize>() > 8192
            {
                return Err("MCP stdio requires explicit host permissions, bounded fixed arguments and an absolute directory".to_owned());
            }
            let mut keys = BTreeSet::new();
            for (name, value) in &stdio.environment {
                if name.is_empty()
                    || name.len() > 64
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    || !keys.insert(name.to_ascii_uppercase())
                    || value.len() > 2048
                    || value.chars().any(char::is_control)
                {
                    return Err(
                        "MCP stdio environment must be bounded, explicit and unambiguous"
                            .to_owned(),
                    );
                }
            }
            for (name, reference) in &stdio.environment_refs {
                let expected =
                    StdioClientConfig::keyring_reference(&server.id, &stdio.sha256, name)
                        .map_err(|_| "MCP stdio credential binding is invalid".to_owned())?;
                if *reference != expected || !keys.insert(name.to_ascii_uppercase()) {
                    return Err("MCP stdio credentials must match this server, executable and unique environment name".to_owned());
                }
                keyring_key(reference)?;
            }
            if stdio.sha256.len() != 64
                || !stdio
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("MCP stdio requires a lowercase executable SHA256".to_owned());
            }
            let mut expected = [0; 32];
            for (index, byte) in expected.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&stdio.sha256[index * 2..index * 2 + 2], 16)
                    .map_err(|_| "MCP executable digest is invalid".to_owned())?;
            }
            let directory = Sandbox::new_pinned(&stdio.working_directory, SandboxLimits::default())
                .map_err(|_| "MCP working directory cannot be pinned".to_owned())?;
            if directory.resolve_root().native() != stdio.working_directory {
                return Err("MCP working directory must be canonical".to_owned());
            }
            let mut policy = ExecPolicy::deny_all().with_writable_root(&stdio.working_directory);
            policy
                .allow_program_with_sha256(
                    "mcp",
                    &stdio.program,
                    ArgvPolicy::exactly(&stdio.arguments),
                    expected,
                )
                .map_err(|_| {
                    "MCP executable violates its reviewed identity or path policy".to_owned()
                })?;
            let mut credentials = BTreeMap::new();
            let mut environment_bytes = stdio.environment.values().map(String::len).sum::<usize>();
            for (name, reference) in &stdio.environment_refs {
                let value = SecretString::new(
                    read_token(reference)
                        .map_err(|_| "MCP stdio native credential is unavailable".to_owned())?
                        .into(),
                );
                let text = value.expose_secret();
                environment_bytes += text.len();
                if !(16..=2048).contains(&text.len())
                    || text.trim() != text
                    || text.chars().any(char::is_control)
                    || environment_bytes > 8192
                {
                    return Err(
                        "MCP stdio credential exceeds the explicit environment policy".to_owned(),
                    );
                }
                credentials.insert(
                    name.clone(),
                    StdioCredential {
                        reference: reference.clone(),
                        value,
                    },
                );
            }
            let credential_digests: BTreeMap<_, _> = credentials
                .iter()
                .map(|(name, credential)| {
                    (name, digest(credential.value.expose_secret().as_bytes()))
                })
                .collect();
            let identity = digest(
                &serde_json::to_vec(&("stdio", &stdio, credential_digests))
                    .map_err(|_| "MCP stdio review cannot be encoded".to_owned())?,
            );
            Ok((
                ServerTransport::Stdio(Arc::new(ReviewedStdio {
                    policy,
                    configured: stdio,
                    directory,
                    credentials,
                })),
                identity,
            ))
        }
        _ => Err("MCP server requires exactly one HTTP URL or stdio configuration".to_owned()),
    }
}

struct BoundedResourceUri(String);

impl std::fmt::Write for BoundedResourceUri {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        if self.0.len().saturating_add(value.len()) > 2048 {
            return Err(std::fmt::Error);
        }
        self.0.push_str(value);
        Ok(())
    }
}

fn expand_template(template: &UriTemplateStr, context: &SimpleContext) -> Result<String, String> {
    use std::fmt::Write as _;
    let expanded = template
        .expand::<UriSpec, _>(context)
        .map_err(|_| "MCP resource template cannot be expanded".to_owned())?;
    let mut bounded = BoundedResourceUri(String::new());
    write!(&mut bounded, "{expanded}")
        .map_err(|_| "MCP resource template exceeds its URI budget".to_owned())?;
    let parsed = url::Url::parse(&bounded.0)
        .map_err(|_| "MCP resource template must produce an absolute URI".to_owned())?;
    if parsed.as_str() != bounded.0
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || !template
            .as_str()
            .starts_with(&parsed[..url::Position::BeforePath])
    {
        return Err(
            "MCP resource template must keep a canonical fixed scheme and authority".to_owned(),
        );
    }
    Ok(bounded.0)
}

fn template_schema(value: &str) -> Result<Value, String> {
    if value.len() > 2048
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("MCP resource template must be bounded URI text".to_owned());
    }
    let template = UriTemplateStr::new(value)
        .map_err(|_| "MCP resource template syntax is invalid".to_owned())?;
    let mut properties = serde_json::Map::new();
    let mut context = SimpleContext::new();
    for variable in template.variables() {
        let name = variable.as_str();
        if !valid_name(name) {
            return Err("MCP resource template variable is invalid".to_owned());
        }
        properties.insert(
            name.to_owned(),
            json!({"type":"string","minLength":1,"maxLength":256}),
        );
        context.insert(name, "template-validation");
    }
    if properties.is_empty() || properties.len() > 16 {
        return Err("MCP resource template requires one through sixteen variables".to_owned());
    }
    expand_template(template, &context)?;
    let required = properties.keys().cloned().collect::<Vec<_>>();
    Ok(
        json!({"type":"object","required":required,"properties":properties,"additionalProperties":false}),
    )
}

fn template_target(
    value: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<String, PortError> {
    let template = UriTemplateStr::new(value)
        .map_err(|_| invalid("MCP reviewed resource template is invalid"))?;
    let mut context = SimpleContext::new();
    for variable in template.variables() {
        let name = variable.as_str();
        let value = arguments
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            })
            .ok_or_else(|| invalid("MCP template variables must be bounded nonempty strings"))?;
        context.insert(name, value);
    }
    expand_template(template, &context)
        .map_err(|_| invalid("MCP expanded resource URI is unsafe or exceeds its budget"))
}

fn reviewed_descriptor(
    kind: OperationKind,
    descriptor: Value,
) -> Result<(String, String, Value, Value), String> {
    match kind {
        OperationKind::Tool => {
            let remote: claw_mcp::model::Tool = serde_json::from_value(descriptor)
                .map_err(|_| "MCP reviewed tool descriptor is invalid".to_owned())?;
            if !valid_name(&remote.name) {
                return Err("MCP remote tool name is invalid".to_owned());
            }
            let schema = Value::Object((*remote.input_schema).clone());
            let name = remote.name.to_string();
            let description = remote.description.as_deref().unwrap_or_default().to_owned();
            let descriptor = serde_json::to_value(remote)
                .map_err(|_| "MCP descriptor cannot be encoded".to_owned())?;
            Ok((name, description, schema, descriptor))
        }
        OperationKind::Resource | OperationKind::ResourceWatch => {
            let resource: claw_mcp::model::Resource = serde_json::from_value(descriptor)
                .map_err(|_| "MCP reviewed resource descriptor is invalid".to_owned())?;
            if resource.uri.len() > 2048
                || resource
                    .uri
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
                || url::Url::parse(&resource.uri).is_err()
                || !valid_name(&resource.name)
            {
                return Err(
                    "MCP resource requires a bounded absolute URI and valid name".to_owned(),
                );
            }
            let uri = resource.uri.clone();
            if matches!(kind, OperationKind::ResourceWatch) {
                let parsed = url::Url::parse(&uri)
                    .map_err(|_| "MCP observed resource URI is invalid".to_owned())?;
                if parsed.as_str() != uri
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(
                        "MCP observed resource URI must be canonical and unambiguous".to_owned(),
                    );
                }
            }
            let description = resource.description.clone().unwrap_or_default();
            let descriptor = serde_json::to_value(resource)
                .map_err(|_| "MCP resource descriptor cannot be encoded".to_owned())?;
            Ok((
                uri,
                description,
                if matches!(kind, OperationKind::ResourceWatch) {
                    json!({"type":"object","required":["durationMs","maxUpdates"],"properties":{"durationMs":{"type":"integer","minimum":1,"maximum":3000},"maxUpdates":{"type":"integer","minimum":1,"maximum":32}},"additionalProperties":false})
                } else {
                    json!({"type":"object","additionalProperties":false})
                },
                descriptor,
            ))
        }
        OperationKind::ResourceTemplate => {
            let resource: claw_mcp::model::ResourceTemplate = serde_json::from_value(descriptor)
                .map_err(|_| "MCP reviewed resource template descriptor is invalid".to_owned())?;
            if !valid_name(&resource.name) {
                return Err("MCP resource template name is invalid".to_owned());
            }
            let schema = template_schema(&resource.uri_template)?;
            let target = resource.uri_template.clone();
            let description = resource.description.clone().unwrap_or_default();
            let descriptor = serde_json::to_value(resource)
                .map_err(|_| "MCP resource template descriptor cannot be encoded".to_owned())?;
            Ok((target, description, schema, descriptor))
        }
        OperationKind::Prompt => {
            let prompt: claw_mcp::model::Prompt = serde_json::from_value(descriptor)
                .map_err(|_| "MCP reviewed prompt descriptor is invalid".to_owned())?;
            if !valid_name(&prompt.name)
                || prompt
                    .arguments
                    .as_ref()
                    .is_some_and(|arguments| arguments.len() > 16)
            {
                return Err("MCP prompt name or parameter count is invalid".to_owned());
            }
            let mut properties = serde_json::Map::new();
            let mut required = Vec::new();
            for argument in prompt.arguments.as_deref().unwrap_or_default() {
                if !valid_name(&argument.name)
                    || argument.description.as_ref().is_some_and(|description| {
                        description.len() > 2048 || description.chars().any(char::is_control)
                    })
                    || properties
                        .insert(
                            argument.name.clone(),
                            json!({"type":"string","maxLength":4096}),
                        )
                        .is_some()
                {
                    return Err("MCP prompt parameter is ambiguous or invalid".to_owned());
                }
                if argument.required.unwrap_or(false) {
                    required.push(argument.name.clone());
                }
            }
            let name = prompt.name.clone();
            let description = prompt.description.clone().unwrap_or_default();
            let descriptor = serde_json::to_value(prompt)
                .map_err(|_| "MCP prompt descriptor cannot be encoded".to_owned())?;
            Ok((
                name,
                description,
                json!({"type":"object","required":required,"properties":properties,"additionalProperties":false}),
                descriptor,
            ))
        }
    }
}

fn parse_policy(
    encoded: &str,
    mut read_token: impl FnMut(&str) -> Result<String, String>,
) -> Result<BTreeMap<String, PublishedTool>, String> {
    let document = claw_memory::json::from_json_value_reader(encoded.as_bytes(), POLICY_BYTES)
        .map_err(|_| "MCP tool policy must be bounded unambiguous JSON".to_owned())?;
    let policy: Policy = serde_json::from_value(document)
        .map_err(|_| "MCP tool policy must match its closed schema".to_owned())?;
    if policy.schema_version != 1 || policy.servers.len() > 4 {
        return Err("MCP tool policy version or server count is unsupported".to_owned());
    }
    let mut entries = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for mut server in policy.servers {
        if !valid_name(&server.id)
            || !identities.insert(server.id.clone())
            || server.review_revision == 0
            || server.tools.is_empty()
            || server.tools.len() > 8
        {
            return Err("MCP server identities or tool counts are invalid".to_owned());
        }
        let (transport, transport_identity) = parse_transport(&mut server, &mut read_token)?;
        let review_identity = digest(
            &serde_json::to_vec(&(
                "native-mcp-server-review/v1",
                &server.id,
                server.review_revision,
            ))
            .map_err(|_| "MCP review identity cannot be encoded".to_owned())?,
        );
        let owner = Arc::new(Server {
            id: server.id,
            transport,
            review_revision: server.review_revision,
            review_identity,
            revoked: AtomicBool::new(false),
            revocation: CancellationToken::new(),
        });
        let mut remote_names = BTreeSet::new();
        for tool in server.tools {
            if !valid_name(&tool.name) || !tool.name.starts_with("mcp_") || entries.len() >= 16 {
                return Err("MCP local tool names or global tool count are invalid".to_owned());
            }
            let (remote_name, description, schema, remote_descriptor) =
                reviewed_descriptor(tool.kind, tool.remote)?;
            if !remote_names.insert((tool.kind.label(), remote_name.clone()))
                || description.len() > 2048
                || description.chars().any(char::is_control)
                || schema.get("type").and_then(Value::as_str) != Some("object")
            {
                return Err(
                    "MCP reviewed descriptor name, description or object schema is invalid"
                        .to_owned(),
                );
            }
            let encoded = serde_json::to_vec(&(
                &owner.id,
                &transport_identity,
                &tool.name,
                tool.kind,
                &remote_descriptor,
                &owner.review_identity,
            ))
            .map_err(|_| "MCP publication cannot be encoded".to_owned())?;
            if encoded.len() > ARGUMENT_BYTES {
                return Err("MCP descriptor exceeds its byte limit".to_owned());
            }
            let validator = jsonschema::options()
                .offline()
                .with_pattern_options(
                    jsonschema::PatternOptions::regex()
                        .size_limit(256 * 1024)
                        .dfa_size_limit(512 * 1024),
                )
                .build(&schema)
                .map_err(|_| "MCP schema requires unsupported or external resources".to_owned())?;
            let entry = PublishedTool {
                server: Arc::clone(&owner),
                definition: ToolDefinition {
                    name: tool.name.clone(),
                    description: Some(description),
                    input_schema: schema,
                },
                remote_name,
                remote_descriptor,
                kind: tool.kind,
                publication: digest(&encoded),
                validator,
            };
            if entries.insert(tool.name, entry).is_some() {
                return Err("MCP local tool names conflict".to_owned());
            }
        }
    }
    Ok(entries)
}

impl PublishedTool {
    fn arguments(&self, invocation: &ToolInvocation) -> Result<Value, PortError> {
        let arguments = claw_memory::json::from_json_value_reader(
            invocation.call.arguments.as_bytes(),
            ARGUMENT_BYTES,
        )
        .map_err(|_| invalid("MCP arguments must be bounded unambiguous JSON"))?;
        if invocation.call.name != self.definition.name
            || !arguments.is_object()
            || !self.validator.is_valid(&arguments)
        {
            return Err(invalid(
                "MCP arguments do not match the reviewed tool schema",
            ));
        }
        Ok(arguments)
    }

    fn binding(
        &self,
        invocation: &ToolInvocation,
        authority: &InvocationAuthority,
    ) -> Result<ToolBinding, PortError> {
        if !authority.can_execute() {
            return Err(invalid(
                "MCP tools require authenticated execution authority",
            ));
        }
        if self.server.revoked.load(Ordering::Acquire) {
            return Err(invalid(
                "MCP server review was revoked; explicit re-enrollment is required",
            ));
        }
        let arguments = self.arguments(invocation)?;
        let target_binding = if matches!(self.kind, OperationKind::ResourceTemplate) {
            let target = template_target(
                &self.remote_name,
                arguments
                    .as_object()
                    .ok_or_else(|| invalid("MCP template arguments must be an object"))?,
            )?;
            format!("; expandedUriSha256={}", digest(target.as_bytes()))
        } else {
            String::new()
        };
        let identity = serde_json::to_vec(&(
            &self.publication,
            authority.subject(),
            authority.account(),
            authority.generation(),
            invocation.session_id.as_str(),
            &arguments,
        ))
        .map_err(|_| invalid("MCP approval cannot be encoded"))?;
        ToolBinding::new(&format!("mcp-{}", digest(&identity)), 1)?.with_resource(format!(
            "mcpServer={}; reviewRevision={}; {}; operation={}; remoteTarget={}; descriptorSha256={}{}; remote content is untrusted; no automatic retry",
            self.server.id, self.server.review_revision, self.server.transport.resource(), self.kind.label(), self.remote_name, digest(self.remote_descriptor.to_string().as_bytes()), target_binding
        ))
    }
}

struct ResourceObservations {
    uri: String,
    limit: usize,
    updates: AtomicUsize,
    ready: tokio::sync::Notify,
}

impl ResourceObservations {
    fn record(&self, uri: &str) {
        if uri == self.uri {
            let _ = self
                .updates
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |updates| {
                    Some(updates.saturating_add(1).min(self.limit + 1))
                });
            self.ready.notify_one();
        }
    }
}

struct CatalogEvents {
    server: Arc<Server>,
    observations: Option<Arc<ResourceObservations>>,
}

impl ClientEventSink for CatalogEvents {
    fn emit(&self, event: McpClientEvent) {
        if matches!(
            event,
            McpClientEvent::ToolsChanged
                | McpClientEvent::ResourcesChanged
                | McpClientEvent::PromptsChanged
        ) {
            self.server.revoke();
        } else if let McpClientEvent::ResourceUpdated(update) = event
            && let Some(observations) = &self.observations
        {
            observations.record(&update.uri);
        }
    }
}

pub(crate) struct NativeMcp {
    entries: BTreeMap<String, PublishedTool>,
    state: Arc<claw_state::DurableStateStore>,
    tasks: TaskTracker,
    slots: Arc<tokio::sync::Semaphore>,
    accepting: Mutex<bool>,
    shutdown: CancellationToken,
}

impl NativeMcp {
    pub(crate) async fn from_environment(
        state: Arc<claw_state::DurableStateStore>,
    ) -> Result<Arc<Self>, String> {
        let encoded = match std::env::var("GTA_CLAW_MCP_TOOL_POLICY") {
            Ok(encoded) => encoded,
            Err(std::env::VarError::NotPresent) => r#"{"schemaVersion":1,"servers":[]}"#.to_owned(),
            Err(_) => return Err("MCP tool policy must be UTF-8".to_owned()),
        };
        let entries =
            tokio::task::spawn_blocking(move || parse_policy(&encoded, read_configured_credential))
                .await
                .map_err(|_| "MCP policy or credential worker failed".to_owned())??;
        Self::from_entries(entries, state).await
    }

    #[cfg(test)]
    async fn from_policy(
        encoded: &str,
        read_token: impl FnMut(&str) -> Result<String, String>,
        state: Arc<claw_state::DurableStateStore>,
    ) -> Result<Arc<Self>, String> {
        let entries = parse_policy(encoded, read_token)?;
        Self::from_entries(entries, state).await
    }

    async fn from_entries(
        entries: BTreeMap<String, PublishedTool>,
        state: Arc<claw_state::DurableStateStore>,
    ) -> Result<Arc<Self>, String> {
        for entry in entries.values() {
            if state
                .tool_publication_revoked(&entry.server.review_identity)
                .await
                .map_err(|_| "MCP revocation state is unavailable".to_owned())?
            {
                entry.server.revoke();
            }
        }
        Ok(Arc::new(Self {
            entries,
            state,
            tasks: TaskTracker::new(),
            slots: Arc::new(tokio::sync::Semaphore::new(2)),
            accepting: Mutex::new(true),
            shutdown: CancellationToken::new(),
        }))
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub(super) fn reject_writable_programs(&self, root: &Path) -> Result<(), String> {
        for entry in self.entries.values() {
            if let ServerTransport::Stdio(program) = &entry.server.transport
                && program.configured.program.starts_with(root)
            {
                return Err(
                    "MCP executables must be outside the agent writable workspace".to_owned(),
                );
            }
        }
        Ok(())
    }

    pub(super) fn extend_catalog(&self, definitions: &mut Vec<ToolDefinition>) {
        for entry in self.entries.values() {
            if definitions
                .iter()
                .any(|tool| tool.name == entry.definition.name)
            {
                definitions.retain(|tool| tool.name != entry.definition.name);
            } else if !self.shutdown.is_cancelled()
                && !self.state.recovery_required()
                && !entry.server.revoked.load(Ordering::Acquire)
            {
                definitions.push(entry.definition.clone());
            }
        }
    }

    pub(super) fn summary(&self) -> Value {
        let active = self.tasks.len();
        json!({"enabled":!self.entries.is_empty(),"accepting":!self.shutdown.is_cancelled(),
            "activeInvocations":active,"allInvocationsDrained":active == 0,
            "tools":self.entries.keys().collect::<Vec<_>>(),"reviews":self.entries.values().map(|entry| json!({"tool":entry.definition.name,"server":entry.server.id,"reviewRevision":entry.server.review_revision,"revoked":entry.server.revoked.load(Ordering::Acquire),"transport":entry.server.transport.label()})).collect::<Vec<_>>(),"sampling":false,"automaticReplay":false,"credentialsIncluded":false})
    }

    pub(super) fn binding(
        &self,
        invocation: &ToolInvocation,
        authority: &InvocationAuthority,
    ) -> Result<ToolBinding, PortError> {
        if self.shutdown.is_cancelled() || self.state.recovery_required() {
            return Err(PortError::Unavailable("MCP tools are closed".to_owned()));
        }
        self.entries
            .get(&invocation.call.name)
            .ok_or_else(|| invalid("MCP tool is not explicitly configured"))?
            .binding(invocation, authority)
    }

    pub(super) async fn invoke(
        self: &Arc<Self>,
        invocation: ToolInvocation,
        authority: InvocationAuthority,
        binding: ToolBinding,
        cancellation: CancellationToken,
        audit: Arc<DurableSecurityAudit>,
    ) -> Result<ToolOutcome, PortError> {
        if cancellation.is_cancelled() || self.binding(&invocation, &authority)? != binding {
            return Err(invalid("MCP approval binding changed or was cancelled"));
        }
        let _cancel_on_drop = cancellation.clone().drop_guard();
        let task = {
            let accepting = self
                .accepting
                .lock()
                .map_err(|_| invalid("MCP admission gate failed"))?;
            if !*accepting {
                return Err(PortError::Unavailable("MCP tools are closed".to_owned()));
            }
            let slot = Arc::clone(&self.slots)
                .try_acquire_owned()
                .map_err(|_| PortError::Unavailable("MCP tool capacity exceeded".to_owned()))?;
            let tools = Arc::clone(self);
            let task = self.tasks.spawn(async move {
                let _slot = slot;
                if cancellation.is_cancelled() || tools.binding(&invocation, &authority)? != binding
                {
                    return Err(invalid("MCP authority changed before connection"));
                }
                audit
                    .persist_internal_tool(
                        &invocation,
                        &authority,
                        &binding,
                        InternalToolAuditPhase::Authorized,
                    )
                    .map_err(|_| {
                        PortError::Unavailable(
                            "MCP authorization audit could not be persisted".to_owned(),
                        )
                    })?;
                let result = std::panic::AssertUnwindSafe(tools.execute(
                    &invocation,
                    &authority,
                    &binding,
                    &cancellation,
                ))
                .catch_unwind()
                .await
                .unwrap_or_else(|_| Err(unknown("MCP operation ended without a confirmed result")));
                let phase = if result.as_ref().is_ok_and(|(_, failed)| !failed) {
                    InternalToolAuditPhase::Completed
                } else {
                    InternalToolAuditPhase::Failed
                };
                audit
                    .persist_internal_tool(&invocation, &authority, &binding, phase)
                    .map_err(|_| {
                        unknown(
                            "MCP completion audit is unconfirmed; inspect effects before retrying",
                        )
                    })?;
                let (output, failed) = result?;
                Ok(ToolOutcome {
                    call_id: invocation.call.call_id,
                    status: if failed {
                        ToolStatus::Failed
                    } else {
                        ToolStatus::Ok
                    },
                    output,
                    changed_workspace: true,
                })
            });
            drop(accepting);
            task
        };
        task.await.map_err(|_| {
            unknown("MCP invocation result is unknown; do not repeat it automatically")
        })?
    }

    async fn cancelled(&self, cancellation: &CancellationToken, server: &Server) {
        tokio::select! { () = cancellation.cancelled() => {}, () = self.shutdown.cancelled() => {}, () = server.revocation.cancelled() => {} }
    }

    async fn execute(
        &self,
        invocation: &ToolInvocation,
        authority: &InvocationAuthority,
        binding: &ToolBinding,
        cancellation: &CancellationToken,
    ) -> Result<(String, bool), PortError> {
        let entry = self
            .entries
            .get(&invocation.call.name)
            .ok_or_else(|| invalid("MCP tool publication is absent"))?;
        if self
            .state
            .tool_publication_revoked(&entry.server.review_identity)
            .await?
        {
            entry.server.revoke();
        }
        if entry.server.revoked.load(Ordering::Acquire) {
            return Err(invalid(
                "MCP review is durably revoked; no connection is permitted",
            ));
        }
        let result = std::panic::AssertUnwindSafe(self.execute_connection(
            entry,
            invocation,
            authority,
            binding,
            cancellation,
        ))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(unknown("MCP transport ended without a confirmed result")));
        if entry.server.revoked.load(Ordering::Acquire) {
            if self
                .state
                .revoke_tool_publication(&entry.server.review_identity)
                .await
                .is_err()
            {
                self.shutdown.cancel();
                return Err(unknown(
                    "MCP revocation could not be confirmed on disk; all MCP tools are disabled for this runtime",
                ));
            }
            return Err(unknown(
                "MCP server review was revoked; review and re-enroll before any further call",
            ));
        }
        result
    }

    async fn execute_connection(
        &self,
        entry: &PublishedTool,
        invocation: &ToolInvocation,
        authority: &InvocationAuthority,
        binding: &ToolBinding,
        cancellation: &CancellationToken,
    ) -> Result<(String, bool), PortError> {
        let arguments = entry
            .arguments(invocation)?
            .as_object()
            .cloned()
            .ok_or_else(|| invalid("MCP arguments must be an object"))?;
        verify_keyring_credential(&entry.server).await?;
        let observations = if matches!(entry.kind, OperationKind::ResourceWatch) {
            Some(Arc::new(ResourceObservations {
                uri: entry.remote_name.clone(),
                limit: usize::try_from(
                    arguments
                        .get("maxUpdates")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| invalid("MCP watch update limit is missing"))?,
                )
                .map_err(|_| invalid("MCP watch update limit is invalid"))?,
                updates: AtomicUsize::new(0),
                ready: tokio::sync::Notify::new(),
            }))
        } else {
            None
        };
        let events = Arc::new(CatalogEvents {
            server: Arc::clone(&entry.server),
            observations: observations.clone(),
        });
        let mut prepared = if let ServerTransport::Stdio(program) = &entry.server.transport {
            let program = Arc::clone(program);
            Some(
                tokio::task::spawn_blocking(move || {
                    program.directory.validate_root().map_err(|_| ())?;
                    let executable = program.policy.pin_program("mcp").map_err(|_| ())?;
                    program.directory.validate_root().map_err(|_| ())?;
                    let mut config = StdioClientConfig::new(executable.path());
                    config.arguments = program
                        .configured
                        .arguments
                        .iter()
                        .map(Into::into)
                        .collect();
                    config.environment = program
                        .configured
                        .environment
                        .iter()
                        .map(|(name, value)| (name.into(), value.into()))
                        .collect();
                    for (name, credential) in &program.credentials {
                        let expected =
                            Sha256::digest(credential.value.expose_secret().as_bytes()).into();
                        if !credential_matches(&credential.reference, &expected).map_err(|_| ())? {
                            return Err(());
                        }
                        config
                            .environment
                            .insert(name.into(), credential.value.expose_secret().into());
                    }
                    config.connect_timeout = Duration::from_secs(3);
                    config.request_timeout = Duration::from_secs(5);
                    config.max_frame_bytes = 64 * 1024;
                    Ok::<_, ()>(PreparedStdio {
                        config: Some(config),
                        directory: program.directory.resolve_root().native(),
                        _executable: executable,
                    })
                })
                .await
                .map_err(|_| unknown("MCP executable verification worker failed"))?
                .map_err(|()| {
                    entry.server.revoke();
                    unknown(
                        "MCP executable, directory or credential changed; child was not started",
                    )
                })?,
            )
        } else {
            None
        };
        if self.binding(invocation, authority)? != *binding {
            return Err(invalid("MCP authority changed before transport startup"));
        }
        let connect = async {
            match &entry.server.transport {
                ServerTransport::Http {
                    endpoint,
                    token,
                    route,
                    ..
                } => {
                    let mut config = HttpClientConfig::new(endpoint.clone());
                    config.bearer_token = token.clone();
                    config.connect_timeout = Duration::from_secs(3);
                    config.request_timeout = Duration::from_secs(5);
                    McpClient::connect_http_with_route(
                        config,
                        route.as_ref().clone(),
                        Arc::new(RejectSampling),
                        events.clone(),
                    )
                    .await
                }
                ServerTransport::Stdio(_) => {
                    let prepared = prepared.as_mut().ok_or_else(|| {
                        claw_mcp::error::McpError::Protocol("missing stdio preparation".into())
                    })?;
                    let config = prepared.config.take().ok_or_else(|| {
                        claw_mcp::error::McpError::Protocol(
                            "stdio preparation was already consumed".into(),
                        )
                    })?;
                    McpClient::connect_stdio_isolated_at(
                        config,
                        prepared.directory.clone(),
                        Arc::new(RejectSampling),
                        events.clone(),
                    )
                    .await
                }
            }
        };
        let client = tokio::select! {
            biased;
            () = self.cancelled(cancellation, &entry.server) => return Err(unknown("MCP connection cancelled; no automatic retry")),
            connected = connect => connected.map_err(|_| unknown("MCP connection was not confirmed; no automatic retry"))?,
        };
        let result = async {
            let supported = client.server_info().is_some_and(|info| match entry.kind {
                OperationKind::Tool => info.capabilities.tools.is_some(),
                OperationKind::Resource | OperationKind::ResourceTemplate => info.capabilities.resources.is_some(),
                OperationKind::ResourceWatch => info.capabilities.resources.as_ref().is_some_and(|resources| resources.subscribe == Some(true)),
                OperationKind::Prompt => info.capabilities.prompts.is_some(),
            });
            if !supported {
                entry.server.revoke();
                return Err(unknown("MCP server did not advertise the reviewed operation capability"));
            }
            let (descriptors, paginated) = tokio::select! {
                biased;
                () = self.cancelled(cancellation, &entry.server) => return Err(unknown("MCP discovery cancelled; no automatic retry")),
                listed = discover(&client, entry.kind) => listed?,
            };
            if paginated || descriptors.len() > 128 {
                entry.server.revoke();
                return Err(unknown("MCP discovery exceeds the supported bounded single-page contract"));
            }
            let key = match entry.kind { OperationKind::Resource | OperationKind::ResourceWatch => "uri", OperationKind::ResourceTemplate => "uriTemplate", OperationKind::Tool | OperationKind::Prompt => "name" };
            let matching = descriptors.iter().filter(|descriptor| descriptor[key].as_str() == Some(entry.remote_name.as_str())).collect::<Vec<_>>();
            if matching.len() != 1 || matching[0] != &entry.remote_descriptor {
                entry.server.revoke();
                return Err(unknown("MCP reviewed tool descriptor changed; no remote tool was invoked"));
            }
            verify_keyring_credential(&entry.server).await?;
            if self.binding(invocation, authority)? != *binding || entry.server.revoked.load(Ordering::Acquire) {
                return Err(unknown("MCP authority or tool catalog changed before invocation"));
            }
            let (result, failed) = if let Some(observations) = &observations {
                let observed = tokio::select! {
                    biased;
                    () = self.cancelled(cancellation, &entry.server) => Err(unknown("MCP resource observation cancelled; subscription cleanup must be confirmed")),
                    result = observe_resource(&client, &arguments, observations) => result,
                };
                let released = client.unsubscribe(claw_mcp::model::UnsubscribeRequestParams::new(entry.remote_name.clone())).await;
                observed?;
                released.map_err(|_| unknown("MCP resource unsubscription was not confirmed; connection is closing"))?;
                verify_keyring_credential(&entry.server).await?;
                if self.binding(invocation, authority)? != *binding { return Err(unknown("MCP watch authority changed before completion")); }
                let updates = observations.updates.load(Ordering::Acquire);
                (json!({"uri":entry.remote_name,"observedUpdates":updates.min(observations.limit),"limitReached":updates >= observations.limit,
                    "coalesced":true,"unsubscribed":true,"automaticRead":false,"continuousSubscription":false}), false)
            } else {
                tokio::select! {
                    biased;
                    () = self.cancelled(cancellation, &entry.server) => return Err(unknown("MCP invocation cancelled; effects require reconciliation")),
                    result = invoke_remote(&client, entry, arguments) => result?,
                }
            };
            if entry.server.revoked.load(Ordering::Acquire) { return Err(unknown("MCP catalog changed during the call; reconcile remote effects")); }
            let output = serde_json::to_string(&json!({"server":entry.server.id,"tool":entry.remote_name,"operation":entry.kind.label(),"untrusted":true,"automaticReplay":false,"remoteResult":result}))
                .map_err(|_| unknown("MCP result could not be encoded"))?;
            if output.len() > ARGUMENT_BYTES { return Err(unknown("MCP result exceeds its output budget; inspect remote effects")); }
            Ok((output, failed))
        }.await;
        let closed = client.close().await;
        drop(prepared);
        closed
            .map_err(|_| unknown("MCP connection did not close cleanly; inspect remote effects"))?;
        result
    }

    pub(super) async fn shutdown(&self) {
        if let Ok(mut accepting) = self.accepting.lock() {
            *accepting = false;
        }
        self.shutdown.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }
}

fn unknown(message: &str) -> PortError {
    PortError::OutcomeUnknown(message.to_owned())
}

async fn discover(
    client: &McpClient,
    kind: OperationKind,
) -> Result<(Vec<Value>, bool), PortError> {
    let failure = || unknown("MCP reviewed catalog could not be confirmed");
    match kind {
        OperationKind::Tool => {
            let listed = client.list_tools().await.map_err(|_| failure())?;
            Ok((
                listed
                    .tools
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| failure())?,
                listed.next_cursor.is_some(),
            ))
        }
        OperationKind::Resource | OperationKind::ResourceWatch => {
            let listed = client.list_resources().await.map_err(|_| failure())?;
            Ok((
                listed
                    .resources
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| failure())?,
                listed.next_cursor.is_some(),
            ))
        }
        OperationKind::ResourceTemplate => {
            let listed = client
                .list_resource_templates()
                .await
                .map_err(|_| failure())?;
            Ok((
                listed
                    .resource_templates
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| failure())?,
                listed.next_cursor.is_some(),
            ))
        }
        OperationKind::Prompt => {
            let listed = client.list_prompts().await.map_err(|_| failure())?;
            Ok((
                listed
                    .prompts
                    .into_iter()
                    .map(serde_json::to_value)
                    .collect::<Result<_, _>>()
                    .map_err(|_| failure())?,
                listed.next_cursor.is_some(),
            ))
        }
    }
}

async fn observe_resource(
    client: &McpClient,
    arguments: &serde_json::Map<String, Value>,
    observations: &ResourceObservations,
) -> Result<(), PortError> {
    let duration = arguments
        .get("durationMs")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("MCP observation duration is missing"))?;
    client
        .subscribe(claw_mcp::model::SubscribeRequestParams::new(
            observations.uri.clone(),
        ))
        .await
        .map_err(|_| unknown("MCP resource subscription was not confirmed; no automatic retry"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(duration);
    loop {
        let notified = observations.ready.notified();
        if observations.updates.load(Ordering::Acquire) >= observations.limit {
            return Ok(());
        }
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(()),
            () = notified => {}
        }
    }
}

async fn invoke_remote(
    client: &McpClient,
    entry: &PublishedTool,
    arguments: serde_json::Map<String, Value>,
) -> Result<(Value, bool), PortError> {
    let failure =
        || unknown("MCP operation has an unconfirmed outcome; do not repeat automatically");
    match entry.kind {
        OperationKind::ResourceWatch => Err(invalid(
            "MCP resource watch requires owned observation state",
        )),
        OperationKind::Tool => {
            let result = client
                .call_tool(
                    claw_mcp::model::CallToolRequestParams::new(entry.remote_name.clone())
                        .with_arguments(arguments),
                )
                .await
                .map_err(|_| failure())?;
            let failed = result.is_error.unwrap_or(false);
            Ok((serde_json::to_value(result).map_err(|_| failure())?, failed))
        }
        OperationKind::Resource | OperationKind::ResourceTemplate => {
            let target = if matches!(entry.kind, OperationKind::ResourceTemplate) {
                template_target(&entry.remote_name, &arguments)?
            } else {
                entry.remote_name.clone()
            };
            let result = client
                .read_resource(claw_mcp::model::ReadResourceRequestParams::new(
                    target.clone(),
                ))
                .await
                .map_err(|_| failure())?;
            let result = serde_json::to_value(result).map_err(|_| failure())?;
            if result["contents"].as_array().is_none_or(|contents| {
                contents.len() > 32
                    || contents
                        .iter()
                        .any(|content| content["uri"].as_str() != Some(target.as_str()))
            }) {
                return Err(unknown(
                    "MCP resource result does not match its approved URI or item budget",
                ));
            }
            Ok((result, false))
        }
        OperationKind::Prompt => {
            let request =
                serde_json::from_value(json!({"name":entry.remote_name,"arguments":arguments}))
                    .map_err(|_| failure())?;
            let result = client.get_prompt(request).await.map_err(|_| failure())?;
            if result.messages.len() > 32 {
                return Err(unknown("MCP prompt result exceeds its message budget"));
            }
            Ok((serde_json::to_value(result).map_err(|_| failure())?, false))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_application::model::ids::{ToolCallId, TurnId};
    use claw_application::model::message::ToolCall;
    use claw_application::ports::tool::{InvocationAccess, InvocationSource};

    #[test]
    fn native_mcp_resource_watch_requires_bounded_arguments_and_counts_only_its_fixed_uri() {
        let mut source = policy();
        source["servers"][0]["tools"][0] = json!({"name":"mcp_fixture_echo","kind":"resource_watch","remote":{"name":"watched","uri":"gta://watch/owned","description":"Observe reviewed resource"}});
        let entries = parse_policy(&source.to_string(), |_| panic!("no configured credentials"))
            .expect("resource watch enrollment");
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "watch-reviewer",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("authority");
        let entry = &entries["mcp_fixture_echo"];
        let binding = entry
            .binding(
                &invocation(&json!({"durationMs":100,"maxUpdates":2})),
                &authority,
            )
            .expect("exact watch approval");
        assert!(
            binding
                .resource()
                .expect("resource")
                .contains("operation=resource_watch")
        );
        assert_ne!(
            binding,
            entry
                .binding(
                    &invocation(&json!({"durationMs":101,"maxUpdates":2})),
                    &authority
                )
                .expect("different observation window")
        );
        for invalid in [
            json!({}),
            json!({"durationMs":0,"maxUpdates":1}),
            json!({"durationMs":3001,"maxUpdates":1}),
            json!({"durationMs":1,"maxUpdates":33}),
            json!({"durationMs":1,"maxUpdates":0}),
            json!({"durationMs":1,"maxUpdates":1,"uri":"gta://other/resource"}),
        ] {
            assert!(entry.binding(&invocation(&invalid), &authority).is_err());
        }
        let observations = ResourceObservations {
            uri: "gta://watch/owned".to_owned(),
            limit: 2,
            updates: AtomicUsize::new(0),
            ready: tokio::sync::Notify::new(),
        };
        observations.record("gta://watch/foreign");
        assert_eq!(observations.updates.load(Ordering::Acquire), 0);
        for _ in 0..100 {
            observations.record("gta://watch/owned");
        }
        assert_eq!(observations.updates.load(Ordering::Acquire), 3);
    }

    #[test]
    fn native_mcp_template_expansion_is_bounded_canonical_and_bound_without_argument_disclosure() {
        let uri = "gta://fixture/notes/{id}{?query}";
        let schema = template_schema(uri).expect("reviewed RFC 6570 template");
        assert_eq!(schema["required"], json!(["id", "query"]));
        assert_eq!(schema["additionalProperties"], false);
        let arguments = json!({"id":"note/one","query":"hello world"});
        assert_eq!(
            template_target(uri, arguments.as_object().expect("arguments"))
                .expect("encoded target"),
            "gta://fixture/notes/note%2Fone?query=hello%20world"
        );
        for invalid in [
            "gta://{host}/notes/{id}",
            "{scheme}://fixture/notes/{id}",
            "/relative/{id}",
            "gta://fixture/notes",
            "gta://fixture/{id",
            "gta://fixture/notes/{id}#fragment",
        ] {
            assert!(template_schema(invalid).is_err());
        }
        for arguments in [
            json!({"id":"..","query":"x"}),
            json!({"id":"x"}),
            json!({"id":"x","query":true}),
            json!({"id":"x","query":"x".repeat(257)}),
            json!({"id":"x","query":"bad\nvalue"}),
        ] {
            assert!(template_target(uri, arguments.as_object().expect("arguments")).is_err());
        }
        let repeated = format!("gta://fixture/{}", "{id}".repeat(10));
        assert!(template_schema(&repeated).is_ok());
        assert!(
            template_target(
                &repeated,
                json!({"id":"x".repeat(256)})
                    .as_object()
                    .expect("arguments")
            )
            .is_err()
        );
        let mut source = policy();
        source["servers"][0]["tools"][0] = json!({"name":"mcp_fixture_echo","kind":"resource_template","remote":{"name":"notes-by-id","uriTemplate":uri,"description":"Reviewed note template"}});
        let entries = parse_policy(&source.to_string(), |_| panic!("no credentials configured"))
            .expect("template enrollment");
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "template-reviewer",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("authority");
        let call = invocation(&json!({"id":"private-template-variable","query":"private-query"}));
        let binding = entries["mcp_fixture_echo"]
            .binding(&call, &authority)
            .expect("template approval");
        let resource = binding.resource().expect("resource scope");
        assert!(resource.contains("expandedUriSha256=") && resource.contains(uri));
        assert!(
            !resource.contains("private-template-variable") && !resource.contains("private-query")
        );
        assert_ne!(
            binding,
            entries["mcp_fixture_echo"]
                .binding(
                    &invocation(&json!({"id":"other","query":"private-query"})),
                    &authority
                )
                .expect("other exact target")
        );
        assert!(
            entries["mcp_fixture_echo"]
                .binding(&invocation(&json!({"id":"..","query":"x"})), &authority)
                .is_err()
        );
        assert!(
            entries["mcp_fixture_echo"]
                .binding(
                    &invocation(&json!({"id":"one","query":"x","extra":"field"})),
                    &authority
                )
                .is_err()
        );
    }

    fn invocation(arguments: &Value) -> ToolInvocation {
        ToolInvocation {
            session_id: claw_domain::SessionId::new("mcp-session").expect("session"),
            turn: TurnId::FIRST,
            call: ToolCall {
                call_id: ToolCallId::new("mcp-call").expect("call"),
                name: "mcp_fixture_echo".to_owned(),
                arguments: arguments.to_string(),
            },
        }
    }

    fn policy() -> Value {
        json!({"schemaVersion":1,"servers":[{"id":"fixture","url":"http://127.0.0.1:32109/mcp","tools":[{"name":"mcp_fixture_echo","remote":{"name":"echo","description":"Reviewed local echo","inputSchema":{"type":"object","required":["text"],"properties":{"text":{"type":"string","maxLength":64}},"additionalProperties":false}}}]}]})
    }

    #[test]
    fn native_mcp_token_refs_are_bound_to_the_server_origin_before_lookup() {
        let mut source = policy();
        let endpoint =
            url::Url::parse(source["servers"][0]["url"].as_str().expect("URL")).expect("endpoint");
        let reference = claw_mcp::oauth::CredentialBinding::new("fixture", &endpoint)
            .expect("binding")
            .keyring_reference();
        source["servers"][0]["tokenRef"] = json!(reference);
        let entries = parse_policy(&source.to_string(), |requested| {
            assert_eq!(requested, reference);
            Ok("private-native-fixture-secret".to_owned())
        })
        .expect("origin-bound credential lookup");
        let ServerTransport::Http {
            keyring_ref, token, ..
        } = &entries["mcp_fixture_echo"].server.transport
        else {
            panic!("HTTP transport");
        };
        assert_eq!(keyring_ref.as_deref(), Some(reference.as_str()));
        assert_eq!(
            token.as_ref().expect("loaded token").expose_secret(),
            "private-native-fixture-secret"
        );
        for invalid in [
            "inline-private-value".to_owned(),
            "keyring://gta-claw.other/account".to_owned(),
            "service://gta-claw.mcp-outbound/account".to_owned(),
            "fd://0".to_owned(),
            claw_mcp::oauth::CredentialBinding::new("other-server", &endpoint)
                .expect("other binding")
                .keyring_reference(),
            claw_mcp::oauth::CredentialBinding::new(
                "fixture",
                &url::Url::parse("http://127.0.0.1:32110/mcp").expect("other endpoint"),
            )
            .expect("other origin")
            .keyring_reference(),
        ] {
            let mut rejected = source.clone();
            rejected["servers"][0]["tokenRef"] = json!(invalid);
            let error = parse_policy(&rejected.to_string(), |_| {
                panic!("foreign or inline reference must never be resolved")
            })
            .err()
            .expect("reference refused");
            assert!(!error.contains("inline-private-value"));
        }
        source["servers"][0]["tokenEnv"] = json!("GTA_CLAW_MCP_OUTBOUND_FIXTURE");
        assert!(
            parse_policy(&source.to_string(), |_| panic!(
                "mixed credential sources refused"
            ))
            .is_err()
        );
    }

    #[test]
    fn native_mcp_policy_pins_only_reviewed_loopback_tools_and_offline_schemas() {
        let source = policy();
        let entries = parse_policy(&source.to_string(), |_| {
            Err("no credential requested".to_owned())
        })
        .expect("explicit policy");
        assert_eq!(entries.len(), 1);
        let entry = &entries["mcp_fixture_echo"];
        assert_eq!(entry.remote_name, "echo");
        assert!(entry.validator.is_valid(&json!({"text":"hello"})));
        assert!(
            !entry
                .validator
                .is_valid(&json!({"text":"hello","extra":true}))
        );
        for (pointer, value) in [
            ("/servers/0/url", json!("http://localhost:32109/mcp")),
            ("/servers/0/url", json!("https://remote.example/mcp")),
            (
                "/servers/0/url",
                json!("http://private-secret@127.0.0.1/mcp"),
            ),
            (
                "/servers/0/url",
                json!("http://127.0.0.1/mcp?token=private-secret"),
            ),
            ("/servers/0/tools/0/name", json!("update_goal")),
            (
                "/servers/0/tools/0/remote/inputSchema",
                json!({"type":"object","$ref":"https://remote.example/schema"}),
            ),
            ("/schemaVersion", json!(2)),
        ] {
            let mut changed = source.clone();
            *changed.pointer_mut(pointer).expect("field") = value;
            let error = parse_policy(&changed.to_string(), |_| Ok("private-secret".to_owned()))
                .err()
                .expect("invalid policy");
            assert!(!error.contains("private-secret"));
        }
        let mut changed = source.clone();
        changed["servers"][0]["tools"]
            .as_array_mut()
            .expect("tools")
            .push(source["servers"][0]["tools"][0].clone());
        assert!(parse_policy(&changed.to_string(), |_| Err(String::new())).is_err());
        changed = source;
        changed["servers"][0]["tokenEnv"] = json!("GITHUB_TOKEN");
        assert!(
            parse_policy(&changed.to_string(), |_| panic!(
                "invalid secret reference must not be read"
            ))
            .is_err()
        );
        assert!(
            parse_policy(
                r#"{"schemaVersion":1,"schemaVersion":1,"servers":[]}"#,
                |_| Err(String::new())
            )
            .is_err()
        );
        let mut group = policy();
        let mut sibling = group["servers"][0]["tools"][0].clone();
        sibling["name"] = json!("mcp_fixture_other");
        sibling["remote"]["name"] = json!("other");
        group["servers"][0]["tools"]
            .as_array_mut()
            .expect("tools")
            .push(sibling);
        let mut independent = policy()["servers"][0].clone();
        independent["id"] = json!("independent");
        independent["tools"][0]["name"] = json!("mcp_independent_echo");
        group["servers"]
            .as_array_mut()
            .expect("servers")
            .push(independent);
        let grouped =
            parse_policy(&group.to_string(), |_| Err(String::new())).expect("independent groups");
        let first = &grouped["mcp_fixture_echo"].server;
        let sibling = &grouped["mcp_fixture_other"].server;
        let independent = &grouped["mcp_independent_echo"].server;
        let pending_sibling = sibling.revocation.child_token();
        CatalogEvents {
            server: Arc::clone(first),
            observations: None,
        }
        .emit(McpClientEvent::ToolsChanged);
        assert!(first.revoked.load(Ordering::Acquire));
        assert!(sibling.revoked.load(Ordering::Acquire));
        assert!(pending_sibling.is_cancelled());
        assert!(!independent.revoked.load(Ordering::Acquire));
        assert!(!independent.revocation.is_cancelled());
        let original = first.review_identity.clone();
        group["servers"][0]["url"] = json!("http://127.0.0.1:32110/mcp");
        group["servers"][0]["tools"][0]["remote"]["description"] = json!("revised descriptor");
        let altered = parse_policy(&group.to_string(), |_| Err(String::new()))
            .expect("changed local configuration");
        assert_eq!(
            altered["mcp_fixture_echo"].server.review_identity, original,
            "editing a URL or descriptor cannot implicitly replace a revoked review"
        );
        group["servers"][0]["reviewRevision"] = json!(2);
        let reviewed =
            parse_policy(&group.to_string(), |_| Err(String::new())).expect("explicit new review");
        assert_ne!(
            reviewed["mcp_fixture_echo"].server.review_identity,
            original
        );
        group["servers"][0]["reviewRevision"] = json!(0);
        assert!(parse_policy(&group.to_string(), |_| Err(String::new())).is_err());
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn native_mcp_oauth_records_require_original_fresh_generation_without_automatic_refresh()
    {
        use axum::{Json, Router, extract::State, response::IntoResponse as _, routing::post};
        use claw_mcp::oauth::{AuthorizationCallback, OAuthClient};
        use claw_provider_sdk::secret::{
            CredentialKey, SecretStore as _, SecretString as StoredSecret,
            WindowsCredentialManagerStore,
        };
        use std::sync::atomic::AtomicUsize;

        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        struct OwnedCredential {
            binding: CredentialBinding,
            store: NativeTokenStore,
        }
        impl Drop for OwnedCredential {
            fn drop(&mut self) {
                let _ = self.store.delete(&self.binding);
            }
        }
        struct Remote {
            mode: &'static str,
            binding: CredentialBinding,
            resource: String,
            descriptor: Value,
            token_requests: AtomicUsize,
            initializations: AtomicUsize,
            calls: AtomicUsize,
        }
        fn change_record(binding: &CredentialBinding, field: &str, value: Value) {
            let reference = NativeTokenStore::keyring_reference(binding);
            let key = CredentialKey::new(
                "gta-claw.mcp-oauth",
                reference.rsplit('/').next().expect("account"),
            )
            .expect("owned key");
            let store = WindowsCredentialManagerStore::new().expect("owned keyring");
            let record = store
                .get(&key)
                .expect("owned token record")
                .expect("present");
            let mut record: Value = serde_json::from_str(record.expose()).expect("stored JSON");
            record[field] = value;
            store
                .set(&key, &StoredSecret::new(record.to_string()))
                .expect("change only owned record");
        }
        async fn exchange(State(remote): State<Arc<Remote>>, body: String) -> Json<Value> {
            let form: BTreeMap<_, _> = url::form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect();
            assert_eq!(
                form["grant_type"], "authorization_code",
                "daemon must not refresh"
            );
            assert_eq!(form["client_id"], "fixture-public-client");
            assert_eq!(form["resource"], remote.resource);
            remote.token_requests.fetch_add(1, Ordering::SeqCst);
            Json(
                json!({"access_token":"private-daemon-oauth-access","refresh_token":"private-daemon-oauth-refresh","expires_in":3600,"token_type":"Bearer"}),
            )
        }
        async fn respond(
            State(remote): State<Arc<Remote>>,
            headers: axum::http::HeaderMap,
            Json(request): Json<Value>,
        ) -> axum::response::Response {
            assert_eq!(
                headers
                    .get("authorization")
                    .expect("bound bearer")
                    .to_str()
                    .expect("header"),
                "Bearer private-daemon-oauth-access"
            );
            let Some(id) = request.get("id") else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            let result = match request["method"].as_str().expect("method") {
                "initialize" => {
                    remote.initializations.fetch_add(1, Ordering::SeqCst);
                    json!({"protocolVersion":"2025-03-26","serverInfo":{"name":"oauth-mcp-fixture","version":"1"},"capabilities":{"tools":{}}})
                }
                "tools/list" => {
                    if remote.mode == "scope-during-discovery" {
                        change_record(&remote.binding, "scope", json!("changed-scope"));
                    }
                    json!({"tools":[remote.descriptor]})
                }
                "tools/call" => {
                    remote.calls.fetch_add(1, Ordering::SeqCst);
                    json!({"content":[{"type":"text","text":"owned OAuth MCP result"}],"isError":false})
                }
                other => panic!("unexpected MCP fixture method {other}"),
            };
            Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
        }

        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let root = Root(std::env::temp_dir().join(format!("claw-mcp-oauth-{nonce}")));
        std::fs::create_dir(&root.0).expect("owned directory");
        let state = Arc::new(
            claw_state::DurableStateStore::open(root.0.join("state.redb")).expect("state"),
        );
        let audit = Arc::new(
            DurableSecurityAudit::open(
                &root.0.join("audit.jsonl"),
                Arc::new(super::super::http_api::DependencyReadiness::new(["audit"])),
            )
            .expect("audit"),
        );
        for (ordinal, mode) in [
            "success",
            "deleted",
            "pending",
            "scope-changed",
            "refresh-changed",
            "expired",
            "scope-during-discovery",
        ]
        .into_iter()
        .enumerate()
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("owned HTTP fixture");
            let base = url::Url::parse(&format!(
                "http://{}/",
                listener.local_addr().expect("address")
            ))
            .expect("base");
            let endpoint = base.join("mcp").expect("resource");
            let binding = CredentialBinding::new(format!("oauth-{nonce}-{ordinal}"), &endpoint)
                .expect("credential binding");
            let store = NativeTokenStore::new().expect("native fixture store");
            assert!(
                store
                    .load(&binding)
                    .expect("unique credential preflight")
                    .is_none()
            );
            let owned = OwnedCredential {
                binding: binding.clone(),
                store,
            };
            let mut source = policy();
            source["servers"][0]["id"] = json!(binding.profile());
            source["servers"][0]["url"] = json!(endpoint.as_str());
            source["servers"][0]["oauth"] = json!({"issuer":base.as_str(),"authorizationEndpoint":base.join("authorize").expect("authorization").as_str(),
                "tokenEndpoint":base.join("token").expect("token").as_str(),"clientId":"fixture-public-client","credentialRef":NativeTokenStore::keyring_reference(&binding)});
            let remote = Arc::new(Remote {
                mode,
                binding: binding.clone(),
                resource: endpoint.to_string(),
                descriptor: source["servers"][0]["tools"][0]["remote"].clone(),
                token_requests: AtomicUsize::new(0),
                initializations: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
            });
            let router = Router::new()
                .route("/token", post(exchange))
                .route("/mcp", post(respond))
                .with_state(Arc::clone(&remote));
            let stop = CancellationToken::new();
            let _stop_on_drop = stop.clone().drop_guard();
            let server_stop = stop.clone();
            let server_task = tokio::spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(server_stop.cancelled_owned())
                    .await
                    .expect("owned serving");
            });
            let auth_server = DiscoveredAuthorizationServer::reviewed(
                base.clone(),
                base.join("authorize").expect("authorization"),
                base.join("token").expect("token"),
            )
            .expect("reviewed issuer");
            let oauth_client = OAuthClient::with_routes(
                Duration::from_secs(2),
                [
                    auth_server.authorization_endpoint().clone(),
                    auth_server.token_endpoint().clone(),
                ]
                .map(|url| claw_mcp::HttpRoutePolicy::direct_loopback(url).expect("fixture route")),
            )
            .expect("OAuth client");
            let client = RegisteredClient::public("fixture-public-client").expect("public client");
            let redirect = base.join("callback").expect("redirect");
            let authorization = oauth_client
                .authorization_request(&auth_server, &client, &redirect, None, Some(&endpoint))
                .expect("authorization");
            oauth_client
                .exchange_code(
                    &binding,
                    &owned.store,
                    &auth_server,
                    &client,
                    AuthorizationCallback {
                        code: "owned-authorization-code",
                        state: &authorization.state,
                        request: &authorization,
                        redirect_uri: &redirect,
                    },
                    Some(&endpoint),
                )
                .await
                .expect("actual native OAuth login fixture");
            for (pointer, value) in [
                (
                    "/servers/0/oauth/credentialRef",
                    json!(binding.keyring_reference()),
                ),
                ("/servers/0/oauth/clientId", json!("other-client")),
                (
                    "/servers/0/oauth/issuer",
                    json!(base.join("other-issuer").expect("issuer").as_str()),
                ),
                (
                    "/servers/0/oauth/tokenEndpoint",
                    json!("http://remote.example/token"),
                ),
            ] {
                let mut invalid = source.clone();
                *invalid.pointer_mut(pointer).expect("field") = value;
                assert!(
                    parse_policy(&invalid.to_string(), |_| panic!(
                        "OAuth must not read static token sources"
                    ))
                    .is_err()
                );
            }
            let mut mixed = source.clone();
            mixed["servers"][0]["tokenEnv"] = json!("GTA_CLAW_MCP_OUTBOUND_FIXTURE");
            assert!(
                parse_policy(&mixed.to_string(), |_| panic!(
                    "mixed credential sources refused"
                ))
                .is_err()
            );
            let tools = NativeMcp::from_policy(
                &source.to_string(),
                |_| panic!("OAuth must use its native record"),
                Arc::clone(&state),
            )
            .await
            .expect("fresh OAuth MCP enrollment");
            assert_eq!(remote.initializations.load(Ordering::SeqCst), 0);
            assert_eq!(remote.token_requests.load(Ordering::SeqCst), 1);
            let authority = InvocationAuthority::new(
                InvocationSource::Gateway,
                "oauth-reviewer",
                None,
                InvocationAccess::Execute,
                0,
            )
            .expect("authority");
            let call = invocation(&json!({"text":"hello"}));
            let approved = tools
                .binding(&call, &authority)
                .expect("exact approval binding");
            let review = tools.entries["mcp_fixture_echo"]
                .server
                .review_identity
                .clone();
            assert!(
                approved
                    .resource()
                    .expect("resource")
                    .contains("automaticRefresh=false")
            );
            assert!(
                !approved
                    .resource()
                    .expect("resource")
                    .contains("private-daemon-oauth")
            );
            match mode {
                "deleted" => {
                    owned
                        .store
                        .delete(&binding)
                        .expect("delete owned OAuth record");
                }
                "pending" => {
                    owned
                        .store
                        .begin_update(&binding, None)
                        .expect("pending update fixture");
                }
                "scope-changed" => {
                    change_record(&binding, "scope", json!("changed-scope"));
                }
                "refresh-changed" => {
                    change_record(&binding, "refresh_token", json!("different-refresh-token"));
                }
                "expired" => {
                    change_record(&binding, "expires_at", json!({"seconds":0,"nanoseconds":0}));
                }
                "success" | "scope-during-discovery" => {}
                _ => unreachable!(),
            }
            if matches!(mode, "scope-changed" | "refresh-changed") {
                let entries =
                    parse_policy(&source.to_string(), |_| panic!("no static credentials"))
                        .expect("new generation can be explicitly reviewed");
                assert_ne!(
                    entries["mcp_fixture_echo"]
                        .binding(&call, &authority)
                        .expect("new publication"),
                    approved
                );
            }
            let result = tools
                .invoke(
                    call,
                    authority,
                    approved,
                    CancellationToken::new(),
                    Arc::clone(&audit),
                )
                .await;
            assert_eq!(result.is_ok(), mode == "success", "{result:?}");
            assert_eq!(
                remote.initializations.load(Ordering::SeqCst),
                usize::from(matches!(mode, "success" | "scope-during-discovery"))
            );
            assert_eq!(
                remote.calls.load(Ordering::SeqCst),
                usize::from(mode == "success")
            );
            assert_eq!(
                remote.token_requests.load(Ordering::SeqCst),
                1,
                "daemon never refreshes"
            );
            assert_eq!(
                state
                    .tool_publication_revoked(&review)
                    .await
                    .expect("review status"),
                mode != "success"
            );
            assert!(!format!("{result:?}").contains("private-daemon-oauth"));
            tools.shutdown().await;
            stop.cancel();
            server_task.await.expect("owned server joined");
            owned
                .store
                .delete(&binding)
                .expect("owned OAuth credential cleanup");
            assert!(
                owned
                    .store
                    .load(&binding)
                    .expect("cleanup verified")
                    .is_none()
            );
        }
        state.shutdown().await;
        drop(audit);
        drop(state);
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn native_mcp_keyring_rotation_and_deletion_revoke_before_connecting() {
        use axum::{Json, Router, extract::State, response::IntoResponse as _, routing::post};
        use claw_provider_sdk::secret::{
            CredentialKey, SecretStore as _, SecretString as StoredSecret,
            WindowsCredentialManagerStore,
        };
        use std::sync::atomic::AtomicUsize;
        struct OwnedCredential {
            store: WindowsCredentialManagerStore,
            key: CredentialKey,
        }
        impl Drop for OwnedCredential {
            fn drop(&mut self) {
                let _ = self.store.delete(&self.key);
            }
        }
        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        struct Remote {
            key: CredentialKey,
            descriptor: Value,
            initializations: AtomicUsize,
            calls: AtomicUsize,
        }
        async fn respond(
            State(remote): State<Arc<Remote>>,
            Json(request): Json<Value>,
        ) -> axum::response::Response {
            let Some(id) = request.get("id") else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            let result = match request["method"].as_str().expect("method") {
                "initialize" => {
                    remote.initializations.fetch_add(1, Ordering::SeqCst);
                    json!({"protocolVersion":"2025-03-26","serverInfo":{"name":"keyring-race-fixture","version":"1"},"capabilities":{"tools":{}}})
                }
                "tools/list" => {
                    WindowsCredentialManagerStore::new()
                        .expect("owned keyring")
                        .set(
                            &remote.key,
                            &StoredSecret::new("private-owned-keyring-replacement"),
                        )
                        .expect("rotate test credential while returning discovery");
                    json!({"tools":[remote.descriptor]})
                }
                "tools/call" => {
                    remote.calls.fetch_add(1, Ordering::SeqCst);
                    json!({"content":[],"isError":false})
                }
                other => panic!("unexpected keyring fixture method {other}"),
            };
            Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
        }
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let root = Root(std::env::temp_dir().join(format!("claw-mcp-keyring-{nonce}")));
        std::fs::create_dir(&root.0).expect("owned directory");
        let state = Arc::new(
            claw_state::DurableStateStore::open(root.0.join("state.redb")).expect("state"),
        );
        let audit = Arc::new(
            DurableSecurityAudit::open(
                &root.0.join("audit.jsonl"),
                Arc::new(super::super::http_api::DependencyReadiness::new(["audit"])),
            )
            .expect("audit"),
        );
        for (ordinal, (deleted, after_discovery, stdio)) in [
            (false, false, false),
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, false, true),
        ]
        .into_iter()
        .enumerate()
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("owned endpoint");
            let endpoint = url::Url::parse(&format!(
                "http://{}/mcp",
                listener.local_addr().expect("address")
            ))
            .expect("endpoint");
            let name = format!("keyring-{nonce}-{ordinal}");
            let bytes = b"MZ-inert-credential-rotation-fixture";
            let program = root.0.join(format!("never-started-{ordinal}.exe"));
            let directory = root.0.join(format!("working-{ordinal}"));
            let reference = if stdio {
                std::fs::write(&program, bytes).expect("owned inert executable");
                std::fs::create_dir(&directory).expect("owned working directory");
                StdioClientConfig::keyring_reference(&name, &digest(bytes), "API_TOKEN")
                    .expect("stdio binding")
            } else {
                claw_mcp::oauth::CredentialBinding::new(&name, &endpoint)
                    .expect("binding")
                    .keyring_reference()
            };
            let owned = OwnedCredential {
                store: WindowsCredentialManagerStore::new().expect("native credential store"),
                key: keyring_key(&reference).expect("dedicated key"),
            };
            assert!(
                owned
                    .store
                    .get(&owned.key)
                    .expect("unique credential lookup")
                    .is_none()
            );
            owned
                .store
                .set(
                    &owned.key,
                    &StoredSecret::new("private-owned-keyring-original"),
                )
                .expect("write owned test credential");
            assert!(
                owned
                    .store
                    .get(&owned.key)
                    .expect("immediate native readback")
                    .is_some_and(|secret| secret.expose() == "private-owned-keyring-original"),
                "native fixture write/readback mismatch at case {ordinal}, stdio={stdio}"
            );
            let expected_reference = reference.clone();
            let mut source = policy();
            source["servers"][0]["id"] = json!(name);
            if stdio {
                source["servers"][0]
                    .as_object_mut()
                    .expect("server")
                    .remove("url");
                source["servers"][0]["stdio"] = json!({"program":program,"sha256":digest(bytes),"workingDirectory":directory,
                    "allowHostPermissions":true,"environmentRefs":{"API_TOKEN":reference}});
            } else {
                source["servers"][0]["url"] = json!(endpoint.as_str());
                source["servers"][0]["tokenRef"] = json!(reference);
            }
            let tools = NativeMcp::from_policy(
                &source.to_string(),
                move |reference| {
                    assert_eq!(
                        reference, expected_reference,
                        "fixture credential reference changed"
                    );
                    let loaded = read_configured_credential(reference);
                    assert!(
                        loaded.is_ok(),
                        "native fixture case {ordinal}, stdio={stdio}: {}",
                        loaded.as_ref().err().map_or("no error", String::as_str)
                    );
                    loaded
                },
                Arc::clone(&state),
            )
            .await
            .expect("native lookup");
            let entry = &tools.entries["mcp_fixture_echo"];
            verify_keyring_credential(&entry.server)
                .await
                .expect("unchanged native credential");
            let review = entry.server.review_identity.clone();
            let authority = InvocationAuthority::new(
                InvocationSource::Gateway,
                "keyring-reviewer",
                None,
                InvocationAccess::Execute,
                0,
            )
            .expect("authority");
            let call = invocation(&json!({"text":"hello"}));
            let binding = tools
                .binding(&call, &authority)
                .expect("original approval binding");
            let remote = Arc::new(Remote {
                key: owned.key.clone(),
                descriptor: source["servers"][0]["tools"][0]["remote"].clone(),
                initializations: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
            });
            let stop = CancellationToken::new();
            let _cancel_on_drop = stop.clone().drop_guard();
            let mut listener = Some(listener);
            let server = after_discovery.then(|| {
                let listener = listener.take().expect("fixture listener");
                let router = Router::new()
                    .route("/mcp", post(respond))
                    .with_state(Arc::clone(&remote));
                let server_stop = stop.clone();
                tokio::spawn(async move {
                    axum::serve(listener, router)
                        .with_graceful_shutdown(server_stop.cancelled_owned())
                        .await
                        .expect("fixture serving");
                })
            });
            if deleted {
                assert!(
                    owned
                        .store
                        .delete(&owned.key)
                        .expect("remove owned credential")
                );
            } else if !after_discovery {
                owned
                    .store
                    .set(
                        &owned.key,
                        &StoredSecret::new("private-owned-keyring-replacement"),
                    )
                    .expect("rotate owned credential");
            }
            let result = tools
                .invoke(
                    call,
                    authority,
                    binding,
                    CancellationToken::new(),
                    Arc::clone(&audit),
                )
                .await;
            assert!(
                matches!(result, Err(PortError::OutcomeUnknown(_))),
                "native credential case {ordinal}, stdio={stdio}, after_discovery={after_discovery}, deleted={deleted}: {result:?}"
            );
            assert!(
                state
                    .tool_publication_revoked(&review)
                    .await
                    .expect("credential review revoked"),
                "missing durable revocation in native credential case {ordinal}, stdio={stdio}, after_discovery={after_discovery}, deleted={deleted}: {result:?}; initialized={}, calls={}",
                remote.initializations.load(Ordering::SeqCst),
                remote.calls.load(Ordering::SeqCst)
            );
            if let Some(listener) = listener {
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), listener.accept())
                        .await
                        .is_err(),
                    "changed native credentials cannot open the remote connection"
                );
            }
            assert_eq!(
                remote.initializations.load(Ordering::SeqCst),
                usize::from(after_discovery)
            );
            assert_eq!(
                remote.calls.load(Ordering::SeqCst),
                0,
                "rotation during discovery must stop the later tool call"
            );
            assert!(!format!("{result:?}").contains("private-owned-keyring"));
            tools.shutdown().await;
            stop.cancel();
            if let Some(server) = server {
                server.await.expect("keyring fixture joined");
            }
            assert!(owned.store.delete(&owned.key).is_ok());
            assert!(
                owned
                    .store
                    .get(&owned.key)
                    .expect("owned credential cleanup")
                    .is_none()
            );
        }
        state.shutdown().await;
        let audit = std::fs::read_to_string(root.0.join("audit.jsonl")).expect("audit");
        assert!(!audit.contains("private-owned-keyring"));
    }

    #[test]
    fn native_mcp_data_policy_rejects_ambiguous_parameters_and_nonabsolute_resources() {
        let prompt = json!({"name":"reviewed-prompt","description":"Reviewed prompt","arguments":[{"name":"subject","required":true}]});
        let mut source = policy();
        source["servers"][0]["tools"][0]["kind"] = json!("prompt");
        source["servers"][0]["tools"][0]["remote"] = prompt.clone();
        for invalid in [
            json!({"name":"reviewed-prompt","arguments":[{"name":"subject"},{"name":"subject"}]}),
            json!({"name":"reviewed-prompt","arguments":[{"name":"subject","description":"control\ntext"}]}),
            json!({"name":"reviewed-prompt","arguments":[{"name":"subject","required":"yes"}]}),
            json!({"name":"reviewed-prompt","arguments":vec![json!({"name":"subject"});17]}),
        ] {
            source["servers"][0]["tools"][0]["remote"] = invalid;
            assert!(parse_policy(&source.to_string(), |_| Err(String::new())).is_err());
        }
        source["servers"][0]["tools"][0]["kind"] = json!("resource");
        for uri in [
            "relative/resource",
            "gta://fixture/has space",
            "gta://fixture/line\nbreak",
            "",
        ] {
            source["servers"][0]["tools"][0]["remote"] =
                json!({"name":"reviewed-resource","uri":uri});
            assert!(parse_policy(&source.to_string(), |_| Err(String::new())).is_err());
        }
        source["servers"][0]["tools"][0]["kind"] = json!("automatic_prompt");
        source["servers"][0]["tools"][0]["remote"] = prompt;
        assert!(parse_policy(&source.to_string(), |_| Err(String::new())).is_err());
    }

    #[tokio::test]
    async fn native_mcp_resource_watch_has_bounded_notifications_and_owned_subscription_cleanup() {
        use axum::{Json, Router, extract::State, response::IntoResponse as _, routing::post};

        const URI: &str = "gta://watch/owned";
        struct Fixture {
            mode: &'static str,
            descriptor: Value,
            subscriptions: AtomicUsize,
            unsubscriptions: AtomicUsize,
            started: tokio::sync::Notify,
            release: CancellationToken,
        }
        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        async fn endpoint(
            State(fixture): State<Arc<Fixture>>,
            Json(request): Json<Value>,
        ) -> axum::response::Response {
            let Some(id) = request.get("id") else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            let result = match request["method"].as_str().expect("method") {
                "initialize" => {
                    json!({"protocolVersion":"2025-03-26","serverInfo":{"name":"watch-fixture","version":"1"},"capabilities":{"resources":{"subscribe":fixture.mode != "unsupported"}}})
                }
                "resources/list" => {
                    let mut descriptor = fixture.descriptor.clone();
                    if fixture.mode == "changed-catalog" {
                        descriptor["description"] = json!("changed description");
                    }
                    json!({"resources":[descriptor]})
                }
                "resources/subscribe" => {
                    fixture.subscriptions.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request["params"]["uri"], URI);
                    if fixture.mode == "cancel-subscribe" {
                        fixture.started.notify_one();
                        fixture.release.cancelled().await;
                    }
                    if fixture.mode == "subscribe-error" {
                        return Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"private-subscription-error"}})).into_response();
                    }
                    let mut events = Vec::new();
                    if fixture.mode == "revoked" {
                        events.push(json!({"jsonrpc":"2.0","method":"notifications/resources/list_changed"}));
                    }
                    if fixture.mode != "silent" {
                        let uri = if fixture.mode == "foreign" {
                            "gta://watch/foreign"
                        } else {
                            URI
                        };
                        for _ in 0..4 {
                            events.push(json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":uri,"_meta":{"private":"private-observation-metadata"}}}));
                        }
                    }
                    events.push(json!({"jsonrpc":"2.0","id":id,"result":{}}));
                    return axum::response::Sse::new(futures_util::stream::iter(
                        events.into_iter().map(|event| {
                            Ok::<_, std::convert::Infallible>(
                                axum::response::sse::Event::default().data(event.to_string()),
                            )
                        }),
                    ))
                    .into_response();
                }
                "resources/unsubscribe" => {
                    fixture.unsubscriptions.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request["params"]["uri"], URI);
                    if fixture.mode == "unsubscribe-error" {
                        return Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"private-unsubscription-error"}})).into_response();
                    }
                    json!({})
                }
                other => panic!("watch must not read resource content or call a tool: {other}"),
            };
            Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
        }
        let root = Root(std::env::temp_dir().join(format!(
                "claw-mcp-watch-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned watch fixture");
        let state = Arc::new(
            claw_state::DurableStateStore::open(root.0.join("state.redb")).expect("state"),
        );
        let audit = Arc::new(
            DurableSecurityAudit::open(
                &root.0.join("audit.jsonl"),
                Arc::new(super::super::http_api::DependencyReadiness::new(["audit"])),
            )
            .expect("audit"),
        );
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "watch-reviewer",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("authority");
        for mode in [
            "success",
            "silent",
            "foreign",
            "subscribe-error",
            "unsubscribe-error",
            "cancel-subscribe",
            "changed-catalog",
            "unsupported",
            "revoked",
        ] {
            let fixture = Arc::new(Fixture {
                mode,
                descriptor: json!({"name":"watched","uri":URI,"description":"Observe reviewed resource"}),
                subscriptions: AtomicUsize::new(0),
                unsubscriptions: AtomicUsize::new(0),
                started: tokio::sync::Notify::new(),
                release: CancellationToken::new(),
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("owned watch endpoint");
            let endpoint_url = format!("http://{}/mcp", listener.local_addr().expect("address"));
            let stop = CancellationToken::new();
            let _stop_on_drop = stop.clone().drop_guard();
            let _release_on_drop = fixture.release.clone().drop_guard();
            let router = Router::new()
                .route("/mcp", post(endpoint))
                .with_state(Arc::clone(&fixture));
            let server_stop = stop.clone();
            let server = tokio::spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(server_stop.cancelled_owned())
                    .await
                    .expect("fixture server");
            });
            let mut source = policy();
            source["servers"][0]["id"] = json!(format!("watch-{mode}"));
            source["servers"][0]["url"] = json!(endpoint_url);
            source["servers"][0]["tools"][0] = json!({"name":"mcp_fixture_echo","kind":"resource_watch","remote":fixture.descriptor});
            let tools = NativeMcp::from_policy(
                &source.to_string(),
                |_| panic!("no credentials"),
                Arc::clone(&state),
            )
            .await
            .expect("watch policy");
            let call = invocation(&json!({"durationMs":20,"maxUpdates":1}));
            let binding = tools
                .binding(&call, &authority)
                .expect("approved observation");
            let cancellation = CancellationToken::new();
            let pending = tools.invoke(
                call,
                authority.clone(),
                binding,
                cancellation.clone(),
                Arc::clone(&audit),
            );
            tokio::pin!(pending);
            if mode == "cancel-subscribe" {
                tokio::select! {
                    result = &mut pending => panic!("observation ended before cancellation: {result:?}"),
                    () = fixture.started.notified() => {}
                }
                cancellation.cancel();
                fixture.release.cancel();
            }
            let result = pending.await;
            assert_eq!(
                result.is_ok(),
                matches!(mode, "success" | "silent" | "foreign"),
                "{mode}: {result:?}"
            );
            if let Ok(result) = result {
                let value: Value = serde_json::from_str(&result.output).expect("metadata result");
                assert_eq!(value["operation"], "resource_watch");
                assert_eq!(
                    value["remoteResult"]["observedUpdates"],
                    usize::from(mode == "success")
                );
                assert_eq!(value["remoteResult"]["unsubscribed"], true);
                assert_eq!(value["remoteResult"]["automaticRead"], false);
                assert_eq!(value["remoteResult"]["continuousSubscription"], false);
                assert!(!result.output.contains("private-observation"));
            }
            assert_eq!(
                fixture.subscriptions.load(Ordering::SeqCst),
                usize::from(!matches!(mode, "unsupported" | "changed-catalog"))
            );
            if matches!(mode, "revoked" | "cancel-subscribe") {
                assert!(fixture.unsubscriptions.load(Ordering::SeqCst) <= 1);
            } else {
                assert_eq!(
                    fixture.unsubscriptions.load(Ordering::SeqCst),
                    usize::from(matches!(
                        mode,
                        "success" | "silent" | "foreign" | "unsubscribe-error"
                    ))
                );
            }
            if matches!(mode, "revoked" | "unsupported" | "changed-catalog") {
                assert!(
                    state
                        .tool_publication_revoked(
                            &tools.entries["mcp_fixture_echo"].server.review_identity
                        )
                        .await
                        .expect("persisted revocation")
                );
            }
            tools.shutdown().await;
            assert_eq!(tools.slots.available_permits(), 2);
            stop.cancel();
            server.await.expect("fixture joined");
        }
        state.shutdown().await;
        let audit_text = std::fs::read_to_string(root.0.join("audit.jsonl")).expect("audit");
        assert!(
            !audit_text.contains("private-observation")
                && !audit_text.contains("private-subscription-error")
        );
    }

    #[tokio::test]
    async fn native_mcp_resources_and_prompts_are_reviewed_bounded_untrusted_data() {
        use axum::{Json, Router, extract::State, response::IntoResponse as _, routing::post};
        use std::sync::atomic::AtomicUsize;
        struct Fixture {
            kind: OperationKind,
            descriptor: Value,
            mode: &'static str,
            calls: AtomicUsize,
        }
        async fn endpoint(
            State(fixture): State<Arc<Fixture>>,
            Json(request): Json<Value>,
        ) -> axum::response::Response {
            let Some(id) = request.get("id") else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            let result = match request["method"].as_str().expect("method") {
                "initialize" => {
                    json!({"protocolVersion":"2025-03-26","serverInfo":{"name":"owned-data-fixture","version":"1"},"capabilities":if fixture.mode == "unsupported" { json!({}) } else { json!({"resources":{},"prompts":{}}) }})
                }
                "resources/list" | "resources/templates/list" | "prompts/list" => {
                    assert_eq!(
                        request["method"],
                        if matches!(fixture.kind, OperationKind::Resource) {
                            "resources/list"
                        } else if matches!(fixture.kind, OperationKind::ResourceTemplate) {
                            "resources/templates/list"
                        } else {
                            "prompts/list"
                        }
                    );
                    let mut descriptor = fixture.descriptor.clone();
                    if fixture.mode == "changed" {
                        descriptor["description"] = json!("unreviewed change");
                    }
                    let descriptors = match fixture.mode {
                        "missing" => vec![],
                        "duplicate" => vec![descriptor.clone(), descriptor],
                        "catalog-too-large" => vec![descriptor; 129],
                        _ => vec![descriptor],
                    };
                    let key = if matches!(fixture.kind, OperationKind::Resource) {
                        "resources"
                    } else if matches!(fixture.kind, OperationKind::ResourceTemplate) {
                        "resourceTemplates"
                    } else {
                        "prompts"
                    };
                    let mut result = json!({key: descriptors});
                    if fixture.mode == "paginated" {
                        result["nextCursor"] = json!("unreviewed-next-page");
                    }
                    if fixture.mode == "notification" {
                        let method = if matches!(
                            fixture.kind,
                            OperationKind::Resource | OperationKind::ResourceTemplate
                        ) {
                            "notifications/resources/list_changed"
                        } else {
                            "notifications/prompts/list_changed"
                        };
                        return axum::response::Sse::new(futures_util::stream::iter(
                            [
                                json!({"jsonrpc":"2.0","method":method}),
                                json!({"jsonrpc":"2.0","id":id,"result":result}),
                            ]
                            .into_iter()
                            .map(|value| {
                                Ok::<_, std::convert::Infallible>(
                                    axum::response::sse::Event::default().data(value.to_string()),
                                )
                            }),
                        ))
                        .into_response();
                    }
                    result
                }
                "resources/read" => {
                    fixture.calls.fetch_add(1, Ordering::SeqCst);
                    let expected = if matches!(fixture.kind, OperationKind::ResourceTemplate) {
                        "gta://owned/resource/one%2Ftwo?query=private-template-query"
                    } else {
                        "gta://owned/resource"
                    };
                    assert_eq!(request["params"]["uri"], expected);
                    let uri = if fixture.mode == "wrong-target" {
                        "gta://unapproved/resource"
                    } else {
                        expected
                    };
                    json!({"contents":[{"uri":uri,"mimeType":"text/plain","text":if fixture.mode == "oversize" { "x".repeat(17 * 1024) } else { "untrusted resource content".to_owned() }}]})
                }
                "prompts/get" => {
                    fixture.calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request["params"]["name"], "reviewed-prompt");
                    assert_eq!(
                        request["params"]["arguments"],
                        json!({"subject":"fixture subject"})
                    );
                    let message = json!({"role":"user","content":{"type":"text","text":if fixture.mode == "oversize" { "x".repeat(17 * 1024) } else { "untrusted prompt content".to_owned() }}});
                    json!({"messages":vec![message; if fixture.mode == "wrong-target" { 33 } else { 1 }]})
                }
                other => panic!("unapproved method {other}"),
            };
            Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
        }
        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Root(std::env::temp_dir().join(format!(
                "claw-mcp-reviewed-data-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned state directory");
        let state = Arc::new(
            claw_state::DurableStateStore::open(root.0.join("state.redb")).expect("state"),
        );
        let audit = Arc::new(
            DurableSecurityAudit::open(
                &root.0.join("audit.jsonl"),
                Arc::new(super::super::http_api::DependencyReadiness::new(["audit"])),
            )
            .expect("audit"),
        );
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "resource-reader",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("authority");
        for kind in [
            OperationKind::Resource,
            OperationKind::Prompt,
            OperationKind::ResourceTemplate,
        ] {
            for mode in [
                "success",
                "changed",
                "missing",
                "duplicate",
                "notification",
                "wrong-target",
                "oversize",
                "unsupported",
                "paginated",
                "catalog-too-large",
            ] {
                let descriptor = if matches!(kind, OperationKind::Resource) {
                    json!({"uri":"gta://owned/resource","name":"reviewed-resource","description":"Reviewed resource","mimeType":"text/plain"})
                } else if matches!(kind, OperationKind::ResourceTemplate) {
                    json!({"uriTemplate":"gta://owned/resource/{id}{?query}","name":"reviewed-template","description":"Reviewed resource template","mimeType":"text/plain"})
                } else {
                    json!({"name":"reviewed-prompt","description":"Reviewed prompt","arguments":[{"name":"subject","description":"A subject","required":true}]})
                };
                let fixture = Arc::new(Fixture {
                    kind,
                    descriptor: descriptor.clone(),
                    mode,
                    calls: AtomicUsize::new(0),
                });
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("owned data endpoint");
                let address = listener.local_addr().expect("address");
                let router = Router::new()
                    .route("/mcp", post(endpoint))
                    .with_state(Arc::clone(&fixture));
                let stop = CancellationToken::new();
                let _cancel_on_drop = stop.clone().drop_guard();
                let server_stop = stop.clone();
                let server = tokio::spawn(async move {
                    axum::serve(listener, router)
                        .with_graceful_shutdown(server_stop.cancelled_owned())
                        .await
                        .expect("owned endpoint");
                });
                let mut source = policy();
                source["servers"][0]["id"] = json!(format!("{}-{mode}", kind.label()));
                source["servers"][0]["url"] = json!(format!("http://{address}/mcp"));
                source["servers"][0]["tools"][0]["kind"] = json!(kind);
                source["servers"][0]["tools"][0]["remote"] = descriptor;
                let tools = NativeMcp::from_policy(
                    &source.to_string(),
                    |_| Err(String::new()),
                    Arc::clone(&state),
                )
                .await
                .expect("reviewed data policy");
                let arguments = if matches!(kind, OperationKind::Resource) {
                    json!({})
                } else if matches!(kind, OperationKind::ResourceTemplate) {
                    json!({"id":"one/two","query":"private-template-query"})
                } else {
                    json!({"subject":"fixture subject"})
                };
                let call = invocation(&arguments);
                let binding = tools
                    .binding(&call, &authority)
                    .expect("approved data binding");
                for invalid in [
                    json!({"uri":"gta://other/resource"}),
                    json!({"subject":42}),
                    json!({"subject":"fixture subject","unreviewed":true}),
                ] {
                    assert!(tools.binding(&invocation(&invalid), &authority).is_err());
                }
                if matches!(
                    kind,
                    OperationKind::Prompt | OperationKind::ResourceTemplate
                ) {
                    assert!(tools.binding(&invocation(&json!({})), &authority).is_err());
                }
                assert!(
                    binding
                        .resource()
                        .expect("scope")
                        .contains(&format!("operation={}", kind.label()))
                );
                let result = tools
                    .invoke(
                        call,
                        authority.clone(),
                        binding,
                        CancellationToken::new(),
                        Arc::clone(&audit),
                    )
                    .await;
                assert_eq!(result.is_ok(), mode == "success", "{}:{mode}", kind.label());
                if let Ok(result) = result {
                    let value: Value =
                        serde_json::from_str(&result.output).expect("bounded output");
                    assert_eq!(value["untrusted"], true);
                    assert_eq!(value["operation"], kind.label());
                    assert_eq!(value["automaticReplay"], false);
                }
                assert_eq!(
                    fixture.calls.load(Ordering::SeqCst),
                    usize::from(matches!(mode, "success" | "wrong-target" | "oversize"))
                );
                if matches!(
                    mode,
                    "changed"
                        | "missing"
                        | "duplicate"
                        | "notification"
                        | "paginated"
                        | "catalog-too-large"
                        | "unsupported"
                ) {
                    let review = &tools.entries["mcp_fixture_echo"].server.review_identity;
                    assert!(
                        state
                            .tool_publication_revoked(review)
                            .await
                            .expect("catalog revocation persists")
                    );
                }
                tools.shutdown().await;
                stop.cancel();
                server.await.expect("owned endpoint joined");
            }
        }
        state.shutdown().await;
        let text = std::fs::read_to_string(root.0.join("audit.jsonl")).expect("audit");
        assert!(!text.contains("untrusted resource content"));
        assert!(!text.contains("untrusted prompt content"));
        assert!(!text.contains("fixture subject"));
        assert!(!text.contains("private-template-query"));
    }

    #[tokio::test]
    async fn native_mcp_https_requires_explicit_proxy_and_keeps_credentials_inside_tls() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Root(std::env::temp_dir().join(format!(
                "claw-mcp-https-proxy-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned directory");
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned proxy");
        let proxy_address = proxy.local_addr().expect("proxy address");
        let mut source = policy();
        source["servers"][0]["url"] = json!("https://approved-mcp.example/rpc");
        source["servers"][0]["httpProxy"] = json!(format!("http://{proxy_address}"));
        source["servers"][0]["tokenEnv"] = json!("GTA_CLAW_MCP_OUTBOUND_FIXTURE");
        for invalid in [
            "http://approved-mcp.example/rpc",
            "https://127.0.0.1/rpc",
            "https://10.0.0.1/rpc",
            "https://169.254.169.254/rpc",
            "https://service.internal/rpc",
            "https://localhost/rpc",
            "https://secret@approved-mcp.example/rpc",
            "https://approved-mcp.example/rpc?secret=one",
        ] {
            let mut changed = source.clone();
            changed["servers"][0]["url"] = json!(invalid);
            assert!(
                parse_policy(&changed.to_string(), |_| panic!(
                    "invalid route cannot load credentials"
                ))
                .is_err()
            );
        }
        for invalid in [
            "http://localhost:2080",
            "http://remote.example:2080",
            "http://secret@127.0.0.1:2080",
            "http://127.0.0.1:2080/path",
            "socks5://127.0.0.1:2080",
        ] {
            let mut changed = source.clone();
            changed["servers"][0]["httpProxy"] = json!(invalid);
            assert!(
                parse_policy(&changed.to_string(), |_| panic!(
                    "invalid proxy cannot load credentials"
                ))
                .is_err()
            );
        }
        let state = Arc::new(
            claw_state::DurableStateStore::open(root.0.join("state.redb")).expect("state"),
        );
        let audit = Arc::new(
            DurableSecurityAudit::open(
                &root.0.join("audit.jsonl"),
                Arc::new(super::super::http_api::DependencyReadiness::new(["audit"])),
            )
            .expect("audit"),
        );
        let tools = NativeMcp::from_policy(
            &source.to_string(),
            |_| Ok("private-mcp-fixture-token".to_owned()),
            Arc::clone(&state),
        )
        .await
        .expect("approved remote route");
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "reviewer",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("authority");
        let call = invocation(&json!({"text":"hello"}));
        let binding = tools.binding(&call, &authority).expect("binding");
        assert!(
            binding
                .resource()
                .expect("preview")
                .contains(&format!("proxy=http://{proxy_address}/"))
        );
        assert!(
            !binding
                .resource()
                .expect("preview")
                .contains("private-mcp-fixture-token")
        );
        let mut changed = source.clone();
        changed["servers"][0]["httpProxy"] = json!("http://127.0.0.1:32101");
        let changed = parse_policy(&changed.to_string(), |_| {
            Ok("private-mcp-fixture-token".to_owned())
        })
        .expect("different enrolled route");
        assert_ne!(
            binding,
            changed["mcp_fixture_echo"]
                .binding(&call, &authority)
                .expect("changed proxy binding")
        );
        let proxy_task = tokio::spawn(async move {
            let (mut connection, _) = tokio::time::timeout(Duration::from_secs(3), proxy.accept())
                .await
                .expect("approved proxy contacted")
                .expect("proxy connection");
            let mut request = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let mut buffer = [0; 512];
                    let count = connection.read(&mut buffer).await.expect("CONNECT bytes");
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() <= 8_192);
                }
            })
            .await
            .expect("CONNECT deadline");
            connection
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("owned proxy refuses tunnel");
            request
        });
        let result = tools
            .invoke(
                call,
                authority,
                binding,
                CancellationToken::new(),
                Arc::clone(&audit),
            )
            .await;
        assert!(matches!(result, Err(PortError::OutcomeUnknown(_))));
        let connect =
            String::from_utf8(proxy_task.await.expect("owned proxy joined")).expect("CONNECT text");
        assert!(connect.starts_with("CONNECT approved-mcp.example:443 HTTP/1.1\r\n"));
        assert!(!connect.to_ascii_lowercase().contains("authorization"));
        assert!(!connect.contains("private-mcp-fixture-token"));
        assert!(!format!("{result:?}").contains("private-mcp-fixture-token"));
        tools.shutdown().await;
        state.shutdown().await;
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn native_mcp_stdio_policy_requires_fixed_launch_and_excludes_writable_programs() {
        struct Root(PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Root(std::env::temp_dir().join(format!(
                "claw-mcp-stdio-policy-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        let directory = root.0.join("working");
        std::fs::create_dir_all(&directory).expect("owned directory");
        let program = root.0.join("fixture.exe");
        let bytes = b"MZ-inert-reviewed-program";
        std::fs::write(&program, bytes).expect("inert program fixture");
        let mut source = policy();
        source["servers"][0]
            .as_object_mut()
            .expect("server")
            .remove("url");
        source["servers"][0]["stdio"] = json!({"program":program,"sha256":digest(bytes),"workingDirectory":directory,
            "allowHostPermissions":true,"arguments":["--reviewed"],"environment":{"EXPLICIT_VALUE":"private-config-value"}});
        for (pointer, invalid_value) in [
            ("/servers/0/stdio/allowHostPermissions", json!(false)),
            ("/servers/0/stdio/program", json!("relative.exe")),
            ("/servers/0/stdio/workingDirectory", json!("relative")),
            ("/servers/0/stdio/sha256", json!("0".repeat(64))),
            ("/servers/0/stdio/sha256", json!("A".repeat(64))),
            ("/servers/0/stdio/arguments", json!(["invalid\nargument"])),
            ("/servers/0/stdio/arguments", json!(["x".repeat(2049)])),
            (
                "/servers/0/stdio/environment",
                json!({"PATH":"one","path":"two"}),
            ),
            (
                "/servers/0/stdio/environment",
                json!({"INVALID=KEY":"value"}),
            ),
            (
                "/servers/0/stdio/environment",
                json!({"VALUE":"private\nvalue"}),
            ),
        ] {
            let mut invalid = source.clone();
            *invalid.pointer_mut(pointer).expect("field") = invalid_value;
            let error = parse_policy(&invalid.to_string(), |_| {
                panic!("stdio cannot read bearer credentials")
            })
            .err()
            .expect("launch policy rejected");
            assert!(!error.contains("private-config-value"));
        }
        let mut both = source.clone();
        both["servers"][0]["url"] = json!("http://127.0.0.1/mcp");
        assert!(
            parse_policy(&both.to_string(), |_| panic!(
                "mixed transports cannot read a token"
            ))
            .is_err()
        );
        let mut secret = source.clone();
        secret["servers"][0]["tokenEnv"] = json!("GTA_CLAW_MCP_OUTBOUND_FIXTURE");
        assert!(
            parse_policy(&secret.to_string(), |_| panic!(
                "stdio bearer reference refused"
            ))
            .is_err()
        );
        let mut inside = source.clone();
        let writable_program = directory.join("fixture.exe");
        std::fs::write(&writable_program, bytes).expect("owned writable program");
        inside["servers"][0]["stdio"]["program"] = json!(writable_program);
        assert!(parse_policy(&inside.to_string(), |_| Err(String::new())).is_err());
        let state = Arc::new(
            claw_state::DurableStateStore::open(root.0.join("state.redb")).expect("state"),
        );
        let tools = NativeMcp::from_policy(
            &source.to_string(),
            |_| Err(String::new()),
            Arc::clone(&state),
        )
        .await
        .expect("reviewed policy");
        assert!(tools.reject_writable_programs(&root.0).is_err());
        assert!(tools.reject_writable_programs(&directory).is_ok());
        assert!(
            std::fs::rename(&directory, root.0.join("replaced")).is_err(),
            "reviewed working directory stays pinned"
        );
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "reviewer",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("authority");
        let original_binding = tools
            .binding(&invocation(&json!({"text":"hello"})), &authority)
            .expect("original binding");
        assert!(
            !original_binding
                .resource()
                .expect("resource")
                .contains("private-config-value")
        );
        for (pointer, value) in [
            ("/servers/0/stdio/arguments", json!(["--different"])),
            (
                "/servers/0/stdio/environment",
                json!({"EXPLICIT_VALUE":"changed-value"}),
            ),
        ] {
            let mut changed = source.clone();
            *changed.pointer_mut(pointer).expect("changed field") = value;
            let entries = parse_policy(&changed.to_string(), |_| Err(String::new()))
                .expect("new reviewed configuration");
            assert_ne!(
                original_binding,
                entries["mcp_fixture_echo"]
                    .binding(&invocation(&json!({"text":"hello"})), &authority)
                    .expect("new binding")
            );
        }
        let reference =
            StdioClientConfig::keyring_reference("fixture", &digest(bytes), "API_TOKEN")
                .expect("stdio reference");
        let mut protected = source.clone();
        protected["servers"][0]["stdio"]["environmentRefs"] = json!({"API_TOKEN":reference});
        let mut lookups = 0;
        let entries = parse_policy(&protected.to_string(), |requested| {
            lookups += 1;
            assert_eq!(requested, reference);
            Ok("private-stdio-token-first".to_owned())
        })
        .expect("protected environment enrollment");
        assert_eq!(lookups, 1);
        let protected_binding = entries["mcp_fixture_echo"]
            .binding(&invocation(&json!({"text":"hello"})), &authority)
            .expect("protected binding");
        assert!(
            protected_binding
                .resource()
                .expect("resource")
                .contains("API_TOKEN")
        );
        assert!(
            !protected_binding
                .resource()
                .expect("resource")
                .contains("private-stdio-token")
                && !protected_binding
                    .resource()
                    .expect("resource")
                    .contains("keyring://")
        );
        let rotated = parse_policy(&protected.to_string(), |_| {
            Ok("private-stdio-token-second".to_owned())
        })
        .expect("rotated enrollment");
        assert_ne!(
            protected_binding,
            rotated["mcp_fixture_echo"]
                .binding(&invocation(&json!({"text":"hello"})), &authority)
                .expect("new binding")
        );
        for replacement in [
            json!({"API_TOKEN":"keyring://gta-claw.mcp-outbound/foreign"}),
            json!({"OTHER_TOKEN":reference}),
            json!({"API_TOKEN":reference,"api_token":reference}),
        ] {
            let mut invalid = protected.clone();
            invalid["servers"][0]["stdio"]["environmentRefs"] = replacement;
            assert!(
                parse_policy(&invalid.to_string(), |_| panic!(
                    "invalid reference must not access a credential"
                ))
                .is_err()
            );
        }
        let mut collision = protected.clone();
        collision["servers"][0]["stdio"]["environment"] = json!({"api_token":"plain-collision"});
        assert!(
            parse_policy(&collision.to_string(), |_| panic!(
                "mixed environment collision"
            ))
            .is_err()
        );
        for secret in [
            "short".to_owned(),
            "x".repeat(2049),
            "private-token\ncontrol".to_owned(),
        ] {
            assert!(parse_policy(&protected.to_string(), |_| Ok(secret.clone())).is_err());
        }
        let mut budget = protected.clone();
        budget["servers"][0]["stdio"]["environment"] = json!({"PLAIN":"x".repeat(2048)});
        budget["servers"][0]["stdio"]["environmentRefs"] = Value::Object(
            (0..3)
                .map(|index| {
                    let name = format!("SECRET_{index}");
                    let reference =
                        StdioClientConfig::keyring_reference("fixture", &digest(bytes), &name)
                            .expect("secret reference");
                    (name, json!(reference))
                })
                .collect(),
        );
        assert!(parse_policy(&budget.to_string(), |_| Ok("x".repeat(2048))).is_ok());
        budget["servers"][0]["stdio"]["environmentRefs"]["EXTRA"] = json!(
            StdioClientConfig::keyring_reference("fixture", &digest(bytes), "EXTRA")
                .expect("extra reference")
        );
        assert!(parse_policy(&budget.to_string(), |_| Ok("x".repeat(2048))).is_err());
        budget["servers"][0]["stdio"]["environmentRefs"] = Value::Object(
            (0..16)
                .map(|index| {
                    let name = format!("SECRET_{index}");
                    let reference =
                        StdioClientConfig::keyring_reference("fixture", &digest(bytes), &name)
                            .expect("secret reference");
                    (name, json!(reference))
                })
                .collect(),
        );
        assert!(
            parse_policy(&budget.to_string(), |_| panic!(
                "combined environment count is rejected before credential reads"
            ))
            .is_err()
        );
        drop(entries);
        drop(rotated);
        tools.shutdown().await;
        drop(tools);
        state.shutdown().await;
        drop(state);
        std::fs::rename(&directory, root.0.join("released")).expect("directory pin released");
    }

    #[tokio::test]
    async fn native_mcp_invokes_only_exact_reviewed_descriptors_once_and_audits_outcomes() {
        use axum::{Json, Router, extract::State, response::IntoResponse as _, routing::post};
        use std::sync::atomic::AtomicUsize;
        struct Fixture {
            descriptor: Value,
            mode: &'static str,
            calls: AtomicUsize,
            started: tokio::sync::Notify,
            release: CancellationToken,
            state: Arc<claw_state::DurableStateStore>,
        }
        async fn respond(
            State(fixture): State<Arc<Fixture>>,
            Json(request): Json<Value>,
        ) -> axum::response::Response {
            let Some(id) = request.get("id") else {
                return axum::http::StatusCode::ACCEPTED.into_response();
            };
            let result = match request["method"].as_str().expect("MCP method") {
                "initialize" => {
                    json!({"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"owned-mcp-fixture","version":"1"}})
                }
                "tools/list" => {
                    let mut descriptor = fixture.descriptor.clone();
                    if matches!(fixture.mode, "changed" | "revocation-storage-failed") {
                        descriptor["description"] = json!("unreviewed description");
                    }
                    if fixture.mode == "revocation-storage-failed" {
                        fixture.state.shutdown().await;
                    }
                    let tools = match fixture.mode {
                        "missing" => vec![],
                        "duplicate" => vec![descriptor.clone(), descriptor],
                        _ => vec![descriptor],
                    };
                    if fixture.mode == "notification" {
                        let events = [
                            json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"}),
                            json!({"jsonrpc":"2.0","id":id,"result":{"tools":tools}}),
                        ];
                        return axum::response::Sse::new(futures_util::stream::iter(
                            events.into_iter().map(|event| {
                                Ok::<_, std::convert::Infallible>(
                                    axum::response::sse::Event::default().data(event.to_string()),
                                )
                            }),
                        ))
                        .into_response();
                    }
                    json!({"tools":tools})
                }
                "tools/call" => {
                    fixture.calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request["params"]["name"], "echo");
                    assert_eq!(request["params"]["arguments"], json!({"text":"hello"}));
                    if matches!(fixture.mode, "cancel" | "drop" | "shutdown") {
                        fixture.started.notify_one();
                        fixture.release.cancelled().await;
                    }
                    if fixture.mode == "error" {
                        return Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"private-remote-error"}})).into_response();
                    }
                    json!({"content":[{"type":"text","text":if fixture.mode == "oversize" { "x".repeat(17 * 1024) } else { "reply".to_owned() }}],"isError":fixture.mode == "tool-error"})
                }
                other => panic!("unexpected fixture method {other}"),
            };
            Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
        }
        struct Root(std::path::PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Root(std::env::temp_dir().join(format!(
                "claw-mcp-native-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned audit root");
        let audit = Arc::new(
            DurableSecurityAudit::open(
                &root.0.join("audit.jsonl"),
                Arc::new(super::super::http_api::DependencyReadiness::new(["audit"])),
            )
            .expect("audit"),
        );
        for mode in [
            "success",
            "changed",
            "missing",
            "duplicate",
            "notification",
            "error",
            "tool-error",
            "oversize",
            "cancel",
            "drop",
            "shutdown",
            "revocation-storage-failed",
        ] {
            let mut source = policy();
            source["servers"][0]["id"] = json!(mode);
            let state_path = root.0.join(format!("{mode}.redb"));
            let state = Arc::new(
                claw_state::DurableStateStore::open(&state_path).expect("revocation database"),
            );
            let fixture = Arc::new(Fixture {
                descriptor: source["servers"][0]["tools"][0]["remote"].clone(),
                mode,
                calls: AtomicUsize::new(0),
                started: tokio::sync::Notify::new(),
                release: CancellationToken::new(),
                state: Arc::clone(&state),
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("owned endpoint");
            source["servers"][0]["url"] = json!(format!(
                "http://{}/mcp",
                listener.local_addr().expect("address")
            ));
            let router = Router::new()
                .route("/mcp", post(respond))
                .with_state(Arc::clone(&fixture));
            let stopped = CancellationToken::new();
            let _cancel_on_drop = stopped.clone().drop_guard();
            let server_stop = stopped.clone();
            let server = tokio::spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(server_stop.cancelled_owned())
                    .await
                    .expect("fixture server");
            });
            let tools = NativeMcp::from_policy(
                &source.to_string(),
                |_| Err(String::new()),
                Arc::clone(&state),
            )
            .await
            .expect("policy");
            let authority = InvocationAuthority::new(
                InvocationSource::Gateway,
                "fixture-owner",
                None,
                InvocationAccess::Execute,
                0,
            )
            .expect("authority");
            let call = invocation(&json!({"text":"hello"}));
            let binding = tools.binding(&call, &authority).expect("bound publication");
            assert_ne!(
                binding,
                tools
                    .binding(&invocation(&json!({"text":"changed"})), &authority)
                    .expect("other args")
            );
            assert!(
                tools
                    .binding(&invocation(&json!({"text":42})), &authority)
                    .is_err()
            );
            let cancellation = CancellationToken::new();
            let mut pending = Box::pin(tools.invoke(
                call,
                authority,
                binding,
                cancellation.clone(),
                Arc::clone(&audit),
            ));
            if matches!(mode, "cancel" | "drop" | "shutdown") {
                tokio::time::timeout(Duration::from_secs(3), async {
                    tokio::select! {
                        result = &mut pending => panic!("invocation finished before its cancellation probe: {result:?}"),
                        () = fixture.started.notified() => {},
                    }
                }).await.expect("remote call started");
                if mode == "drop" {
                    drop(pending);
                    assert!(cancellation.is_cancelled());
                    tokio::time::timeout(Duration::from_secs(8), tools.shutdown())
                        .await
                        .expect("dropped caller's owned task drained");
                    fixture.release.cancel();
                    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
                    assert_eq!(tools.slots.available_permits(), 2);
                    state.shutdown().await;
                    stopped.cancel();
                    server.await.expect("fixture joined after caller drop");
                    continue;
                }
                if mode == "shutdown" {
                    tools.shutdown.cancel();
                } else {
                    cancellation.cancel();
                }
            }
            let result = tokio::time::timeout(Duration::from_secs(8), pending)
                .await
                .expect("bounded owned MCP execution");
            fixture.release.cancel();
            assert_eq!(
                result.is_ok(),
                matches!(mode, "success" | "tool-error"),
                "{mode}"
            );
            if let Ok(result) = &result {
                assert_eq!(
                    result.status,
                    if mode == "tool-error" {
                        ToolStatus::Failed
                    } else {
                        ToolStatus::Ok
                    }
                );
                assert_eq!(
                    serde_json::from_str::<Value>(&result.output).expect("output")["untrusted"],
                    true
                );
            }
            assert!(!format!("{result:?}").contains("private-remote-error"));
            assert_eq!(
                fixture.calls.load(Ordering::SeqCst),
                usize::from(!matches!(
                    mode,
                    "changed"
                        | "missing"
                        | "duplicate"
                        | "notification"
                        | "revocation-storage-failed"
                ))
            );
            if mode == "revocation-storage-failed" {
                assert!(
                    tools.shutdown.is_cancelled(),
                    "an unconfirmed revocation disables all outbound MCP tools"
                );
                let mut catalog = Vec::new();
                tools.extend_catalog(&mut catalog);
                assert!(catalog.is_empty());
                tools.shutdown().await;
                assert_eq!(tools.slots.available_permits(), 2);
                stopped.cancel();
                server.await.expect("failed-storage fixture joined");
                continue;
            }
            tools.shutdown().await;
            assert_eq!(tools.slots.available_permits(), 2);
            let revoked = matches!(mode, "changed" | "missing" | "duplicate" | "notification");
            let review_identity = tools.entries["mcp_fixture_echo"]
                .server
                .review_identity
                .clone();
            assert_eq!(
                state
                    .tool_publication_revoked(&review_identity)
                    .await
                    .expect("revocation readback"),
                revoked
            );
            state.shutdown().await;
            drop(tools);
            stopped.cancel();
            server.await.expect("fixture joined before database reopen");
            drop(fixture);
            drop(state);
            let state = Arc::new(
                claw_state::DurableStateStore::open(&state_path).expect("reopened database"),
            );
            let restored = NativeMcp::from_policy(
                &source.to_string(),
                |_| Err(String::new()),
                Arc::clone(&state),
            )
            .await
            .expect("restored policy");
            let mut catalog = Vec::new();
            restored.extend_catalog(&mut catalog);
            assert_eq!(
                catalog.is_empty(),
                revoked,
                "revoked reviews must remain unpublished after restart"
            );
            if revoked {
                let owner = InvocationAuthority::new(
                    InvocationSource::Gateway,
                    "fixture-owner",
                    None,
                    InvocationAccess::Execute,
                    0,
                )
                .expect("authority");
                assert!(
                    restored
                        .binding(&invocation(&json!({"text":"hello"})), &owner)
                        .is_err()
                );
                source["servers"][0]["reviewRevision"] = json!(2);
                let reenrolled = NativeMcp::from_policy(
                    &source.to_string(),
                    |_| Err(String::new()),
                    Arc::clone(&state),
                )
                .await
                .expect("explicitly new review");
                assert!(
                    reenrolled
                        .binding(&invocation(&json!({"text":"hello"})), &owner)
                        .is_ok()
                );
                assert!(
                    state
                        .tool_publication_revoked(&review_identity)
                        .await
                        .expect("old review remains revoked")
                );
                reenrolled.shutdown().await;
            }
            restored.shutdown().await;
            state.shutdown().await;
        }
        let text = std::fs::read_to_string(root.0.join("audit.jsonl")).expect("audit persisted");
        assert!(!text.contains("private-remote-error"));
        let records = text
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("audit record"))
            .filter(|record| record["action"] == "internal_tool")
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 24);
        assert_eq!(
            records
                .iter()
                .filter(|record| record["phase"] == "authorized")
                .count(),
            12
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record["phase"] == "completed")
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record["phase"] == "failed")
                .count(),
            11
        );
    }
}

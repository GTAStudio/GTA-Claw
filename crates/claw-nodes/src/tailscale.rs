//! Tailscale LocalAPI discovery, identity, exposure, and authorization.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use url::{Position, Url};

const MAX_LOCAL_API_BODY: usize = 1024 * 1024;
const LOCAL_API_HOST: &str = "local-tailscaled.sock";
const MAX_EXPOSURE_WRITE_ATTEMPTS: usize = 3;

/// LocalAPI HTTP method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalApiMethod {
    /// Read-only request.
    Get,
    /// State-changing request.
    Post,
    /// State-removal request.
    Delete,
}

impl LocalApiMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

/// Bounded LocalAPI request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalApiRequest {
    /// HTTP method.
    pub method: LocalApiMethod,
    /// Absolute LocalAPI path and query.
    pub path_and_query: String,
    /// JSON body, if any.
    pub body: Vec<u8>,
    /// Exact Serve-config revision required for a state-changing request.
    pub if_match: Option<String>,
}

/// Bounded LocalAPI response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalApiResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body.
    pub body: Vec<u8>,
    /// Serve-config revision supplied by LocalAPI.
    pub etag: Option<String>,
}

/// Injectable transport for Tailscale's privileged local API.
#[async_trait]
pub trait LocalApiTransport: Send + Sync {
    /// Performs one bounded request.
    async fn request(&self, request: LocalApiRequest) -> Result<LocalApiResponse, TailscaleError>;
}

/// Loopback HTTP LocalAPI transport, useful for explicitly configured local proxies.
pub struct LoopbackLocalApiTransport {
    base_url: Url,
    endpoint: SocketAddr,
    timeout: Duration,
}

impl LoopbackLocalApiTransport {
    /// Creates a transport that rejects non-loopback destinations.
    pub fn new(base_url: Url, timeout: Duration) -> Result<Self, TailscaleError> {
        if base_url.scheme() != "http"
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || !is_loopback_host(&base_url)
        {
            return Err(TailscaleError::UnsafeEndpoint);
        }
        let port = base_url
            .port_or_known_default()
            .ok_or(TailscaleError::UnsafeEndpoint)?;
        let endpoint = match base_url.host().ok_or(TailscaleError::UnsafeEndpoint)? {
            url::Host::Domain(_) => SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
            url::Host::Ipv4(address) => SocketAddr::new(address.into(), port),
            url::Host::Ipv6(address) => SocketAddr::new(address.into(), port),
        };
        Ok(Self {
            base_url,
            endpoint,
            timeout,
        })
    }
}

#[async_trait]
impl LocalApiTransport for LoopbackLocalApiTransport {
    async fn request(&self, request: LocalApiRequest) -> Result<LocalApiResponse, TailscaleError> {
        validate_local_api_request(&request)?;
        let url = self
            .base_url
            .join(&request.path_and_query)
            .map_err(TailscaleError::Url)?;
        let path_and_query = url[Position::BeforePath..].to_owned();
        let stream =
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(self.endpoint))
                .await
                .map_err(|_| TailscaleError::Timeout)?
                .map_err(TailscaleError::Io)?;
        exchange_http(
            stream,
            LocalApiRequest {
                path_and_query,
                ..request
            },
            self.timeout,
        )
        .await
    }
}

/// Native Unix-domain-socket LocalAPI transport.
#[cfg(unix)]
pub struct UnixLocalApiTransport {
    socket_path: PathBuf,
    timeout: Duration,
}

#[cfg(unix)]
impl UnixLocalApiTransport {
    /// Creates a Unix socket transport.
    #[must_use]
    pub fn new(socket_path: PathBuf, timeout: Duration) -> Self {
        Self {
            socket_path,
            timeout,
        }
    }
}

#[cfg(unix)]
#[async_trait]
impl LocalApiTransport for UnixLocalApiTransport {
    async fn request(&self, request: LocalApiRequest) -> Result<LocalApiResponse, TailscaleError> {
        validate_local_api_request(&request)?;
        let stream = tokio::time::timeout(
            self.timeout,
            tokio::net::UnixStream::connect(&self.socket_path),
        )
        .await
        .map_err(|_| TailscaleError::Timeout)?
        .map_err(TailscaleError::Io)?;
        exchange_http(stream, request, self.timeout).await
    }
}

/// Native Windows named-pipe LocalAPI transport.
#[cfg(windows)]
pub struct WindowsLocalApiTransport {
    pipe_path: PathBuf,
    timeout: Duration,
}

#[cfg(windows)]
impl WindowsLocalApiTransport {
    /// Creates a named-pipe transport.
    #[must_use]
    pub fn new(pipe_path: PathBuf, timeout: Duration) -> Self {
        Self { pipe_path, timeout }
    }
}

#[cfg(windows)]
#[async_trait]
impl LocalApiTransport for WindowsLocalApiTransport {
    async fn request(&self, request: LocalApiRequest) -> Result<LocalApiResponse, TailscaleError> {
        validate_local_api_request(&request)?;
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&self.pipe_path)
            .map_err(TailscaleError::Io)?;
        exchange_http(stream, request, self.timeout).await
    }
}

/// Tailnet node returned by LocalAPI status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TailscaleNode {
    /// Stable Tailscale node identifier.
    #[serde(default, rename = "ID")]
    pub id: String,
    /// Machine hostname.
    #[serde(default)]
    pub host_name: String,
    /// MagicDNS name.
    #[serde(default, rename = "DNSName")]
    pub dns_name: String,
    /// Tailnet IP addresses.
    #[serde(default, rename = "TailscaleIPs")]
    pub tailscale_ips: Vec<IpAddr>,
    /// Whether the peer is currently online.
    #[serde(default)]
    pub online: bool,
    /// Owning tailnet user identifier.
    #[serde(default, rename = "UserID")]
    pub user_id: u64,
}

/// Tailnet user profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TailnetUser {
    /// Stable user identifier.
    #[serde(default, rename = "ID")]
    pub id: u64,
    /// Login name.
    #[serde(default)]
    pub login_name: String,
    /// Display name.
    #[serde(default)]
    pub display_name: String,
}

/// Local tailnet status and peer inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct TailnetStatus {
    /// Tailscale daemon version.
    #[serde(default)]
    pub version: String,
    /// Backend state such as `Running`.
    #[serde(default)]
    pub backend_state: String,
    /// This machine's tailnet addresses.
    #[serde(default, rename = "TailscaleIPs")]
    pub tailscale_ips: Vec<IpAddr>,
    /// This machine's node record.
    #[serde(rename = "Self")]
    pub self_node: TailscaleNode,
    /// Peer records keyed by node key.
    #[serde(default)]
    pub peer: BTreeMap<String, TailscaleNode>,
    /// Tailnet users keyed by decimal identifier.
    #[serde(default)]
    pub user: BTreeMap<String, TailnetUser>,
}

impl TailnetStatus {
    /// Returns the local machine followed by peers in stable key order.
    #[must_use]
    pub fn nodes(&self) -> Vec<&TailscaleNode> {
        std::iter::once(&self.self_node)
            .chain(self.peer.values())
            .collect()
    }

    /// Returns the local tailnet identity.
    pub fn identity(&self) -> Result<TailnetIdentity, TailscaleError> {
        if self.self_node.id.is_empty()
            || self.self_node.dns_name.is_empty()
            || self.self_node.tailscale_ips.is_empty()
            || self.self_node.user_id == 0
        {
            return Err(TailscaleError::IncompleteIdentity);
        }
        let user = self
            .user
            .get(&self.self_node.user_id.to_string())
            .ok_or(TailscaleError::IncompleteIdentity)?;
        Ok(TailnetIdentity {
            node_id: self.self_node.id.clone(),
            dns_name: self.self_node.dns_name.trim_end_matches('.').to_owned(),
            addresses: self.self_node.tailscale_ips.clone(),
            user_id: user.id,
            login_name: user.login_name.clone(),
        })
    }
}

/// Local machine's tailnet identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TailnetIdentity {
    /// Stable node identifier.
    pub node_id: String,
    /// MagicDNS name without a trailing dot.
    pub dns_name: String,
    /// Tailnet addresses.
    pub addresses: Vec<IpAddr>,
    /// Stable user identifier.
    pub user_id: u64,
    /// User login name.
    pub login_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct WhoIsResponse {
    node: WhoIsNode,
    user_profile: TailnetUser,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
struct WhoIsNode {
    #[serde(default, rename = "ID")]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    user: u64,
}

/// Authenticated peer identity returned by LocalAPI whois.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WhoIsIdentity {
    /// Stable node identifier.
    pub node_id: String,
    /// MagicDNS node name.
    pub node_name: String,
    /// Stable user identifier.
    pub user_id: u64,
    /// User login name.
    pub login_name: String,
}

/// Privileged Tailscale operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TailscalePermission {
    /// Read the peer inventory.
    Discover,
    /// Resolve a network peer to a tailnet principal.
    IdentifyPeer,
    /// Configure tailnet-only Serve exposure.
    ExposeServe,
    /// Configure internet-facing Funnel exposure.
    ExposeFunnel,
    /// Remove exposure configuration.
    RemoveExposure,
}

/// One allow-only ACL rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TailscaleAclRule {
    /// Optional exact node identifier.
    pub node_id: Option<String>,
    /// Optional exact, case-insensitive user login.
    pub login_name: Option<String>,
    /// Allowed operations.
    pub permissions: BTreeSet<TailscalePermission>,
}

/// Default-deny ACL for LocalAPI operations performed on behalf of a peer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TailscaleAcl {
    rules: Vec<TailscaleAclRule>,
}

impl TailscaleAcl {
    /// Creates an ACL from allow-only rules.
    #[must_use]
    pub fn new(rules: Vec<TailscaleAclRule>) -> Self {
        Self { rules }
    }

    /// Fails closed unless one complete rule matches the identity and operation.
    pub fn authorize(
        &self,
        identity: &WhoIsIdentity,
        permission: TailscalePermission,
    ) -> Result<(), TailscaleError> {
        let allowed = self.rules.iter().any(|rule| {
            rule.permissions.contains(&permission)
                && rule
                    .node_id
                    .as_deref()
                    .is_none_or(|node_id| node_id == identity.node_id)
                && rule
                    .login_name
                    .as_deref()
                    .is_none_or(|login| login.eq_ignore_ascii_case(identity.login_name.as_str()))
                && (rule.node_id.is_some() || rule.login_name.is_some())
        });
        if allowed {
            Ok(())
        } else {
            Err(TailscaleError::PermissionDenied)
        }
    }
}

/// Tailnet exposure mode.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExposureMode {
    /// Tailnet-only HTTPS through Tailscale Serve.
    Serve,
    /// Public HTTPS through Tailscale Funnel.
    Funnel,
}

/// Validated exposure request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureRequest {
    /// Public HTTPS port.
    pub public_port: u16,
    /// Local loopback target port.
    pub local_port: u16,
    /// Tailnet-only or public mode.
    pub mode: ExposureMode,
}

/// High-level Tailscale LocalAPI client.
pub struct TailscaleClient<T> {
    transport: T,
    acl: TailscaleAcl,
    managed_exposures: tokio::sync::Mutex<BTreeSet<ManagedExposure>>,
}

impl<T: LocalApiTransport> TailscaleClient<T> {
    /// Creates a LocalAPI client with a default-deny ACL.
    #[must_use]
    pub fn new(transport: T, acl: TailscaleAcl) -> Self {
        Self {
            transport,
            acl,
            managed_exposures: tokio::sync::Mutex::new(BTreeSet::new()),
        }
    }

    /// Reads local status and validates its structural identity fields.
    pub async fn status(&self) -> Result<TailnetStatus, TailscaleError> {
        let response = self
            .transport
            .request(LocalApiRequest {
                method: LocalApiMethod::Get,
                path_and_query: "/localapi/v0/status".to_owned(),
                body: Vec::new(),
                if_match: None,
            })
            .await?;
        decode_json_response(response)
    }

    /// Returns a stable snapshot of this node and all known peers.
    pub async fn discover_nodes(
        &self,
        actor: &WhoIsIdentity,
    ) -> Result<Vec<TailscaleNode>, TailscaleError> {
        self.acl.authorize(actor, TailscalePermission::Discover)?;
        let status = self.status().await?;
        Ok(status.nodes().into_iter().cloned().collect())
    }

    /// Resolves and authorizes a tailnet source address.
    pub async fn whois(
        &self,
        actor: &WhoIsIdentity,
        address: &str,
    ) -> Result<WhoIsIdentity, TailscaleError> {
        self.acl
            .authorize(actor, TailscalePermission::IdentifyPeer)?;
        let address = address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| TailscaleError::InvalidAddress)?;
        let path = format!(
            "/localapi/v0/whois?addr={}",
            url::form_urlencoded::byte_serialize(address.to_string().as_bytes())
                .collect::<String>()
        );
        let response = self
            .transport
            .request(LocalApiRequest {
                method: LocalApiMethod::Get,
                path_and_query: path,
                body: Vec::new(),
                if_match: None,
            })
            .await?;
        let whois: WhoIsResponse = decode_json_response(response)?;
        if whois.node.id.is_empty()
            || whois.node.name.is_empty()
            || whois.node.user == 0
            || whois.user_profile.id != whois.node.user
            || whois.user_profile.login_name.is_empty()
        {
            return Err(TailscaleError::IncompleteIdentity);
        }
        Ok(WhoIsIdentity {
            node_id: whois.node.id,
            node_name: whois.node.name,
            user_id: whois.node.user,
            login_name: whois.user_profile.login_name,
        })
    }

    /// Atomically adds a non-conflicting Serve or Funnel exposure.
    pub async fn set_exposure(
        &self,
        actor: &WhoIsIdentity,
        request: &ExposureRequest,
    ) -> Result<(), TailscaleError> {
        let permission = match request.mode {
            ExposureMode::Serve => TailscalePermission::ExposeServe,
            ExposureMode::Funnel => TailscalePermission::ExposeFunnel,
        };
        self.acl.authorize(actor, permission)?;
        if request.public_port == 0 || request.local_port == 0 {
            return Err(TailscaleError::InvalidExposure);
        }
        let identity = self.status().await?.identity()?;
        let host_port = format!("{}:{}", identity.dns_name, request.public_port);
        let mut managed = self.managed_exposures.lock().await;
        let exposure = ManagedExposure {
            host_port,
            public_port: request.public_port,
            local_port: request.local_port,
            mode: request.mode,
        };
        for _ in 0..MAX_EXPOSURE_WRITE_ATTEMPTS {
            let (mut config, etag) = self.read_serve_config().await?;
            config.insert_proxy(&exposure.host_port, request)?;
            if self.write_serve_config(&config, etag).await? {
                managed.insert(exposure);
                return Ok(());
            }
        }
        Err(TailscaleError::ConcurrentExposureUpdate)
    }

    /// Removes one exact exposure, safely adopting it after a client restart.
    pub async fn clear_exposure(
        &self,
        actor: &WhoIsIdentity,
        request: &ExposureRequest,
    ) -> Result<(), TailscaleError> {
        self.acl
            .authorize(actor, TailscalePermission::RemoveExposure)?;
        if request.public_port == 0 || request.local_port == 0 {
            return Err(TailscaleError::InvalidExposure);
        }
        let mut managed = self.managed_exposures.lock().await;
        let exposure = if let Some(exposure) = managed
            .iter()
            .find(|exposure| exposure.matches_request(request))
            .cloned()
        {
            exposure
        } else {
            let identity = self.status().await?.identity()?;
            ManagedExposure {
                host_port: format!("{}:{}", identity.dns_name, request.public_port),
                public_port: request.public_port,
                local_port: request.local_port,
                mode: request.mode,
            }
        };
        for _ in 0..MAX_EXPOSURE_WRITE_ATTEMPTS {
            let (mut config, etag) = self.read_serve_config().await?;
            match config.exposure_state(&exposure) {
                ExposureState::Absent => {
                    managed.remove(&exposure);
                    return Ok(());
                }
                ExposureState::Conflict => return Err(TailscaleError::ExposureConflict),
                ExposureState::Exact => config.remove_proxy(&exposure),
            }
            if self.write_serve_config(&config, etag).await? {
                managed.remove(&exposure);
                return Ok(());
            }
        }
        Err(TailscaleError::ConcurrentExposureUpdate)
    }

    async fn read_serve_config(&self) -> Result<(ServeConfig, String), TailscaleError> {
        let response = self
            .transport
            .request(LocalApiRequest {
                method: LocalApiMethod::Get,
                path_and_query: "/localapi/v0/serve-config".to_owned(),
                body: Vec::new(),
                if_match: None,
            })
            .await?;
        let etag = response.etag.clone().ok_or(TailscaleError::MissingEtag)?;
        if response.status == 404 {
            return Ok((ServeConfig::default(), etag));
        }
        decode_json_response(response).map(|config| (config, etag))
    }

    async fn write_serve_config(
        &self,
        config: &ServeConfig,
        etag: String,
    ) -> Result<bool, TailscaleError> {
        let body = serde_json::to_vec(config).map_err(TailscaleError::Json)?;
        let response = self
            .transport
            .request(LocalApiRequest {
                method: LocalApiMethod::Post,
                path_and_query: "/localapi/v0/serve-config".to_owned(),
                body,
                if_match: Some(etag),
            })
            .await?;
        if response.status == 412 {
            return Ok(false);
        }
        require_success(response).map(|_| true)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "PascalCase")]
struct ServeConfig {
    #[serde(rename = "TCP")]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    tcp: BTreeMap<u16, ServeTcp>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    web: BTreeMap<String, ServeWeb>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    allow_funnel: BTreeMap<String, bool>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl ServeConfig {
    fn insert_proxy(
        &mut self,
        host_port: &str,
        request: &ExposureRequest,
    ) -> Result<(), TailscaleError> {
        if self.tcp.contains_key(&request.public_port)
            || self.web.contains_key(host_port)
            || self.allow_funnel.contains_key(host_port)
        {
            return Err(TailscaleError::ExposureConflict);
        }
        let mut handlers = BTreeMap::new();
        handlers.insert(
            "/".to_owned(),
            ServeHandler {
                proxy: Some(format!("http://127.0.0.1:{}", request.local_port)),
                additional: BTreeMap::new(),
            },
        );
        self.tcp.insert(
            request.public_port,
            ServeTcp {
                https: Some(true),
                additional: BTreeMap::new(),
            },
        );
        self.web.insert(
            host_port.to_owned(),
            ServeWeb {
                handlers,
                additional: BTreeMap::new(),
            },
        );
        if request.mode == ExposureMode::Funnel {
            self.allow_funnel.insert(host_port.to_owned(), true);
        } else {
            self.allow_funnel.remove(host_port);
        }
        Ok(())
    }

    fn exposure_state(&self, exposure: &ManagedExposure) -> ExposureState {
        let expected_proxy = format!("http://127.0.0.1:{}", exposure.local_port);
        let web = self.web.get(&exposure.host_port);
        let tcp = self.tcp.get(&exposure.public_port);
        let funnel = self.allow_funnel.get(&exposure.host_port);
        let exact_funnel = match exposure.mode {
            ExposureMode::Serve => funnel.is_none(),
            ExposureMode::Funnel => funnel == Some(&true),
        };
        if web.is_some_and(|web| web.matches_proxy(&expected_proxy))
            && tcp.is_some_and(ServeTcp::is_managed_https)
            && exact_funnel
        {
            ExposureState::Exact
        } else if web.is_none() && tcp.is_none() && funnel.is_none() {
            ExposureState::Absent
        } else {
            ExposureState::Conflict
        }
    }

    fn remove_proxy(&mut self, exposure: &ManagedExposure) {
        let expected_proxy = format!("http://127.0.0.1:{}", exposure.local_port);
        let web_matches = self
            .web
            .get(&exposure.host_port)
            .is_some_and(|web| web.matches_proxy(&expected_proxy));
        if web_matches {
            self.web.remove(&exposure.host_port);
        }
        let port_suffix = format!(":{}", exposure.public_port);
        let port_still_used = self
            .web
            .keys()
            .any(|host_port| host_port.ends_with(&port_suffix));
        let tcp_matches = self
            .tcp
            .get(&exposure.public_port)
            .is_some_and(ServeTcp::is_managed_https);
        if web_matches && !port_still_used && tcp_matches {
            self.tcp.remove(&exposure.public_port);
        }
        if web_matches
            && exposure.mode == ExposureMode::Funnel
            && self.allow_funnel.get(&exposure.host_port) == Some(&true)
        {
            self.allow_funnel.remove(&exposure.host_port);
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ServeTcp {
    #[serde(rename = "HTTPS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    https: Option<bool>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl ServeTcp {
    fn is_managed_https(&self) -> bool {
        self.https == Some(true) && self.additional.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ServeWeb {
    handlers: BTreeMap<String, ServeHandler>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl ServeWeb {
    fn matches_proxy(&self, expected_proxy: &str) -> bool {
        self.additional.is_empty()
            && self.handlers.len() == 1
            && self
                .handlers
                .get("/")
                .is_some_and(|handler| handler.matches_proxy(expected_proxy))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ServeHandler {
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy: Option<String>,
    #[serde(flatten)]
    additional: BTreeMap<String, serde_json::Value>,
}

impl ServeHandler {
    fn matches_proxy(&self, expected_proxy: &str) -> bool {
        self.proxy.as_deref() == Some(expected_proxy) && self.additional.is_empty()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ManagedExposure {
    host_port: String,
    public_port: u16,
    local_port: u16,
    mode: ExposureMode,
}

impl ManagedExposure {
    fn matches_request(&self, request: &ExposureRequest) -> bool {
        self.public_port == request.public_port
            && self.local_port == request.local_port
            && self.mode == request.mode
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExposureState {
    Exact,
    Absent,
    Conflict,
}

fn validate_local_api_request(request: &LocalApiRequest) -> Result<(), TailscaleError> {
    if !request.path_and_query.starts_with("/localapi/v0/")
        || request.path_and_query.contains(['\r', '\n', '#'])
        || request.body.len() > MAX_LOCAL_API_BODY
        || request
            .if_match
            .as_deref()
            .is_some_and(|etag| !valid_etag(etag))
    {
        return Err(TailscaleError::InvalidRequest);
    }
    Ok(())
}

fn valid_etag(etag: &str) -> bool {
    !etag.is_empty() && etag.len() <= 256 && etag.is_ascii() && !etag.chars().any(char::is_control)
}

async fn exchange_http<S>(
    mut stream: S,
    request: LocalApiRequest,
    timeout: Duration,
) -> Result<LocalApiResponse, TailscaleError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let if_match = request
        .if_match
        .as_ref()
        .map_or_else(String::new, |etag| format!("If-Match: {etag}\r\n"));
    let headers = format!(
        "{} {} HTTP/1.1\r\nHost: {LOCAL_API_HOST}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{if_match}Connection: close\r\n\r\n",
        request.method.as_str(),
        request.path_and_query,
        request.body.len()
    );
    tokio::time::timeout(timeout, async {
        stream
            .write_all(headers.as_bytes())
            .await
            .map_err(TailscaleError::Io)?;
        stream
            .write_all(&request.body)
            .await
            .map_err(TailscaleError::Io)?;
        stream.shutdown().await.map_err(TailscaleError::Io)?;
        let mut bytes = Vec::new();
        stream
            .take((MAX_LOCAL_API_BODY + 16 * 1024 + 1) as u64)
            .read_to_end(&mut bytes)
            .await
            .map_err(TailscaleError::Io)?;
        parse_http_response(&bytes)
    })
    .await
    .map_err(|_| TailscaleError::Timeout)?
}

fn parse_http_response(bytes: &[u8]) -> Result<LocalApiResponse, TailscaleError> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(TailscaleError::MalformedResponse)?;
    if header_end > 16 * 1024 {
        return Err(TailscaleError::MalformedResponse);
    }
    let headers =
        std::str::from_utf8(&bytes[..header_end]).map_err(|_| TailscaleError::MalformedResponse)?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .filter(|status| (100..=599).contains(status))
        .ok_or(TailscaleError::MalformedResponse)?;
    let mut content_length = None;
    let mut etag = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(TailscaleError::MalformedResponse);
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return Err(TailscaleError::UnsupportedEncoding);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| TailscaleError::MalformedResponse)?;
            if content_length.replace(length).is_some() {
                return Err(TailscaleError::MalformedResponse);
            }
        }
        if name.eq_ignore_ascii_case("etag") {
            let value = value.trim();
            if !valid_etag(value) || etag.replace(value.to_owned()).is_some() {
                return Err(TailscaleError::MalformedResponse);
            }
        }
    }
    let body = &bytes[header_end + 4..];
    if body.len() > MAX_LOCAL_API_BODY {
        return Err(TailscaleError::ResponseTooLarge);
    }
    if content_length.is_some_and(|length| length != body.len()) {
        return Err(TailscaleError::MalformedResponse);
    }
    Ok(LocalApiResponse {
        status,
        body: body.to_vec(),
        etag,
    })
}

fn decode_json_response<T: for<'de> Deserialize<'de>>(
    response: LocalApiResponse,
) -> Result<T, TailscaleError> {
    let body = require_success(response)?;
    serde_json::from_slice(&body).map_err(TailscaleError::Json)
}

fn require_success(response: LocalApiResponse) -> Result<Vec<u8>, TailscaleError> {
    if !(200..300).contains(&response.status) {
        return Err(TailscaleError::ApiStatus(response.status));
    }
    Ok(response.body)
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// Tailscale LocalAPI, identity, or ACL failure.
#[derive(Debug)]
pub enum TailscaleError {
    /// An HTTP LocalAPI endpoint was not loopback-only.
    UnsafeEndpoint,
    /// A LocalAPI request was malformed or exceeded its bound.
    InvalidRequest,
    /// A status or whois response lacked required identity fields.
    IncompleteIdentity,
    /// An address supplied to whois was not a socket address.
    InvalidAddress,
    /// No ACL rule allowed this operation.
    PermissionDenied,
    /// Exposure ports or mode were invalid.
    InvalidExposure,
    /// The requested port or host route is already owned by another configuration.
    ExposureConflict,
    /// Serve configuration lacked the revision required for safe replacement.
    MissingEtag,
    /// Serve configuration changed during every bounded update attempt.
    ConcurrentExposureUpdate,
    /// The LocalAPI rejected the request.
    ApiStatus(u16),
    /// A LocalAPI response exceeded the fixed body limit.
    ResponseTooLarge,
    /// The local HTTP exchange timed out.
    Timeout,
    /// The HTTP response was truncated or malformed.
    MalformedResponse,
    /// The socket response used an unsupported transfer encoding.
    UnsupportedEncoding,
    /// Local socket I/O failed.
    Io(std::io::Error),
    /// Endpoint parsing failed.
    Url(url::ParseError),
    /// JSON encoding or decoding failed.
    Json(serde_json::Error),
}

impl Display for TailscaleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeEndpoint => formatter.write_str("Tailscale LocalAPI endpoint is not local"),
            Self::InvalidRequest => formatter.write_str("invalid Tailscale LocalAPI request"),
            Self::IncompleteIdentity => formatter.write_str("incomplete tailnet identity"),
            Self::InvalidAddress => formatter.write_str("invalid tailnet source address"),
            Self::PermissionDenied => formatter.write_str("Tailscale ACL denied the operation"),
            Self::InvalidExposure => formatter.write_str("invalid Tailscale exposure"),
            Self::ExposureConflict => {
                formatter.write_str("Tailscale exposure conflicts with an existing route")
            }
            Self::MissingEtag => {
                formatter.write_str("Tailscale Serve configuration has no revision ETag")
            }
            Self::ConcurrentExposureUpdate => {
                formatter.write_str("Tailscale Serve configuration changed concurrently")
            }
            Self::ApiStatus(status) => {
                write!(formatter, "Tailscale LocalAPI returned HTTP {status}")
            }
            Self::ResponseTooLarge => {
                formatter.write_str("Tailscale LocalAPI response is too large")
            }
            Self::Timeout => formatter.write_str("Tailscale LocalAPI request timed out"),
            Self::MalformedResponse => formatter.write_str("malformed Tailscale LocalAPI response"),
            Self::UnsupportedEncoding => {
                formatter.write_str("unsupported Tailscale LocalAPI response encoding")
            }
            Self::Io(error) => write!(formatter, "Tailscale LocalAPI I/O failed: {error}"),
            Self::Url(error) => write!(formatter, "invalid Tailscale LocalAPI URL: {error}"),
            Self::Json(error) => write!(formatter, "invalid Tailscale LocalAPI JSON: {error}"),
        }
    }
}

impl Error for TailscaleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Url(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use tokio::sync::Notify;

    struct FakeTransport {
        responses: Mutex<Vec<LocalApiResponse>>,
        requests: Mutex<Vec<LocalApiRequest>>,
    }

    #[async_trait]
    impl LocalApiTransport for FakeTransport {
        async fn request(
            &self,
            request: LocalApiRequest,
        ) -> Result<LocalApiResponse, TailscaleError> {
            self.requests.lock().expect("requests").push(request);
            let mut responses = self.responses.lock().expect("responses");
            if responses.is_empty() {
                return Err(TailscaleError::MalformedResponse);
            }
            Ok(responses.remove(0))
        }
    }

    struct CoordinatedTransport {
        requests: Mutex<Vec<LocalApiRequest>>,
        serve_reads: AtomicUsize,
        first_read_started: Arc<Notify>,
        release_first_read: Arc<Notify>,
    }

    #[async_trait]
    impl LocalApiTransport for CoordinatedTransport {
        async fn request(
            &self,
            request: LocalApiRequest,
        ) -> Result<LocalApiResponse, TailscaleError> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            match (request.method, request.path_and_query.as_str()) {
                (LocalApiMethod::Get, "/localapi/v0/status") => Ok(LocalApiResponse {
                    status: 200,
                    body: status_body(),
                    etag: None,
                }),
                (LocalApiMethod::Get, "/localapi/v0/serve-config") => {
                    let read = self.serve_reads.fetch_add(1, Ordering::SeqCst);
                    if read == 0 {
                        self.first_read_started.notify_one();
                        self.release_first_read.notified().await;
                        Ok(LocalApiResponse {
                            status: 200,
                            body: b"{}".to_vec(),
                            etag: Some("\"revision-1\"".to_owned()),
                        })
                    } else {
                        Ok(LocalApiResponse {
                            status: 200,
                            body: br#"{
                                "TCP":{"443":{"HTTPS":true}},
                                "Web":{
                                    "studio.tail.example:443":{
                                        "Handlers":{"/":{"Proxy":"http://127.0.0.1:18789"}}
                                    }
                                }
                            }"#
                            .to_vec(),
                            etag: Some("\"revision-2\"".to_owned()),
                        })
                    }
                }
                (LocalApiMethod::Post, "/localapi/v0/serve-config") => Ok(LocalApiResponse {
                    status: 204,
                    body: Vec::new(),
                    etag: None,
                }),
                _ => Err(TailscaleError::InvalidRequest),
            }
        }
    }

    fn actor() -> WhoIsIdentity {
        WhoIsIdentity {
            node_id: "node-allowed".to_owned(),
            node_name: "operator.tail.example.".to_owned(),
            user_id: 42,
            login_name: "operator@example.test".to_owned(),
        }
    }

    fn acl(permissions: &[TailscalePermission]) -> TailscaleAcl {
        TailscaleAcl::new(vec![TailscaleAclRule {
            node_id: Some("node-allowed".to_owned()),
            login_name: Some("operator@example.test".to_owned()),
            permissions: permissions.iter().copied().collect(),
        }])
    }

    fn status_body() -> Vec<u8> {
        br#"{
            "Version":"1.90.1",
            "BackendState":"Running",
            "TailscaleIPs":["100.64.0.1","fd7a:115c:a1e0::1"],
            "Self":{
                "ID":"node-self",
                "HostName":"studio",
                "DNSName":"studio.tail.example.",
                "TailscaleIPs":["100.64.0.1","fd7a:115c:a1e0::1"],
                "Online":true,
                "UserID":42
            },
            "Peer":{
                "node-key":{
                    "ID":"node-peer",
                    "HostName":"peer",
                    "DNSName":"peer.tail.example.",
                    "TailscaleIPs":["100.64.0.2"],
                    "Online":false,
                    "UserID":43
                }
            },
            "User":{
                "42":{"ID":42,"LoginName":"operator@example.test","DisplayName":"Operator"}
            }
        }"#
        .to_vec()
    }

    #[tokio::test]
    async fn enumerates_tailnet_and_builds_funnel_config() {
        let transport = FakeTransport {
            responses: Mutex::new(vec![
                LocalApiResponse {
                    status: 200,
                    body: status_body(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: br#"{
                        "TCP":{"9443":{"HTTPS":true,"Opaque":"preserved"}},
                        "Web":{
                            "other.tail.example:9443":{
                                "Handlers":{
                                    "/":{
                                        "Proxy":"http://127.0.0.1:9000",
                                        "OpaqueHandler":7
                                    }
                                },
                                "OpaqueWeb":true
                            }
                        },
                        "AllowFunnel":{"other.tail.example:9443":true},
                        "OpaqueTop":{"Enabled":true}
                    }"#
                    .to_vec(),
                    etag: Some("\"revision-1\"".to_owned()),
                },
                LocalApiResponse {
                    status: 204,
                    body: Vec::new(),
                    etag: None,
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let client = TailscaleClient::new(
            transport,
            acl(&[
                TailscalePermission::ExposeFunnel,
                TailscalePermission::Discover,
            ]),
        );

        client
            .set_exposure(
                &actor(),
                &ExposureRequest {
                    public_port: 443,
                    local_port: 18789,
                    mode: ExposureMode::Funnel,
                },
            )
            .await
            .expect("exposure");

        let requests = client.transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests[0],
            LocalApiRequest {
                method: LocalApiMethod::Get,
                path_and_query: "/localapi/v0/status".to_owned(),
                body: Vec::new(),
                if_match: None,
            }
        );
        assert_eq!(
            requests[1],
            LocalApiRequest {
                method: LocalApiMethod::Get,
                path_and_query: "/localapi/v0/serve-config".to_owned(),
                body: Vec::new(),
                if_match: None,
            }
        );
        let config: serde_json::Value =
            serde_json::from_slice(&requests[2].body).expect("serve JSON");
        assert_eq!(requests[2].if_match.as_deref(), Some("\"revision-1\""));
        assert_eq!(
            config,
            serde_json::json!({
                "TCP":{
                    "443":{"HTTPS":true},
                    "9443":{"HTTPS":true,"Opaque":"preserved"}
                },
                "Web":{
                    "studio.tail.example:443":{
                        "Handlers":{
                            "/":{"Proxy":"http://127.0.0.1:18789"}
                        }
                    },
                    "other.tail.example:9443":{
                        "Handlers":{
                            "/":{
                                "Proxy":"http://127.0.0.1:9000",
                                "OpaqueHandler":7
                            }
                        },
                        "OpaqueWeb":true
                    }
                },
                "AllowFunnel":{
                    "other.tail.example:9443":true,
                    "studio.tail.example:443":true
                },
                "OpaqueTop":{"Enabled":true}
            })
        );
    }

    #[tokio::test]
    async fn exposure_rejects_an_existing_port_without_overwriting_it() {
        let transport = FakeTransport {
            responses: Mutex::new(vec![
                LocalApiResponse {
                    status: 200,
                    body: status_body(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: br#"{
                        "TCP":{"443":{"HTTPS":true}},
                        "Web":{
                            "other.tail.example:443":{
                                "Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"}}
                            }
                        }
                    }"#
                    .to_vec(),
                    etag: Some("\"revision-1\"".to_owned()),
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let client = TailscaleClient::new(transport, acl(&[TailscalePermission::ExposeServe]));

        assert!(matches!(
            client
                .set_exposure(
                    &actor(),
                    &ExposureRequest {
                        public_port: 443,
                        local_port: 18_789,
                        mode: ExposureMode::Serve,
                    },
                )
                .await,
            Err(TailscaleError::ExposureConflict)
        ));
        assert_eq!(
            client
                .transport
                .requests
                .lock()
                .expect("requests")
                .iter()
                .map(|request| (request.method, request.path_and_query.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (LocalApiMethod::Get, "/localapi/v0/status"),
                (LocalApiMethod::Get, "/localapi/v0/serve-config"),
            ]
        );
        assert!(
            client
                .managed_exposures
                .try_lock()
                .expect("managed")
                .is_empty()
        );
    }

    #[test]
    fn cleanup_preserves_modified_and_shared_serve_entries() {
        let mut modified: ServeConfig = serde_json::from_slice(
            br#"{
                "TCP":{"443":{"HTTPS":true}},
                "Web":{
                    "studio.tail.example:443":{
                        "Handlers":{"/":{"Proxy":"http://127.0.0.1:19000"}}
                    }
                },
                "AllowFunnel":{"studio.tail.example:443":true}
            }"#,
        )
        .expect("serve config");
        let exposure = ManagedExposure {
            host_port: "studio.tail.example:443".to_owned(),
            public_port: 443,
            local_port: 18_789,
            mode: ExposureMode::Funnel,
        };

        modified.remove_proxy(&exposure);

        assert_eq!(
            serde_json::to_value(modified).expect("modified config"),
            serde_json::json!({
                "TCP":{"443":{"HTTPS":true}},
                "Web":{
                    "studio.tail.example:443":{
                        "Handlers":{"/":{"Proxy":"http://127.0.0.1:19000"}}
                    }
                },
                "AllowFunnel":{"studio.tail.example:443":true}
            })
        );

        let mut shared: ServeConfig = serde_json::from_slice(
            br#"{
                "TCP":{"443":{"HTTPS":true}},
                "Web":{
                    "studio.tail.example:443":{
                        "Handlers":{"/":{"Proxy":"http://127.0.0.1:18789"}}
                    },
                    "other.tail.example:443":{
                        "Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"}}
                    }
                }
            }"#,
        )
        .expect("shared config");

        shared.remove_proxy(&exposure);

        assert_eq!(
            serde_json::to_value(shared).expect("shared config"),
            serde_json::json!({
                "TCP":{"443":{"HTTPS":true}},
                "Web":{
                    "other.tail.example:443":{
                        "Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"}}
                    }
                }
            })
        );
    }

    #[tokio::test]
    async fn acl_denies_partial_identity_and_prevents_api_call() {
        let transport = FakeTransport {
            responses: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        };
        let client = TailscaleClient::new(
            transport,
            TailscaleAcl::new(vec![TailscaleAclRule {
                node_id: Some("node-allowed".to_owned()),
                login_name: Some("different@example.test".to_owned()),
                permissions: [TailscalePermission::Discover].into_iter().collect(),
            }]),
        );

        let result = client.discover_nodes(&actor()).await;

        assert!(matches!(result, Err(TailscaleError::PermissionDenied)));
        assert!(
            client
                .transport
                .requests
                .lock()
                .expect("requests")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cleanup_adopts_an_exact_persistent_exposure_after_restart() {
        let transport = FakeTransport {
            responses: Mutex::new(vec![
                LocalApiResponse {
                    status: 200,
                    body: status_body(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: br#"{
                        "TCP":{"443":{"HTTPS":true}},
                        "Web":{
                            "studio.tail.example:443":{
                                "Handlers":{"/":{"Proxy":"http://127.0.0.1:18789"}}
                            }
                        },
                        "AllowFunnel":{"studio.tail.example:443":true}
                    }"#
                    .to_vec(),
                    etag: Some("\"restart-revision\"".to_owned()),
                },
                LocalApiResponse {
                    status: 204,
                    body: Vec::new(),
                    etag: None,
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let client = TailscaleClient::new(transport, acl(&[TailscalePermission::RemoveExposure]));
        let exposure = ExposureRequest {
            public_port: 443,
            local_port: 18_789,
            mode: ExposureMode::Funnel,
        };

        client
            .clear_exposure(&actor(), &exposure)
            .await
            .expect("restart cleanup");

        let requests = client.transport.requests.lock().expect("requests");
        assert_eq!(
            requests
                .iter()
                .map(|request| (request.method, request.path_and_query.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (LocalApiMethod::Get, "/localapi/v0/status"),
                (LocalApiMethod::Get, "/localapi/v0/serve-config"),
                (LocalApiMethod::Post, "/localapi/v0/serve-config"),
            ]
        );
        assert_eq!(
            requests[2].if_match.as_deref(),
            Some("\"restart-revision\"")
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[2].body).expect("cleanup config"),
            serde_json::json!({})
        );
    }

    #[tokio::test]
    async fn exposure_retries_with_the_latest_etag_after_precondition_failure() {
        let transport = FakeTransport {
            responses: Mutex::new(vec![
                LocalApiResponse {
                    status: 200,
                    body: status_body(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: b"{}".to_vec(),
                    etag: Some("\"revision-1\"".to_owned()),
                },
                LocalApiResponse {
                    status: 412,
                    body: Vec::new(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: b"{}".to_vec(),
                    etag: Some("\"revision-2\"".to_owned()),
                },
                LocalApiResponse {
                    status: 204,
                    body: Vec::new(),
                    etag: None,
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let client = TailscaleClient::new(transport, acl(&[TailscalePermission::ExposeServe]));

        client
            .set_exposure(
                &actor(),
                &ExposureRequest {
                    public_port: 443,
                    local_port: 18_789,
                    mode: ExposureMode::Serve,
                },
            )
            .await
            .expect("conditional retry");

        let requests = client.transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[2].if_match.as_deref(), Some("\"revision-1\""));
        assert_eq!(requests[4].if_match.as_deref(), Some("\"revision-2\""));
        assert_eq!(requests[2].body, requests[4].body);
    }

    #[tokio::test]
    async fn status_discovery_whois_serve_and_cleanup_follow_local_api_contract() {
        let transport = FakeTransport {
            responses: Mutex::new(vec![
                LocalApiResponse {
                    status: 200,
                    body: status_body(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: br#"{
                        "Node":{"ID":"node-peer","Name":"peer.tail.example.","User":43},
                        "UserProfile":{"ID":43,"LoginName":"peer@example.test","DisplayName":"Peer"}
                    }"#
                    .to_vec(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: status_body(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: br#"{
                        "TCP":{"9443":{"HTTPS":true}},
                        "Web":{
                            "other.tail.example:9443":{
                                "Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"}}
                            }
                        }
                    }"#
                    .to_vec(),
                    etag: Some("\"revision-1\"".to_owned()),
                },
                LocalApiResponse {
                    status: 204,
                    body: Vec::new(),
                    etag: None,
                },
                LocalApiResponse {
                    status: 200,
                    body: br#"{
                        "TCP":{"8443":{"HTTPS":true},"9443":{"HTTPS":true}},
                        "Web":{
                            "studio.tail.example:8443":{
                                "Handlers":{"/":{"Proxy":"http://127.0.0.1:18790"}}
                            },
                            "other.tail.example:9443":{
                                "Handlers":{"/":{"Proxy":"http://127.0.0.1:9000"}}
                            }
                        }
                    }"#
                    .to_vec(),
                    etag: Some("\"revision-2\"".to_owned()),
                },
                LocalApiResponse {
                    status: 204,
                    body: Vec::new(),
                    etag: None,
                },
            ]),
            requests: Mutex::new(Vec::new()),
        };
        let client = TailscaleClient::new(
            transport,
            acl(&[
                TailscalePermission::Discover,
                TailscalePermission::IdentifyPeer,
                TailscalePermission::ExposeServe,
                TailscalePermission::RemoveExposure,
            ]),
        );

        let nodes = client.discover_nodes(&actor()).await.expect("nodes");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].id, "node-self");
        assert_eq!(nodes[0].tailscale_ips.len(), 2);
        assert_eq!(nodes[1].id, "node-peer");
        assert_eq!(
            client
                .whois(&actor(), "100.64.0.2:443")
                .await
                .expect("whois"),
            WhoIsIdentity {
                node_id: "node-peer".to_owned(),
                node_name: "peer.tail.example.".to_owned(),
                user_id: 43,
                login_name: "peer@example.test".to_owned(),
            }
        );
        let exposure = ExposureRequest {
            public_port: 8443,
            local_port: 18_790,
            mode: ExposureMode::Serve,
        };
        client
            .set_exposure(&actor(), &exposure)
            .await
            .expect("serve");
        client
            .clear_exposure(&actor(), &exposure)
            .await
            .expect("cleanup");

        let requests = client.transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 7);
        assert_eq!(
            requests[1].path_and_query,
            "/localapi/v0/whois?addr=100.64.0.2%3A443"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[4].body).expect("serve config"),
            serde_json::json!({
                "TCP":{"8443":{"HTTPS":true},"9443":{"HTTPS":true}},
                "Web":{
                    "studio.tail.example:8443":{
                        "Handlers":{
                            "/":{"Proxy":"http://127.0.0.1:18790"}
                        }
                    },
                    "other.tail.example:9443":{
                        "Handlers":{
                            "/":{"Proxy":"http://127.0.0.1:9000"}
                        }
                    }
                }
            })
        );
        assert_eq!(requests[4].if_match.as_deref(), Some("\"revision-1\""));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[6].body).expect("cleanup config"),
            serde_json::json!({
                "TCP":{"9443":{"HTTPS":true}},
                "Web":{
                    "other.tail.example:9443":{
                        "Handlers":{
                            "/":{"Proxy":"http://127.0.0.1:9000"}
                        }
                    }
                }
            })
        );
        assert_eq!(requests[6].if_match.as_deref(), Some("\"revision-2\""));
    }

    #[tokio::test]
    async fn exposure_updates_serialize_read_modify_write_and_bookkeeping() {
        let first_read_started = Arc::new(Notify::new());
        let release_first_read = Arc::new(Notify::new());
        let client = Arc::new(TailscaleClient::new(
            CoordinatedTransport {
                requests: Mutex::new(Vec::new()),
                serve_reads: AtomicUsize::new(0),
                first_read_started: Arc::clone(&first_read_started),
                release_first_read: Arc::clone(&release_first_read),
            },
            acl(&[
                TailscalePermission::ExposeServe,
                TailscalePermission::RemoveExposure,
            ]),
        ));
        let setter = {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client
                    .set_exposure(
                        &actor(),
                        &ExposureRequest {
                            public_port: 443,
                            local_port: 18_789,
                            mode: ExposureMode::Serve,
                        },
                    )
                    .await
            })
        };
        first_read_started.notified().await;
        assert!(client.managed_exposures.try_lock().is_err());
        let clearer = {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client
                    .clear_exposure(
                        &actor(),
                        &ExposureRequest {
                            public_port: 443,
                            local_port: 18_789,
                            mode: ExposureMode::Serve,
                        },
                    )
                    .await
            })
        };

        release_first_read.notify_one();
        setter.await.expect("setter task").expect("set exposure");
        clearer
            .await
            .expect("clearer task")
            .expect("clear exposure");

        let requests = client.transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 5);
        assert_eq!(
            requests
                .iter()
                .map(|request| (request.method, request.path_and_query.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (LocalApiMethod::Get, "/localapi/v0/status"),
                (LocalApiMethod::Get, "/localapi/v0/serve-config"),
                (LocalApiMethod::Post, "/localapi/v0/serve-config"),
                (LocalApiMethod::Get, "/localapi/v0/serve-config"),
                (LocalApiMethod::Post, "/localapi/v0/serve-config"),
            ]
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[4].body).expect("cleanup JSON"),
            serde_json::json!({})
        );
        assert_eq!(requests[2].if_match.as_deref(), Some("\"revision-1\""));
        assert_eq!(requests[4].if_match.as_deref(), Some("\"revision-2\""));
        assert!(
            client
                .managed_exposures
                .try_lock()
                .expect("managed")
                .is_empty()
        );
    }

    #[test]
    fn rejects_truncated_and_oversized_socket_responses() {
        let parsed = parse_http_response(
            b"HTTP/1.1 200 OK\r\nETag: \"revision-1\"\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("valid response");
        assert_eq!(
            parsed,
            LocalApiResponse {
                status: 200,
                body: b"{}".to_vec(),
                etag: Some("\"revision-1\"".to_owned()),
            }
        );
        assert!(matches!(
            parse_http_response(
                b"HTTP/1.1 200 OK\r\nETag: \"revision-1\"\r\nETag: \"revision-2\"\r\nContent-Length: 2\r\n\r\n{}"
            ),
            Err(TailscaleError::MalformedResponse)
        ));
        assert!(matches!(
            parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}"),
            Err(TailscaleError::MalformedResponse)
        ));
        let oversized = [
            b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
            vec![b'x'; MAX_LOCAL_API_BODY + 1].as_slice(),
        ]
        .concat();
        assert!(matches!(
            parse_http_response(&oversized),
            Err(TailscaleError::ResponseTooLarge)
        ));
    }

    #[test]
    fn loopback_transport_rejects_remote_and_credentialed_urls() {
        let localhost = LoopbackLocalApiTransport::new(
            Url::parse("http://localhost:41112/").expect("URL"),
            Duration::from_secs(1),
        )
        .expect("loopback transport");
        assert_eq!(
            localhost.endpoint,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41_112)
        );
        assert!(matches!(
            LoopbackLocalApiTransport::new(
                Url::parse("http://example.test/").expect("URL"),
                Duration::from_secs(1)
            ),
            Err(TailscaleError::UnsafeEndpoint)
        ));
        assert!(matches!(
            LoopbackLocalApiTransport::new(
                Url::parse("http://user:password@127.0.0.1/").expect("URL"),
                Duration::from_secs(1)
            ),
            Err(TailscaleError::UnsafeEndpoint)
        ));
    }
}

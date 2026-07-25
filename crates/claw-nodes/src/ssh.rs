//! Pure-Rust SSH discovery, fail-closed host verification, and forwarding.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use claw_security::authorization::{ClientClass, Role, ScopeSet};
use claw_security::identity::{
    DeviceId, DeviceIdentity, DevicePublicKey, DeviceSignature, HandshakeSigningInput,
};
use russh::ChannelOpenFailure;
use russh::client;
use russh::keys::key::PrivateKeyWithHashAlg;
use secrecy::{ExposeSecret, SecretString};
use tokio::io as tokio_io;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinSet;

use crate::identity::{NodeClientKind, NodeIdentity, admit_protocol};

const DEFAULT_SSH_PORT: u16 = 22;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const FORWARDED_CHANNEL_CAPACITY: usize = 64;
const MAX_LOCAL_FORWARD_CONNECTIONS: usize = 64;
const PAIRING_NONCE: &[u8] = b"gta-claw-ssh-pairing-v1";

/// Pairing challenge bound to a known SSH host key and expected node identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshPairingChallenge {
    /// Fresh 256-bit caller challenge.
    pub nonce: [u8; 32],
    /// SHA-256 SSH host-key fingerprint accepted through known_hosts.
    pub host_key_fingerprint: String,
    /// Node identity expected from a prior authenticated discovery record.
    pub expected_device_id: DeviceId,
    /// Authenticated node protocol version.
    pub protocol_version: u16,
}

impl SshPairingChallenge {
    fn validate(&self) -> Result<(), SshError> {
        if self.host_key_fingerprint.is_empty()
            || self.host_key_fingerprint.len() > 256
            || self.host_key_fingerprint.chars().any(char::is_control)
            || self.nonce.iter().all(|byte| *byte == 0)
        {
            return Err(SshError::InvalidPairingChallenge);
        }
        admit_protocol(NodeClientKind::Node, self.protocol_version, true)
            .map_err(|_| SshError::InvalidPairingChallenge)?;
        Ok(())
    }

    fn payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        append_pairing_field(&mut payload, &self.nonce);
        append_pairing_field(&mut payload, self.host_key_fingerprint.as_bytes());
        append_pairing_field(&mut payload, self.expected_device_id.to_string().as_bytes());
        payload
    }
}

/// Node proof returned through an authenticated SSH channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SshPairingProof {
    /// Claimed node identifier.
    pub device_id: DeviceId,
    /// Public key corresponding to the node identifier.
    pub public_key: DevicePublicKey,
    /// Unix signature timestamp.
    pub signed_at_unix_millis: u64,
    /// Signature over the challenge and verified SSH host key.
    pub signature: DeviceSignature,
}

/// Creates a host-key-bound pairing proof.
pub fn create_pairing_proof(
    identity: &DeviceIdentity,
    challenge: &SshPairingChallenge,
    signed_at_unix_millis: u64,
) -> Result<SshPairingProof, SshError> {
    challenge.validate()?;
    let device_id = identity.device_id();
    if device_id != challenge.expected_device_id {
        return Err(SshError::PairingIdentityMismatch);
    }
    let payload = challenge.payload();
    let signature = identity.sign_handshake(HandshakeSigningInput {
        device_id: &device_id,
        role: Role::Node,
        scopes: ScopeSet::EMPTY,
        protocol_version: challenge.protocol_version,
        client_class: ClientClass::AuthenticatedNode,
        signed_at_unix_millis,
        nonce: PAIRING_NONCE,
        challenge: &payload,
    });
    Ok(SshPairingProof {
        device_id,
        public_key: identity.public_key(),
        signed_at_unix_millis,
        signature,
    })
}

/// Verifies a pairing proof and returns the bound node identity.
pub fn verify_pairing_proof(
    challenge: &SshPairingChallenge,
    proof: &SshPairingProof,
    now_unix_millis: u64,
    signature_window_millis: u64,
) -> Result<NodeIdentity, SshError> {
    challenge.validate()?;
    if proof.device_id != challenge.expected_device_id {
        return Err(SshError::PairingIdentityMismatch);
    }
    if now_unix_millis.abs_diff(proof.signed_at_unix_millis) > signature_window_millis {
        return Err(SshError::PairingExpired);
    }
    let identity = NodeIdentity::new(proof.device_id, proof.public_key)
        .map_err(|_| SshError::PairingIdentityMismatch)?;
    let payload = challenge.payload();
    proof
        .public_key
        .verify_handshake(
            HandshakeSigningInput {
                device_id: &proof.device_id,
                role: Role::Node,
                scopes: ScopeSet::EMPTY,
                protocol_version: challenge.protocol_version,
                client_class: ClientClass::AuthenticatedNode,
                signed_at_unix_millis: proof.signed_at_unix_millis,
                nonce: PAIRING_NONCE,
                challenge: &payload,
            },
            &proof.signature,
        )
        .map_err(|_| SshError::PairingSignature)?;
    Ok(identity)
}

fn append_pairing_field(payload: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("pairing fields are bounded");
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(value);
}

/// Parsed SSH connection target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshTarget {
    /// Optional user name.
    pub user: Option<String>,
    /// Hostname or IP literal without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl SshTarget {
    /// Parses `[user@]host[:port]` and bracketed IPv6 targets.
    pub fn parse(value: &str) -> Result<Self, SshError> {
        let value = value.trim().strip_prefix("ssh ").unwrap_or(value.trim());
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(SshError::InvalidTarget);
        }
        let (user, host_port) = value.split_once('@').map_or((None, value), |(user, rest)| {
            let user = user.trim();
            (Some(user), rest.trim())
        });
        if user.is_some_and(|user| user.is_empty() || !valid_user(user)) {
            return Err(SshError::InvalidTarget);
        }

        let bracketed_host = host_port.starts_with('[');
        let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
            let end = bracketed.find(']').ok_or(SshError::InvalidTarget)?;
            let host = &bracketed[..end];
            let suffix = &bracketed[end + 1..];
            let port = if suffix.is_empty() {
                DEFAULT_SSH_PORT
            } else {
                parse_port(suffix.strip_prefix(':').ok_or(SshError::InvalidTarget)?)?
            };
            (host, port)
        } else if host_port.matches(':').count() == 1 {
            let (host, port) = host_port.rsplit_once(':').ok_or(SshError::InvalidTarget)?;
            (host, parse_port(port)?)
        } else {
            (host_port, DEFAULT_SSH_PORT)
        };
        let host = host.trim();
        if host.is_empty()
            || host.starts_with('-')
            || host.ends_with(':')
            || (host.contains(':') && !bracketed_host)
            || host.chars().any(char::is_whitespace)
        {
            return Err(SshError::InvalidTarget);
        }
        Ok(Self {
            user: user.map(str::to_owned),
            host: host.to_owned(),
            port,
        })
    }
}

/// Resolved OpenSSH host configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshHostConfig {
    /// Alias used to resolve this host.
    pub alias: String,
    /// Effective hostname.
    pub host_name: String,
    /// Effective user name, when configured.
    pub user: Option<String>,
    /// Effective SSH port.
    pub port: u16,
    /// Identity files in configuration order.
    pub identity_files: Vec<PathBuf>,
}

/// Pure parser for bounded OpenSSH client configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SshConfig {
    blocks: Vec<SshConfigBlock>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SshConfigBlock {
    patterns: Vec<String>,
    host_name: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_files: Vec<PathBuf>,
}

impl SshConfig {
    /// Parses `Host`, `HostName`, `User`, `Port`, and `IdentityFile` directives.
    pub fn parse(contents: &str) -> Result<Self, SshError> {
        if contents.len() > MAX_CONFIG_BYTES {
            return Err(SshError::ConfigTooLarge);
        }
        let mut blocks = vec![SshConfigBlock {
            patterns: vec!["*".to_owned()],
            ..SshConfigBlock::default()
        }];
        for raw_line in contents.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (directive, value) = split_directive(line).ok_or(SshError::InvalidConfig)?;
            match directive.to_ascii_lowercase().as_str() {
                "host" => {
                    let patterns = value
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect::<Vec<_>>();
                    if patterns.is_empty() {
                        return Err(SshError::InvalidConfig);
                    }
                    blocks.push(SshConfigBlock {
                        patterns,
                        ..SshConfigBlock::default()
                    });
                }
                "hostname" => set_once(
                    &mut blocks
                        .last_mut()
                        .expect("default block is always present")
                        .host_name,
                    value,
                ),
                "user" => set_once(
                    &mut blocks
                        .last_mut()
                        .expect("default block is always present")
                        .user,
                    value,
                ),
                "port" => {
                    let port = parse_port(value)?;
                    let slot = &mut blocks
                        .last_mut()
                        .expect("default block is always present")
                        .port;
                    if slot.is_none() {
                        *slot = Some(port);
                    }
                }
                "identityfile" => blocks
                    .last_mut()
                    .expect("default block is always present")
                    .identity_files
                    .push(PathBuf::from(value)),
                _ => {}
            }
        }
        Ok(Self { blocks })
    }

    /// Returns concrete aliases suitable for host discovery.
    #[must_use]
    pub fn discovered_aliases(&self) -> Vec<&str> {
        let mut aliases = BTreeSet::new();
        for pattern in self.blocks.iter().flat_map(|block| &block.patterns) {
            if !pattern.starts_with('!') && !pattern.contains(['*', '?']) {
                aliases.insert(pattern.as_str());
            }
        }
        aliases.into_iter().collect()
    }

    /// Resolves the first-value-wins OpenSSH configuration for one alias.
    pub fn resolve(&self, alias: &str) -> Result<SshHostConfig, SshError> {
        if alias.trim().is_empty() || alias.chars().any(char::is_whitespace) {
            return Err(SshError::InvalidTarget);
        }
        let mut host_name = None;
        let mut user = None;
        let mut port = None;
        let mut identity_files = Vec::new();
        for block in &self.blocks {
            if !host_patterns_match(&block.patterns, alias) {
                continue;
            }
            if host_name.is_none() {
                host_name.clone_from(&block.host_name);
            }
            if user.is_none() {
                user.clone_from(&block.user);
            }
            if port.is_none() {
                port = block.port;
            }
            identity_files.extend(block.identity_files.iter().cloned());
        }
        Ok(SshHostConfig {
            alias: alias.to_owned(),
            host_name: host_name.unwrap_or_else(|| alias.to_owned()),
            user,
            port: port.unwrap_or(DEFAULT_SSH_PORT),
            identity_files,
        })
    }
}

/// Verifies an OpenSSH host key against a selected known-hosts file.
///
/// Unknown hosts and changed keys are both hard failures. This function never
/// learns or updates keys implicitly.
pub fn verify_known_host(
    known_hosts_path: &Path,
    host: &str,
    port: u16,
    public_key: &russh::keys::PublicKey,
) -> Result<(), SshError> {
    match russh::keys::check_known_hosts_path(host, port, public_key, known_hosts_path) {
        Ok(true) => Ok(()),
        Ok(false) => Err(SshError::UnknownHost),
        Err(russh::keys::Error::KeyChanged { .. }) => Err(SshError::HostKeyMismatch),
        Err(error) => Err(SshError::Key(error)),
    }
}

/// Inputs for a fail-closed key-authenticated SSH connection.
pub struct SshConnectConfig {
    /// Target host, port, and optional user.
    pub target: SshTarget,
    /// User override when the target contains no user.
    pub default_user: String,
    /// OpenSSH private-key path.
    pub identity_file: PathBuf,
    /// OpenSSH known-hosts path.
    pub known_hosts_file: PathBuf,
    /// Inactivity timeout.
    pub timeout: Duration,
}

struct ClientHandler {
    host: String,
    port: u16,
    known_hosts_file: PathBuf,
    forwarded: mpsc::Sender<ForwardedConnection>,
}

impl client::Handler for ClientHandler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        verify_known_host(
            &self.known_hosts_file,
            &self.host,
            self.port,
            server_public_key,
        )?;
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let connection = ForwardedConnection {
            connected_address: connected_address.to_owned(),
            connected_port,
            originator_address: originator_address.to_owned(),
            originator_port,
            channel,
        };
        if self.forwarded.try_send(connection).is_ok() {
            reply.accept().await;
        } else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
        }
        Ok(())
    }
}

/// Authenticated russh client connection.
pub struct SshConnection {
    handle: Arc<Mutex<client::Handle<ClientHandler>>>,
    forwarded: Mutex<mpsc::Receiver<ForwardedConnection>>,
}

impl SshConnection {
    /// Connects, verifies the host key, and performs key-based authentication.
    pub async fn connect(
        config: SshConnectConfig,
        key_passphrase: Option<&SecretString>,
    ) -> Result<Self, SshError> {
        let user = config
            .target
            .user
            .clone()
            .unwrap_or_else(|| config.default_user.clone())
            .trim()
            .to_owned();
        if !valid_user(&user) {
            return Err(SshError::InvalidUser);
        }
        let private_key = russh::keys::load_secret_key(
            &config.identity_file,
            key_passphrase.map(|secret| secret.expose_secret()),
        )
        .map_err(SshError::Key)?;
        let (forwarded_tx, forwarded_rx) = mpsc::channel(FORWARDED_CHANNEL_CAPACITY);
        let handler = ClientHandler {
            host: config.target.host.clone(),
            port: config.target.port,
            known_hosts_file: config.known_hosts_file,
            forwarded: forwarded_tx,
        };
        let client_config = Arc::new(client::Config {
            inactivity_timeout: Some(config.timeout),
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            nodelay: true,
            ..client::Config::default()
        });
        let mut handle = client::connect(
            client_config,
            (config.target.host.as_str(), config.target.port),
            handler,
        )
        .await?;
        let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
        let authentication = handle
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(Arc::new(private_key), rsa_hash),
            )
            .await?;
        if !authentication.success() {
            return Err(SshError::AuthenticationFailed);
        }
        Ok(Self {
            handle: Arc::new(Mutex::new(handle)),
            forwarded: Mutex::new(forwarded_rx),
        })
    }

    /// Binds a local loopback or caller-selected listener without accepting yet.
    pub async fn bind_local(address: &str, port: u16) -> Result<TcpListener, SshError> {
        TcpListener::bind((address, port))
            .await
            .map_err(SshError::Io)
    }

    /// Serves a local port forward until the stop signal becomes true.
    pub async fn serve_local_forward(
        &self,
        listener: TcpListener,
        remote_host: &str,
        remote_port: u16,
        mut stop: watch::Receiver<bool>,
    ) -> Result<(), SshError> {
        if remote_host.is_empty() || remote_port == 0 {
            return Err(SshError::InvalidForward);
        }
        if *stop.borrow() {
            return Ok(());
        }
        let mut forwards = JoinSet::new();
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    if changed.is_err() {
                        forwards.shutdown().await;
                        return Err(SshError::StopChannelClosed);
                    }
                    if *stop.borrow() {
                        while let Some(completed) = forwards.join_next().await {
                            Self::complete_local_forward(completed)?;
                        }
                        return Ok(());
                    }
                }
                completed = forwards.join_next(), if !forwards.is_empty() => {
                    if let Some(completed) = completed
                        && let Err(error) = Self::complete_local_forward(completed)
                    {
                        forwards.shutdown().await;
                        return Err(error);
                    }
                }
                accepted = listener.accept(), if forwards.len() < MAX_LOCAL_FORWARD_CONNECTIONS => {
                    let (stream, originator) = accepted.map_err(SshError::Io)?;
                    let handle = Arc::clone(&self.handle);
                    let remote_host = remote_host.to_owned();
                    let originator_host = originator.ip().to_string();
                    let session_stop = stop.clone();
                    forwards.spawn(async move {
                        Self::forward_local_stream_with_stop(
                            handle,
                            stream,
                            &remote_host,
                            remote_port,
                            &originator_host,
                            originator.port(),
                            session_stop,
                        )
                        .await
                    });
                }
            }
        }
    }

    /// Forwards one established local stream through a direct-tcpip channel.
    pub async fn forward_local_stream(
        &self,
        stream: TcpStream,
        remote_host: &str,
        remote_port: u16,
        originator_host: &str,
        originator_port: u16,
    ) -> Result<u64, SshError> {
        Self::forward_local_stream_with_handle(
            Arc::clone(&self.handle),
            stream,
            remote_host,
            remote_port,
            originator_host,
            originator_port,
        )
        .await
    }

    fn complete_local_forward(
        completed: Result<Result<u64, SshError>, tokio::task::JoinError>,
    ) -> Result<(), SshError> {
        match completed {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(SshError::ForwardTask(error)),
        }
    }

    async fn forward_local_stream_with_stop(
        handle: Arc<Mutex<client::Handle<ClientHandler>>>,
        mut stream: TcpStream,
        remote_host: &str,
        remote_port: u16,
        originator_host: &str,
        originator_port: u16,
        mut stop: watch::Receiver<bool>,
    ) -> Result<u64, SshError> {
        if remote_host.is_empty() || remote_port == 0 || originator_host.is_empty() {
            return Err(SshError::InvalidForward);
        }
        if *stop.borrow() {
            return Ok(0);
        }
        let open_channel = async {
            let handle = handle.lock().await;
            handle
                .channel_open_direct_tcpip(
                    remote_host,
                    u32::from(remote_port),
                    originator_host,
                    u32::from(originator_port),
                )
                .await
        };
        tokio::pin!(open_channel);
        let channel = loop {
            tokio::select! {
                changed = stop.changed() => {
                    changed.map_err(|_| SshError::StopChannelClosed)?;
                    if *stop.borrow() {
                        return Ok(0);
                    }
                }
                channel = &mut open_channel => break channel?,
            }
        };
        let mut channel = channel.into_stream();
        let mut copy = Box::pin(tokio_io::copy_bidirectional(&mut stream, &mut channel));
        loop {
            tokio::select! {
                changed = stop.changed() => {
                    changed.map_err(|_| SshError::StopChannelClosed)?;
                    if *stop.borrow() {
                        break;
                    }
                }
                result = &mut copy => {
                    let (sent, received) = result.map_err(SshError::Io)?;
                    return Ok(sent.saturating_add(received));
                }
            }
        }
        drop(copy);
        stream.shutdown().await.map_err(SshError::Io)?;
        channel.shutdown().await.map_err(SshError::Io)?;
        Ok(0)
    }

    async fn forward_local_stream_with_handle(
        handle: Arc<Mutex<client::Handle<ClientHandler>>>,
        mut stream: TcpStream,
        remote_host: &str,
        remote_port: u16,
        originator_host: &str,
        originator_port: u16,
    ) -> Result<u64, SshError> {
        if remote_host.is_empty() || remote_port == 0 || originator_host.is_empty() {
            return Err(SshError::InvalidForward);
        }
        let channel = {
            let handle = handle.lock().await;
            handle
                .channel_open_direct_tcpip(
                    remote_host,
                    u32::from(remote_port),
                    originator_host,
                    u32::from(originator_port),
                )
                .await?
        };
        let mut channel = channel.into_stream();
        let (sent, received) = tokio_io::copy_bidirectional(&mut stream, &mut channel)
            .await
            .map_err(SshError::Io)?;
        Ok(sent.saturating_add(received))
    }

    /// Requests a server-side TCP listener for remote forwarding.
    pub async fn request_remote_forward(
        &self,
        bind_address: &str,
        bind_port: u16,
    ) -> Result<u16, SshError> {
        if bind_address.is_empty() {
            return Err(SshError::InvalidForward);
        }
        let allocated = self
            .handle
            .lock()
            .await
            .tcpip_forward(bind_address, u32::from(bind_port))
            .await?;
        u16::try_from(allocated).map_err(|_| SshError::InvalidForward)
    }

    /// Cancels an exact server-side TCP listener.
    pub async fn cancel_remote_forward(
        &self,
        bind_address: &str,
        bind_port: u16,
    ) -> Result<(), SshError> {
        if bind_address.is_empty() || bind_port == 0 {
            return Err(SshError::InvalidForward);
        }
        self.handle
            .lock()
            .await
            .cancel_tcpip_forward(bind_address, u32::from(bind_port))
            .await
            .map_err(SshError::Russh)
    }

    /// Accepts the next server-opened remote-forward channel.
    pub async fn accept_remote_forward(&self) -> Result<ForwardedConnection, SshError> {
        self.forwarded
            .lock()
            .await
            .recv()
            .await
            .ok_or(SshError::ConnectionClosed)
    }

    /// Gracefully disconnects the SSH session.
    pub async fn disconnect(&self) -> Result<(), SshError> {
        self.handle
            .lock()
            .await
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .map_err(SshError::Russh)
    }
}

/// One accepted remote-forward connection.
pub struct ForwardedConnection {
    connected_address: String,
    connected_port: u32,
    originator_address: String,
    originator_port: u32,
    channel: russh::Channel<client::Msg>,
}

impl ForwardedConnection {
    /// Returns the server-side listener address.
    #[must_use]
    pub fn connected_address(&self) -> &str {
        &self.connected_address
    }

    /// Returns the server-side listener port.
    #[must_use]
    pub const fn connected_port(&self) -> u32 {
        self.connected_port
    }

    /// Returns the remote connection's originator address.
    #[must_use]
    pub fn originator_address(&self) -> &str {
        &self.originator_address
    }

    /// Returns the remote connection's originator port.
    #[must_use]
    pub const fn originator_port(&self) -> u32 {
        self.originator_port
    }

    /// Bridges this remote-forward channel to a local TCP destination.
    pub async fn bridge_to(self, local: &str, port: u16) -> Result<u64, SshError> {
        if local.is_empty() || port == 0 {
            return Err(SshError::InvalidForward);
        }
        let mut socket = TcpStream::connect((local, port))
            .await
            .map_err(SshError::Io)?;
        let mut channel = self.channel.into_stream();
        let (sent, received) = tokio_io::copy_bidirectional(&mut socket, &mut channel)
            .await
            .map_err(SshError::Io)?;
        Ok(sent.saturating_add(received))
    }
}

fn split_directive(line: &str) -> Option<(&str, &str)> {
    if let Some((key, value)) = line.split_once('=') {
        let key = key.trim();
        let value = value.trim();
        return (!key.is_empty() && !value.is_empty()).then_some((key, value));
    }
    let split = line.find(char::is_whitespace)?;
    let key = line[..split].trim();
    let value = line[split..].trim();
    (!key.is_empty() && !value.is_empty()).then_some((key, value))
}

fn set_once(slot: &mut Option<String>, value: &str) {
    if slot.is_none() {
        *slot = Some(value.to_owned());
    }
}

fn host_patterns_match(patterns: &[String], alias: &str) -> bool {
    let mut included = false;
    for pattern in patterns {
        let (negative, pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern.as_str()), |pattern| (true, pattern));
        if wildcard_match(pattern.as_bytes(), alias.as_bytes()) {
            if negative {
                return false;
            }
            included = true;
        }
    }
    included
}

fn wildcard_match(pattern: &[u8], value: &[u8]) -> bool {
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star_index, mut star_value_index) = (None, 0);
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn parse_port(value: &str) -> Result<u16, SshError> {
    let port = value.parse::<u16>().map_err(|_| SshError::InvalidTarget)?;
    if port == 0 {
        return Err(SshError::InvalidTarget);
    }
    Ok(port)
}

fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 128
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// SSH trust or transport failure.
#[derive(Debug)]
pub enum SshError {
    /// Target syntax is malformed or injection-prone.
    InvalidTarget,
    /// Pairing challenge is malformed or uses an unsupported protocol.
    InvalidPairingChallenge,
    /// Pairing proof does not match the expected node identity.
    PairingIdentityMismatch,
    /// Pairing proof is outside the caller's signature window.
    PairingExpired,
    /// Pairing signature did not verify.
    PairingSignature,
    /// Resolved user is malformed.
    InvalidUser,
    /// SSH configuration exceeds the fixed input limit.
    ConfigTooLarge,
    /// SSH configuration syntax is malformed.
    InvalidConfig,
    /// No matching key exists for the target.
    UnknownHost,
    /// A matching host entry has a different key.
    HostKeyMismatch,
    /// Key parsing or known-hosts access failed.
    Key(russh::keys::Error),
    /// Key authentication was rejected.
    AuthenticationFailed,
    /// A forwarding endpoint is malformed.
    InvalidForward,
    /// The caller's stop channel closed without a stop decision.
    StopChannelClosed,
    /// A local-forward session task failed to complete normally.
    ForwardTask(tokio::task::JoinError),
    /// The SSH connection closed before a forwarded channel arrived.
    ConnectionClosed,
    /// Socket I/O failed.
    Io(io::Error),
    /// SSH protocol processing failed.
    Russh(russh::Error),
}

impl From<russh::Error> for SshError {
    fn from(error: russh::Error) -> Self {
        Self::Russh(error)
    }
}

impl Display for SshError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget => formatter.write_str("invalid SSH target"),
            Self::InvalidPairingChallenge => formatter.write_str("invalid SSH pairing challenge"),
            Self::PairingIdentityMismatch => formatter.write_str("SSH pairing identity mismatch"),
            Self::PairingExpired => formatter.write_str("expired SSH pairing proof"),
            Self::PairingSignature => formatter.write_str("invalid SSH pairing signature"),
            Self::InvalidUser => formatter.write_str("invalid SSH user"),
            Self::ConfigTooLarge => formatter.write_str("SSH configuration is too large"),
            Self::InvalidConfig => formatter.write_str("invalid SSH configuration"),
            Self::UnknownHost => formatter.write_str("SSH host is not present in known_hosts"),
            Self::HostKeyMismatch => formatter.write_str("SSH host key mismatch"),
            Self::Key(error) => write!(formatter, "SSH key verification failed: {error}"),
            Self::AuthenticationFailed => formatter.write_str("SSH key authentication failed"),
            Self::InvalidForward => formatter.write_str("invalid SSH forwarding endpoint"),
            Self::StopChannelClosed => formatter.write_str("SSH tunnel stop channel closed"),
            Self::ForwardTask(error) => write!(formatter, "SSH tunnel task failed: {error}"),
            Self::ConnectionClosed => formatter.write_str("SSH connection closed"),
            Self::Io(error) => write!(formatter, "SSH socket I/O failed: {error}"),
            Self::Russh(error) => write!(formatter, "SSH protocol failed: {error}"),
        }
    }
}

impl Error for SshError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Key(error) => Some(error),
            Self::ForwardTask(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Russh(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use russh::keys::parse_public_key_base64;
    use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
    use russh::server;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[test]
    fn parses_targets_without_option_injection() {
        assert_eq!(
            SshTarget::parse("ssh alice@[::1]:2222").expect("valid target"),
            SshTarget {
                user: Some("alice".to_owned()),
                host: "::1".to_owned(),
                port: 2222,
            }
        );
        assert!(matches!(
            SshTarget::parse("-oProxyCommand=bad"),
            Err(SshError::InvalidTarget)
        ));
        assert!(matches!(
            SshTarget::parse("host::22"),
            Err(SshError::InvalidTarget)
        ));
        assert!(matches!(
            SshTarget::parse("bad user@host"),
            Err(SshError::InvalidTarget)
        ));
    }

    #[test]
    fn discovers_and_resolves_bounded_ssh_config() {
        let config = SshConfig::parse(
            r#"
            Host *
              User fallback
              Port 22
            Host studio !studio-old
              HostName 10.0.0.7
              User operator
              Port 2201
              IdentityFile ~/.ssh/studio
            Host *.tail
              Port 2222
            "#,
        )
        .expect("valid config");

        assert_eq!(config.discovered_aliases(), vec!["studio"]);
        assert_eq!(
            config.resolve("studio").expect("resolved"),
            SshHostConfig {
                alias: "studio".to_owned(),
                host_name: "10.0.0.7".to_owned(),
                user: Some("fallback".to_owned()),
                port: 22,
                identity_files: vec![PathBuf::from("~/.ssh/studio")],
            }
        );
        assert_eq!(config.resolve("node.tail").expect("resolved").port, 22);
    }

    #[test]
    fn host_key_mismatch_fails_closed() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gta-claw-known-hosts-{}-{unique}",
            std::process::id()
        ));
        fs::write(
            &path,
            "example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n",
        )
        .expect("fixture");
        let different_key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF",
        )
        .expect("test key");

        let result = verify_known_host(&path, "example.test", 22, &different_key);
        fs::remove_file(path).expect("remove fixture");
        assert!(matches!(result, Err(SshError::HostKeyMismatch)));
    }

    #[test]
    fn rejects_truncated_and_oversized_config() {
        assert!(matches!(
            SshConfig::parse("Host"),
            Err(SshError::InvalidConfig)
        ));
        assert!(matches!(
            SshConfig::parse(&"x".repeat(MAX_CONFIG_BYTES + 1)),
            Err(SshError::ConfigTooLarge)
        ));
    }

    #[test]
    fn pairing_proof_binds_discovered_identity_and_verified_host_key() {
        let mut rng = ChaCha20Rng::seed_from_u64(81);
        let identity = DeviceIdentity::generate(&mut rng);
        let challenge = SshPairingChallenge {
            nonce: [7; 32],
            host_key_fingerprint: "SHA256:known-host-key".to_owned(),
            expected_device_id: identity.device_id(),
            protocol_version: 4,
        };
        let proof = create_pairing_proof(&identity, &challenge, 1_750_000_000_000).expect("proof");

        let verified = verify_pairing_proof(&challenge, &proof, 1_750_000_000_100, 5 * 60 * 1000)
            .expect("verified");

        assert_eq!(verified.device_id(), identity.device_id());
        assert_eq!(verified.public_key(), identity.public_key());

        let mut spoofed_host_key = challenge;
        spoofed_host_key.host_key_fingerprint = "SHA256:attacker-key".to_owned();
        assert!(matches!(
            verify_pairing_proof(&spoofed_host_key, &proof, 1_750_000_000_100, 5 * 60 * 1000),
            Err(SshError::PairingSignature)
        ));
    }

    struct LoopbackSshHandler {
        allowed_key: PublicKey,
        remote_results: mpsc::Sender<Vec<u8>>,
    }

    impl server::Handler for LoopbackSshHandler {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            user: &str,
            public_key: &PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            if user == "node" && public_key == &self.allowed_key {
                Ok(server::Auth::Accept)
            } else {
                Ok(server::Auth::reject())
            }
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            channel: russh::Channel<server::Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            _originator_address: &str,
            _originator_port: u32,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> Result<(), Self::Error> {
            if host_to_connect != "127.0.0.1" || port_to_connect > u32::from(u16::MAX) {
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
            let Ok(mut target) =
                TcpStream::connect((host_to_connect, port_to_connect as u16)).await
            else {
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
                return Ok(());
            };
            reply.accept().await;
            tokio::spawn(async move {
                let mut channel = channel.into_stream();
                let _ = tokio_io::copy_bidirectional(&mut target, &mut channel).await;
            });
            Ok(())
        }

        async fn tcpip_forward(
            &mut self,
            address: &str,
            port: &mut u32,
            session: &mut server::Session,
        ) -> Result<bool, Self::Error> {
            if address != "127.0.0.1" {
                return Ok(false);
            }
            if *port == 0 {
                *port = 39_001;
            }
            let connected_port = *port;
            let handle = session.handle();
            let results = self.remote_results.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                let Ok(channel) = handle
                    .channel_open_forwarded_tcpip("127.0.0.1", connected_port, "127.0.0.1", 45_000)
                    .await
                else {
                    return;
                };
                let mut stream = channel.into_stream();
                if stream.write_all(b"remote-ping").await.is_err()
                    || stream.shutdown().await.is_err()
                {
                    return;
                }
                let mut echoed = Vec::new();
                if stream.read_to_end(&mut echoed).await.is_ok() {
                    let _ = results.send(echoed).await;
                }
            });
            Ok(true)
        }

        async fn cancel_tcpip_forward(
            &mut self,
            address: &str,
            port: u32,
            _session: &mut server::Session,
        ) -> Result<bool, Self::Error> {
            Ok(address == "127.0.0.1" && port != 0)
        }
    }

    async fn start_echo_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("echo listener");
        let port = listener.local_addr().expect("echo address").port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("echo connection");
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await.expect("echo read");
            socket.write_all(&bytes).await.expect("echo write");
            socket.shutdown().await.expect("echo shutdown");
        });
        (port, task)
    }

    async fn start_holding_server() -> (u16, mpsc::Receiver<()>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("holding listener");
        let port = listener.local_addr().expect("holding address").port();
        let (active_tx, active_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("holding accept");
            active_tx.send(()).await.expect("active signal");
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await.expect("holding read");
        });
        (port, active_rx, task)
    }

    fn fixture_path(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gta-claw-ssh-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn loopback_key_auth_local_and_remote_tunnels_complete_lifecycle() {
        let mut server_rng = ChaCha20Rng::seed_from_u64(101);
        let server_key =
            PrivateKey::random(&mut server_rng, Algorithm::Ed25519).expect("server key");
        let server_public = server_key.public_key().clone();
        let mut client_rng = ChaCha20Rng::seed_from_u64(102);
        let client_key =
            PrivateKey::random(&mut client_rng, Algorithm::Ed25519).expect("client key");
        let client_public = client_key.public_key().clone();
        let key_path = fixture_path("identity");
        let known_hosts_path = fixture_path("known-hosts");
        fs::write(
            &key_path,
            client_key
                .to_openssh(LineEnding::LF)
                .expect("private key")
                .as_bytes(),
        )
        .expect("write private key");

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("SSH listener");
        let ssh_port = listener.local_addr().expect("SSH address").port();
        fs::write(
            &known_hosts_path,
            format!(
                "[127.0.0.1]:{ssh_port} {}\n",
                server_public.to_openssh().expect("public key")
            ),
        )
        .expect("write known_hosts");
        let (remote_tx, mut remote_rx) = mpsc::channel(1);
        let mut server_config = server::Config {
            auth_rejection_time: Duration::from_millis(1),
            auth_rejection_time_initial: Some(Duration::from_millis(1)),
            ..server::Config::default()
        };
        server_config.keys.push(server_key);
        let server_task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("SSH connection");
            let running = server::run_stream(
                Arc::new(server_config),
                socket,
                LoopbackSshHandler {
                    allowed_key: client_public,
                    remote_results: remote_tx,
                },
            )
            .await
            .expect("SSH session");
            let _ = running.await;
        });
        let connection = SshConnection::connect(
            SshConnectConfig {
                target: SshTarget {
                    user: Some("node".to_owned()),
                    host: "127.0.0.1".to_owned(),
                    port: ssh_port,
                },
                default_user: "unused".to_owned(),
                identity_file: key_path.clone(),
                known_hosts_file: known_hosts_path.clone(),
                timeout: Duration::from_secs(5),
            },
            None,
        )
        .await
        .expect("authenticated SSH");

        let (local_target_port, local_echo_task) = start_echo_server().await;
        let local_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("local caller listener");
        let local_address = local_listener.local_addr().expect("local address");
        let caller = TcpStream::connect(local_address);
        let accepted = local_listener.accept();
        let (caller, accepted) = tokio::join!(caller, accepted);
        let mut caller = caller.expect("caller");
        let (accepted, originator) = accepted.expect("accepted");
        let originator_host = originator.ip().to_string();
        let forward = connection.forward_local_stream(
            accepted,
            "127.0.0.1",
            local_target_port,
            &originator_host,
            originator.port(),
        );
        let caller_io = async {
            caller.write_all(b"local-ping").await.expect("local write");
            caller.shutdown().await.expect("local shutdown");
            let mut echoed = Vec::new();
            caller.read_to_end(&mut echoed).await.expect("local read");
            echoed
        };
        let (forwarded_bytes, echoed) = tokio::join!(forward, caller_io);
        assert_eq!(forwarded_bytes.expect("local forward"), 20);
        assert_eq!(echoed, b"local-ping");
        local_echo_task.await.expect("local echo task");

        let (holding_port, mut active_rx, holding_task) = start_holding_server().await;
        let served_listener = SshConnection::bind_local("127.0.0.1", 0)
            .await
            .expect("served listener");
        let served_address = served_listener.local_addr().expect("served address");
        let (stop_tx, stop_rx) = watch::channel(false);
        let mut served = Box::pin(connection.serve_local_forward(
            served_listener,
            "127.0.0.1",
            holding_port,
            stop_rx,
        ));
        let mut held_caller = TcpStream::connect(served_address)
            .await
            .expect("held caller");
        held_caller
            .write_all(b"held-open")
            .await
            .expect("held write");
        tokio::select! {
            result = &mut served => panic!("local forward exited early: {result:?}"),
            active = active_rx.recv() => assert_eq!(active, Some(())),
        }
        stop_tx.send(true).expect("stop local forward");
        tokio::time::timeout(Duration::from_secs(5), &mut served)
            .await
            .expect("local forward stop timeout")
            .expect("local forward stop");
        drop(held_caller);
        holding_task.abort();
        if let Err(error) = holding_task.await {
            assert!(error.is_cancelled());
        }

        let (remote_target_port, remote_echo_task) = start_echo_server().await;
        let allocated = connection
            .request_remote_forward("127.0.0.1", 0)
            .await
            .expect("remote forward");
        assert_eq!(allocated, 39_001);
        let forwarded = connection
            .accept_remote_forward()
            .await
            .expect("forwarded connection");
        assert_eq!(forwarded.connected_address(), "127.0.0.1");
        assert_eq!(forwarded.connected_port(), 39_001);
        assert_eq!(forwarded.originator_address(), "127.0.0.1");
        assert_eq!(forwarded.originator_port(), 45_000);
        let bridge = forwarded.bridge_to("127.0.0.1", remote_target_port);
        let remote_result = tokio::time::timeout(Duration::from_secs(5), remote_rx.recv());
        let (bridged_bytes, remote_result) = tokio::join!(bridge, remote_result);
        assert_eq!(bridged_bytes.expect("remote bridge"), 22);
        assert_eq!(
            remote_result
                .expect("remote timeout")
                .expect("remote result"),
            b"remote-ping"
        );
        remote_echo_task.await.expect("remote echo task");

        connection
            .cancel_remote_forward("127.0.0.1", allocated)
            .await
            .expect("cancel remote forward");
        connection.disconnect().await.expect("disconnect");
        server_task.abort();
        fs::remove_file(key_path).expect("remove key");
        fs::remove_file(known_hosts_path).expect("remove known hosts");
    }
}

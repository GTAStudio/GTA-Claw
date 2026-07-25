//! Signed OpenClaw Gateway DNS-SD records and a pure-Rust mDNS runtime.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use claw_security::authorization::{ClientClass, Role, ScopeSet};
use claw_security::identity::{
    DeviceId, DeviceIdentity, DevicePublicKey, DeviceSignature, HandshakeSigningInput,
};
use flume::RecvTimeoutError;
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::{RData, RecordType};
use mdns_sd::{
    DaemonEvent, Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo,
    UnregisterStatus,
};

use crate::identity::{NodeClientKind, NodeIdentity, admit_protocol};

/// Frozen local Gateway service type.
pub const GATEWAY_SERVICE_TYPE: &str = "_openclaw-gw._tcp.local.";
/// Maximum accepted age for a signed discovery beacon.
pub const DEFAULT_SIGNATURE_WINDOW_MILLIS: u64 = 5 * 60 * 1_000;

const SIGNING_NONCE: &[u8] = b"GTA-Claw/mdns-record/v1";
const TXT_AUTH_VERSION: &str = "authV";
const TXT_DEVICE_ID: &str = "deviceId";
const TXT_INSTANCE: &str = "authInstance";
const TXT_PROTOCOL: &str = "protocol";
const TXT_PUBLIC_KEY: &str = "publicKey";
const TXT_SIGNATURE: &str = "signature";
const TXT_SIGNED_AT: &str = "signedAt";
const MAX_INSTANCE_BYTES: usize = 63;
const MAX_TXT_ENTRY_BYTES: usize = 255;

/// Parameters mirrored from the pinned OpenClaw Bonjour advertiser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAdvertisementConfig {
    /// User-visible service instance.
    pub instance_name: String,
    /// Local DNS hostname ending in `.local.`.
    pub host_name: String,
    /// Explicit IPv4 and IPv6 addresses to announce.
    pub addresses: Vec<IpAddr>,
    /// Gateway WebSocket port.
    pub gateway_port: u16,
    /// SSH port advertised to node-connect clients.
    pub ssh_port: Option<u16>,
    /// Whether Gateway TLS is enabled.
    pub gateway_tls: bool,
    /// Optional SHA-256 certificate fingerprint.
    pub gateway_tls_sha256: Option<String>,
    /// Whether direct Gateway reachability was verified.
    pub gateway_direct_reachable: bool,
    /// Optional canvas port.
    pub canvas_port: Option<u16>,
    /// Optional tailnet DNS name.
    pub tailnet_dns: Option<String>,
    /// Optional native CLI path.
    pub cli_path: Option<String>,
}

/// A signed, bounded DNS-SD advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAdvertisement {
    service_type: String,
    instance_name: String,
    host_name: String,
    addresses: Vec<IpAddr>,
    port: u16,
    txt: BTreeMap<String, String>,
}

impl GatewayAdvertisement {
    /// Builds and signs the exact Gateway TXT contract.
    pub fn sign(
        config: GatewayAdvertisementConfig,
        identity: &DeviceIdentity,
        protocol_version: u16,
        signed_at_unix_millis: u64,
    ) -> Result<Self, DnsSdError> {
        Self::sign_for_service(
            GATEWAY_SERVICE_TYPE,
            config,
            identity,
            protocol_version,
            signed_at_unix_millis,
        )
    }

    /// Signs a unicast wide-area DNS-SD record for an explicit service domain.
    pub fn sign_for_service(
        service_type: &str,
        config: GatewayAdvertisementConfig,
        identity: &DeviceIdentity,
        protocol_version: u16,
        signed_at_unix_millis: u64,
    ) -> Result<Self, DnsSdError> {
        admit_protocol(NodeClientKind::Node, protocol_version, true)
            .map_err(|_| DnsSdError::UnsupportedProtocol)?;
        validate_service_type(service_type)?;
        validate_config(&config, service_type)?;

        let mut txt = BTreeMap::from([
            (
                "displayName".to_owned(),
                display_name(&config.instance_name),
            ),
            ("gatewayPort".to_owned(), config.gateway_port.to_string()),
            ("lanHost".to_owned(), config.host_name.clone()),
            ("role".to_owned(), "gateway".to_owned()),
            ("transport".to_owned(), "gateway".to_owned()),
            (TXT_AUTH_VERSION.to_owned(), "1".to_owned()),
            (TXT_DEVICE_ID.to_owned(), identity.device_id().to_string()),
            (TXT_INSTANCE.to_owned(), config.instance_name.clone()),
            (TXT_PROTOCOL.to_owned(), protocol_version.to_string()),
            (
                TXT_PUBLIC_KEY.to_owned(),
                STANDARD_NO_PAD.encode(identity.public_key().as_bytes()),
            ),
            (TXT_SIGNED_AT.to_owned(), signed_at_unix_millis.to_string()),
        ]);
        if let Some(ssh_port) = config.ssh_port {
            txt.insert("sshPort".to_owned(), ssh_port.to_string());
        }
        if config.gateway_tls {
            txt.insert("gatewayTls".to_owned(), "1".to_owned());
        }
        if let Some(fingerprint) = config.gateway_tls_sha256 {
            txt.insert("gatewayTlsSha256".to_owned(), fingerprint);
        }
        if config.gateway_direct_reachable {
            txt.insert("gatewayDirectReachable".to_owned(), "1".to_owned());
        }
        if let Some(canvas_port) = config.canvas_port {
            txt.insert("canvasPort".to_owned(), canvas_port.to_string());
        }
        if let Some(tailnet_dns) = config.tailnet_dns {
            txt.insert("tailnetDns".to_owned(), tailnet_dns);
        }
        if let Some(cli_path) = config.cli_path {
            txt.insert("cliPath".to_owned(), cli_path);
        }
        validate_txt(&txt)?;

        let mut advertisement = Self {
            service_type: service_type.to_owned(),
            instance_name: config.instance_name,
            host_name: config.host_name,
            addresses: canonical_addresses(config.addresses),
            port: config.gateway_port,
            txt,
        };
        let payload = advertisement.canonical_payload();
        let device_id = identity.device_id();
        let signature = identity.sign_handshake(HandshakeSigningInput {
            device_id: &device_id,
            role: Role::Node,
            scopes: ScopeSet::EMPTY,
            protocol_version,
            client_class: ClientClass::AuthenticatedNode,
            signed_at_unix_millis,
            nonce: SIGNING_NONCE,
            challenge: &payload,
        });
        advertisement.txt.insert(
            TXT_SIGNATURE.to_owned(),
            STANDARD_NO_PAD.encode(signature.to_bytes()),
        );
        Ok(advertisement)
    }

    /// Strictly decodes an untrusted resolved DNS-SD record.
    pub fn from_resolved(
        instance_name: impl Into<String>,
        host_name: impl Into<String>,
        addresses: impl IntoIterator<Item = IpAddr>,
        port: u16,
        txt: BTreeMap<String, String>,
    ) -> Result<Self, DnsSdError> {
        Self::from_resolved_service(
            GATEWAY_SERVICE_TYPE,
            instance_name,
            host_name,
            addresses,
            port,
            txt,
        )
    }

    /// Strictly decodes an untrusted record for an explicit DNS-SD service domain.
    pub fn from_resolved_service(
        service_type: &str,
        instance_name: impl Into<String>,
        host_name: impl Into<String>,
        addresses: impl IntoIterator<Item = IpAddr>,
        port: u16,
        txt: BTreeMap<String, String>,
    ) -> Result<Self, DnsSdError> {
        validate_service_type(service_type)?;
        let instance_name = instance_name.into();
        let host_name = host_name.into();
        let addresses = canonical_addresses(addresses.into_iter().collect());
        validate_common(
            &instance_name,
            &host_name,
            &addresses,
            port,
            service_type == GATEWAY_SERVICE_TYPE,
        )?;
        validate_txt(&txt)?;
        Ok(Self {
            service_type: service_type.to_owned(),
            instance_name,
            host_name,
            addresses,
            port,
            txt,
        })
    }

    /// Verifies identity binding, timestamp, protocol, and every endpoint byte.
    pub fn verify(
        &self,
        now_unix_millis: u64,
        signature_window_millis: u64,
    ) -> Result<VerifiedGateway, DnsSdError> {
        if self.txt.get(TXT_AUTH_VERSION).map(String::as_str) != Some("1") {
            return Err(DnsSdError::UnsupportedAuthVersion);
        }
        if self.txt.get(TXT_INSTANCE) != Some(&self.instance_name) {
            return Err(DnsSdError::InstanceMismatch);
        }
        let protocol_version = parse_u16(self.txt.get(TXT_PROTOCOL), "protocol")?;
        admit_protocol(NodeClientKind::Node, protocol_version, true)
            .map_err(|_| DnsSdError::UnsupportedProtocol)?;
        let signed_at = parse_u64(self.txt.get(TXT_SIGNED_AT), "signedAt")?;
        if now_unix_millis.abs_diff(signed_at) > signature_window_millis {
            return Err(DnsSdError::ExpiredSignature);
        }

        let public_key_bytes = decode_base64(self.txt.get(TXT_PUBLIC_KEY), "publicKey")?;
        let public_key =
            DevicePublicKey::decode(&public_key_bytes).map_err(|_| DnsSdError::InvalidPublicKey)?;
        let claimed_id = self
            .txt
            .get(TXT_DEVICE_ID)
            .ok_or(DnsSdError::MissingTxtField("deviceId"))?;
        let device_id = DeviceId::parse(claimed_id).map_err(|_| DnsSdError::InvalidDeviceId)?;
        let node_identity =
            NodeIdentity::new(device_id, public_key).map_err(|_| DnsSdError::DeviceIdMismatch)?;

        let signature_bytes = decode_base64(self.txt.get(TXT_SIGNATURE), "signature")?;
        let signature =
            DeviceSignature::decode(&signature_bytes).map_err(|_| DnsSdError::InvalidSignature)?;
        let payload = self.canonical_payload();
        public_key
            .verify_handshake(
                HandshakeSigningInput {
                    device_id: &device_id,
                    role: Role::Node,
                    scopes: ScopeSet::EMPTY,
                    protocol_version,
                    client_class: ClientClass::AuthenticatedNode,
                    signed_at_unix_millis: signed_at,
                    nonce: SIGNING_NONCE,
                    challenge: &payload,
                },
                &signature,
            )
            .map_err(|_| DnsSdError::InvalidSignature)?;

        Ok(VerifiedGateway {
            identity: node_identity,
            service_type: self.service_type.clone(),
            instance_name: self.instance_name.clone(),
            host_name: self.host_name.clone(),
            addresses: self.addresses.clone(),
            port: self.port,
            gateway_tls: truthy(self.txt.get("gatewayTls")),
            gateway_tls_sha256: self.txt.get("gatewayTlsSha256").cloned(),
            ssh_port: optional_port(self.txt.get("sshPort"))?,
            txt: self.txt.clone(),
        })
    }

    /// Returns the exact TXT map submitted to DNS-SD.
    #[must_use]
    pub const fn txt(&self) -> &BTreeMap<String, String> {
        &self.txt
    }

    /// Returns the authenticated DNS-SD service type.
    #[must_use]
    pub fn service_type(&self) -> &str {
        &self.service_type
    }

    fn canonical_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        append_field(&mut payload, self.service_type.as_bytes());
        append_field(&mut payload, self.instance_name.as_bytes());
        append_field(&mut payload, self.host_name.as_bytes());
        payload.extend_from_slice(&self.port.to_be_bytes());
        for address in &self.addresses {
            append_field(&mut payload, address.to_string().as_bytes());
        }
        for (key, value) in self
            .txt
            .iter()
            .filter(|(key, _)| key.as_str() != TXT_SIGNATURE)
        {
            append_field(&mut payload, key.as_bytes());
            append_field(&mut payload, value.as_bytes());
        }
        payload
    }

    fn service_info(&self) -> Result<ServiceInfo, DnsSdError> {
        if self.service_type != GATEWAY_SERVICE_TYPE {
            return Err(DnsSdError::UnexpectedServiceType);
        }
        let properties = self
            .txt
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<HashMap<_, _>>();
        ServiceInfo::new(
            GATEWAY_SERVICE_TYPE,
            &self.instance_name,
            &self.host_name,
            self.addresses.as_slice(),
            self.port,
            properties,
        )
        .map_err(DnsSdError::Mdns)
    }

    fn validate_own_signature(&self) -> Result<(), DnsSdError> {
        let signed_at = parse_u64(self.txt.get(TXT_SIGNED_AT), "signedAt")?;
        self.verify(signed_at, 0).map(|_| ())
    }

    fn fullname(&self) -> String {
        format!("{}.{}", self.instance_name, self.service_type)
    }
}

/// An authenticated Gateway resolved from DNS-SD.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGateway {
    identity: NodeIdentity,
    instance_name: String,
    host_name: String,
    addresses: Vec<IpAddr>,
    port: u16,
    gateway_tls: bool,
    gateway_tls_sha256: Option<String>,
    ssh_port: Option<u16>,
    txt: BTreeMap<String, String>,
    service_type: String,
}

impl VerifiedGateway {
    /// Returns the authenticated node identity.
    #[must_use]
    pub const fn identity(&self) -> NodeIdentity {
        self.identity
    }

    /// Returns the user-visible instance name.
    #[must_use]
    pub fn instance_name(&self) -> &str {
        &self.instance_name
    }

    /// Returns the resolved DNS hostname.
    #[must_use]
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    /// Returns all resolved IPv4 and IPv6 addresses in canonical order.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Returns the Gateway port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns whether TLS is required.
    #[must_use]
    pub const fn gateway_tls(&self) -> bool {
        self.gateway_tls
    }

    /// Returns the optional TLS certificate fingerprint.
    #[must_use]
    pub fn gateway_tls_sha256(&self) -> Option<&str> {
        self.gateway_tls_sha256.as_deref()
    }

    /// Returns the optional SSH port.
    #[must_use]
    pub const fn ssh_port(&self) -> Option<u16> {
        self.ssh_port
    }

    /// Returns the authenticated TXT properties.
    #[must_use]
    pub const fn txt(&self) -> &BTreeMap<String, String> {
        &self.txt
    }

    /// Returns the authenticated DNS-SD service type.
    #[must_use]
    pub fn service_type(&self) -> &str {
        &self.service_type
    }
}

/// Allocates the RFC 6762 conflict suffix used by the pure-Rust responder.
#[must_use]
pub fn resolve_instance_collision<'a>(
    requested: &str,
    existing: impl IntoIterator<Item = &'a str>,
) -> String {
    let existing = existing.into_iter().collect::<BTreeSet<_>>();
    if !existing.contains(requested) {
        return requested.to_owned();
    }
    (2_u32..)
        .map(|suffix| format!("{requested} ({suffix})"))
        .find(|candidate| !existing.contains(candidate.as_str()))
        .expect("the unbounded numeric suffix space always has a free name")
}

/// One fully resolved wide-area DNS-SD fixture or resolver result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WideAreaDnsRecord {
    /// PTR target naming the service instance.
    pub instance_fqdn: String,
    /// SRV target hostname.
    pub host_name: String,
    /// SRV port.
    pub port: u16,
    /// Resolved A and AAAA records.
    pub addresses: Vec<IpAddr>,
    /// Individual TXT character strings.
    pub txt_strings: Vec<Vec<u8>>,
}

/// Resolves wide-area DNS-SD through the operating system's configured unicast DNS.
pub struct WideAreaDnsBrowser {
    resolver: TokioResolver,
    service_type: String,
}

impl WideAreaDnsBrowser {
    /// Creates a browser for `_openclaw-gw._tcp.<zone>`.
    pub fn new(zone: &str) -> Result<Self, DnsSdError> {
        let zone = zone.trim();
        let zone = if zone.ends_with('.') {
            zone.to_owned()
        } else {
            format!("{zone}.")
        };
        let service_type = format!("_openclaw-gw._tcp.{zone}");
        validate_service_type(&service_type)?;
        let resolver = TokioResolver::builder_tokio()
            .map_err(DnsSdError::Resolve)?
            .build()
            .map_err(DnsSdError::Resolve)?;
        Ok(Self {
            resolver,
            service_type,
        })
    }

    /// Browses PTR, SRV, TXT, A, and AAAA records and authenticates each result.
    pub async fn browse(
        &self,
        now_unix_millis: u64,
        signature_window_millis: u64,
    ) -> Result<Vec<VerifiedGateway>, DnsSdError> {
        let pointer_lookup = self
            .resolver
            .lookup(self.service_type.as_str(), RecordType::PTR)
            .await
            .map_err(DnsSdError::Resolve)?;
        let mut instance_names = pointer_lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                RData::PTR(pointer) => Some(pointer.0.to_utf8()),
                _ => None,
            })
            .collect::<Vec<_>>();
        instance_names.sort();
        instance_names.dedup();
        let mut verified = Vec::with_capacity(instance_names.len());
        for instance_fqdn in instance_names {
            let service_lookup = self
                .resolver
                .srv_lookup(instance_fqdn.as_str())
                .await
                .map_err(DnsSdError::Resolve)?;
            let services = service_lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::SRV(service) => Some(service),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if services.len() != 1 {
                return Err(DnsSdError::AmbiguousWideAreaRecord);
            }
            let service = services[0];
            let host_name = service.target.to_utf8();
            let addresses = self
                .resolver
                .lookup_ip(host_name.as_str())
                .await
                .map_err(DnsSdError::Resolve)?
                .iter()
                .collect::<Vec<_>>();
            let txt_lookup = self
                .resolver
                .txt_lookup(instance_fqdn.as_str())
                .await
                .map_err(DnsSdError::Resolve)?;
            let txt_strings = txt_lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(txt),
                    _ => None,
                })
                .flat_map(|txt| txt.txt_data.iter().map(|value| value.to_vec()))
                .collect();
            let record = WideAreaDnsRecord {
                instance_fqdn,
                host_name,
                port: service.port,
                addresses,
                txt_strings,
            };
            verified.push(resolve_wide_area_fixture(
                &self.service_type,
                &record,
                now_unix_millis,
                signature_window_millis,
            )?);
        }
        Ok(verified)
    }
}

/// Resolves and authenticates one deterministic wide-area DNS-SD fixture.
pub fn resolve_wide_area_fixture(
    service_type: &str,
    record: &WideAreaDnsRecord,
    now_unix_millis: u64,
    signature_window_millis: u64,
) -> Result<VerifiedGateway, DnsSdError> {
    validate_service_type(service_type)?;
    let mut txt = BTreeMap::new();
    for raw in &record.txt_strings {
        if raw.is_empty() || raw.len() > MAX_TXT_ENTRY_BYTES {
            return Err(DnsSdError::InvalidTxtValue);
        }
        let value = std::str::from_utf8(raw).map_err(|_| DnsSdError::InvalidTxtValue)?;
        let (key, value) = value.split_once('=').ok_or(DnsSdError::InvalidTxtValue)?;
        if key.is_empty() || txt.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(DnsSdError::DuplicateTxtField);
        }
    }
    let instance = txt
        .get(TXT_INSTANCE)
        .cloned()
        .ok_or(DnsSdError::MissingTxtField("authInstance"))?;
    let expected_owner = format!("{instance}.{service_type}");
    if !record.instance_fqdn.eq_ignore_ascii_case(&expected_owner) {
        return Err(DnsSdError::InstanceMismatch);
    }
    GatewayAdvertisement::from_resolved_service(
        service_type,
        instance,
        record.host_name.clone(),
        record.addresses.iter().copied(),
        record.port,
        txt,
    )?
    .verify(now_unix_millis, signature_window_millis)
}

/// Active pure-Rust mDNS advertisement.
pub struct MdnsAdvertiser {
    daemon: ServiceDaemon,
    advertisement: GatewayAdvertisement,
    monitor: Receiver<DaemonEvent>,
}

impl MdnsAdvertiser {
    /// Starts advertising the exact signed IPv4/IPv6 address set.
    pub fn start(advertisement: &GatewayAdvertisement) -> Result<Self, DnsSdError> {
        advertisement.validate_own_signature()?;
        let daemon = ServiceDaemon::new().map_err(DnsSdError::Mdns)?;
        let monitor = daemon.monitor().map_err(DnsSdError::Mdns)?;
        let service = advertisement.service_info()?;
        daemon.register(service).map_err(DnsSdError::Mdns)?;
        Ok(Self {
            daemon,
            advertisement: advertisement.clone(),
            monitor,
        })
    }

    /// Replaces the signed record after an address or collision change.
    ///
    /// Callers must construct a newly signed advertisement from the observed runtime event.
    pub fn replace(
        &mut self,
        advertisement: &GatewayAdvertisement,
        timeout: Duration,
    ) -> Result<(), DnsSdError> {
        advertisement.validate_own_signature()?;
        let replacement = advertisement.service_info()?;
        let previous = self.advertisement.service_info()?;
        let withdrawn = self
            .daemon
            .unregister(&self.advertisement.fullname())
            .map_err(DnsSdError::Mdns)?
            .recv_timeout(timeout)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => DnsSdError::OperationTimedOut,
                RecvTimeoutError::Disconnected => DnsSdError::ChannelClosed,
            })?;
        if !matches!(withdrawn, UnregisterStatus::OK) {
            return Err(DnsSdError::UnregisterFailed);
        }
        if let Err(operation) = self.daemon.register(replacement) {
            return match self.daemon.register(previous) {
                Ok(()) => Err(DnsSdError::Mdns(operation)),
                Err(rollback) => Err(DnsSdError::RegistrationRollbackFailed {
                    operation: operation.to_string(),
                    rollback: rollback.to_string(),
                }),
            };
        }
        self.advertisement = advertisement.clone();
        Ok(())
    }

    /// Receives a conflict, address-change, or daemon error event.
    pub fn next_event(&self, timeout: Duration) -> Result<Option<MdnsRuntimeEvent>, DnsSdError> {
        match self.monitor.recv_timeout(timeout) {
            Ok(DaemonEvent::NameChange(change)) => Ok(Some(MdnsRuntimeEvent::NameChanged {
                original: change.original,
                replacement: change.new_name,
            })),
            Ok(DaemonEvent::IpAdd(address)) => Ok(Some(MdnsRuntimeEvent::AddressAdded(address))),
            Ok(DaemonEvent::IpDel(address)) => Ok(Some(MdnsRuntimeEvent::AddressRemoved(address))),
            Ok(DaemonEvent::Error(error)) => Err(DnsSdError::Mdns(error)),
            Ok(_) => Ok(Some(MdnsRuntimeEvent::Activity)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(DnsSdError::ChannelClosed),
        }
    }

    /// Gracefully withdraws the record and stops the daemon.
    pub fn shutdown(self, timeout: Duration) -> Result<(), DnsSdError> {
        let unregistered = self
            .daemon
            .unregister(&self.advertisement.fullname())
            .map_err(DnsSdError::Mdns)?
            .recv_timeout(timeout)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => DnsSdError::OperationTimedOut,
                RecvTimeoutError::Disconnected => DnsSdError::ChannelClosed,
            })?;
        if !matches!(unregistered, UnregisterStatus::OK) {
            return Err(DnsSdError::UnregisterFailed);
        }
        self.daemon
            .shutdown()
            .map_err(DnsSdError::Mdns)?
            .recv_timeout(timeout)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => DnsSdError::OperationTimedOut,
                RecvTimeoutError::Disconnected => DnsSdError::ChannelClosed,
            })?;
        Ok(())
    }
}

/// Observable mDNS runtime change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MdnsRuntimeEvent {
    /// A service or hostname collision was resolved.
    NameChanged {
        /// Original DNS name.
        original: String,
        /// Replacement DNS name.
        replacement: String,
    },
    /// An interface gained an address.
    AddressAdded(IpAddr),
    /// An interface lost an address.
    AddressRemoved(IpAddr),
    /// Non-security-sensitive responder activity.
    Activity,
}

/// Active pure-Rust mDNS browser.
pub struct MdnsBrowser {
    daemon: ServiceDaemon,
    receiver: Receiver<ServiceEvent>,
}

impl MdnsBrowser {
    /// Starts browsing the frozen local Gateway service type.
    pub fn start() -> Result<Self, DnsSdError> {
        let daemon = ServiceDaemon::new().map_err(DnsSdError::Mdns)?;
        let receiver = daemon
            .browse(GATEWAY_SERVICE_TYPE)
            .map_err(DnsSdError::Mdns)?;
        Ok(Self { daemon, receiver })
    }

    /// Returns the next authenticated resolution or removal event.
    pub fn next_event(
        &self,
        timeout: Duration,
        now_unix_millis: u64,
        signature_window_millis: u64,
    ) -> Result<Option<DiscoveryEvent>, DnsSdError> {
        match self.receiver.recv_timeout(timeout) {
            Ok(ServiceEvent::ServiceResolved(service)) => {
                let advertisement = advertisement_from_mdns(&service)?;
                advertisement
                    .verify(now_unix_millis, signature_window_millis)
                    .map(Box::new)
                    .map(DiscoveryEvent::Resolved)
                    .map(Some)
            }
            Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                Ok(Some(DiscoveryEvent::Removed(fullname)))
            }
            Ok(_) => Ok(None),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(DnsSdError::ChannelClosed),
        }
    }

    /// Stops browsing and shuts down the daemon.
    pub fn shutdown(self, timeout: Duration) -> Result<(), DnsSdError> {
        self.daemon
            .stop_browse(GATEWAY_SERVICE_TYPE)
            .map_err(DnsSdError::Mdns)?;
        self.daemon
            .shutdown()
            .map_err(DnsSdError::Mdns)?
            .recv_timeout(timeout)
            .map_err(|error| match error {
                RecvTimeoutError::Timeout => DnsSdError::OperationTimedOut,
                RecvTimeoutError::Disconnected => DnsSdError::ChannelClosed,
            })?;
        Ok(())
    }
}

/// Authenticated browser event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryEvent {
    /// A valid signed Gateway record was resolved.
    Resolved(Box<VerifiedGateway>),
    /// A previously resolved service fullname disappeared.
    Removed(String),
}

fn advertisement_from_mdns(service: &ResolvedService) -> Result<GatewayAdvertisement, DnsSdError> {
    if service.ty_domain != GATEWAY_SERVICE_TYPE {
        return Err(DnsSdError::UnexpectedServiceType);
    }
    let suffix = format!(".{}", service.ty_domain);
    let instance = service
        .fullname
        .strip_suffix(&suffix)
        .filter(|instance| !instance.is_empty())
        .ok_or(DnsSdError::InvalidInstanceName)?
        .to_owned();
    let txt = service
        .txt_properties
        .iter()
        .map(|property| {
            if property.val().is_none() {
                return Err(DnsSdError::InvalidTxtValue);
            }
            Ok((property.key().to_owned(), property.val_str().to_owned()))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    GatewayAdvertisement::from_resolved(
        instance,
        service.host.clone(),
        service.addresses.iter().map(mdns_sd::ScopedIp::to_ip_addr),
        service.port,
        txt,
    )
}

fn validate_config(
    config: &GatewayAdvertisementConfig,
    service_type: &str,
) -> Result<(), DnsSdError> {
    validate_common(
        &config.instance_name,
        &config.host_name,
        &config.addresses,
        config.gateway_port,
        service_type == GATEWAY_SERVICE_TYPE,
    )?;
    if config.ssh_port == Some(0) || config.canvas_port == Some(0) {
        return Err(DnsSdError::InvalidPort);
    }
    for value in [
        config.gateway_tls_sha256.as_deref(),
        config.tailnet_dns.as_deref(),
        config.cli_path.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_text(value)?;
    }
    Ok(())
}

fn validate_common(
    instance_name: &str,
    host_name: &str,
    addresses: &[IpAddr],
    port: u16,
    require_local_host: bool,
) -> Result<(), DnsSdError> {
    if instance_name.trim().is_empty()
        || instance_name.trim() != instance_name
        || instance_name.len() > MAX_INSTANCE_BYTES
        || instance_name.chars().any(char::is_control)
        || instance_name.contains(['.', '\\'])
    {
        return Err(DnsSdError::InvalidInstanceName);
    }
    if !valid_dns_name(host_name, false)
        || (require_local_host && !host_name.ends_with(".local."))
        || (require_local_host && host_name == ".local.")
    {
        return Err(DnsSdError::InvalidHostName);
    }
    if addresses.is_empty() {
        return Err(DnsSdError::MissingAddress);
    }
    if port == 0 {
        return Err(DnsSdError::InvalidPort);
    }
    Ok(())
}

fn validate_service_type(service_type: &str) -> Result<(), DnsSdError> {
    let Some(zone) = service_type.strip_prefix("_openclaw-gw._tcp.") else {
        return Err(DnsSdError::UnexpectedServiceType);
    };
    if !valid_dns_name(zone, false) {
        return Err(DnsSdError::UnexpectedServiceType);
    }
    Ok(())
}

fn valid_dns_name(name: &str, allow_underscore: bool) -> bool {
    if !name.ends_with('.') || name.len() > 253 || !name.is_ascii() {
        return false;
    }
    name[..name.len() - 1].split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-' || (allow_underscore && byte == b'_')
            })
    })
}

fn validate_text(value: &str) -> Result<(), DnsSdError> {
    if value.trim() != value || value.is_empty() || value.chars().any(char::is_control) {
        return Err(DnsSdError::InvalidTxtValue);
    }
    Ok(())
}

fn validate_txt(txt: &BTreeMap<String, String>) -> Result<(), DnsSdError> {
    for (key, value) in txt {
        if key.is_empty()
            || !key.is_ascii()
            || key.contains('=')
            || key.len() + 1 + value.len() > MAX_TXT_ENTRY_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(DnsSdError::InvalidTxtValue);
        }
    }
    Ok(())
}

fn display_name(instance: &str) -> String {
    instance
        .strip_suffix(" (OpenClaw)")
        .unwrap_or(instance)
        .trim()
        .to_owned()
}

fn canonical_addresses(mut addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

fn append_field(payload: &mut Vec<u8>, field: &[u8]) {
    let length = u32::try_from(field.len()).expect("bounded DNS-SD fields fit in u32");
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(field);
}

fn decode_base64(value: Option<&String>, field: &'static str) -> Result<Vec<u8>, DnsSdError> {
    let value = value.ok_or(DnsSdError::MissingTxtField(field))?;
    STANDARD_NO_PAD
        .decode(value)
        .map_err(|_| DnsSdError::InvalidBase64(field))
}

fn parse_u16(value: Option<&String>, field: &'static str) -> Result<u16, DnsSdError> {
    let parsed = parse_u64(value, field)?;
    u16::try_from(parsed).map_err(|_| DnsSdError::InvalidNumber(field))
}

fn parse_u64(value: Option<&String>, field: &'static str) -> Result<u64, DnsSdError> {
    value
        .ok_or(DnsSdError::MissingTxtField(field))?
        .parse()
        .map_err(|_| DnsSdError::InvalidNumber(field))
}

fn optional_port(value: Option<&String>) -> Result<Option<u16>, DnsSdError> {
    value
        .map(|value| {
            let port = value
                .parse::<u16>()
                .map_err(|_| DnsSdError::InvalidNumber("sshPort"))?;
            if port == 0 {
                return Err(DnsSdError::InvalidPort);
            }
            Ok(port)
        })
        .transpose()
}

fn truthy(value: Option<&String>) -> bool {
    value.is_some_and(|value| {
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
}

/// Strict DNS-SD boundary failure.
#[derive(Debug)]
pub enum DnsSdError {
    /// Service instance violates DNS-SD bounds.
    InvalidInstanceName,
    /// Hostname is not a valid absolute DNS hostname.
    InvalidHostName,
    /// No IPv4 or IPv6 address was supplied.
    MissingAddress,
    /// A zero or malformed port was supplied.
    InvalidPort,
    /// TXT data is malformed or oversized.
    InvalidTxtValue,
    /// A TXT key occurs more than once.
    DuplicateTxtField,
    /// A required TXT field is absent.
    MissingTxtField(&'static str),
    /// A numeric TXT field is malformed.
    InvalidNumber(&'static str),
    /// A base64 TXT field is malformed.
    InvalidBase64(&'static str),
    /// The discovery authentication version is not supported.
    UnsupportedAuthVersion,
    /// The protocol version is outside the authenticated node window.
    UnsupportedProtocol,
    /// The signed timestamp is outside the caller's replay window.
    ExpiredSignature,
    /// The public key is malformed.
    InvalidPublicKey,
    /// The claimed device identifier is malformed.
    InvalidDeviceId,
    /// The claimed device identifier does not match the key.
    DeviceIdMismatch,
    /// The signature is malformed or does not verify.
    InvalidSignature,
    /// The signed instance name differs from the resolved instance.
    InstanceMismatch,
    /// A result for another service type reached this browser.
    UnexpectedServiceType,
    /// A wide-area instance had zero or multiple SRV records.
    AmbiguousWideAreaRecord,
    /// The responder or browser channel closed unexpectedly.
    ChannelClosed,
    /// A bounded responder operation timed out.
    OperationTimedOut,
    /// Graceful record withdrawal failed.
    UnregisterFailed,
    /// Updating a record failed and restoring the previous record also failed.
    RegistrationRollbackFailed {
        /// Replacement registration failure.
        operation: String,
        /// Previous-record restoration failure.
        rollback: String,
    },
    /// The pure-Rust mDNS engine rejected an operation.
    Mdns(mdns_sd::Error),
    /// The unicast DNS resolver rejected a lookup.
    Resolve(hickory_resolver::net::NetError),
}

impl Display for DnsSdError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInstanceName => formatter.write_str("invalid DNS-SD instance name"),
            Self::InvalidHostName => formatter.write_str("invalid mDNS hostname"),
            Self::MissingAddress => formatter.write_str("DNS-SD record has no address"),
            Self::InvalidPort => formatter.write_str("invalid DNS-SD port"),
            Self::InvalidTxtValue => formatter.write_str("invalid DNS-SD TXT value"),
            Self::DuplicateTxtField => formatter.write_str("duplicate DNS-SD TXT field"),
            Self::MissingTxtField(field) => write!(formatter, "missing DNS-SD TXT field {field}"),
            Self::InvalidNumber(field) => write!(formatter, "invalid numeric TXT field {field}"),
            Self::InvalidBase64(field) => write!(formatter, "invalid base64 TXT field {field}"),
            Self::UnsupportedAuthVersion => {
                formatter.write_str("unsupported DNS-SD authentication version")
            }
            Self::UnsupportedProtocol => formatter.write_str("unsupported node protocol version"),
            Self::ExpiredSignature => formatter.write_str("expired DNS-SD signature"),
            Self::InvalidPublicKey => formatter.write_str("invalid DNS-SD public key"),
            Self::InvalidDeviceId => formatter.write_str("invalid DNS-SD device id"),
            Self::DeviceIdMismatch => formatter.write_str("DNS-SD device id mismatch"),
            Self::InvalidSignature => formatter.write_str("invalid DNS-SD signature"),
            Self::InstanceMismatch => formatter.write_str("DNS-SD instance mismatch"),
            Self::UnexpectedServiceType => formatter.write_str("unexpected DNS-SD service type"),
            Self::AmbiguousWideAreaRecord => {
                formatter.write_str("ambiguous wide-area DNS-SD SRV record")
            }
            Self::ChannelClosed => formatter.write_str("mDNS channel closed"),
            Self::OperationTimedOut => formatter.write_str("mDNS operation timed out"),
            Self::UnregisterFailed => formatter.write_str("mDNS record withdrawal failed"),
            Self::RegistrationRollbackFailed {
                operation,
                rollback,
            } => write!(
                formatter,
                "mDNS update failed ({operation}) and restoration failed ({rollback})"
            ),
            Self::Mdns(error) => Display::fmt(error, formatter),
            Self::Resolve(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for DnsSdError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Mdns(error) => Some(error),
            Self::Resolve(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::*;

    fn signed_advertisement() -> GatewayAdvertisement {
        let mut rng = ChaCha20Rng::seed_from_u64(17);
        let identity = DeviceIdentity::generate(&mut rng);
        GatewayAdvertisement::sign(
            GatewayAdvertisementConfig {
                instance_name: "Studio Mac (OpenClaw)".to_owned(),
                host_name: "studio-mac.local.".to_owned(),
                addresses: vec![
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                ],
                gateway_port: 18_790,
                ssh_port: Some(22),
                gateway_tls: true,
                gateway_tls_sha256: Some("a".repeat(64)),
                gateway_direct_reachable: true,
                canvas_port: Some(18_791),
                tailnet_dns: Some("studio.tail.example".to_owned()),
                cli_path: Some("/opt/gta-claw".to_owned()),
            },
            &identity,
            4,
            1_750_000_000_000,
        )
        .expect("valid fixture")
    }

    #[test]
    fn emits_the_pinned_gateway_txt_contract_and_both_ip_families() {
        let advertisement = signed_advertisement();
        let txt = advertisement.txt();

        assert_eq!(txt.get("role").map(String::as_str), Some("gateway"));
        assert_eq!(txt.get("gatewayPort").map(String::as_str), Some("18790"));
        assert_eq!(
            txt.get("lanHost").map(String::as_str),
            Some("studio-mac.local.")
        );
        assert_eq!(
            txt.get("displayName").map(String::as_str),
            Some("Studio Mac")
        );
        assert_eq!(txt.get("transport").map(String::as_str), Some("gateway"));
        assert_eq!(txt.get("sshPort").map(String::as_str), Some("22"));
        assert_eq!(txt.get("gatewayTls").map(String::as_str), Some("1"));
        assert_eq!(
            advertisement.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
        );
        let service = advertisement.service_info().expect("mDNS service");
        assert!(!service.is_addr_auto());
        assert_eq!(service.get_port(), 18_790);
    }

    #[test]
    fn rejects_instance_names_that_mdns_would_escape() {
        let mut rng = ChaCha20Rng::seed_from_u64(18);
        let identity = DeviceIdentity::generate(&mut rng);
        for instance_name in ["Studio.Gateway", r"Studio\Gateway"] {
            let result = GatewayAdvertisement::sign(
                GatewayAdvertisementConfig {
                    instance_name: instance_name.to_owned(),
                    host_name: "studio.local.".to_owned(),
                    addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                    gateway_port: 18_790,
                    ssh_port: None,
                    gateway_tls: false,
                    gateway_tls_sha256: None,
                    gateway_direct_reachable: false,
                    canvas_port: None,
                    tailnet_dns: None,
                    cli_path: None,
                },
                &identity,
                4,
                1_750_000_000_000,
            );
            assert!(matches!(result, Err(DnsSdError::InvalidInstanceName)));
        }
    }

    #[test]
    fn mdns_advertise_discover_fixture_authenticates_exact_record() {
        let advertisement = signed_advertisement();
        let resolved = advertisement
            .service_info()
            .expect("mDNS advertisement")
            .as_resolved_service();

        let verified = advertisement_from_mdns(&resolved)
            .expect("bounded discovery record")
            .verify(1_750_000_000_010, DEFAULT_SIGNATURE_WINDOW_MILLIS)
            .expect("authenticated discovery");

        assert_eq!(verified.instance_name(), "Studio Mac (OpenClaw)");
        assert_eq!(verified.host_name(), "studio-mac.local.");
        assert_eq!(
            verified.addresses(),
            [
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
        );
        assert_eq!(verified.port(), 18_790);
        assert_eq!(verified.ssh_port(), Some(22));
        assert!(verified.gateway_tls());
        assert_eq!(
            verified.gateway_tls_sha256(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(verified.service_type(), GATEWAY_SERVICE_TYPE);
    }

    #[test]
    fn rejects_spoofed_endpoint_and_txt_data() {
        let advertisement = signed_advertisement();
        let mut spoofed_port = advertisement.clone();
        spoofed_port.port = 18_792;
        assert!(matches!(
            spoofed_port.verify(1_750_000_000_010, DEFAULT_SIGNATURE_WINDOW_MILLIS),
            Err(DnsSdError::InvalidSignature)
        ));

        let mut spoofed_host = advertisement.clone();
        spoofed_host.host_name = "attacker.local.".to_owned();
        assert!(matches!(
            spoofed_host.verify(1_750_000_000_010, DEFAULT_SIGNATURE_WINDOW_MILLIS),
            Err(DnsSdError::InvalidSignature)
        ));

        let mut spoofed_txt = advertisement;
        spoofed_txt
            .txt
            .insert("gatewayDirectReachable".to_owned(), "0".to_owned());
        assert!(matches!(
            spoofed_txt.verify(1_750_000_000_010, DEFAULT_SIGNATURE_WINDOW_MILLIS),
            Err(DnsSdError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_a_signed_record_replayed_under_another_dns_owner() {
        let advertisement = signed_advertisement();
        let mut resolved = advertisement
            .service_info()
            .expect("service info")
            .as_resolved_service();
        resolved.fullname = format!("Attacker.{}", GATEWAY_SERVICE_TYPE);

        let replayed = advertisement_from_mdns(&resolved).expect("bounded record");

        assert!(matches!(
            replayed.verify(1_750_000_000_010, DEFAULT_SIGNATURE_WINDOW_MILLIS),
            Err(DnsSdError::InstanceMismatch)
        ));
    }

    #[test]
    fn rejects_expired_and_oversized_records() {
        let advertisement = signed_advertisement();
        assert!(matches!(
            advertisement.verify(1_750_000_600_001, DEFAULT_SIGNATURE_WINDOW_MILLIS),
            Err(DnsSdError::ExpiredSignature)
        ));

        let mut txt = advertisement.txt.clone();
        txt.insert("oversized".to_owned(), "x".repeat(250));
        assert!(matches!(
            GatewayAdvertisement::from_resolved(
                advertisement.instance_name,
                advertisement.host_name,
                advertisement.addresses,
                advertisement.port,
                txt
            ),
            Err(DnsSdError::InvalidTxtValue)
        ));
    }

    #[test]
    fn allocates_deterministic_collision_suffixes() {
        assert_eq!(
            resolve_instance_collision("OpenClaw", ["OpenClaw", "OpenClaw (2)", "OpenClaw (4)"]),
            "OpenClaw (3)"
        );
        assert_eq!(
            resolve_instance_collision("OpenClaw", ["Different"]),
            "OpenClaw"
        );
    }

    #[test]
    fn wide_area_fixture_matches_srv_txt_a_and_aaaa_contract() {
        let mut rng = ChaCha20Rng::seed_from_u64(23);
        let identity = DeviceIdentity::generate(&mut rng);
        let service_type = "_openclaw-gw._tcp.discovery.example.";
        let advertisement = GatewayAdvertisement::sign_for_service(
            service_type,
            GatewayAdvertisementConfig {
                instance_name: "Studio Gateway".to_owned(),
                host_name: "gateway.discovery.example.".to_owned(),
                addresses: vec![
                    "203.0.113.8".parse().expect("IPv4"),
                    "2001:db8::8".parse().expect("IPv6"),
                ],
                gateway_port: 18_790,
                ssh_port: Some(2222),
                gateway_tls: true,
                gateway_tls_sha256: Some("b".repeat(64)),
                gateway_direct_reachable: true,
                canvas_port: None,
                tailnet_dns: None,
                cli_path: None,
            },
            &identity,
            4,
            1_750_000_000_000,
        )
        .expect("wide-area advertisement");
        let record = WideAreaDnsRecord {
            instance_fqdn: "Studio Gateway._openclaw-gw._tcp.discovery.example.".to_owned(),
            host_name: "gateway.discovery.example.".to_owned(),
            port: 18_790,
            addresses: vec![
                "2001:db8::8".parse().expect("IPv6"),
                "203.0.113.8".parse().expect("IPv4"),
            ],
            txt_strings: advertisement
                .txt()
                .iter()
                .map(|(key, value)| format!("{key}={value}").into_bytes())
                .collect(),
        };

        let gateway = resolve_wide_area_fixture(
            service_type,
            &record,
            1_750_000_000_100,
            DEFAULT_SIGNATURE_WINDOW_MILLIS,
        )
        .expect("verified fixture");

        assert_eq!(gateway.service_type(), service_type);
        assert_eq!(gateway.instance_name(), "Studio Gateway");
        assert_eq!(gateway.host_name(), "gateway.discovery.example.");
        assert_eq!(gateway.port(), 18_790);
        assert_eq!(gateway.ssh_port(), Some(2222));
        assert_eq!(
            gateway.addresses(),
            &[
                "203.0.113.8".parse::<IpAddr>().expect("IPv4"),
                "2001:db8::8".parse::<IpAddr>().expect("IPv6"),
            ]
        );
    }

    #[test]
    fn wide_area_fixture_rejects_owner_spoofing_and_duplicate_txt() {
        let advertisement = signed_advertisement();
        let txt_strings = advertisement
            .txt()
            .iter()
            .map(|(key, value)| format!("{key}={value}").into_bytes())
            .collect::<Vec<_>>();
        let spoofed = WideAreaDnsRecord {
            instance_fqdn: "Attacker._openclaw-gw._tcp.local.".to_owned(),
            host_name: "studio-mac.local.".to_owned(),
            port: 18_790,
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            txt_strings: txt_strings.clone(),
        };
        assert!(matches!(
            resolve_wide_area_fixture(
                GATEWAY_SERVICE_TYPE,
                &spoofed,
                1_750_000_000_100,
                DEFAULT_SIGNATURE_WINDOW_MILLIS
            ),
            Err(DnsSdError::InstanceMismatch)
        ));

        let mut duplicate = spoofed;
        duplicate.instance_fqdn = "Studio Mac (OpenClaw)._openclaw-gw._tcp.local.".to_owned();
        duplicate.txt_strings.push(b"role=attacker".to_vec());
        assert!(matches!(
            resolve_wide_area_fixture(
                GATEWAY_SERVICE_TYPE,
                &duplicate,
                1_750_000_000_100,
                DEFAULT_SIGNATURE_WINDOW_MILLIS
            ),
            Err(DnsSdError::DuplicateTxtField)
        ));
    }
}

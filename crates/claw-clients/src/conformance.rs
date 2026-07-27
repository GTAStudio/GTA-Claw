//! Shared protocol-v4 connection compliance and platform smoke suite for the
//! frozen client inventory.
//!
//! Upstream sources at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`: `apps`, `ui`,
//! `src/tui` and `src/cli`.
//!
//! # What this suite actually runs
//!
//! For every one of the ten inventoried surfaces in [`crate::SURFACES`] it runs
//! the host side of that surface's connection contract and then the surface's
//! platform smoke steps:
//!
//! - a Gateway surface is driven through the real
//!   [`claw_protocol::gateway::Negotiation`] reducer — challenge, strict
//!   `req/connect` decode, protocol predicate, authentication and device
//!   policy, `hello-ok` preparation, and the ready transition — once per frozen
//!   [`crate::GatewayProfile`] the surface declares;
//! - a sidecar, helper or browser-relay surface is driven through
//!   [`attach`], which is fail-closed on local identity, attachment secret and
//!   loopback evidence;
//! - every surface then runs capability negotiation, session projection and
//!   bounded event delivery, including the deny paths for a capability and an
//!   event class the surface is not permitted to receive.
//!
//! Nothing here performs I/O. Frames are fixed in-repository fixtures decoded
//! by the pinned codec, so no request can leave the process.
//!
//! # What this suite does not run
//!
//! It does not build or execute the shipped client applications. [`COVERAGE`]
//! records that for every surface as an explicit [`ClientIntegration`] value,
//! so the gap is enumerable rather than implied, and
//! [`SurfaceCoverage::host_steps`] is asserted against what [`run_smoke`]
//! really performed.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_protocol::gateway::{
    AuthenticationDecision, Codec, CompatibilityMode, ConnectErrorDetailCode, DeviceProofDecision,
    Frame, GATEWAY_PROTOCOL_VERSION, HelloOk, Negotiation, NegotiationError, NegotiationState,
    OperatorScope, RequestId, Role,
};

use crate::{
    CapabilityError, ClientCapability, ConnectionContract, ConnectionError, DeliveredEvent,
    DeliveryError, EventDelivery, GatewayProfile, SessionEventKind, SessionProjection,
    SessionRecord, SurfaceId, negotiate_capabilities, project_session, surface,
    validate_gateway_profile,
};

/// Request identifier used by every fixture connect envelope.
pub const CONNECT_REQUEST_ID: &str = "conformance-connect";

/// Longest request identifier the fixture codec accepts.
const REQUEST_ID_LIMIT: usize = 1024;

/// Per-connection event payload ceiling used by the smoke suite.
const SMOKE_PAYLOAD_BYTES: usize = 64;

/// `src/gateway/server/ws-connection.ts` challenge event at the frozen baseline.
const CHALLENGE_EVENT: &str = r#"{"type":"event","event":"connect.challenge","payload":{"nonce":"conformance-nonce","ts":1737264000000}}"#;

/// One step the suite performs against a surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmokeStep {
    /// Full Gateway protocol-v4 negotiation for every frozen profile.
    ProtocolV4Negotiation,
    /// Fail-closed local process or browser-relay attachment.
    LocalAttachment,
    /// Deny-by-default host capability negotiation.
    CapabilityNegotiation,
    /// Least-privilege session projection.
    SessionProjection,
    /// Bounded, sequenced, per-connection event delivery.
    EventDelivery,
}

/// Steps run for a surface that speaks Gateway protocol v4.
const GATEWAY_STEPS: &[SmokeStep] = &[
    SmokeStep::ProtocolV4Negotiation,
    SmokeStep::CapabilityNegotiation,
    SmokeStep::SessionProjection,
    SmokeStep::EventDelivery,
];

/// Steps run for a surface that attaches locally instead.
const LOCAL_STEPS: &[SmokeStep] = &[
    SmokeStep::LocalAttachment,
    SmokeStep::CapabilityNegotiation,
    SmokeStep::SessionProjection,
    SmokeStep::EventDelivery,
];

/// How far this repository gets on the client side of one surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientIntegration {
    /// A GTA-Claw client crate for this surface exists in this repository but is
    /// not yet wired to this suite. The named path owns that work.
    PendingInRepositoryClient(&'static str),
    /// GTA-Claw ships no client for this surface at all. The upstream
    /// application is not built here, so only the host side can be exercised.
    UpstreamClientNotShipped,
}

/// Honest per-surface coverage record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceCoverage {
    /// Inventoried surface.
    pub surface: SurfaceId,
    /// Steps [`run_smoke`] performs for this surface.
    pub host_steps: &'static [SmokeStep],
    /// Client-side status of the surface.
    pub client: ClientIntegration,
}

/// Coverage for all and only the ten frozen surfaces, in inventory order.
pub const COVERAGE: [SurfaceCoverage; 10] = [
    SurfaceCoverage {
        surface: SurfaceId::Cli,
        host_steps: GATEWAY_STEPS,
        client: ClientIntegration::PendingInRepositoryClient("apps/gta-claw-cli"),
    },
    SurfaceCoverage {
        surface: SurfaceId::Tui,
        host_steps: GATEWAY_STEPS,
        client: ClientIntegration::PendingInRepositoryClient("apps/gta-claw-tui"),
    },
    SurfaceCoverage {
        surface: SurfaceId::ControlUi,
        host_steps: GATEWAY_STEPS,
        client: ClientIntegration::UpstreamClientNotShipped,
    },
    SurfaceCoverage {
        surface: SurfaceId::Android,
        host_steps: GATEWAY_STEPS,
        client: ClientIntegration::PendingInRepositoryClient("apps/gta-claw-android"),
    },
    SurfaceCoverage {
        surface: SurfaceId::Ios,
        host_steps: GATEWAY_STEPS,
        client: ClientIntegration::PendingInRepositoryClient("apps/gta-claw-ios"),
    },
    SurfaceCoverage {
        surface: SurfaceId::MacOs,
        host_steps: GATEWAY_STEPS,
        client: ClientIntegration::PendingInRepositoryClient("desktop/apps/gta-claw-desktop"),
    },
    SurfaceCoverage {
        surface: SurfaceId::MacOsMlxTts,
        host_steps: LOCAL_STEPS,
        client: ClientIntegration::UpstreamClientNotShipped,
    },
    SurfaceCoverage {
        surface: SurfaceId::Swabble,
        host_steps: LOCAL_STEPS,
        client: ClientIntegration::UpstreamClientNotShipped,
    },
    SurfaceCoverage {
        surface: SurfaceId::ChromeExtension,
        host_steps: LOCAL_STEPS,
        client: ClientIntegration::UpstreamClientNotShipped,
    },
    SurfaceCoverage {
        surface: SurfaceId::NodeHost,
        host_steps: GATEWAY_STEPS,
        client: ClientIntegration::PendingInRepositoryClient("apps/gta-claw-daemon"),
    },
];

/// Returns the coverage record for one surface.
#[must_use]
pub const fn coverage(surface_id: SurfaceId) -> &'static SurfaceCoverage {
    &COVERAGE[surface_id as usize]
}

/// Successful negotiation of one frozen Gateway profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionOutcome {
    /// Profile that was negotiated.
    pub profile: GatewayProfile,
    /// Compatibility path the reducer selected.
    pub compatibility: CompatibilityMode,
    /// Protocol carried by the accepted hello.
    pub protocol: u64,
    /// Authenticated role.
    pub role: Role,
    /// Authenticated operator scopes.
    pub scopes: Vec<OperatorScope>,
    /// Terminal reducer phase, always [`NegotiationState::Ready`] on success.
    pub state: NegotiationState,
}

/// Evidence a sidecar or helper presents when attaching to the host process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalProcessAttachment {
    /// The peer proved it runs the pinned local executable identity.
    pub executable_identity_verified: bool,
    /// The peer proved possession of the per-launch attachment secret.
    pub attachment_secret_verified: bool,
}

impl LocalProcessAttachment {
    /// Evidence with every check satisfied.
    pub const VERIFIED: Self = Self {
        executable_identity_verified: true,
        attachment_secret_verified: true,
    };
}

/// Evidence the Chrome extension relay presents when attaching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayAttachment {
    /// The peer proved the pinned extension identity.
    pub extension_identity_verified: bool,
    /// The peer proved possession of the per-launch attachment secret.
    pub attachment_secret_verified: bool,
    /// The relay endpoint is bound to loopback only.
    pub loopback_only: bool,
}

impl RelayAttachment {
    /// Evidence with every check satisfied.
    pub const VERIFIED: Self = Self {
        extension_identity_verified: true,
        attachment_secret_verified: true,
        loopback_only: true,
    };
}

/// Attachment evidence for a surface that does not speak Gateway v4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentEvidence {
    /// Local process evidence for a sidecar or helper.
    LocalProcess(LocalProcessAttachment),
    /// Loopback relay evidence for the browser extension.
    Relay(RelayAttachment),
}

/// Accepted non-Gateway attachment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentOutcome {
    /// An authenticated local process is attached.
    LocalProcess,
    /// An authenticated loopback Chrome relay is attached.
    ChromeRelay,
}

/// Reason a non-Gateway attachment was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentError {
    /// The surface uses Gateway protocol v4, not a local attachment.
    GatewaySurface,
    /// The evidence kind does not match the surface's transport.
    TransportMismatch,
    /// The peer did not prove the pinned local executable identity.
    ExecutableIdentityUnverified,
    /// The peer did not prove the pinned extension identity.
    ExtensionIdentityUnverified,
    /// The peer did not prove possession of the attachment secret.
    AttachmentSecretUnverified,
    /// The relay endpoint was not restricted to loopback.
    LoopbackRequired,
}

impl Display for AttachmentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GatewaySurface => "surface attaches over Gateway protocol v4",
            Self::TransportMismatch => "attachment evidence does not match the surface transport",
            Self::ExecutableIdentityUnverified => "local executable identity was not verified",
            Self::ExtensionIdentityUnverified => "browser extension identity was not verified",
            Self::AttachmentSecretUnverified => "attachment secret was not verified",
            Self::LoopbackRequired => "relay endpoint must be loopback-only",
        })
    }
}

impl Error for AttachmentError {}

/// Admits a non-Gateway attachment, rejecting on any missing proof.
///
/// # Errors
///
/// Returns the [`AttachmentError`] naming the proof that was absent, or
/// [`AttachmentError::GatewaySurface`] / [`AttachmentError::TransportMismatch`]
/// when the surface does not use this transport at all.
pub const fn attach(
    surface_id: SurfaceId,
    evidence: AttachmentEvidence,
) -> Result<AttachmentOutcome, AttachmentError> {
    match (surface(surface_id).connection, evidence) {
        (ConnectionContract::GatewayV4(_), _) => Err(AttachmentError::GatewaySurface),
        (
            ConnectionContract::AuthenticatedLocalProcess,
            AttachmentEvidence::LocalProcess(local),
        ) => {
            if !local.executable_identity_verified {
                return Err(AttachmentError::ExecutableIdentityUnverified);
            }
            if !local.attachment_secret_verified {
                return Err(AttachmentError::AttachmentSecretUnverified);
            }
            Ok(AttachmentOutcome::LocalProcess)
        }
        (ConnectionContract::ChromeExtensionRelay, AttachmentEvidence::Relay(relay)) => {
            if !relay.extension_identity_verified {
                return Err(AttachmentError::ExtensionIdentityUnverified);
            }
            if !relay.attachment_secret_verified {
                return Err(AttachmentError::AttachmentSecretUnverified);
            }
            if !relay.loopback_only {
                return Err(AttachmentError::LoopbackRequired);
            }
            Ok(AttachmentOutcome::ChromeRelay)
        }
        (
            ConnectionContract::AuthenticatedLocalProcess
            | ConnectionContract::ChromeExtensionRelay,
            _,
        ) => Err(AttachmentError::TransportMismatch),
    }
}

/// One suite run against a surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmokeReport {
    /// Surface that was exercised.
    pub surface: SurfaceId,
    /// Steps actually performed, in order.
    pub steps: Vec<SmokeStep>,
    /// Successful Gateway negotiations, one per frozen profile.
    pub connections: Vec<ConnectionOutcome>,
    /// Accepted non-Gateway attachment, when the surface uses one.
    pub attachment: Option<AttachmentOutcome>,
    /// Capabilities the host granted.
    pub granted: Vec<ClientCapability>,
    /// A capability proved to be denied, when the surface disallows one.
    pub denied_capability: Option<ClientCapability>,
    /// Projection built from the granted capabilities.
    pub projection: SessionProjection,
    /// Events delivered in order, one per permitted event class.
    pub delivered: Vec<DeliveredEvent>,
    /// An event class proved to be rejected, when the surface disallows one.
    pub rejected_event: Option<SessionEventKind>,
}

/// A suite step that did not complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmokeFailure {
    /// Surface being exercised.
    pub surface: SurfaceId,
    /// Step that failed.
    pub step: SmokeStep,
    /// Typed handshake rejection code, when the reducer produced one.
    pub rejection: Option<ConnectErrorDetailCode>,
    /// Human-readable reason.
    pub detail: String,
}

impl Display for SmokeFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} failed at {:?}: {}",
            self.surface, self.step, self.detail
        )
    }
}

impl Error for SmokeFailure {}

impl SmokeFailure {
    fn new(surface: SurfaceId, step: SmokeStep, detail: impl Into<String>) -> Self {
        Self {
            surface,
            step,
            rejection: None,
            detail: detail.into(),
        }
    }

    fn rejected(
        surface: SurfaceId,
        step: SmokeStep,
        rejection: ConnectErrorDetailCode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            surface,
            step,
            rejection: Some(rejection),
            detail: detail.into(),
        }
    }
}

/// Drives one frozen Gateway profile through the pinned protocol-v4 reducer.
///
/// The profile is first checked against the surface's frozen contract, so a
/// profile the contract does not admit fails before any frame is decoded.
///
/// # Errors
///
/// Returns a [`SmokeFailure`] carrying the reducer's typed
/// [`ConnectErrorDetailCode`] when the handshake was rejected, and a decoded
/// reason otherwise.
pub fn negotiate_profile(
    surface_id: SurfaceId,
    profile: &GatewayProfile,
    min_protocol: u64,
    max_protocol: u64,
    device_proof: DeviceProofDecision,
) -> Result<ConnectionOutcome, SmokeFailure> {
    let step = SmokeStep::ProtocolV4Negotiation;
    let fail = |detail: String| SmokeFailure::new(surface_id, step, detail);
    validate_gateway_profile(surface_id, *profile, GATEWAY_PROTOCOL_VERSION.get())
        .map_err(|error: ConnectionError| fail(error.to_string()))?;
    let role = match profile.role {
        Role::Operator => Role::Operator,
        Role::Node => Role::Node,
        Role::Worker => {
            return Err(fail(
                "worker identities use the closed worker protocol".to_owned(),
            ));
        }
    };

    let codec = Codec::preauthentication();
    let challenge_frame = codec
        .decode(CHALLENGE_EVENT.as_bytes())
        .map_err(|error| fail(format!("challenge event: {error}")))?;
    let Frame::Event(challenge_event) = challenge_frame else {
        return Err(fail("challenge fixture is not an event frame".to_owned()));
    };
    let challenge = codec
        .decode_challenge(&challenge_event)
        .map_err(|error| fail(format!("challenge payload: {error}")))?;

    let mut negotiation = Negotiation::challenge_sent(challenge);
    let connect = codec
        .decode(connect_envelope(profile, role, min_protocol, max_protocol).as_bytes())
        .map_err(|error| fail(format!("connect envelope: {error}")))?;
    negotiation
        .receive_first(connect, &codec)
        .map_err(|error| reducer_failure(surface_id, step, &negotiation, &error))?;
    let compatibility = negotiation
        .check_protocol()
        .map_err(|error| reducer_failure(surface_id, step, &negotiation, &error))?;
    if compatibility != CompatibilityMode::Current {
        return Err(fail(format!(
            "frozen client surfaces require the current protocol path, got {compatibility:?}"
        )));
    }
    negotiation
        .apply_authentication(AuthenticationDecision::Accepted {
            role,
            scopes: profile.scopes.to_vec(),
            device_proof,
        })
        .map_err(|error| reducer_failure(surface_id, step, &negotiation, &error))?;
    let hello = decode_hello(surface_id, profile, role, &codec)?;
    negotiation
        .prepare_hello(hello)
        .map_err(|error| reducer_failure(surface_id, step, &negotiation, &error))?;
    let protocol = negotiation
        .hello()
        .ok_or_else(|| fail("prepared hello is absent".to_owned()))?
        .protocol
        .get();
    negotiation
        .mark_hello_sent()
        .map_err(|error| reducer_failure(surface_id, step, &negotiation, &error))?;
    negotiation
        .mark_ready()
        .map_err(|error| reducer_failure(surface_id, step, &negotiation, &error))?;
    if negotiation.state() != NegotiationState::Ready {
        return Err(fail(format!(
            "negotiation ended in {:?}",
            negotiation.state()
        )));
    }
    if protocol != GATEWAY_PROTOCOL_VERSION.get() {
        return Err(fail(format!("hello negotiated protocol {protocol}")));
    }
    Ok(ConnectionOutcome {
        profile: *profile,
        compatibility,
        protocol,
        role,
        scopes: profile.scopes.to_vec(),
        state: negotiation.state(),
    })
}

/// Runs the whole suite for one inventoried surface.
///
/// # Errors
///
/// Returns the [`SmokeFailure`] for the first step that did not complete.
pub fn run_smoke(surface_id: SurfaceId) -> Result<SmokeReport, SmokeFailure> {
    let contract = surface(surface_id);
    let mut steps = Vec::new();
    let mut connections = Vec::new();
    let mut attachment = None;

    match contract.connection {
        ConnectionContract::GatewayV4(profiles) => {
            steps.push(SmokeStep::ProtocolV4Negotiation);
            for profile in profiles {
                connections.push(negotiate_profile(
                    surface_id,
                    profile,
                    GATEWAY_PROTOCOL_VERSION.get(),
                    GATEWAY_PROTOCOL_VERSION.get(),
                    DeviceProofDecision::Verified,
                )?);
            }
        }
        ConnectionContract::AuthenticatedLocalProcess => {
            steps.push(SmokeStep::LocalAttachment);
            attachment = Some(
                attach(
                    surface_id,
                    AttachmentEvidence::LocalProcess(LocalProcessAttachment::VERIFIED),
                )
                .map_err(|error| {
                    SmokeFailure::new(surface_id, SmokeStep::LocalAttachment, error.to_string())
                })?,
            );
        }
        ConnectionContract::ChromeExtensionRelay => {
            steps.push(SmokeStep::LocalAttachment);
            attachment = Some(
                attach(
                    surface_id,
                    AttachmentEvidence::Relay(RelayAttachment::VERIFIED),
                )
                .map_err(|error| {
                    SmokeFailure::new(surface_id, SmokeStep::LocalAttachment, error.to_string())
                })?,
            );
        }
    }

    steps.push(SmokeStep::CapabilityNegotiation);
    let granted = negotiate_capabilities(surface_id, contract.capabilities).map_err(
        |error: CapabilityError| {
            SmokeFailure::new(
                surface_id,
                SmokeStep::CapabilityNegotiation,
                error.to_string(),
            )
        },
    )?;
    if granted != contract.capabilities {
        return Err(SmokeFailure::new(
            surface_id,
            SmokeStep::CapabilityNegotiation,
            "granted capabilities differ from the frozen contract".to_owned(),
        ));
    }
    let denied_capability = ALL_CAPABILITIES
        .iter()
        .copied()
        .find(|capability| !contract.capabilities.contains(capability));
    if let Some(denied) = denied_capability
        && negotiate_capabilities(surface_id, &[denied]) != Err(CapabilityError::NotAllowed(denied))
    {
        return Err(SmokeFailure::new(
            surface_id,
            SmokeStep::CapabilityNegotiation,
            format!("capability {denied:?} was not denied"),
        ));
    }

    steps.push(SmokeStep::SessionProjection);
    let projection = project_session(&smoke_session(), &granted);
    if projection.messages.is_some() != granted.contains(&ClientCapability::SessionRead) {
        return Err(SmokeFailure::new(
            surface_id,
            SmokeStep::SessionProjection,
            "projection exposed messages without session-read".to_owned(),
        ));
    }
    if projection.writable != granted.contains(&ClientCapability::SessionWrite) {
        return Err(SmokeFailure::new(
            surface_id,
            SmokeStep::SessionProjection,
            "projection writability does not follow session-write".to_owned(),
        ));
    }

    steps.push(SmokeStep::EventDelivery);
    let capacity = contract.events.len().max(1);
    let mut delivery = EventDelivery::new(surface_id, capacity, SMOKE_PAYLOAD_BYTES).map_err(
        |error: DeliveryError| {
            SmokeFailure::new(surface_id, SmokeStep::EventDelivery, error.to_string())
        },
    )?;
    for (index, kind) in contract.events.iter().enumerate() {
        let expected = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        let sequence = delivery.push(*kind, "{}").map_err(|error| {
            SmokeFailure::new(surface_id, SmokeStep::EventDelivery, error.to_string())
        })?;
        if sequence != expected {
            return Err(SmokeFailure::new(
                surface_id,
                SmokeStep::EventDelivery,
                format!("event {kind:?} took sequence {sequence}, expected {expected}"),
            ));
        }
    }
    let mut delivered = Vec::with_capacity(contract.events.len());
    while let Some(event) = delivery.pop() {
        delivered.push(event);
    }
    let rejected_event = ALL_EVENT_KINDS
        .iter()
        .copied()
        .find(|kind| !contract.events.contains(kind));
    if let Some(rejected) = rejected_event
        && delivery.push(rejected, "{}") != Err(DeliveryError::EventNotAllowed(rejected))
    {
        return Err(SmokeFailure::new(
            surface_id,
            SmokeStep::EventDelivery,
            format!("event {rejected:?} was not rejected"),
        ));
    }

    Ok(SmokeReport {
        surface: surface_id,
        steps,
        connections,
        attachment,
        granted,
        denied_capability,
        projection,
        delivered,
        rejected_event,
    })
}

/// Runs the suite for every inventoried surface, in inventory order.
///
/// # Errors
///
/// Returns the first [`SmokeFailure`] any surface produced.
pub fn run_all() -> Result<Vec<SmokeReport>, SmokeFailure> {
    SurfaceId::ALL.into_iter().map(run_smoke).collect()
}

const ALL_CAPABILITIES: [ClientCapability; 8] = [
    ClientCapability::SessionRead,
    ClientCapability::SessionWrite,
    ClientCapability::SessionEvents,
    ClientCapability::Approvals,
    ClientCapability::NodeCommands,
    ClientCapability::SpeechSynthesis,
    ClientCapability::SpeechCapture,
    ClientCapability::ChromeDevtools,
];

const ALL_EVENT_KINDS: [SessionEventKind; 6] = [
    SessionEventKind::SessionChanged,
    SessionEventKind::Chat,
    SessionEventKind::Agent,
    SessionEventKind::Approval,
    SessionEventKind::NodePresence,
    SessionEventKind::Talk,
];

fn smoke_session() -> SessionRecord {
    SessionRecord {
        id: "conformance-session".to_owned(),
        title: "Conformance".to_owned(),
        messages: vec!["first".to_owned(), "second".to_owned()],
        active: true,
        pending_approvals: 1,
    }
}

fn reducer_failure(
    surface_id: SurfaceId,
    step: SmokeStep,
    negotiation: &Negotiation,
    error: &NegotiationError,
) -> SmokeFailure {
    negotiation.rejection().map_or_else(
        || SmokeFailure::new(surface_id, step, error.to_string()),
        |rejection| SmokeFailure::rejected(surface_id, step, rejection.code(), rejection.message()),
    )
}

fn decode_hello(
    surface_id: SurfaceId,
    profile: &GatewayProfile,
    role: Role,
    codec: &Codec,
) -> Result<HelloOk, SmokeFailure> {
    let step = SmokeStep::ProtocolV4Negotiation;
    let id = RequestId::new(CONNECT_REQUEST_ID, REQUEST_ID_LIMIT)
        .map_err(|error| SmokeFailure::new(surface_id, step, format!("request id: {error}")))?;
    let response = codec
        .decode_response(hello_envelope(profile, role).as_bytes(), &id)
        .map_err(|error| SmokeFailure::new(surface_id, step, format!("hello envelope: {error}")))?;
    codec
        .decode_hello(&response)
        .map_err(|error| SmokeFailure::new(surface_id, step, format!("hello payload: {error}")))
}

fn scope_list(profile: &GatewayProfile) -> String {
    profile
        .scopes
        .iter()
        .map(|scope| format!("\"{}\"", scope.as_str()))
        .collect::<Vec<_>>()
        .join(",")
}

fn connect_envelope(
    profile: &GatewayProfile,
    role: Role,
    min_protocol: u64,
    max_protocol: u64,
) -> String {
    let scopes = if profile.scopes.is_empty() {
        String::new()
    } else {
        format!(r#","scopes":[{}]"#, scope_list(profile))
    };
    let device = if profile.requires_device_identity {
        r#","device":{"id":"conformance-device","publicKey":"cHVi","signature":"c2ln","signedAt":1737264000000,"nonce":"conformance-nonce"}"#
    } else {
        ""
    };
    format!(
        r#"{{"type":"req","id":"{id}","method":"connect","params":{{"minProtocol":{min_protocol},"maxProtocol":{max_protocol},"client":{{"id":"{client}","version":"2026.7.2","platform":"conformance","mode":"{mode}"}},"role":"{role}"{scopes}{device},"auth":{{"token":"conformance-token"}}}}}}"#,
        id = CONNECT_REQUEST_ID,
        client = profile.client_id.as_str(),
        mode = profile.mode.as_str(),
        role = role.as_str(),
    )
}

fn hello_envelope(profile: &GatewayProfile, role: Role) -> String {
    format!(
        r#"{{"type":"res","id":"{id}","ok":true,"payload":{{"type":"hello-ok","protocol":4,"server":{{"version":"2026.7.2","connId":"conformance-conn"}},"features":{{"methods":["health"],"events":["tick"]}},"snapshot":{{"presence":[],"health":null,"stateVersion":{{"presence":0,"health":0}},"uptimeMs":1,"authMode":"token"}},"auth":{{"role":"{role}","scopes":[{scopes}]}},"policy":{{"maxPayload":26214400,"maxBufferedBytes":52428800,"tickIntervalMs":15000}}}}}}"#,
        id = CONNECT_REQUEST_ID,
        role = role.as_str(),
        scopes = scope_list(profile),
    )
}

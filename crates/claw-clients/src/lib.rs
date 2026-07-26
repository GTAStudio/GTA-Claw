//! Host-side compatibility contracts for the frozen OpenClaw client inventory.
//!
//! GTA-Claw does not ship the upstream mobile applications, Control UI, or
//! browser extension. This crate defines the authenticated connection profiles,
//! negotiated host capabilities, session projections, and bounded event
//! delivery those clients consume.
//!
//! ## Frozen scope ceilings and concrete requests
//!
//! An operator [`GatewayProfile::scopes`] list is the pinned upstream surface
//! ceiling, not the exact request every GTA-Claw client must send and not a
//! quota. [`validate_gateway_profile`] admits any subset of that ceiling and
//! rejects scopes outside it. In particular, both the Android and iOS ceilings
//! include the `operator.talk.secrets` wire scope. Local request composition is
//! narrower and remains separate from those ceilings:
//!
//! - `apps/gta-claw-android/src/session.rs` requests only `operator.read` and
//!   uses `AuthorizationExpectation::ExactRequested`.
//! - `apps/gta-claw-ios/src/profile.rs` starts with no requested scopes, lets
//!   callers select the narrow set, and uses
//!   `AuthorizationExpectation::RequestedRole`, not exact-scope matching. This
//!   checkout has no production iOS connection composition; its read-only
//!   integration fixture selects `operator.read`.
//!
//! Request narrowing belongs in a concrete client composition root, when one is
//! present; it must not be represented by shrinking these frozen upstream
//! ceilings. `operator.read` is also the correct frozen scope for
//! browse/read-only clients. It is a protocol wire identity, so local code must
//! not rename it or split it into narrower GTA-Claw-only scopes.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_protocol::gateway::{ClientId, ClientMode, GATEWAY_PROTOCOL_VERSION, OperatorScope, Role};

/// Frozen upstream baseline represented by this crate.
pub const BASELINE_SHA: &str = "b43e832fcc8000ed7287c7accc54e381db607f85";

/// Inventory classification shared by every client descriptor.
pub const CLASSIFICATION: &str = "official_client_interop";

/// Stable identity for one inventoried client surface.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SurfaceId {
    /// Command-line client.
    Cli,
    /// Terminal application.
    Tui,
    /// Browser Control UI.
    ControlUi,
    /// Android application.
    Android,
    /// iOS application.
    Ios,
    /// macOS application.
    MacOs,
    /// macOS MLX text-to-speech sidecar.
    MacOsMlxTts,
    /// Native Swabble helper.
    Swabble,
    /// Chrome extension.
    ChromeExtension,
    /// Headless node host.
    NodeHost,
}

impl SurfaceId {
    /// All and only the frozen client surfaces, in inventory order.
    pub const ALL: [Self; 10] = [
        Self::Cli,
        Self::Tui,
        Self::ControlUi,
        Self::Android,
        Self::Ios,
        Self::MacOs,
        Self::MacOsMlxTts,
        Self::Swabble,
        Self::ChromeExtension,
        Self::NodeHost,
    ];

    /// Returns the exact inventory identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Tui => "tui",
            Self::ControlUi => "control-ui",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::MacOs => "macos",
            Self::MacOsMlxTts => "macos-mlx-tts",
            Self::Swabble => "swabble",
            Self::ChromeExtension => "chrome-extension",
            Self::NodeHost => "node-host",
        }
    }
}

/// Frozen kind of one inventoried client surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceKind {
    /// Terminal command client.
    TerminalClient,
    /// Interactive terminal application.
    TerminalApp,
    /// Browser-hosted application.
    WebApp,
    /// Native application.
    NativeApp,
    /// Native process sidecar.
    NativeSidecar,
    /// Native helper process.
    NativeHelper,
    /// Browser extension.
    BrowserExtension,
    /// Headless node process.
    HeadlessNode,
}

impl SurfaceKind {
    /// Returns the exact inventory kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TerminalClient => "terminal_client",
            Self::TerminalApp => "terminal_app",
            Self::WebApp => "web_app",
            Self::NativeApp => "native_app",
            Self::NativeSidecar => "native_sidecar",
            Self::NativeHelper => "native_helper",
            Self::BrowserExtension => "browser_extension",
            Self::HeadlessNode => "headless_node",
        }
    }
}

/// Exact frozen descriptor plus its stable Rust identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceDescriptor {
    /// Stable Rust identity.
    pub id: SurfaceId,
    /// Exact inventory record identity.
    pub record_id: &'static str,
    /// Exact upstream source path.
    pub source_path: &'static str,
    /// Exact inventory kind.
    pub kind: SurfaceKind,
}

/// Gateway authentication profile accepted for a client surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayProfile {
    /// Closed Gateway client identity.
    pub client_id: ClientId,
    /// Closed Gateway client mode.
    pub mode: ClientMode,
    /// Authenticated role.
    pub role: Role,
    /// Maximum pinned operator scopes for this surface.
    ///
    /// Concrete clients may request a subset. Node profiles always use an
    /// empty slice.
    pub scopes: &'static [OperatorScope],
    /// Whether a verified device identity is mandatory.
    pub requires_device_identity: bool,
}

/// Connection boundary exposed by the GTA-Claw host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionContract {
    /// One or more Gateway v4 profiles.
    GatewayV4(&'static [GatewayProfile]),
    /// Authenticated local process protocol; no network listener is exposed.
    AuthenticatedLocalProcess,
    /// Authenticated loopback Chrome relay.
    ChromeExtensionRelay,
}

/// Host feature that a client may request.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ClientCapability {
    /// Read session lists and messages.
    SessionRead,
    /// Create, send to, and mutate sessions.
    SessionWrite,
    /// Receive live session events.
    SessionEvents,
    /// Make approval decisions.
    Approvals,
    /// Expose device/node commands to the Gateway.
    NodeCommands,
    /// Provide local speech synthesis.
    SpeechSynthesis,
    /// Provide local speech capture.
    SpeechCapture,
    /// Relay explicitly allowed Chrome DevTools operations.
    ChromeDevtools,
}

/// Session event class available to a surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEventKind {
    /// Session metadata changed.
    SessionChanged,
    /// A chat message was added or updated.
    Chat,
    /// An agent run changed.
    Agent,
    /// An approval requires attention.
    Approval,
    /// A node became available or unavailable.
    NodePresence,
    /// Talk mode or speech state changed.
    Talk,
}

/// Complete host-side contract for one frozen surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceContract {
    /// Exact frozen descriptor.
    pub descriptor: SurfaceDescriptor,
    /// Accepted transport and identity profiles.
    pub connection: ConnectionContract,
    /// Capabilities the host may grant.
    pub capabilities: &'static [ClientCapability],
    /// Event classes the host may deliver.
    pub events: &'static [SessionEventKind],
    /// Whether GTA-Claw exercises a shipped client end to end.
    pub exercise: ExerciseStatus,
}

/// Honest client exercise status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExerciseStatus {
    /// The Rust host contract is tested, but no production session path uses it yet.
    ContractOnlyHostSurface,
    /// Only the host contract is exercised; the upstream application is not shipped.
    ContractOnlyThirdPartyClient,
}

const ANDROID_OPERATOR_SCOPES: &[OperatorScope] = &[
    OperatorScope::Admin,
    OperatorScope::Approvals,
    OperatorScope::Read,
    OperatorScope::TalkSecrets,
    OperatorScope::Write,
];
const IOS_OPERATOR_SCOPES: &[OperatorScope] = &[
    OperatorScope::Read,
    OperatorScope::Write,
    OperatorScope::TalkSecrets,
    OperatorScope::Admin,
    OperatorScope::Approvals,
];
const MACOS_OPERATOR_SCOPES: &[OperatorScope] = &[
    OperatorScope::Admin,
    OperatorScope::Read,
    OperatorScope::Write,
    OperatorScope::Approvals,
    OperatorScope::Pairing,
];
const CLI_OPERATOR_SCOPES: &[OperatorScope] = &[
    OperatorScope::Admin,
    OperatorScope::Read,
    OperatorScope::Write,
    OperatorScope::Approvals,
    OperatorScope::Pairing,
    OperatorScope::TalkSecrets,
];
const TUI_OPERATOR_SCOPES: &[OperatorScope] = &[OperatorScope::Admin];
const CONTROL_UI_SCOPES: &[OperatorScope] = &[
    OperatorScope::Admin,
    OperatorScope::Read,
    OperatorScope::Write,
    OperatorScope::Approvals,
    OperatorScope::Pairing,
];
const READ_WRITE_CAPABILITIES: &[ClientCapability] = &[
    ClientCapability::SessionRead,
    ClientCapability::SessionWrite,
    ClientCapability::SessionEvents,
    ClientCapability::Approvals,
];
const READ_WRITE_EVENTS: &[SessionEventKind] = &[
    SessionEventKind::SessionChanged,
    SessionEventKind::Chat,
    SessionEventKind::Agent,
    SessionEventKind::Approval,
    SessionEventKind::NodePresence,
    SessionEventKind::Talk,
];
const NODE_CAPABILITIES: &[ClientCapability] = &[
    ClientCapability::SessionRead,
    ClientCapability::SessionWrite,
    ClientCapability::SessionEvents,
    ClientCapability::Approvals,
    ClientCapability::NodeCommands,
];
const MOBILE_PROFILES_ANDROID: &[GatewayProfile] = &[
    GatewayProfile {
        client_id: ClientId::Android,
        mode: ClientMode::Ui,
        role: Role::Operator,
        scopes: ANDROID_OPERATOR_SCOPES,
        requires_device_identity: true,
    },
    GatewayProfile {
        client_id: ClientId::Android,
        mode: ClientMode::Node,
        role: Role::Node,
        scopes: &[],
        requires_device_identity: true,
    },
];
const MOBILE_PROFILES_IOS: &[GatewayProfile] = &[
    GatewayProfile {
        client_id: ClientId::Ios,
        mode: ClientMode::Ui,
        role: Role::Operator,
        scopes: IOS_OPERATOR_SCOPES,
        requires_device_identity: true,
    },
    GatewayProfile {
        client_id: ClientId::Ios,
        mode: ClientMode::Node,
        role: Role::Node,
        scopes: &[],
        requires_device_identity: true,
    },
];
const MACOS_PROFILES: &[GatewayProfile] = &[
    GatewayProfile {
        client_id: ClientId::MacOs,
        mode: ClientMode::Ui,
        role: Role::Operator,
        scopes: MACOS_OPERATOR_SCOPES,
        requires_device_identity: true,
    },
    GatewayProfile {
        client_id: ClientId::MacOs,
        mode: ClientMode::Node,
        role: Role::Node,
        scopes: &[],
        requires_device_identity: true,
    },
];
const CLI_PROFILE: &[GatewayProfile] = &[GatewayProfile {
    client_id: ClientId::Cli,
    mode: ClientMode::Cli,
    role: Role::Operator,
    scopes: CLI_OPERATOR_SCOPES,
    requires_device_identity: true,
}];
const TUI_PROFILE: &[GatewayProfile] = &[GatewayProfile {
    client_id: ClientId::Tui,
    mode: ClientMode::Ui,
    role: Role::Operator,
    scopes: TUI_OPERATOR_SCOPES,
    requires_device_identity: true,
}];
const CONTROL_UI_PROFILE: &[GatewayProfile] = &[GatewayProfile {
    client_id: ClientId::ControlUi,
    mode: ClientMode::Webchat,
    role: Role::Operator,
    scopes: CONTROL_UI_SCOPES,
    requires_device_identity: true,
}];
const NODE_HOST_PROFILE: &[GatewayProfile] = &[GatewayProfile {
    client_id: ClientId::NodeHost,
    mode: ClientMode::Node,
    role: Role::Node,
    scopes: &[],
    requires_device_identity: true,
}];

/// All and only the frozen host-side client contracts, in inventory order.
pub const SURFACES: [SurfaceContract; 10] = [
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::Cli,
            record_id: "client:cli",
            source_path: "src/cli",
            kind: SurfaceKind::TerminalClient,
        },
        connection: ConnectionContract::GatewayV4(CLI_PROFILE),
        capabilities: READ_WRITE_CAPABILITIES,
        events: READ_WRITE_EVENTS,
        exercise: ExerciseStatus::ContractOnlyHostSurface,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::Tui,
            record_id: "client:tui",
            source_path: "src/tui",
            kind: SurfaceKind::TerminalApp,
        },
        connection: ConnectionContract::GatewayV4(TUI_PROFILE),
        capabilities: READ_WRITE_CAPABILITIES,
        events: READ_WRITE_EVENTS,
        exercise: ExerciseStatus::ContractOnlyHostSurface,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::ControlUi,
            record_id: "client:control-ui",
            source_path: "ui/src",
            kind: SurfaceKind::WebApp,
        },
        connection: ConnectionContract::GatewayV4(CONTROL_UI_PROFILE),
        capabilities: READ_WRITE_CAPABILITIES,
        events: READ_WRITE_EVENTS,
        exercise: ExerciseStatus::ContractOnlyThirdPartyClient,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::Android,
            record_id: "client:android",
            source_path: "apps/android",
            kind: SurfaceKind::NativeApp,
        },
        connection: ConnectionContract::GatewayV4(MOBILE_PROFILES_ANDROID),
        capabilities: NODE_CAPABILITIES,
        events: READ_WRITE_EVENTS,
        exercise: ExerciseStatus::ContractOnlyThirdPartyClient,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::Ios,
            record_id: "client:ios",
            source_path: "apps/ios",
            kind: SurfaceKind::NativeApp,
        },
        connection: ConnectionContract::GatewayV4(MOBILE_PROFILES_IOS),
        capabilities: NODE_CAPABILITIES,
        events: READ_WRITE_EVENTS,
        exercise: ExerciseStatus::ContractOnlyThirdPartyClient,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::MacOs,
            record_id: "client:macos",
            source_path: "apps/macos",
            kind: SurfaceKind::NativeApp,
        },
        connection: ConnectionContract::GatewayV4(MACOS_PROFILES),
        capabilities: NODE_CAPABILITIES,
        events: READ_WRITE_EVENTS,
        exercise: ExerciseStatus::ContractOnlyThirdPartyClient,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::MacOsMlxTts,
            record_id: "client:macos-mlx-tts",
            source_path: "apps/macos-mlx-tts",
            kind: SurfaceKind::NativeSidecar,
        },
        connection: ConnectionContract::AuthenticatedLocalProcess,
        capabilities: &[ClientCapability::SpeechSynthesis],
        events: &[SessionEventKind::Talk],
        exercise: ExerciseStatus::ContractOnlyThirdPartyClient,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::Swabble,
            record_id: "client:swabble",
            source_path: "apps/swabble",
            kind: SurfaceKind::NativeHelper,
        },
        connection: ConnectionContract::AuthenticatedLocalProcess,
        capabilities: &[ClientCapability::SpeechCapture],
        events: &[SessionEventKind::Talk],
        exercise: ExerciseStatus::ContractOnlyThirdPartyClient,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::ChromeExtension,
            record_id: "client:chrome-extension",
            source_path: "extensions/browser/chrome-extension",
            kind: SurfaceKind::BrowserExtension,
        },
        connection: ConnectionContract::ChromeExtensionRelay,
        capabilities: &[ClientCapability::ChromeDevtools],
        events: &[],
        exercise: ExerciseStatus::ContractOnlyThirdPartyClient,
    },
    SurfaceContract {
        descriptor: SurfaceDescriptor {
            id: SurfaceId::NodeHost,
            record_id: "client:node-host",
            source_path: "src/node-host",
            kind: SurfaceKind::HeadlessNode,
        },
        connection: ConnectionContract::GatewayV4(NODE_HOST_PROFILE),
        capabilities: &[ClientCapability::NodeCommands],
        events: &[SessionEventKind::NodePresence],
        exercise: ExerciseStatus::ContractOnlyHostSurface,
    },
];

/// Returns a frozen surface contract.
#[must_use]
pub const fn surface(id: SurfaceId) -> &'static SurfaceContract {
    &SURFACES[id as usize]
}

/// Validates a Gateway profile against the frozen protocol and identity ceiling.
///
/// Operator scopes are subset-checked: the frozen profile is a ceiling, not an
/// exact-request quota. A candidate may omit any ceiling scope, but may not add
/// a scope outside it.
pub fn validate_gateway_profile(
    surface_id: SurfaceId,
    candidate: GatewayProfile,
    protocol: u64,
) -> Result<(), ConnectionError> {
    if protocol != GATEWAY_PROTOCOL_VERSION.get() {
        return Err(ConnectionError::ProtocolMismatch);
    }
    let ConnectionContract::GatewayV4(profiles) = surface(surface_id).connection else {
        return Err(ConnectionError::WrongTransport);
    };
    let Some(expected) = profiles.iter().find(|expected| {
        expected.client_id == candidate.client_id
            && expected.mode == candidate.mode
            && expected.role == candidate.role
            && expected.requires_device_identity == candidate.requires_device_identity
    }) else {
        return Err(ConnectionError::ProfileNotAllowed);
    };
    if candidate.role == Role::Node && !candidate.scopes.is_empty() {
        return Err(ConnectionError::ProfileNotAllowed);
    }
    if candidate
        .scopes
        .iter()
        .any(|scope| !expected.scopes.contains(scope))
    {
        return Err(ConnectionError::ProfileNotAllowed);
    }
    Ok(())
}

/// Connection contract rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionError {
    /// General clients must use Gateway protocol v4.
    ProtocolMismatch,
    /// This surface does not use the Gateway transport.
    WrongTransport,
    /// Identity, mode, role, scopes, or device policy differs from the contract.
    ProfileNotAllowed,
}

impl Display for ConnectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProtocolMismatch => "client surface requires Gateway protocol v4",
            Self::WrongTransport => "client surface does not use the Gateway transport",
            Self::ProfileNotAllowed => "client connection profile is not allowed",
        })
    }
}

impl Error for ConnectionError {}

/// Negotiates requested host features using an exact deny-by-default registry.
pub fn negotiate_capabilities(
    surface_id: SurfaceId,
    requested: &[ClientCapability],
) -> Result<Vec<ClientCapability>, CapabilityError> {
    let allowed = surface(surface_id).capabilities;
    let mut granted = Vec::with_capacity(requested.len());
    for capability in requested {
        if !allowed.contains(capability) {
            return Err(CapabilityError::NotAllowed(*capability));
        }
        if !granted.contains(capability) {
            granted.push(*capability);
        }
    }
    Ok(granted)
}

/// Denied capability request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    /// The surface is not permitted to receive this capability.
    NotAllowed(ClientCapability),
}

impl Display for CapabilityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let Self::NotAllowed(capability) = self;
        write!(formatter, "capability {capability:?} is not allowed")
    }
}

impl Error for CapabilityError {}

/// One host session before surface-specific projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    /// Stable session identity.
    pub id: String,
    /// Display title.
    pub title: String,
    /// Ordered text messages.
    pub messages: Vec<String>,
    /// Whether an agent run is active.
    pub active: bool,
    /// Number of pending approvals.
    pub pending_approvals: usize,
}

/// Capability-filtered session view returned to a client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionProjection {
    /// Stable session identity.
    pub id: String,
    /// Display title.
    pub title: String,
    /// Messages, present only with session-read capability.
    pub messages: Option<Vec<String>>,
    /// Agent activity, present only with live event capability.
    pub active: Option<bool>,
    /// Pending approval count, present only with approval capability.
    pub pending_approvals: Option<usize>,
    /// Whether mutations are accepted for this projection.
    pub writable: bool,
}

/// Builds a least-privilege session projection from negotiated capabilities.
#[must_use]
pub fn project_session(record: &SessionRecord, granted: &[ClientCapability]) -> SessionProjection {
    SessionProjection {
        id: record.id.clone(),
        title: record.title.clone(),
        messages: granted
            .contains(&ClientCapability::SessionRead)
            .then(|| record.messages.clone()),
        active: granted
            .contains(&ClientCapability::SessionEvents)
            .then_some(record.active),
        pending_approvals: granted
            .contains(&ClientCapability::Approvals)
            .then_some(record.pending_approvals),
        writable: granted.contains(&ClientCapability::SessionWrite),
    }
}

/// One sequenced event delivered to a client connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveredEvent {
    /// Per-connection monotonic sequence.
    pub sequence: u64,
    /// Event class.
    pub kind: SessionEventKind,
    /// Opaque serialized event payload.
    pub payload: String,
}

/// Bounded, isolated event delivery queue for one client connection.
#[derive(Debug)]
pub struct EventDelivery {
    surface: SurfaceId,
    capacity: usize,
    max_payload_bytes: usize,
    next_sequence: u64,
    queue: VecDeque<DeliveredEvent>,
}

impl EventDelivery {
    /// Creates one per-connection delivery queue with explicit nonzero bounds.
    pub fn new(
        surface: SurfaceId,
        capacity: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, DeliveryError> {
        if capacity == 0 || max_payload_bytes == 0 {
            return Err(DeliveryError::InvalidBound);
        }
        Ok(Self {
            surface,
            capacity,
            max_payload_bytes,
            next_sequence: 1,
            queue: VecDeque::with_capacity(capacity),
        })
    }

    /// Enqueues one authorized event without affecting any other connection.
    pub fn push(
        &mut self,
        kind: SessionEventKind,
        payload: impl Into<String>,
    ) -> Result<u64, DeliveryError> {
        if !surface(self.surface).events.contains(&kind) {
            return Err(DeliveryError::EventNotAllowed(kind));
        }
        if self.queue.len() == self.capacity {
            return Err(DeliveryError::QueueFull);
        }
        let payload = payload.into();
        if payload.len() > self.max_payload_bytes {
            return Err(DeliveryError::PayloadTooLarge {
                actual: payload.len(),
                limit: self.max_payload_bytes,
            });
        }
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(DeliveryError::SequenceExhausted)?;
        self.queue.push_back(DeliveredEvent {
            sequence,
            kind,
            payload,
        });
        Ok(sequence)
    }

    /// Removes and returns the oldest pending event.
    pub fn pop(&mut self) -> Option<DeliveredEvent> {
        self.queue.pop_front()
    }

    /// Returns the number of queued events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Reports whether no events are queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Event delivery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryError {
    /// Queue and payload limits must be positive.
    InvalidBound,
    /// The surface does not consume this event class.
    EventNotAllowed(SessionEventKind),
    /// The per-connection queue is full.
    QueueFull,
    /// The payload exceeds the configured byte cap.
    PayloadTooLarge {
        /// Encoded payload bytes.
        actual: usize,
        /// Configured maximum.
        limit: usize,
    },
    /// The per-connection sequence counter was exhausted.
    SequenceExhausted,
}

impl Display for DeliveryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBound => formatter.write_str("event delivery bounds must be positive"),
            Self::EventNotAllowed(kind) => write!(formatter, "event {kind:?} is not allowed"),
            Self::QueueFull => formatter.write_str("client event queue is full"),
            Self::PayloadTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "event payload is {actual} bytes; limit is {limit}"
                )
            }
            Self::SequenceExhausted => formatter.write_str("client event sequence exhausted"),
        }
    }
}

impl Error for DeliveryError {}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Inventory {
        schema_version: u64,
        inventory_id: String,
        classification: String,
        baseline_sha: String,
        counts: Counts,
        items: Vec<InventoryItem>,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct Counts {
        total: usize,
    }

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct InventoryItem {
        record_id: String,
        id: String,
        classification: String,
        source_path: String,
        kind: String,
    }

    #[test]
    fn implemented_surface_set_exactly_matches_frozen_inventory() {
        let inventory_json = include_str!("../../../compat/upstream/inventories/clients.json")
            .trim_start_matches('\u{feff}');
        let inventory: Inventory =
            serde_json::from_str(inventory_json).expect("frozen inventory is valid JSON");
        assert_eq!(inventory.schema_version, 1);
        assert_eq!(inventory.inventory_id, "clients");
        assert_eq!(inventory.classification, CLASSIFICATION);
        assert_eq!(inventory.baseline_sha, BASELINE_SHA);
        assert_eq!(inventory.counts.total, 10);

        let implemented = SURFACES
            .iter()
            .map(|contract| InventoryItem {
                record_id: contract.descriptor.record_id.to_owned(),
                id: contract.descriptor.id.as_str().to_owned(),
                classification: CLASSIFICATION.to_owned(),
                source_path: contract.descriptor.source_path.to_owned(),
                kind: contract.descriptor.kind.as_str().to_owned(),
            })
            .collect::<Vec<_>>();
        assert_eq!(inventory.items, implemented);
        assert_eq!(SurfaceId::ALL.len(), SURFACES.len());
    }

    #[test]
    fn gateway_profiles_require_exact_v4_identity_and_device_policy() {
        let profile = GatewayProfile {
            client_id: ClientId::Android,
            mode: ClientMode::Ui,
            role: Role::Operator,
            scopes: &[
                OperatorScope::Admin,
                OperatorScope::Approvals,
                OperatorScope::Read,
                OperatorScope::TalkSecrets,
                OperatorScope::Write,
            ],
            requires_device_identity: true,
        };
        assert_eq!(
            validate_gateway_profile(SurfaceId::Android, profile, 4),
            Ok(())
        );
        assert_eq!(
            validate_gateway_profile(SurfaceId::Android, profile, 3),
            Err(ConnectionError::ProtocolMismatch)
        );
        let forged = GatewayProfile {
            client_id: ClientId::Ios,
            mode: profile.mode,
            role: profile.role,
            scopes: profile.scopes,
            requires_device_identity: profile.requires_device_identity,
        };
        assert_eq!(
            validate_gateway_profile(SurfaceId::Android, forged, 4),
            Err(ConnectionError::ProfileNotAllowed)
        );
        assert_eq!(
            validate_gateway_profile(SurfaceId::ChromeExtension, profile, 4),
            Err(ConnectionError::WrongTransport)
        );
    }

    #[test]
    fn mobile_gateway_scope_ceilings_admit_narrow_read_only_profiles() {
        for (surface_id, client_id) in [
            (SurfaceId::Android, ClientId::Android),
            (SurfaceId::Ios, ClientId::Ios),
        ] {
            let ConnectionContract::GatewayV4(profiles) = surface(surface_id).connection else {
                panic!("mobile surface must use Gateway v4");
            };
            let operator = profiles
                .iter()
                .find(|profile| profile.role == Role::Operator)
                .expect("mobile surface must have an operator profile");
            assert!(
                operator.scopes.contains(&OperatorScope::TalkSecrets),
                "{surface_id:?} frozen ceiling must retain operator.talk.secrets"
            );
            assert_eq!(
                validate_gateway_profile(
                    surface_id,
                    GatewayProfile {
                        client_id,
                        mode: ClientMode::Ui,
                        role: Role::Operator,
                        scopes: &[OperatorScope::Read],
                        requires_device_identity: true,
                    },
                    4,
                ),
                Ok(()),
                "{surface_id:?} must admit the narrower read-only composition"
            );
        }
    }

    #[test]
    fn gateway_surface_profiles_match_pinned_upstream_defaults() {
        // Sources are openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85:
        // Android: apps/android/app/src/main/java/ai/openclaw/app/node/ConnectionManager.kt
        // iOS: apps/ios/Sources/Model/NodeAppModel.swift makeOperatorConnectOptions
        // macOS: apps/macos/Sources/OpenClawMacCLI/GatewayScopes.swift
        // CLI: src/gateway/method-scopes.ts CLI_DEFAULT_OPERATOR_SCOPES
        // TUI: src/tui/gateway-chat.ts plus packages/gateway-client/src/client.ts fallback
        // Control UI: ui/src/api/gateway.ts CONTROL_UI_OPERATOR_SCOPES
        let expected: &[(SurfaceId, &[GatewayProfile])] = &[
            (
                SurfaceId::Cli,
                &[GatewayProfile {
                    client_id: ClientId::Cli,
                    mode: ClientMode::Cli,
                    role: Role::Operator,
                    scopes: &[
                        OperatorScope::Admin,
                        OperatorScope::Read,
                        OperatorScope::Write,
                        OperatorScope::Approvals,
                        OperatorScope::Pairing,
                        OperatorScope::TalkSecrets,
                    ],
                    requires_device_identity: true,
                }],
            ),
            (
                SurfaceId::Tui,
                &[GatewayProfile {
                    client_id: ClientId::Tui,
                    mode: ClientMode::Ui,
                    role: Role::Operator,
                    scopes: &[OperatorScope::Admin],
                    requires_device_identity: true,
                }],
            ),
            (
                SurfaceId::ControlUi,
                &[GatewayProfile {
                    client_id: ClientId::ControlUi,
                    mode: ClientMode::Webchat,
                    role: Role::Operator,
                    scopes: &[
                        OperatorScope::Admin,
                        OperatorScope::Read,
                        OperatorScope::Write,
                        OperatorScope::Approvals,
                        OperatorScope::Pairing,
                    ],
                    requires_device_identity: true,
                }],
            ),
            (
                SurfaceId::Android,
                &[
                    GatewayProfile {
                        client_id: ClientId::Android,
                        mode: ClientMode::Ui,
                        role: Role::Operator,
                        scopes: &[
                            OperatorScope::Admin,
                            OperatorScope::Approvals,
                            OperatorScope::Read,
                            OperatorScope::TalkSecrets,
                            OperatorScope::Write,
                        ],
                        requires_device_identity: true,
                    },
                    GatewayProfile {
                        client_id: ClientId::Android,
                        mode: ClientMode::Node,
                        role: Role::Node,
                        scopes: &[],
                        requires_device_identity: true,
                    },
                ],
            ),
            (
                SurfaceId::Ios,
                &[
                    GatewayProfile {
                        client_id: ClientId::Ios,
                        mode: ClientMode::Ui,
                        role: Role::Operator,
                        scopes: &[
                            OperatorScope::Read,
                            OperatorScope::Write,
                            OperatorScope::TalkSecrets,
                            OperatorScope::Admin,
                            OperatorScope::Approvals,
                        ],
                        requires_device_identity: true,
                    },
                    GatewayProfile {
                        client_id: ClientId::Ios,
                        mode: ClientMode::Node,
                        role: Role::Node,
                        scopes: &[],
                        requires_device_identity: true,
                    },
                ],
            ),
            (
                SurfaceId::MacOs,
                &[
                    GatewayProfile {
                        client_id: ClientId::MacOs,
                        mode: ClientMode::Ui,
                        role: Role::Operator,
                        scopes: &[
                            OperatorScope::Admin,
                            OperatorScope::Read,
                            OperatorScope::Write,
                            OperatorScope::Approvals,
                            OperatorScope::Pairing,
                        ],
                        requires_device_identity: true,
                    },
                    GatewayProfile {
                        client_id: ClientId::MacOs,
                        mode: ClientMode::Node,
                        role: Role::Node,
                        scopes: &[],
                        requires_device_identity: true,
                    },
                ],
            ),
            (
                SurfaceId::NodeHost,
                &[GatewayProfile {
                    client_id: ClientId::NodeHost,
                    mode: ClientMode::Node,
                    role: Role::Node,
                    scopes: &[],
                    requires_device_identity: true,
                }],
            ),
        ];

        for &(surface_id, expected_profiles) in expected {
            let ConnectionContract::GatewayV4(profiles) = surface(surface_id).connection else {
                panic!("expected Gateway profile");
            };
            assert_eq!(profiles, expected_profiles, "surface {surface_id:?}");
            for profile in expected_profiles {
                assert_eq!(
                    validate_gateway_profile(surface_id, *profile, 4),
                    Ok(()),
                    "surface {surface_id:?}"
                );
            }
        }
    }

    #[test]
    fn gateway_scope_profiles_reject_cross_surface_overgrants() {
        let cases = [
            (
                SurfaceId::Android,
                ClientId::Android,
                ClientMode::Ui,
                &[OperatorScope::Pairing][..],
                Err(ConnectionError::ProfileNotAllowed),
            ),
            (
                SurfaceId::Ios,
                ClientId::Ios,
                ClientMode::Ui,
                &[OperatorScope::Pairing][..],
                Err(ConnectionError::ProfileNotAllowed),
            ),
            (
                SurfaceId::MacOs,
                ClientId::MacOs,
                ClientMode::Ui,
                &[OperatorScope::TalkSecrets][..],
                Err(ConnectionError::ProfileNotAllowed),
            ),
            (
                SurfaceId::ControlUi,
                ClientId::ControlUi,
                ClientMode::Webchat,
                &[OperatorScope::TalkSecrets][..],
                Err(ConnectionError::ProfileNotAllowed),
            ),
            (
                SurfaceId::Tui,
                ClientId::Tui,
                ClientMode::Ui,
                &[OperatorScope::Write][..],
                Err(ConnectionError::ProfileNotAllowed),
            ),
            (
                SurfaceId::Cli,
                ClientId::Cli,
                ClientMode::Cli,
                &[OperatorScope::Pairing, OperatorScope::TalkSecrets][..],
                Ok(()),
            ),
        ];
        for (surface_id, client_id, mode, scopes, expected) in cases {
            assert_eq!(
                validate_gateway_profile(
                    surface_id,
                    GatewayProfile {
                        client_id,
                        mode,
                        role: Role::Operator,
                        scopes,
                        requires_device_identity: true,
                    },
                    4,
                ),
                expected,
                "surface {surface_id:?}"
            );
        }
    }

    #[test]
    fn exercise_statuses_do_not_claim_unwired_end_to_end_clients() {
        assert_eq!(
            surface(SurfaceId::Cli).exercise,
            ExerciseStatus::ContractOnlyHostSurface
        );
        assert_eq!(
            surface(SurfaceId::Tui).exercise,
            ExerciseStatus::ContractOnlyHostSurface
        );
        assert_eq!(
            surface(SurfaceId::NodeHost).exercise,
            ExerciseStatus::ContractOnlyHostSurface
        );
        for surface_id in [
            SurfaceId::ControlUi,
            SurfaceId::Android,
            SurfaceId::Ios,
            SurfaceId::MacOs,
            SurfaceId::MacOsMlxTts,
            SurfaceId::Swabble,
            SurfaceId::ChromeExtension,
        ] {
            assert_eq!(
                surface(surface_id).exercise,
                ExerciseStatus::ContractOnlyThirdPartyClient,
                "surface {surface_id:?}"
            );
        }
    }

    #[test]
    fn capability_negotiation_is_deny_by_default_and_deduplicated() {
        assert_eq!(
            negotiate_capabilities(
                SurfaceId::Cli,
                &[
                    ClientCapability::SessionRead,
                    ClientCapability::SessionRead,
                    ClientCapability::SessionWrite,
                ],
            ),
            Ok(vec![
                ClientCapability::SessionRead,
                ClientCapability::SessionWrite,
            ])
        );
        assert_eq!(
            negotiate_capabilities(SurfaceId::ControlUi, &[ClientCapability::NodeCommands]),
            Err(CapabilityError::NotAllowed(ClientCapability::NodeCommands))
        );
    }

    #[test]
    fn session_projection_exposes_only_negotiated_fields() {
        let source = SessionRecord {
            id: "session-7".to_owned(),
            title: "Release".to_owned(),
            messages: vec!["one".to_owned(), "two".to_owned()],
            active: true,
            pending_approvals: 2,
        };
        let projection = project_session(&source, &[ClientCapability::SessionRead]);
        assert_eq!(projection.id, "session-7");
        assert_eq!(projection.title, "Release");
        assert_eq!(
            projection.messages,
            Some(vec!["one".to_owned(), "two".to_owned()])
        );
        assert_eq!(projection.active, None);
        assert_eq!(projection.pending_approvals, None);
        assert!(!projection.writable);
    }

    #[test]
    fn event_delivery_is_bounded_sequenced_and_connection_isolated() {
        let mut first = EventDelivery::new(SurfaceId::Cli, 1, 8).expect("valid bounds");
        let mut second = EventDelivery::new(SurfaceId::Cli, 1, 8).expect("valid bounds");
        assert_eq!(first.push(SessionEventKind::Chat, "message"), Ok(1));
        assert_eq!(
            first.push(SessionEventKind::Agent, "run"),
            Err(DeliveryError::QueueFull)
        );
        assert_eq!(second.len(), 0);
        assert_eq!(second.push(SessionEventKind::Agent, "running"), Ok(1));

        let delivered = first.pop().expect("first event");
        assert_eq!(delivered.sequence, 1);
        assert_eq!(delivered.kind, SessionEventKind::Chat);
        assert_eq!(delivered.payload, "message");
        assert_eq!(
            first.push(SessionEventKind::Chat, "123456789"),
            Err(DeliveryError::PayloadTooLarge {
                actual: 9,
                limit: 8,
            })
        );
        assert_eq!(
            EventDelivery::new(SurfaceId::ChromeExtension, 1, 8)
                .expect("valid bounds")
                .push(SessionEventKind::Chat, "{}"),
            Err(DeliveryError::EventNotAllowed(SessionEventKind::Chat))
        );
    }
}

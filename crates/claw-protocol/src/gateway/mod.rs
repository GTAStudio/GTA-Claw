//! Transport-independent `OpenClaw` Gateway protocol v4 support.
//!
//! The contracts are pinned to
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`.
//! Registry membership describes wire compatibility and authorization metadata;
//! it does not claim that any of the 278 core method behaviors are implemented.
//! This crate is workspace-only: its build verifies the frozen registry input
//! under `compat/upstream` and intentionally fails when that input is absent.

mod authorization;
mod codec;
mod frame;
mod handshake;
mod limits;
mod registry;

pub use authorization::{AuthorizationDecision, AuthorizationError, authorize, authorize_named};
pub use codec::{Codec, CodecError, EventSequenceError, EventSequenceTracker};
pub use frame::{
    AuthCredentials, AuthMode, ChallengeNonce, ClientId, ClientInfo, ClientMode, ConnectChallenge,
    ConnectParams, ControlUiTab, ControlUiTabGroup, CoreErrorCode, DeviceProof, DevicePublicKey,
    DeviceSignature, DynamicGatewayMethodName, ErrorCode, ErrorMessage, ErrorShape, EventFrame,
    EventName, EventSequence, FiniteNumber, Frame, FrameKind, GatewayMethodName, HelloAuth,
    HelloDeviceToken, HelloFeatures, HelloOk, HelloOkKind, HelloPolicy, HelloServer,
    IntegerValidationError, Name, NonNegativeInteger, OpaqueField, OpaqueJson, PluginSurfaceUrls,
    PositiveInteger, PresenceEntry, ProtocolVersion, RequestFrame, RequestId, ResponseFrame,
    SessionDefaults, ShutdownEvent, Snapshot, StateVersion, StringValidationError, TickEvent,
    UpdateAvailable,
};
pub use handshake::{
    AuthenticationDecision, AuthenticationPort, AuthenticationRequest, CompatibilityMode,
    ConnectErrorDetailCode, ConnectRecoveryNextStep, DeviceProofDecision, HandshakeRejection,
    Negotiation, NegotiationError, NegotiationState, PairingRequiredCode, PairingRequiredDetails,
    PairingRequiredReason,
};
pub use limits::{
    AUTHENTICATED_MAX_FRAME_BYTES, DEFAULT_JSON_NESTING_DEPTH, LimitError, PREAUTH_MAX_FRAME_BYTES,
    TransportPhase, ValidationPolicy,
};
pub use registry::{
    DynamicPluginMethod, DynamicPluginRegistry, GatewayMethod, MethodScope, OperatorScope,
    PluginLookup, RegistryError, Role, baseline_sha, core_events, core_methods, operator_scopes,
    resolve_core_event, resolve_core_method, resolve_gateway_method, roles,
};

/// Current protocol emitted by successful Gateway handshakes.
pub const GATEWAY_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new_const(4);
/// Lowest version admitted for ordinary clients.
pub const MIN_GENERAL_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new_const(4);
/// Lowest version admitted for an authenticated node in the N-1 window.
pub const MIN_NODE_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new_const(3);
/// Lowest version admitted for an authenticated probe in the N-1 window.
pub const MIN_PROBE_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new_const(3);

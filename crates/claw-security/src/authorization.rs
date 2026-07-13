//! Closed gateway role/scope registries and deny-by-default authorization.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::audit::{
    AuditAction, AuditEvent, AuditFailure, AuditOutcome, AuditReason, AuditSink, AuditSubject,
};

/// Current gateway protocol version pinned by the P00a baseline.
pub const CURRENT_PROTOCOL_VERSION: u16 = 4;
/// Minimum version for general clients.
pub const MIN_GENERAL_PROTOCOL_VERSION: u16 = 4;
/// Minimum version for authenticated node-mode clients.
pub const MIN_AUTHENTICATED_NODE_PROTOCOL_VERSION: u16 = 3;
/// Minimum version for lightweight probes.
pub const MIN_PROBE_PROTOCOL_VERSION: u16 = 3;

/// Exact gateway roles frozen by `compat/upstream/inventories/gateway-protocol.json`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Role {
    /// Control-plane client.
    Operator = 0,
    /// Capability host.
    Node = 1,
    /// Cloud execution host on the separate closed worker protocol.
    Worker = 2,
}

impl Role {
    /// Frozen role registry in stable ordinal order.
    pub const ALL: [Self; 3] = [Self::Operator, Self::Node, Self::Worker];

    /// Parses an exact, case-sensitive role identity.
    pub fn parse(value: &str) -> Result<Self, RegistryError> {
        match value {
            "operator" => Ok(Self::Operator),
            "node" => Ok(Self::Node),
            "worker" => Ok(Self::Worker),
            _ => Err(RegistryError::UnknownRole),
        }
    }

    /// Returns the frozen role identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Node => "node",
            Self::Worker => "worker",
        }
    }

    /// Returns the stable role ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }
}

impl Display for Role {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exact operator scopes frozen by the P00a baseline.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Scope {
    /// Full administrative access.
    OperatorAdmin = 0,
    /// Read access.
    OperatorRead = 1,
    /// Write access.
    OperatorWrite = 2,
    /// Approval decisions.
    OperatorApprovals = 3,
    /// Pairing decisions.
    OperatorPairing = 4,
    /// Talk configuration secret access.
    OperatorTalkSecrets = 5,
}

impl Scope {
    /// Frozen scope registry in source ordinal order.
    pub const ALL: [Self; 6] = [
        Self::OperatorAdmin,
        Self::OperatorRead,
        Self::OperatorWrite,
        Self::OperatorApprovals,
        Self::OperatorPairing,
        Self::OperatorTalkSecrets,
    ];

    /// Parses an exact, case-sensitive scope identity.
    pub fn parse(value: &str) -> Result<Self, RegistryError> {
        match value {
            "operator.admin" => Ok(Self::OperatorAdmin),
            "operator.read" => Ok(Self::OperatorRead),
            "operator.write" => Ok(Self::OperatorWrite),
            "operator.approvals" => Ok(Self::OperatorApprovals),
            "operator.pairing" => Ok(Self::OperatorPairing),
            "operator.talk.secrets" => Ok(Self::OperatorTalkSecrets),
            _ => Err(RegistryError::UnknownScope),
        }
    }

    /// Returns the frozen scope identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperatorAdmin => "operator.admin",
            Self::OperatorRead => "operator.read",
            Self::OperatorWrite => "operator.write",
            Self::OperatorApprovals => "operator.approvals",
            Self::OperatorPairing => "operator.pairing",
            Self::OperatorTalkSecrets => "operator.talk.secrets",
        }
    }

    /// Returns the stable scope ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }
}

impl Display for Scope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A deterministic set over the six closed scopes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScopeSet(u8);

impl ScopeSet {
    /// Empty scope set.
    pub const EMPTY: Self = Self(0);

    /// Builds a scope set, naturally removing duplicates.
    #[must_use]
    pub fn from_scopes(scopes: impl IntoIterator<Item = Scope>) -> Self {
        let mut bits = 0_u8;
        for scope in scopes {
            bits |= 1 << scope.ordinal();
        }
        Self(bits)
    }

    /// Returns whether the set contains a scope.
    #[must_use]
    pub const fn contains(self, scope: Scope) -> bool {
        self.0 & (1 << scope.ordinal()) != 0
    }

    /// Returns whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the stable bit representation used by signed handshake payloads.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Iterates scopes in frozen ordinal order.
    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL
            .into_iter()
            .filter(move |scope| self.contains(*scope))
    }
}

/// Unknown identities are rejected rather than normalized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// The role is outside the frozen registry.
    UnknownRole,
    /// The scope is outside the frozen registry.
    UnknownScope,
}

impl Display for RegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRole => formatter.write_str("unknown gateway role"),
            Self::UnknownScope => formatter.write_str("unknown gateway scope"),
        }
    }
}

impl Error for RegistryError {}

/// Client classes relevant to the pinned protocol compatibility window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ClientClass {
    /// Any general gateway client.
    General = 0,
    /// A device-authenticated client declaring role=node and mode=node.
    AuthenticatedNode = 1,
    /// A lightweight compatibility probe.
    Probe = 2,
    /// A worker using the separate closed worker protocol.
    Worker = 3,
}

impl ClientClass {
    /// Returns the stable signed-payload ordinal.
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }
}

/// Validates only the compatibility behavior proven by the pinned baseline.
pub fn validate_protocol(
    role: Role,
    class: ClientClass,
    version: u16,
) -> Result<(), ProtocolPolicyError> {
    if role == Role::Worker {
        return Err(ProtocolPolicyError::IndependentWorkerProtocol);
    }
    match class {
        ClientClass::General if version == CURRENT_PROTOCOL_VERSION => Ok(()),
        ClientClass::AuthenticatedNode
            if role == Role::Node
                && (MIN_AUTHENTICATED_NODE_PROTOCOL_VERSION..=CURRENT_PROTOCOL_VERSION)
                    .contains(&version) =>
        {
            Ok(())
        }
        ClientClass::Probe
            if (MIN_PROBE_PROTOCOL_VERSION..=CURRENT_PROTOCOL_VERSION).contains(&version) =>
        {
            Ok(())
        }
        ClientClass::Worker => Err(ProtocolPolicyError::IndependentWorkerProtocol),
        ClientClass::AuthenticatedNode if role != Role::Node => {
            Err(ProtocolPolicyError::NodeClassRequiresNodeRole)
        }
        _ => Err(ProtocolPolicyError::UnsupportedVersion),
    }
}

/// A protocol claim outside the pinned compatibility window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolPolicyError {
    /// General clients cannot silently downgrade below v4.
    UnsupportedVersion,
    /// The v3 node window requires the node role.
    NodeClassRequiresNodeRole,
    /// Workers do not negotiate the general gateway protocol.
    IndependentWorkerProtocol,
}

impl Display for ProtocolPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => formatter.write_str("unsupported gateway protocol version"),
            Self::NodeClassRequiresNodeRole => {
                formatter.write_str("authenticated node compatibility requires role=node")
            }
            Self::IndependentWorkerProtocol => {
                formatter.write_str("worker uses an independent closed protocol")
            }
        }
    }
}

impl Error for ProtocolPolicyError {}

/// Validates the only role-to-scope rule proven by pinned sources.
///
/// Operator roles may carry members of the closed operator scope set. Node and
/// worker roles carry no operator scopes. This function does not claim any
/// gateway methods are implemented.
pub fn validate_role_scopes(role: Role, scopes: ScopeSet) -> Result<(), RoleScopeError> {
    if role == Role::Operator || scopes.is_empty() {
        Ok(())
    } else {
        Err(RoleScopeError::OperatorScopesRequireOperatorRole)
    }
}

/// A role/scope combination outside the frozen source policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleScopeError {
    /// Node and worker roles cannot receive operator scopes.
    OperatorScopesRequireOperatorRole,
}

impl Display for RoleScopeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("operator scopes require role=operator")
    }
}

impl Error for RoleScopeError {}

/// Stage at which a security decision was made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionStage {
    /// Identity or credential authentication.
    Authentication,
    /// Role/scope authorization.
    Authorization,
    /// Human or policy approval.
    Approval,
}

/// Auditable authorization reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationReason {
    /// All required gates passed.
    Granted,
    /// No authenticated identity is present.
    AuthenticationRequired,
    /// The role cannot use operator scopes.
    RoleNotAuthorized,
    /// The authenticated principal lacks the required scope.
    ScopeNotGranted,
    /// Explicit approval has not occurred.
    ApprovalRequired,
}

/// A deny-by-default authorization result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationDecision {
    /// Whether access is granted.
    pub granted: bool,
    /// Gate responsible for the result.
    pub stage: DecisionStage,
    /// Stable reason code.
    pub reason: AuthorizationReason,
}

/// Inputs to one authorization decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    /// Whether the caller has authenticated.
    pub authenticated: bool,
    /// Authenticated role.
    pub role: Role,
    /// Closed granted scope set.
    pub granted_scopes: ScopeSet,
    /// Scope required by caller-supplied method policy.
    pub required_scope: Scope,
    /// Whether an independent approval gate has passed.
    pub approved: bool,
}

fn authorize(request: AuthorizationRequest) -> AuthorizationDecision {
    if !request.authenticated {
        return AuthorizationDecision {
            granted: false,
            stage: DecisionStage::Authentication,
            reason: AuthorizationReason::AuthenticationRequired,
        };
    }
    if request.role != Role::Operator {
        return AuthorizationDecision {
            granted: false,
            stage: DecisionStage::Authorization,
            reason: AuthorizationReason::RoleNotAuthorized,
        };
    }
    if !scope_satisfied(request.granted_scopes, request.required_scope) {
        return AuthorizationDecision {
            granted: false,
            stage: DecisionStage::Authorization,
            reason: AuthorizationReason::ScopeNotGranted,
        };
    }
    if !request.approved {
        return AuthorizationDecision {
            granted: false,
            stage: DecisionStage::Approval,
            reason: AuthorizationReason::ApprovalRequired,
        };
    }
    AuthorizationDecision {
        granted: true,
        stage: DecisionStage::Authorization,
        reason: AuthorizationReason::Granted,
    }
}

// Pinned `operator-scope-compat.ts` proves admin satisfies every operator scope
// and write satisfies read. No other implications are assumed.
fn scope_satisfied(granted: ScopeSet, required: Scope) -> bool {
    granted.contains(Scope::OperatorAdmin)
        || granted.contains(required)
        || (required == Scope::OperatorRead && granted.contains(Scope::OperatorWrite))
}

/// Authorizes only after the structured decision is durably audited.
pub fn authorize_audited<S: AuditSink>(
    request: AuthorizationRequest,
    unix_millis: u64,
    sink: &mut S,
) -> Result<AuthorizationDecision, AuditFailure<S::Error>> {
    let decision = authorize(request);
    let event = AuditEvent {
        action: AuditAction::AuthorizationEvaluated,
        subject: AuditSubject::Role(request.role),
        outcome: if decision.granted {
            AuditOutcome::Allowed
        } else {
            AuditOutcome::Denied
        },
        reason: if decision.granted {
            AuditReason::PolicySatisfied
        } else {
            AuditReason::PolicyRejected
        },
        unix_millis,
    };
    sink.persist(&event).map_err(AuditFailure::Sink)?;
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registries_are_bidirectionally_frozen() {
        let role_names = ["operator", "node", "worker"];
        assert_eq!(
            Role::ALL.map(Role::as_str),
            role_names,
            "registry equality does not claim methods are implemented"
        );
        for (ordinal, name) in role_names.into_iter().enumerate() {
            let role = Role::parse(name).expect("frozen role");
            assert_eq!(usize::from(role.ordinal()), ordinal);
            assert_eq!(role.as_str(), name);
        }

        let scope_names = [
            "operator.admin",
            "operator.read",
            "operator.write",
            "operator.approvals",
            "operator.pairing",
            "operator.talk.secrets",
        ];
        assert_eq!(Scope::ALL.map(Scope::as_str), scope_names);
        for (ordinal, name) in scope_names.into_iter().enumerate() {
            let scope = Scope::parse(name).expect("frozen scope");
            assert_eq!(usize::from(scope.ordinal()), ordinal);
            assert_eq!(scope.as_str(), name);
        }
    }

    #[test]
    fn registry_rejects_casing_and_unicode_aliases() {
        for value in ["Operator", "NODE", "ｗorker", "operatοr"] {
            assert_eq!(Role::parse(value), Err(RegistryError::UnknownRole));
        }
        for value in ["Operator.read", "operator.READ", "operator．read"] {
            assert_eq!(Scope::parse(value), Err(RegistryError::UnknownScope));
        }
    }

    #[test]
    fn protocol_window_never_downgrades_general_clients() {
        assert_eq!(
            validate_protocol(Role::Operator, ClientClass::General, 3),
            Err(ProtocolPolicyError::UnsupportedVersion)
        );
        assert_eq!(
            validate_protocol(Role::Node, ClientClass::AuthenticatedNode, 3),
            Ok(())
        );
        assert_eq!(validate_protocol(Role::Node, ClientClass::Probe, 3), Ok(()));
        assert_eq!(
            validate_protocol(Role::Operator, ClientClass::AuthenticatedNode, 3),
            Err(ProtocolPolicyError::NodeClassRequiresNodeRole)
        );
        assert_eq!(
            validate_protocol(Role::Worker, ClientClass::General, 4),
            Err(ProtocolPolicyError::IndependentWorkerProtocol)
        );
    }

    #[test]
    fn role_scope_policy_is_closed() {
        let all = ScopeSet::from_scopes(Scope::ALL);
        assert_eq!(validate_role_scopes(Role::Operator, all), Ok(()));
        assert_eq!(validate_role_scopes(Role::Node, ScopeSet::EMPTY), Ok(()));
        assert_eq!(
            validate_role_scopes(Role::Worker, all),
            Err(RoleScopeError::OperatorScopesRequireOperatorRole)
        );
    }

    #[test]
    fn authorization_distinguishes_all_gates() {
        let base = AuthorizationRequest {
            authenticated: false,
            role: Role::Operator,
            granted_scopes: ScopeSet::from_scopes([Scope::OperatorRead]),
            required_scope: Scope::OperatorRead,
            approved: true,
        };
        assert_eq!(authorize(base).stage, DecisionStage::Authentication);
        assert_eq!(
            authorize(AuthorizationRequest {
                authenticated: true,
                role: Role::Node,
                ..base
            })
            .stage,
            DecisionStage::Authorization
        );
        assert_eq!(
            authorize(AuthorizationRequest {
                authenticated: true,
                approved: false,
                ..base
            })
            .stage,
            DecisionStage::Approval
        );
        assert!(
            authorize(AuthorizationRequest {
                authenticated: true,
                ..base
            })
            .granted
        );
        assert!(
            authorize(AuthorizationRequest {
                authenticated: true,
                granted_scopes: ScopeSet::from_scopes([Scope::OperatorAdmin]),
                ..base
            })
            .granted
        );
        assert!(
            authorize(AuthorizationRequest {
                authenticated: true,
                granted_scopes: ScopeSet::from_scopes([Scope::OperatorWrite]),
                ..base
            })
            .granted
        );
    }
}

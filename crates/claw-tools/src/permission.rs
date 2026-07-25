//! Deny-by-default capability grants, scoped revocable authorization, and the
//! permission broker port.
//!
//! No tool in this crate can perform a privileged operation without an
//! [`Authorization`] token, and only [`crate::registry::ToolRegistry`] can mint
//! one, and only after a broker returned [`PermissionDecision::Granted`].

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;

use serde::Serialize;

/// A privileged action class requested by a tool.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read file content or directory listings inside the workspace sandbox.
    FilesystemRead,
    /// Create or modify files inside the workspace sandbox.
    FilesystemWrite,
    /// Spawn an operating-system process.
    ProcessExecute,
    /// Perform an outbound HTTP request.
    NetworkFetch,
    /// Query an external search provider.
    NetworkSearch,
}

impl Capability {
    /// Every capability in stable order.
    pub const ALL: [Self; 5] = [
        Self::FilesystemRead,
        Self::FilesystemWrite,
        Self::ProcessExecute,
        Self::NetworkFetch,
        Self::NetworkSearch,
    ];

    /// Returns the stable capability identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemWrite => "filesystem.write",
            Self::ProcessExecute => "process.execute",
            Self::NetworkFetch => "network.fetch",
            Self::NetworkSearch => "network.search",
        }
    }
}

impl Display for Capability {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Operator-visible danger level of a tool.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Confined, read-only, and reversible.
    Low,
    /// Modifies workspace state.
    Medium,
    /// Executes code or reaches outside the host.
    High,
}

/// Static permission metadata attached to every tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionDescriptor {
    /// Capability the tool requires for every invocation.
    pub capability: Capability,
    /// Operator-visible danger level.
    pub risk: RiskLevel,
    /// Whether an explicit human or policy approval is required.
    pub requires_approval: bool,
    /// Frozen gateway scope that fronts this tool over the wire.
    pub gateway_scope: &'static str,
}

/// The concrete object a capability is exercised against.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Resource {
    /// Normalized sandbox-relative path with `/` separators.
    Path(String),
    /// Resolved executable program identity.
    Program(String),
    /// Canonical target host.
    Host(String),
    /// A capability with no addressable resource.
    Global,
}

/// Scope attached to one grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantScope {
    /// A sandbox-relative path prefix matched component-wise.
    ///
    /// An empty prefix covers the whole workspace.
    PathPrefix(String),
    /// One exact resolved program identity.
    Program(String),
    /// One exact canonical host.
    Host(String),
    /// The whole capability with no resource restriction.
    Unrestricted,
}

impl GrantScope {
    fn matches(&self, resource: &Resource) -> bool {
        match (self, resource) {
            (Self::Unrestricted, _) => true,
            (Self::PathPrefix(prefix), Resource::Path(path)) => path_prefix_matches(prefix, path),
            (Self::Program(allowed), Resource::Program(program)) => allowed == program,
            (Self::Host(allowed), Resource::Host(host)) => allowed == host,
            _ => false,
        }
    }
}

/// Matches `prefix` against `path` on whole path components.
///
/// String prefixes are deliberately not used: `src` must not match `srcs/x`.
fn path_prefix_matches(prefix: &str, path: &str) -> bool {
    let prefix_components: Vec<&str> = prefix.split('/').filter(|part| !part.is_empty()).collect();
    let path_components: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    prefix_components.len() <= path_components.len()
        && prefix_components
            .iter()
            .zip(&path_components)
            .all(|(left, right)| left == right)
}

/// Evidence that stands behind a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// An operator or approval policy explicitly decided this grant.
    Explicit,
    /// Configured default policy without an interactive approval decision.
    Implicit,
}

/// Stable identifier of one issued grant.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GrantId(u64);

impl GrantId {
    /// Returns the stable numeric identity.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl Display for GrantId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "grant-{}", self.0)
    }
}

/// A scoped, expiring, revocable authorization to exercise one capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    id: GrantId,
    capability: Capability,
    scope: GrantScope,
    expires_unix_millis: Option<u64>,
    remaining_uses: Option<u32>,
    approval: Approval,
}

impl Grant {
    /// Returns the evidence behind the grant.
    #[must_use]
    pub const fn approval(&self) -> Approval {
        self.approval
    }

    /// Returns the grant identity.
    #[must_use]
    pub const fn id(&self) -> GrantId {
        self.id
    }

    /// Returns the authorized capability.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Returns the resource scope.
    #[must_use]
    pub const fn scope(&self) -> &GrantScope {
        &self.scope
    }

    /// Returns the expiry instant, if the grant is time-bounded.
    #[must_use]
    pub const fn expires_unix_millis(&self) -> Option<u64> {
        self.expires_unix_millis
    }

    /// Returns the remaining use count, if the grant is use-bounded.
    #[must_use]
    pub const fn remaining_uses(&self) -> Option<u32> {
        self.remaining_uses
    }
}

/// A grant request submitted to the ledger by an approval flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRequest {
    /// Capability being authorized.
    pub capability: Capability,
    /// Resource restriction.
    pub scope: GrantScope,
    /// Optional expiry instant in Unix milliseconds.
    pub expires_unix_millis: Option<u64>,
    /// Optional bound on how many invocations the grant covers.
    pub max_uses: Option<u32>,
    /// Evidence standing behind the grant.
    pub approval: Approval,
}

/// One authorization question asked before a tool runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionRequest {
    /// Requesting tool identity.
    pub tool: &'static str,
    /// Capability the tool declared.
    pub capability: Capability,
    /// Concrete resource derived from validated arguments.
    pub resource: Resource,
    /// Whether the tool descriptor demands explicit approval.
    pub requires_approval: bool,
    /// Caller-supplied wall-clock instant.
    pub unix_millis: u64,
}

/// Reason an authorization question was answered negatively.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    /// No grant covers the capability and resource.
    NoMatchingGrant,
    /// A matching grant exists but its lifetime elapsed.
    GrantExpired,
    /// A matching grant exists but its use budget is exhausted.
    GrantExhausted,
    /// The broker refuses every request.
    BrokerDeniesAll,
    /// The tool requires an approval-backed grant and none was found.
    ApprovalRequired,
}

impl Display for DenialReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NoMatchingGrant => "no grant covers this capability and resource",
            Self::GrantExpired => "the matching grant has expired",
            Self::GrantExhausted => "the matching grant has no remaining uses",
            Self::BrokerDeniesAll => "the permission broker denies all requests",
            Self::ApprovalRequired => "explicit approval is required",
        };
        formatter.write_str(message)
    }
}

/// Result of one authorization question.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionDecision {
    /// The named grant authorizes the request.
    Granted(GrantId),
    /// The request is refused.
    Denied(DenialReason),
}

/// Port implemented by whatever component owns approval policy.
///
/// Implementations must fail closed: any state they cannot evaluate must be
/// answered with [`PermissionDecision::Denied`].
pub trait PermissionBroker {
    /// Answers exactly one authorization question and may consume budget.
    fn evaluate(&mut self, request: &PermissionRequest) -> PermissionDecision;
}

/// A broker that refuses everything, used as the safe default.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DenyAllBroker;

impl PermissionBroker for DenyAllBroker {
    fn evaluate(&mut self, _request: &PermissionRequest) -> PermissionDecision {
        PermissionDecision::Denied(DenialReason::BrokerDeniesAll)
    }
}

/// In-process ledger of scoped, expiring, revocable grants.
///
/// The ledger is deny-by-default: an empty ledger authorizes nothing.
#[derive(Clone, Debug, Default)]
pub struct GrantLedger {
    next_id: u64,
    grants: BTreeMap<u64, Grant>,
}

impl GrantLedger {
    /// Creates an empty ledger that authorizes nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one approval decision as a scoped grant.
    pub fn grant(&mut self, request: GrantRequest) -> GrantId {
        self.next_id += 1;
        let id = GrantId(self.next_id);
        self.grants.insert(
            id.0,
            Grant {
                id,
                capability: request.capability,
                scope: request.scope,
                expires_unix_millis: request.expires_unix_millis,
                remaining_uses: request.max_uses,
                approval: request.approval,
            },
        );
        id
    }

    /// Revokes one grant, returning whether it existed.
    pub fn revoke(&mut self, id: GrantId) -> bool {
        self.grants.remove(&id.0).is_some()
    }

    /// Revokes every grant.
    pub fn revoke_all(&mut self) {
        self.grants.clear();
    }

    /// Returns the grants that are still valid at `unix_millis`, oldest first.
    pub fn active(&self, unix_millis: u64) -> impl Iterator<Item = &Grant> {
        self.grants.values().filter(move |grant| {
            grant
                .expires_unix_millis
                .is_none_or(|expiry| unix_millis < expiry)
                && grant.remaining_uses != Some(0)
        })
    }
}

impl PermissionBroker for GrantLedger {
    fn evaluate(&mut self, request: &PermissionRequest) -> PermissionDecision {
        let mut saw_expired = false;
        let mut saw_exhausted = false;
        let mut saw_unapproved = false;
        let mut selected = None;
        for grant in self.grants.values() {
            if grant.capability != request.capability || !grant.scope.matches(&request.resource) {
                continue;
            }
            if grant
                .expires_unix_millis
                .is_some_and(|expiry| request.unix_millis >= expiry)
            {
                saw_expired = true;
                continue;
            }
            if grant.remaining_uses == Some(0) {
                saw_exhausted = true;
                continue;
            }
            if request.requires_approval && grant.approval != Approval::Explicit {
                saw_unapproved = true;
                continue;
            }
            selected = Some(grant.id);
            break;
        }
        let Some(id) = selected else {
            return PermissionDecision::Denied(if saw_unapproved {
                DenialReason::ApprovalRequired
            } else if saw_expired {
                DenialReason::GrantExpired
            } else if saw_exhausted {
                DenialReason::GrantExhausted
            } else {
                DenialReason::NoMatchingGrant
            });
        };
        if let Some(grant) = self.grants.get_mut(&id.0)
            && let Some(remaining) = grant.remaining_uses.as_mut()
        {
            *remaining -= 1;
        }
        PermissionDecision::Granted(id)
    }
}

/// Unforgeable proof that a broker authorized exactly one tool invocation.
///
/// The private field prevents construction outside this crate, so a tool
/// implementation cannot be driven without passing the authorization gate.
#[derive(Debug)]
pub struct Authorization<'a> {
    grant: GrantId,
    capability: Capability,
    _lifetime: PhantomData<&'a ()>,
}

impl Authorization<'_> {
    pub(crate) const fn new(grant: GrantId, capability: Capability) -> Self {
        Self {
            grant,
            capability,
            _lifetime: PhantomData,
        }
    }

    /// Returns the grant that authorized the invocation.
    #[must_use]
    pub const fn grant(&self) -> GrantId {
        self.grant
    }

    /// Returns the authorized capability.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }
}

/// A permission gate refused the invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionError {
    /// Tool that was refused.
    pub tool: &'static str,
    /// Capability that was refused.
    pub capability: Capability,
    /// Stable refusal reason.
    pub reason: DenialReason,
}

impl Display for PermissionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "tool `{}` was denied capability `{}`: {}",
            self.tool, self.capability, self.reason
        )
    }
}

impl Error for PermissionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(capability: Capability, resource: Resource, now: u64) -> PermissionRequest {
        PermissionRequest {
            tool: "test_tool",
            capability,
            resource,
            requires_approval: true,
            unix_millis: now,
        }
    }

    #[test]
    fn an_empty_ledger_authorizes_nothing() {
        let mut ledger = GrantLedger::new();
        for capability in Capability::ALL {
            assert_eq!(
                ledger.evaluate(&request(capability, Resource::Global, 0)),
                PermissionDecision::Denied(DenialReason::NoMatchingGrant)
            );
        }
    }

    #[test]
    fn deny_all_broker_refuses_every_capability() {
        let mut broker = DenyAllBroker;
        for capability in Capability::ALL {
            assert_eq!(
                broker.evaluate(&request(capability, Resource::Global, 0)),
                PermissionDecision::Denied(DenialReason::BrokerDeniesAll)
            );
        }
    }

    #[test]
    fn path_scope_matches_components_not_string_prefixes() {
        let mut ledger = GrantLedger::new();
        let id = ledger.grant(GrantRequest {
            capability: Capability::FilesystemRead,
            scope: GrantScope::PathPrefix("src".to_owned()),
            expires_unix_millis: None,
            max_uses: None,
            approval: Approval::Explicit,
        });
        assert_eq!(
            ledger.evaluate(&request(
                Capability::FilesystemRead,
                Resource::Path("src/main.rs".to_owned()),
                0
            )),
            PermissionDecision::Granted(id)
        );
        assert_eq!(
            ledger.evaluate(&request(
                Capability::FilesystemRead,
                Resource::Path("src".to_owned()),
                0
            )),
            PermissionDecision::Granted(id)
        );
        for outside in ["srcs/main.rs", "source/main.rs", "other/src/main.rs"] {
            assert_eq!(
                ledger.evaluate(&request(
                    Capability::FilesystemRead,
                    Resource::Path(outside.to_owned()),
                    0
                )),
                PermissionDecision::Denied(DenialReason::NoMatchingGrant),
                "{outside}"
            );
        }
    }

    #[test]
    fn a_grant_never_leaks_across_capabilities_or_resource_kinds() {
        let mut ledger = GrantLedger::new();
        ledger.grant(GrantRequest {
            capability: Capability::FilesystemRead,
            scope: GrantScope::PathPrefix(String::new()),
            expires_unix_millis: None,
            max_uses: None,
            approval: Approval::Explicit,
        });
        assert_eq!(
            ledger.evaluate(&request(
                Capability::FilesystemWrite,
                Resource::Path("a.txt".to_owned()),
                0
            )),
            PermissionDecision::Denied(DenialReason::NoMatchingGrant)
        );
        assert_eq!(
            ledger.evaluate(&request(
                Capability::FilesystemRead,
                Resource::Program("a.txt".to_owned()),
                0
            )),
            PermissionDecision::Denied(DenialReason::NoMatchingGrant)
        );
    }

    #[test]
    fn expiry_revocation_and_use_budgets_all_close_the_gate() {
        let mut ledger = GrantLedger::new();
        let timed = ledger.grant(GrantRequest {
            capability: Capability::NetworkFetch,
            scope: GrantScope::Host("api.example.com".to_owned()),
            expires_unix_millis: Some(1_000),
            max_uses: None,
            approval: Approval::Explicit,
        });
        let host = Resource::Host("api.example.com".to_owned());
        assert_eq!(
            ledger.evaluate(&request(Capability::NetworkFetch, host.clone(), 999)),
            PermissionDecision::Granted(timed)
        );
        assert_eq!(
            ledger.evaluate(&request(Capability::NetworkFetch, host.clone(), 1_000)),
            PermissionDecision::Denied(DenialReason::GrantExpired)
        );
        assert!(ledger.revoke(timed));
        assert!(!ledger.revoke(timed));
        assert_eq!(
            ledger.evaluate(&request(Capability::NetworkFetch, host.clone(), 0)),
            PermissionDecision::Denied(DenialReason::NoMatchingGrant)
        );

        let once = ledger.grant(GrantRequest {
            capability: Capability::NetworkFetch,
            scope: GrantScope::Host("api.example.com".to_owned()),
            expires_unix_millis: None,
            max_uses: Some(1),
            approval: Approval::Explicit,
        });
        assert_eq!(
            ledger.evaluate(&request(Capability::NetworkFetch, host.clone(), 0)),
            PermissionDecision::Granted(once)
        );
        assert_eq!(
            ledger.evaluate(&request(Capability::NetworkFetch, host, 0)),
            PermissionDecision::Denied(DenialReason::GrantExhausted)
        );
        assert_eq!(ledger.active(0).count(), 0);
    }

    #[test]
    fn host_and_program_scopes_require_exact_equality() {
        let mut ledger = GrantLedger::new();
        ledger.grant(GrantRequest {
            capability: Capability::ProcessExecute,
            scope: GrantScope::Program("cargo".to_owned()),
            expires_unix_millis: None,
            max_uses: None,
            approval: Approval::Explicit,
        });
        ledger.grant(GrantRequest {
            capability: Capability::NetworkFetch,
            scope: GrantScope::Host("api.example.com".to_owned()),
            expires_unix_millis: None,
            max_uses: None,
            approval: Approval::Explicit,
        });
        for program in ["cargo.exe", "Cargo", "cargo-audit", "/usr/bin/cargo"] {
            assert_eq!(
                ledger.evaluate(&request(
                    Capability::ProcessExecute,
                    Resource::Program(program.to_owned()),
                    0
                )),
                PermissionDecision::Denied(DenialReason::NoMatchingGrant),
                "{program}"
            );
        }
        for host in [
            "API.example.com",
            "api.example.com.evil.test",
            "example.com",
        ] {
            assert_eq!(
                ledger.evaluate(&request(
                    Capability::NetworkFetch,
                    Resource::Host(host.to_owned()),
                    0
                )),
                PermissionDecision::Denied(DenialReason::NoMatchingGrant),
                "{host}"
            );
        }
    }

    #[test]
    fn an_implicit_grant_cannot_satisfy_a_tool_that_demands_approval() {
        let mut ledger = GrantLedger::new();
        let implicit = ledger.grant(GrantRequest {
            capability: Capability::ProcessExecute,
            scope: GrantScope::Unrestricted,
            expires_unix_millis: None,
            max_uses: None,
            approval: Approval::Implicit,
        });
        let mut approval_required = request(Capability::ProcessExecute, Resource::Global, 0);
        approval_required.requires_approval = true;
        assert_eq!(
            ledger.evaluate(&approval_required),
            PermissionDecision::Denied(DenialReason::ApprovalRequired)
        );
        let mut no_approval_required = approval_required.clone();
        no_approval_required.requires_approval = false;
        assert_eq!(
            ledger.evaluate(&no_approval_required),
            PermissionDecision::Granted(implicit)
        );
        let explicit = ledger.grant(GrantRequest {
            capability: Capability::ProcessExecute,
            scope: GrantScope::Unrestricted,
            expires_unix_millis: None,
            max_uses: None,
            approval: Approval::Explicit,
        });
        assert_eq!(
            ledger.evaluate(&approval_required),
            PermissionDecision::Granted(explicit)
        );
    }

    #[test]
    fn revoke_all_clears_every_capability_at_once() {
        let mut ledger = GrantLedger::new();
        for capability in Capability::ALL {
            ledger.grant(GrantRequest {
                capability,
                scope: GrantScope::Unrestricted,
                expires_unix_millis: None,
                max_uses: None,
                approval: Approval::Explicit,
            });
        }
        assert_eq!(ledger.active(0).count(), 5);
        ledger.revoke_all();
        assert_eq!(ledger.active(0).count(), 0);
        for capability in Capability::ALL {
            assert_eq!(
                ledger.evaluate(&request(capability, Resource::Global, 0)),
                PermissionDecision::Denied(DenialReason::NoMatchingGrant)
            );
        }
    }
}

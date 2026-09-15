//! The tool execution port.

use claw_domain::SessionId;
use std::sync::Arc;

use super::{PortError, PortFuture};
use crate::model::ids::{ToolCallId, TurnId};
use crate::model::message::ToolCall;

/// Trusted ingress that established the caller identity, never a model-supplied field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationSource {
    /// A device-authenticated Gateway connection.
    Gateway,
    /// A bearer-authenticated HTTP request.
    Http,
    /// A separately authenticated MCP request.
    Mcp,
    /// An authenticated channel account and sender.
    Channel,
}

/// Tool access derived by an authenticated ingress, not inferred from session ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvocationAccess {
    /// The caller may inspect state but cannot execute tools.
    ReadOnly,
    /// The caller has explicit tool execution access, subject to per-tool policy and approval.
    Execute,
    /// The ingress verified an owner/admin grant; resource policy and approval still apply.
    Owner,
}

/// Host-owned revocation signal for one authenticated grant revision.
pub trait InvocationRevocation: Send + Sync {
    /// Reports whether the captured grant is no longer valid.
    fn is_revoked(&self) -> bool;

    /// Completes when that grant is revoked; completion must be permanent.
    fn revoked(&self) -> PortFuture<'_, ()>;
}

/// Immutable caller claims carried across a runtime turn and its tool invocations.
///
/// This type deliberately has no deserializer. Only the host's authentication adapter may
/// construct it; session keys, model output and request body metadata are not authentication.
#[derive(Clone)]
pub struct InvocationAuthority {
    source: InvocationSource,
    subject: String,
    account: Option<String>,
    access: InvocationAccess,
    generation: u64,
    revocation: Option<Arc<dyn InvocationRevocation>>,
}

impl InvocationAuthority {
    /// Captures bounded claims from a completed authentication decision.
    ///
    /// # Errors
    /// Rejects empty, oversized or control-bearing subject/account identifiers.
    pub fn new(
        source: InvocationSource,
        subject: &str,
        account: Option<&str>,
        access: InvocationAccess,
        generation: u64,
    ) -> Result<Self, PortError> {
        if std::iter::once(subject).chain(account).any(|value| {
            value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
        }) {
            return Err(PortError::Invalid(
                "invalid authenticated invocation identity".to_owned(),
            ));
        }
        Ok(Self {
            source,
            subject: subject.to_owned(),
            account: account.map(str::to_owned),
            access,
            generation,
            revocation: None,
        })
    }

    /// Authentication source used for policy and audit partitioning.
    #[must_use]
    pub const fn source(&self) -> InvocationSource {
        self.source
    }

    /// Authenticated subject, not a caller-selected routing key.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Authenticated account identity, when the ingress actually verified one.
    #[must_use]
    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    /// Whether ingress authorization permits execution before per-tool policy checks.
    #[must_use]
    pub fn can_execute(&self) -> bool {
        !matches!(self.access, InvocationAccess::ReadOnly) && !self.is_revoked()
    }

    /// Whether an owner/admin grant was verified, without bypassing resource or approval policy.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        matches!(self.access, InvocationAccess::Owner) && !self.is_revoked()
    }

    /// Configuration/permission generation attached by the host.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Attaches the current host policy generation before admission.
    #[must_use]
    pub const fn at_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Attaches the host's lease before accepting work on this authority.
    #[must_use]
    pub fn with_revocation(mut self, revocation: Arc<dyn InvocationRevocation>) -> Self {
        self.revocation = Some(revocation);
        self
    }

    /// Reports revocation independently of the originally granted access level.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revocation
            .as_ref()
            .is_some_and(|revocation| revocation.is_revoked())
    }

    /// Waits for the original grant to be revoked, or forever for a non-revocable host.
    #[must_use]
    pub fn revoked(&self) -> PortFuture<'_, ()> {
        self.revocation.as_ref().map_or_else(
            || Box::pin(std::future::pending()) as PortFuture<'_, ()>,
            |revocation| revocation.revoked(),
        )
    }
}

impl PartialEq for InvocationAuthority {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
            && self.subject == other.subject
            && self.account == other.account
            && self.access == other.access
            && self.generation == other.generation
            && match (&self.revocation, &other.revocation) {
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                (None, None) => true,
                _ => false,
            }
    }
}

impl Eq for InvocationAuthority {}

impl std::fmt::Debug for InvocationAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InvocationAuthority")
            .field("source", &self.source)
            .field("access", &self.access)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// A host-owned tool publication captured before asking for approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolBinding {
    identity: String,
    revision: u64,
    resource: Option<String>,
}

impl ToolBinding {
    /// Captures a host-assigned publication revision before asking for approval.
    ///
    /// # Errors
    /// Rejects missing, oversized or control-bearing tool identifiers and revision zero.
    pub fn new(identity: &str, revision: u64) -> Result<Self, PortError> {
        if identity.is_empty()
            || identity.len() > 256
            || identity.chars().any(char::is_control)
            || revision == 0
        {
            return Err(PortError::Invalid(
                "invalid tool publication binding".to_owned(),
            ));
        }
        Ok(Self {
            identity: identity.to_owned(),
            revision,
            resource: None,
        })
    }

    /// Host-owned tool publication identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Monotonic publication revision that must still match at execution.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Adds a bounded host-derived resource description to the reviewed publication.
    ///
    /// # Errors
    /// Rejects empty or oversized descriptions and terminal control characters.
    pub fn with_resource(mut self, resource: String) -> Result<Self, PortError> {
        if resource.is_empty() || resource.len() > 2048 || resource.chars().any(char::is_control) {
            return Err(PortError::Invalid(
                "invalid tool resource description".to_owned(),
            ));
        }
        self.resource = Some(resource);
        Ok(self)
    }

    /// Host-derived resource/workspace restriction shown with the approval.
    #[must_use]
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
}

/// A tool the runtime may dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDescriptor {
    /// The dispatch name used by providers.
    pub name: String,
    /// A one-line human summary.
    pub summary: String,
    /// Whether an approval decision is required before every call.
    pub requires_approval: bool,
    /// Whether a successful call can mutate the workspace.
    pub mutates_workspace: bool,
}

/// One dispatched tool call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolInvocation {
    /// The session that requested the call.
    pub session_id: SessionId,
    /// The turn that requested the call.
    pub turn: TurnId,
    /// The call to run.
    pub call: ToolCall,
}

/// How a tool call ended.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ToolStatus {
    /// The tool ran and succeeded.
    Ok,
    /// The tool ran and reported a failure.
    Failed,
    /// An operator refused the call.
    Denied,
    /// The call was cancelled before it finished.
    Cancelled,
    /// The call exceeded its deadline.
    TimedOut,
}

impl ToolStatus {
    /// Every status in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Ok,
        Self::Failed,
        Self::Denied,
        Self::Cancelled,
        Self::TimedOut,
    ];

    /// Returns the stable wire label for this status.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }

    /// Returns whether the provider should be told the call failed.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::Ok)
    }
}

/// The result of one tool call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolOutcome {
    /// The call this outcome answers.
    pub call_id: ToolCallId,
    /// How the call ended.
    pub status: ToolStatus,
    /// The serialised tool output or failure detail.
    pub output: String,
    /// Whether the call mutated the workspace.
    pub changed_workspace: bool,
}

/// Durable audit transitions for tools whose state is owned by the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InternalToolAuditPhase {
    /// Permission and approval were checked before the first possible effect.
    Authorized,
    /// Runtime-owned state was committed successfully.
    Completed,
    /// The authorized operation was refused or failed.
    Failed,
}

/// Runs tools on behalf of a turn.
///
/// Dropping the future returned by [`ToolPort::invoke`] must abort the call. `cancel` exists so
/// adapters that own external resources — subprocesses, sockets, remote jobs — can tear them down
/// eagerly instead of waiting for drop.
pub trait ToolPort: Send + Sync + 'static {
    /// Returns every tool this adapter can run.
    fn describe(&self) -> Vec<ToolDescriptor>;

    /// Runs one tool call.
    fn invoke(&self, invocation: ToolInvocation) -> PortFuture<'_, Result<ToolOutcome, PortError>>;

    /// Runs a call while preserving authenticated claims through the adapter boundary.
    ///
    /// The default refuses rather than discarding the authority and invoking the legacy entry.
    fn invoke_authorized(
        &self,
        _invocation: ToolInvocation,
        _authority: InvocationAuthority,
    ) -> PortFuture<'_, Result<ToolOutcome, PortError>> {
        Box::pin(std::future::ready(Err(PortError::Unavailable(
            "tool adapter cannot preserve authenticated invocation authority".to_owned(),
        ))))
    }

    /// Validates a call and captures its host-owned tool version without executing it.
    ///
    /// # Errors
    /// Refuses unsupported adapters, denied callers, invalid input and unavailable publications.
    fn bind_authorized(
        &self,
        _invocation: &ToolInvocation,
        _authority: &InvocationAuthority,
    ) -> Result<ToolBinding, PortError> {
        Err(PortError::Unavailable(
            "tool adapter cannot bind an authenticated publication".to_owned(),
        ))
    }

    /// Executes only the exact publication bound before approval.
    fn invoke_bound(
        &self,
        _invocation: ToolInvocation,
        _authority: InvocationAuthority,
        _binding: ToolBinding,
    ) -> PortFuture<'_, Result<ToolOutcome, PortError>> {
        Box::pin(std::future::ready(Err(PortError::Unavailable(
            "tool adapter cannot execute a bound publication".to_owned(),
        ))))
    }

    /// Persists runtime-owned tool effects without delegating their state mutation to the adapter.
    fn audit_internal<'a>(
        &'a self,
        _invocation: &'a ToolInvocation,
        _authority: &'a InvocationAuthority,
        _binding: &'a ToolBinding,
        _phase: InternalToolAuditPhase,
    ) -> PortFuture<'a, Result<(), PortError>> {
        Box::pin(std::future::ready(Err(PortError::Unavailable(
            "tool adapter cannot durably audit runtime-owned effects".to_owned(),
        ))))
    }

    /// Asks the adapter to abandon an in-flight call.
    fn cancel(&self, call_id: &ToolCallId) -> PortFuture<'_, Result<(), PortError>>;
}

#[cfg(test)]
mod tests {
    use super::{InvocationAccess, InvocationAuthority, InvocationSource, ToolStatus};

    #[test]
    fn invocation_authority_keeps_verified_claims_bounded_and_debug_redacted() {
        let reader = InvocationAuthority::new(
            InvocationSource::Mcp,
            "verified-subject",
            Some("verified-account"),
            InvocationAccess::ReadOnly,
            7,
        )
        .expect("verified claims");
        assert!(!reader.can_execute());
        assert!(!reader.is_owner());
        assert_eq!(reader.subject(), "verified-subject");
        assert_eq!(reader.account(), Some("verified-account"));
        assert_eq!(reader.generation(), 7);
        assert!(!format!("{reader:?}").contains("verified-"));
        let owner = InvocationAuthority::new(
            InvocationSource::Http,
            "subject",
            None,
            InvocationAccess::Owner,
            8,
        )
        .expect("owner");
        assert!(owner.can_execute() && owner.is_owner());
        for subject in [String::new(), "bad\nsubject".to_owned(), "x".repeat(257)] {
            assert!(
                InvocationAuthority::new(
                    InvocationSource::Gateway,
                    &subject,
                    None,
                    InvocationAccess::Execute,
                    0
                )
                .is_err()
            );
        }
    }

    #[test]
    fn tool_status_labels_are_stable() {
        let labels: Vec<&str> = ToolStatus::ALL.iter().map(|s| s.label()).collect();

        assert_eq!(
            labels,
            vec!["ok", "failed", "denied", "cancelled", "timed_out"]
        );
    }

    #[test]
    fn only_ok_is_a_success() {
        let failures: Vec<ToolStatus> = ToolStatus::ALL
            .into_iter()
            .filter(|status| status.is_failure())
            .collect();

        assert_eq!(
            failures,
            vec![
                ToolStatus::Failed,
                ToolStatus::Denied,
                ToolStatus::Cancelled,
                ToolStatus::TimedOut,
            ]
        );
    }
}

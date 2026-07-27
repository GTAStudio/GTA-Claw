use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_config::{CrestodianRescueConfig, RescueEnabled};
use serde::{Deserialize, Serialize};

use crate::mutation::{ConfigDigestChange, MutationRejection, TypedMutation};
use crate::ring::CrestodianOperation;

/// Exact prefix every rescue command must carry.
const RESCUE_PREFIX: &str = "/crestodian ";

/// Every accepted rescue command spelling, for the closed-grammar hint.
const GRAMMAR_HINT: &str = "use status, validate config, restart gateway, \
config set <path> <value>, config set-ref <path> env <NAME>, yes, or no";

/// Closed deterministic remote rescue command grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RescueCommand {
    /// One typed Crestodian operation.
    Operation(CrestodianOperation),
    /// Approve the exact pending mutation.
    Approve,
    /// Decline the pending mutation.
    Decline,
}

/// Why a message was not in the closed rescue grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RescueParseReason {
    /// The message is not a rescue command at all.
    NotARescueCommand,
    /// The command is outside the closed grammar.
    UnknownCommand,
    /// The command is known but its operands are incomplete.
    IncompleteCommand {
        /// Exact accepted spelling.
        expected: &'static str,
    },
    /// The typed mutation surface refused the operands.
    Mutation(MutationRejection),
}

/// A message was not in the closed rescue grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescueParseError {
    message: String,
    reason: RescueParseReason,
}

impl RescueParseError {
    /// Returns why the message was refused.
    #[must_use]
    pub const fn reason(&self) -> &RescueParseReason {
        &self.reason
    }
}

impl Display for RescueParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match &self.reason {
            RescueParseReason::NotARescueCommand => write!(
                formatter,
                "message {:?} is not a Crestodian rescue command; {GRAMMAR_HINT}",
                self.message
            ),
            RescueParseReason::UnknownCommand => write!(
                formatter,
                "unsupported Crestodian rescue command {:?}; {GRAMMAR_HINT}",
                self.message
            ),
            RescueParseReason::IncompleteCommand { expected } => write!(
                formatter,
                "incomplete Crestodian rescue command {:?}; expected {expected}",
                self.message
            ),
            RescueParseReason::Mutation(rejection) => Display::fmt(rejection, formatter),
        }
    }
}

impl Error for RescueParseError {}

/// Parses exact `/crestodian` rescue commands without inference.
///
/// The grammar is closed: nothing is guessed, no model is ever consulted, and a
/// message that is not spelled exactly is refused with the accepted spellings.
pub fn parse_rescue_command(message: &str) -> Result<RescueCommand, RescueParseError> {
    let trimmed = message.trim();
    let refuse = |reason: RescueParseReason| RescueParseError {
        message: trimmed.to_owned(),
        reason,
    };
    let Some(rest) = trimmed.strip_prefix(RESCUE_PREFIX) else {
        return Err(refuse(RescueParseReason::NotARescueCommand));
    };
    match rest {
        "status" => return Ok(RescueCommand::Operation(CrestodianOperation::Status)),
        "validate config" => {
            return Ok(RescueCommand::Operation(
                CrestodianOperation::ValidateConfig,
            ));
        }
        "restart gateway" => {
            return Ok(RescueCommand::Operation(
                CrestodianOperation::RestartGateway,
            ));
        }
        "yes" => return Ok(RescueCommand::Approve),
        "no" => return Ok(RescueCommand::Decline),
        _ => {}
    }
    if let Some(operands) = rest.strip_prefix("config set-ref ") {
        let tokens: Vec<&str> = operands.split(' ').collect();
        let [path, source, name] = tokens.as_slice() else {
            return Err(refuse(RescueParseReason::IncompleteCommand {
                expected: "config set-ref <path> env <NAME>",
            }));
        };
        return TypedMutation::set_reference(path, source, name)
            .map(|mutation| RescueCommand::Operation(CrestodianOperation::Configure(mutation)))
            .map_err(|rejection| refuse(RescueParseReason::Mutation(rejection)));
    }
    if let Some(operands) = rest.strip_prefix("config set ") {
        let Some((path, value)) = operands.split_once(' ') else {
            return Err(refuse(RescueParseReason::IncompleteCommand {
                expected: "config set <path> <value>",
            }));
        };
        return TypedMutation::set_text(path, value)
            .map(|mutation| RescueCommand::Operation(CrestodianOperation::Configure(mutation)))
            .map_err(|rejection| refuse(RescueParseReason::Mutation(rejection)));
    }
    Err(refuse(RescueParseReason::UnknownCommand))
}

/// Trusted message metadata used for authorization and audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescueContext {
    /// Whether the sender exactly matches configured owner identity.
    pub owner_verified: bool,
    /// Whether the message is a direct message.
    pub direct_message: bool,
    /// Whether the current session is sandboxed.
    pub sandboxed: bool,
    /// Whether execution posture is unsandboxed YOLO.
    pub yolo: bool,
    /// Stable channel identifier.
    pub channel: String,
    /// Stable channel account identifier.
    pub account: String,
    /// Stable sender identifier.
    pub sender: String,
    /// Transport source address or equivalent stable metadata.
    pub source_address: String,
}

/// Closed remote rescue authorization denial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RescueAuthorizationError {
    /// Rescue policy is disabled for this posture.
    Disabled,
    /// Sandboxed sessions can never use remote rescue.
    Sandboxed,
    /// Sender is not an explicitly verified owner.
    OwnerRequired,
    /// Owner identity metadata is missing, so the sender is effectively anonymous.
    AnonymousIdentity {
        /// Identity field that was blank.
        field: &'static str,
    },
    /// Policy allows only owner direct messages.
    DirectMessageRequired,
}

impl Display for RescueAuthorizationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("remote rescue is disabled for this posture"),
            Self::Sandboxed => formatter.write_str("remote rescue is forbidden while sandboxed"),
            Self::OwnerRequired => formatter.write_str("remote rescue requires a verified owner"),
            Self::AnonymousIdentity { field } => write!(
                formatter,
                "remote rescue requires an explicit owner identity, but {field} is empty"
            ),
            Self::DirectMessageRequired => {
                formatter.write_str("remote rescue requires an owner direct message")
            }
        }
    }
}

impl Error for RescueAuthorizationError {}

/// Authorizes a remote rescue context under the typed policy.
///
/// Every gate fails closed, and identity is required to be explicit: a context
/// that claims owner verification without stable channel, account, sender, and
/// source-address metadata is refused rather than trusted.
pub fn authorize_rescue(
    policy: &CrestodianRescueConfig,
    context: &RescueContext,
) -> Result<(), RescueAuthorizationError> {
    if context.sandboxed {
        return Err(RescueAuthorizationError::Sandboxed);
    }
    let enabled = match policy.enabled {
        RescueEnabled::Auto(_) => context.yolo,
        RescueEnabled::Explicit(enabled) => enabled,
    };
    if !enabled {
        return Err(RescueAuthorizationError::Disabled);
    }
    if !context.owner_verified {
        return Err(RescueAuthorizationError::OwnerRequired);
    }
    for (field, value) in [
        ("channel", &context.channel),
        ("account", &context.account),
        ("sender", &context.sender),
        ("source_address", &context.source_address),
    ] {
        if value.trim().is_empty() {
            return Err(RescueAuthorizationError::AnonymousIdentity { field });
        }
    }
    if policy.owner_dm_only && !context.direct_message {
        return Err(RescueAuthorizationError::DirectMessageRequired);
    }
    Ok(())
}

/// Read-only gateway health returned by rescue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RescueStatus {
    /// Whether the gateway responds.
    pub gateway_reachable: bool,
    /// Whether the strict configuration validates.
    pub config_valid: bool,
}

/// Minimal ring-zero rescue control plane.
pub trait RescueControlPlane {
    /// Concrete control-plane error.
    type Error: Error + Send + Sync + 'static;

    /// Reads gateway and config health.
    fn status(&mut self) -> Result<RescueStatus, Self::Error>;

    /// Restarts the gateway.
    fn restart_gateway(&mut self) -> Result<(), Self::Error>;

    /// Applies one approved typed mutation and reports both config digests.
    fn apply(&mut self, mutation: &TypedMutation) -> Result<ConfigDigestChange, Self::Error>;
}

/// Audited rescue event kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RescueAuditKind {
    /// Exact mutation was approved before execution.
    Approved,
    /// Approved mutation completed.
    Applied,
}

/// Metadata-only remote rescue audit event.
///
/// The operation is recorded by its stable label, and a configuration mutation
/// also records the configuration digests on both sides of the write. No
/// mutated value and no secret material ever reaches the audit trail.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RescueAuditEvent {
    /// Event kind.
    pub kind: RescueAuditKind,
    /// Stable operation label.
    pub operation: String,
    /// Stable channel identifier.
    pub channel: String,
    /// Stable account identifier.
    pub account: String,
    /// Stable sender identifier.
    pub sender: String,
    /// Source address metadata.
    pub source_address: String,
    /// Caller-supplied event time.
    pub unix_millis: u64,
    /// Configuration digests recorded for an applied configuration mutation.
    pub config_digest: Option<ConfigDigestChange>,
}

/// Mandatory durable rescue audit sink.
pub trait RescueAuditSink {
    /// Concrete audit persistence error.
    type Error: Error + Send + Sync + 'static;

    /// Persists one metadata-only event.
    fn persist(&mut self, event: &RescueAuditEvent) -> Result<(), Self::Error>;
}

/// A mutating operation staged for the owner's explicit approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingOperation {
    /// Gateway restart.
    RestartGateway,
    /// Typed configuration mutation.
    Configure(TypedMutation),
}

impl PendingOperation {
    /// Stages a mutating operation, or reports that the operation is read-only.
    #[must_use]
    pub fn staged(operation: CrestodianOperation) -> Option<Self> {
        match operation {
            CrestodianOperation::Status | CrestodianOperation::ValidateConfig => None,
            CrestodianOperation::RestartGateway => Some(Self::RestartGateway),
            CrestodianOperation::Configure(mutation) => Some(Self::Configure(mutation)),
        }
    }

    /// Returns the metadata-only audit label, never a mutated value.
    #[must_use]
    pub fn audit_label(&self) -> String {
        match self {
            Self::RestartGateway => "restart_gateway".to_owned(),
            Self::Configure(mutation) => mutation.audit_label(),
        }
    }

    /// Renders the approval proposal shown to the owner.
    #[must_use]
    pub fn proposal(&self) -> String {
        match self {
            Self::RestartGateway => "restart the gateway".to_owned(),
            Self::Configure(mutation) => mutation.proposal(),
        }
    }
}

/// Deterministic rescue response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RescueResponse {
    /// Read-only status.
    Status(RescueStatus),
    /// The exact mutation awaits owner approval.
    Planned {
        /// Stable operation label.
        operation: String,
        /// Owner-facing proposal, with secrets rendered as references.
        proposal: String,
        /// Expiration time.
        expires_at_unix_ms: u64,
    },
    /// The pending mutation was applied.
    Applied {
        /// Stable operation label.
        operation: String,
        /// Configuration digests recorded for a configuration mutation.
        config_digest: Option<ConfigDigestChange>,
    },
    /// Pending mutation was declined.
    Declined,
}

/// Rescue execution failure preserving concrete adapters.
#[derive(Debug)]
pub enum RescueError<ControlError, AuditError> {
    /// Policy rejected the caller or runtime posture.
    Authorization(RescueAuthorizationError),
    /// No pending mutation exists.
    NoPendingApproval,
    /// Pending approval expired.
    ApprovalExpired,
    /// Approval came from different message metadata.
    ApprovalIdentityChanged,
    /// Control-plane operation failed.
    Control(ControlError),
    /// Mandatory audit persistence failed.
    Audit(AuditError),
    /// Mutation completed, but its post-action audit receipt could not persist.
    AppliedButAuditFailed(AuditError),
}

impl<ControlError: Display, AuditError: Display> Display for RescueError<ControlError, AuditError> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authorization(error) => write!(formatter, "{error}"),
            Self::NoPendingApproval => formatter.write_str("no rescue mutation is pending"),
            Self::ApprovalExpired => formatter.write_str("pending rescue approval expired"),
            Self::ApprovalIdentityChanged => {
                formatter.write_str("pending rescue approval belongs to different message metadata")
            }
            Self::Control(error) => write!(formatter, "rescue control plane failed: {error}"),
            Self::Audit(error) => write!(formatter, "rescue audit persistence failed: {error}"),
            Self::AppliedButAuditFailed(error) => write!(
                formatter,
                "rescue mutation completed, but its audit receipt failed: {error}"
            ),
        }
    }
}

impl<ControlError, AuditError> Error for RescueError<ControlError, AuditError>
where
    ControlError: Error + 'static,
    AuditError: Error + 'static,
{
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Pending {
    operation: PendingOperation,
    expires_at_unix_ms: u64,
    channel: String,
    account: String,
    sender: String,
    source_address: String,
}

/// Stateful deterministic rescue approval handler.
///
/// A pending approval lives only in memory, so a gateway restart always drops
/// it and an approval that arrives after a restart has nothing to apply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescueSession {
    policy: CrestodianRescueConfig,
    pending: Option<Pending>,
}

impl RescueSession {
    /// Creates an empty rescue session under one immutable policy.
    #[must_use]
    pub const fn new(policy: CrestodianRescueConfig) -> Self {
        Self {
            policy,
            pending: None,
        }
    }

    /// Whether an approval is currently pending.
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Returns the policy this session enforces.
    #[must_use]
    pub const fn policy(&self) -> &CrestodianRescueConfig {
        &self.policy
    }

    /// Executes read-only commands or manages one exact pending mutation.
    pub fn handle<C, A>(
        &mut self,
        command: RescueCommand,
        context: &RescueContext,
        unix_millis: u64,
        control: &mut C,
        audit: &mut A,
    ) -> Result<RescueResponse, RescueError<C::Error, A::Error>>
    where
        C: RescueControlPlane,
        A: RescueAuditSink,
    {
        authorize_rescue(&self.policy, context).map_err(RescueError::Authorization)?;
        match command {
            RescueCommand::Operation(operation) => match PendingOperation::staged(operation) {
                None => control
                    .status()
                    .map(RescueResponse::Status)
                    .map_err(RescueError::Control),
                Some(staged) => {
                    let expires_at_unix_ms = unix_millis
                        .saturating_add(u64::from(self.policy.pending_ttl_minutes) * 60_000);
                    let response = RescueResponse::Planned {
                        operation: staged.audit_label(),
                        proposal: staged.proposal(),
                        expires_at_unix_ms,
                    };
                    self.pending = Some(Pending {
                        operation: staged,
                        expires_at_unix_ms,
                        channel: context.channel.clone(),
                        account: context.account.clone(),
                        sender: context.sender.clone(),
                        source_address: context.source_address.clone(),
                    });
                    Ok(response)
                }
            },
            RescueCommand::Decline => {
                self.pending = None;
                Ok(RescueResponse::Declined)
            }
            RescueCommand::Approve => {
                let pending = self.pending.take().ok_or(RescueError::NoPendingApproval)?;
                if unix_millis > pending.expires_at_unix_ms {
                    return Err(RescueError::ApprovalExpired);
                }
                if pending.channel != context.channel
                    || pending.account != context.account
                    || pending.sender != context.sender
                    || pending.source_address != context.source_address
                {
                    return Err(RescueError::ApprovalIdentityChanged);
                }
                let operation = pending.operation.audit_label();
                audit
                    .persist(&event(
                        RescueAuditKind::Approved,
                        operation.clone(),
                        context,
                        unix_millis,
                        None,
                    ))
                    .map_err(RescueError::Audit)?;
                let config_digest = match &pending.operation {
                    PendingOperation::RestartGateway => {
                        control.restart_gateway().map_err(RescueError::Control)?;
                        None
                    }
                    PendingOperation::Configure(mutation) => {
                        Some(control.apply(mutation).map_err(RescueError::Control)?)
                    }
                };
                audit
                    .persist(&event(
                        RescueAuditKind::Applied,
                        operation.clone(),
                        context,
                        unix_millis,
                        config_digest.clone(),
                    ))
                    .map_err(RescueError::AppliedButAuditFailed)?;
                Ok(RescueResponse::Applied {
                    operation,
                    config_digest,
                })
            }
        }
    }
}

fn event(
    kind: RescueAuditKind,
    operation: String,
    context: &RescueContext,
    unix_millis: u64,
    config_digest: Option<ConfigDigestChange>,
) -> RescueAuditEvent {
    RescueAuditEvent {
        kind,
        operation,
        channel: context.channel.clone(),
        account: context.account.clone(),
        sender: context.sender.clone(),
        source_address: context.source_address.clone(),
        unix_millis,
        config_digest,
    }
}

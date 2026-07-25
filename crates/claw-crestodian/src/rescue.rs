use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_config::{CrestodianRescueConfig, RescueEnabled};

/// Closed deterministic remote rescue command grammar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RescueCommand {
    /// Show gateway/config health.
    Status,
    /// Validate the current configuration.
    ValidateConfig,
    /// Propose a gateway restart.
    RestartGateway,
    /// Approve the exact pending mutation.
    Approve,
    /// Decline the pending mutation.
    Decline,
}

/// A message was not in the closed rescue grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescueParseError {
    message: String,
}

impl Display for RescueParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "unsupported Crestodian rescue command {:?}; use status, validate config, restart gateway, yes, or no",
            self.message
        )
    }
}

impl Error for RescueParseError {}

/// Parses exact `/crestodian` rescue commands without inference.
pub fn parse_rescue_command(message: &str) -> Result<RescueCommand, RescueParseError> {
    match message.trim() {
        "/crestodian status" => Ok(RescueCommand::Status),
        "/crestodian validate config" => Ok(RescueCommand::ValidateConfig),
        "/crestodian restart gateway" => Ok(RescueCommand::RestartGateway),
        "/crestodian yes" => Ok(RescueCommand::Approve),
        "/crestodian no" => Ok(RescueCommand::Decline),
        _ => Err(RescueParseError {
            message: message.to_owned(),
        }),
    }
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
    /// Policy allows only owner direct messages.
    DirectMessageRequired,
}

impl Display for RescueAuthorizationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("remote rescue is disabled for this posture"),
            Self::Sandboxed => formatter.write_str("remote rescue is forbidden while sandboxed"),
            Self::OwnerRequired => formatter.write_str("remote rescue requires a verified owner"),
            Self::DirectMessageRequired => {
                formatter.write_str("remote rescue requires an owner direct message")
            }
        }
    }
}

impl Error for RescueAuthorizationError {}

/// Authorizes a remote rescue context under the typed policy.
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
}

/// Audited rescue event kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RescueAuditKind {
    /// Exact mutation was approved before execution.
    Approved,
    /// Approved mutation completed.
    Applied,
}

/// Metadata-only remote rescue audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescueAuditEvent {
    /// Event kind.
    pub kind: RescueAuditKind,
    /// Typed operation.
    pub operation: RescueCommand,
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
}

/// Mandatory durable rescue audit sink.
pub trait RescueAuditSink {
    /// Concrete audit persistence error.
    type Error: Error + Send + Sync + 'static;

    /// Persists one metadata-only event.
    fn persist(&mut self, event: &RescueAuditEvent) -> Result<(), Self::Error>;
}

/// Deterministic rescue response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RescueResponse {
    /// Read-only status.
    Status(RescueStatus),
    /// Exact restart awaits owner approval.
    RestartPlanned {
        /// Expiration time.
        expires_at_unix_ms: u64,
    },
    /// Pending restart was applied.
    Restarted,
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
                "gateway restart completed, but its audit receipt failed: {error}"
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
struct PendingRestart {
    expires_at_unix_ms: u64,
    channel: String,
    account: String,
    sender: String,
    source_address: String,
}

/// Stateful deterministic rescue approval handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RescueSession {
    policy: CrestodianRescueConfig,
    pending: Option<PendingRestart>,
}

impl RescueSession {
    /// Creates an empty rescue session under one immutable policy.
    #[must_use]
    pub fn new(policy: CrestodianRescueConfig) -> Self {
        Self {
            policy,
            pending: None,
        }
    }

    /// Executes read-only commands or manages one exact pending restart.
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
            RescueCommand::Status | RescueCommand::ValidateConfig => control
                .status()
                .map(RescueResponse::Status)
                .map_err(RescueError::Control),
            RescueCommand::RestartGateway => {
                let expires_at_unix_ms =
                    unix_millis.saturating_add(u64::from(self.policy.pending_ttl_minutes) * 60_000);
                self.pending = Some(PendingRestart {
                    expires_at_unix_ms,
                    channel: context.channel.clone(),
                    account: context.account.clone(),
                    sender: context.sender.clone(),
                    source_address: context.source_address.clone(),
                });
                Ok(RescueResponse::RestartPlanned { expires_at_unix_ms })
            }
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
                audit
                    .persist(&event(RescueAuditKind::Approved, context, unix_millis))
                    .map_err(RescueError::Audit)?;
                control.restart_gateway().map_err(RescueError::Control)?;
                audit
                    .persist(&event(RescueAuditKind::Applied, context, unix_millis))
                    .map_err(RescueError::AppliedButAuditFailed)?;
                Ok(RescueResponse::Restarted)
            }
        }
    }
}

fn event(kind: RescueAuditKind, context: &RescueContext, unix_millis: u64) -> RescueAuditEvent {
    RescueAuditEvent {
        kind,
        operation: RescueCommand::RestartGateway,
        channel: context.channel.clone(),
        account: context.account.clone(),
        sender: context.sender.clone(),
        source_address: context.source_address.clone(),
        unix_millis,
    }
}

//! Deterministic owner-DM rescue grammar and approval tests.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_config::{CrestodianRescueConfig, RescueEnabled};
use claw_crestodian::{
    RescueAuditEvent, RescueAuditKind, RescueAuditSink, RescueAuthorizationError, RescueCommand,
    RescueContext, RescueControlPlane, RescueError, RescueResponse, RescueSession, RescueStatus,
    authorize_rescue, parse_rescue_command,
};

#[derive(Debug)]
struct AdapterError(&'static str);

impl Display for AdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for AdapterError {}

struct Control {
    status: RescueStatus,
    restarts: usize,
    fail: bool,
}

impl RescueControlPlane for Control {
    type Error = AdapterError;

    fn status(&mut self) -> Result<RescueStatus, Self::Error> {
        if self.fail {
            Err(AdapterError("status failed"))
        } else {
            Ok(self.status)
        }
    }

    fn restart_gateway(&mut self) -> Result<(), Self::Error> {
        if self.fail {
            Err(AdapterError("restart failed"))
        } else {
            self.restarts += 1;
            Ok(())
        }
    }
}

struct Audit {
    events: Vec<RescueAuditEvent>,
    fail: bool,
    fail_after_first: bool,
}

impl RescueAuditSink for Audit {
    type Error = AdapterError;

    fn persist(&mut self, event: &RescueAuditEvent) -> Result<(), Self::Error> {
        if self.fail || (self.fail_after_first && !self.events.is_empty()) {
            Err(AdapterError("audit failed"))
        } else {
            self.events.push(event.clone());
            Ok(())
        }
    }
}

#[test]
fn rescue_parser_accepts_only_the_closed_command_grammar() {
    let cases = [
        ("/crestodian status", RescueCommand::Status),
        ("/crestodian validate config", RescueCommand::ValidateConfig),
        ("/crestodian restart gateway", RescueCommand::RestartGateway),
        ("/crestodian yes", RescueCommand::Approve),
        ("/crestodian no", RescueCommand::Decline),
    ];
    for (source, expected) in cases {
        assert_eq!(parse_rescue_command(source), Ok(expected));
    }
    let error = parse_rescue_command("/crestodian please fix everything")
        .expect_err("natural language must fail closed");
    assert_eq!(
        error.to_string(),
        "unsupported Crestodian rescue command \"/crestodian please fix everything\"; use status, validate config, restart gateway, yes, or no"
    );
}

#[test]
fn sandbox_owner_and_direct_message_gates_are_fail_closed() {
    let policy = policy();
    let context = context();
    assert_eq!(authorize_rescue(&policy, &context), Ok(()));

    let mut sandboxed = context.clone();
    sandboxed.sandboxed = true;
    assert_eq!(
        authorize_rescue(&policy, &sandboxed),
        Err(RescueAuthorizationError::Sandboxed)
    );
    let mut stranger = context.clone();
    stranger.owner_verified = false;
    assert_eq!(
        authorize_rescue(&policy, &stranger),
        Err(RescueAuthorizationError::OwnerRequired)
    );
    let mut group = context.clone();
    group.direct_message = false;
    assert_eq!(
        authorize_rescue(&policy, &group),
        Err(RescueAuthorizationError::DirectMessageRequired)
    );
    let mut non_yolo = context;
    non_yolo.yolo = false;
    assert_eq!(
        authorize_rescue(&policy, &non_yolo),
        Err(RescueAuthorizationError::Disabled)
    );
}

#[test]
fn restart_requires_same_owner_approval_and_writes_metadata_only_audit() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = audit();

    let planned = session
        .handle(
            RescueCommand::RestartGateway,
            &context,
            1_000,
            &mut control,
            &mut audit,
        )
        .expect("plan restart");
    assert_eq!(
        planned,
        RescueResponse::RestartPlanned {
            expires_at_unix_ms: 901_000,
        }
    );
    assert_eq!(control.restarts, 0);
    assert_eq!(audit.events, Vec::new());

    let applied = session
        .handle(
            RescueCommand::Approve,
            &context,
            2_000,
            &mut control,
            &mut audit,
        )
        .expect("approve restart");
    assert_eq!(applied, RescueResponse::Restarted);
    assert_eq!(control.restarts, 1);
    assert_eq!(
        audit.events,
        vec![
            RescueAuditEvent {
                kind: RescueAuditKind::Approved,
                operation: RescueCommand::RestartGateway,
                channel: "telegram".to_owned(),
                account: "primary".to_owned(),
                sender: "owner-42".to_owned(),
                source_address: "chat-99".to_owned(),
                unix_millis: 2_000,
            },
            RescueAuditEvent {
                kind: RescueAuditKind::Applied,
                operation: RescueCommand::RestartGateway,
                channel: "telegram".to_owned(),
                account: "primary".to_owned(),
                sender: "owner-42".to_owned(),
                source_address: "chat-99".to_owned(),
                unix_millis: 2_000,
            },
        ]
    );
}

#[test]
fn expired_or_changed_identity_approval_never_restarts() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = audit();
    session
        .handle(
            RescueCommand::RestartGateway,
            &context,
            0,
            &mut control,
            &mut audit,
        )
        .expect("plan");
    let expired = session
        .handle(
            RescueCommand::Approve,
            &context,
            900_001,
            &mut control,
            &mut audit,
        )
        .expect_err("expired");
    match expired {
        RescueError::ApprovalExpired => {}
        other => panic!("expected expiration, got {other}"),
    }
    assert_eq!(control.restarts, 0);
    assert_eq!(audit.events, Vec::new());

    session
        .handle(
            RescueCommand::RestartGateway,
            &context,
            1_000_000,
            &mut control,
            &mut audit,
        )
        .expect("plan again");
    let mut changed = context;
    changed.sender = "different-owner".to_owned();
    let error = session
        .handle(
            RescueCommand::Approve,
            &changed,
            1_000_001,
            &mut control,
            &mut audit,
        )
        .expect_err("identity changed");
    match error {
        RescueError::ApprovalIdentityChanged => {}
        other => panic!("expected identity rejection, got {other}"),
    }
    assert_eq!(control.restarts, 0);
}

#[test]
fn mandatory_pre_action_audit_failure_prevents_restart() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = Audit {
        events: Vec::new(),
        fail: true,
        fail_after_first: false,
    };
    session
        .handle(
            RescueCommand::RestartGateway,
            &context,
            10,
            &mut control,
            &mut audit,
        )
        .expect("plan");

    let error = session
        .handle(
            RescueCommand::Approve,
            &context,
            11,
            &mut control,
            &mut audit,
        )
        .expect_err("audit failure");
    match error {
        RescueError::Audit(AdapterError(message)) => {
            assert_eq!(message, "audit failed");
        }
        other => panic!("expected audit failure, got {other}"),
    }
    assert_eq!(control.restarts, 0);
}

#[test]
fn post_action_audit_failure_explicitly_reports_that_restart_completed() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = Audit {
        events: Vec::new(),
        fail: false,
        fail_after_first: true,
    };
    session
        .handle(
            RescueCommand::RestartGateway,
            &context,
            10,
            &mut control,
            &mut audit,
        )
        .expect("plan");

    let error = session
        .handle(
            RescueCommand::Approve,
            &context,
            11,
            &mut control,
            &mut audit,
        )
        .expect_err("post-action receipt fails");
    match error {
        RescueError::AppliedButAuditFailed(AdapterError(message)) => {
            assert_eq!(message, "audit failed");
        }
        other => panic!("expected explicit applied-but-audit-failed outcome, got {other}"),
    }
    assert_eq!(control.restarts, 1);
    assert_eq!(audit.events.len(), 1);
    assert_eq!(audit.events[0].kind, RescueAuditKind::Approved);
}

#[test]
fn read_only_status_runs_without_approval_or_audit() {
    let mut session = RescueSession::new(policy());
    let mut control = control();
    let mut audit = audit();
    let response = session
        .handle(
            RescueCommand::Status,
            &context(),
            0,
            &mut control,
            &mut audit,
        )
        .expect("status");

    assert_eq!(
        response,
        RescueResponse::Status(RescueStatus {
            gateway_reachable: false,
            config_valid: false,
        })
    );
    assert_eq!(control.restarts, 0);
    assert_eq!(audit.events, Vec::new());
}

fn policy() -> CrestodianRescueConfig {
    CrestodianRescueConfig {
        enabled: RescueEnabled::default(),
        owner_dm_only: true,
        pending_ttl_minutes: 15,
    }
}

fn context() -> RescueContext {
    RescueContext {
        owner_verified: true,
        direct_message: true,
        sandboxed: false,
        yolo: true,
        channel: "telegram".to_owned(),
        account: "primary".to_owned(),
        sender: "owner-42".to_owned(),
        source_address: "chat-99".to_owned(),
    }
}

fn control() -> Control {
    Control {
        status: RescueStatus {
            gateway_reachable: false,
            config_valid: false,
        },
        restarts: 0,
        fail: false,
    }
}

fn audit() -> Audit {
    Audit {
        events: Vec::new(),
        fail: false,
        fail_after_first: false,
    }
}

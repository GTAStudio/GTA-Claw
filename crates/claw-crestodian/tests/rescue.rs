//! Closed rescue grammar, owner-DM authorization, and approval acceptance tests.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_config::{CrestodianRescueConfig, RescueEnabled};
use claw_crestodian::{
    ConfigDigestChange, CrestodianOperation, CrestodianSettings, RescueAuditEvent, RescueAuditKind,
    RescueAuditSink, RescueAuthorizationError, RescueCommand, RescueContext, RescueControlPlane,
    RescueError, RescueParseReason, RescueResponse, RescueSession, RescueStatus, TypedMutation,
    authorize_rescue, parse_rescue_command,
};

/// Frozen rescue grammar. Every accepted spelling and every refusal is pinned,
/// so widening or narrowing the grammar cannot pass unnoticed.
const GOLDEN_GRAMMAR: &[(&str, &str)] = &[
    ("/crestodian status", "op:status"),
    ("/crestodian validate config", "op:validate_config"),
    ("/crestodian restart gateway", "op:restart_gateway"),
    ("  /crestodian status  ", "op:status"),
    ("/crestodian yes", "approve"),
    ("/crestodian no", "decline"),
    (
        "/crestodian config set gateway.port 19001",
        "op:config_set:gateway.port [set gateway.port = 19001]",
    ),
    (
        "/crestodian config set crestodian.rescue.pendingTtlMinutes 30",
        "op:config_set:crestodian.rescue.pendingTtlMinutes [set crestodian.rescue.pendingTtlMinutes = 30]",
    ),
    (
        "/crestodian config set crestodian.rescue.enabled auto",
        "op:config_set:crestodian.rescue.enabled [set crestodian.rescue.enabled = auto]",
    ),
    (
        "/crestodian config set crestodian.rescue.ownerDmOnly false",
        "op:config_set:crestodian.rescue.ownerDmOnly [set crestodian.rescue.ownerDmOnly = false]",
    ),
    (
        "/crestodian config set-ref gateway.auth.token env OPENCLAW_GATEWAY_TOKEN",
        "op:config_set_ref:gateway.auth.token [set-ref gateway.auth.token = env:OPENCLAW_GATEWAY_TOKEN]",
    ),
    (
        "/crestodian please fix everything",
        "error:unsupported Crestodian rescue command \"/crestodian please fix everything\"; use status, validate config, restart gateway, config set <path> <value>, config set-ref <path> env <NAME>, yes, or no",
    ),
    (
        "/crestodian STATUS",
        "error:unsupported Crestodian rescue command \"/crestodian STATUS\"; use status, validate config, restart gateway, config set <path> <value>, config set-ref <path> env <NAME>, yes, or no",
    ),
    (
        "/crestodian  status",
        "error:unsupported Crestodian rescue command \"/crestodian  status\"; use status, validate config, restart gateway, config set <path> <value>, config set-ref <path> env <NAME>, yes, or no",
    ),
    (
        "why did my gateway stop?",
        "error:message \"why did my gateway stop?\" is not a Crestodian rescue command; use status, validate config, restart gateway, config set <path> <value>, config set-ref <path> env <NAME>, yes, or no",
    ),
    (
        "/crestodian",
        "error:message \"/crestodian\" is not a Crestodian rescue command; use status, validate config, restart gateway, config set <path> <value>, config set-ref <path> env <NAME>, yes, or no",
    ),
    (
        "/crestodian config set gateway.port",
        "error:incomplete Crestodian rescue command \"/crestodian config set gateway.port\"; expected config set <path> <value>",
    ),
    (
        "/crestodian config set-ref gateway.auth.token env",
        "error:incomplete Crestodian rescue command \"/crestodian config set-ref gateway.auth.token env\"; expected config set-ref <path> env <NAME>",
    ),
    (
        "/crestodian config set gateway.port 70000",
        "error:configuration path gateway.port accepts 1..=65535, but received 70000",
    ),
    (
        "/crestodian config set gateway.port eighty",
        "error:configuration path gateway.port expects non-negative integer, but received text",
    ),
    (
        "/crestodian config set auth.token abc",
        "error:configuration path \"auth.token\" owns the inference route and cannot be written by Crestodian; run openclaw onboard",
    ),
    (
        "/crestodian config set secrets.gateway abc",
        "error:configuration path \"secrets.gateway\" owns credential resolution and cannot be written by Crestodian",
    ),
    (
        "/crestodian config set gateway.auth.token hunter2",
        "error:configuration path gateway.auth.token holds secret material; use config set-ref gateway.auth.token env <NAME>",
    ),
    (
        "/crestodian config set-ref gateway.port env PORT",
        "error:configuration path gateway.port holds no secret material and takes a literal value",
    ),
    (
        "/crestodian config set-ref gateway.auth.token file /etc/token",
        "error:secret source \"file\" is unsupported; only env is accepted",
    ),
    (
        "/crestodian config set nope.thing 1",
        "error:configuration path \"nope.thing\" is not ring-zero writable",
    ),
    (
        "/crestodian config set ..bad 1",
        "error:configuration path \"..bad\" must not contain an empty segment",
    ),
];

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
    applied: Vec<TypedMutation>,
    settings: CrestodianSettings,
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

    fn apply(&mut self, mutation: &TypedMutation) -> Result<ConfigDigestChange, Self::Error> {
        if self.fail {
            return Err(AdapterError("apply failed"));
        }
        let before = self
            .settings
            .digest()
            .map_err(|_| AdapterError("digest failed"))?;
        self.settings.apply(mutation);
        let after = self
            .settings
            .digest()
            .map_err(|_| AdapterError("digest failed"))?;
        self.applied.push(mutation.clone());
        Ok(ConfigDigestChange { before, after })
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
fn rescue_grammar_matches_the_frozen_golden_table() {
    for (source, expected) in GOLDEN_GRAMMAR {
        assert_eq!(&render(source), expected, "grammar drift for {source:?}");
    }
}

#[test]
fn natural_language_is_refused_by_reason_and_never_inferred() {
    let error = parse_rescue_command("/crestodian please restart the gateway for me")
        .expect_err("natural language must fail closed");
    assert_eq!(error.reason(), &RescueParseReason::UnknownCommand);

    let error = parse_rescue_command("restart gateway").expect_err("bare prose must fail closed");
    assert_eq!(error.reason(), &RescueParseReason::NotARescueCommand);

    let error = parse_rescue_command("/crestodian config set gateway.port 0")
        .expect_err("out-of-range port must fail closed");
    assert!(matches!(error.reason(), RescueParseReason::Mutation(_)));
}

#[test]
fn sandbox_owner_identity_and_direct_message_gates_are_fail_closed() {
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
    let mut non_yolo = context.clone();
    non_yolo.yolo = false;
    assert_eq!(
        authorize_rescue(&policy, &non_yolo),
        Err(RescueAuthorizationError::Disabled)
    );
    let mut disabled = policy.clone();
    disabled.enabled = RescueEnabled::Explicit(false);
    assert_eq!(
        authorize_rescue(&disabled, &context),
        Err(RescueAuthorizationError::Disabled)
    );
}

#[test]
fn owner_identity_must_be_explicit_on_every_metadata_field() {
    type Blank = fn(&mut RescueContext);

    let policy = policy();
    let cases: [(&str, Blank); 4] = [
        ("channel", |context| context.channel = String::new()),
        ("account", |context| context.account = "   ".to_owned()),
        ("sender", |context| context.sender = String::new()),
        ("source_address", |context| {
            context.source_address = String::new();
        }),
    ];
    for (field, blank) in cases {
        let mut anonymous = context();
        blank(&mut anonymous);
        assert_eq!(
            authorize_rescue(&policy, &anonymous),
            Err(RescueAuthorizationError::AnonymousIdentity { field }),
            "{field} must be explicit"
        );
    }

    let error = authorize_rescue(
        &policy,
        &RescueContext {
            sender: String::new(),
            ..context()
        },
    )
    .expect_err("anonymous sender");
    assert_eq!(
        error.to_string(),
        "remote rescue requires an explicit owner identity, but sender is empty"
    );
}

#[test]
fn group_rescue_runs_only_after_explicit_opt_in() {
    let mut group = context();
    group.direct_message = false;
    assert_eq!(
        authorize_rescue(&policy(), &group),
        Err(RescueAuthorizationError::DirectMessageRequired)
    );

    let opted_in = CrestodianRescueConfig {
        owner_dm_only: false,
        ..policy()
    };
    assert_eq!(authorize_rescue(&opted_in, &group), Ok(()));

    let mut stranger = group;
    stranger.owner_verified = false;
    assert_eq!(
        authorize_rescue(&opted_in, &stranger),
        Err(RescueAuthorizationError::OwnerRequired)
    );
}

#[test]
fn restart_requires_same_owner_approval_and_writes_metadata_only_audit() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = audit();

    let planned = session
        .handle(restart(), &context, 1_000, &mut control, &mut audit)
        .expect("plan restart");
    assert_eq!(
        planned,
        RescueResponse::Planned {
            operation: "restart_gateway".to_owned(),
            proposal: "restart the gateway".to_owned(),
            expires_at_unix_ms: 901_000,
        }
    );
    assert!(session.has_pending());
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
    assert_eq!(
        applied,
        RescueResponse::Applied {
            operation: "restart_gateway".to_owned(),
            config_digest: None,
        }
    );
    assert!(!session.has_pending());
    assert_eq!(control.restarts, 1);
    assert_eq!(
        audit.events,
        vec![
            audit_event(RescueAuditKind::Approved, "restart_gateway", 2_000, None),
            audit_event(RescueAuditKind::Applied, "restart_gateway", 2_000, None),
        ]
    );
}

#[test]
fn approved_config_mutation_records_digests_and_never_the_written_value() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = audit();
    let command = parse_rescue_command("/crestodian config set gateway.port 19001")
        .expect("typed mutation command");

    let planned = session
        .handle(command, &context, 1_000, &mut control, &mut audit)
        .expect("plan mutation");
    assert_eq!(
        planned,
        RescueResponse::Planned {
            operation: "config_set:gateway.port".to_owned(),
            proposal: "set gateway.port = 19001".to_owned(),
            expires_at_unix_ms: 901_000,
        }
    );
    assert_eq!(control.applied, Vec::new());

    let before = control.settings.digest().expect("digest before");
    let applied = session
        .handle(
            RescueCommand::Approve,
            &context,
            2_000,
            &mut control,
            &mut audit,
        )
        .expect("approve mutation");
    let after = control.settings.digest().expect("digest after");
    assert_ne!(before, after);
    assert_eq!(
        applied,
        RescueResponse::Applied {
            operation: "config_set:gateway.port".to_owned(),
            config_digest: Some(ConfigDigestChange {
                before: before.clone(),
                after: after.clone(),
            }),
        }
    );
    assert_eq!(control.applied, vec![TypedMutation::GatewayPort(19_001)]);
    assert_eq!(control.settings.gateway_port, 19_001);
    assert_eq!(
        audit.events,
        vec![
            audit_event(
                RescueAuditKind::Approved,
                "config_set:gateway.port",
                2_000,
                None
            ),
            audit_event(
                RescueAuditKind::Applied,
                "config_set:gateway.port",
                2_000,
                Some(ConfigDigestChange { before, after })
            ),
        ]
    );
    let trail = serde_json::to_string(&audit.events).expect("serialize audit trail");
    assert!(
        !trail.contains("19001"),
        "audit trail must stay metadata-only: {trail}"
    );
}

#[test]
fn expired_or_changed_identity_approval_never_mutates() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = audit();
    session
        .handle(restart(), &context, 0, &mut control, &mut audit)
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
        .handle(restart(), &context, 1_000_000, &mut control, &mut audit)
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
    assert_eq!(audit.events, Vec::new());
}

#[test]
fn declining_drops_the_pending_mutation_before_any_side_effect() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = audit();
    session
        .handle(restart(), &context, 10, &mut control, &mut audit)
        .expect("plan");

    assert_eq!(
        session
            .handle(
                RescueCommand::Decline,
                &context,
                11,
                &mut control,
                &mut audit
            )
            .expect("decline"),
        RescueResponse::Declined
    );
    assert!(!session.has_pending());
    let error = session
        .handle(
            RescueCommand::Approve,
            &context,
            12,
            &mut control,
            &mut audit,
        )
        .expect_err("nothing pending");
    match error {
        RescueError::NoPendingApproval => {}
        other => panic!("expected no pending approval, got {other}"),
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
        .handle(restart(), &context, 10, &mut control, &mut audit)
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
fn post_action_audit_failure_explicitly_reports_that_the_mutation_completed() {
    let mut session = RescueSession::new(policy());
    let context = context();
    let mut control = control();
    let mut audit = Audit {
        events: Vec::new(),
        fail: false,
        fail_after_first: true,
    };
    session
        .handle(restart(), &context, 10, &mut control, &mut audit)
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
            RescueCommand::Operation(CrestodianOperation::Status),
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
    assert!(!session.has_pending());
    assert_eq!(control.restarts, 0);
    assert_eq!(audit.events, Vec::new());
}

#[test]
fn a_denied_context_never_reaches_the_control_plane() {
    let mut session = RescueSession::new(policy());
    let mut control = control();
    let mut audit = audit();
    let mut sandboxed = context();
    sandboxed.sandboxed = true;

    let error = session
        .handle(restart(), &sandboxed, 0, &mut control, &mut audit)
        .expect_err("sandboxed rescue");
    match error {
        RescueError::Authorization(RescueAuthorizationError::Sandboxed) => {}
        other => panic!("expected sandbox refusal, got {other}"),
    }
    assert!(!session.has_pending());
    assert_eq!(control.restarts, 0);
    assert_eq!(control.applied, Vec::new());
    assert_eq!(audit.events, Vec::new());
}

fn render(source: &str) -> String {
    match parse_rescue_command(source) {
        Ok(RescueCommand::Approve) => "approve".to_owned(),
        Ok(RescueCommand::Decline) => "decline".to_owned(),
        Ok(RescueCommand::Operation(CrestodianOperation::Configure(mutation))) => {
            format!("op:{} [{}]", mutation.audit_label(), mutation.proposal())
        }
        Ok(RescueCommand::Operation(operation)) => format!("op:{}", operation.audit_label()),
        Err(error) => format!("error:{error}"),
    }
}

fn restart() -> RescueCommand {
    RescueCommand::Operation(CrestodianOperation::RestartGateway)
}

fn audit_event(
    kind: RescueAuditKind,
    operation: &str,
    unix_millis: u64,
    config_digest: Option<ConfigDigestChange>,
) -> RescueAuditEvent {
    RescueAuditEvent {
        kind,
        operation: operation.to_owned(),
        channel: "telegram".to_owned(),
        account: "primary".to_owned(),
        sender: "owner-42".to_owned(),
        source_address: "chat-99".to_owned(),
        unix_millis,
        config_digest,
    }
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
        applied: Vec::new(),
        settings: CrestodianSettings::default(),
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

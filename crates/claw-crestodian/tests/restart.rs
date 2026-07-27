//! Restart acceptance tests.
//!
//! A gateway restart must carry the durable ring-zero settings forward exactly
//! and must drop everything that was never confirmed — above all a pending
//! approval for a mutation the owner has not approved since the restart.

mod common;

use claw_config::{RescueAuto, RescueEnabled};
use claw_crestodian::{
    CrestodianError, CrestodianRuntime, CrestodianSettings, DEFAULT_GATEWAY_PORT, JsonlRescueAudit,
    RescueAuditKind, RescueCommand, RescueContext, RescueControlPlane, RescueError, RescueResponse,
    RescueStatus, TypedMutation, parse_rescue_command,
};

use common::TestDirectory;

struct Control<'a> {
    runtime: &'a mut CrestodianRuntime,
    restarts: usize,
}

impl RescueControlPlane for Control<'_> {
    type Error = CrestodianError;

    fn status(&mut self) -> Result<RescueStatus, Self::Error> {
        Ok(RescueStatus {
            gateway_reachable: true,
            config_valid: self.runtime.settings().validate().is_ok(),
        })
    }

    fn restart_gateway(&mut self) -> Result<(), Self::Error> {
        self.restarts += 1;
        Ok(())
    }

    fn apply(
        &mut self,
        mutation: &TypedMutation,
    ) -> Result<claw_crestodian::ConfigDigestChange, Self::Error> {
        self.runtime.apply(mutation)
    }
}

#[test]
fn a_first_start_publishes_defaults_and_a_restart_reloads_them_unchanged() {
    let directory = TestDirectory::create();
    let settings_path = directory.path().join("crestodian").join("settings.json");

    let runtime = CrestodianRuntime::start(&settings_path).expect("first start");
    assert_eq!(runtime.settings(), &CrestodianSettings::default());
    assert_eq!(runtime.settings().gateway_port, DEFAULT_GATEWAY_PORT);
    assert!(settings_path.is_file(), "defaults must be published");
    let published = std::fs::read(&settings_path).expect("read settings");
    let digest = runtime.digest().expect("digest");
    drop(runtime);

    let restarted = CrestodianRuntime::start(&settings_path).expect("restart");
    assert_eq!(restarted.settings(), &CrestodianSettings::default());
    assert_eq!(restarted.digest().expect("digest"), digest);
    assert_eq!(
        std::fs::read(&settings_path).expect("read settings"),
        published,
        "a restart must not rewrite settings it did not change"
    );
}

#[test]
fn every_typed_mutation_survives_a_restart_exactly() {
    let directory = TestDirectory::create();
    let settings_path = directory.path().join("settings.json");
    let mut runtime = CrestodianRuntime::start(&settings_path).expect("first start");

    let mutations = [
        TypedMutation::set_json("gateway.port", &serde_json::json!(19_001)).expect("port"),
        TypedMutation::set_json(
            "crestodian.rescue.pendingTtlMinutes",
            &serde_json::json!(45),
        )
        .expect("ttl"),
        TypedMutation::set_json("crestodian.rescue.ownerDmOnly", &serde_json::json!(false))
            .expect("dm"),
        TypedMutation::set_json("crestodian.rescue.enabled", &serde_json::json!(true))
            .expect("enabled"),
        TypedMutation::set_json("workspace", &serde_json::json!("/srv/openclaw"))
            .expect("workspace"),
        TypedMutation::set_reference("gateway.auth.token", "env", "OPENCLAW_GATEWAY_TOKEN")
            .expect("secret reference"),
    ];
    let mut digests = Vec::new();
    for mutation in &mutations {
        let change = runtime.apply(mutation).expect("apply");
        assert_ne!(change.before, change.after, "{}", mutation.audit_label());
        digests.push(change);
    }
    for window in digests.windows(2) {
        assert_eq!(
            window[0].after, window[1].before,
            "digests must chain across consecutive writes"
        );
    }
    let expected = runtime.settings().clone();
    drop(runtime);

    let restarted = CrestodianRuntime::start(&settings_path).expect("restart");
    assert_eq!(restarted.settings(), &expected);
    assert_eq!(restarted.settings().gateway_port, 19_001);
    assert_eq!(restarted.settings().rescue.pending_ttl_minutes, 45);
    assert!(!restarted.settings().rescue.owner_dm_only);
    assert_eq!(
        restarted.settings().rescue.enabled,
        RescueEnabled::Explicit(true)
    );
    assert_eq!(
        restarted.settings().workspace.as_deref(),
        Some(std::path::Path::new("/srv/openclaw"))
    );
    assert_eq!(
        restarted.settings().gateway_auth_token.as_deref(),
        Some("env:OPENCLAW_GATEWAY_TOKEN"),
        "a secret reference is durable, and it is still only a reference"
    );
    assert_eq!(
        restarted.digest().expect("digest"),
        digests.last().expect("at least one write").after
    );
}

#[test]
fn a_rescue_approved_mutation_and_its_audit_trail_both_survive_a_restart() {
    let directory = TestDirectory::create();
    let settings_path = directory.path().join("settings.json");
    let audit_path = directory.path().join("audit").join("rescue.jsonl");
    let context = context();

    let mut runtime = CrestodianRuntime::start(&settings_path).expect("first start");
    let mut session = runtime.open_rescue_session();
    assert!(!session.has_pending());
    let mut audit = JsonlRescueAudit::new(&audit_path);
    let command = parse_rescue_command("/crestodian config set gateway.port 19001").expect("parse");
    {
        let mut control = Control {
            runtime: &mut runtime,
            restarts: 0,
        };
        session
            .handle(command, &context, 1_000, &mut control, &mut audit)
            .expect("plan");
        let applied = session
            .handle(
                RescueCommand::Approve,
                &context,
                2_000,
                &mut control,
                &mut audit,
            )
            .expect("approve");
        let RescueResponse::Applied {
            operation,
            config_digest,
        } = applied
        else {
            panic!("expected an applied mutation");
        };
        assert_eq!(operation, "config_set:gateway.port");
        let change = config_digest.expect("a configuration write records both digests");
        assert_ne!(change.before, change.after);
        assert_eq!(control.restarts, 0);
    }
    assert_eq!(runtime.settings().gateway_port, 19_001);
    let digest = runtime.digest().expect("digest");
    drop(runtime);
    drop(session);

    let restarted = CrestodianRuntime::start(&settings_path).expect("restart");
    assert_eq!(restarted.settings().gateway_port, 19_001);
    assert_eq!(restarted.digest().expect("digest"), digest);

    let events = JsonlRescueAudit::read(&audit_path).expect("read audit trail");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].kind, RescueAuditKind::Approved);
    assert_eq!(events[0].operation, "config_set:gateway.port");
    assert_eq!(events[0].channel, "telegram");
    assert_eq!(events[0].account, "primary");
    assert_eq!(events[0].sender, "owner-42");
    assert_eq!(events[0].source_address, "chat-99");
    assert_eq!(events[0].config_digest, None);
    assert_eq!(events[1].kind, RescueAuditKind::Applied);
    let change = events[1]
        .config_digest
        .clone()
        .expect("applied write records digests");
    assert_eq!(change.after, digest);
    let raw = std::fs::read_to_string(&audit_path).expect("raw trail");
    assert!(
        !raw.contains("19001"),
        "the durable trail must stay metadata-only: {raw}"
    );
}

#[test]
fn a_pending_approval_never_survives_a_restart() {
    let directory = TestDirectory::create();
    let settings_path = directory.path().join("settings.json");
    let audit_path = directory.path().join("rescue.jsonl");
    let context = context();
    let mut audit = JsonlRescueAudit::new(&audit_path);

    let mut runtime = CrestodianRuntime::start(&settings_path).expect("first start");
    let mut session = runtime.open_rescue_session();
    {
        let mut control = Control {
            runtime: &mut runtime,
            restarts: 0,
        };
        session
            .handle(
                parse_rescue_command("/crestodian config set gateway.port 19001").expect("parse"),
                &context,
                1_000,
                &mut control,
                &mut audit,
            )
            .expect("plan");
    }
    assert!(session.has_pending(), "the mutation is staged, not applied");
    assert_eq!(runtime.settings().gateway_port, DEFAULT_GATEWAY_PORT);
    drop(session);
    drop(runtime);

    let mut restarted = CrestodianRuntime::start(&settings_path).expect("restart");
    assert_eq!(
        restarted.settings().gateway_port,
        DEFAULT_GATEWAY_PORT,
        "an unapproved mutation must never be applied"
    );
    let mut recovered = restarted.open_rescue_session();
    assert!(
        !recovered.has_pending(),
        "an approval must never outlive the process that staged it"
    );
    let mut control = Control {
        runtime: &mut restarted,
        restarts: 0,
    };
    let error = recovered
        .handle(
            RescueCommand::Approve,
            &context,
            3_000,
            &mut control,
            &mut audit,
        )
        .expect_err("an approval after a restart has nothing to apply");
    match error {
        RescueError::NoPendingApproval => {}
        other => panic!("expected no pending approval, got {other}"),
    }
    assert_eq!(control.restarts, 0);
    assert_eq!(
        JsonlRescueAudit::read(&audit_path).expect("read audit trail"),
        Vec::new(),
        "nothing was applied, so nothing is audited"
    );
}

#[test]
fn the_rescue_policy_in_force_after_a_restart_is_the_durable_one() {
    let directory = TestDirectory::create();
    let settings_path = directory.path().join("settings.json");
    let mut runtime = CrestodianRuntime::start(&settings_path).expect("first start");
    assert_eq!(
        runtime.open_rescue_session().policy().enabled,
        RescueEnabled::Auto(RescueAuto::Auto)
    );

    runtime
        .apply(&TypedMutation::RescueEnabled(RescueEnabled::Explicit(
            false,
        )))
        .expect("disable rescue");
    runtime
        .apply(&TypedMutation::RescuePendingTtlMinutes(45))
        .expect("widen ttl");
    drop(runtime);

    let restarted = CrestodianRuntime::start(&settings_path).expect("restart");
    let session = restarted.open_rescue_session();
    assert_eq!(session.policy().enabled, RescueEnabled::Explicit(false));
    assert_eq!(session.policy().pending_ttl_minutes, 45);
}

#[test]
fn hand_edited_settings_fail_closed_instead_of_reverting_to_defaults() {
    let directory = TestDirectory::create();

    for (name, contents, expected) in [
        (
            "schema.json",
            r#"{"schemaVersion":2,"gatewayPort":18789,"gatewayAuthToken":null,"rescue":{"enabled":"auto","ownerDmOnly":true,"pendingTtlMinutes":15},"workspace":null}"#,
            "unsupported settings schema version 2 (supported 1)",
        ),
        (
            "port.json",
            r#"{"schemaVersion":1,"gatewayPort":0,"gatewayAuthToken":null,"rescue":{"enabled":"auto","ownerDmOnly":true,"pendingTtlMinutes":15},"workspace":null}"#,
            "gateway.port accepts 1..=65535, but received 0",
        ),
        (
            "ttl.json",
            r#"{"schemaVersion":1,"gatewayPort":18789,"gatewayAuthToken":null,"rescue":{"enabled":"auto","ownerDmOnly":true,"pendingTtlMinutes":0},"workspace":null}"#,
            "crestodian.rescue.pendingTtlMinutes accepts 1..=1440, but received 0",
        ),
        (
            "plaintext.json",
            r#"{"schemaVersion":1,"gatewayPort":18789,"gatewayAuthToken":"hunter2","rescue":{"enabled":"auto","ownerDmOnly":true,"pendingTtlMinutes":15},"workspace":null}"#,
            "gateway.auth.token: only env:<NAME> secret references are supported",
        ),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, contents).expect("write hand-edited settings");
        let error = CrestodianRuntime::start(&path).expect_err("hand edit must fail closed");
        match error {
            CrestodianError::InvalidSettings {
                path: reported,
                message,
            } => {
                assert_eq!(reported, path);
                assert_eq!(message, expected, "drift for {name}");
            }
            other => panic!("expected a validation refusal for {name}, got {other}"),
        }
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            contents,
            "a refused settings file must not be rewritten"
        );
    }
}

#[test]
fn malformed_settings_report_the_exact_failing_field() {
    let directory = TestDirectory::create();
    let path = directory.path().join("settings.json");
    std::fs::write(
        &path,
        r#"{"schemaVersion":1,"gatewayPort":"18789","gatewayAuthToken":null,"rescue":{"enabled":"auto","ownerDmOnly":true,"pendingTtlMinutes":15},"workspace":null}"#,
    )
    .expect("write malformed settings");

    let error = CrestodianRuntime::start(&path).expect_err("malformed settings");
    match error {
        CrestodianError::SettingsDecode {
            path: reported,
            json_path,
            message,
        } => {
            assert_eq!(reported, path);
            assert_eq!(json_path, "gatewayPort");
            assert!(message.contains("invalid type"), "{message}");
        }
        other => panic!("expected a decode failure, got {other}"),
    }

    std::fs::write(&path, r#"{"schemaVersion":1,"nope":true}"#).expect("write unknown field");
    let error = CrestodianRuntime::start(&path).expect_err("unknown field");
    match error {
        CrestodianError::SettingsDecode { json_path, .. } => assert_eq!(json_path, "nope"),
        other => panic!("expected a decode failure, got {other}"),
    }
}

#[test]
fn a_settings_write_that_fails_never_takes_effect_in_memory() {
    let directory = TestDirectory::create();
    let settings_path = directory.path().join("settings.json");
    let mut runtime = CrestodianRuntime::start(&settings_path).expect("first start");
    let before = runtime.digest().expect("digest");
    assert_eq!(runtime.settings().gateway_port, DEFAULT_GATEWAY_PORT);

    // Replace the settings file with a directory: the atomic write can never
    // land, so the mutation must be reported as failed and not take effect.
    std::fs::remove_file(&settings_path).expect("remove settings file");
    std::fs::create_dir(&settings_path).expect("block the settings path");
    let failure = runtime
        .apply(&TypedMutation::GatewayPort(19_001))
        .expect_err("an unwritable settings path must fail the mutation");
    assert!(
        matches!(
            failure,
            CrestodianError::Config(_) | CrestodianError::Io { .. }
        ),
        "expected a write failure, got {failure}"
    );
    assert_eq!(
        runtime.settings().gateway_port,
        DEFAULT_GATEWAY_PORT,
        "a running gateway must never enforce a policy that is not on disk"
    );
    assert_eq!(runtime.digest().expect("digest"), before);

    std::fs::remove_dir(&settings_path).expect("unblock the settings path");
    runtime
        .apply(&TypedMutation::GatewayPort(19_001))
        .expect("apply once the path is writable again");
    assert_ne!(runtime.digest().expect("digest"), before);
    assert_eq!(
        CrestodianRuntime::start(&settings_path)
            .expect("restart")
            .settings()
            .gateway_port,
        19_001
    );
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

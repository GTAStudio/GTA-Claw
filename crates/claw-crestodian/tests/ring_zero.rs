//! Ring-zero authority tool acceptance tests.
//!
//! The privileged surface has exactly one authority tool. These tests pin who
//! may open it, which backends are trusted to enforce that restriction, and the
//! closed argument schema the tool accepts.

use claw_crestodian::{
    BackendToolContract, CODEX_PLANNER_TOOL, CrestodianOperation, MutationField, RING_ZERO_TOOL,
    RingZeroDenial, RingZeroSession, SessionKind, TypedMutation, parse_operation,
    ring_zero_tool_descriptor, ring_zero_tool_schema,
};
use serde_json::{Value, json};

/// Frozen refusals of the closed ring-zero argument schema.
const GOLDEN_ARGUMENT_REFUSALS: &[(&str, &str)] = &[
    (
        r#""status""#,
        "crestodian tool arguments must be an object, but received string",
    ),
    (
        "[]",
        "crestodian tool arguments must be an object, but received array",
    ),
    ("{}", "crestodian tool argument operation is required"),
    (
        r#"{"operation": null}"#,
        "crestodian tool argument operation is required",
    ),
    (
        r#"{"operation": 5}"#,
        "crestodian tool argument operation expects string, but received number",
    ),
    (
        r#"{"operation": "status", "shell": "rm -rf /"}"#,
        "crestodian tool argument \"shell\" is outside the closed schema",
    ),
    (
        r#"{"operation": "reboot"}"#,
        "crestodian operation \"reboot\" is outside the closed operation set",
    ),
    (
        r#"{"operation": "Status"}"#,
        "crestodian operation \"Status\" is outside the closed operation set",
    ),
    (
        r#"{"operation": "status", "path": "gateway.port"}"#,
        "crestodian tool argument path is not accepted by operation status",
    ),
    (
        r#"{"operation": "restart_gateway", "value": 1}"#,
        "crestodian tool argument value is not accepted by operation restart_gateway",
    ),
    (
        r#"{"operation": "config_set", "source": "env"}"#,
        "crestodian tool argument source is not accepted by operation config_set",
    ),
    (
        r#"{"operation": "config_set", "path": "gateway.port"}"#,
        "crestodian tool argument value is required",
    ),
    (
        r#"{"operation": "config_set", "path": "gateway.port", "value": null}"#,
        "crestodian tool argument value is required",
    ),
    (
        r#"{"operation": "config_set", "value": 19001}"#,
        "crestodian tool argument path is required",
    ),
    (
        r#"{"operation": "config_set", "path": 7, "value": 19001}"#,
        "crestodian tool argument path expects string, but received number",
    ),
    (
        r#"{"operation": "config_set", "path": "gateway.port", "value": "19001"}"#,
        "configuration path gateway.port expects non-negative integer, but received string",
    ),
    (
        r#"{"operation": "config_set", "path": "gateway.port", "value": true}"#,
        "configuration path gateway.port expects non-negative integer, but received boolean",
    ),
    (
        r#"{"operation": "config_set", "path": "gateway.port", "value": 0}"#,
        "configuration path gateway.port accepts 1..=65535, but received 0",
    ),
    (
        r#"{"operation": "config_set", "path": "gateway.port", "value": 65536}"#,
        "configuration path gateway.port accepts 1..=65535, but received 65536",
    ),
    (
        r#"{"operation": "config_set", "path": "crestodian.rescue.ownerDmOnly", "value": 1}"#,
        "configuration path crestodian.rescue.ownerDmOnly expects boolean, but received number",
    ),
    (
        r#"{"operation": "config_set", "path": "crestodian.rescue.enabled", "value": "sometimes"}"#,
        "configuration path crestodian.rescue.enabled expects boolean or \"auto\", but received string",
    ),
    (
        r#"{"operation": "config_set", "path": "gateway.auth.token", "value": "hunter2"}"#,
        "configuration path gateway.auth.token holds secret material; use config set-ref gateway.auth.token env <NAME>",
    ),
    (
        r#"{"operation": "config_set_ref", "path": "gateway.auth.token", "source": "env"}"#,
        "crestodian tool argument name is required",
    ),
    (
        r#"{"operation": "config_set_ref", "path": "gateway.auth.token", "source": "vault", "name": "TOKEN"}"#,
        "secret source \"vault\" is unsupported; only env is accepted",
    ),
    (
        r#"{"operation": "config_set_ref", "path": "gateway.auth.token", "source": "env", "name": "1BAD"}"#,
        "configuration path gateway.auth.token: environment name must match [A-Za-z_][A-Za-z0-9_]*",
    ),
    (
        r#"{"operation": "config_set_ref", "path": "gateway.port", "source": "env", "name": "PORT"}"#,
        "configuration path gateway.port holds no secret material and takes a literal value",
    ),
];

#[test]
fn a_normal_agent_session_never_receives_the_ring_zero_tool() {
    for backend in [
        BackendToolContract::SelectableNativeTools,
        BackendToolContract::NoNativeTools,
        BackendToolContract::CodexAppServer,
        BackendToolContract::AlwaysOnNativeTools,
        BackendToolContract::UnknownNativeTools,
    ] {
        let denial = RingZeroSession::open(SessionKind::NormalAgent, backend)
            .expect_err("normal agent sessions have no ring-zero surface");
        assert_eq!(denial, RingZeroDenial::NormalAgentSession);
        assert_eq!(
            denial.to_string(),
            "the crestodian ring-zero tool is never exposed to a normal agent session"
        );
    }
}

#[test]
fn backends_that_cannot_prove_the_single_tool_restriction_fail_closed() {
    let denial = RingZeroSession::open(
        SessionKind::Crestodian,
        BackendToolContract::AlwaysOnNativeTools,
    )
    .expect_err("always-on native tools cannot be restricted");
    assert_eq!(
        denial,
        RingZeroDenial::BackendCannotRestrictTools {
            contract: BackendToolContract::AlwaysOnNativeTools
        }
    );
    assert_eq!(
        denial.to_string(),
        "backend tool contract always-on-native-tools cannot prove the single-tool ring-zero restriction"
    );

    let denial = RingZeroSession::open(
        SessionKind::Crestodian,
        BackendToolContract::UnknownNativeTools,
    )
    .expect_err("an unknown contract is not a trusted contract");
    assert_eq!(
        denial,
        RingZeroDenial::BackendCannotRestrictTools {
            contract: BackendToolContract::UnknownNativeTools
        }
    );
    assert_eq!(
        denial.to_string(),
        "backend tool contract unknown-native-tools cannot prove the single-tool ring-zero restriction"
    );
}

#[test]
fn trusted_backends_expose_exactly_one_authority_tool() {
    for (backend, expected) in [
        (
            BackendToolContract::SelectableNativeTools,
            vec![RING_ZERO_TOOL],
        ),
        (BackendToolContract::NoNativeTools, vec![RING_ZERO_TOOL]),
        (
            BackendToolContract::CodexAppServer,
            vec![CODEX_PLANNER_TOOL, RING_ZERO_TOOL],
        ),
    ] {
        let session =
            RingZeroSession::open(SessionKind::Crestodian, backend).expect("trusted backend");
        assert_eq!(session.allowed_tools(), expected.as_slice());
        assert_eq!(
            session
                .allowed_tools()
                .iter()
                .filter(|tool| **tool == RING_ZERO_TOOL)
                .count(),
            1,
            "{} must expose exactly one authority tool",
            backend.label()
        );
    }
}

#[test]
fn tools_outside_the_allow_list_and_inert_tools_are_refused_distinctly() {
    let session = RingZeroSession::open(
        SessionKind::Crestodian,
        BackendToolContract::SelectableNativeTools,
    )
    .expect("trusted backend");
    let arguments = json!({"operation": "status"});

    let denial = session
        .invoke("shell", &arguments)
        .expect_err("shell is not a ring-zero tool");
    assert_eq!(
        denial,
        RingZeroDenial::ToolNotAllowed {
            requested: "shell".to_owned()
        }
    );
    assert_eq!(
        denial.to_string(),
        "tool \"shell\" is outside the ring-zero allow-list"
    );

    let denial = session
        .invoke(CODEX_PLANNER_TOOL, &arguments)
        .expect_err("the planner is not selected on this backend");
    assert_eq!(
        denial,
        RingZeroDenial::ToolNotAllowed {
            requested: CODEX_PLANNER_TOOL.to_owned()
        }
    );

    let codex = RingZeroSession::open(SessionKind::Crestodian, BackendToolContract::CodexAppServer)
        .expect("trusted backend");
    let denial = codex
        .invoke(CODEX_PLANNER_TOOL, &arguments)
        .expect_err("the planner carries no OpenClaw authority");
    assert_eq!(
        denial,
        RingZeroDenial::InertTool {
            requested: CODEX_PLANNER_TOOL.to_owned()
        }
    );
    assert_eq!(
        denial.to_string(),
        "tool \"update_plan\" carries no OpenClaw authority and cannot run an operation"
    );
    assert_eq!(
        codex
            .invoke(RING_ZERO_TOOL, &arguments)
            .expect("authority tool"),
        CrestodianOperation::Status
    );
}

#[test]
fn a_refused_tool_name_is_never_echoed_back_verbatim() {
    let session =
        RingZeroSession::open(SessionKind::Crestodian, BackendToolContract::NoNativeTools)
            .expect("trusted backend");
    let denial = session
        .invoke("sh -c \"rm -rf /\"", &json!({"operation": "status"}))
        .expect_err("injection attempt");
    let RingZeroDenial::ToolNotAllowed { requested } = &denial else {
        panic!("expected an allow-list refusal, got {denial}");
    };
    assert_eq!(requested, "sh-crm-rf");
    assert_eq!(
        denial.to_string(),
        "tool \"sh-crm-rf\" is outside the ring-zero allow-list"
    );
}

#[test]
fn ring_zero_tool_contract_matches_the_frozen_schema() {
    let descriptor = ring_zero_tool_descriptor();
    assert_eq!(descriptor.name, "crestodian");
    assert_eq!(descriptor.title, "Crestodian");
    assert_eq!(
        descriptor.description,
        "Run one typed Crestodian operation. Read-only operations run immediately; \
mutations are staged for the owner's explicit approval."
    );

    assert_eq!(
        ring_zero_tool_schema(),
        json!({
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": [
                        "config_set",
                        "config_set_ref",
                        "restart_gateway",
                        "status",
                        "validate_config",
                    ],
                    "description": "Typed Crestodian operation to run.",
                },
                "path": {
                    "type": "string",
                    "enum": [
                        "crestodian.rescue.enabled",
                        "crestodian.rescue.ownerDmOnly",
                        "crestodian.rescue.pendingTtlMinutes",
                        "gateway.auth.token",
                        "gateway.port",
                        "workspace",
                    ],
                    "description": "Configuration path for config_set and config_set_ref.",
                },
                "value": {
                    "description":
                        "Value for config_set, checked against the declared type of path.",
                },
                "source": {
                    "type": "string",
                    "enum": ["env"],
                    "description": "Secret source for config_set_ref.",
                },
                "name": {
                    "type": "string",
                    "pattern": "^[A-Za-z_][A-Za-z0-9_]*$",
                    "description": "Environment variable name for config_set_ref.",
                },
            },
            "required": ["operation"],
            "additionalProperties": false,
        })
    );
}

#[test]
fn the_published_schema_advertises_exactly_the_writable_field_table() {
    let schema = ring_zero_tool_schema();
    let advertised = schema["properties"]["path"]["enum"]
        .as_array()
        .expect("path enum")
        .iter()
        .map(|value| value.as_str().expect("path string").to_owned())
        .collect::<Vec<_>>();
    let writable = MutationField::ALL
        .into_iter()
        .map(|field| field.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(advertised, writable);
}

#[test]
fn the_closed_argument_schema_refuses_every_malformed_payload() {
    for (source, expected) in GOLDEN_ARGUMENT_REFUSALS {
        let arguments: Value = serde_json::from_str(source).expect("test payload");
        let rejection =
            parse_operation(&arguments).expect_err(&format!("payload must be refused: {source}"));
        assert_eq!(&rejection.to_string(), expected, "drift for {source}");
    }
}

#[test]
fn accepted_payloads_parse_into_exactly_one_typed_operation() {
    assert_eq!(
        parse_operation(&json!({"operation": "status"})).expect("status"),
        CrestodianOperation::Status
    );
    assert_eq!(
        parse_operation(&json!({"operation": "validate_config"})).expect("validate"),
        CrestodianOperation::ValidateConfig
    );
    assert_eq!(
        parse_operation(&json!({"operation": "restart_gateway"})).expect("restart"),
        CrestodianOperation::RestartGateway
    );
    assert_eq!(
        parse_operation(
            &json!({"operation": "config_set", "path": "gateway.port", "value": 19001})
        )
        .expect("typed write"),
        CrestodianOperation::Configure(TypedMutation::GatewayPort(19_001))
    );

    let reference = parse_operation(&json!({
        "operation": "config_set_ref",
        "path": "gateway.auth.token",
        "source": "env",
        "name": "OPENCLAW_GATEWAY_TOKEN",
    }))
    .expect("secret reference");
    assert_eq!(
        reference.proposal(),
        "set-ref gateway.auth.token = env:OPENCLAW_GATEWAY_TOKEN"
    );
    assert_eq!(reference.audit_label(), "config_set_ref:gateway.auth.token");
}

#[test]
fn read_only_and_mutating_operations_are_classified_exactly() {
    assert!(!CrestodianOperation::Status.mutating());
    assert!(!CrestodianOperation::ValidateConfig.mutating());
    assert!(CrestodianOperation::RestartGateway.mutating());
    assert!(
        CrestodianOperation::Configure(TypedMutation::GatewayPort(19_001)).mutating(),
        "a configuration write is never a read-only operation"
    );
}

#[test]
fn the_ring_zero_tool_refuses_inference_route_and_credential_paths() {
    for (path, expected) in [
        (
            "auth.token",
            "configuration path \"auth.token\" owns the inference route and cannot be written by Crestodian; run openclaw onboard",
        ),
        (
            "models.gpt-5.alias",
            "configuration path \"models.gpt-5.alias\" owns the inference route and cannot be written by Crestodian; run openclaw onboard",
        ),
        (
            "agents.main.model",
            "configuration path \"agents.main.model\" owns the inference route and cannot be written by Crestodian; run openclaw onboard",
        ),
        (
            "tools.exec.enabled",
            "configuration path \"tools.exec.enabled\" owns the inference route and cannot be written by Crestodian; run openclaw onboard",
        ),
        (
            "cli.codex.command",
            "configuration path \"cli.codex.command\" owns the inference route and cannot be written by Crestodian; run openclaw onboard",
        ),
        (
            "env.OPENCLAW_TOKEN",
            "configuration path \"env.OPENCLAW_TOKEN\" owns credential resolution and cannot be written by Crestodian",
        ),
        (
            "secrets.gateway",
            "configuration path \"secrets.gateway\" owns credential resolution and cannot be written by Crestodian",
        ),
        (
            "plugins.evil.enabled",
            "configuration path \"plugins.evil.enabled\" owns credential resolution and cannot be written by Crestodian",
        ),
        (
            "$include",
            "configuration path \"$include\" owns credential resolution and cannot be written by Crestodian",
        ),
    ] {
        let rejection =
            parse_operation(&json!({"operation": "config_set", "path": path, "value": "x"}))
                .expect_err("forbidden root");
        assert_eq!(rejection.to_string(), expected, "drift for {path}");
    }
}

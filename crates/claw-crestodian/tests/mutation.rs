//! Typed configuration mutation acceptance tests.
//!
//! Every accepted write is a typed value of a closed field table. These tests
//! pin the table, the refusal reasons, and the guarantee that no secret and no
//! mutated value ever leaks into an owner-facing proposal or an audit label.

use std::path::PathBuf;

use claw_config::{RescueAuto, RescueEnabled};
use claw_crestodian::{
    CRESTODIAN_SETTINGS_SCHEMA_VERSION, CrestodianSettings, DEFAULT_GATEWAY_PORT, MutationField,
    MutationRejection, TypedMutation, ValueType,
};
use serde_json::json;

/// Frozen closed table of ring-zero writable configuration fields.
const GOLDEN_WRITABLE_TABLE: &[(&str, ValueType)] = &[
    ("crestodian.rescue.enabled", ValueType::RescueMode),
    ("crestodian.rescue.ownerDmOnly", ValueType::Boolean),
    ("crestodian.rescue.pendingTtlMinutes", ValueType::Minutes),
    ("gateway.auth.token", ValueType::SecretReference),
    ("gateway.port", ValueType::Port),
    ("workspace", ValueType::Workspace),
];

#[test]
fn the_writable_field_table_is_closed_and_frozen() {
    let actual: Vec<(&str, ValueType)> = MutationField::ALL
        .into_iter()
        .map(|field| (field.path(), field.value_type()))
        .collect();
    assert_eq!(actual.as_slice(), GOLDEN_WRITABLE_TABLE);

    for (path, value_type) in GOLDEN_WRITABLE_TABLE {
        let field = MutationField::parse(path).expect("table path resolves");
        assert_eq!(field.path(), *path);
        assert_eq!(field.value_type(), *value_type);
    }
}

#[test]
fn every_writable_field_accepts_its_declared_type() {
    assert_eq!(
        TypedMutation::set_json("gateway.port", &json!(19_001)).expect("port"),
        TypedMutation::GatewayPort(19_001)
    );
    assert_eq!(
        TypedMutation::set_json("crestodian.rescue.pendingTtlMinutes", &json!(30)).expect("ttl"),
        TypedMutation::RescuePendingTtlMinutes(30)
    );
    assert_eq!(
        TypedMutation::set_json("crestodian.rescue.ownerDmOnly", &json!(false)).expect("dm"),
        TypedMutation::RescueOwnerDmOnly(false)
    );
    assert_eq!(
        TypedMutation::set_json("crestodian.rescue.enabled", &json!("auto")).expect("auto"),
        TypedMutation::RescueEnabled(RescueEnabled::Auto(RescueAuto::Auto))
    );
    assert_eq!(
        TypedMutation::set_json("crestodian.rescue.enabled", &json!(true)).expect("explicit"),
        TypedMutation::RescueEnabled(RescueEnabled::Explicit(true))
    );
    assert_eq!(
        TypedMutation::set_json("workspace", &json!("/srv/openclaw")).expect("workspace"),
        TypedMutation::Workspace(PathBuf::from("/srv/openclaw"))
    );
    assert_eq!(
        TypedMutation::set_reference("gateway.auth.token", "env", "OPENCLAW_GATEWAY_TOKEN")
            .expect("secret reference")
            .proposal(),
        "set-ref gateway.auth.token = env:OPENCLAW_GATEWAY_TOKEN"
    );
}

#[test]
fn json_values_are_never_coerced_across_declared_types() {
    for (path, value, expected) in [
        (
            "gateway.port",
            json!("19001"),
            MutationRejection::TypeMismatch {
                path: "gateway.port",
                expected: "non-negative integer",
                found: "string",
            },
        ),
        (
            "gateway.port",
            json!(-1),
            MutationRejection::TypeMismatch {
                path: "gateway.port",
                expected: "non-negative integer",
                found: "number",
            },
        ),
        (
            "crestodian.rescue.ownerDmOnly",
            json!("false"),
            MutationRejection::TypeMismatch {
                path: "crestodian.rescue.ownerDmOnly",
                expected: "boolean",
                found: "string",
            },
        ),
        (
            "crestodian.rescue.enabled",
            json!(["auto"]),
            MutationRejection::TypeMismatch {
                path: "crestodian.rescue.enabled",
                expected: "boolean or \"auto\"",
                found: "array",
            },
        ),
        (
            "workspace",
            json!(7),
            MutationRejection::TypeMismatch {
                path: "workspace",
                expected: "string",
                found: "number",
            },
        ),
        (
            "workspace",
            json!(""),
            MutationRejection::TypeMismatch {
                path: "workspace",
                expected: "non-empty workspace path",
                found: "empty text",
            },
        ),
        (
            "workspace",
            json!("/srv/open\nclaw"),
            MutationRejection::TypeMismatch {
                path: "workspace",
                expected: "workspace path without control characters",
                found: "control characters",
            },
        ),
    ] {
        assert_eq!(
            TypedMutation::set_json(path, &value).expect_err("coercion must be refused"),
            expected,
            "drift for {path} = {value}"
        );
    }
}

#[test]
fn bounded_fields_reject_both_edges_and_accept_the_boundary() {
    for (path, value, minimum, maximum) in [
        ("gateway.port", 0_u64, 1_u64, 65_535_u64),
        ("gateway.port", 65_536, 1, 65_535),
        ("crestodian.rescue.pendingTtlMinutes", 0, 1, 1_440),
        ("crestodian.rescue.pendingTtlMinutes", 1_441, 1, 1_440),
    ] {
        assert_eq!(
            TypedMutation::set_json(path, &json!(value)).expect_err("out of range"),
            MutationRejection::OutOfRange {
                path: MutationField::parse(path).expect("known path").path(),
                minimum,
                maximum,
                found: value,
            }
        );
    }

    assert_eq!(
        TypedMutation::set_json("gateway.port", &json!(1)).expect("lowest port"),
        TypedMutation::GatewayPort(1)
    );
    assert_eq!(
        TypedMutation::set_json("gateway.port", &json!(65_535)).expect("highest port"),
        TypedMutation::GatewayPort(65_535)
    );
    assert_eq!(
        TypedMutation::set_json("crestodian.rescue.pendingTtlMinutes", &json!(1_440))
            .expect("longest ttl"),
        TypedMutation::RescuePendingTtlMinutes(1_440)
    );
}

#[test]
fn forbidden_configuration_roots_are_refused_before_the_writable_table() {
    for path in [
        "auth",
        "auth.token",
        "agents.main.tools",
        "cli.codex.command",
        "models.default",
        "tools.exec.security",
    ] {
        assert_eq!(
            MutationField::parse(path).expect_err("inference route"),
            MutationRejection::InferenceRoute {
                path: path.to_owned()
            },
            "drift for {path}"
        );
    }

    for path in ["$include", "env.TOKEN", "plugins.x", "secrets.gateway"] {
        assert_eq!(
            MutationField::parse(path).expect_err("credential resolution"),
            MutationRejection::CredentialResolution {
                path: path.to_owned()
            },
            "drift for {path}"
        );
    }
}

#[test]
fn a_forbidden_root_is_refused_even_when_it_is_otherwise_unknown() {
    // The refusal must never depend on whether the path happens to exist, so an
    // unknown path under a forbidden root still reports the forbidden root.
    assert_eq!(
        MutationField::parse("auth.this.path.does.not.exist").expect_err("inference route"),
        MutationRejection::InferenceRoute {
            path: "auth.this.path.does.not.exist".to_owned()
        }
    );
    assert_eq!(
        MutationField::parse("nowhere.at.all").expect_err("unknown"),
        MutationRejection::UnknownPath {
            path: "nowhere.at.all".to_owned()
        }
    );
}

#[test]
fn malformed_paths_are_refused_by_syntax_with_a_sanitized_echo() {
    for (path, message) in [
        ("", "must not be empty"),
        ("..bad", "must not contain an empty segment"),
        ("gateway.", "must not contain an empty segment"),
        (".gateway", "must not contain an empty segment"),
        (
            "gateway.port; rm -rf /",
            "accepts only [A-Za-z0-9_$-] inside a segment",
        ),
        (
            "gateway['port']",
            "accepts only [A-Za-z0-9_$-] inside a segment",
        ),
    ] {
        let rejection = MutationField::parse(path).expect_err("malformed path");
        let MutationRejection::MalformedPath {
            path: echoed,
            message: actual,
        } = &rejection
        else {
            panic!("expected a syntax refusal for {path:?}, got {rejection}");
        };
        assert_eq!(actual, &message, "drift for {path:?}");
        assert!(
            !echoed.contains(' ') && !echoed.contains('\'') && !echoed.contains(';'),
            "refusal echoed an attacker fragment verbatim: {echoed}"
        );
    }

    assert_eq!(
        MutationField::parse(&"a".repeat(129)).expect_err("over-long path"),
        MutationRejection::MalformedPath {
            path: "a".repeat(48),
            message: "must not exceed 128 bytes",
        }
    );
}

#[test]
fn secret_material_can_only_ever_be_written_as_a_reference() {
    assert_eq!(
        TypedMutation::set_json("gateway.auth.token", &json!("hunter2")).expect_err("raw secret"),
        MutationRejection::SecretRequiresReference {
            path: "gateway.auth.token"
        }
    );
    assert_eq!(
        TypedMutation::set_text("gateway.auth.token", "hunter2").expect_err("raw secret"),
        MutationRejection::SecretRequiresReference {
            path: "gateway.auth.token"
        }
    );
    assert_eq!(
        TypedMutation::set_reference("gateway.port", "env", "PORT").expect_err("not a secret path"),
        MutationRejection::NotASecretPath {
            path: "gateway.port"
        }
    );
    assert_eq!(
        TypedMutation::set_reference("workspace", "env", "WORKSPACE").expect_err("not a secret"),
        MutationRejection::NotASecretPath { path: "workspace" }
    );
    assert_eq!(
        TypedMutation::set_reference("gateway.auth.token", "vault", "TOKEN")
            .expect_err("unsupported source"),
        MutationRejection::UnsupportedSecretSource {
            source: "vault".to_owned()
        }
    );
    assert_eq!(
        TypedMutation::set_reference("gateway.auth.token", "env", "9NOPE")
            .expect_err("invalid environment name"),
        MutationRejection::InvalidSecretReference {
            path: "gateway.auth.token",
            message: "environment name must match [A-Za-z_][A-Za-z0-9_]*",
        }
    );
}

#[test]
fn a_secret_write_is_labelled_and_proposed_without_the_secret() {
    let mutation =
        TypedMutation::set_reference("gateway.auth.token", "env", "OPENCLAW_GATEWAY_TOKEN")
            .expect("secret reference");
    assert!(mutation.sensitive());
    assert_eq!(mutation.audit_label(), "config_set_ref:gateway.auth.token");
    assert_eq!(
        mutation.proposal(),
        "set-ref gateway.auth.token = env:OPENCLAW_GATEWAY_TOKEN"
    );

    let mut settings = CrestodianSettings::default();
    settings.apply(&mutation);
    assert_eq!(
        settings.gateway_auth_token.as_deref(),
        Some("env:OPENCLAW_GATEWAY_TOKEN")
    );
    let encoded = String::from_utf8(settings.to_bytes().expect("encode")).expect("utf-8");
    assert!(
        encoded.contains("env:OPENCLAW_GATEWAY_TOKEN"),
        "the reference is durable: {encoded}"
    );
    assert!(!mutation.proposal().contains("hunter2"));
}

#[test]
fn non_secret_writes_are_labelled_as_plain_configuration_writes() {
    let mutation = TypedMutation::set_json("gateway.port", &json!(19_001)).expect("port");
    assert!(!mutation.sensitive());
    assert_eq!(mutation.audit_label(), "config_set:gateway.port");
    assert_eq!(mutation.proposal(), "set gateway.port = 19001");
    assert_eq!(mutation.path(), "gateway.port");
    assert_eq!(mutation.field(), MutationField::GatewayPort);
}

#[test]
fn applying_a_mutation_changes_the_configuration_digest_deterministically() {
    let settings = CrestodianSettings::default();
    assert_eq!(settings.schema_version, CRESTODIAN_SETTINGS_SCHEMA_VERSION);
    assert_eq!(settings.gateway_port, DEFAULT_GATEWAY_PORT);
    let before = settings.digest().expect("digest");
    assert_eq!(before, settings.digest().expect("stable digest"));
    assert_eq!(before.as_str().len(), 64);
    assert!(before.as_str().chars().all(|c| c.is_ascii_hexdigit()));

    let mut changed = settings.clone();
    changed.apply(&TypedMutation::GatewayPort(19_001));
    let after = changed.digest().expect("digest");
    assert_ne!(before, after);

    let mut reverted = changed;
    reverted.apply(&TypedMutation::GatewayPort(DEFAULT_GATEWAY_PORT));
    assert_eq!(reverted, settings);
    assert_eq!(reverted.digest().expect("digest"), before);
}

#[test]
fn durable_settings_are_revalidated_rather_than_trusted() {
    let settings = CrestodianSettings::default();
    assert_eq!(settings.validate(), Ok(()));

    let mut wrong_schema = settings.clone();
    wrong_schema.schema_version = CRESTODIAN_SETTINGS_SCHEMA_VERSION + 1;
    assert_eq!(
        wrong_schema.validate(),
        Err("unsupported settings schema version 2 (supported 1)".to_owned())
    );

    let mut zero_port = settings.clone();
    zero_port.gateway_port = 0;
    assert_eq!(
        zero_port.validate(),
        Err("gateway.port accepts 1..=65535, but received 0".to_owned())
    );

    let mut zero_ttl = settings.clone();
    zero_ttl.rescue.pending_ttl_minutes = 0;
    assert_eq!(
        zero_ttl.validate(),
        Err("crestodian.rescue.pendingTtlMinutes accepts 1..=1440, but received 0".to_owned())
    );

    let mut plaintext = settings;
    plaintext.gateway_auth_token = Some("hunter2".to_owned());
    assert_eq!(
        plaintext.validate(),
        Err("gateway.auth.token: only env:<NAME> secret references are supported".to_owned())
    );
}

#![expect(
    missing_docs,
    reason = "an integration-test binary publishes no API and has no downstream consumers; \
what each fixture pins is stated by its test name and inline comments"
)]

use claw_migrate::{
    Artifact, ArtifactKind, ArtifactSignature, Bridge, ContractViolation, Diagnostic,
    DiagnosticSeverity, InputKind, LegacySkillError, LoadedRole, MigrationInput, MigrationResult,
    MigrationStatus, RemainingJavascript, RoleError, RoleLoadOutcome, load_role_json,
    load_role_source, parse_legacy_skill, recognize_bridges,
};
use serde_json::Value;

const MIGRATION_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../compat/legacy/fixtures/migration/"
);
const ROLE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../compat/legacy/fixtures/role/"
);
const SKILL_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../compat/legacy/fixtures/skill/"
);

fn parse_migration(path: &str) -> MigrationResult {
    let full = format!("{MIGRATION_ROOT}{path}");
    let text = std::fs::read_to_string(full).expect("read frozen migration fixture");
    serde_json::from_str(&text).expect("parse frozen migration fixture")
}

fn signature() -> ArtifactSignature {
    ArtifactSignature {
        algorithm: "ed25519".to_owned(),
        key_id: "fixture-key".to_owned(),
        value: "fixture-signature".to_owned(),
    }
}

#[test]
fn migration_environment_migrated_fixture() {
    let actual = parse_migration("environment-migrated.json");
    let expected = MigrationResult {
        contract_version: "1.0.0".to_owned(),
        input: MigrationInput {
            kind: InputKind::Environment,
            source: ".env".to_owned(),
            sha256: "d".repeat(64),
        },
        status: MigrationStatus::Migrated,
        exit_code: 0,
        recognized_bridges: Vec::new(),
        remaining_javascript: Vec::new(),
        artifacts: vec![Artifact {
            kind: ArtifactKind::Json5Config,
            path: "config/imported.json5".to_owned(),
            sha256: "e".repeat(64),
            signature: signature(),
        }],
        diagnostics: Vec::new(),
    };
    assert_eq!(actual, expected);
    assert_eq!(actual.validate(), Ok(()));
}

#[test]
fn migration_legacy_skill_migrated_fixture() {
    let actual = parse_migration("legacy-skill-migrated.json");
    let expected = MigrationResult {
        contract_version: "1.0.0".to_owned(),
        input: MigrationInput {
            kind: InputKind::LegacySkill,
            source: "deploy/conf/skills/web_fetch.json".to_owned(),
            sha256: "5".repeat(64),
        },
        status: MigrationStatus::Migrated,
        exit_code: 0,
        recognized_bridges: vec![Bridge::HttpGet, Bridge::Log],
        remaining_javascript: Vec::new(),
        artifacts: vec![
            Artifact {
                kind: ArtifactKind::WasiManifest,
                path: "web_fetch/manifest.json".to_owned(),
                sha256: "6".repeat(64),
                signature: signature(),
            },
            Artifact {
                kind: ArtifactKind::WitScaffold,
                path: "web_fetch/world.wit".to_owned(),
                sha256: "7".repeat(64),
                signature: signature(),
            },
        ],
        diagnostics: vec![Diagnostic {
            code: "RUST_PORT_VERIFIED".to_owned(),
            severity: DiagnosticSeverity::Info,
            message: "The signed Rust/WASI replacement contains no remaining JavaScript."
                .to_owned(),
        }],
    };
    assert_eq!(actual, expected);
    assert_eq!(actual.validate(), Ok(()));
}

#[test]
fn migration_manual_port_required_fixture() {
    let actual = parse_migration("manual-port-required.json");
    let expected = MigrationResult {
        contract_version: "1.0.0".to_owned(),
        input: MigrationInput {
            kind: InputKind::LegacySkill,
            source: "deploy/conf/skills/web_fetch.json".to_owned(),
            sha256: "a".repeat(64),
        },
        status: MigrationStatus::ManualPortRequired,
        exit_code: 2,
        recognized_bridges: vec![Bridge::HttpGet, Bridge::Log],
        remaining_javascript: vec![RemainingJavascript {
            location: "executeCode".to_owned(),
            reason:
                "Control flow, truncation, and return semantics require an explicit Rust implementation."
                    .to_owned(),
        }],
        artifacts: vec![
            Artifact {
                kind: ArtifactKind::WasiManifest,
                path: "web_fetch/manifest.json".to_owned(),
                sha256: "b".repeat(64),
                signature: signature(),
            },
            Artifact {
                kind: ArtifactKind::WitScaffold,
                path: "web_fetch/world.wit".to_owned(),
                sha256: "c".repeat(64),
                signature: signature(),
            },
        ],
        diagnostics: vec![Diagnostic {
            code: "LEGACY_JS_REMAINS".to_owned(),
            severity: DiagnosticSeverity::Error,
            message: "Scaffold generated, but JavaScript was not converted or enabled.".to_owned(),
        }],
    };
    assert_eq!(actual, expected);
    assert_eq!(actual.validate(), Ok(()));
}

#[test]
fn migration_role_migrated_fixture() {
    let actual = parse_migration("role-migrated.json");
    let expected = MigrationResult {
        contract_version: "1.0.0".to_owned(),
        input: MigrationInput {
            kind: InputKind::Role,
            source: "https://example.test/role.json".to_owned(),
            sha256: "d".repeat(64),
        },
        status: MigrationStatus::Migrated,
        exit_code: 0,
        recognized_bridges: Vec::new(),
        remaining_javascript: Vec::new(),
        artifacts: vec![Artifact {
            kind: ArtifactKind::Role,
            path: "roles/default.json".to_owned(),
            sha256: "e".repeat(64),
            signature: signature(),
        }],
        diagnostics: Vec::new(),
    };
    assert_eq!(actual, expected);
    assert_eq!(actual.validate(), Ok(()));
}

#[test]
fn migration_negative_environment_wasi_artifact_fixture() {
    let actual = parse_migration("negative/environment-wasi-artifact.json");
    assert_eq!(
        actual.validate(),
        Err(ContractViolation::ArtifactKindMismatch {
            input: InputKind::Environment,
        })
    );
}

#[test]
fn migration_negative_failed_zero_exit_fixture() {
    let actual = parse_migration("negative/failed-zero-exit.json");
    assert_eq!(
        actual.validate(),
        Err(ContractViolation::ExitCode {
            status: MigrationStatus::Failed,
            expected: 1,
            actual: 0,
        })
    );
}

#[test]
fn migration_negative_legacy_skill_missing_port_evidence_fixture() {
    let actual = parse_migration("negative/legacy-skill-missing-port-evidence.json");
    assert_eq!(
        actual.validate(),
        Err(ContractViolation::MissingPortEvidence)
    );
}

#[test]
fn migration_negative_manual_role_artifacts_fixture() {
    let actual = parse_migration("negative/manual-role-artifacts.json");
    assert_eq!(
        actual.validate(),
        Err(ContractViolation::ArtifactKindMismatch {
            input: InputKind::LegacySkill,
        })
    );
}

#[test]
fn migration_negative_role_javascript_evidence_fixture() {
    let actual = parse_migration("negative/role-javascript-evidence.json");
    assert_eq!(
        actual.validate(),
        Err(ContractViolation::RoleJavascriptEvidence)
    );
}

#[test]
fn migration_negative_silent_javascript_success_fixture() {
    let actual = parse_migration("negative/silent-javascript-success.json");
    assert_eq!(
        actual.validate(),
        Err(ContractViolation::MigratedWithJavascript)
    );
}

fn role_fixture(path: &str) -> String {
    std::fs::read_to_string(format!("{ROLE_ROOT}{path}")).expect("read frozen role fixture")
}

#[test]
fn role_positive_content_fixture() {
    assert_eq!(
        load_role_json(&role_fixture("positive/content.json")),
        Ok(LoadedRole {
            content: "You are a concise operational assistant.".to_owned(),
            model: Some("gpt-4o".to_owned()),
        })
    );
}

#[test]
fn role_positive_content_precedence_fixture() {
    assert_eq!(
        load_role_json(&role_fixture("positive/content-precedence.json")),
        Ok(LoadedRole {
            content: "This value wins.".to_owned(),
            model: None,
        })
    );
}

#[test]
fn role_positive_non_string_content_fallback_fixture() {
    assert_eq!(
        load_role_json(&role_fixture("positive/non-string-content-fallback.json")),
        Ok(LoadedRole {
            content: "A non-string content field falls back to this prompt.".to_owned(),
            model: Some("gpt-4o".to_owned()),
        })
    );
}

#[test]
fn role_positive_non_string_model_fixture() {
    assert_eq!(
        load_role_json(&role_fixture("positive/non-string-model.json")),
        Ok(LoadedRole {
            content: "Use the default model.".to_owned(),
            model: None,
        })
    );
}

#[test]
fn role_positive_prompt_fixture() {
    assert_eq!(
        load_role_json(&role_fixture("positive/prompt.json")),
        Ok(LoadedRole {
            content: "Use the prompt alias as the system message.".to_owned(),
            model: Some("claude-opus-4.6".to_owned()),
        })
    );
}

#[test]
fn role_negative_empty_content_fixture() {
    assert_eq!(
        load_role_json(&role_fixture("negative/empty-content.json")),
        Err(RoleError::EmptyContent)
    );
}

#[test]
fn role_negative_missing_content_fixture() {
    assert_eq!(
        load_role_json(&role_fixture("negative/missing-content.json")),
        Err(RoleError::MissingContent)
    );
}

#[test]
fn role_negative_non_string_content_fixture() {
    assert_eq!(
        load_role_json(&role_fixture("negative/non-string-content.json")),
        Err(RoleError::MissingContent)
    );
}

fn parse_role_source_fixture(path: &str) -> Value {
    serde_json::from_str(&role_fixture(path)).expect("parse frozen role source fixture")
}

#[test]
fn role_source_json_content_fixture() {
    let fixture = parse_role_source_fixture("sources/json-content.json");
    assert_eq!(
        load_role_source(
            fixture["content_type"].as_str().expect("content type"),
            &fixture["body"],
        ),
        Ok((
            RoleLoadOutcome::LoadedJson,
            LoadedRole {
                content: "JSON role content".to_owned(),
                model: Some("gpt-4o".to_owned()),
            },
        ))
    );
}

#[test]
fn role_source_json_error_fixture() {
    let fixture = parse_role_source_fixture("sources/json-error.json");
    assert_eq!(
        load_role_source(
            fixture["content_type"].as_str().expect("content type"),
            &fixture["body"],
        ),
        Err(RoleError::MissingContent)
    );
}

#[test]
fn role_source_non_string_model_fixture() {
    let fixture = parse_role_source_fixture("sources/non-string-model.json");
    assert_eq!(
        load_role_source(
            fixture["content_type"].as_str().expect("content type"),
            &fixture["body"],
        ),
        Ok((
            RoleLoadOutcome::LoadedJson,
            LoadedRole {
                content: "Use the default model.".to_owned(),
                model: None,
            },
        ))
    );
}

#[test]
fn role_source_plain_text_fixture() {
    let fixture = parse_role_source_fixture("sources/plain-text.json");
    assert_eq!(
        load_role_source(
            fixture["content_type"].as_str().expect("content type"),
            &fixture["body"],
        ),
        Ok((
            RoleLoadOutcome::LoadedPlainText,
            LoadedRole {
                content: "Plain text is used verbatim as the system prompt.\n".to_owned(),
                model: None,
            },
        ))
    );
}

#[test]
fn role_source_text_json_fallback_fixture() {
    let fixture = parse_role_source_fixture("sources/text-json-fallback.json");
    assert_eq!(
        load_role_source(
            fixture["content_type"].as_str().expect("content type"),
            &fixture["body"],
        ),
        Ok((
            RoleLoadOutcome::LoadedPlainText,
            LoadedRole {
                content: "{\"model\":\"gpt-4o\"}".to_owned(),
                model: None,
            },
        ))
    );
}

fn skill_fixture(path: &str) -> String {
    std::fs::read_to_string(format!("{SKILL_ROOT}{path}")).expect("read frozen skill fixture")
}

#[test]
fn skill_positive_array_parameters_fixture() {
    let skill =
        parse_legacy_skill(&skill_fixture("positive/array-parameters.json")).expect("valid skill");
    assert_eq!(skill.name, "array_parameters");
    assert_eq!(
        skill.description,
        "Arrays pass the legacy typeof object parameters check."
    );
    assert_eq!(skill.parameters, Value::Array(Vec::new()));
    assert_eq!(
        skill.execute_code,
        "function run(params) { return params; }"
    );
    assert_eq!(skill.recognized_bridges, Vec::<Bridge>::new());
}

#[test]
fn skill_positive_http_bridge_fixture() {
    let skill =
        parse_legacy_skill(&skill_fixture("positive/http-bridge.json")).expect("valid skill");
    assert_eq!(skill.name, "lookup_status");
    assert_eq!(skill.description, "Fetch a status endpoint.");
    assert_eq!(
        skill.parameters,
        serde_json::json!({
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        })
    );
    assert_eq!(
        skill.execute_code,
        "async function run(params, api) { api.log(params.url); return api.httpGet(params.url); }"
    );
    assert_eq!(skill.recognized_bridges, vec![Bridge::HttpGet, Bridge::Log]);
}

#[test]
fn skill_negative_missing_execute_code_fixture() {
    assert_eq!(
        parse_legacy_skill(&skill_fixture("negative/missing-execute-code.json")),
        Err(LegacySkillError::MissingExecuteCode)
    );
}

#[test]
fn skill_negative_null_parameters_fixture() {
    assert_eq!(
        parse_legacy_skill(&skill_fixture("negative/null-parameters.json")),
        Err(LegacySkillError::InvalidParameters)
    );
}

#[test]
fn skill_negative_unsafe_name_fixture() {
    assert_eq!(
        parse_legacy_skill(&skill_fixture("negative/unsafe-name.json")),
        Err(LegacySkillError::InvalidName)
    );
}

#[test]
fn role_source_json_like_plain_text_uses_json_semantics() {
    assert_eq!(
        load_role_source(
            "text/plain",
            &Value::String("{\"content\":\"Detected JSON\",\"model\":\"gpt-5\"}".to_owned()),
        ),
        Ok((
            RoleLoadOutcome::LoadedJson,
            LoadedRole {
                content: "Detected JSON".to_owned(),
                model: Some("gpt-5".to_owned()),
            },
        ))
    );
}

#[test]
fn bridge_recognition_requires_api_word_boundaries() {
    assert_eq!(
        recognize_bridges(
            "httpGet(); api.httpGetter(); prefixapi.httpPost(); api.httpGet(); api.log();",
        ),
        vec![Bridge::HttpGet, Bridge::Log]
    );
}

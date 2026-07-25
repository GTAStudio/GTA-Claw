//! Executable coverage for every frozen legacy skill and migration fixture.

use claw_skills::{
    LegacyBridge, LegacyParameterShape, LegacySkillDisposition, LegacySkillError,
    MigrationEvidenceError, MigrationInputKind, MigrationStatus, PortArtifactEvidence,
    ValidatedMigrationEvidence, inspect_legacy_manifest, validate_migration_evidence,
};

#[test]
fn positive_http_bridge_fixture_requires_manual_port_without_source_retention() {
    let fixture = include_str!("../../../compat/legacy/fixtures/skill/positive/http-bridge.json");
    let disposition = inspect_legacy_manifest(fixture);
    assert_eq!(
        disposition,
        Ok(LegacySkillDisposition {
            name: "lookup_status".to_owned(),
            description: "Fetch a status endpoint.".to_owned(),
            parameter_shape: LegacyParameterShape::Object,
            recognized_bridges: vec![LegacyBridge::HttpGet, LegacyBridge::Log],
        })
    );
    let debug = format!("{:?}", disposition.expect("valid disposition"));
    assert_eq!(
        debug,
        "LegacySkillDisposition { name: \"lookup_status\", description: \"Fetch a status endpoint.\", parameter_shape: Object, recognized_bridges: [HttpGet, Log] }"
    );
}

#[test]
fn positive_array_parameters_fixture_preserves_historical_acceptance() {
    let fixture =
        include_str!("../../../compat/legacy/fixtures/skill/positive/array-parameters.json");
    assert_eq!(
        inspect_legacy_manifest(fixture),
        Ok(LegacySkillDisposition {
            name: "array_parameters".to_owned(),
            description: "Arrays pass the legacy typeof object parameters check.".to_owned(),
            parameter_shape: LegacyParameterShape::Array,
            recognized_bridges: Vec::new(),
        })
    );
}

#[test]
fn every_negative_legacy_fixture_returns_its_exact_error() {
    let cases = [
        (
            include_str!("../../../compat/legacy/fixtures/skill/negative/unsafe-name.json"),
            LegacySkillError::InvalidName,
        ),
        (
            include_str!("../../../compat/legacy/fixtures/skill/negative/null-parameters.json"),
            LegacySkillError::InvalidParameters,
        ),
        (
            include_str!(
                "../../../compat/legacy/fixtures/skill/negative/missing-execute-code.json"
            ),
            LegacySkillError::MissingExecuteCode,
        ),
    ];
    for (fixture, expected) in cases {
        assert_eq!(inspect_legacy_manifest(fixture), Err(expected));
    }
}

#[test]
fn signed_native_migration_fixture_is_accepted_exactly() {
    let fixture =
        include_str!("../../../compat/legacy/fixtures/migration/legacy-skill-migrated.json");
    assert_eq!(
        validate_migration_evidence(fixture),
        Ok(ValidatedMigrationEvidence {
            input_kind: MigrationInputKind::LegacySkill,
            source_reference: "deploy/conf/skills/web_fetch.json".to_owned(),
            status: MigrationStatus::Migrated,
            artifacts: vec![
                PortArtifactEvidence {
                    kind: "wasi_manifest".to_owned(),
                    path: "web_fetch/manifest.json".to_owned(),
                    sha256: "6666666666666666666666666666666666666666666666666666666666666666"
                        .to_owned(),
                    key_id: "fixture-key".to_owned(),
                },
                PortArtifactEvidence {
                    kind: "wit_scaffold".to_owned(),
                    path: "web_fetch/world.wit".to_owned(),
                    sha256: "7777777777777777777777777777777777777777777777777777777777777777"
                        .to_owned(),
                    key_id: "fixture-key".to_owned(),
                },
            ],
            recognized_bridges: vec!["httpGet".to_owned(), "log".to_owned()],
            remaining_javascript_count: 0,
        })
    );
}

#[test]
fn manual_port_fixture_remains_non_executable_and_explicit() {
    let fixture =
        include_str!("../../../compat/legacy/fixtures/migration/manual-port-required.json");
    assert_eq!(
        validate_migration_evidence(fixture),
        Ok(ValidatedMigrationEvidence {
            input_kind: MigrationInputKind::LegacySkill,
            source_reference: "deploy/conf/skills/web_fetch.json".to_owned(),
            status: MigrationStatus::ManualPortRequired,
            artifacts: vec![
                PortArtifactEvidence {
                    kind: "wasi_manifest".to_owned(),
                    path: "web_fetch/manifest.json".to_owned(),
                    sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_owned(),
                    key_id: "fixture-key".to_owned(),
                },
                PortArtifactEvidence {
                    kind: "wit_scaffold".to_owned(),
                    path: "web_fetch/world.wit".to_owned(),
                    sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_owned(),
                    key_id: "fixture-key".to_owned(),
                },
            ],
            recognized_bridges: vec!["httpGet".to_owned(), "log".to_owned()],
            remaining_javascript_count: 1,
        })
    );
}

#[test]
fn role_and_environment_migration_fixtures_validate_their_exact_artifact_kinds() {
    let cases = [
        (
            include_str!("../../../compat/legacy/fixtures/migration/role-migrated.json"),
            ValidatedMigrationEvidence {
                input_kind: MigrationInputKind::Role,
                source_reference: "https://example.test/role.json".to_owned(),
                status: MigrationStatus::Migrated,
                artifacts: vec![PortArtifactEvidence {
                    kind: "role".to_owned(),
                    path: "roles/default.json".to_owned(),
                    sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                        .to_owned(),
                    key_id: "fixture-key".to_owned(),
                }],
                recognized_bridges: Vec::new(),
                remaining_javascript_count: 0,
            },
        ),
        (
            include_str!("../../../compat/legacy/fixtures/migration/environment-migrated.json"),
            ValidatedMigrationEvidence {
                input_kind: MigrationInputKind::Environment,
                source_reference: ".env".to_owned(),
                status: MigrationStatus::Migrated,
                artifacts: vec![PortArtifactEvidence {
                    kind: "json5_config".to_owned(),
                    path: "config/imported.json5".to_owned(),
                    sha256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                        .to_owned(),
                    key_id: "fixture-key".to_owned(),
                }],
                recognized_bridges: Vec::new(),
                remaining_javascript_count: 0,
            },
        ),
    ];
    for (fixture, expected) in cases {
        assert_eq!(validate_migration_evidence(fixture), Ok(expected));
    }
}

#[test]
fn every_negative_migration_fixture_returns_its_exact_error() {
    let cases = [
        (
            include_str!(
                "../../../compat/legacy/fixtures/migration/negative/silent-javascript-success.json"
            ),
            MigrationEvidenceError::RemainingJavaScript,
        ),
        (
            include_str!(
                "../../../compat/legacy/fixtures/migration/negative/role-javascript-evidence.json"
            ),
            MigrationEvidenceError::RemainingJavaScript,
        ),
        (
            include_str!(
                "../../../compat/legacy/fixtures/migration/negative/failed-zero-exit.json"
            ),
            MigrationEvidenceError::MigrationFailed,
        ),
        (
            include_str!(
                "../../../compat/legacy/fixtures/migration/negative/manual-role-artifacts.json"
            ),
            MigrationEvidenceError::InvalidArtifact,
        ),
        (
            include_str!(
                "../../../compat/legacy/fixtures/migration/negative/legacy-skill-missing-port-evidence.json"
            ),
            MigrationEvidenceError::MissingPortEvidence,
        ),
        (
            include_str!(
                "../../../compat/legacy/fixtures/migration/negative/environment-wasi-artifact.json"
            ),
            MigrationEvidenceError::InvalidArtifact,
        ),
    ];
    for (fixture, expected) in cases {
        assert_eq!(validate_migration_evidence(fixture), Err(expected));
    }
}

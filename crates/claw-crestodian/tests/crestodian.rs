//! Real filesystem setup and recovery acceptance tests.

mod common;

use claw_config::{ConfigSnapshot, load_file, parse_json5, to_json5};
use claw_crestodian::{
    CRESTODIAN_STATE_SCHEMA_VERSION, ConfigCondition, Crestodian, CrestodianError, CrestodianState,
    GuidedSetup, RecoveryAction, RecoveryGuidance, SetupAnswers, SetupConstraint, SetupField,
    StateCondition,
};

const VALID: &str = r#"
{
  schema_version: 1,
  core: {
    auth: { github: { pat: "env:GITHUB_TOKEN", device: { enabled: false } } },
    role: { source_url: "https://roles.example.test/default.json" },
    channels: { teams: { enabled: false } },
    server: {},
    logging: {},
    sessions: {},
    copilot: {},
    legacy: {},
    updates: {},
    admin: {},
    network: {},
  },
}
"#;

#[test]
fn guided_setup_has_closed_typed_questions_and_persists_only_secret_references() {
    let questions = GuidedSetup::questions();
    assert_eq!(questions.len(), 6);
    assert_eq!(questions[0].field, SetupField::GithubTokenEnvironment);
    assert_eq!(questions[0].prompt, "GitHub token environment variable");
    assert!(questions[0].required);
    assert!(!questions[0].secret);
    assert_eq!(
        questions[0].constraint,
        SetupConstraint::Exact("GITHUB_TOKEN")
    );
    assert_eq!(questions[5].field, SetupField::TeamsPasswordEnvironment);
    assert_eq!(
        questions[5].constraint,
        SetupConstraint::ExactWhen {
            value: "MicrosoftAppPassword",
            field: SetupField::EnableTeams,
        }
    );

    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config/config.json5");
    let state_path = directory.path().join("state/crestodian.json");
    let report = GuidedSetup::new(&config_path, &state_path)
        .apply(&SetupAnswers {
            github_token_environment: "GITHUB_TOKEN".to_owned(),
            role_source_url: "https://roles.example.test/setup.json".to_owned(),
            workspace: Some(directory.path().join("workspace")),
            enable_teams: false,
            teams_app_id: None,
            teams_password_environment: None,
        })
        .expect("guided setup");

    assert_eq!(
        report
            .config
            .core()
            .auth()
            .github_pat()
            .expect("ref")
            .as_str(),
        "env:GITHUB_TOKEN"
    );
    assert!(report.state.setup_completed);
    assert_eq!(
        report.state.workspace,
        Some(directory.path().join("workspace"))
    );
    assert_eq!(report.warnings, Vec::new());
    let persisted = std::fs::read_to_string(&config_path).expect("read config");
    assert!(!persisted.contains("__present_in_platform_environment__"));
    assert!(persisted.contains("env:GITHUB_TOKEN"));
    let state: CrestodianState =
        serde_json::from_slice(&std::fs::read(state_path).expect("read state"))
            .expect("state JSON");
    assert_eq!(state, report.state);
}

#[test]
fn disabled_teams_answers_do_not_leave_credential_scaffolding() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    let state_path = directory.path().join("crestodian.json");
    let report = GuidedSetup::new(&config_path, &state_path)
        .apply(&SetupAnswers {
            github_token_environment: "GITHUB_TOKEN".to_owned(),
            role_source_url: "https://roles.example.test/setup.json".to_owned(),
            workspace: None,
            enable_teams: false,
            teams_app_id: Some("ignored-app-id".to_owned()),
            teams_password_environment: Some("ignored-password-name".to_owned()),
        })
        .expect("disabled Teams answers are ignored");
    let persisted = to_json5(&report.config).expect("serialize");

    assert!(!persisted.contains("ignored-app-id"));
    assert!(!persisted.contains("MicrosoftAppPassword"));
}

#[test]
fn guided_teams_setup_requires_and_persists_typed_credentials_as_references() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    let state_path = directory.path().join("crestodian.json");
    let report = GuidedSetup::new(&config_path, &state_path)
        .apply(&SetupAnswers {
            github_token_environment: "GITHUB_TOKEN".to_owned(),
            role_source_url: "https://roles.example.test/setup.json".to_owned(),
            workspace: None,
            enable_teams: true,
            teams_app_id: Some("teams-app-id".to_owned()),
            teams_password_environment: Some("MicrosoftAppPassword".to_owned()),
        })
        .expect("Teams setup");
    let persisted = to_json5(&report.config).expect("serialize");

    assert!(persisted.contains("teams-app-id"));
    assert!(persisted.contains("env:MicrosoftAppPassword"));
    assert!(!persisted.contains("__present_in_platform_environment__"));
}

#[test]
fn setup_uses_real_filesystem_failure_and_restores_interrupted_empty_config() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    std::fs::write(&config_path, b"").expect("seed interrupted empty config");
    let blocker = directory.path().join("not-a-directory");
    std::fs::write(&blocker, b"blocker").expect("write blocker file");
    let state_path = blocker.join("crestodian.json");

    let error = GuidedSetup::new(&config_path, &state_path)
        .apply(&SetupAnswers {
            github_token_environment: "GITHUB_TOKEN".to_owned(),
            role_source_url: "https://roles.example.test/setup.json".to_owned(),
            workspace: None,
            enable_teams: false,
            teams_app_id: None,
            teams_password_environment: None,
        })
        .expect_err("state parent is a real file");
    match error {
        CrestodianError::Io { path, source } => {
            assert_eq!(path, blocker);
            assert!(matches!(
                source.kind(),
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotADirectory
            ));
        }
        other => panic!("expected real I/O failure, got {other}"),
    }
    assert_eq!(std::fs::read(&config_path).expect("restored config"), b"");
    assert_eq!(
        std::fs::read(&blocker).expect("blocker preserved"),
        b"blocker"
    );
}

#[test]
fn corrupt_and_interrupted_files_are_backed_up_then_recovered() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    let state_path = directory.path().join("crestodian.json");
    let corrupt_config = b"{ schema_version: 1, core:";
    let corrupt_state = b"{\"schema_version\":1";
    std::fs::write(&config_path, corrupt_config).expect("write corrupt config");
    std::fs::write(&state_path, corrupt_state).expect("write corrupt state");
    let interrupted_path = directory.path().join(".config.json5.gta-claw.tmp.123.7");
    let interrupted_bytes = b"{ partially-written";
    std::fs::write(&interrupted_path, interrupted_bytes).expect("write orphan temp");
    let crestodian = Crestodian::new(&config_path, &state_path);
    let before = crestodian.inspect();
    match before.config {
        ConfigCondition::Corrupt { diagnostic } => {
            assert!(!diagnostic.is_empty());
        }
        other => panic!("expected corrupt config, got {other:?}"),
    }
    match before.state {
        StateCondition::Corrupt { diagnostic } => {
            assert!(!diagnostic.is_empty());
        }
        other => panic!("expected corrupt state, got {other:?}"),
    }

    let baseline = baseline();
    let report = crestodian
        .recover(&baseline, 123_456)
        .expect("recover corrupt files");
    let config_backup = match report.config_action {
        RecoveryAction::Replaced { backup_path } => backup_path,
        other => panic!("expected replaced config, got {other:?}"),
    };
    let state_backup = match report.state_action {
        RecoveryAction::Replaced { backup_path } => backup_path,
        other => panic!("expected replaced state, got {other:?}"),
    };
    assert_eq!(
        std::fs::read(config_backup).expect("config backup"),
        corrupt_config
    );
    assert_eq!(
        std::fs::read(state_backup).expect("state backup"),
        corrupt_state
    );
    assert_eq!(load_file(&config_path).expect("recovered config"), baseline);
    let state: CrestodianState =
        serde_json::from_slice(&std::fs::read(&state_path).expect("recovered state"))
            .expect("state JSON");
    assert_eq!(
        state,
        CrestodianState {
            schema_version: CRESTODIAN_STATE_SCHEMA_VERSION,
            setup_completed: false,
            workspace: None,
            last_recovery_unix_ms: Some(123_456),
        }
    );
    assert_eq!(report.interrupted_artifact_backups.len(), 1);
    assert_eq!(
        report.warnings,
        Vec::new(),
        "a recovery reported as successful must also report full write durability"
    );
    assert_eq!(
        std::fs::read(&report.interrupted_artifact_backups[0]).expect("orphan backup"),
        interrupted_bytes
    );
    assert_eq!(
        std::fs::read(&interrupted_path).expect("orphan source retained"),
        interrupted_bytes
    );
}

#[test]
fn a_state_file_with_a_torn_tail_is_corrupt_rather_than_healthy() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    let state_path = directory.path().join("crestodian.json");
    std::fs::write(&config_path, VALID).expect("write valid config");
    let healthy = br#"{"schema_version":1,"setup_completed":true,"workspace":null,"last_recovery_unix_ms":null}"#;
    let mut torn = healthy.to_vec();
    torn.extend_from_slice(br#"{"schema_version":1,"setup_"#);
    std::fs::write(&state_path, &torn).expect("write torn state");

    let assessment = Crestodian::new(&config_path, &state_path).inspect();

    assert_eq!(assessment.config, ConfigCondition::Healthy);
    match assessment.state {
        StateCondition::Corrupt { diagnostic } => assert!(!diagnostic.is_empty()),
        other => panic!("a state file with a torn tail must be corrupt, got {other:?}"),
    }
    assert_eq!(std::fs::read(&state_path).expect("state preserved"), torn);
}

#[test]
fn incompatible_config_and_state_are_detected_without_mutation() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    let state_path = directory.path().join("crestodian.json");
    let future_config = VALID.replace("schema_version: 1", "schema_version: 99");
    let future_state = br#"{"schema_version":99,"setup_completed":false,"workspace":null,"last_recovery_unix_ms":null}"#;
    std::fs::write(&config_path, future_config.as_bytes()).expect("write future config");
    std::fs::write(&state_path, future_state).expect("write future state");

    let crestodian = Crestodian::new(&config_path, &state_path);
    let assessment = crestodian.inspect();

    assert_eq!(
        assessment.config,
        ConfigCondition::Incompatible {
            found: 99,
            supported: 1,
        }
    );
    assert_eq!(
        assessment.state,
        StateCondition::Incompatible {
            found: 99,
            supported: CRESTODIAN_STATE_SCHEMA_VERSION,
        }
    );
    assert_eq!(assessment.guidance(), RecoveryGuidance::UseCompatibleBuild);
    assert_eq!(
        std::fs::read(&config_path).expect("config preserved"),
        future_config.as_bytes()
    );
    assert_eq!(
        std::fs::read(&state_path).expect("state preserved"),
        future_state
    );

    let mut entries_before = std::fs::read_dir(directory.path())
        .expect("read directory before recovery")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect::<Vec<_>>();
    entries_before.sort();
    let error = crestodian
        .recover(&baseline(), 42)
        .expect_err("future schemas must be refused");
    assert!(matches!(
        error,
        CrestodianError::IncompatibleRecovery {
            config: Some((99, 1)),
            state: Some((99, CRESTODIAN_STATE_SCHEMA_VERSION)),
        }
    ));
    assert_eq!(
        std::fs::read(&config_path).expect("config remains byte-identical"),
        future_config.as_bytes()
    );
    assert_eq!(
        std::fs::read(&state_path).expect("state remains byte-identical"),
        future_state
    );
    let mut entries_after = std::fs::read_dir(directory.path())
        .expect("read directory after recovery")
        .map(|entry| entry.expect("directory entry").file_name())
        .collect::<Vec<_>>();
    entries_after.sort();
    assert_eq!(
        entries_after, entries_before,
        "recovery must create no artifacts"
    );
}

#[test]
fn missing_files_are_guided_to_setup_without_allocating_an_empty_backup() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    let state_path = directory.path().join("crestodian.json");
    let crestodian = Crestodian::new(&config_path, &state_path);
    let assessment = crestodian.inspect();
    assert_eq!(assessment.guidance(), RecoveryGuidance::RunGuidedSetup);

    let report = crestodian
        .recover(&baseline(), 42)
        .expect("create missing files");
    assert_eq!(report.config_action, RecoveryAction::Created);
    assert_eq!(report.state_action, RecoveryAction::Created);
    assert_eq!(report.backup_directory, None);
    assert!(
        std::fs::read_dir(directory.path())
            .expect("read directory")
            .all(|entry| {
                !entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".crestodian-recovery-")
            })
    );
}

#[test]
fn non_directory_path_components_are_reported_as_missing() {
    let directory = common::TestDirectory::create();
    let blocker = directory.path().join("not-a-directory");
    std::fs::write(&blocker, b"blocker").expect("write blocker");
    let assessment =
        Crestodian::new(blocker.join("config.json5"), blocker.join("state.json")).inspect();

    assert_eq!(assessment.config, ConfigCondition::Missing);
    assert_eq!(assessment.state, StateCondition::Missing);
    assert_eq!(assessment.guidance(), RecoveryGuidance::RunGuidedSetup);
}

#[test]
fn later_real_write_failure_restores_exact_corrupt_config_bytes() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    let corrupt = b"{ definitely-not-valid";
    std::fs::write(&config_path, corrupt).expect("write corrupt config");
    let blocker = directory.path().join("state-parent-is-file");
    std::fs::write(&blocker, b"blocker").expect("write blocker");
    let state_path = blocker.join("crestodian.json");
    let crestodian = Crestodian::new(&config_path, &state_path);

    let error = crestodian
        .recover(&baseline(), 5)
        .expect_err("real state write failure");
    match error {
        CrestodianError::Io { path, source } => {
            assert_eq!(path, blocker);
            assert!(matches!(
                source.kind(),
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotADirectory
            ));
        }
        other => panic!("expected I/O failure after successful rollback, got {other}"),
    }
    assert_eq!(
        std::fs::read(&config_path).expect("exact corrupt bytes restored"),
        corrupt
    );
    let recovery_directories = std::fs::read_dir(directory.path())
        .expect("read recovery root")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect entries")
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".crestodian-recovery-"))
        })
        .collect::<Vec<_>>();
    assert_eq!(recovery_directories.len(), 1);
    assert_eq!(
        std::fs::read(recovery_directories[0].path().join("config.original"))
            .expect("retained recovery backup"),
        corrupt
    );
}

#[test]
fn healthy_files_are_never_rewritten() {
    let directory = common::TestDirectory::create();
    let config_path = directory.path().join("config.json5");
    let state_path = directory.path().join("crestodian.json");
    std::fs::write(&config_path, VALID.as_bytes()).expect("write valid config");
    let state = CrestodianState::default();
    std::fs::write(
        &state_path,
        serde_json::to_vec(&state).expect("serialize state"),
    )
    .expect("write valid state");
    let config_before = std::fs::read(&config_path).expect("config before");
    let state_before = std::fs::read(&state_path).expect("state before");

    let report = Crestodian::new(&config_path, &state_path)
        .recover(&baseline(), 999)
        .expect("healthy recovery no-op");

    assert_eq!(report.config_action, RecoveryAction::Unchanged);
    assert_eq!(report.state_action, RecoveryAction::Unchanged);
    assert_eq!(report.backup_directory, None);
    assert_eq!(
        std::fs::read(&config_path).expect("config after"),
        config_before
    );
    assert_eq!(
        std::fs::read(&state_path).expect("state after"),
        state_before
    );
}

fn baseline() -> ConfigSnapshot {
    parse_json5(VALID, "baseline.json5").expect("baseline")
}

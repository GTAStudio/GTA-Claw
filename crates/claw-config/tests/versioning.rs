//! Backup-first schema migration and rollback tests.

mod common;

use claw_config::{
    ConfigMigrationError, ConfigMigrationOutcome, migrate_config_file, rollback_config_migration,
};

const VERSION_ZERO: &str = r#"
{
  schema_version: 0,
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
fn destructive_migration_creates_exact_backup_before_publication() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("config.json5");
    std::fs::write(&path, VERSION_ZERO.as_bytes()).expect("write version zero");

    let outcome = migrate_config_file(&path).expect("migrate version zero");
    let record = match outcome {
        ConfigMigrationOutcome::Migrated(record) => record,
        ConfigMigrationOutcome::Current => panic!("version zero must migrate"),
    };
    assert_eq!(record.config_path, path);
    assert_eq!(record.from_version, 0);
    assert_eq!(record.to_version, 1);
    assert_eq!(
        std::fs::read(&record.backup_path).expect("read backup"),
        VERSION_ZERO.as_bytes()
    );
    let migrated: serde_json::Value =
        json5::from_str(&std::fs::read_to_string(&path).expect("read migrated"))
            .expect("parse migrated");
    assert_eq!(migrated["schema_version"], 1);
}

#[test]
fn rollback_restores_exact_original_bytes() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("config.json5");
    std::fs::write(&path, VERSION_ZERO.as_bytes()).expect("write version zero");
    let outcome = migrate_config_file(&path).expect("migrate version zero");
    let record = match outcome {
        ConfigMigrationOutcome::Migrated(record) => record,
        ConfigMigrationOutcome::Current => panic!("version zero must migrate"),
    };

    rollback_config_migration(&record).expect("rollback");

    assert_eq!(
        std::fs::read(&path).expect("read restored"),
        VERSION_ZERO.as_bytes()
    );
    assert_eq!(
        std::fs::read(&record.backup_path).expect("backup remains available"),
        VERSION_ZERO.as_bytes()
    );
}

#[test]
fn incompatible_future_version_fails_without_creating_backup() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("config.json5");
    let future = VERSION_ZERO.replace("schema_version: 0", "schema_version: 99");
    std::fs::write(&path, future.as_bytes()).expect("write future version");

    let error = migrate_config_file(&path).expect_err("future version must fail");
    match error {
        ConfigMigrationError::UnsupportedPath { found, current } => {
            assert_eq!(found, 99);
            assert_eq!(current, 1);
        }

        other => panic!("expected unsupported path, got {other}"),
    }
    assert_eq!(
        std::fs::read(&path).expect("source preserved"),
        future.as_bytes()
    );
    assert_eq!(
        std::fs::read_dir(directory.path())
            .expect("read directory")
            .count(),
        1
    );
}

#[test]
fn current_version_is_validated_without_creating_a_backup() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("config.json5");
    let current = VERSION_ZERO.replace("schema_version: 0", "schema_version: 1");
    std::fs::write(&path, current.as_bytes()).expect("write current version");

    assert_eq!(
        migrate_config_file(&path).expect("validate current version"),
        ConfigMigrationOutcome::Current
    );
    assert_eq!(
        std::fs::read_dir(directory.path())
            .expect("read directory")
            .count(),
        1,
        "validation must not allocate a migration backup"
    );
}

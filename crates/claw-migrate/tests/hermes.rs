//! Frozen plan/apply fixtures for the Hermes migration provider.
//!
//! Covers the seven items the parity contract requires of
//! `interop.migration.hermes`: config, models, memory, skills, secrets,
//! credentials and safe exclusions. Discovery runs entirely through injected
//! platform paths, so no test here reads a real `~/.hermes`.

use std::path::{Path, PathBuf};

use claw_migrate::{
    ApplyContext, DetectionConfidence, HermesMigrationProvider, HostPlatform, MigrationProvider,
    MigrationStatus, PlanContext,
};

mod common;

use common::{
    MemorySecretStore, TestDir, diagnostic_codes, files_under, leaks, manifest_operations, paths,
    read, signer, write,
};

const CONFIG: &str = r"default_model: openai/gpt-5
small_model: openai/gpt-5-mini
models:
  openai/gpt-5:
    context_window: 400000
    reasoning_effort: high
  openai/gpt-5-mini:
    context_window: 200000
api_key: hermes-config-plaintext
mcp_servers:
  local:
    command: safe-tool
    headers:
      X-Custom: hermes-header-plaintext
";

const ENVIRONMENT: &str = r"# Hermes provider credentials
OPENAI_API_KEY=hermes-openai-plaintext
GITHUB_TOKEN='hermes-github-plaintext'
EMPTY_PLACEHOLDER=
";

const AUTH: &str = r#"{"oauth":{"refresh":"hermes-auth-plaintext"}}"#;

const OPENCODE_AUTH: &str = r#"{"anthropic":{"key":"hermes-opencode-plaintext"}}"#;

/// Writes a complete Hermes profile under the injected home directory,
/// including the plugin and MCP token trees the provider must refuse to move.
fn seed_hermes_home(root: &TestDir) -> PathBuf {
    let hermes = root.join("home").join(".hermes");
    write(&hermes.join("config.yaml"), CONFIG);
    write(&hermes.join(".env"), ENVIRONMENT);
    write(&hermes.join("auth.json"), AUTH);
    write(
        &root.join("data").join("opencode").join("auth.json"),
        OPENCODE_AUTH,
    );
    write(&hermes.join("SOUL.md"), "I am careful and terse.\n");
    write(&hermes.join("AGENTS.md"), "Hermes agent instructions.\n");
    write(
        &hermes.join("memories").join("MEMORY.md"),
        "The deploy key rotates every Monday.\n",
    );
    write(
        &hermes.join("memories").join("USER.md"),
        "The user prefers metric units.\n",
    );
    write(
        &hermes.join("skills").join("research").join("SKILL.md"),
        "---\nname: research\ndescription: Research a topic.\n---\n",
    );
    write(
        &hermes.join("sessions").join("session-1.json"),
        "{\"messages\":[]}",
    );
    write(&hermes.join("logs").join("run.log"), "started\n");
    write(&hermes.join("cron").join("jobs.json"), "[]");
    write(&hermes.join("state.db"), "SQLite format 3\u{0}");
    write(
        &hermes.join("plugins").join("native").join("plugin.js"),
        "module.exports = () => { throw new Error('never'); };",
    );
    write(
        &hermes.join("mcp-tokens").join("github.json"),
        "{\"token\":\"hermes-mcp-token-plaintext\"}",
    );
    hermes
}

#[test]
fn hermes_plan_covers_config_models_memory_skills_secrets_and_credentials() {
    let root = TestDir::new("hermes-plan");
    let target = root.join("target");
    let hermes = seed_hermes_home(&root);
    let platform_paths = paths(&root, HostPlatform::MacOs);
    let signer = signer();

    let detection = HermesMigrationProvider
        .detect(&platform_paths, None)
        .expect("detect the injected Hermes profile");
    assert!(detection.found);
    assert_eq!(detection.confidence, DetectionConfidence::High);
    assert_eq!(detection.source, hermes);

    let plan = HermesMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan the Hermes migration");

    assert_eq!(plan.result.status, MigrationStatus::Migrated);
    assert_eq!(plan.result.exit_code, 0);
    assert_eq!(plan.operation_count(), 14);
    assert_eq!(
        diagnostic_codes(&plan),
        vec![
            "BACKUP_REQUIRED".to_owned(),
            "HERMES_MCP_TOKENS_MANUAL_REAUTH".to_owned(),
            "HERMES_PLUGINS_MANUAL_REVIEW".to_owned(),
            "HERMES_SAFE_IMPORT".to_owned(),
        ]
    );

    // A dry run reads the whole profile and writes nothing.
    assert!(!target.exists());
    assert!(!root.join("backup").exists());
    let debug = format!("{plan:?}");
    for plaintext in [
        "hermes-config-plaintext",
        "hermes-openai-plaintext",
        "hermes-auth-plaintext",
        "hermes-opencode-plaintext",
    ] {
        assert!(
            !debug.contains(plaintext),
            "plan debug output leaked {plaintext}"
        );
    }
}

#[test]
fn hermes_apply_preserves_models_and_memory_while_externalizing_every_secret() {
    let root = TestDir::new("hermes-apply");
    let target = root.join("target");
    let backup = root.join("backup");
    let hermes = seed_hermes_home(&root);
    let platform_paths = paths(&root, HostPlatform::MacOs);
    let signer = signer();
    let plan = HermesMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan the Hermes migration");

    let mut secrets = MemorySecretStore::default();
    let receipt = {
        let mut apply = ApplyContext {
            target_root: &target,
            backup_root: &backup,
            overwrite: false,
            secret_store: &mut secrets,
        };
        HermesMigrationProvider
            .apply(&mut apply, &plan)
            .expect("apply the Hermes migration")
    };

    assert_eq!(
        manifest_operations(&target, "hermes"),
        vec![
            (
                "text-config".to_owned(),
                "config/migrations/hermes/config.yaml".to_owned()
            ),
            (
                "environment".to_owned(),
                "config/migrations/hermes/env.json".to_owned()
            ),
            (
                "secret-document".to_owned(),
                "config/migrations/hermes/auth.json".to_owned()
            ),
            (
                "secret-document".to_owned(),
                "config/migrations/hermes/opencode-auth.json".to_owned()
            ),
            ("copy".to_owned(), "workspace/SOUL.md".to_owned()),
            ("copy".to_owned(), "workspace/AGENTS.md".to_owned()),
            ("append".to_owned(), "workspace/MEMORY.md".to_owned()),
            ("append".to_owned(), "workspace/USER.md".to_owned()),
            ("copy".to_owned(), "workspace/skills/research".to_owned()),
            (
                "copy".to_owned(),
                "reports/migration/hermes/sessions".to_owned()
            ),
            (
                "copy".to_owned(),
                "reports/migration/hermes/logs".to_owned()
            ),
            (
                "copy".to_owned(),
                "reports/migration/hermes/cron".to_owned()
            ),
            (
                "copy".to_owned(),
                "reports/migration/hermes/state.db".to_owned()
            ),
        ]
    );

    // Config and models: every routing decision survives the migration verbatim.
    let config = read(
        &target
            .join("config")
            .join("migrations")
            .join("hermes")
            .join("config.yaml"),
    );
    assert!(config.contains("default_model: openai/gpt-5\n"));
    assert!(config.contains("small_model: openai/gpt-5-mini\n"));
    assert!(config.contains("  openai/gpt-5:\n"));
    assert!(config.contains("    context_window: 400000\n"));
    assert!(config.contains("    reasoning_effort: high\n"));
    assert!(config.contains("  openai/gpt-5-mini:\n"));
    assert!(config.contains("    context_window: 200000\n"));
    assert!(config.contains("    command: safe-tool\n"));
    // Secrets inside the same file are externalized rather than copied.
    assert!(!config.contains("hermes-config-plaintext"));
    assert!(!config.contains("hermes-header-plaintext"));
    assert!(config.contains("api_key: \"keyring://gta-claw/hermes-config-"));

    // Memory.
    let memory = read(&target.join("workspace").join("MEMORY.md"));
    assert!(memory.contains("Imported Hermes memory"));
    assert!(memory.contains("The deploy key rotates every Monday."));
    let user = read(&target.join("workspace").join("USER.md"));
    assert!(user.contains("Imported Hermes user memory"));
    assert!(user.contains("The user prefers metric units."));
    assert_eq!(
        read(&target.join("workspace").join("SOUL.md")),
        "I am careful and terse.\n"
    );

    // Skills.
    assert_eq!(
        read(
            &target
                .join("workspace")
                .join("skills")
                .join("research")
                .join("SKILL.md")
        ),
        "---\nname: research\ndescription: Research a topic.\n---\n"
    );

    // Secrets: the environment file becomes a reference map, never a copy, and
    // an empty assignment contributes no reference at all.
    let environment: serde_json::Value = serde_json::from_str(&read(
        &target
            .join("config")
            .join("migrations")
            .join("hermes")
            .join("env.json"),
    ))
    .expect("parse the migrated environment references");
    let environment = environment.as_object().expect("environment object");
    assert_eq!(environment.len(), 2);
    for key in ["OPENAI_API_KEY", "GITHUB_TOKEN"] {
        let reference = environment[key].as_str().expect("reference string");
        assert!(reference.starts_with("keyring://gta-claw/hermes-env-"));
    }
    assert!(secrets.holds("hermes-openai-plaintext"));
    assert!(secrets.holds("hermes-github-plaintext"));

    // Credentials: both credential documents are stored, not written out.
    assert_eq!(
        read(
            &target
                .join("config")
                .join("migrations")
                .join("hermes")
                .join("auth.json")
        ),
        "{\n  \"secret_ref\": \"keyring://gta-claw/hermes-auth\"\n}"
    );
    assert_eq!(secrets.plaintext("hermes-auth").as_deref(), Some(AUTH));
    assert_eq!(
        read(
            &target
                .join("config")
                .join("migrations")
                .join("hermes")
                .join("opencode-auth.json")
        ),
        "{\n  \"secret_ref\": \"keyring://gta-claw/hermes-opencode-auth\"\n}"
    );
    assert_eq!(
        secrets.plaintext("hermes-opencode-auth").as_deref(),
        Some(OPENCODE_AUTH)
    );
    assert_eq!(secrets.values.len(), 6);

    // The same probe finds each value in the untouched Hermes profile, so an
    // empty result below is a real absence rather than a broken search.
    for plaintext in [
        "hermes-config-plaintext",
        "hermes-header-plaintext",
        "hermes-openai-plaintext",
        "hermes-github-plaintext",
        "hermes-auth-plaintext",
        "hermes-opencode-plaintext",
    ] {
        assert!(
            !leaks(&hermes, plaintext).is_empty()
                || !leaks(&root.join("data"), plaintext).is_empty(),
            "probe for {plaintext} matches nothing in the source profile"
        );
        assert_eq!(leaks(&target, plaintext), Vec::<String>::new());
        assert_eq!(leaks(&backup, plaintext), Vec::<String>::new());
    }

    {
        let mut rollback = ApplyContext {
            target_root: &target,
            backup_root: &backup,
            overwrite: false,
            secret_store: &mut secrets,
        };
        HermesMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect("roll the Hermes migration back");
    }
    assert_eq!(files_under(&target), Vec::<String>::new());
    assert!(secrets.values.is_empty());
}

#[test]
fn hermes_excludes_plugins_and_mcp_tokens_instead_of_migrating_them() {
    let root = TestDir::new("hermes-exclusions");
    let target = root.join("target");
    seed_hermes_home(&root);
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = HermesMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan the Hermes migration");

    let excluded = plan
        .result
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic.code.starts_with("HERMES_") && diagnostic.code != "HERMES_SAFE_IMPORT"
        })
        .map(|diagnostic| (diagnostic.code.clone(), diagnostic.message.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        excluded,
        vec![
            (
                "HERMES_PLUGINS_MANUAL_REVIEW".to_owned(),
                "Hermes plugins were detected but were not copied or activated.".to_owned()
            ),
            (
                "HERMES_MCP_TOKENS_MANUAL_REAUTH".to_owned(),
                "Opaque Hermes MCP token state requires manual reauthentication and was not copied."
                    .to_owned()
            ),
        ]
    );

    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    HermesMigrationProvider
        .apply(&mut apply, &plan)
        .expect("apply the Hermes migration");

    let migrated = files_under(&target);
    for excluded in ["plugins", "mcp-tokens"] {
        assert!(
            !migrated
                .iter()
                .any(|path| path.split('/').any(|segment| segment == excluded)),
            "{excluded} reached the migration target: {migrated:?}"
        );
    }
    assert!(!migrated.iter().any(|path| {
        Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("js"))
    }));
    assert_eq!(
        leaks(&target, "hermes-mcp-token-plaintext"),
        Vec::<String>::new()
    );
    assert!(!secrets.holds("hermes-mcp-token-plaintext"));

    // Opaque runtime state is quarantined under reports rather than activated.
    assert!(
        migrated
            .iter()
            .any(|path| path == "reports/migration/hermes/state.db")
    );
    assert!(
        !migrated
            .iter()
            .any(|path| path.starts_with("config/migrations/hermes/state"))
    );
}

#[test]
fn hermes_apply_fails_closed_on_an_unsafe_environment_key() {
    let root = TestDir::new("hermes-unsafe-env");
    let target = root.join("target");
    let hermes = seed_hermes_home(&root);
    write(&hermes.join(".env"), "2FA_SHARED=hermes-unsafe-plaintext\n");
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = HermesMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan the Hermes migration");
    assert_eq!(plan.result.status, MigrationStatus::Migrated);

    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    let error = HermesMigrationProvider
        .apply(&mut apply, &plan)
        .expect_err("an unsafe environment key must fail the whole apply");
    assert_eq!(
        error.to_string(),
        format!(
            "migration apply failed: invalid migration input {}: environment key on line 1 is unsafe",
            hermes.join(".env").display()
        )
    );
    assert!(!error.to_string().contains("hermes-unsafe-plaintext"));

    // The transaction is undone: nothing written, no secret left behind.
    assert_eq!(files_under(&target), Vec::<String>::new());
    assert!(secrets.values.is_empty());
}

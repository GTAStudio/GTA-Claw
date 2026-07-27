#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use claw_migrate::{
    ApplyContext, ClaudeMigrationProvider, CodexMigrationProvider, DetectionConfidence,
    Ed25519ArtifactSigner, HermesMigrationProvider, HostPlatform, MigrationProvider,
    MigrationStatus, PlanContext, SecretStore, SecretStoreError, SecretValue, SystemPlatformPaths,
};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "claw-migrate-{label}-{}-{sequence}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove stale test directory");
        }
        fs::create_dir_all(&path).expect("create test directory");
        Self { path }
    }

    fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.path.join(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("remove test directory");
        }
    }
}

#[derive(Default)]
struct MemorySecretStore {
    values: BTreeMap<String, SecretValue>,
    fail_put: bool,
}

impl SecretStore for MemorySecretStore {
    fn get(&mut self, id: &str) -> Result<Option<SecretValue>, SecretStoreError> {
        Ok(self.values.get(id).cloned())
    }

    fn put(&mut self, id: &str, value: SecretValue) -> Result<String, SecretStoreError> {
        if self.fail_put {
            return Err(SecretStoreError::new("injected put failure"));
        }
        self.values.insert(id.to_owned(), value);
        Ok(format!("keyring://gta-claw/{id}"))
    }

    fn remove(&mut self, id: &str) -> Result<(), SecretStoreError> {
        self.values.remove(id);
        Ok(())
    }
}

fn paths(root: &TestDir, platform: HostPlatform) -> SystemPlatformPaths {
    SystemPlatformPaths::from_parts(
        platform,
        root.join("home"),
        root.join("config"),
        root.join("data"),
    )
}

fn signer() -> Ed25519ArtifactSigner {
    Ed25519ArtifactSigner::from_bytes("test-migration-key", &[7; 32])
}

fn write(path: &Path, content: &str) {
    fs::create_dir_all(path.parent().expect("test file parent")).expect("create test file parent");
    fs::write(path, content).expect("write test file");
}

fn plan_keys(plan: &claw_migrate::MigrationPlan) -> BTreeSet<String> {
    let value = serde_json::to_value(plan).expect("serialize plan");
    value
        .as_object()
        .expect("plan object")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn claude_desktop_discovery_is_platform_injectable() {
    for (label, platform) in [
        ("windows", HostPlatform::Windows),
        ("macos", HostPlatform::MacOs),
        ("linux", HostPlatform::Linux),
    ] {
        let root = TestDir::new(label);
        let platform_paths = paths(&root, platform);
        let desktop = root
            .join("config")
            .join("Claude")
            .join("claude_desktop_config.json");
        write(
            &desktop,
            "{\"mcpServers\":{\"safe\":{\"command\":\"tool\"}}}",
        );
        let detection = ClaudeMigrationProvider
            .detect(&platform_paths, None)
            .expect("detect injected desktop state");
        assert!(detection.found);
        assert_eq!(detection.source, desktop);
        assert_eq!(detection.confidence, DetectionConfidence::High);
        assert_eq!(detection.message, "Claude state found.");
    }
}

#[test]
fn claude_plan_apply_and_rollback_are_side_effect_free_then_reversible() {
    let root = TestDir::new("claude");
    let source = root.join("project");
    let target = root.join("target");
    let backup = root.join("backup");
    write(&source.join("CLAUDE.md"), "Project instructions.");
    write(
        &source.join(".mcp.json"),
        r#"{"mcpServers":{"example":{"command":"safe-tool","env":{"API_TOKEN":"claude-secret"},"headers":{"Authorization":"Bearer private"}}}}"#,
    );
    write(
        &source.join(".claude").join("settings.json"),
        r#"{"hooks":{"after":"review only"},"permissions":{"allow":["Read"]},"env":{"NESTED_SECRET":"settings-secret"}}"#,
    );
    write(
        &source
            .join(".claude")
            .join("skills")
            .join("review")
            .join("SKILL.md"),
        "---\nname: review\ndescription: Review code.\n---\n",
    );
    write(
        &source.join(".claude").join("commands").join("summarize.md"),
        "Summarize the current project.",
    );
    write(&target.join("workspace").join("AGENTS.md"), "Existing.\n");
    let before = fs::read(target.join("workspace").join("AGENTS.md")).expect("read original");
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan Claude migration");
    assert_eq!(plan.result.status, MigrationStatus::Migrated);
    assert_eq!(plan.result.exit_code, 0);
    assert_eq!(plan.operation_count(), 6);
    assert_eq!(
        plan_keys(&plan),
        BTreeSet::from([
            "artifacts".to_owned(),
            "contract_version".to_owned(),
            "diagnostics".to_owned(),
            "exit_code".to_owned(),
            "input".to_owned(),
            "recognized_bridges".to_owned(),
            "remaining_javascript".to_owned(),
            "status".to_owned(),
        ])
    );
    assert_eq!(
        fs::read(target.join("workspace").join("AGENTS.md")).expect("dry-run target"),
        before
    );
    assert!(
        !target
            .join("config")
            .join("migrations")
            .join("claude")
            .exists()
    );

    let mut secrets = MemorySecretStore::default();
    let receipt = {
        let mut apply = ApplyContext {
            target_root: &target,
            backup_root: &backup,
            overwrite: false,
            secret_store: &mut secrets,
        };
        ClaudeMigrationProvider
            .apply(&mut apply, &plan)
            .expect("apply Claude migration")
    };
    assert!(receipt.backup_dir.join("manifest.json").is_file());
    let mcp = fs::read_to_string(
        target
            .join("config")
            .join("migrations")
            .join("claude")
            .join("project-mcp.json"),
    )
    .expect("read migrated MCP config");
    assert!(!mcp.contains("claude-secret"));
    assert!(!mcp.contains("Bearer private"));
    assert!(mcp.contains("keyring://gta-claw/"));
    assert_eq!(secrets.values.len(), 3);
    assert_eq!(
        fs::read_to_string(
            target
                .join("workspace")
                .join("skills")
                .join("claude-command-summarize")
                .join("SKILL.md"),
        )
        .expect("read generated command skill"),
        "---\nname: claude-command-summarize\ndescription: \"Summarize the current project.\"\ndisable-model-invocation: true\n---\n\n<!-- Imported inert Claude command -->\n\nSummarize the current project.\n"
    );

    {
        let mut rollback = ApplyContext {
            target_root: &target,
            backup_root: &backup,
            overwrite: false,
            secret_store: &mut secrets,
        };
        ClaudeMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect("rollback Claude migration");
    }
    assert_eq!(
        fs::read(target.join("workspace").join("AGENTS.md")).expect("restored instructions"),
        before
    );
    assert!(
        !target
            .join("config")
            .join("migrations")
            .join("claude")
            .exists()
    );
    assert!(
        !target
            .join("workspace")
            .join("skills")
            .join("review")
            .exists()
    );
    assert_eq!(secrets.values, BTreeMap::new());
}

#[test]
fn codex_imports_config_auth_sessions_skills_and_sidecars() {
    let root = TestDir::new("codex");
    let source = root.join("codex-home");
    let target = root.join("target");
    let backup = root.join("backup");
    write(
        &source.join("config.toml"),
        "model = \"gpt-5\"\napi_key = \"codex-secret\"\n[mcp.servers.local.env]\nREGION = \"private-region\"\n",
    );
    write(
        &source.join("auth.json"),
        "{\"access_token\":\"codex-auth-secret\"}",
    );
    write(
        &source.join("sessions").join("session-1.jsonl"),
        "{\"role\":\"user\",\"content\":\"hello\"}\n",
    );
    write(&source.join("history.jsonl"), "{\"session\":\"one\"}\n");
    write(
        &source.join("skills").join("audit").join("SKILL.md"),
        "---\nname: audit\ndescription: Audit code.\n---\n",
    );
    write(&source.join("AGENTS.md"), "Codex instructions.");
    write(
        &source.join("models_cache.json"),
        "{\"models\":[\"gpt-5\"]}",
    );
    fs::create_dir_all(source.join("plugins")).expect("create plugin marker");
    let platform_paths = paths(&root, HostPlatform::Windows);
    let signer = signer();
    let plan = CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan Codex migration");
    assert_eq!(plan.result.status, MigrationStatus::Migrated);
    assert_eq!(plan.operation_count(), 8);
    assert!(
        plan.result
            .diagnostics
            .iter()
            .any(|item| item.code == "CODEX_PLUGINS_MANUAL_REVIEW")
    );

    let mut secrets = MemorySecretStore::default();
    let receipt = {
        let mut apply = ApplyContext {
            target_root: &target,
            backup_root: &backup,
            overwrite: false,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .apply(&mut apply, &plan)
            .expect("apply Codex migration")
    };
    let config = fs::read_to_string(
        target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("config.toml"),
    )
    .expect("read Codex config");
    assert_eq!(
        config,
        "model = \"gpt-5\"\napi_key = \"keyring://gta-claw/codex-config-4f221e5cc3c539f4\"\n[mcp.servers.local.env]\nREGION = \"keyring://gta-claw/codex-config-f087189868ae4c7e\"\n"
    );
    let auth = fs::read_to_string(
        target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("auth.json"),
    )
    .expect("read auth reference");
    assert_eq!(
        auth,
        "{\n  \"secret_ref\": \"keyring://gta-claw/codex-auth\"\n}"
    );
    assert_eq!(secrets.values.len(), 3);
    assert_eq!(
        fs::read_to_string(
            target
                .join("sessions")
                .join("codex")
                .join("session-1.jsonl"),
        )
        .expect("read migrated session"),
        "{\"role\":\"user\",\"content\":\"hello\"}\n"
    );
    assert!(
        !target
            .join("reports")
            .join("migration")
            .join("codex")
            .join("plugins")
            .exists()
    );

    {
        let mut rollback = ApplyContext {
            target_root: &target,
            backup_root: &backup,
            overwrite: false,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect("rollback Codex migration");
    }
    assert!(!target.join("sessions").join("codex").exists());
    assert_eq!(secrets.values, BTreeMap::new());
}

#[test]
fn hermes_imports_config_memory_skills_sessions_and_secrets() {
    let root = TestDir::new("hermes");
    let source = root.join("hermes-home");
    let target = root.join("target");
    let backup = root.join("backup");
    write(
        &source.join("config.yaml"),
        "default_model: openai/gpt-5\napi_key: hermes-config-secret\nmcp_servers:\n  local:\n    command: safe-tool\n    headers:\n      X-Custom: hermes-header-secret\n",
    );
    write(
        &source.join(".env"),
        "OPENAI_API_KEY=hermes-openai-secret\nGITHUB_TOKEN='hermes-github-secret'\n",
    );
    write(
        &source.join("auth.json"),
        "{\"oauth\":\"hermes-auth-secret\"}",
    );
    write(&source.join("SOUL.md"), "Hermes soul.");
    write(&source.join("AGENTS.md"), "Hermes agents.");
    write(&source.join("memories").join("MEMORY.md"), "Remember this.");
    write(&source.join("memories").join("USER.md"), "User preference.");
    write(
        &source.join("skills").join("research").join("SKILL.md"),
        "---\nname: research\ndescription: Research.\n---\n",
    );
    write(
        &source.join("sessions").join("session.json"),
        "{\"messages\":[]}",
    );
    write(&source.join("logs").join("migration.log"), "legacy log");
    fs::create_dir_all(source.join("plugins")).expect("create plugin marker");
    fs::create_dir_all(source.join("mcp-tokens")).expect("create token marker");
    let platform_paths = paths(&root, HostPlatform::MacOs);
    let signer = signer();
    let plan = HermesMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan Hermes migration");
    assert_eq!(plan.result.status, MigrationStatus::Migrated);
    assert_eq!(plan.operation_count(), 11);
    assert_eq!(
        plan.result
            .diagnostics
            .iter()
            .map(|item| item.code.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "BACKUP_REQUIRED",
            "HERMES_MCP_TOKENS_MANUAL_REAUTH",
            "HERMES_PLUGINS_MANUAL_REVIEW",
            "HERMES_SAFE_IMPORT",
        ])
    );

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
            .expect("apply Hermes migration")
    };
    let config = fs::read_to_string(
        target
            .join("config")
            .join("migrations")
            .join("hermes")
            .join("config.yaml"),
    )
    .expect("read Hermes config");
    assert!(!config.contains("hermes-config-secret"));
    assert!(!config.contains("hermes-header-secret"));
    assert!(config.contains("keyring://gta-claw/"));
    let env = fs::read_to_string(
        target
            .join("config")
            .join("migrations")
            .join("hermes")
            .join("env.json"),
    )
    .expect("read Hermes env references");
    assert!(!env.contains("hermes-openai-secret"));
    assert!(!env.contains("hermes-github-secret"));
    assert_eq!(secrets.values.len(), 5);
    assert_eq!(
        fs::read_to_string(
            target
                .join("reports")
                .join("migration")
                .join("hermes")
                .join("sessions")
                .join("session.json"),
        )
        .expect("read archived Hermes session"),
        "{\"messages\":[]}"
    );

    {
        let mut rollback = ApplyContext {
            target_root: &target,
            backup_root: &backup,
            overwrite: false,
            secret_store: &mut secrets,
        };
        HermesMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect("rollback Hermes migration");
    }
    assert!(!target.join("workspace").join("SOUL.md").exists());
    assert!(
        !target
            .join("reports")
            .join("migration")
            .join("hermes")
            .exists()
    );
    assert_eq!(secrets.values, BTreeMap::new());
}

#[test]
fn executable_artifact_is_failed_not_silent_success() {
    let root = TestDir::new("executable");
    let source = root.join("codex-home");
    let target = root.join("target");
    write(&source.join("config.toml"), "model = \"gpt-5\"\n");
    write(
        &source.join("skills").join("unsafe").join("SKILL.md"),
        "---\nname: unsafe\ndescription: Unsafe.\n---\n",
    );
    write(
        &source.join("skills").join("unsafe").join("run.js"),
        "throw new Error('never execute');",
    );
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("produce rejected plan");
    assert_eq!(plan.result.status, MigrationStatus::Failed);
    assert_eq!(plan.result.exit_code, 1);
    assert_eq!(plan.operation_count(), 0);
    assert_eq!(
        plan.result.diagnostics[0].code,
        "EXECUTABLE_ARTIFACT_REQUIRES_PORT"
    );
    assert!(!target.exists());
    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    let error = CodexMigrationProvider
        .apply(&mut apply, &plan)
        .expect_err("failed plan cannot apply");
    assert_eq!(
        error.to_string(),
        "only a validated migrated plan may be applied"
    );
}

#[test]
fn secret_store_failure_rolls_back_without_plaintext_output() {
    let root = TestDir::new("secret-failure");
    let source = root.join("codex-home");
    let target = root.join("target");
    write(
        &source.join("config.toml"),
        "api_key = \"must-never-leak\"\n",
    );
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan secret migration");
    let mut secrets = MemorySecretStore {
        values: BTreeMap::new(),
        fail_put: true,
    };
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    let error = CodexMigrationProvider
        .apply(&mut apply, &plan)
        .expect_err("secret failure is fail closed");
    assert_eq!(
        error.to_string(),
        "migration apply failed: secret store failed: injected put failure"
    );
    assert!(!error.to_string().contains("must-never-leak"));
    assert!(
        !target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("config.toml")
            .exists()
    );
    assert_eq!(secrets.values, BTreeMap::new());
}

#[test]
fn existing_target_is_classified_as_failed_plan() {
    let root = TestDir::new("conflict");
    let source = root.join("hermes-home");
    let target = root.join("target");
    write(&source.join("SOUL.md"), "Imported soul.");
    write(&target.join("workspace").join("SOUL.md"), "Existing soul.");
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = HermesMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("produce conflict plan");
    assert_eq!(plan.result.status, MigrationStatus::Failed);
    assert_eq!(plan.result.exit_code, 1);
    assert_eq!(plan.result.diagnostics.len(), 1);
    assert_eq!(plan.result.diagnostics[0].code, "TARGET_EXISTS");
    assert_eq!(
        fs::read_to_string(target.join("workspace").join("SOUL.md")).expect("existing target"),
        "Existing soul."
    );
}

#[test]
fn apply_rejects_source_changed_after_dry_run() {
    let root = TestDir::new("source-change");
    let source = root.join("codex-home");
    let target = root.join("target");
    let config = source.join("config.toml");
    write(&config, "model = \"gpt-5\"\n");
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan source snapshot");
    write(&config, "model = \"changed-after-plan\"\n");
    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    let error = CodexMigrationProvider
        .apply(&mut apply, &plan)
        .expect_err("changed source must fail");
    assert_eq!(
        error.to_string(),
        format!(
            "invalid migration input {}: source changed after the reviewed dry-run plan",
            config.display()
        )
    );
    assert!(!target.exists());
}

#[test]
fn rollback_refuses_to_delete_concurrent_target_changes() {
    let root = TestDir::new("rollback-race");
    let source = root.join("codex-home");
    let target = root.join("target");
    let migrated = target
        .join("config")
        .join("migrations")
        .join("codex")
        .join("config.toml");
    write(&source.join("config.toml"), "api_key = \"private\"\n");
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan migration");
    let mut secrets = MemorySecretStore::default();
    let receipt = {
        let mut apply = ApplyContext {
            target_root: &target,
            backup_root: &root.join("backup"),
            overwrite: false,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .apply(&mut apply, &plan)
            .expect("apply migration")
    };
    write(&migrated, "concurrent user edit\n");
    let error = {
        let mut rollback = ApplyContext {
            target_root: &target,
            backup_root: &root.join("backup"),
            overwrite: false,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect_err("concurrent edit must block rollback")
    };
    assert_eq!(
        error.to_string(),
        format!("migration target exists: {}", migrated.display())
    );
    assert_eq!(
        fs::read_to_string(&migrated).expect("preserve concurrent edit"),
        "concurrent user edit\n"
    );
    assert_eq!(secrets.values.len(), 1);
}

#[test]
fn codex_default_discovery_imports_cli_and_desktop_config_together() {
    let root = TestDir::new("codex-desktop");
    let target = root.join("target");
    write(
        &root.join("home").join(".codex").join("config.toml"),
        "model = \"gpt-5\"\n",
    );
    write(
        &root.join("config").join("Codex").join("config.json"),
        "{\"theme\":\"dark\",\"api_token\":\"desktop-private\"}",
    );
    let platform_paths = paths(&root, HostPlatform::Windows);
    let signer = signer();
    let plan = CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan combined Codex sources");
    assert_eq!(plan.result.status, MigrationStatus::Migrated);
    assert_eq!(plan.operation_count(), 3);
    let mut secrets = MemorySecretStore::default();
    let receipt = {
        let mut apply = ApplyContext {
            target_root: &target,
            backup_root: &root.join("backup"),
            overwrite: false,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .apply(&mut apply, &plan)
            .expect("apply combined Codex sources")
    };
    // The imported document keeps the member order of the user's original
    // Codex config (`theme` before `api_token`) instead of re-sorting it, so a
    // migrated file stays diff-comparable against the source it came from.
    assert_eq!(
        fs::read_to_string(
            target
                .join("config")
                .join("migrations")
                .join("codex")
                .join("desktop.json"),
        )
        .expect("read desktop config"),
        "{\n  \"theme\": \"dark\",\n  \"api_token\": \"keyring://gta-claw/codex-desktop-9de92caff5340b4d\"\n}"
    );
    assert_eq!(secrets.values.len(), 1);
    let mut rollback = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    CodexMigrationProvider
        .rollback(&mut rollback, &receipt)
        .expect("rollback combined Codex sources");
}

#[test]
fn corrupted_backup_never_replaces_current_target() {
    let root = TestDir::new("backup-corruption");
    let source = root.join("hermes-home");
    let target = root.join("target");
    let soul = target.join("workspace").join("SOUL.md");
    write(&source.join("SOUL.md"), "Imported soul.");
    write(&soul, "Original soul.");
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = HermesMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: true,
            signer: &signer,
        })
        .expect("plan overwrite");
    let mut secrets = MemorySecretStore::default();
    let receipt = {
        let mut apply = ApplyContext {
            target_root: &target,
            backup_root: &root.join("backup"),
            overwrite: true,
            secret_store: &mut secrets,
        };
        HermesMigrationProvider
            .apply(&mut apply, &plan)
            .expect("apply overwrite")
    };
    assert_eq!(
        fs::read_to_string(&soul).expect("read imported target"),
        "Imported soul."
    );
    write(
        &receipt.backup_dir.join("items").join("0"),
        "Corrupt backup.",
    );
    let error = {
        let mut rollback = ApplyContext {
            target_root: &target,
            backup_root: &root.join("backup"),
            overwrite: true,
            secret_store: &mut secrets,
        };
        HermesMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect_err("corrupt backup blocks rollback")
    };
    assert_eq!(
        error.to_string(),
        format!(
            "backup verification failed for {}",
            receipt.backup_dir.join("items").join("0").display()
        )
    );
    assert_eq!(
        fs::read_to_string(&soul).expect("current target remains"),
        "Imported soul."
    );
}

#[test]
fn codex_home_override_is_injected_without_real_environment_access() {
    let root = TestDir::new("codex-home");
    let custom_home = root.join("custom-codex");
    let target = root.join("target");
    write(&custom_home.join("config.toml"), "model = \"gpt-5\"\n");
    let platform_paths = paths(&root, HostPlatform::Linux).with_codex_home(custom_home.clone());
    let detection = CodexMigrationProvider
        .detect(&platform_paths, None)
        .expect("detect injected CODEX_HOME");
    assert!(detection.found);
    assert_eq!(detection.source, custom_home);
    assert_eq!(detection.confidence, DetectionConfidence::High);
    let signer = signer();
    let plan = CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan injected CODEX_HOME");
    assert_eq!(plan.result.status, MigrationStatus::Migrated);
    assert_eq!(plan.operation_count(), 2);
    assert!(!target.exists());
}

#[test]
fn rollback_restores_preexisting_secret_value() {
    let root = TestDir::new("secret-restore");
    let source = root.join("codex-home");
    let target = root.join("target");
    write(
        &source.join("config.toml"),
        "api_key = \"replacement-secret\"\n",
    );
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = CodexMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&source),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan secret replacement");
    let secret_id = "codex-config-4a2082f529e356d5";
    let mut secrets = MemorySecretStore::default();
    secrets
        .values
        .insert(secret_id.to_owned(), SecretValue::new(b"original-secret"));
    let receipt = {
        let mut apply = ApplyContext {
            target_root: &target,
            backup_root: &root.join("backup"),
            overwrite: false,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .apply(&mut apply, &plan)
            .expect("apply secret replacement")
    };
    assert_eq!(
        secrets.values.get(secret_id).expect("replacement").expose(),
        b"replacement-secret"
    );
    {
        let mut rollback = ApplyContext {
            target_root: &target,
            backup_root: &root.join("backup"),
            overwrite: false,
            secret_store: &mut secrets,
        };
        CodexMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect("rollback secret replacement");
    }
    assert_eq!(
        secrets.values.get(secret_id).expect("restored").expose(),
        b"original-secret"
    );
}

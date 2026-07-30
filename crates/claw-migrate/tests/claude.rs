//! Frozen plan/apply fixtures for the Claude migration provider.
//!
//! Covers the six items the parity contract requires of
//! `interop.migration.claude`: instructions, MCP servers, skills, memory,
//! credentials and safe config. Every fixture is rooted in a temporary
//! directory and drives discovery through injected platform paths, so no test
//! here can read or write a real `~/.claude`.

use std::fs;
use std::path::Path;

use claw_migrate::{
    ApplyContext, ClaudeMigrationProvider, DetectionConfidence, HostPlatform, MigrationProvider,
    MigrationStatus, PlanContext,
};

mod common;

use common::{
    MemorySecretStore, TestDir, diagnostic_codes, files_under, leaks, manifest_operations, paths,
    read, signer, write,
};

const SETTINGS: &str = r#"{
  "model": "claude-opus-4",
  "apiKeyHelper": "/opt/claude/get-key.sh",
  "hooks": {"PostToolUse": [{"command": "/opt/claude/audit.sh"}]},
  "permissions": {"allow": ["Read(**)"], "deny": ["Bash"]},
  "env": {"CLAUDE_ENV_SECRET": "claude-env-plaintext"}
}"#;

const CREDENTIALS: &str = r#"{"claudeAiOauth":{"accessToken":"claude-oauth-plaintext","refreshToken":"claude-refresh-plaintext","expiresAt":1780000000}}"#;

const USER_CONFIG: &str = r#"{
  "mcpServers": {
    "docs": {
      "command": "docs-server",
      "args": ["--read-only"],
      "env": {"MCP_TOKEN": "claude-mcp-plaintext"}
    }
  },
  "projects": {"/work": {"lastCost": 0.5}}
}"#;

const DESKTOP_CONFIG: &str = r#"{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-fs",
      "args": ["--root", "/tmp"],
      "env": {"FS_TOKEN": "claude-desktop-plaintext"}
    }
  }
}"#;

/// Writes a complete Claude user profile under the injected home directory.
///
/// The tree carries every required item plus the runtime state the provider
/// must refuse to move.
fn seed_claude_home(root: &TestDir) {
    let home = root.join("home");
    let claude = home.join(".claude");
    write(&claude.join("CLAUDE.md"), "Remember: prefer small diffs.\n");
    write(&claude.join("settings.json"), SETTINGS);
    write(&claude.join(".credentials.json"), CREDENTIALS);
    write(&home.join(".claude.json"), USER_CONFIG);
    write(
        &root
            .join("config")
            .join("Claude")
            .join("claude_desktop_config.json"),
        DESKTOP_CONFIG,
    );
    write(
        &claude.join("skills").join("review").join("SKILL.md"),
        "---\nname: review\ndescription: Review code.\n---\n",
    );
    write(
        &claude.join("commands").join("summarize.md"),
        "Summarize the current project.",
    );
    write(
        &claude.join("projects").join("work").join("chat.jsonl"),
        "{\"role\":\"user\",\"content\":\"prior session\"}\n",
    );
    write(&claude.join("plans").join("plan.md"), "Legacy plan.\n");
    // Runtime state that must never be carried into the migration target.
    write(
        &claude.join("plugins").join("vendor").join("index.js"),
        "throw new Error('never migrated');",
    );
    write(
        &claude.join("shell-snapshots").join("snapshot-1.sh"),
        "export SNAPSHOT_SECRET=claude-snapshot-plaintext\n",
    );
    write(
        &claude.join("statsig").join("cache.json"),
        "{\"gate\":true}",
    );
    write(&claude.join("todos").join("todo.json"), "[]");
    write(&claude.join("ide").join("lock.json"), "{\"pid\":1}");
}

#[test]
fn claude_plan_covers_instructions_mcp_skills_memory_credentials_and_safe_config() {
    let root = TestDir::new("claude-plan");
    let target = root.join("target");
    seed_claude_home(&root);
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();

    let detection = ClaudeMigrationProvider
        .detect(&platform_paths, None)
        .expect("detect the injected Claude profile");
    assert!(detection.found);
    assert_eq!(detection.confidence, DetectionConfidence::High);
    assert_eq!(detection.source, root.join("home").join(".claude"));

    let plan = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan the Claude migration");

    assert_eq!(plan.result.status, MigrationStatus::Migrated);
    assert_eq!(plan.result.exit_code, 0);
    assert_eq!(plan.operation_count(), 10);
    assert_eq!(
        diagnostic_codes(&plan),
        vec![
            "BACKUP_REQUIRED".to_owned(),
            "CLAUDE_COMMAND_SETTING_MANUAL_REVIEW".to_owned(),
            "CLAUDE_ENV_EXTERNALIZED".to_owned(),
            "CLAUDE_HOOKS_MANUAL_REVIEW".to_owned(),
            "CLAUDE_PERMISSIONS_MANUAL_REVIEW".to_owned(),
            "CLAUDE_SAFE_IMPORT".to_owned(),
            "CLAUDE_UNSAFE_STATE_EXCLUDED".to_owned(),
        ]
    );

    // A dry run inspects the profile and writes nothing at all.
    assert!(!target.exists());
    assert!(!root.join("backup").exists());
    let debug = format!("{plan:?}");
    for plaintext in [
        "claude-env-plaintext",
        "claude-oauth-plaintext",
        "claude-mcp-plaintext",
        "claude-desktop-plaintext",
    ] {
        assert!(
            !debug.contains(plaintext),
            "plan debug output leaked {plaintext}"
        );
    }
}

#[test]
fn claude_apply_migrates_instructions_mcp_skills_memory_and_credentials() {
    let root = TestDir::new("claude-apply");
    let target = root.join("target");
    let backup = root.join("backup");
    seed_claude_home(&root);
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan the Claude migration");

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
            .expect("apply the Claude migration")
    };
    assert!(receipt.backup_dir.join("manifest.json").is_file());

    assert_eq!(
        manifest_operations(&target, "claude"),
        vec![
            ("append".to_owned(), "workspace/USER.md".to_owned()),
            (
                "json-config".to_owned(),
                "config/migrations/claude/settings.json".to_owned()
            ),
            (
                "json-config".to_owned(),
                "config/migrations/claude/claude.json".to_owned()
            ),
            (
                "json-config".to_owned(),
                "config/migrations/claude/desktop.json".to_owned()
            ),
            (
                "secret-document".to_owned(),
                "config/migrations/claude/credentials.json".to_owned()
            ),
            ("copy".to_owned(), "workspace/skills/review".to_owned()),
            (
                "command-skill".to_owned(),
                "workspace/skills/claude-command-summarize".to_owned()
            ),
            ("copy".to_owned(), "sessions/claude".to_owned()),
            (
                "copy".to_owned(),
                "reports/migration/claude/plans".to_owned()
            ),
        ]
    );

    // Instructions and memory.
    let memory = read(&target.join("workspace").join("USER.md"));
    assert!(memory.contains("Imported Claude user instructions"));
    assert!(memory.contains("Remember: prefer small diffs."));

    // MCP servers, from both the CLI profile and the desktop application.
    let user_config = read(
        &target
            .join("config")
            .join("migrations")
            .join("claude")
            .join("claude.json"),
    );
    assert!(user_config.contains("\"docs-server\""));
    assert!(user_config.contains("--read-only"));
    assert!(!user_config.contains("claude-mcp-plaintext"));
    assert!(user_config.contains("keyring://gta-claw/claude-user-"));
    let desktop = read(
        &target
            .join("config")
            .join("migrations")
            .join("claude")
            .join("desktop.json"),
    );
    assert!(desktop.contains("\"mcp-fs\""));
    assert!(!desktop.contains("claude-desktop-plaintext"));
    assert!(desktop.contains("keyring://gta-claw/claude-desktop-"));

    // Skills, including a Claude command imported as an inert skill.
    assert_eq!(
        read(
            &target
                .join("workspace")
                .join("skills")
                .join("review")
                .join("SKILL.md")
        ),
        "---\nname: review\ndescription: Review code.\n---\n"
    );
    let command_skill = read(
        &target
            .join("workspace")
            .join("skills")
            .join("claude-command-summarize")
            .join("SKILL.md"),
    );
    assert!(command_skill.contains("disable-model-invocation: true"));

    // Prior sessions.
    assert_eq!(
        read(
            &target
                .join("sessions")
                .join("claude")
                .join("work")
                .join("chat.jsonl")
        ),
        "{\"role\":\"user\",\"content\":\"prior session\"}\n"
    );

    // Credentials: only a reference reaches the disk, the bytes reach the store.
    assert_eq!(
        read(
            &target
                .join("config")
                .join("migrations")
                .join("claude")
                .join("credentials.json")
        ),
        "{\n  \"secret_ref\": \"keyring://gta-claw/claude-credentials\"\n}"
    );
    assert_eq!(
        secrets.plaintext("claude-credentials").as_deref(),
        Some(CREDENTIALS)
    );
    assert!(secrets.holds("claude-env-plaintext"));
    assert!(secrets.holds("claude-mcp-plaintext"));
    assert!(secrets.holds("claude-desktop-plaintext"));
    assert!(secrets.holds("/opt/claude/get-key.sh"));
    assert_eq!(secrets.values.len(), 5);

    // Safe config: reviewable settings survive as data, secrets do not.
    let settings = read(
        &target
            .join("config")
            .join("migrations")
            .join("claude")
            .join("settings.json"),
    );
    assert!(settings.contains("\"claude-opus-4\""));
    assert!(settings.contains("/opt/claude/audit.sh"));
    assert!(settings.contains("Read(**)"));
    assert!(!settings.contains("/opt/claude/get-key.sh"));
    assert!(!settings.contains("claude-env-plaintext"));

    // No migrated credential is written anywhere, target or backup. The same
    // probe finds each value in the untouched source profile, so an empty
    // result is a real absence rather than a broken search.
    for plaintext in [
        "claude-env-plaintext",
        "claude-oauth-plaintext",
        "claude-refresh-plaintext",
        "claude-mcp-plaintext",
        "claude-desktop-plaintext",
    ] {
        assert!(
            !leaks(&root.join("home"), plaintext).is_empty()
                || !leaks(&root.join("config"), plaintext).is_empty(),
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
        ClaudeMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect("roll the Claude migration back");
    }
    assert_eq!(files_under(&target), Vec::<String>::new());
    assert!(secrets.values.is_empty());
}

#[test]
fn claude_excludes_plugins_and_runtime_state_instead_of_copying_them() {
    let root = TestDir::new("claude-exclusions");
    let target = root.join("target");
    let backup = root.join("backup");
    seed_claude_home(&root);
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan the Claude migration");

    let exclusion = plan
        .result
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "CLAUDE_UNSAFE_STATE_EXCLUDED")
        .expect("the plan names its exclusions");
    assert_eq!(
        exclusion.message,
        "Claude runtime state was detected and excluded from the migration: ide, plugins, shell-snapshots, statsig, todos."
    );

    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &backup,
        overwrite: false,
        secret_store: &mut secrets,
    };
    ClaudeMigrationProvider
        .apply(&mut apply, &plan)
        .expect("apply the Claude migration");

    let migrated = files_under(&target);
    for excluded in ["plugins", "shell-snapshots", "statsig", "todos", "ide"] {
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
        leaks(&target, "claude-snapshot-plaintext"),
        Vec::<String>::new()
    );
    assert!(!secrets.holds("claude-snapshot-plaintext"));
}

#[test]
fn claude_refuses_a_javascript_skill_instead_of_migrating_it_silently() {
    let root = TestDir::new("claude-executable");
    let target = root.join("target");
    let claude = root.join("home").join(".claude");
    write(&claude.join("CLAUDE.md"), "Instructions.\n");
    write(
        &claude.join("skills").join("bridge").join("SKILL.md"),
        "---\nname: bridge\ndescription: Bridge.\n---\n",
    );
    write(
        &claude.join("skills").join("bridge").join("bridge.mjs"),
        "export function run() { throw new Error('never'); }",
    );
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("an executable artifact produces a rejected plan, not an error");

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
    let error = ClaudeMigrationProvider
        .apply(&mut apply, &plan)
        .expect_err("a rejected plan can never be applied");
    assert_eq!(
        error.to_string(),
        "only a validated migrated plan may be applied"
    );
    assert!(!target.exists());
}

#[test]
fn claude_discovery_reads_only_the_injected_home() {
    let root = TestDir::new("claude-injected-home");
    fs::create_dir_all(root.join("home")).expect("create empty injected home");
    let platform_paths = paths(&root, HostPlatform::Linux);

    let detection = ClaudeMigrationProvider
        .detect(&platform_paths, None)
        .expect("detect against an empty injected home");
    assert!(!detection.found);
    assert_eq!(detection.confidence, DetectionConfidence::Low);
    assert_eq!(detection.message, "Claude state not found.");
    assert!(
        detection.source.starts_with(root.path()),
        "discovery escaped the injected home: {}",
        detection.source.display()
    );

    let signer = signer();
    let error = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: None,
            target_root: &root.join("target"),
            overwrite: false,
            signer: &signer,
        })
        .expect_err("an empty home has nothing to migrate");
    assert_eq!(
        error.to_string(),
        format!(
            "claude state was not found at {}",
            root.join("config")
                .join("Claude")
                .join("claude_desktop_config.json")
                .display()
        )
    );
}

#[test]
fn explicit_claude_file_is_isolated_from_default_sources() {
    let root = TestDir::new("claude-explicit-file");
    let target = root.join("target");
    seed_claude_home(&root);
    let explicit = root.join("isolated").join("claude.json");
    write(
        &explicit,
        r#"{"mcpServers":{"isolated":{"command":"safe","env":{"TOKEN":"isolated-secret"}}}}"#,
    );
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();

    let detection = ClaudeMigrationProvider
        .detect(&platform_paths, Some(&explicit))
        .expect("detect isolated explicit file");
    assert!(detection.found);
    assert_eq!(detection.source, explicit);

    let plan = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&explicit),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan only the explicit file");
    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    ClaudeMigrationProvider
        .apply(&mut apply, &plan)
        .expect("apply isolated explicit file");

    assert!(secrets.holds("isolated-secret"));
    for default_secret in [
        "claude-env-plaintext",
        "claude-oauth-plaintext",
        "claude-mcp-plaintext",
        "claude-desktop-plaintext",
    ] {
        assert!(!secrets.holds(default_secret));
    }
    assert_eq!(
        files_under(&target)
            .into_iter()
            .filter(|path| path != "config/migrations/claude.json5")
            .collect::<Vec<_>>(),
        vec!["config/migrations/claude/claude-desktop.json".to_owned()]
    );
}

#[test]
fn explicit_claude_directory_excludes_parent_and_platform_companions() {
    let root = TestDir::new("claude-explicit-directory");
    let target = root.join("target");
    seed_claude_home(&root);
    let explicit = root.join("isolated").join(".claude");
    write(
        &explicit.join("settings.json"),
        r#"{"model":"claude-explicit","env":{"TOKEN":"directory-only-secret"}}"#,
    );
    write(
        &root.join("isolated").join(".claude.json"),
        r#"{"env":{"TOKEN":"explicit-parent-must-not-import"}}"#,
    );
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let plan = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&explicit),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect("plan only the explicit Claude directory");
    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };

    ClaudeMigrationProvider
        .apply(&mut apply, &plan)
        .expect("apply isolated explicit directory");

    assert!(secrets.holds("directory-only-secret"));
    for ambient in [
        "explicit-parent-must-not-import",
        "claude-mcp-plaintext",
        "claude-desktop-plaintext",
    ] {
        assert!(!secrets.holds(ambient), "imported ambient secret {ambient}");
    }
    assert!(
        !target
            .join("config")
            .join("migrations")
            .join("claude")
            .join("claude.json")
            .exists()
    );
    assert!(
        !target
            .join("config")
            .join("migrations")
            .join("claude")
            .join("desktop.json")
            .exists()
    );
}

#[test]
fn missing_explicit_claude_source_never_falls_back_to_defaults() {
    let root = TestDir::new("claude-missing-explicit");
    seed_claude_home(&root);
    let missing = root.join("isolated").join("missing.json");
    let platform_paths = paths(&root, HostPlatform::Linux);
    let signer = signer();
    let target = root.join("target");

    let error = ClaudeMigrationProvider
        .plan(&PlanContext {
            paths: &platform_paths,
            source: Some(&missing),
            target_root: &target,
            overwrite: false,
            signer: &signer,
        })
        .expect_err("missing explicit source must fail");
    assert_eq!(
        error.to_string(),
        format!("claude state was not found at {}", missing.display())
    );
    assert!(!target.exists());
}

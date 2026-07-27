//! Frozen plan/apply fixtures for the Codex migration provider.
//!
//! Covers the five items the parity contract requires of
//! `interop.migration.codex`: auth, session bindings, source discovery, targets
//! and sidecars. Discovery is always driven through injected platform paths, so
//! no test here reads a real `~/.codex`, a real `CODEX_HOME` or a real desktop
//! configuration directory.
#![allow(missing_docs)]

use std::fs;

use claw_migrate::{
    ApplyContext, CodexMigrationProvider, DetectionConfidence, HostPlatform, MigrationProvider,
    MigrationStatus, PlanContext,
};

mod common;

use common::{
    MemorySecretStore, TestDir, diagnostic_codes, files_under, leaks, manifest_operations, paths,
    read, signer, write,
};

const CONFIG: &str = r#"model = "gpt-5-codex"
approval_policy = "on-request"
api_key = "codex-config-plaintext"

[mcp_servers.docs]
command = "docs-server"

[mcp_servers.docs.env]
DOCS_TOKEN = "codex-mcp-plaintext"
"#;

const AUTH: &str = r#"{"OPENAI_API_KEY":"codex-auth-plaintext","tokens":{"access_token":"codex-access-plaintext"}}"#;

/// Writes a complete Codex CLI home, including the sidecars it must quarantine
/// and the native plugin and hook trees it must refuse to move.
fn seed_codex_home(root: &TestDir) -> std::path::PathBuf {
    let codex = root.join("codex-home");
    write(&codex.join("config.toml"), CONFIG);
    write(&codex.join("auth.json"), AUTH);
    write(
        &codex.join("sessions").join("2026").join("rollout.jsonl"),
        "{\"id\":\"session-1\",\"cwd\":\"/work\"}\n",
    );
    write(
        &codex.join("archived_sessions").join("old.jsonl"),
        "{\"id\":\"session-0\"}\n",
    );
    write(
        &codex.join("history.jsonl"),
        "{\"session\":\"session-1\"}\n",
    );
    write(
        &codex.join("skills").join("audit").join("SKILL.md"),
        "---\nname: audit\ndescription: Audit code.\n---\n",
    );
    write(
        &codex.join("prompts").join("review.md"),
        "Review the diff.\n",
    );
    write(&codex.join("AGENTS.md"), "Codex repository instructions.\n");
    write(&codex.join("rules").join("style.md"), "Use tabs never.\n");
    write(
        &codex.join("models_cache.json"),
        "{\"models\":[\"gpt-5-codex\"]}",
    );
    write(
        &codex.join("plugins").join("native").join("plugin.toml"),
        "name = \"native\"\n",
    );
    write(
        &codex.join("hooks").join("pre-tool.sh"),
        "#!/bin/sh\necho codex-hook-plaintext\n",
    );
    codex
}

#[test]
fn codex_plan_covers_auth_session_bindings_targets_and_sidecars() {
    let root = TestDir::new("codex-plan");
    let target = root.join("target");
    let source = seed_codex_home(&root);
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
        .expect("plan the Codex migration");

    assert_eq!(plan.result.status, MigrationStatus::Migrated);
    assert_eq!(plan.result.exit_code, 0);
    assert_eq!(plan.operation_count(), 11);
    assert_eq!(
        diagnostic_codes(&plan),
        vec![
            "BACKUP_REQUIRED".to_owned(),
            "CODEX_HOOKS_MANUAL_REVIEW".to_owned(),
            "CODEX_PLUGINS_MANUAL_REVIEW".to_owned(),
            "CODEX_SAFE_IMPORT".to_owned(),
        ]
    );

    // A dry run reads the Codex home and writes nothing.
    assert!(!target.exists());
    assert!(!root.join("backup").exists());
    let debug = format!("{plan:?}");
    for plaintext in [
        "codex-auth-plaintext",
        "codex-config-plaintext",
        "codex-mcp-plaintext",
    ] {
        assert!(
            !debug.contains(plaintext),
            "plan debug output leaked {plaintext}"
        );
    }
}

#[test]
fn codex_apply_routes_auth_binds_sessions_and_quarantines_sidecars() {
    let root = TestDir::new("codex-apply");
    let target = root.join("target");
    let backup = root.join("backup");
    let source = seed_codex_home(&root);
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
        .expect("plan the Codex migration");

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
            .expect("apply the Codex migration")
    };

    // Targets: the signed manifest is the complete record of what was written.
    assert_eq!(
        manifest_operations(&target, "codex"),
        vec![
            (
                "text-config".to_owned(),
                "config/migrations/codex/config.toml".to_owned()
            ),
            (
                "secret-document".to_owned(),
                "config/migrations/codex/auth.json".to_owned()
            ),
            ("copy".to_owned(), "sessions/codex".to_owned()),
            (
                "copy".to_owned(),
                "reports/migration/codex/archived_sessions".to_owned()
            ),
            ("copy".to_owned(), "sessions/codex/history.jsonl".to_owned()),
            ("copy".to_owned(), "workspace/skills/audit".to_owned()),
            ("copy".to_owned(), "workspace/prompts/codex".to_owned()),
            ("append".to_owned(), "workspace/AGENTS.md".to_owned()),
            (
                "copy".to_owned(),
                "reports/migration/codex/rules".to_owned()
            ),
            (
                "copy".to_owned(),
                "reports/migration/codex/models_cache.json".to_owned()
            ),
        ]
    );

    // Auth: the credential document never lands on disk in the clear.
    assert_eq!(
        read(
            &target
                .join("config")
                .join("migrations")
                .join("codex")
                .join("auth.json")
        ),
        "{\n  \"secret_ref\": \"keyring://gta-claw/codex-auth\"\n}"
    );
    assert_eq!(secrets.plaintext("codex-auth").as_deref(), Some(AUTH));
    let config = read(
        &target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("config.toml"),
    );
    assert!(config.contains("model = \"gpt-5-codex\""));
    assert!(config.contains("approval_policy = \"on-request\""));
    assert!(config.contains("command = \"docs-server\""));
    assert!(!config.contains("codex-config-plaintext"));
    assert!(!config.contains("codex-mcp-plaintext"));
    assert!(secrets.holds("codex-config-plaintext"));
    assert!(secrets.holds("codex-mcp-plaintext"));

    // Session bindings: live rollouts stay live, archives are quarantined.
    assert_eq!(
        read(
            &target
                .join("sessions")
                .join("codex")
                .join("2026")
                .join("rollout.jsonl")
        ),
        "{\"id\":\"session-1\",\"cwd\":\"/work\"}\n"
    );
    assert_eq!(
        read(&target.join("sessions").join("codex").join("history.jsonl")),
        "{\"session\":\"session-1\"}\n"
    );
    assert_eq!(
        read(
            &target
                .join("reports")
                .join("migration")
                .join("codex")
                .join("archived_sessions")
                .join("old.jsonl")
        ),
        "{\"id\":\"session-0\"}\n"
    );

    // Sidecars: prompts, skills and instructions become active state, while
    // rules and the model cache are parked under reports for review.
    assert_eq!(
        read(
            &target
                .join("workspace")
                .join("prompts")
                .join("codex")
                .join("review.md")
        ),
        "Review the diff.\n"
    );
    assert_eq!(
        read(
            &target
                .join("workspace")
                .join("skills")
                .join("audit")
                .join("SKILL.md")
        ),
        "---\nname: audit\ndescription: Audit code.\n---\n"
    );
    let instructions = read(&target.join("workspace").join("AGENTS.md"));
    assert!(instructions.contains("Imported Codex instructions"));
    assert!(instructions.contains("Codex repository instructions."));
    assert_eq!(
        read(
            &target
                .join("reports")
                .join("migration")
                .join("codex")
                .join("rules")
                .join("style.md")
        ),
        "Use tabs never.\n"
    );

    // The same probe finds each value in the untouched Codex home, so an empty
    // result below is a real absence rather than a broken search.
    for plaintext in [
        "codex-auth-plaintext",
        "codex-access-plaintext",
        "codex-config-plaintext",
        "codex-mcp-plaintext",
    ] {
        assert!(
            !leaks(&source, plaintext).is_empty(),
            "probe for {plaintext} matches nothing in the source home"
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
        CodexMigrationProvider
            .rollback(&mut rollback, &receipt)
            .expect("roll the Codex migration back");
    }
    assert_eq!(files_under(&target), Vec::<String>::new());
    assert!(secrets.values.is_empty());
}

#[test]
fn codex_excludes_native_plugins_and_hooks_instead_of_activating_them() {
    let root = TestDir::new("codex-exclusions");
    let target = root.join("target");
    let source = seed_codex_home(&root);
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
        .expect("plan the Codex migration");

    let named = plan
        .result
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code.ends_with("_MANUAL_REVIEW"))
        .map(|diagnostic| diagnostic.message.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        named,
        vec![
            "Codex native plugins were detected but were not copied or activated.".to_owned(),
            "Codex hooks were detected but were not copied or activated.".to_owned(),
        ]
    );

    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    CodexMigrationProvider
        .apply(&mut apply, &plan)
        .expect("apply the Codex migration");

    let migrated = files_under(&target);
    for excluded in ["plugins", "hooks"] {
        assert!(
            !migrated
                .iter()
                .any(|path| path.split('/').any(|segment| segment == excluded)),
            "{excluded} reached the migration target: {migrated:?}"
        );
    }
    assert_eq!(leaks(&target, "codex-hook-plaintext"), Vec::<String>::new());
}

#[test]
fn codex_source_discovery_prefers_override_then_cli_home_then_desktop() {
    let root = TestDir::new("codex-discovery");
    let explicit = root.join("explicit-home");
    let override_home = root.join("override-home");
    let cli_home = root.join("home").join(".codex");
    let desktop = root.join("config").join("Codex");
    write(&explicit.join("config.toml"), "model = \"explicit\"\n");
    write(&override_home.join("config.toml"), "model = \"override\"\n");
    write(&cli_home.join("config.toml"), "model = \"cli\"\n");
    write(&desktop.join("config.json"), "{\"theme\":\"dark\"}");

    // An explicit source always wins, even with an override present.
    let overridden = paths(&root, HostPlatform::Linux).with_codex_home(override_home.clone());
    let detection = CodexMigrationProvider
        .detect(&overridden, Some(&explicit))
        .expect("detect an explicit source");
    assert_eq!(detection.source, explicit);
    assert_eq!(detection.confidence, DetectionConfidence::High);

    // Without one, the injected `CODEX_HOME` override wins over the CLI home.
    let detection = CodexMigrationProvider
        .detect(&overridden, None)
        .expect("detect the injected override");
    assert_eq!(detection.source, override_home);

    // Without an override, discovery falls back to the CLI home.
    let plain = paths(&root, HostPlatform::Linux);
    let detection = CodexMigrationProvider
        .detect(&plain, None)
        .expect("detect the CLI home");
    assert_eq!(detection.source, cli_home);

    // With no CLI home at all, the desktop configuration directory is used.
    let desktop_only = TestDir::new("codex-desktop-only");
    write(
        &desktop_only
            .join("config")
            .join("Codex")
            .join("config.json"),
        "{\"theme\":\"dark\",\"api_token\":\"codex-desktop-plaintext\"}",
    );
    fs::create_dir_all(desktop_only.join("home")).expect("create empty injected home");
    let desktop_paths = paths(&desktop_only, HostPlatform::Windows);
    let detection = CodexMigrationProvider
        .detect(&desktop_paths, None)
        .expect("detect the desktop configuration");
    assert!(detection.found);
    assert_eq!(detection.source, desktop_only.join("config").join("Codex"));
    assert_eq!(detection.confidence, DetectionConfidence::High);

    // Personal agent skills alone are a weaker but still real signal.
    let agents_only = TestDir::new("codex-agents-only");
    write(
        &agents_only
            .join("home")
            .join(".agents")
            .join("skills")
            .join("triage")
            .join("SKILL.md"),
        "---\nname: triage\ndescription: Triage.\n---\n",
    );
    let agent_paths = paths(&agents_only, HostPlatform::MacOs);
    let detection = CodexMigrationProvider
        .detect(&agent_paths, None)
        .expect("detect personal agent skills");
    assert!(detection.found);
    assert_eq!(detection.confidence, DetectionConfidence::Medium);

    // An empty machine yields nothing, proving discovery never leaves the
    // injected roots for a real user profile.
    let empty = TestDir::new("codex-empty");
    fs::create_dir_all(empty.join("home")).expect("create empty injected home");
    let empty_paths = paths(&empty, HostPlatform::Linux);
    let detection = CodexMigrationProvider
        .detect(&empty_paths, None)
        .expect("detect against an empty machine");
    assert!(!detection.found);
    assert!(detection.source.starts_with(empty.path()));
}

#[test]
fn codex_refuses_to_overwrite_an_existing_target() {
    let root = TestDir::new("codex-target-conflict");
    let target = root.join("target");
    let source = seed_codex_home(&root);
    let occupied = target
        .join("config")
        .join("migrations")
        .join("codex")
        .join("config.toml");
    write(&occupied, "model = \"already-migrated\"\n");
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
        .expect("an occupied target produces a rejected plan, not an error");
    assert_eq!(plan.result.status, MigrationStatus::Failed);
    assert_eq!(plan.result.exit_code, 1);
    assert_eq!(plan.result.diagnostics.len(), 1);
    assert_eq!(plan.result.diagnostics[0].code, "TARGET_EXISTS");
    assert_eq!(read(&occupied), "model = \"already-migrated\"\n");

    let mut secrets = MemorySecretStore::default();
    let mut apply = ApplyContext {
        target_root: &target,
        backup_root: &root.join("backup"),
        overwrite: false,
        secret_store: &mut secrets,
    };
    let error = CodexMigrationProvider
        .apply(&mut apply, &plan)
        .expect_err("a rejected plan can never be applied");
    assert_eq!(
        error.to_string(),
        "only a validated migrated plan may be applied"
    );
    assert_eq!(read(&occupied), "model = \"already-migrated\"\n");
    assert!(secrets.values.is_empty());
}

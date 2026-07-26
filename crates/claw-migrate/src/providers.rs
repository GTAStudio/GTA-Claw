use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::contract::{Diagnostic, DiagnosticSeverity};
use crate::engine::{
    Detection, DetectionConfidence, MigrationError, MigrationOperation, MigrationPlan,
    MigrationProvider, PlanContext, reject_executable_tree, rejected_plan, successful_plan,
};
use crate::platform::{HostPlatform, PlatformPaths};

/// Claude Desktop and Claude Code migration provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClaudeMigrationProvider;

/// OpenAI Codex desktop and CLI migration provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct CodexMigrationProvider;

/// Hermes agent migration provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct HermesMigrationProvider;

impl MigrationProvider for ClaudeMigrationProvider {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn detect(
        &self,
        paths: &dyn PlatformPaths,
        source: Option<&Path>,
    ) -> Result<Detection, MigrationError> {
        let root = source
            .map(Path::to_path_buf)
            .unwrap_or_else(|| paths.home_dir().join(".claude"));
        let primary = [
            root.join("settings.json"),
            root.join("CLAUDE.md"),
            root.join(".mcp.json"),
            root.join(".claude").join("settings.json"),
            root.join(".claude").join("CLAUDE.md"),
        ];
        let desktop = claude_desktop_config(paths);
        let user_json = paths.home_dir().join(".claude.json");
        let high =
            primary.iter().any(|path| path.is_file()) || desktop.is_file() || user_json.is_file();
        let medium = root.join("skills").is_dir()
            || root.join("commands").is_dir()
            || root.join("projects").is_dir()
            || root.join(".claude").join("skills").is_dir()
            || root.join(".claude").join("commands").is_dir()
            || root.join(".claude").join("rules").is_dir()
            || root.join(".claude").join("agents").is_dir();
        let found = high || medium;
        Ok(Detection {
            found,
            source: if root.exists() {
                root
            } else if user_json.is_file() {
                user_json
            } else {
                desktop
            },
            confidence: if high {
                DetectionConfidence::High
            } else if medium {
                DetectionConfidence::Medium
            } else {
                DetectionConfidence::Low
            },
            message: if found {
                "Claude state found.".to_owned()
            } else {
                "Claude state not found.".to_owned()
            },
        })
    }

    fn plan(&self, context: &PlanContext<'_>) -> Result<MigrationPlan, MigrationError> {
        let detection = self.detect(context.paths, context.source)?;
        if !detection.found {
            return Err(MigrationError::SourceNotFound {
                provider: self.id(),
                path: detection.source,
            });
        }
        let source_root = detection.source;
        let mut diagnostics = vec![diagnostic(
            "CLAUDE_SAFE_IMPORT",
            DiagnosticSeverity::Info,
            "Instructions, MCP definitions, skills, commands, and session history are imported without executing source code.",
        )];
        let operations = match build_claude_operations(context, &source_root, &mut diagnostics) {
            Ok(operations) => operations,
            Err(MigrationError::ExecutableArtifact(_)) => {
                return rejected_plan(
                    self.id(),
                    source_root,
                    context.target_root.to_path_buf(),
                    "EXECUTABLE_ARTIFACT_REQUIRES_PORT",
                    "A Claude JavaScript, TypeScript, or WASI artifact requires explicit review and was not copied.",
                );
            }
            Err(error) => return Err(error),
        };
        finalize_plan(self.id(), source_root, operations, diagnostics, context)
    }
}

impl MigrationProvider for CodexMigrationProvider {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn detect(
        &self,
        paths: &dyn PlatformPaths,
        source: Option<&Path>,
    ) -> Result<Detection, MigrationError> {
        let root = source
            .map(Path::to_path_buf)
            .or_else(|| paths.codex_home().map(Path::to_path_buf))
            .unwrap_or_else(|| paths.home_dir().join(".codex"));
        let desktop = paths.config_dir().join("Codex");
        let personal_agents = paths.home_dir().join(".agents");
        let high = root.join("config.toml").is_file()
            || root.join("auth.json").is_file()
            || desktop.join("config.json").is_file();
        let medium = root.join("sessions").is_dir()
            || root.join("skills").is_dir()
            || root.join("prompts").is_dir()
            || root.join("history.jsonl").is_file()
            || personal_agents.join("skills").is_dir();
        let found = high || medium;
        Ok(Detection {
            found,
            source: if root.exists() {
                root
            } else if desktop.join("config.json").is_file() {
                desktop
            } else {
                personal_agents
            },
            confidence: if high {
                DetectionConfidence::High
            } else if medium {
                DetectionConfidence::Medium
            } else {
                DetectionConfidence::Low
            },
            message: if found {
                "Codex state found.".to_owned()
            } else {
                "Codex state not found.".to_owned()
            },
        })
    }

    fn plan(&self, context: &PlanContext<'_>) -> Result<MigrationPlan, MigrationError> {
        let detection = self.detect(context.paths, context.source)?;
        if !detection.found {
            return Err(MigrationError::SourceNotFound {
                provider: self.id(),
                path: detection.source,
            });
        }
        let source_root = detection.source;
        let mut diagnostics = vec![diagnostic(
            "CODEX_SAFE_IMPORT",
            DiagnosticSeverity::Info,
            "Codex configuration, skills, prompts, credentials, session bindings, and sidecars are preserved without starting Codex or plugins.",
        )];
        let operations = match build_codex_operations(context, &source_root, &mut diagnostics) {
            Ok(operations) => operations,
            Err(MigrationError::ExecutableArtifact(_)) => {
                return rejected_plan(
                    self.id(),
                    source_root,
                    context.target_root.to_path_buf(),
                    "EXECUTABLE_ARTIFACT_REQUIRES_PORT",
                    "A Codex JavaScript, TypeScript, or WASI artifact requires explicit review and was not copied.",
                );
            }
            Err(error) => return Err(error),
        };
        finalize_plan(self.id(), source_root, operations, diagnostics, context)
    }
}

impl MigrationProvider for HermesMigrationProvider {
    fn id(&self) -> &'static str {
        "hermes"
    }

    fn detect(
        &self,
        paths: &dyn PlatformPaths,
        source: Option<&Path>,
    ) -> Result<Detection, MigrationError> {
        let root = source
            .map(Path::to_path_buf)
            .unwrap_or_else(|| paths.home_dir().join(".hermes"));
        let high = root.join("config.yaml").is_file()
            || root.join(".env").is_file()
            || root.join("auth.json").is_file();
        let medium = root.join("SOUL.md").is_file()
            || root.join("AGENTS.md").is_file()
            || root.join("memories").is_dir()
            || root.join("skills").is_dir()
            || root.join("sessions").is_dir()
            || root.join("plugins").is_dir()
            || root.join("logs").is_dir()
            || root.join("cron").is_dir()
            || root.join("mcp-tokens").is_dir()
            || root.join("state.db").is_file();
        let found = high || medium;
        Ok(Detection {
            found,
            source: root,
            confidence: if high {
                DetectionConfidence::High
            } else if medium {
                DetectionConfidence::Medium
            } else {
                DetectionConfidence::Low
            },
            message: if found {
                "Hermes state found.".to_owned()
            } else {
                "Hermes state not found.".to_owned()
            },
        })
    }

    fn plan(&self, context: &PlanContext<'_>) -> Result<MigrationPlan, MigrationError> {
        let detection = self.detect(context.paths, context.source)?;
        if !detection.found {
            return Err(MigrationError::SourceNotFound {
                provider: self.id(),
                path: detection.source,
            });
        }
        let source_root = detection.source;
        let mut diagnostics = vec![diagnostic(
            "HERMES_SAFE_IMPORT",
            DiagnosticSeverity::Info,
            "Hermes models, MCP config, memory, skills, credentials, and sessions are preserved while plugins remain disabled.",
        )];
        let operations = match build_hermes_operations(context, &source_root, &mut diagnostics) {
            Ok(operations) => operations,
            Err(MigrationError::ExecutableArtifact(_)) => {
                return rejected_plan(
                    self.id(),
                    source_root,
                    context.target_root.to_path_buf(),
                    "EXECUTABLE_ARTIFACT_REQUIRES_PORT",
                    "A Hermes JavaScript, TypeScript, or WASI artifact requires explicit review and was not copied.",
                );
            }
            Err(error) => return Err(error),
        };
        finalize_plan(self.id(), source_root, operations, diagnostics, context)
    }
}

fn finalize_plan(
    provider_id: &'static str,
    source_root: PathBuf,
    operations: Vec<MigrationOperation>,
    diagnostics: Vec<Diagnostic>,
    context: &PlanContext<'_>,
) -> Result<MigrationPlan, MigrationError> {
    if operations.is_empty() {
        return rejected_plan(
            provider_id,
            source_root,
            context.target_root.to_path_buf(),
            "NO_MIGRATABLE_STATE",
            "Provider state was detected, but no safe migratable items were found.",
        );
    }
    if let Some(target) = first_conflict(&operations, context.overwrite) {
        return rejected_plan(
            provider_id,
            source_root,
            context.target_root.to_path_buf(),
            "TARGET_EXISTS",
            &format!(
                "Migration target already exists: {}. Re-run with explicit overwrite after review.",
                target.display()
            ),
        );
    }
    let manifest = context
        .target_root
        .join("config")
        .join("migrations")
        .join(format!("{provider_id}.json5"));
    if manifest.exists() && !context.overwrite {
        return rejected_plan(
            provider_id,
            source_root,
            context.target_root.to_path_buf(),
            "TARGET_EXISTS",
            "The signed provider manifest already exists. Re-run with explicit overwrite after review.",
        );
    }
    successful_plan(
        provider_id,
        source_root,
        context.target_root.to_path_buf(),
        operations,
        diagnostics,
        context.signer,
    )
}

fn build_claude_operations(
    context: &PlanContext<'_>,
    root: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<MigrationOperation>, MigrationError> {
    let target = context.target_root;
    let mut operations = Vec::new();
    if root.is_file() {
        validate_json(root)?;
        let file_name = root.file_name().and_then(|name| name.to_str());
        let target_name = if file_name == Some(".claude.json") {
            "claude.json"
        } else {
            "claude-desktop.json"
        };
        operations.push(MigrationOperation::TransformJson {
            source: root.to_path_buf(),
            target: target
                .join("config")
                .join("migrations")
                .join("claude")
                .join(target_name),
            namespace: "claude-desktop".to_owned(),
        });
        return Ok(operations);
    }
    let global = root.file_name().is_some_and(|name| name == ".claude");
    if global {
        add_append(
            &mut operations,
            &root.join("CLAUDE.md"),
            &target.join("workspace").join("USER.md"),
            "Imported Claude user instructions",
        );
        for (name, file) in [
            ("settings.json", root.join("settings.json")),
            ("settings.local.json", root.join("settings.local.json")),
        ] {
            add_json_transform(
                &mut operations,
                &file,
                &target
                    .join("config")
                    .join("migrations")
                    .join("claude")
                    .join(name),
                &format!("claude-{name}"),
            )?;
            add_claude_manual_diagnostic(&file, diagnostics)?;
        }
        if let Some(home) = root.parent() {
            add_json_transform(
                &mut operations,
                &home.join(".claude.json"),
                &target
                    .join("config")
                    .join("migrations")
                    .join("claude")
                    .join("claude.json"),
                "claude-user",
            )?;
        }
        let desktop = claude_desktop_config(context.paths);
        add_json_transform(
            &mut operations,
            &desktop,
            &target
                .join("config")
                .join("migrations")
                .join("claude")
                .join("desktop.json"),
            "claude-desktop",
        )?;
        collect_skill_directories(
            &root.join("skills"),
            &target.join("workspace").join("skills"),
            &mut operations,
        )?;
        collect_commands(
            &root.join("commands"),
            &target.join("workspace").join("skills"),
            &mut operations,
        )?;
        add_copy_checked(
            &mut operations,
            &root.join("projects"),
            &target.join("sessions").join("claude"),
        )?;
        for name in ["cache", "plans", "agents"] {
            add_copy_checked(
                &mut operations,
                &root.join(name),
                &target
                    .join("reports")
                    .join("migration")
                    .join("claude")
                    .join(name),
            )?;
        }
    } else {
        add_append(
            &mut operations,
            &root.join("CLAUDE.md"),
            &target.join("workspace").join("AGENTS.md"),
            "Imported Claude project instructions",
        );
        add_append(
            &mut operations,
            &root.join(".claude").join("CLAUDE.md"),
            &target.join("workspace").join("AGENTS.md"),
            "Imported .claude project instructions",
        );
        add_json_transform(
            &mut operations,
            &root.join(".mcp.json"),
            &target
                .join("config")
                .join("migrations")
                .join("claude")
                .join("project-mcp.json"),
            "claude-project-mcp",
        )?;
        for name in ["settings.json", "settings.local.json"] {
            let file = root.join(".claude").join(name);
            add_json_transform(
                &mut operations,
                &file,
                &target
                    .join("config")
                    .join("migrations")
                    .join("claude")
                    .join(format!("project-{name}")),
                &format!("claude-project-{name}"),
            )?;
            add_claude_manual_diagnostic(&file, diagnostics)?;
        }
        collect_skill_directories(
            &root.join(".claude").join("skills"),
            &target.join("workspace").join("skills"),
            &mut operations,
        )?;
        collect_commands(
            &root.join(".claude").join("commands"),
            &target.join("workspace").join("skills"),
            &mut operations,
        )?;
        for (source, name) in [
            (root.join("CLAUDE.local.md"), "CLAUDE.local.md"),
            (root.join(".claude").join("rules"), "rules"),
            (root.join(".claude").join("agents"), "agents"),
        ] {
            add_copy_checked(
                &mut operations,
                &source,
                &target
                    .join("reports")
                    .join("migration")
                    .join("claude")
                    .join(name),
            )?;
        }
    }
    Ok(operations)
}

fn build_codex_operations(
    context: &PlanContext<'_>,
    root: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<MigrationOperation>, MigrationError> {
    let target = context.target_root;
    let mut operations = Vec::new();
    add_text_transform(
        &mut operations,
        &root.join("config.toml"),
        &target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("config.toml"),
        "codex-config",
    )?;
    add_secret_document(
        &mut operations,
        &root.join("auth.json"),
        &target
            .join("config")
            .join("migrations")
            .join("codex")
            .join("auth.json"),
        "codex-auth",
    );
    add_copy_checked(
        &mut operations,
        &root.join("sessions"),
        &target.join("sessions").join("codex"),
    )?;
    add_copy_checked(
        &mut operations,
        &root.join("archived_sessions"),
        &target
            .join("reports")
            .join("migration")
            .join("codex")
            .join("archived_sessions"),
    )?;
    add_copy_checked(
        &mut operations,
        &root.join("history.jsonl"),
        &target.join("sessions").join("codex").join("history.jsonl"),
    )?;
    collect_skill_directories(
        &root.join("skills"),
        &target.join("workspace").join("skills"),
        &mut operations,
    )?;
    let personal_agents = context.paths.home_dir().join(".agents");
    if context.source.is_none() && root != personal_agents {
        collect_skill_directories(
            &personal_agents.join("skills"),
            &target.join("workspace").join("skills"),
            &mut operations,
        )?;
    }
    add_copy_checked(
        &mut operations,
        &root.join("prompts"),
        &target.join("workspace").join("prompts").join("codex"),
    )?;
    add_append(
        &mut operations,
        &root.join("AGENTS.md"),
        &target.join("workspace").join("AGENTS.md"),
        "Imported Codex instructions",
    );
    for name in ["rules", "models_cache.json"] {
        add_copy_checked(
            &mut operations,
            &root.join(name),
            &target
                .join("reports")
                .join("migration")
                .join("codex")
                .join(name),
        )?;
    }
    let platform_desktop = context.paths.config_dir().join("Codex");
    if context.source.is_some() || root == platform_desktop {
        add_json_transform(
            &mut operations,
            &root.join("config.json"),
            &target
                .join("config")
                .join("migrations")
                .join("codex")
                .join("desktop.json"),
            "codex-desktop",
        )?;
    }
    if context.source.is_none() && root != platform_desktop {
        add_json_transform(
            &mut operations,
            &platform_desktop.join("config.json"),
            &target
                .join("config")
                .join("migrations")
                .join("codex")
                .join("desktop.json"),
            "codex-desktop",
        )?;
    }
    if root.join("plugins").exists() {
        diagnostics.push(diagnostic(
            "CODEX_PLUGINS_MANUAL_REVIEW",
            DiagnosticSeverity::Warning,
            "Codex native plugins were detected but were not copied or activated.",
        ));
    }
    if root.join("hooks").exists() {
        diagnostics.push(diagnostic(
            "CODEX_HOOKS_MANUAL_REVIEW",
            DiagnosticSeverity::Warning,
            "Codex hooks were detected but were not copied or activated.",
        ));
    }
    Ok(operations)
}

fn build_hermes_operations(
    context: &PlanContext<'_>,
    root: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Vec<MigrationOperation>, MigrationError> {
    let target = context.target_root;
    let mut operations = Vec::new();
    add_text_transform(
        &mut operations,
        &root.join("config.yaml"),
        &target
            .join("config")
            .join("migrations")
            .join("hermes")
            .join("config.yaml"),
        "hermes-config",
    )?;
    if root.join(".env").is_file() {
        validate_text(&root.join(".env"))?;
        operations.push(MigrationOperation::ImportEnvironment {
            source: root.join(".env"),
            target: target
                .join("config")
                .join("migrations")
                .join("hermes")
                .join("env.json"),
            namespace: "hermes-env".to_owned(),
        });
    }
    add_secret_document(
        &mut operations,
        &root.join("auth.json"),
        &target
            .join("config")
            .join("migrations")
            .join("hermes")
            .join("auth.json"),
        "hermes-auth",
    );
    if context.source.is_none() {
        add_secret_document(
            &mut operations,
            &context.paths.data_dir().join("opencode").join("auth.json"),
            &target
                .join("config")
                .join("migrations")
                .join("hermes")
                .join("opencode-auth.json"),
            "hermes-opencode-auth",
        );
    }
    add_copy_checked(
        &mut operations,
        &root.join("SOUL.md"),
        &target.join("workspace").join("SOUL.md"),
    )?;
    add_copy_checked(
        &mut operations,
        &root.join("AGENTS.md"),
        &target.join("workspace").join("AGENTS.md"),
    )?;
    add_append(
        &mut operations,
        &root.join("memories").join("MEMORY.md"),
        &target.join("workspace").join("MEMORY.md"),
        "Imported Hermes memory",
    );
    add_append(
        &mut operations,
        &root.join("memories").join("USER.md"),
        &target.join("workspace").join("USER.md"),
        "Imported Hermes user memory",
    );
    collect_skill_directories(
        &root.join("skills"),
        &target.join("workspace").join("skills"),
        &mut operations,
    )?;
    add_copy_checked(
        &mut operations,
        &root.join("sessions"),
        &target
            .join("reports")
            .join("migration")
            .join("hermes")
            .join("sessions"),
    )?;
    for name in ["logs", "cron", "state.db"] {
        add_copy_checked(
            &mut operations,
            &root.join(name),
            &target
                .join("reports")
                .join("migration")
                .join("hermes")
                .join(name),
        )?;
    }
    for (name, code, message) in [
        (
            "plugins",
            "HERMES_PLUGINS_MANUAL_REVIEW",
            "Hermes plugins were detected but were not copied or activated.",
        ),
        (
            "mcp-tokens",
            "HERMES_MCP_TOKENS_MANUAL_REAUTH",
            "Opaque Hermes MCP token state requires manual reauthentication and was not copied.",
        ),
    ] {
        if root.join(name).exists() {
            diagnostics.push(diagnostic(code, DiagnosticSeverity::Warning, message));
        }
    }
    Ok(operations)
}

fn claude_desktop_config(paths: &dyn PlatformPaths) -> PathBuf {
    let application = match paths.platform() {
        HostPlatform::Windows | HostPlatform::MacOs => "Claude",
        HostPlatform::Linux => "Claude",
    };
    paths
        .config_dir()
        .join(application)
        .join("claude_desktop_config.json")
}

fn add_claude_manual_diagnostic(
    path: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), MigrationError> {
    if !path.is_file() {
        return Ok(());
    }
    let text = read_text(path)?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| MigrationError::InvalidInput {
            path: path.to_path_buf(),
            reason: "JSON configuration is malformed".to_owned(),
        })?;
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    for (key, code, message) in [
        (
            "hooks",
            "CLAUDE_HOOKS_MANUAL_REVIEW",
            "Claude hooks were preserved in redacted configuration but are never executed.",
        ),
        (
            "permissions",
            "CLAUDE_PERMISSIONS_MANUAL_REVIEW",
            "Claude permission allowlists were preserved for review but are not trusted.",
        ),
        (
            "env",
            "CLAUDE_ENV_EXTERNALIZED",
            "Claude environment values are routed to the secret store during apply.",
        ),
    ] {
        if object.contains_key(key) {
            diagnostics.push(diagnostic(code, DiagnosticSeverity::Warning, message));
        }
    }
    Ok(())
}

fn add_copy_checked(
    operations: &mut Vec<MigrationOperation>,
    source: &Path,
    target: &Path,
) -> Result<(), MigrationError> {
    if !source.exists() {
        return Ok(());
    }
    reject_executable_tree(source)?;
    operations.push(MigrationOperation::CopyPath {
        source: source.to_path_buf(),
        target: target.to_path_buf(),
    });
    Ok(())
}

fn add_append(
    operations: &mut Vec<MigrationOperation>,
    source: &Path,
    target: &Path,
    heading: &str,
) {
    if source.is_file() {
        operations.push(MigrationOperation::AppendFile {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            heading: heading.to_owned(),
        });
    }
}

fn add_json_transform(
    operations: &mut Vec<MigrationOperation>,
    source: &Path,
    target: &Path,
    namespace: &str,
) -> Result<(), MigrationError> {
    if source.is_file() {
        validate_json(source)?;
        operations.push(MigrationOperation::TransformJson {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            namespace: namespace.to_owned(),
        });
    }
    Ok(())
}

fn add_text_transform(
    operations: &mut Vec<MigrationOperation>,
    source: &Path,
    target: &Path,
    namespace: &str,
) -> Result<(), MigrationError> {
    if source.is_file() {
        validate_text(source)?;
        operations.push(MigrationOperation::TransformText {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            namespace: namespace.to_owned(),
        });
    }
    Ok(())
}

fn add_secret_document(
    operations: &mut Vec<MigrationOperation>,
    source: &Path,
    target: &Path,
    id: &str,
) {
    if source.is_file() {
        operations.push(MigrationOperation::StoreDocument {
            source: source.to_path_buf(),
            target: target.to_path_buf(),
            secret_id: id.to_owned(),
        });
    }
}

fn collect_skill_directories(
    source_root: &Path,
    target_root: &Path,
    operations: &mut Vec<MigrationOperation>,
) -> Result<(), MigrationError> {
    if !source_root.is_dir() {
        return Ok(());
    }
    for entry in sorted_entries(source_root)? {
        if !entry.path().is_dir() || !entry.path().join("SKILL.md").is_file() {
            continue;
        }
        let Some(name) = sanitize_name(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        add_copy_checked(operations, &entry.path(), &target_root.join(name))?;
    }
    Ok(())
}

fn collect_commands(
    source_root: &Path,
    target_root: &Path,
    operations: &mut Vec<MigrationOperation>,
) -> Result<(), MigrationError> {
    if !source_root.is_dir() {
        return Ok(());
    }
    collect_commands_recursive(source_root, source_root, target_root, operations)
}

fn collect_commands_recursive(
    root: &Path,
    current: &Path,
    target_root: &Path,
    operations: &mut Vec<MigrationOperation>,
) -> Result<(), MigrationError> {
    for entry in sorted_entries(current)? {
        let path = entry.path();
        if path.is_dir() {
            collect_commands_recursive(root, &path, target_root, operations)?;
        } else if path.extension().is_some_and(|extension| extension == "md") {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| MigrationError::UnsafeTarget(path.clone()))?;
            let raw = relative
                .with_extension("")
                .to_string_lossy()
                .replace(['\\', '/'], "-");
            if let Some(name) = sanitize_name(&format!("claude-command-{raw}")) {
                operations.push(MigrationOperation::GeneratedCommandSkill {
                    source: path,
                    target: target_root.join(&name),
                    name,
                });
            }
        }
    }
    Ok(())
}

fn first_conflict(operations: &[MigrationOperation], overwrite: bool) -> Option<&Path> {
    if overwrite {
        return None;
    }
    let mut targets = BTreeSet::new();
    for operation in operations {
        if !targets.insert(operation.target().to_path_buf())
            && !matches!(operation, MigrationOperation::AppendFile { .. })
        {
            return Some(operation.target());
        }
        if operation.target().exists()
            && !matches!(operation, MigrationOperation::AppendFile { .. })
        {
            return Some(operation.target());
        }
    }
    None
}

fn validate_json(path: &Path) -> Result<(), MigrationError> {
    let text = read_text(path)?;
    serde_json::from_str::<serde_json::Value>(&text)
        .map(|_| ())
        .map_err(|_| MigrationError::InvalidInput {
            path: path.to_path_buf(),
            reason: "JSON configuration is malformed".to_owned(),
        })
}

fn validate_text(path: &Path) -> Result<(), MigrationError> {
    read_text(path).map(|_| ())
}

fn read_text(path: &Path) -> Result<String, MigrationError> {
    fs::read_to_string(path).map_err(|source| MigrationError::Io {
        action: "read UTF-8 source",
        path: path.to_path_buf(),
        source,
    })
}

fn sorted_entries(path: &Path) -> Result<Vec<fs::DirEntry>, MigrationError> {
    let mut entries = fs::read_dir(path)
        .map_err(|source| MigrationError::Io {
            action: "read source directory",
            path: path.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| MigrationError::Io {
            action: "read source directory entry",
            path: path.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn sanitize_name(value: &str) -> Option<String> {
    let mut sanitized = String::new();
    let mut previous_dash = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash && !sanitized.is_empty() {
            sanitized.push('-');
            previous_dash = true;
        }
    }
    while sanitized.ends_with('-') {
        sanitized.pop();
    }
    (!sanitized.is_empty()).then_some(sanitized)
}

fn diagnostic(code: &str, severity: DiagnosticSeverity, message: &str) -> Diagnostic {
    Diagnostic {
        code: code.to_owned(),
        severity,
        message: message.to_owned(),
    }
}

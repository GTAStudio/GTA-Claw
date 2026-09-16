//! Local source inspection and model-only candidate tasks; never live model selection.

use std::path::{Path, PathBuf};

use claw_platform::configuration::{
    ConfigurationFileError, PreparedProviderConfiguration, ProviderConfiguration, ProviderEdit,
    inspect_provider, prepare_provider,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::task::JoinHandle;

/// Maximum UTF-8 bytes accepted by the local configuration command.
pub const MAX_COMMAND_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Inspect {
        source: PathBuf,
    },
    Prepare {
        source: PathBuf,
        destination: PathBuf,
        model: String,
    },
}

#[derive(Debug)]
enum Outcome {
    Inspected(PathBuf, Box<ProviderConfiguration>),
    Prepared(Box<PreparedProviderConfiguration>),
}

/// One locally owned file task and its latest content-free result.
#[derive(Debug, Default)]
pub struct LocalConfiguration {
    inspected: Option<(PathBuf, ProviderConfiguration)>,
    task: Option<JoinHandle<Result<Outcome, ConfigurationFileError>>>,
    notice: String,
}

fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|path| path.len() <= 4096 && !path.chars().any(char::is_control))
}

fn parse(encoded: &str) -> Result<Command, &'static str> {
    if encoded.len() > MAX_COMMAND_BYTES {
        return Err("Local configuration command exceeds 16 KiB");
    }
    let command: Command = serde_json::from_str(encoded)
        .map_err(|_| "Local configuration requires one closed JSON inspect or prepare object")?;
    let valid = match &command {
        Command::Inspect { source } => valid_path(source),
        Command::Prepare {
            source,
            destination,
            model,
        } => {
            valid_path(source)
                && valid_path(destination)
                && source != destination
                && !model.is_empty()
                && model.len() <= 256
                && !model
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        }
    };
    if !valid {
        return Err("Local configuration paths or exact model ID are invalid");
    }
    Ok(command)
}

impl LocalConfiguration {
    /// Whether a file operation is still executing; reconnect never resets this state.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.task.is_some()
    }

    /// Starts one bounded local operation from a command and an already validated catalogue page.
    ///
    /// # Errors
    /// Rejects uninspected sources, stale/missing model pages, changed provider selection,
    /// ambiguous input or another in-flight file task. No network request is performed.
    pub fn begin(&mut self, encoded: &str, catalogue: Option<&Value>) -> Result<(), &'static str> {
        if self.is_pending() {
            return Err("Local configuration work is already in progress");
        }
        let command = parse(encoded)?;
        let expected = if let Command::Prepare { source, model, .. } = &command {
            let (_, configuration) = self
                .inspected
                .as_ref()
                .filter(|(path, _)| path == source)
                .ok_or("Inspect the explicit source file before preparing a candidate")?;
            let page = catalogue
                .filter(|page| page["available"] == true)
                .ok_or("Read the current model catalogue before preparing a candidate")?;
            let provider = configuration
                .snapshot
                .core()
                .provider()
                .filter(|provider| provider.model().is_some())
                .ok_or("The local configuration has no explicit active provider")?;
            if provider.catalogue_provider_id() != page["provider"].as_str()
                || provider.model() != page["selectedModel"].as_str()
            {
                return Err("Local provider and current model do not match the observed catalogue");
            }
            if !page["models"].as_array().is_some_and(|models| {
                models
                    .iter()
                    .any(|entry| entry["id"].as_str() == Some(model.as_str()))
            }) {
                return Err("Choose an exact model ID from the current catalogue page");
            }
            if provider.model() == Some(model.as_str()) {
                return Err("The selected model is already configured");
            }
            configuration.source_sha256.clone()
        } else {
            String::new()
        };
        "Local configuration pending; no live configuration applied".clone_into(&mut self.notice);
        self.task = Some(tokio::task::spawn_blocking(move || match command {
            Command::Inspect { source } => inspect_provider(&source)
                .map(|configuration| Outcome::Inspected(source, Box::new(configuration))),
            Command::Prepare {
                source,
                destination,
                model,
            } => prepare_provider(
                &source,
                &destination,
                &expected,
                ProviderEdit::ExactModel(&model),
            )
            .map(Box::new)
            .map(Outcome::Prepared),
        }));
        Ok(())
    }

    /// Waits for the current local operation without detaching it on select cancellation.
    ///
    /// An absent task waits indefinitely so callers can use this directly in a select loop.
    /// Normal shutdown should call this only when [`Self::is_pending`] is true.
    pub async fn receive(&mut self) {
        let result = match self.task.as_mut() {
            Some(task) => task.await,
            None => std::future::pending().await,
        };
        self.task.take();
        match result {
            Ok(Ok(Outcome::Inspected(path, configuration))) => {
                self.inspected = Some((path, *configuration));
                "Local source verified; source unchanged".clone_into(&mut self.notice);
            }
            Ok(Ok(Outcome::Prepared(candidate))) => {
                let model = candidate
                    .snapshot
                    .core()
                    .provider()
                    .and_then(|provider| provider.model())
                    .unwrap_or("unknown");
                self.notice = format!(
                    "Candidate created and read back\nModel: {model}\nCandidate SHA256: {}\nSource unchanged; not applied\nRestart required after explicit application\nGateway file association and live readiness: unverified",
                    candidate.candidate_sha256
                );
            }
            Ok(Err(error)) => {
                self.notice = format!(
                    "{}{}",
                    error.message,
                    if error.output_may_exist {
                        "; preserve any candidate file"
                    } else {
                        "; no candidate confirmed"
                    }
                );
            }
            Err(_) => {
                "Local result is unknown; preserve any candidate file and inspect again"
                    .clone_into(&mut self.notice);
                self.inspected = None;
            }
        }
    }

    /// Bounded metadata suitable for the Models view, without credential references.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        if self.notice.is_empty() {
            return Vec::new();
        }
        let mut lines = self.notice.lines().map(str::to_owned).collect::<Vec<_>>();
        if let Some((_, configuration)) = &self.inspected {
            lines.push(format!("Source SHA256: {}", configuration.source_sha256));
            if let Some(provider) = configuration.snapshot.core().provider() {
                lines.push(format!("Saved provider: {:?}", provider.kind()));
                lines.push(format!(
                    "Saved model: {}",
                    provider.model().unwrap_or("disabled")
                ));
            } else {
                lines.push("Saved provider: implicit/default".to_owned());
            }
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn interrupted_local_result_wait_keeps_the_started_task_for_shutdown() {
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let mut local = LocalConfiguration {
            task: Some(tokio::task::spawn_blocking(move || {
                entered.send(()).expect("task entered");
                held.recv().expect("explicit task release");
                Err(ConfigurationFileError {
                    message: "synthetic completed local operation",
                    output_may_exist: true,
                })
            })),
            ..LocalConfiguration::default()
        };
        started.await.expect("started local task");
        tokio::select! {
            biased;
            () = local.receive() => panic!("held operation cannot complete"),
            () = tokio::task::yield_now() => {},
        }
        assert!(
            local.is_pending(),
            "select cancellation must retain the task handle"
        );
        release.send(()).expect("release held operation");
        tokio::time::timeout(std::time::Duration::from_secs(3), local.receive())
            .await
            .expect("shutdown can finish the same task");
        assert!(!local.is_pending());
        assert!(
            local
                .lines()
                .join("\n")
                .contains("preserve any candidate file")
        );
    }

    #[test]
    fn local_commands_are_closed_bounded_and_keep_paths_as_data() {
        let path = std::env::temp_dir().join("config with spaces.json5");
        assert!(parse(&json!({"action":"inspect","source":path}).to_string()).is_ok());
        assert!(parse(&json!({"action":"prepare","source":path,"destination":path.with_file_name("candidate.json5"),"model":"provider/model:exact"}).to_string()).is_ok());
        for invalid in [
            json!({"action":"apply","source":path}).to_string(),
            json!({"action":"inspect","source":path,"extra":"private-content"}).to_string(),
            json!({"action":"prepare","source":path,"destination":path,"model":"exact"})
                .to_string(),
            json!({"action":"inspect","source":"relative.json5"}).to_string(),
            r#"{"action":"inspect","action":"prepare","source":"duplicate"}"#.to_owned(),
            " ".repeat(MAX_COMMAND_BYTES + 1),
        ] {
            assert!(parse(&invalid).is_err());
        }
    }

    #[tokio::test]
    async fn local_model_candidates_pin_source_and_catalogue_without_modifying_originals() {
        struct OwnedRoot(PathBuf);
        impl Drop for OwnedRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = OwnedRoot(
            std::env::temp_dir().join(format!(
                "claw-tui-config-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )),
        );
        std::fs::create_dir(&root.0).expect("owned directory");
        let source = root.0.join("source with spaces.json5");
        let destination = root.0.join("candidate.json5");
        let original=json!({"schema_version":1,"core":{"role":{"source_url":"http://127.0.0.1:9/role"},"channels":{"teams":{"enabled":false}},
            "auth":{},"server":{},"logging":{},"sessions":{},"copilot":{},"legacy":{},"updates":{},"admin":{},"network":{},
            "provider":{"kind":"openai","model":"before","api_key":"env:TUI_PRIVATE_REFERENCE"}}}).to_string();
        std::fs::write(&source, &original).expect("source");
        let inspect = json!({"action":"inspect","source":source}).to_string();
        let prepare =
            json!({"action":"prepare","source":source,"destination":destination,"model":"after"})
                .to_string();
        let page = json!({"available":true,"provider":"openai","selectedModel":"before","models":[{"id":"before"},{"id":"after"}]});
        let mut local = LocalConfiguration::default();
        assert!(local.begin(&prepare, Some(&page)).is_err());
        local
            .begin(&inspect, None)
            .expect("inspect without gateway");
        assert!(local.is_pending());
        assert!(local.begin(&inspect, None).is_err());
        local.receive().await;
        assert!(!local.is_pending());
        assert!(!local.lines().join("\n").contains("TUI_PRIVATE_REFERENCE"));
        assert!(local.begin(&prepare, None).is_err());
        let mut stale = page.clone();
        stale["provider"] = json!("anthropic");
        assert!(local.begin(&prepare, Some(&stale)).is_err());
        stale = page.clone();
        stale["models"] = json!([{"id":"other"}]);
        assert!(local.begin(&prepare, Some(&stale)).is_err());
        local.begin(&prepare, Some(&page)).expect("owned candidate");
        local.receive().await;
        let candidate = inspect_provider(&destination).expect("new valid candidate");
        assert_eq!(
            candidate
                .snapshot
                .core()
                .provider()
                .expect("provider")
                .model(),
            Some("after")
        );
        assert_eq!(
            std::fs::read_to_string(&source).expect("source unchanged"),
            original
        );
        assert!(local.lines().join("\n").contains("not applied"));
        local
            .begin(&prepare, Some(&page))
            .expect("explicit retry of file action");
        local.receive().await;
        assert!(local.lines().join("\n").contains("preserve any candidate"));
        assert_eq!(
            inspect_provider(&destination)
                .expect("unchanged output")
                .source_sha256,
            candidate.source_sha256
        );
        std::fs::write(&source, original.replace("before", "external"))
            .expect("external source edit");
        let drift=json!({"action":"prepare","source":source,"destination":root.0.join("drift.json5"),"model":"after"}).to_string();
        local
            .begin(&drift, Some(&page))
            .expect("reviewed old snapshot");
        local.receive().await;
        assert!(local.lines().join("\n").contains("SHA256 changed"));
        assert!(!root.0.join("drift.json5").exists());
    }
}

//! Compatibility checks for the pre-Gateway CLI foundation.

use std::io::Write as _;
#[cfg(unix)]
use std::io::{BufRead as _, Read as _};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
struct OAuthCoordinationRoot(std::path::PathBuf);

#[cfg(windows)]
impl OAuthCoordinationRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "claw-cli-oauth-coordination-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&root).expect("owned CLI coordination directory");
        Self(root)
    }
}

#[cfg(windows)]
impl Drop for OAuthCoordinationRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn provider_config_cli_prepares_verified_new_files_without_network_secrets_or_source_changes() {
    use serde_json::{Value, json};
    use std::fmt::Write as _;
    struct OwnedRoot(std::path::PathBuf);
    impl Drop for OwnedRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = OwnedRoot(std::env::temp_dir().join(format!(
            "gta-claw-config-cli-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
    std::fs::create_dir(&root.0).expect("owned candidate directory");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no-network witness");
    listener.set_nonblocking(true).expect("nonblocking");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let initial = claw_config::ConfigLayers::new().with_workspace_json5(json!({"core":{
        "role":{"source_url":format!("{origin}/role")},"channels":{"teams":{"enabled":false}},
        "provider":{"kind":"openai","model":"initial-model","api_key":"env:UNRESOLVED_CONFIG_TEST_KEY","base_url":format!("{origin}/v1/")}
    }}).to_string()).resolve().expect("initial typed config").config;
    let source = root.0.join("source.json5");
    let original = claw_config::to_json5(&initial).expect("initial encoding");
    std::fs::write(&source, &original).expect("source file");
    let run = |action: &str,
               destination: Option<&std::path::Path>,
               digest: Option<&str>,
               model: Option<&str>,
               input: &[u8]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
        command.env_clear();
        for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .args(["config", "provider", action, "--source"])
            .arg(&source)
            .arg("--json")
            .env(
                "GTA_CLAW_PROVIDER_POLICY",
                "invalid-runtime-policy-must-not-be-applied",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(destination) = destination {
            command
                .arg("--destination")
                .arg(destination)
                .args(["--expected-sha256", digest.expect("explicit digest")]);
            if let Some(model) = model {
                command.args(["--model", model]);
            } else {
                command.arg("--selection-stdin");
            }
        }
        let mut child = command.spawn().expect("config CLI");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("selection input");
        let output = child.wait_with_output().expect("config CLI finished");
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).expect("receipt UTF8");
        assert!(
            !text.contains("private-fixture-token") && !text.contains("UNRESOLVED_CONFIG_TEST_KEY")
        );
        (
            output.status.success(),
            serde_json::from_str::<Value>(&text).expect("JSON receipt"),
        )
    };
    let (success, inspection) = run("inspect", None, None, None, &[]);
    assert!(success, "{inspection}");
    assert_eq!(inspection["selection"]["model"], "initial-model");
    assert_eq!(inspection["environmentApplied"], false);
    assert_eq!(inspection["credentialsResolved"], false);
    let digest = inspection["sourceSha256"].as_str().expect("source SHA");
    for scenario in [
        "valid",
        "disabled",
        "changed-source",
        "duplicate",
        "literal",
        "unknown",
        "existing",
        "invalid-endpoint",
        "missing-github",
        "exact-model",
    ] {
        let destination = root.0.join(format!("{scenario}.json5"));
        if scenario == "existing" {
            std::fs::write(&destination, b"keep-existing-config").expect("existing target");
        }
        let selection = match scenario {
            "disabled" => r#"{"kind":"disabled"}"#.to_owned(),
            "duplicate" => r#"{"kind":"openai","kind":"disabled"}"#.to_owned(),
            "literal" => r#"{"kind":"openai","model":"model","api_key":"private-fixture-token"}"#.to_owned(),
            "unknown" => r#"{"kind":"disabled","extra":"private-fixture-token"}"#.to_owned(),
            "invalid-endpoint" => r#"{"kind":"openai","model":"model","api_key":"env:KEY","base_url":"https://user:private-fixture-token@example.test"}"#.to_owned(),
            "missing-github" => r#"{"kind":"copilot","model":"model"}"#.to_owned(),
            _ => json!({"kind":"anthropic","model":"candidate-model","api_key":"env:UNRESOLVED_CONFIG_TEST_KEY","base_url":origin,"credential_origin":origin,"request_timeout_ms":5000}).to_string(),
        };
        let bad_digest = "0".repeat(64);
        let (success, receipt) = run(
            "prepare",
            Some(&destination),
            Some(if scenario == "changed-source" {
                &bad_digest
            } else {
                digest
            }),
            (scenario == "exact-model").then_some("Exact-Model:2026-09"),
            selection.as_bytes(),
        );
        assert_eq!(
            success,
            matches!(scenario, "valid" | "disabled" | "exact-model"),
            "{scenario}: {receipt}"
        );
        assert_eq!(receipt["sourceModified"], false);
        assert_eq!(receipt["credentialsResolved"], false);
        assert_eq!(receipt["networkContacted"], false);
        assert_eq!(receipt["applied"], false);
        assert_eq!(
            std::fs::read_to_string(&source).expect("source preserved"),
            original
        );
        if success {
            let candidate = std::fs::read_to_string(&destination).expect("new candidate");
            let parsed = claw_config::parse_json5(&candidate, "candidate.json5")
                .expect("full candidate validates");
            assert_eq!(
                parsed.core().provider().expect("selection").kind(),
                if scenario == "exact-model" {
                    claw_config::ProviderKind::Openai
                } else if scenario == "disabled" {
                    claw_config::ProviderKind::Disabled
                } else {
                    claw_config::ProviderKind::Anthropic
                }
            );
            if scenario == "exact-model" {
                assert_eq!(
                    parsed,
                    claw_config::with_provider_model(&initial, "Exact-Model:2026-09")
                        .expect("exact model only")
                );
                assert_eq!(receipt["modelOnly"], true);
                assert_eq!(receipt["catalogueVerified"], false);
            }
            let mut file_sha = String::with_capacity(64);
            for byte in ring::digest::digest(&ring::digest::SHA256, candidate.as_bytes()).as_ref() {
                write!(file_sha, "{byte:02x}").expect("candidate digest");
            }
            assert_eq!(receipt["candidateSha256"], file_sha);
            assert_eq!(receipt["restartRequired"], true);
        } else if scenario == "existing" {
            assert_eq!(
                std::fs::read(&destination).expect("old target preserved"),
                b"keep-existing-config"
            );
        } else {
            assert!(!destination.exists(), "invalid candidate creates no file");
        }
        assert!(
            matches!(listener.accept(),Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

#[test]
fn provider_config_cli_apply_is_reviewed_backed_up_and_never_activates_a_provider() {
    use serde_json::{Value, json};
    use std::fmt::Write as _;
    struct OwnedRoot(std::path::PathBuf);
    impl Drop for OwnedRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = OwnedRoot(std::env::temp_dir().join(format!(
            "claw-config-apply-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
    std::fs::create_dir(&root.0).expect("owned directory");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no network witness");
    listener.set_nonblocking(true).expect("nonblocking");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let initial = claw_config::ConfigLayers::new().with_workspace_json5(json!({"core":{
        "role":{"source_url":format!("{origin}/role")},"channels":{"teams":{"enabled":false}},
        "provider":{"kind":"openai","model":"first","api_key":"env:PRIVATE_APPLY_REFERENCE","base_url":format!("{origin}/v1/")}
    }}).to_string()).resolve().expect("typed initial").config;
    let original = claw_config::to_json5(&initial).expect("original");
    let candidate_config =
        claw_config::with_provider_json(&initial, r#"{"kind":"disabled"}"#).expect("candidate");
    let candidate_text = claw_config::to_json5(&candidate_config).expect("encoded candidate");
    let hash = |bytes: &[u8]| {
        let mut digest = String::with_capacity(64);
        for byte in ring::digest::digest(&ring::digest::SHA256, bytes).as_ref() {
            write!(digest, "{byte:02x}").expect("digest");
        }
        digest
    };
    for scenario in [
        "valid",
        "restore",
        "recover-corrupt",
        "recover-bad-candidate",
        "source-drift",
        "candidate-drift",
        "unrelated",
        "invalid",
        "backup-exists",
        "no-confirm",
        "no-offline",
        "same-selection",
        "source-held",
        "candidate-held",
        "source-hardlink",
        "candidate-hardlink",
        "source-readonly",
        "candidate-readonly",
        "candidate-oversize",
        "backup-parent-missing",
    ] {
        let directory = root.0.join(scenario);
        std::fs::create_dir(&directory).expect("case directory");
        let source = directory.join("source.json5");
        let candidate = directory.join("candidate.json5");
        let backup = directory.join(if scenario == "backup-parent-missing" {
            "missing/backup.json5"
        } else {
            "backup.json5"
        });
        let source_contents = if scenario.starts_with("recover-") {
            "partial-crash-residue"
        } else if scenario == "restore" {
            &candidate_text
        } else {
            &original
        };
        let mut candidate_contents = if matches!(scenario, "restore" | "same-selection")
            || scenario.starts_with("recover-")
        {
            original.clone()
        } else {
            candidate_text.clone()
        };
        if scenario == "unrelated" {
            let changed = claw_config::ConfigLayers::new().with_workspace_json5(json!({"core":{
                "role":{"source_url":format!("{origin}/role")},"channels":{"teams":{"enabled":false}},
                "provider":{"kind":"disabled"},"logging":{"level":"debug"}
            }}).to_string()).resolve().expect("unrelated change").config;
            candidate_contents =
                claw_config::to_json5(&changed).expect("encoded changed configuration");
        } else if matches!(scenario, "invalid" | "recover-bad-candidate") {
            candidate_contents = "invalid-private-config".to_owned();
        }
        if scenario == "candidate-oversize" {
            candidate_contents = " ".repeat(4 * 1024 * 1024 + 1);
        }
        std::fs::write(&source, source_contents).expect("source");
        std::fs::write(&candidate, &candidate_contents).expect("candidate");
        if scenario == "backup-exists" {
            std::fs::write(&backup, b"keep-existing").expect("old backup");
        }
        if matches!(scenario, "source-hardlink" | "candidate-hardlink") {
            std::fs::hard_link(
                if scenario == "source-hardlink" {
                    &source
                } else {
                    &candidate
                },
                directory.join("alias.json5"),
            )
            .expect("owned hard link");
        }
        let held = match scenario {
            "source-held" => Some(std::fs::File::open(&source).expect("existing reader")),
            "candidate-held" => {
                Some(std::fs::File::open(&candidate).expect("existing candidate reader"))
            }
            _ => None,
        };
        let readonly_path = match scenario {
            "source-readonly" => Some(&source),
            "candidate-readonly" => Some(&candidate),
            _ => None,
        };
        let previous_permissions = readonly_path.map(|path| {
            let previous = std::fs::metadata(path)
                .expect("owned attributes")
                .permissions();
            let mut readonly = previous.clone();
            readonly.set_readonly(true);
            std::fs::set_permissions(path, readonly).expect("owned read-only fixture");
            previous
        });
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
        command.env_clear();
        for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .args([
                "config",
                "provider",
                if scenario.starts_with("recover-") {
                    "restore"
                } else {
                    "apply"
                },
                "--source",
            ])
            .arg(&source)
            .arg("--candidate")
            .arg(&candidate)
            .arg("--backup")
            .arg(&backup)
            .args([
                "--expected-sha256",
                &if scenario == "source-drift" {
                    "0".repeat(64)
                } else {
                    hash(source_contents.as_bytes())
                },
                "--candidate-sha256",
                &if scenario == "candidate-drift" {
                    "0".repeat(64)
                } else {
                    hash(candidate_contents.as_bytes())
                },
                "--json",
            ])
            .env("GTA_CLAW_PROVIDER_POLICY", "not-applied-by-offline-command");
        if scenario != "no-confirm" {
            command.arg(if scenario.starts_with("recover-") {
                "--confirm-restore"
            } else {
                "--confirm-apply"
            });
        }
        if scenario != "no-offline" {
            command.arg("--confirm-offline");
        }
        let output = command.output().expect("actual apply command");
        drop(held);
        if let Some((path, permissions)) = readonly_path.zip(previous_permissions) {
            std::fs::set_permissions(path, permissions).expect("restore owned permissions");
        }
        let success = cfg!(windows)
            && matches!(
                scenario,
                "valid" | "restore" | "recover-corrupt" | "candidate-readonly"
            );
        let text = String::from_utf8(output.stdout).expect("UTF8 receipt");
        assert_eq!(output.status.success(), success, "{scenario}: {text}");
        assert!(output.stderr.is_empty());
        assert!(
            !text.contains("PRIVATE_APPLY_REFERENCE") && !text.contains("invalid-private-config")
        );
        if matches!(scenario, "no-confirm" | "no-offline") {
            assert!(!backup.exists());
        } else {
            let receipt: Value = serde_json::from_str(&text).expect("receipt");
            assert_eq!(receipt["applied"], false);
            assert_eq!(receipt["networkContacted"], false);
            assert_eq!(receipt["credentialsResolved"], false);
            assert_eq!(receipt["sourceModified"], success);
            if success {
                assert_eq!(receipt["backupVerified"], true);
                assert_eq!(receipt["configurationSaved"], true);
                assert_eq!(receipt["restartRequired"], true);
                assert_eq!(receipt["restartPerformed"], false);
                assert_eq!(receipt["atomicPublication"], false);
                assert_eq!(receipt["offlineConfirmed"], true);
                assert_eq!(receipt["offlineIndependentlyVerified"], false);
                assert_eq!(
                    receipt["fullSnapshotRestored"],
                    scenario == "recover-corrupt"
                );
                assert_eq!(receipt["savedSha256"], hash(candidate_contents.as_bytes()));
                assert_eq!(
                    std::fs::read(&backup).expect("verified original backup"),
                    source_contents.as_bytes()
                );
                claw_config::load_file(&source).expect("saved file remains valid");
            } else if scenario == "backup-exists" {
                assert_eq!(
                    std::fs::read(&backup).expect("old backup"),
                    b"keep-existing"
                );
            } else {
                assert!(
                    !backup.exists(),
                    "preflight cannot create a backup: {scenario}"
                );
            }
        }
        assert_eq!(
            std::fs::read(&source).expect("source preserved or saved"),
            if success {
                candidate_contents.as_bytes()
            } else {
                source_contents.as_bytes()
            }
        );
        assert_eq!(
            std::fs::read(&candidate).expect("candidate unchanged"),
            candidate_contents.as_bytes()
        );
        assert!(
            matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
        );
    }
}

#[test]
fn version_remains_a_successful_bounded_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .arg("--version")
        .output()
        .expect("CLI process starts");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 stdout"),
        format!("gta-claw-cli {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn local_health_foundation_remains_separate() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .arg("health")
        .output()
        .expect("CLI process starts");

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .expect("UTF-8 stdout")
            .starts_with("healthy runtime=")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn unknown_commands_remain_fail_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .arg("definitely-unknown")
        .output()
        .expect("CLI process starts");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
        "error: unknown command\n"
    );
}

#[test]
fn mcp_credential_reference_is_bound_and_rejects_secret_arguments_without_echoing() {
    let endpoint = "http://127.0.0.1:32109/mcp";
    let run = |endpoint: &str, extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
            .args([
                "mcp",
                "credential",
                "reference",
                "--server",
                "fixture",
                "--endpoint",
                endpoint,
                "--json",
            ])
            .args(extra)
            .output()
            .expect("real credential CLI")
    };
    let output = run(endpoint, &[]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("reference metadata");
    let binding = claw_mcp::oauth::CredentialBinding::new(
        "fixture",
        &url::Url::parse(endpoint).expect("endpoint"),
    )
    .expect("binding");
    assert_eq!(value["tokenRef"], binding.keyring_reference());
    assert_eq!(value["networkContacted"], false);
    assert_eq!(value["storeAccessed"], false);
    for (endpoint, extra) in [
        (endpoint, vec!["--token", "mcp-cli-private-token-argv"]),
        (endpoint, vec!["--token-stdin"]),
        (
            "https://mcp-cli-private-token-user@fixture.example/mcp",
            vec![],
        ),
        (
            "https://fixture.example/mcp?secret=mcp-cli-private-token-query",
            vec![],
        ),
        ("http://fixture.example/mcp", vec![]),
    ] {
        let output = run(endpoint, &extra);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).expect("UTF-8 error metadata");
        assert!(!text.contains("mcp-cli-private-token"));
        assert!(text.len() < 16 * 1024);
    }
}

#[cfg(windows)]
#[test]
fn mcp_credential_cli_native_roundtrip_is_stdin_only_and_never_connects() {
    use claw_provider_sdk::secret::{
        CredentialKey, SecretStore, SecretString, WindowsCredentialManagerStore,
    };
    use serde_json::Value;

    struct OwnedCredential {
        store: WindowsCredentialManagerStore,
        key: CredentialKey,
    }
    impl Drop for OwnedCredential {
        fn drop(&mut self) {
            let _ = self.store.delete(&self.key);
        }
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("owned no-network witness");
    listener.set_nonblocking(true).expect("nonblocking witness");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("fixture address")
    );
    let server = format!(
        "cli-fixture-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    for stdio in [false, true] {
        let sha256 = "a".repeat(64);
        let (reference, service, target_arguments) = if stdio {
            (
                claw_mcp::client::StdioClientConfig::keyring_reference(
                    &server,
                    &sha256,
                    "API_TOKEN",
                )
                .expect("stdio binding"),
                "gta-claw.mcp-stdio",
                vec![
                    "--program-sha256".to_owned(),
                    sha256,
                    "--environment-name".to_owned(),
                    "API_TOKEN".to_owned(),
                ],
            )
        } else {
            (
                claw_mcp::oauth::CredentialBinding::new(
                    &server,
                    &url::Url::parse(&endpoint).expect("endpoint"),
                )
                .expect("binding")
                .keyring_reference(),
                "gta-claw.mcp-outbound",
                vec!["--endpoint".to_owned(), endpoint.clone()],
            )
        };
        let key = CredentialKey::new(
            service,
            reference
                .strip_prefix(&format!("keyring://{service}/"))
                .expect("dedicated namespace"),
        )
        .expect("fixture key");
        let store = WindowsCredentialManagerStore::new()
            .expect("native store required for this acceptance");
        assert!(store.get(&key).expect("unique fixture preflight").is_none());
        let owned = OwnedCredential { store, key };
        let run = |action: &str, extra: &[&str], input: &[u8]| {
            let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
            command.env_clear();
            for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            let mut child = command
                .args(["mcp", "credential", action, "--server", &server, "--json"])
                .args(&target_arguments)
                .args(extra)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("owned credential CLI");
            child
                .stdin
                .take()
                .expect("owned input")
                .write_all(input)
                .expect("stdin fixture bytes");
            let output = child.wait_with_output().expect("credential CLI finished");
            assert!(output.stderr.is_empty());
            let text = String::from_utf8(output.stdout).expect("credential metadata");
            assert!(text.len() < 16 * 1024 && !text.contains("mcp-cli-private-token"));
            let metadata: Value = serde_json::from_str(&text).expect("bounded JSON");
            (output.status.success(), metadata)
        };
        let (success, metadata) = run("reference", &[], &[]);
        assert!(success);
        assert_eq!(metadata["tokenRef"], reference);
        assert_eq!(metadata["storeAccessed"], false);
        let (success, status) = run("status", &[], &[]);
        assert!(success);
        assert_eq!(status["present"], false);
        assert!(!run("set", &["--token-stdin"], &[]).0);
        assert!(!run("set", &["--token-stdin", "--confirm-write"], b"too-short\n").0);
        if stdio {
            assert!(
                !run(
                    "set",
                    &["--token-stdin", "--confirm-write"],
                    &vec![b'a'; 2049]
                )
                .0
            );
        }
        assert!(
            owned
                .store
                .get(&owned.key)
                .expect("invalid input leaves no credential")
                .is_none()
        );
        for token in [
            "mcp-cli-private-token-first",
            "mcp-cli-private-token-rotated",
        ] {
            let (success, receipt) = run(
                "set",
                &["--token-stdin", "--confirm-write"],
                format!("{token}\r\n").as_bytes(),
            );
            assert!(success, "{receipt}");
            assert_eq!(receipt["tokenRef"], reference);
            assert_eq!(receipt["verifiedReadback"], true);
            assert_eq!(receipt["atomicCompareAndSwap"], false);
            assert_eq!(receipt["networkContacted"], false);
            assert_eq!(
                owned.store.get(&owned.key).expect("native readback"),
                Some(SecretString::new(token))
            );
            let (status_ok, status) = run("status", &[], &[]);
            assert!(status_ok, "native {service} status failed: {status}");
            if status["present"] != true {
                let parent = owned.store.get(&owned.key);
                let reopened =
                    WindowsCredentialManagerStore::new().and_then(|store| store.get(&owned.key));
                panic!(
                    "native {service} status lost an independently confirmed fixture: status={status}; parent_read_ok={}, parent_present={}, reopened_read_ok={}, reopened_present={}",
                    parent.is_ok(),
                    parent.as_ref().is_ok_and(Option::is_some),
                    reopened.is_ok(),
                    reopened.as_ref().is_ok_and(Option::is_some),
                );
            }
        }
        assert!(!run("delete", &[], &[]).0);
        assert!(
            owned
                .store
                .get(&owned.key)
                .expect("unconfirmed delete refused")
                .is_some()
        );
        let (success, deleted) = run("delete", &["--confirm-delete"], &[]);
        assert!(success, "{deleted}");
        assert_eq!(deleted["removed"], true);
        assert_eq!(deleted["present"], false);
        assert_eq!(
            run("delete", &["--confirm-delete"], &[]).1["removed"],
            false
        );
        assert!(
            owned
                .store
                .get(&owned.key)
                .expect("owned fixture explicitly cleaned")
                .is_none()
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        drop(owned);
    }
}

#[cfg(windows)]
#[test]
fn mcp_oauth_cli_reports_local_states_and_only_logs_out_with_explicit_confirmation() {
    use claw_mcp::oauth::{
        CredentialBinding, NativeTokenStatus, NativeTokenStore, TokenStore as _,
    };
    use claw_provider_sdk::secret::{
        CredentialKey, SecretStore as _, SecretString, WindowsCredentialManagerStore,
    };
    use serde_json::{Value, json};

    struct OwnedOAuth {
        store: NativeTokenStore,
        binding: CredentialBinding,
    }
    impl Drop for OwnedOAuth {
        fn drop(&mut self) {
            let _ = self.store.delete(&self.binding);
        }
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("no-network witness");
    listener.set_nonblocking(true).expect("nonblocking witness");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("fixture address")
    );
    let server = format!(
        "oauth-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let binding = CredentialBinding::new(&server, &url::Url::parse(&endpoint).expect("endpoint"))
        .expect("binding");
    let store = NativeTokenStore::new().expect("native OAuth store required");
    assert_eq!(
        store.status(&binding).expect("unique fixture preflight"),
        NativeTokenStatus::Absent
    );
    let owned = OwnedOAuth { store, binding };
    let coordination = OAuthCoordinationRoot::new();
    let reference = NativeTokenStore::keyring_reference(&owned.binding);
    let account = reference.rsplit('/').next().expect("account");
    let key = CredentialKey::new("gta-claw.mcp-oauth", account).expect("owned record key");
    let backend = WindowsCredentialManagerStore::new().expect("fixture writer");
    let run = |action: &str, extra: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
        command.env_clear();
        command.env("LOCALAPPDATA", &coordination.0);
        for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let output = command
            .args([
                "mcp",
                "oauth",
                action,
                "--server",
                &server,
                "--endpoint",
                &endpoint,
                "--json",
            ])
            .args(extra)
            .stdin(Stdio::null())
            .output()
            .expect("real OAuth CLI");
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).expect("metadata stdout");
        assert!(text.len() < 16 * 1024 && !text.contains("private-oauth"));
        let value: Value = serde_json::from_str(&text).expect("bounded JSON");
        (output.status.success(), value)
    };
    let (success, metadata) = run("reference", &[]);
    assert!(success);
    assert_eq!(metadata["credentialRef"], reference);
    assert_eq!(metadata["storeAccessed"], false);
    assert_eq!(run("status", &[]).1["record"]["state"], "absent");
    assert!(!run("set", &["--token", "private-oauth-argv"]).0);
    let mut record = json!({"schema_version":1,"binding":account,"incomplete":false,
        "access_token":"private-oauth-fixture-access","refresh_token":"private-oauth-fixture-refresh","token_type":"Bearer","scope":"tools:read",
        "expires_at":null,"authority":vec![7;32]});
    for expired in [false, true] {
        record["expires_at"] = if expired {
            json!({"seconds":0,"nanoseconds":0})
        } else {
            Value::Null
        };
        backend
            .set(&key, &SecretString::new(record.to_string()))
            .expect("owned local-state fixture");
        assert_eq!(
            backend
                .get(&key)
                .expect("fixture write readback before child start"),
            Some(SecretString::new(record.to_string()))
        );
        let (success, status) = run("status", &[]);
        assert!(success);
        assert_eq!(status["credentialRef"], reference);
        assert_eq!(
            status["record"]["state"], "available",
            "OAuth status after confirmed native write; expired fixture: {expired}"
        );
        assert_eq!(status["record"]["fresh"], !expired);
        assert_eq!(status["record"]["expiryKnown"], expired);
        assert_eq!(status["record"]["refreshAvailable"], true);
        assert_eq!(status["remoteAuthenticationVerified"], false);
        assert_eq!(status["networkContacted"], false);
        assert_eq!(
            backend.get(&key).expect("record unchanged"),
            Some(SecretString::new(record.to_string()))
        );
    }
    owned
        .store
        .begin_update(&owned.binding, None)
        .expect("owned pending fixture");
    assert_eq!(
        run("status", &[]).1["record"]["state"],
        "reauthorization_required"
    );
    assert!(!run("logout", &[]).0);
    assert!(!run("logout", &["--confirm-delete"]).0);
    assert_eq!(
        owned
            .store
            .status(&owned.binding)
            .expect("pending preserved"),
        NativeTokenStatus::ReauthorizationRequired
    );
    let (success, logged_out) = run("logout", &["--confirm-logout"]);
    assert!(success);
    assert_eq!(logged_out["record"]["state"], "absent");
    assert_eq!(logged_out["remoteRevoked"], false);
    assert_eq!(logged_out["daemonNotified"], false);
    backend
        .set(
            &key,
            &SecretString::new(r#"{"invalid":"private-oauth-corrupt-record"}"#),
        )
        .expect("owned corrupt record");
    assert!(
        backend
            .get(&key)
            .expect("corrupt fixture readback")
            .is_some(),
        "corrupt native fixture disappeared before the child status check"
    );
    let (success, corrupt_status) = run("status", &[]);
    assert!(
        !success,
        "corrupt native fixture status unexpectedly succeeded: {corrupt_status}"
    );
    assert!(
        backend
            .get(&key)
            .expect("corrupt record not removed implicitly")
            .is_some()
    );
    assert!(run("logout", &["--confirm-logout"]).0);
    assert_eq!(
        owned
            .store
            .status(&owned.binding)
            .expect("explicit cleanup verified"),
        NativeTokenStatus::Absent
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[cfg(windows)]
#[test]
fn mcp_oauth_login_uses_reviewed_metadata_real_callback_and_native_pending_recovery() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use claw_mcp::oauth::{
        CredentialBinding, NativeTokenStatus, NativeTokenStore, TokenStore as _,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::io::{BufRead as _, Read as _};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    struct OwnedLogin {
        store: NativeTokenStore,
        binding: CredentialBinding,
    }
    impl Drop for OwnedLogin {
        fn drop(&mut self) {
            let _ = self.store.delete(&self.binding);
        }
    }
    struct OwnedChild(Option<std::process::Child>);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    async fn request_body(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut bytes = Vec::new();
        loop {
            assert!(bytes.len() < 16 * 1024);
            let mut buffer = [0; 1024];
            let count = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                .await
                .expect("fixture read deadline")
                .expect("fixture read");
            assert!(count > 0);
            bytes.extend_from_slice(&buffer[..count]);
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut request = httparse::Request::new(&mut headers);
            if let httparse::Status::Complete(offset) = request.parse(&bytes).expect("fixture HTTP")
            {
                let length = request
                    .headers
                    .iter()
                    .find(|header| header.name.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |header| {
                        std::str::from_utf8(header.value)
                            .expect("length")
                            .parse::<usize>()
                            .expect("numeric length")
                    });
                assert!(length <= 8192);
                if bytes.len() >= offset + length {
                    return (
                        format!(
                            "{} {}",
                            request.method.expect("method"),
                            request.path.expect("path")
                        ),
                        bytes[offset..offset + length].to_vec(),
                    );
                }
            }
        }
    }
    fn callback(url: &url::Url) {
        let address = url.socket_addrs(|| None).expect("literal callback")[0];
        let mut stream = std::net::TcpStream::connect(address).expect("owned callback connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("callback timeout");
        write!(
            stream,
            "GET {} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",
            &url[url::Position::BeforePath..]
        )
        .expect("callback request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("callback response");
        assert!(!response.contains("private-login-code"));
    }

    fn logout(server: &str, endpoint: &str, coordination: &std::path::Path) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
        command.env_clear().env("LOCALAPPDATA", coordination);
        for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let output = command
            .args([
                "mcp",
                "oauth",
                "logout",
                "--server",
                server,
                "--endpoint",
                endpoint,
                "--confirm-logout",
                "--json",
            ])
            .stdin(Stdio::null())
            .output()
            .expect("confirmed cleanup CLI");
        assert!(output.stderr.is_empty());
        let result: Value = serde_json::from_slice(&output.stdout).expect("cleanup receipt");
        assert!(output.status.success(), "{result}");
        assert_eq!(result["cooperatingCliExclusive"], true);
        assert_eq!(result["record"]["state"], "absent");
    }

    let coordination = OAuthCoordinationRoot::new();
    for mode in [
        "success",
        "denied",
        "timeout",
        "lost-token-response",
        "changed-metadata",
        "refresh-lost-response",
        "refresh-refused",
        "interrupted-before-callback",
    ] {
        let refresh_after_login = matches!(
            mode,
            "success" | "refresh-lost-response" | "refresh-refused"
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("owned issuer fixture");
        let address = listener.local_addr().expect("fixture address");
        listener
            .set_nonblocking(true)
            .expect("async fixture listener");
        let base = format!("http://{address}/");
        let metadata = json!({"issuer":base,"authorization_endpoint":format!("{base}authorize"),
            "token_endpoint":format!("{base}{}", if mode == "changed-metadata" { "unreviewed-token" } else { "token" }),
            "code_challenge_methods_supported":["S256"]}).to_string();
        let backend = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("fixture runtime").block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("owned listener");
                let mut calls = Vec::new();
                for ordinal in 0..if refresh_after_login { 4 } else if mode == "lost-token-response" { 2 } else { 1 } {
                    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(8), listener.accept()).await.expect("fixture admission deadline").expect("one reviewed request");
                    let (target, body) = request_body(&mut stream).await;
                    assert_eq!(target, if ordinal % 2 == 0 { "GET /.well-known/oauth-authorization-server" } else { "POST /token" });
                    calls.push(body);
                    if ordinal == 1 && mode == "lost-token-response" { break; }
                    if ordinal == 3 && mode == "refresh-lost-response" { break; }
                    let (status, body) = if ordinal % 2 == 0 { ("200 OK", metadata.as_str()) }
                    else if ordinal == 1 { ("200 OK", r#"{"access_token":"private-login-access","refresh_token":"private-login-refresh","token_type":"Bearer","expires_in":3600}"#) }
                    else if mode == "refresh-refused" { ("400 Bad Request", r#"{"error":"invalid_grant","error_description":"private-refresh-error"}"#) }
                    else { ("200 OK", r#"{"access_token":"private-refreshed-access","refresh_token":"private-refreshed-refresh","token_type":"Bearer","expires_in":3600}"#) };
                    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.expect("fixture response");
                }
                calls
            })
        });
        let server = format!("login-cli-{}-{}", std::process::id(), address.port());
        let endpoint = format!("{base}mcp");
        let binding =
            CredentialBinding::new(&server, &url::Url::parse(&endpoint).expect("resource"))
                .expect("binding");
        let store = NativeTokenStore::new().expect("native store required");
        assert_eq!(
            store.status(&binding).expect("owned key preflight"),
            NativeTokenStatus::Absent
        );
        let owned = OwnedLogin { store, binding };
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
        command.env_clear();
        command.env("LOCALAPPDATA", &coordination.0);
        for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = OwnedChild(Some(
            command
                .args([
                    "mcp",
                    "oauth",
                    "login",
                    "--server",
                    &server,
                    "--endpoint",
                    &endpoint,
                    "--issuer",
                    &base,
                    "--authorization-endpoint",
                    &format!("{base}authorize"),
                    "--token-endpoint",
                    &format!("{base}token"),
                    "--client-id",
                    "fixture-public-client",
                    "--scope",
                    "tools:read",
                    "--timeout-ms",
                    if mode == "timeout" { "2000" } else { "7000" },
                    "--confirm-login",
                    "--json",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("actual OAuth login CLI"),
        ));
        let mut stdout = std::io::BufReader::new(
            child
                .0
                .as_mut()
                .expect("child")
                .stdout
                .take()
                .expect("stdout"),
        );
        let mut first = String::new();
        stdout
            .read_line(&mut first)
            .expect("authorization readiness output");
        let first: Value = serde_json::from_str(&first).expect("staged JSON output");
        let mut challenge = None;
        let mut callback_address = None;
        if mode == "changed-metadata" {
            assert_eq!(first["stage"], "failed");
        } else {
            assert_eq!(first["stage"], "authorization_required");
            assert_eq!(first["automaticBrowserLaunch"], false);
            let authorization = url::Url::parse(first["authorizationUrl"].as_str().expect("URL"))
                .expect("authorization URL");
            let parameters: BTreeMap<_, _> = authorization.query_pairs().into_owned().collect();
            assert_eq!(parameters["client_id"], "fixture-public-client");
            assert_eq!(parameters["code_challenge_method"], "S256");
            assert_eq!(parameters["resource"], endpoint);
            let redirect =
                url::Url::parse(&parameters["redirect_uri"]).expect("actual callback URI");
            callback_address = Some(redirect.socket_addrs(|| None).expect("literal callback")[0]);
            challenge = Some(parameters["code_challenge"].clone());
            if mode == "success" {
                for (operation, confirm) in [
                    ("login", "--confirm-login"),
                    ("refresh", "--confirm-refresh"),
                    ("logout", "--confirm-logout"),
                ] {
                    let mut competing = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
                    competing.env_clear().env("LOCALAPPDATA", &coordination.0);
                    for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
                        if let Some(value) = std::env::var_os(name) {
                            competing.env(name, value);
                        }
                    }
                    competing.args([
                        "mcp",
                        "oauth",
                        operation,
                        "--server",
                        &server,
                        "--endpoint",
                        &endpoint,
                        confirm,
                        "--json",
                    ]);
                    if operation != "logout" {
                        competing.args([
                            "--issuer",
                            &base,
                            "--authorization-endpoint",
                            &format!("{base}authorize"),
                            "--token-endpoint",
                            &format!("{base}token"),
                            "--client-id",
                            "fixture-public-client",
                            "--timeout-ms",
                            "2000",
                        ]);
                    }
                    let output = competing
                        .stdin(Stdio::null())
                        .output()
                        .expect("competing CLI operation");
                    assert!(!output.status.success());
                    assert!(output.stderr.is_empty());
                    let result: Value =
                        serde_json::from_slice(&output.stdout).expect("busy metadata");
                    assert_eq!(result["mayHaveChanged"], false);
                    assert!(
                        result["error"]["message"]
                            .as_str()
                            .expect("busy error")
                            .contains("profile is busy")
                    );
                    assert_eq!(
                        owned
                            .store
                            .status(&owned.binding)
                            .expect("busy operations did not modify credentials"),
                        NativeTokenStatus::Absent
                    );
                }
            }
            if mode == "interrupted-before-callback" {
                child
                    .0
                    .as_mut()
                    .expect("owned login process")
                    .kill()
                    .expect("interrupt only the fixture child");
            } else if mode != "timeout" {
                let mut returned = redirect;
                returned
                    .query_pairs_mut()
                    .append_pair("state", &parameters["state"])
                    .append_pair("iss", &base);
                if mode == "denied" {
                    returned
                        .query_pairs_mut()
                        .append_pair("error", "access_denied");
                } else {
                    returned
                        .query_pairs_mut()
                        .append_pair("code", "private-login-code");
                }
                callback(&returned);
            }
        }
        let mut tail = String::new();
        stdout.read_to_string(&mut tail).expect("final CLI output");
        let output = child
            .0
            .take()
            .expect("owned process")
            .wait_with_output()
            .expect("login child finished");
        assert!(output.stderr.is_empty());
        assert!(!tail.contains("private-login") && tail.len() < 16 * 1024);
        if mode == "interrupted-before-callback" {
            assert!(!output.status.success());
            assert!(
                tail.is_empty(),
                "terminated operation has no fabricated final receipt"
            );
            assert_eq!(backend.join().expect("owned fixture completed").len(), 1);
            assert_eq!(
                owned
                    .store
                    .status(&owned.binding)
                    .expect("no token request occurred"),
                NativeTokenStatus::Absent
            );
            assert!(
                std::net::TcpStream::connect(callback_address.expect("callback listener")).is_err()
            );
            logout(&server, &endpoint, &coordination.0);
            continue;
        }
        let completed: Value = if mode == "changed-metadata" {
            first
        } else {
            serde_json::from_str(&tail).expect("terminal login JSON")
        };
        assert_eq!(output.status.success(), refresh_after_login, "{completed}");
        assert_eq!(
            completed["stage"],
            if refresh_after_login {
                "completed"
            } else {
                "failed"
            }
        );
        match mode {
            "success" | "refresh-lost-response" | "refresh-refused" => {
                assert_eq!(completed["nativeRecordVerified"], true);
                assert_eq!(completed["resourceRequestPerformed"], false);
                let persisted = owned.store.status(&owned.binding).expect("persisted token");
                assert!(
                    matches!(
                        persisted,
                        NativeTokenStatus::Available {
                            fresh: true,
                            can_refresh: true,
                            ..
                        }
                    ),
                    "{mode}: CLI confirmed native storage but independent status is {persisted:?}"
                );
            }
            "lost-token-response" => {
                assert_eq!(completed["mayHaveChanged"], true);
                assert_eq!(
                    owned.store.status(&owned.binding).expect("durable pending"),
                    NativeTokenStatus::ReauthorizationRequired
                );
            }
            _ => {
                assert_eq!(completed["mayHaveChanged"], false);
                assert_eq!(
                    owned
                        .store
                        .status(&owned.binding)
                        .expect("no token mutation"),
                    NativeTokenStatus::Absent
                );
            }
        }
        if refresh_after_login {
            let original = owned
                .store
                .load(&owned.binding)
                .expect("original record")
                .expect("tokens");
            let run_refresh = |confirmed: bool| {
                let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
                command.env_clear();
                command.env("LOCALAPPDATA", &coordination.0);
                for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
                    if let Some(value) = std::env::var_os(name) {
                        command.env(name, value);
                    }
                }
                command.args([
                    "mcp",
                    "oauth",
                    "refresh",
                    "--server",
                    &server,
                    "--endpoint",
                    &endpoint,
                    "--issuer",
                    &base,
                    "--authorization-endpoint",
                    &format!("{base}authorize"),
                    "--token-endpoint",
                    &format!("{base}token"),
                    "--client-id",
                    "fixture-public-client",
                    "--timeout-ms",
                    "7000",
                    "--json",
                ]);
                if confirmed {
                    command.arg("--confirm-refresh");
                }
                let output = command
                    .stdin(Stdio::null())
                    .output()
                    .expect("real refresh CLI");
                assert!(output.stderr.is_empty());
                let text = String::from_utf8(output.stdout).expect("refresh metadata");
                assert!(
                    text.len() < 16 * 1024
                        && !text.contains("private-")
                        && !text.contains("authorization_required")
                );
                let value: Value = serde_json::from_str(&text).expect("single refresh result");
                (output.status.success(), value)
            };
            assert!(!run_refresh(false).0);
            assert!(
                owned
                    .store
                    .load(&owned.binding)
                    .expect("unconfirmed command did not mutate")
                    .expect("tokens")
                    .same_generation_as(&original)
            );
            let (success, refreshed) = run_refresh(true);
            assert_eq!(success, mode == "success", "{refreshed}");
            assert_eq!(refreshed["method"], "mcp.oauth.refresh");
            if success {
                assert_eq!(refreshed["nativeRecordVerified"], true);
                assert_eq!(refreshed["cooperatingCliExclusive"], true);
                assert_eq!(refreshed["daemonNotified"], false);
                assert!(
                    !owned
                        .store
                        .load(&owned.binding)
                        .expect("new record")
                        .expect("new tokens")
                        .same_generation_as(&original)
                );
            } else {
                assert_eq!(refreshed["mayHaveChanged"], true);
                assert_eq!(
                    owned.store.status(&owned.binding).expect("pending refresh"),
                    NativeTokenStatus::ReauthorizationRequired
                );
                let (retry, result) = run_refresh(true);
                assert!(!retry);
                assert_eq!(result["mayHaveChanged"], false);
                assert!(
                    result["error"]["message"]
                        .as_str()
                        .expect("error")
                        .contains("new authorization before refresh")
                );
            }
        }
        let calls = backend.join().expect("fixture joined");
        if refresh_after_login || mode == "lost-token-response" {
            let form: BTreeMap<_, _> = url::form_urlencoded::parse(&calls[1])
                .into_owned()
                .collect();
            assert_eq!(form["grant_type"], "authorization_code");
            assert_eq!(form["code"], "private-login-code");
            assert_eq!(form["resource"], endpoint);
            assert!(!form.contains_key("client_secret"));
            assert_eq!(
                URL_SAFE_NO_PAD.encode(
                    ring::digest::digest(&ring::digest::SHA256, form["code_verifier"].as_bytes())
                        .as_ref()
                ),
                challenge.expect("PKCE challenge")
            );
        }
        if refresh_after_login {
            assert_eq!(calls.len(), 4);
            let form: BTreeMap<_, _> = url::form_urlencoded::parse(&calls[3])
                .into_owned()
                .collect();
            assert_eq!(form["grant_type"], "refresh_token");
            assert_eq!(form["refresh_token"], "private-login-refresh");
            assert_eq!(form["resource"], endpoint);
            assert!(
                !form.contains_key("code")
                    && !form.contains_key("code_verifier")
                    && !form.contains_key("scope")
                    && !form.contains_key("client_secret")
            );
        }
        if let Some(callback_address) = callback_address {
            assert!(std::net::TcpStream::connect(callback_address).is_err());
        }
        logout(&server, &endpoint, &coordination.0);
        assert_eq!(
            owned
                .store
                .status(&owned.binding)
                .expect("cleanup verified"),
            NativeTokenStatus::Absent
        );
    }
}

#[test]
fn encrypted_state_snapshot_roundtrip_is_private_atomic_and_never_overwrites_targets() {
    use claw_state::{Mutation, StateDatabase};
    use serde_json::{Value, json};

    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = Root(std::env::temp_dir().join(format!(
            "claw-encrypted-snapshot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
    std::fs::create_dir(&root.0).expect("owned snapshot fixture");
    let source = root.0.join("source.redb");
    let archive = root.0.join("backup.age");
    let restored = root.0.join("restored.redb");
    let database = StateDatabase::create_new(&source).expect("source fixture");
    database
        .commit(vec![
            Mutation::put(
                "private-record",
                &json!({"text":"private-source-marker","integer":9_007_199_254_740_993_u64}),
            )
            .expect("fixture record"),
        ])
        .expect("fixture commit");
    let run = |mode: &str, source: &std::path::Path, target: &std::path::Path, passphrase: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
        command.env_clear();
        #[cfg(windows)]
        for name in ["SystemRoot", "SystemDrive", "WINDIR"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = command
            .args(["state", "snapshot", mode, "--source"])
            .arg(source)
            .arg("--destination")
            .arg(target)
            .arg("--passphrase-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("real snapshot CLI");
        writeln!(
            child.stdin.take().expect("owned passphrase input"),
            "{passphrase}"
        )
        .expect("fixture passphrase to stdin only");
        let output = child.wait_with_output().expect("snapshot process finished");
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).expect("bounded metadata output");
        assert!(
            text.len() < 16 * 1024
                && !text.contains("private-source-marker")
                && !text.contains(passphrase)
        );
        let payload: Value = serde_json::from_str(&text).expect("snapshot metadata JSON");
        (output.status.success(), payload)
    };
    let passphrase = "owned-fixture-passphrase-only";
    assert!(
        !run("export", &source, &archive, passphrase).0,
        "a live database lock cannot be bypassed"
    );
    assert!(!archive.exists());
    drop(database);
    let (exported, receipt) = run("export", &source, &archive, passphrase);
    assert!(exported, "{receipt}");
    assert_eq!(receipt["records"], 1);
    assert_eq!(receipt["encryption"], "age-scrypt");
    let ciphertext = std::fs::read(&archive).expect("encrypted snapshot");
    assert!(ciphertext.starts_with(b"age-encryption.org/v1\n"));
    assert!(
        !ciphertext
            .windows(b"private-source-marker".len())
            .any(|bytes| bytes == b"private-source-marker")
    );
    let wrong = root.0.join("wrong-passphrase.redb");
    assert!(!run("restore", &archive, &wrong, "different-fixture-passphrase").0);
    assert!(
        !wrong.exists(),
        "wrong header key must not create a restore target"
    );
    let (complete, restored_receipt) = run("restore", &archive, &restored, passphrase);
    assert!(complete, "{restored_receipt}");
    assert_eq!(restored_receipt["sha256"], receipt["sha256"]);
    assert_eq!(restored_receipt["automaticResume"], false);
    assert_eq!(restored_receipt["restoredDatabaseIsPlaintext"], true);
    let restored_database = StateDatabase::open_existing(&restored).expect("restored data");
    assert_eq!(
        restored_database
            .get("private-record")
            .expect("record")
            .expect("restored record")
            .decode::<Value>()
            .expect("typed content"),
        json!({"text":"private-source-marker","integer":9_007_199_254_740_993_u64})
    );
    drop(restored_database);
    let unchanged = std::fs::read(&restored).expect("existing target bytes");
    assert!(!run("restore", &archive, &restored, passphrase).0);
    assert_eq!(
        std::fs::read(&restored).expect("target preserved"),
        unchanged
    );
    assert!(!run("export", &source, &archive, passphrase).0);
    assert_eq!(
        std::fs::read(&archive).expect("archive preserved"),
        ciphertext
    );
    let mut tampered = ciphertext.clone();
    *tampered.last_mut().expect("encrypted data") ^= 1;
    let corrupt = root.0.join("corrupt.age");
    std::fs::write(&corrupt, tampered).expect("owned corruption fixture");
    let incomplete = root.0.join("incomplete.redb");
    assert!(!run("restore", &corrupt, &incomplete, passphrase).0);
    if incomplete.exists() {
        assert!(
            StateDatabase::open_existing(&incomplete)
                .expect("empty rollback target")
                .get("private-record")
                .expect("no partial records")
                .is_none()
        );
    }
    let truncated = root.0.join("truncated.age");
    std::fs::write(&truncated, &ciphertext[..ciphertext.len() - 8])
        .expect("owned truncated fixture");
    let truncated_target = root.0.join("truncated.redb");
    assert!(!run("restore", &truncated, &truncated_target, passphrase).0);
    if truncated_target.exists() {
        assert!(
            StateDatabase::open_existing(&truncated_target)
                .expect("empty truncated target")
                .get("private-record")
                .expect("no partial restore")
                .is_none()
        );
    }
    let linked = root.0.join("hard-linked-source.redb");
    std::fs::hard_link(&source, &linked).expect("owned hard-link fixture");
    assert!(!run("export", &linked, &root.0.join("linked.age"), passphrase).0);
    assert!(!root.0.join("linked.age").exists());
    let missing = root.0.join("not-a-database.redb");
    assert!(!run("export", &missing, &root.0.join("missing.age"), passphrase).0);
    assert!(!missing.exists());
}

#[test]
fn openclaw_preview_is_read_only_paginated_and_rejects_changed_source() {
    struct Root(std::path::PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let root = Root(std::env::temp_dir().join(format!(
            "claw-cli-openclaw-preview-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
    std::fs::create_dir_all(&root.0).expect("isolated source");
    let config = r#"{"meta":{"lastTouchedVersion":"2026.9.4"},"gateway":{"auth":{"token":"private-preview-credential"}}}"#;
    std::fs::write(root.0.join("openclaw.json"), config).expect("source config");
    for index in 0..10 {
        std::fs::write(root.0.join(format!("metadata-{index}.txt")), b"unchanged")
            .expect("metadata fixture");
    }
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
            .args(["migrate", "openclaw", "preview", "--source"])
            .arg(&root.0)
            .args(extra)
            .output()
            .expect("preview child")
    };
    let first = run(&[]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(first.stderr.is_empty());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).expect("preview JSON");
    assert_eq!(first["entryCount"], 11);
    assert_eq!(first["entries"].as_array().expect("page").len(), 8);
    assert_eq!(first["sourceModified"], false);
    assert_eq!(first["snapshotVerified"], false);
    assert!(!first.to_string().contains("private-preview-credential"));
    let cursor = first["nextCursor"].as_str().expect("cursor");
    let fingerprint = first["fingerprint"].as_str().expect("fingerprint");
    let second = run(&["--after", cursor, "--fingerprint", fingerprint]);
    assert!(second.status.success());
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).expect("second page");
    assert_eq!(second["entries"].as_array().expect("page").len(), 3);
    assert!(second["nextCursor"].is_null());
    assert_eq!(
        std::fs::read_to_string(root.0.join("openclaw.json")).expect("source unchanged"),
        config
    );
    std::fs::write(root.0.join("openclaw.json"), "{}").expect("simulated source change");
    let stale = run(&["--after", cursor, "--fingerprint", fingerprint]);
    assert_eq!(stale.status.code(), Some(2));
    let stale: serde_json::Value = serde_json::from_slice(&stale.stdout).expect("stale error");
    assert_eq!(stale["error"]["code"], "preview_changed");
    assert_eq!(run(&["--apply"]).status.code(), Some(2));
    assert_eq!(
        std::fs::read_to_string(root.0.join("openclaw.json")).expect("no import occurred"),
        "{}"
    );
}

#[test]
fn documentation_never_places_literal_secrets_in_command_arguments() {
    let documentation = include_str!("../README.md");
    assert!(documentation.contains("trap 'restore_tty' 0"));
    assert!(documentation.contains("trap 'exit 130' 2"));
    assert!(documentation.contains("stty -echo"));
    assert!(documentation.contains("IFS= read -r GTA_CLAW_TOKEN"));
    assert!(!documentation.contains("read -r -s"));
    assert!(documentation.contains("Read-Host \"Gateway token\" -AsSecureString"));
    assert!(documentation.contains("version_status: \"redacted_peer_value\""));
    assert!(!documentation.contains("example-automation-token"));
    assert!(!documentation.contains("replace-with-token"));
    assert!(!documentation.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("printf ") || line.starts_with("echo ")
    }));
}

#[cfg(unix)]
#[test]
fn posix_hidden_input_sequence_runs_in_sh_and_dash_and_restores_echo() {
    assert_posix_hidden_input("sh");
    #[cfg(target_os = "linux")]
    assert_posix_hidden_input("dash");
}

#[cfg(unix)]
fn assert_posix_hidden_input(shell: &str) {
    let script = r#"
stty() { command printf '%s\n' "$1" >&2; }
restore_tty() { stty echo; }
trap 'restore_tty' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15
stty -echo
IFS= read -r GTA_CLAW_TOKEN
stty echo
trap - 0 1 2 3 15
"$1" <<EOF
$GTA_CLAW_TOKEN
EOF
"#;
    let sentinel = format!(
        "shell-input-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    );
    assert!(!script.contains(&sentinel));
    let mut child = Command::new(shell)
        .args(["-c", script, "posix-doc-test", "cat"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("POSIX shell starts");
    let mut input = child.stdin.take().expect("shell stdin");
    input
        .write_all(format!("{sentinel}\n").as_bytes())
        .expect("write simulated hidden input");
    drop(input);
    let output = child.wait_with_output().expect("shell output");
    assert!(
        output.status.success(),
        "{shell}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("shell stdout"),
        format!("{sentinel}\n")
    );
    assert_eq!(output.stderr, b"-echo\necho\n");
}

#[cfg(unix)]
#[test]
fn posix_signal_path_restores_echo_and_terminates() {
    let script = r#"
stty() {
  command printf '%s\n' "$1" >&2
  test "$1" != "-echo" || command printf 'ready\n'
}
restore_tty() { stty echo; }
trap 'restore_tty' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15
stty -echo
IFS= read -r GTA_CLAW_TOKEN
exit 99
"#;
    let mut child = Command::new("sh")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("POSIX shell starts");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("shell stdout"));
    let mut ready = String::new();
    stdout.read_line(&mut ready).expect("read readiness");
    assert_eq!(ready, "ready\n");
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send TERM");
    assert!(signal.success());
    drop(child.stdin.take());
    let status = child.wait().expect("signal helper exits");
    assert_eq!(status.code(), Some(143));
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .expect("shell stderr")
        .read_to_end(&mut stderr)
        .expect("read stty trace");
    assert_eq!(stderr, b"-echo\necho\n");
}

#[test]
fn saturated_stdout_cannot_hold_process_exit() {
    let (reader, writer) = os_pipe::pipe().expect("output pipe");
    let mut filler_writer = writer.try_clone().expect("clone output writer");
    let filler = std::thread::spawn(move || {
        let block = [b'x'; 8 * 1024];
        while filler_writer.write_all(&block).is_ok() {}
    });
    std::thread::sleep(Duration::from_millis(250));

    let child = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"))
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::null())
        .spawn()
        .expect("CLI process starts");
    let started = Instant::now();
    let status = wait_bounded(child);
    assert_eq!(status.code(), Some(8));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(reader);
    filler.join().expect("filler exits after reader closes");
}

#[test]
fn broken_stdout_and_stderr_are_typed_internal_failures() {
    for (argument, break_stdout) in [("--help", true), ("definitely-unknown", false)] {
        let (reader, writer) = os_pipe::pipe().expect("broken output pipe");
        drop(reader);
        let mut command = Command::new(env!("CARGO_BIN_EXE_gta-claw-cli"));
        command
            .arg(argument)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if break_stdout {
            command.stdout(Stdio::from(writer));
        } else {
            command.stderr(Stdio::from(writer));
        }
        let status = wait_bounded(command.spawn().expect("CLI process starts"));
        assert_eq!(status.code(), Some(8));
    }
}

fn wait_bounded(mut child: std::process::Child) -> ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("CLI process status") {
            return status;
        }
        if started.elapsed() >= Duration::from_secs(2) {
            child.kill().expect("terminate hung CLI");
            panic!("CLI process exceeded its hard output bound");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

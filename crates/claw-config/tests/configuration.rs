//! Integration tests for strict loading, persistence, and reload behavior.

mod common;

use claw_config::{
    ConfigDomain, ConfigError, ReloadManager, load_file, parse_json5, schema_json, to_json5,
    write_file,
};

const VALID: &str = r#"
{
  // Versioned envelope; trailing commas are intentional.
  schema_version: 1,
  core: {
    auth: { github: { pat: "env:GITHUB_TOKEN", device: { enabled: false, }, }, },
    role: { source_url: "https://roles.example.test/default.json", },
    channels: {
      teams: { enabled: false, },
      telegram: { enabled: false, poll_interval_ms: 2000, },
      discord: { enabled: false, gateway_intents: 33281, },
      whatsapp: { enabled: false, webhook_path: "/whatsapp/webhook", },
    },
    server: { port: 3978, },
    logging: { level: "info", },
    sessions: { ttl_ms: 3600000, max_entries: 100, },
    copilot: { default_model: "gpt-4o", request_timeout_ms: 120000, },
    legacy: { skills: { source_urls: [], execution_timeout_ms: 30000, }, },
    updates: { enabled: false, },
    admin: {},
    network: {},
  },
}
"#;

#[test]
fn explicit_provider_selection_is_typed_and_does_not_require_unused_github_auth() {
    for kind in ["openai", "anthropic", "disabled"] {
        let mut document: serde_json::Value = json5::from_str(VALID).expect("base document");
        document["core"]["auth"]["github"]["pat"] = serde_json::Value::Null;
        document["core"]["provider"] = if kind == "disabled" {
            serde_json::json!({"kind":"disabled"})
        } else {
            serde_json::json!({"kind":kind,"model":"fixture-model","api_key":"env:NATIVE_TEST_KEY",
                "base_url":"http://127.0.0.1:23456/v1/","credential_origin":"http://127.0.0.1:23456",
                "request_timeout_ms":5000,"max_observed_turn_tokens":0})
        };
        let configured = parse_json5(&document.to_string(), "provider.json5")
            .unwrap_or_else(|error| panic!("explicit {kind}: {error}"));
        let persisted = to_json5(&configured).expect("provider serialization");
        assert_eq!(
            parse_json5(&persisted, "roundtrip.json5").expect("provider roundtrip"),
            configured
        );
        assert!(persisted.contains(kind));
    }
    parse_json5(VALID, "legacy.json5").expect("existing configuration unchanged");
}

#[test]
fn explicit_provider_configuration_rejects_invalid_or_inapplicable_settings_and_requires_restart() {
    let mut document: serde_json::Value = json5::from_str(VALID).expect("base document");
    document["core"]["provider"] = serde_json::json!({"kind":"openai","model":"fixture-model","api_key":"env:NATIVE_TEST_KEY","completion_api":"responses"});
    let configured =
        parse_json5(&document.to_string(), "valid-provider.json5").expect("valid native provider");
    let provider = configured.core().provider().expect("explicit selection");
    assert_eq!(provider.kind(), claw_config::ProviderKind::Openai);
    assert_eq!(
        provider.completion_api(),
        Some(claw_config::ProviderCompletionApi::Responses)
    );
    assert_eq!(provider.base_url(), Some("https://api.openai.com/v1/"));
    assert_eq!(provider.credential_origin(), Some("https://api.openai.com"));
    assert!(!format!("{configured:?}").contains("NATIVE_TEST_KEY"));
    for (field, invalid) in [
        ("kind", serde_json::json!("unknown")),
        ("kind", serde_json::json!("disabled")),
        ("kind", serde_json::json!("copilot")),
        ("kind", serde_json::json!("anthropic")),
        ("api_key", serde_json::json!("literal-private-token")),
        ("api_key", serde_json::Value::Null),
        (
            "api_key",
            serde_json::json!(format!("env:{}", "X".repeat(1024))),
        ),
        (
            "base_url",
            serde_json::json!(format!("https://example.test/{}", "x".repeat(2048))),
        ),
        ("model", serde_json::json!(" ")),
        ("model", serde_json::json!("model name")),
        ("model", serde_json::json!("x".repeat(257))),
        ("request_timeout_ms", serde_json::json!(999)),
        ("request_timeout_ms", serde_json::json!(120_001)),
        ("base_url", serde_json::json!("http://example.test/v1/")),
        (
            "base_url",
            serde_json::json!("https://user:private@example.test/v1/"),
        ),
        (
            "base_url",
            serde_json::json!("https://example.test/v1/?token=private"),
        ),
        ("base_url", serde_json::json!("https://example.test/../v1/")),
        (
            "credential_origin",
            serde_json::json!("https://another.test"),
        ),
        (
            "credential_origin",
            serde_json::json!("https://api.openai.com/v1/"),
        ),
        ("fallback", serde_json::json!([])),
        ("max_observed_turn_tokens", serde_json::json!(-1)),
    ] {
        let mut changed = document.clone();
        changed["core"]["provider"][field] = invalid;
        let error = parse_json5(&changed.to_string(), "invalid-provider.json5").expect_err(field);
        assert!(
            error.to_string().contains("core.provider"),
            "{field}: {error}"
        );
        assert!(!error.to_string().contains("literal-private-token"));
    }
    let mut manager = ReloadManager::new(parse_json5(VALID, "legacy.json5").expect("legacy"));
    let outcome = manager
        .reload_json5(&document.to_string(), "provider.json5")
        .expect("typed candidate");
    assert_eq!(outcome.changed_domains, [ConfigDomain::Provider]);
    assert_eq!(outcome.restart_required_domains, [ConfigDomain::Provider]);
    let before = manager.snapshot();
    document["core"]["provider"]["api_key"] = serde_json::json!("rejected-secret");
    assert!(
        manager
            .reload_json5(&document.to_string(), "invalid.json5")
            .is_err()
    );
    assert_eq!(manager.snapshot(), before);
}

#[test]
fn provider_edit_revalidates_the_whole_snapshot_and_rejects_ambiguous_input() {
    let original = parse_json5(VALID, "original.json5").expect("source snapshot");
    let before = to_json5(&original).expect("original serialization");
    let selection = r#"{"kind":"openai","model":"fixture-model","api_key":"env:NATIVE_TEST_KEY","completion_api":"responses"}"#;
    let candidate = claw_config::with_provider_json(&original, selection).expect("validated edit");
    assert_eq!(
        candidate.core().provider().expect("new provider").model(),
        Some("fixture-model")
    );
    assert_eq!(
        to_json5(&original).expect("unchanged serialization"),
        before
    );
    assert!(original.core().provider().is_none());
    for invalid in [
        r#"{"kind":"openai","kind":"disabled"}"#,
        r#"{"kind":"openai","model":"one","model":"two","api_key":"env:KEY"}"#,
        r#"{"kind":"disabled","unexpected":"private-secret"}"#,
        r#"{"kind":"openai","model":"model","api_key":"private-secret"}"#,
        r#"{kind:"disabled"}"#,
    ] {
        let error = claw_config::with_provider_json(&original, invalid).expect_err("invalid edit");
        assert!(!error.to_string().contains("private-secret"));
    }
    assert!(claw_config::with_provider_json(&original, &" ".repeat(16 * 1024 + 1)).is_err());
    let mut document: serde_json::Value = json5::from_str(VALID).expect("source");
    document["core"]["auth"]["github"]["pat"] = serde_json::Value::Null;
    document["core"]["provider"] = serde_json::json!({"kind":"disabled"});
    let disabled =
        parse_json5(&document.to_string(), "disabled.json5").expect("no credential required");
    assert!(
        claw_config::with_provider_json(&disabled, r#"{"kind":"copilot","model":"fixture-model"}"#)
            .is_err()
    );
}

#[test]
fn provider_model_edit_keeps_identity_credentials_limits_and_original_snapshot() {
    let original = parse_json5(VALID, "source").expect("base snapshot");
    assert!(claw_config::with_provider_model(&original, "next").is_err());
    let disabled =
        claw_config::with_provider_json(&original, r#"{"kind":"disabled"}"#).expect("disabled");
    assert!(claw_config::with_provider_model(&disabled, "next").is_err());
    for kind in ["openai", "anthropic", "copilot"] {
        let mut selection = if kind == "copilot" {
            serde_json::json!({"kind":kind,"model":"before","request_timeout_ms":5000,"max_observed_turn_tokens":0})
        } else {
            serde_json::json!({"kind":kind,"model":"before","api_key":"env:MODEL_EDIT_KEY","base_url":"http://127.0.0.1:23456/v1/",
                "credential_origin":"http://127.0.0.1:23456","request_timeout_ms":5000,"max_observed_turn_tokens":0})
        };
        selection["model_aliases"] = serde_json::json!([
            {"alias":"work","model":"before"},
            {"alias":"next","model":"Exact-Model:2026-09"}
        ]);
        let configured = claw_config::with_provider_json(&original, &selection.to_string())
            .expect("explicit source");
        assert_eq!(
            configured
                .core()
                .provider()
                .expect("provider")
                .catalogue_provider_id(),
            Some(if kind == "copilot" {
                "github-copilot"
            } else {
                kind
            })
        );
        let before = configured.clone();
        let candidate = claw_config::with_provider_model(&configured, "Exact-Model:2026-09")
            .expect("model candidate");
        assert_eq!(configured, before);
        assert_eq!(
            candidate.core().provider().expect("provider").model(),
            Some("Exact-Model:2026-09")
        );
        assert_eq!(
            claw_config::with_provider_model(&candidate, "before").expect("restore model"),
            before
        );
        let mut manager = ReloadManager::new(configured.clone());
        let changes = manager
            .reload_json5(
                &to_json5(&candidate).expect("encoded candidate"),
                "model edit",
            )
            .expect("validated change");
        assert_eq!(changes.changed_domains, [ConfigDomain::Provider]);
        assert_eq!(changes.restart_required_domains, [ConfigDomain::Provider]);
        for model in [
            "",
            " spaces ",
            "two models",
            "line\nmodel",
            &"m".repeat(257),
        ] {
            assert!(
                claw_config::with_provider_model(&configured, model).is_err(),
                "invalid exact ID"
            );
            assert_eq!(configured, before);
        }
    }
}

#[test]
fn provider_model_aliases_are_explicit_bounded_and_preserved_without_changing_identity() {
    let original = parse_json5(VALID, "source").expect("base snapshot");
    let base = serde_json::json!({"kind":"openai","model":"exact", "api_key":"env:ALIAS_KEY"});
    let mut valid = base.clone();
    valid["model_aliases"] = serde_json::json!([{"alias":"work","model":"exact"},{"alias":"Work","model":"other/exact@2026"}]);
    let configured =
        claw_config::with_provider_json(&original, &valid.to_string()).expect("explicit aliases");
    let provider = configured.core().provider().expect("provider");
    assert_eq!(provider.model(), Some("exact"));
    assert_eq!(provider.model_aliases().len(), 2);
    assert_eq!(provider.model_aliases()[0].alias(), "work");
    assert_eq!(provider.model_aliases()[1].model(), "other/exact@2026");
    assert_eq!(
        parse_json5(&to_json5(&configured).expect("serialize"), "roundtrip").expect("valid"),
        configured
    );
    assert!(
        claw_config::with_provider_model(&configured, "work").is_err(),
        "exact-model editing cannot silently treat an alias as a real ID"
    );
    for aliases in [
        serde_json::json!([{"alias":"work","model":"exact"},{"alias":"work","model":"exact"}]),
        serde_json::json!([{"alias":"exact","model":"other"}]),
        serde_json::json!([{"alias":"work","model":"next"},{"alias":"next","model":"exact"}]),
        serde_json::json!([{"alias":"work","model":"work"}]),
        serde_json::json!([{"alias":"openclaw/default","model":"exact"}]),
        serde_json::json!([{"alias":"space alias","model":"exact"}]),
        serde_json::json!([{"alias":"work","model":"bad model"}]),
        serde_json::json!([{"alias":"work","model":"exact","endpoint":"https://unrelated.invalid"}]),
        serde_json::json!((0..129).map(|index| serde_json::json!({"alias":format!("alias-{index}"),"model":"exact"})).collect::<Vec<_>>()),
        serde_json::json!((0..20).map(|index| serde_json::json!({"alias":format!("{}{index}", "a".repeat(240)),"model":"exact"})).collect::<Vec<_>>()),
    ] {
        let mut invalid = base.clone();
        invalid["model_aliases"] = aliases;
        assert!(claw_config::with_provider_json(&original, &invalid.to_string()).is_err());
    }
    assert!(
        claw_config::with_provider_json(&original, r#"{"kind":"disabled","model_aliases":[]}"#)
            .is_err()
    );
    let mut manager = ReloadManager::new(
        claw_config::with_provider_json(&original, &base.to_string()).expect("no aliases"),
    );
    let changes = manager
        .reload_json5(&to_json5(&configured).expect("encoded"), "aliases")
        .expect("reload");
    assert_eq!(changes.changed_domains, [ConfigDomain::Provider]);
    assert_eq!(changes.restart_required_domains, [ConfigDomain::Provider]);
}

#[test]
fn accepts_comments_and_trailing_commas() {
    let config = parse_json5(VALID, "test.json5").expect("valid JSON5");

    assert_eq!(config.core().server().port(), 3978);
    assert_eq!(
        config
            .core()
            .auth()
            .github_pat()
            .expect("token reference")
            .as_str(),
        "env:GITHUB_TOKEN"
    );
}

#[test]
fn rejects_unknown_envelope_core_and_nested_fields() {
    for (source, expected_path) in [
        (
            VALID.replace("schema_version: 1,", "schema_version: 1, surprise: true,"),
            "surprise",
        ),
        (
            VALID.replace("auth:", "unsupported_domain: {}, auth:"),
            "core.unsupported_domain",
        ),
        (
            VALID.replace(
                "server: { port: 3978, }",
                "server: { port: 3978, typo: true, }",
            ),
            "core.server.typo",
        ),
    ] {
        let error = parse_json5(&source, "unknown.json5").expect_err("unknown field must fail");
        let ConfigError::Decode { path, .. } = error else {
            panic!("expected typed decode error: {error}");
        };
        assert!(
            path.contains(expected_path),
            "expected {expected_path} in {path}"
        );
    }
}

#[test]
fn rejects_malformed_and_invalid_values_with_paths() {
    let malformed = VALID.replace("port: 3978", "port: 'oops'");
    let error = parse_json5(&malformed, "malformed.json5").expect_err("type mismatch");
    assert!(error.to_string().contains("core.server.port"));

    let invalid = VALID.replace("port: 3978", "port: 0");
    let error = parse_json5(&invalid, "invalid.json5").expect_err("invalid port");
    assert_eq!(
        error.to_string(),
        "core.server.port: must be from 1 through 65535"
    );
}

#[test]
fn enforces_standards_based_url_policy() {
    for (url, expected) in [
        ("http://@", "empty host"),
        ("http://[::1", "invalid IPv6 address"),
        ("http://user@example.test/role", "userinfo is not allowed"),
        (
            "https://example.test/role#fragment",
            "fragment is not allowed",
        ),
        (
            "http://example.test:0/role",
            "port must be from 1 through 65535",
        ),
    ] {
        let source = VALID.replace("https://roles.example.test/default.json", url);
        let error = parse_json5(&source, "url.json5").expect_err("URL must fail");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} for {url:?}, got {error}"
        );
    }

    let ipv6 = VALID.replace(
        "https://roles.example.test/default.json",
        "http://[::1]/role",
    );
    parse_json5(&ipv6, "ipv6.json5").expect("valid IPv6 host");
}

#[test]
fn rejects_plaintext_secrets() {
    let source = VALID.replace("env:GITHUB_TOKEN", "plaintext-token");
    let error = parse_json5(&source, "secret.json5").expect_err("plaintext must fail");

    assert_eq!(
        error.to_string(),
        "core.auth.github.pat: only env:<NAME> secret references are supported"
    );
}

#[test]
fn whatsapp_app_secret_round_trips_as_a_secret_reference() {
    let source = VALID.replace(
        "whatsapp: { enabled: false, webhook_path: \"/whatsapp/webhook\", }",
        "whatsapp: {
            enabled: true,
            verify_token: \"env:WHATSAPP_VERIFY_TOKEN\",
            access_token: \"env:WHATSAPP_ACCESS_TOKEN\",
            app_secret: \"env:WHATSAPP_APP_SECRET\",
            phone_number_id: \"phone-id\",
            webhook_path: \"/whatsapp/webhook\",
        }",
    );
    let config = parse_json5(&source, "whatsapp.json5").expect("WhatsApp configuration");
    let output = to_json5(&config).expect("serialize WhatsApp configuration");

    assert!(output.contains("app_secret"));
    assert!(output.contains("env:WHATSAPP_APP_SECRET"));

    let plaintext = source.replace("env:WHATSAPP_APP_SECRET", "plaintext-app-secret");
    let error = parse_json5(&plaintext, "whatsapp-secret.json5")
        .expect_err("plaintext app secret must fail");
    assert!(
        error
            .to_string()
            .contains("core.channels.whatsapp.app_secret")
    );
}

#[test]
fn output_and_schema_are_deterministic() {
    let config = parse_json5(VALID, "test.json5").expect("valid JSON5");
    let first = to_json5(&config).expect("serialize");
    let second = to_json5(&config).expect("serialize again");

    assert_eq!(first, second);
    assert_eq!(
        parse_json5(&first, "serialized.json5").expect("round trip"),
        config
    );
    let schema = schema_json().expect("generated schema");
    assert!(schema.contains("\"additionalProperties\": false"));
    assert!(schema.contains("\"schema_version\""));
}

#[test]
fn atomic_file_round_trip_is_cross_platform() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("config.json5");
    let config = parse_json5(VALID, "test.json5").expect("valid JSON5");
    std::fs::write(&path, "old contents").expect("seed existing destination");
    #[cfg(windows)]
    let creation_time = {
        use std::os::windows::fs::MetadataExt;
        std::fs::metadata(&path)
            .expect("old destination metadata")
            .creation_time()
    };

    write_file(&path, &config).expect("atomic write");

    assert_eq!(load_file(path).expect("load written file"), config);
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(directory.path().join("config.json5"))
                .expect("replacement metadata")
                .creation_time(),
            creation_time,
            "ReplaceFileW must preserve destination creation metadata"
        );
    }
}

#[test]
fn atomic_first_write_creates_a_valid_file_without_warnings() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("first-write.json5");
    let config = parse_json5(VALID, "test.json5").expect("valid JSON5");

    let outcome = write_file(&path, &config).expect("atomic first write");

    assert!(outcome.warnings.is_empty());
    assert_eq!(load_file(path).expect("load first write"), config);
}

#[cfg(unix)]
#[test]
fn rejects_symlink_destination_and_parent() {
    use std::os::unix::fs::symlink;

    let directory = common::TestDirectory::create();
    let real = directory.path().join("real.json5");
    let link = directory.path().join("link.json5");
    std::fs::write(&real, "old").expect("write real file");
    symlink(&real, &link).expect("create destination symlink");
    let config = parse_json5(VALID, "test.json5").expect("valid JSON5");
    let error = write_file(&link, &config).expect_err("symlink destination must fail");
    assert!(error.to_string().contains("must not be a symlink"));
    assert_eq!(std::fs::read_to_string(&real).expect("real file"), "old");

    let real_parent = directory.path().join("real-parent");
    let linked_parent = directory.path().join("linked-parent");
    std::fs::create_dir(&real_parent).expect("create real parent");
    symlink(&real_parent, &linked_parent).expect("create parent symlink");
    let error = write_file(linked_parent.join("config.json5"), &config)
        .expect_err("symlink parent must fail");
    assert!(error.to_string().contains("parent chain"));
}

#[cfg(windows)]
#[test]
fn rejects_reparse_destination_and_parent_when_symlink_privilege_is_available() {
    use std::io::ErrorKind;
    use std::os::windows::fs::{symlink_dir, symlink_file};

    let directory = common::TestDirectory::create();
    let real = directory.path().join("real.json5");
    let link = directory.path().join("link.json5");
    std::fs::write(&real, "old").expect("write real file");
    match symlink_file(&real, &link) {
        Ok(()) => {}
        Err(error)
            if error.kind() == ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(1314) =>
        {
            return;
        }
        Err(error) => panic!("create destination symlink: {error}"),
    }
    let config = parse_json5(VALID, "test.json5").expect("valid JSON5");
    let error = write_file(&link, &config).expect_err("reparse destination must fail");
    assert!(error.to_string().contains("reparse point"));
    assert_eq!(std::fs::read_to_string(&real).expect("real file"), "old");

    let real_parent = directory.path().join("real-parent");
    let linked_parent = directory.path().join("linked-parent");
    std::fs::create_dir(&real_parent).expect("create real parent");
    symlink_dir(&real_parent, &linked_parent).expect("create parent symlink");
    let error = write_file(linked_parent.join("config.json5"), &config)
        .expect_err("reparse parent must fail");
    assert!(error.to_string().contains("parent chain"));
}

#[test]
fn rejected_reload_keeps_last_known_good_and_classifies_changes() {
    let initial = parse_json5(VALID, "initial.json5").expect("initial config");
    let mut manager = ReloadManager::new(initial);
    let old = manager.snapshot();

    let invalid = VALID.replace("port: 3978", "port: 0");
    manager
        .reload_json5(&invalid, "invalid.json5")
        .expect_err("candidate must be rejected");
    assert_eq!(manager.snapshot(), old);

    let changed = VALID
        .replace("port: 3978", "port: 8080")
        .replace("level: \"info\"", "level: \"debug\"");
    let outcome = manager
        .reload_json5(&changed, "changed.json5")
        .expect("valid candidate");
    assert_eq!(
        outcome.changed_domains,
        vec![ConfigDomain::Server, ConfigDomain::Logging]
    );
    assert_eq!(outcome.restart_required_domains, vec![ConfigDomain::Server]);
}

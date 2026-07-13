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
fn rejects_plaintext_secrets() {
    let source = VALID.replace("env:GITHUB_TOKEN", "plaintext-token");
    let error = parse_json5(&source, "secret.json5").expect_err("plaintext must fail");

    assert_eq!(
        error.to_string(),
        "core.auth.github.pat: only env:<NAME> secret references are supported"
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

    write_file(&path, &config).expect("atomic write");

    assert_eq!(load_file(path).expect("load written file"), config);
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

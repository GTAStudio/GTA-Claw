//! Integration tests for the frozen GTA legacy environment conversion.

use claw_config::{MigrationDiagnostic, MigrationError, migrate_legacy_environment, to_json5};

fn minimum_environment() -> Vec<(&'static str, &'static str)> {
    vec![
        ("GITHUB_TOKEN", "super-secret-token"),
        ("AGENT_ROLE_URL", "https://roles.example.test/default.json"),
        ("ENABLE_TEAMS", "false"),
    ]
}

#[test]
fn migrates_supported_aliases_types_and_legacy_integer_prefixes() {
    let mut environment = minimum_environment();
    environment.extend([
        ("TELEGRAM_POLL_INTERVAL_MS", "2500ms"),
        (
            "ALLOWED_SKILL_DOMAINS",
            " Example.COM,api.test,example.com ",
        ),
        ("HTTPS_PROXY", "http://proxy.example.test"),
        ("https_proxy", "http://proxy.example.test"),
    ]);

    let result = migrate_legacy_environment(environment).expect("migration");

    assert_eq!(
        result
            .config
            .core()
            .channels()
            .telegram()
            .poll_interval_ms(),
        2500
    );
    assert_eq!(
        result
            .config
            .core()
            .network()
            .proxy_url()
            .expect("proxy reference")
            .as_str(),
        "env:HTTPS_PROXY"
    );
    let output = to_json5(&result.config).expect("serialize migration");
    assert!(!output.contains("super-secret-token"));
    assert!(!output.contains("http://proxy.example.test"));
    assert!(output.contains("env:GITHUB_TOKEN"));
    assert!(output.contains("env:HTTPS_PROXY"));
}

#[test]
fn preserves_legacy_unvalidated_discord_gateway_value() {
    let mut environment = minimum_environment();
    environment.push(("DISCORD_GATEWAY_URL", "legacy-gateway-value"));

    let result = migrate_legacy_environment(environment).expect("legacy gateway is copied");
    let output = to_json5(&result.config).expect("serialize migration");
    assert!(output.contains("legacy-gateway-value"));
}

#[test]
fn detects_alias_conflicts_before_deduplication() {
    let mut environment = minimum_environment();
    environment.extend([
        ("HTTPS_PROXY", "http://one.example.test"),
        ("https_proxy", "http://two.example.test"),
    ]);

    let error = migrate_legacy_environment(environment).expect_err("aliases conflict");
    let MigrationError::AliasConflict { target, names } = error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(target, "network.proxy_url");
    assert_eq!(names, vec!["HTTPS_PROXY", "https_proxy"]);
}

#[test]
fn rejects_invalid_boolean_and_range_values() {
    for (name, value) in [
        ("ENABLE_TELEGRAM", "TRUE"),
        ("TELEGRAM_POLL_INTERVAL_MS", "499"),
    ] {
        let mut environment = minimum_environment();
        environment.push((name, value));
        let error = migrate_legacy_environment(environment).expect_err("invalid value");
        assert!(matches!(error, MigrationError::InvalidValue { .. }));
        assert!(error.to_string().contains(name));
    }
}

#[test]
fn matches_number_parse_int_whitespace_and_reports_overflow() {
    let mut whitespace = minimum_environment();
    whitespace.push(("PORT", " \t3978rest"));
    let result = migrate_legacy_environment(whitespace).expect("leading whitespace is accepted");
    assert_eq!(result.config.core().server().port(), 3978);

    let mut overflow = minimum_environment();
    overflow.push((
        "SESSION_TTL_MS",
        "999999999999999999999999999999999999999999999999999",
    ));
    let error = migrate_legacy_environment(overflow).expect_err("overflow must fail");
    assert!(error.to_string().contains("too large to represent"));
}

#[test]
fn applies_legacy_empty_defaults_without_weakening_boolean_types() {
    let mut environment = minimum_environment();
    environment.extend([("DOMAIN", ""), ("COPILOT_MODEL", "")]);
    let result = migrate_legacy_environment(environment).expect("empty defaults");
    assert_eq!(result.config.core().server().public_domain(), "localhost");
    assert_eq!(result.config.core().copilot().default_model(), "gpt-4o");

    let mut invalid_boolean = minimum_environment();
    invalid_boolean.push(("ENABLE_TELEGRAM", ""));
    migrate_legacy_environment(invalid_boolean).expect_err("empty boolean remains invalid");
}

#[test]
fn reports_non_runtime_and_cli_mappings_as_manual() {
    let mut environment = minimum_environment();
    environment.extend([
        ("COPILOT_CLI_PATH", "copilot"),
        ("DOCKER_IMAGE", "example/gta-claw:latest"),
        ("COPILOT_CLI_VERSION", "1.2.3"),
        ("DOCKERHUB_TOKEN", "publish-secret"),
    ]);

    let result = migrate_legacy_environment(environment).expect("migration");

    let manual = result
        .diagnostics
        .iter()
        .filter(|diagnostic| matches!(diagnostic, MigrationDiagnostic::ManualRequired(_)))
        .count();
    assert_eq!(manual, 4);
    let output = to_json5(&result.config).expect("serialize");
    assert!(!output.contains("publish-secret"));
    assert!(!output.contains("cli_path"));
}

#[test]
fn reports_applied_and_unknown_inputs_in_deterministic_order() {
    let mut environment = minimum_environment();
    environment.extend([("PORT", "8080"), ("TYPO_PORT", "8081")]);

    let result = migrate_legacy_environment(environment).expect("migration report");
    let applied = result
        .diagnostics
        .iter()
        .filter_map(|diagnostic| match diagnostic {
            MigrationDiagnostic::Applied { legacy_env, target } => Some((*legacy_env, *target)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        applied,
        vec![
            ("GITHUB_TOKEN", "auth.github.pat"),
            ("AGENT_ROLE_URL", "role.source_url"),
            ("ENABLE_TEAMS", "channels.teams.enabled"),
            ("PORT", "server.port"),
        ]
    );
    assert!(matches!(
        result.diagnostics.last(),
        Some(MigrationDiagnostic::IgnoredUnknown { name }) if name == "TYPO_PORT"
    ));
}

#[test]
fn conversion_is_deterministic_across_input_order() {
    let forward = minimum_environment();
    let reverse = forward.iter().copied().rev().collect::<Vec<_>>();

    let first = migrate_legacy_environment(forward).expect("forward migration");
    let second = migrate_legacy_environment(reverse).expect("reverse migration");

    assert_eq!(first, second);
    assert_eq!(
        to_json5(&first.config).expect("first output"),
        to_json5(&second.config).expect("second output")
    );
}

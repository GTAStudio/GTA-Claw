//! Frozen 47-domain model and schema acceptance tests.

mod common;

use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};
use std::thread;

use claw_config::domains::{DomainSecretRef, SecretSource};
use claw_config::{
    CONFIG_DOMAIN_NAMES, ConfigError, ConfigLayerKind, LayeredConfigError,
    OpenClawConfigFileWatcher, OpenClawConfigHub, OpenClawConfigLayers, OpenClawDomain,
    openclaw_schema_json, openclaw_to_json5, parse_openclaw_json5,
};
use serde_json::Value;

const ALL_DOMAINS: &str = r##"
{
  $schema: "https://example.test/openclaw.schema.json",
  meta: {},
  auth: {},
  accessGroups: {},
  acp: {},
  env: {},
  wizard: {},
  diagnostics: {},
  logging: {},
  audit: {},
  security: {},
  cli: {},
  crestodian: { rescue: {} },
  update: {},
  browser: {},
  ui: { seamColor: "#12aBc9" },
  tui: {},
  secrets: {},
  marketplaces: {},
  skills: {},
  plugins: {},
  surfaces: {},
  models: {},
  nodeHost: {},
  agents: {},
  tools: {},
  bindings: [],
  broadcast: {},
  audio: {},
  media: {},
  messages: {},
  commands: {},
  approvals: {},
  session: {},
  web: {},
  channels: {},
  cron: {},
  transcripts: {},
  commitments: {},
  hooks: {},
  discovery: {},
  talk: {},
  gateway: {},
  cloudWorkers: {},
  memory: {},
  mcp: {},
  proxy: {},
}
"##;

#[test]
fn implemented_domain_set_matches_frozen_inventory_exactly() {
    let inventory_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/upstream/inventories/config-domains.json");
    let inventory_source =
        std::fs::read_to_string(inventory_path).expect("read frozen domain inventory");
    let inventory: Value = serde_json::from_str(inventory_source.trim_start_matches('\u{feff}'))
        .expect("parse frozen domain inventory");
    let names = inventory["items"]
        .as_array()
        .expect("inventory items")
        .iter()
        .map(|item| item["id"].as_str().expect("domain id"))
        .collect::<Vec<_>>();

    assert_eq!(names, CONFIG_DOMAIN_NAMES);
    assert_eq!(names.len(), 47);
    assert_eq!(names.iter().copied().collect::<BTreeSet<_>>().len(), 47);
}

#[test]
fn all_frozen_domains_round_trip_without_name_drift() {
    let config = parse_openclaw_json5(ALL_DOMAINS, "all-domains.json5").expect("all domains");
    let encoded = openclaw_to_json5(&config).expect("serialize all domains");
    let reparsed = parse_openclaw_json5(&encoded, "round-trip.json5").expect("round trip");

    assert_eq!(reparsed, config);
    let value: Value = json5::from_str(&encoded).expect("parse encoded value");
    let keys = value
        .as_object()
        .expect("top-level object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        keys,
        CONFIG_DOMAIN_NAMES.into_iter().collect::<BTreeSet<_>>()
    );
}

#[test]
fn fixed_domains_reject_unknown_fields_with_exact_paths() {
    let source = ALL_DOMAINS.replace("crestodian: { rescue: {} }", "crestodian: { typo: true }");
    let error =
        parse_openclaw_json5(&source, "unknown.json5").expect_err("unknown field must fail");
    match error {
        ConfigError::Decode {
            source_name,
            path,
            message,
        } => {
            assert_eq!(source_name, "unknown.json5");
            assert_eq!(path, "crestodian.typo");
            assert_eq!(
                message,
                "unknown field `typo`, expected `rescue` at line 15 column 17"
            );
        }
        other => panic!("expected decode error, got {other}"),
    }
}

#[test]
fn pinned_imported_domains_reject_drifted_top_level_keys() {
    let source = ALL_DOMAINS.replace("auth: {},", "auth: { typo: true },");
    let error = parse_openclaw_json5(&source, "auth-drift.json5")
        .expect_err("drifted imported-domain key must fail");
    match error {
        ConfigError::Decode {
            source_name,
            path,
            message,
        } => {
            assert_eq!(source_name, "auth-drift.json5");
            assert_eq!(path, "auth.typo");
            assert!(!message.is_empty());
        }
        other => panic!("expected decode error, got {other}"),
    }
}

#[test]
fn validation_reports_the_actionable_json_path() {
    let source = ALL_DOMAINS.replace(
        "crestodian: { rescue: {} }",
        "crestodian: { rescue: { pendingTtlMinutes: 0 } }",
    );
    let error = parse_openclaw_json5(&source, "invalid.json5").expect_err("zero TTL must fail");
    match error {
        ConfigError::Validation { path, message } => {
            assert_eq!(path, "crestodian.rescue.pendingTtlMinutes");
            assert_eq!(message, "must be from 1 through 1440");
        }
        other => panic!("expected validation error, got {other}"),
    }
}

#[test]
fn generated_schema_accepts_valid_and_rejects_invalid_instances() {
    let schema: Value =
        serde_json::from_str(&openclaw_schema_json().expect("schema")).expect("schema JSON");
    let valid: Value = json5::from_str(ALL_DOMAINS).expect("valid instance");
    let unknown: Value = json5::from_str(
        &ALL_DOMAINS.replace("proxy: {},", "proxy: {}, contractBreakingDomain: {},"),
    )
    .expect("unknown instance");
    let wrong_type: Value =
        json5::from_str(&ALL_DOMAINS.replace("crestodian: { rescue: {} }", "crestodian: 42"))
            .expect("wrong-type instance");

    assert_eq!(validate_schema(&schema, &schema, &valid), Ok(()));
    assert_eq!(
        validate_schema(&schema, &schema, &unknown),
        Err("additional property contractBreakingDomain".to_owned())
    );
    assert_eq!(
        validate_schema(&schema, &schema, &wrong_type),
        Err("no anyOf branch accepted the value".to_owned())
    );
}

#[test]
fn generated_schema_enforces_literal_false_and_secret_reference_patterns() {
    let schema: Value =
        serde_json::from_str(&openclaw_schema_json().expect("schema")).expect("schema JSON");
    let valid: Value = json5::from_str(
        r#"
        {
          cron: { sessionRetention: false },
          gateway: {
            auth: {
              token: { source: "env", provider: "default", id: "GATEWAY_TOKEN" },
            },
          },
        }
        "#,
    )
    .expect("valid schema instance");
    assert_eq!(validate_schema(&schema, &schema, &valid), Ok(()));

    for invalid in [
        r"{ cron: { sessionRetention: true } }",
        r#"{ gateway: { auth: { token: { source: "env", provider: "Default", id: "TOKEN" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "env", provider: "default", id: "mixedCase" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "file", provider: "default", id: "/bad/~2escape" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "exec", provider: "default", id: "secret/../escape" } } } }"#,
    ] {
        let instance: Value = json5::from_str(invalid).expect("invalid schema instance");
        assert_ne!(validate_schema(&schema, &schema, &instance), Ok(()));
    }
}

#[test]
fn frozen_wire_literals_and_nested_shapes_round_trip_exactly() {
    let source = r#"
    {
      acp: {
        stream: {
          coalesceIdleMs: 25,
          maxChunkChars: 200,
          deliveryMode: "final_only",
          hiddenBoundarySeparator: "paragraph",
          maxOutputChars: 4000,
          maxSessionUpdateChars: 500,
        },
        runtime: { ttlMinutes: 30 },
      },
      agents: {
        defaults: {
          skipOptionalBootstrapFiles: ["SOUL.md", "USER.md", "HEARTBEAT.md", "IDENTITY.md"],
          timeFormat: "12",
        },
      },
      bindings: [
        { agentId: "route", match: { channel: "discord" } },
        {
          type: "acp",
          agentId: "acp",
          match: { channel: "discord", peer: { kind: "direct", id: "user-1" } },
          acp: { mode: "persistent" },
        },
      ],
      gateway: {
        push: { apns: { relay: { baseUrl: "https://relay.example.test", timeoutMs: 2500 } } },
      },
      models: {
        providers: {
          local: { injectNumCtxForOpenAICompat: true },
        },
      },
      mcp: {
        servers: {
          primary: {
            connectionTimeoutMs: 1000,
            supportsParallelToolCalls: true,
            ssl_verify: false,
            client_cert: "client.crt",
            client_key: "client.key",
            codex: { default_tools_approval_mode: "prompt" },
          },
        },
      },
    }
    "#;
    let config = parse_openclaw_json5(source, "wire-values.json5").expect("frozen wire values");
    let encoded = openclaw_to_json5(&config).expect("encode frozen wire values");
    let value: Value = json5::from_str(&encoded).expect("encoded JSON5");

    assert_eq!(value["acp"]["stream"]["deliveryMode"], "final_only");
    assert_eq!(
        value["agents"]["defaults"]["skipOptionalBootstrapFiles"],
        serde_json::json!(["SOUL.md", "USER.md", "HEARTBEAT.md", "IDENTITY.md"])
    );
    assert_eq!(value["agents"]["defaults"]["timeFormat"], "12");
    assert_eq!(
        value["gateway"]["push"]["apns"]["relay"]["baseUrl"],
        "https://relay.example.test"
    );
    assert_eq!(
        value["models"]["providers"]["local"]["injectNumCtxForOpenAICompat"],
        true
    );
    assert_eq!(value["mcp"]["servers"]["primary"]["ssl_verify"], false);
    assert_eq!(
        value["mcp"]["servers"]["primary"]["codex"]["default_tools_approval_mode"],
        "prompt"
    );
}

#[test]
fn closed_unions_reject_hybrid_secret_providers_and_incomplete_acp_bindings() {
    let manual = r#"{ secrets: { providers: { vault: { source: "exec", command: "vault" } } } }"#;
    let plugin = r#"
    {
      secrets: {
        providers: {
          vault: {
            source: "exec",
            pluginIntegration: { pluginId: "vault", integrationId: "read" },
          },
        },
      },
    }
    "#;
    parse_openclaw_json5(manual, "manual.json5").expect("manual provider");
    parse_openclaw_json5(plugin, "plugin.json5").expect("plugin provider");

    let hybrid = r#"
    {
      secrets: {
        providers: {
          vault: {
            source: "exec",
            command: "vault",
            pluginIntegration: { pluginId: "vault", integrationId: "read" },
          },
        },
      },
    }
    "#;
    let hybrid_error =
        parse_openclaw_json5(hybrid, "hybrid.json5").expect_err("hybrid provider must fail");
    match hybrid_error {
        ConfigError::Decode {
            source_name,
            path,
            message,
        } => {
            assert_eq!(source_name, "hybrid.json5");
            assert_eq!(path, "secrets.providers.vault");
            assert_ne!(message, "");
        }
        other => panic!("expected decode error, got {other}"),
    }

    let binding = r#"
    {
      bindings: [
        { type: "acp", agentId: "acp", match: { channel: "discord" } },
      ],
    }
    "#;
    let binding_error =
        parse_openclaw_json5(binding, "binding.json5").expect_err("ACP peer must be concrete");
    match binding_error {
        ConfigError::Validation { path, message } => {
            assert_eq!(path, "bindings[0].match.peer");
            assert_eq!(message, "ACP bindings require a non-empty match.peer.id");
        }
        other => panic!("expected validation error, got {other}"),
    }

    let cross_variant =
        r#"{ secrets: { providers: { default: { source: "env", path: "secrets.json" } } } }"#;
    let cross_variant_error = parse_openclaw_json5(cross_variant, "cross-variant.json5")
        .expect_err("cross-variant fields must fail");
    match cross_variant_error {
        ConfigError::Decode {
            source_name,
            path,
            message,
        } => {
            assert_eq!(source_name, "cross-variant.json5");
            assert_eq!(path, "secrets.providers.default");
            assert_ne!(message, "");
        }
        other => panic!("expected decode error, got {other}"),
    }
}

#[test]
fn model_contract_requires_catalog_fields_and_types_secret_request_headers() {
    let source = r#"
    {
      models: {
        providers: {
          private: {
            baseUrl: "https://models.example.test",
            request: {
              headers: {
                "X-Api-Key": { source: "env", provider: "default", id: "MODEL_HEADER" },
              },
              auth: {
                mode: "authorization-bearer",
                token: { source: "env", provider: "default", id: "MODEL_TOKEN" },
              },
              proxy: { mode: "env-proxy" },
              tls: { serverName: "models.example.test" },
              allowPrivateNetwork: false,
            },
            models: [{
              id: "model-1",
              name: "Model One",
              reasoning: true,
              input: ["text", "image"],
              cost: {
                input: 1.0,
                output: 2.0,
                cacheRead: 0.1,
                cacheWrite: 0.2,
                tieredPricing: [{
                  input: 1.0,
                  output: 2.0,
                  cacheRead: 0.1,
                  cacheWrite: 0.2,
                  range: [0, 100000],
                }],
              },
              contextWindow: 128000,
              maxTokens: 8192,
              thinkingLevelMap: {
                off: null,
                minimal: "low",
                max: "extreme",
              },
              agentRuntime: { id: "openclaw" },
              compat: {
                supportsTools: true,
                maxTokensField: "max_completion_tokens",
                thinkingFormat: "qwen-chat-template",
              },
              mediaInput: {
                image: { maxBytes: 10000000, tokenMode: "tile" },
              },
            }],
          },
        },
      },
    }
    "#;
    let config = parse_openclaw_json5(source, "models.json5").expect("exact model contract");
    let encoded = openclaw_to_json5(&config).expect("serialize model references");
    assert!(encoded.contains("\"MODEL_HEADER\""));
    assert!(encoded.contains("\"MODEL_TOKEN\""));
    assert!(!encoded.contains("[REDACTED]"));
    let encoded_value: Value = json5::from_str(&encoded).expect("encoded model JSON5");
    assert_eq!(
        encoded_value["models"]["providers"]["private"]["models"][0]["thinkingLevelMap"]["off"],
        Value::Null
    );
    assert_eq!(
        encoded_value["models"]["providers"]["private"]["models"][0]["agentRuntime"]["id"],
        "openclaw"
    );
    assert_eq!(
        parse_openclaw_json5(&encoded, "models-round-trip.json5").expect("round trip"),
        config
    );

    let missing_required = source.replace("reasoning: true,", "");
    let error = parse_openclaw_json5(&missing_required, "missing-model-field.json5")
        .expect_err("required model field");
    match error {
        ConfigError::Decode {
            source_name,
            path,
            message,
        } => {
            assert_eq!(source_name, "missing-model-field.json5");
            assert_eq!(path, "models.providers.private.models[0]");
            assert!(message.contains("reasoning"));
        }
        other => panic!("expected decode error, got {other}"),
    }

    let typo = source.replace("supportsTools: true", "supportsToolz: true");
    let typo_error =
        parse_openclaw_json5(&typo, "model-compat-typo.json5").expect_err("compat is strict");
    match typo_error {
        ConfigError::Decode {
            source_name,
            path,
            message,
        } => {
            assert_eq!(source_name, "model-compat-typo.json5");
            assert_eq!(
                path,
                "models.providers.private.models[0].compat.supportsToolz"
            );
            assert_ne!(message, "");
        }
        other => panic!("expected decode error, got {other}"),
    }
}

#[test]
fn mixed_case_and_snake_case_wire_enums_match_the_frozen_contract() {
    let config = parse_openclaw_json5(
        r#"
        {
          secrets: {
            providers: {
              file: { source: "file", path: "secret.txt", mode: "singleValue" },
            },
          },
          cron: { retry: { retryOn: ["rate_limit", "server_error"] } },
        }
        "#,
        "wire-enums.json5",
    )
    .expect("frozen enum values");
    let encoded = openclaw_to_json5(&config).expect("encode enums");
    assert!(encoded.contains("\"singleValue\""));
    assert!(encoded.contains("\"rate_limit\""));
    assert!(encoded.contains("\"server_error\""));
    for invalid in ["single-value", "rate-limit", "server-error"] {
        let source = if invalid == "single-value" {
            r#"{ secrets: { providers: { file: { source: "file", path: "x", mode: "single-value" } } } }"#
                .to_owned()
        } else {
            format!(r#"{{ cron: {{ retry: {{ retryOn: ["{invalid}"] }} }} }}"#)
        };
        assert!(
            parse_openclaw_json5(&source, "invalid-wire-enum.json5").is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn domain_secret_inputs_never_leak_through_debug_or_serialization() {
    let config = parse_openclaw_json5(
        r#"
        {
          gateway: { auth: { token: "gateway-super-secret" } },
          models: {
            providers: {
              primary: {
                apiKey: "model-super-secret",
                localService: {
                  command: "serve-model",
                  env: {
                    SERVICE_TOKEN: "local-service-secret",
                    SHARED_TOKEN: {
                      source: "env",
                      provider: "default",
                      id: "SHARED_TOKEN",
                    },
                  },
                },
              },
            },
          },
        }
        "#,
        "secrets.json5",
    )
    .expect("secret-bearing domains");

    let debug = format!("{config:?}");
    let encoded = openclaw_to_json5(&config).expect("serialize redacted config");
    for secret in [
        "gateway-super-secret",
        "model-super-secret",
        "local-service-secret",
    ] {
        assert!(!debug.contains(secret));
        assert!(!encoded.contains(secret));
    }
    assert!(debug.contains("SecretInput([REDACTED])"));
    assert!(encoded.contains("[REDACTED]"));
    assert!(encoded.contains("\"SHARED_TOKEN\""));
}

#[test]
fn domain_secret_references_enforce_source_specific_identifiers() {
    for source in [
        r#"{ gateway: { auth: { token: { source: "env", provider: "default", id: "TOKEN_1" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "file", provider: "mounted", id: "/tokens/~0primary/~1id" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "exec", provider: "vault-1", id: "secret/path:#1" } } } }"#,
    ] {
        parse_openclaw_json5(source, "valid-reference.json5").expect("valid secret reference");
    }

    for source in [
        r#"{ gateway: { auth: { token: { source: "env", provider: "Default", id: "TOKEN" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "env", provider: "default", id: "mixedCase" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "file", provider: "default", id: "relative" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "file", provider: "default", id: "/bad/~2escape" } } } }"#,
        r#"{ gateway: { auth: { token: { source: "exec", provider: "default", id: "secret/../escape" } } } }"#,
    ] {
        let error = parse_openclaw_json5(source, "invalid-reference.json5")
            .expect_err("invalid source-specific reference");
        match error {
            ConfigError::Decode {
                source_name,
                path,
                message,
            } => {
                assert_eq!(source_name, "invalid-reference.json5");
                assert_eq!(path, "gateway.auth.token");
                assert_ne!(message, "");
            }
            other => panic!("expected decode error, got {other}"),
        }

        let reference = DomainSecretRef::new(SecretSource::Env, "default", "TOKEN_1")
            .expect("programmatic reference");
        assert_eq!(reference.source(), SecretSource::Env);
        assert_eq!(reference.provider(), "default");
        assert_eq!(reference.id(), "TOKEN_1");
        assert_eq!(
            DomainSecretRef::new(SecretSource::Env, "Default", "mixedCase"),
            Err("secret provider must match [a-z][a-z0-9_-]{0,63}")
        );
    }
}

#[test]
fn false_only_and_object_only_unions_reject_broader_json_types() {
    for (source, expected_path) in [
        (
            r"{ cron: { sessionRetention: true } }",
            "cron.sessionRetention",
        ),
        (
            r"{ gateway: { http: { securityHeaders: { strictTransportSecurity: true } } } }",
            "gateway.http.securityHeaders.strictTransportSecurity",
        ),
        (
            r"{ session: { maintenance: { resetArchiveRetention: true } } }",
            "session.maintenance.resetArchiveRetention",
        ),
        (
            r"{ session: { maintenance: { maxDiskBytes: true } } }",
            "session.maintenance.maxDiskBytes",
        ),
        (
            r"{ messages: { usageTemplate: 42 } }",
            "messages.usageTemplate",
        ),
    ] {
        let error = parse_openclaw_json5(source, "strict-union.json5").expect_err("strict union");
        match error {
            ConfigError::Decode {
                source_name,
                path,
                message,
            } => {
                assert_eq!(source_name, "strict-union.json5");
                assert_eq!(path, expected_path);
                assert_ne!(message, "");
            }
            other => panic!("expected decode error, got {other}"),
        }
    }

    parse_openclaw_json5(
        r#"
        {
          session: {
            maintenance: {
              resetArchiveRetention: false,
              maxDiskBytes: false,
            },
          },
          cron: { sessionRetention: false },
          gateway: {
            http: {
              securityHeaders: { strictTransportSecurity: false },
            },
          },
          tools: {
            web: { search: { enabled: true } },
          },
          messages: { usageTemplate: { input: "search" } },
        }
        "#,
        "strict-union-valid.json5",
    )
    .expect("literal false and object values");
}

#[test]
fn source_domain_precedence_is_exhaustive_and_nested_objects_merge() {
    for mask in 0_u8..32 {
        let mut layers = OpenClawConfigLayers::new();
        if mask & 1 != 0 {
            layers = layers
                .with_system_json5(r"{ gateway: { port: 10001, controlUi: { enabled: true } } }");
        }
        if mask & 2 != 0 {
            layers = layers.with_user_json5(
                r#"{ gateway: { port: 10002, controlUi: { basePath: "/user" } } }"#,
            );
        }
        if mask & 4 != 0 {
            layers = layers.with_workspace_json5(
                r"{ gateway: { port: 10003, controlUi: { toolTitles: true } } }",
            );
        }
        if mask & 8 != 0 {
            layers = layers.with_environment([("PORT", "10004")]);
        }
        if mask & 16 != 0 {
            layers = layers.with_command_line_json5(
                r#"{ gateway: { port: 10005, controlUi: { allowedOrigins: ["local"] } } }"#,
            );
        }

        let resolved = layers.resolve().expect("resolve source-domain layers");
        let expected_port = if mask & 16 != 0 {
            Some(10_005)
        } else if mask & 8 != 0 {
            Some(10_004)
        } else if mask & 4 != 0 {
            Some(10_003)
        } else if mask & 2 != 0 {
            Some(10_002)
        } else if mask & 1 != 0 {
            Some(10_001)
        } else {
            None
        };
        assert_eq!(
            resolved
                .config
                .gateway
                .as_ref()
                .and_then(|gateway| gateway.port),
            expected_port,
            "mask {mask:05b}"
        );

        let mut expected_layers = vec![ConfigLayerKind::BuiltIn];
        if mask & 1 != 0 {
            expected_layers.push(ConfigLayerKind::System);
        }
        if mask & 2 != 0 {
            expected_layers.push(ConfigLayerKind::User);
        }
        if mask & 4 != 0 {
            expected_layers.push(ConfigLayerKind::Workspace);
        }
        if mask & 8 != 0 {
            expected_layers.push(ConfigLayerKind::Environment);
        }
        if mask & 16 != 0 {
            expected_layers.push(ConfigLayerKind::CommandLine);
        }
        assert_eq!(resolved.applied_layers, expected_layers, "mask {mask:05b}");

        let control_ui = resolved
            .config
            .gateway
            .as_ref()
            .and_then(|gateway| gateway.control_ui.as_ref());
        assert_eq!(
            control_ui.and_then(|control_ui| control_ui.enabled),
            (mask & 1 != 0).then_some(true)
        );
        assert_eq!(
            control_ui.and_then(|control_ui| control_ui.base_path.as_deref()),
            (mask & 2 != 0).then_some("/user")
        );
        assert_eq!(
            control_ui.and_then(|control_ui| control_ui.tool_titles),
            (mask & 4 != 0).then_some(true)
        );
        assert_eq!(
            control_ui
                .and_then(|control_ui| control_ui.allowed_origins.as_ref())
                .is_some_and(|origins| origins == &["local"]),
            mask & 16 != 0
        );
    }
}

#[test]
fn source_environment_projection_uses_typed_references_and_cli_wins() {
    let resolved = OpenClawConfigLayers::new()
        .with_environment([
            ("ENABLE_TELEGRAM", "true"),
            ("TELEGRAM_BOT_TOKEN", "plaintext-never-persist"),
            ("TELEGRAM_POLL_INTERVAL_MS", "2000ms"),
            ("HTTPS_PROXY", "http://user:password@proxy.example.test"),
            ("LOG_LEVEL", "debug"),
        ])
        .with_command_line_json5(
            r#"{ channels: { telegram: { enabled: false } }, logging: { level: "trace" } }"#,
        )
        .resolve()
        .expect("resolve projected legacy environment");

    let telegram = resolved
        .config
        .channels
        .as_ref()
        .and_then(|channels| channels.telegram.as_ref())
        .expect("telegram config");
    assert_eq!(telegram.enabled, Some(false));
    assert!(telegram.bot_token.is_some());
    assert_eq!(telegram.poll_interval_ms, Some(2_000));
    assert_eq!(
        resolved
            .config
            .logging
            .as_ref()
            .and_then(|logging| logging.level),
        Some(claw_config::domains::LogLevel::Trace)
    );
    let debug = format!("{resolved:?}");
    let encoded = openclaw_to_json5(&resolved.config).expect("redacted serialization");
    assert!(!debug.contains("plaintext-never-persist"));
    assert!(!debug.contains("password@proxy"));
    assert!(!encoded.contains("plaintext-never-persist"));
    assert!(!encoded.contains("password@proxy"));
    assert_eq!(
        parse_openclaw_json5(&encoded, "projected-round-trip.json5").expect("reference round trip"),
        resolved.config
    );

    let error = OpenClawConfigLayers::new()
        .with_environment([("ENABLE_DISCORD", "TRUE")])
        .resolve()
        .expect_err("legacy booleans are exact");
    match error {
        LayeredConfigError::Layer {
            layer,
            error: ConfigError::Validation { path, message },
        } => {
            assert_eq!(layer, ConfigLayerKind::Environment);
            assert_eq!(path, "ENABLE_DISCORD");
            assert_eq!(message, "must be exactly `true` or `false`");
        }
        other => panic!("expected environment layer validation, got {other}"),
    }

    let auto_update = OpenClawConfigLayers::new()
        .with_environment([("AUTO_UPDATE", "true")])
        .resolve()
        .expect_err("automatic mutation must fail closed");
    match auto_update {
        LayeredConfigError::Layer {
            layer,
            error: ConfigError::Validation { path, message },
        } => {
            assert_eq!(layer, ConfigLayerKind::Environment);
            assert_eq!(path, "AUTO_UPDATE");
            assert_eq!(
                message,
                "true is unsupported because dependency updates are review-only"
            );
        }
        other => panic!("expected AUTO_UPDATE environment validation, got {other}"),
    }

    let out_of_range = OpenClawConfigLayers::new()
        .with_environment([("TELEGRAM_POLL_INTERVAL_MS", "499ms")])
        .resolve()
        .expect_err("legacy range is enforced");
    match out_of_range {
        LayeredConfigError::Layer {
            layer,
            error: ConfigError::Validation { path, message },
        } => {
            assert_eq!(layer, ConfigLayerKind::Environment);
            assert_eq!(path, "TELEGRAM_POLL_INTERVAL_MS");
            assert_eq!(message, "must be from 500 through 60000");
        }
        other => panic!("expected environment range validation, got {other}"),
    }

    let invalid_log_level = OpenClawConfigLayers::new()
        .with_environment([("LOG_LEVEL", "silent")])
        .resolve()
        .expect_err("source-only log level is invalid for legacy mapping");
    match invalid_log_level {
        LayeredConfigError::Layer {
            layer,
            error: ConfigError::Validation { path, message },
        } => {
            assert_eq!(layer, ConfigLayerKind::Environment);
            assert_eq!(path, "LOG_LEVEL");
            assert_eq!(
                message,
                "must be one of trace, debug, info, warn, error, fatal"
            );
        }
        other => panic!("expected log-level validation, got {other}"),
    }
}

#[test]
fn source_environment_strings_trim_and_apply_frozen_empty_defaults() {
    let resolved = OpenClawConfigLayers::new()
        .with_environment([
            ("MicrosoftAppId", "  teams-app  "),
            ("DISCORD_GATEWAY_URL", " \t "),
            ("WHATSAPP_PHONE_NUMBER_ID", " 15551234 "),
            ("WHATSAPP_WEBHOOK_PATH", " "),
            ("MicrosoftAppPassword", "must-not-be-persisted"),
            ("https_proxy", "must-not-be-persisted"),
        ])
        .resolve()
        .expect("legacy string projection");
    let value: Value = json5::from_str(
        &openclaw_to_json5(&resolved.config).expect("serialize projected environment"),
    )
    .expect("projected JSON5");

    assert_eq!(value["channels"]["msteams"]["appId"], "teams-app");
    assert_eq!(
        value["channels"]["discord"]["gatewayUrl"],
        "wss://gateway.discord.gg/?v=10&encoding=json"
    );
    assert_eq!(value["channels"]["whatsapp"]["phoneNumberId"], "15551234");
    assert_eq!(
        value["channels"]["whatsapp"]["webhookPath"],
        "/whatsapp/webhook"
    );
    assert_eq!(value["channels"]["msteams"]["appPassword"], "[REDACTED]");
    assert_eq!(value["proxy"]["proxyUrl"], "[REDACTED]");
    let encoded = value.to_string();
    assert!(!encoded.contains("must-not-be-persisted"));
}

#[test]
fn source_layer_debug_never_exposes_unparsed_secret_inputs() {
    let layers = OpenClawConfigLayers::new()
        .with_system_json5(r#"{ gateway: { auth: { token: "system-secret" } } }"#)
        .with_user_json5(r#"{ models: { providers: { p: { apiKey: "user-secret" } } } }"#)
        .with_workspace_json5(r#"{ proxy: { proxyUrl: "workspace-secret" } }"#)
        .with_environment([("TELEGRAM_BOT_TOKEN", "environment-secret")])
        .with_command_line_json5(r#"{ gateway: { auth: { password: "cli-secret" } } }"#);
    let debug = format!("{layers:?}");

    for secret in [
        "system-secret",
        "user-secret",
        "workspace-secret",
        "environment-secret",
        "cli-secret",
    ] {
        assert!(!debug.contains(secret));
    }
    assert_eq!(
        debug,
        "OpenClawConfigLayers { system_configured: true, user_configured: true, workspace_configured: true, environment_count: 1, command_line_configured: true }"
    );
}

#[test]
fn higher_precedence_closed_union_variants_replace_instead_of_hybridizing() {
    let resolved = OpenClawConfigLayers::new()
        .with_system_json5(
            r#"
            {
              secrets: {
                providers: {
                  vault: { source: "exec", command: "vault", args: ["read"] },
                  mounted: { source: "file", path: "system.json" },
                },
              },
              models: {
                providers: {
                  private: {
                    request: {
                      auth: {
                        mode: "authorization-bearer",
                        token: { source: "env", provider: "default", id: "TOKEN" },
                      },
                      proxy: {
                        mode: "explicit-proxy",
                        url: "https://proxy.example.test",
                      },
                    },
                  },
                },
              },
            }
            "#,
        )
        .with_user_json5(
            r#"
            {
              secrets: {
                providers: {
                  vault: {
                    source: "exec",
                    pluginIntegration: { pluginId: "vault", integrationId: "read" },
                  },
                  mounted: { source: "env", allowlist: ["MOUNTED_SECRET"] },
                },
              },
              models: {
                providers: {
                  private: {
                    request: {
                      auth: { mode: "provider-default" },
                      proxy: { mode: "env-proxy" },
                    },
                  },
                },
              },
            }
            "#,
        )
        .resolve()
        .expect("replace closed variants");
    let value: Value =
        json5::from_str(&openclaw_to_json5(&resolved.config).expect("serialize replaced variants"))
            .expect("JSON5");
    let vault = &value["secrets"]["providers"]["vault"];
    assert!(vault.get("command").is_none());
    assert_eq!(vault["pluginIntegration"]["pluginId"], "vault");
    let mounted = &value["secrets"]["providers"]["mounted"];
    assert!(mounted.get("path").is_none());
    assert_eq!(mounted["source"], "env");
    let request = &value["models"]["providers"]["private"]["request"];
    assert_eq!(request["auth"]["mode"], "provider-default");
    assert!(request["auth"].get("token").is_none());
    assert_eq!(request["proxy"]["mode"], "env-proxy");
    assert!(request["proxy"].get("url").is_none());
}

#[test]
fn extension_objects_with_discriminator_like_keys_still_merge_recursively() {
    let resolved = OpenClawConfigLayers::new()
        .with_system_json5(
            r#"
            {
              plugins: {
                entries: {
                  demo: {
                    config: {
                      type: "oauth",
                      endpoint: "https://plugin.example.test",
                    },
                  },
                },
              },
            }
            "#,
        )
        .with_user_json5(
            r#"
            {
              plugins: {
                entries: {
                  demo: {
                    config: {
                      type: "api-key",
                      audience: "plugin",
                    },
                  },
                },
              },
            }
            "#,
        )
        .resolve()
        .expect("merge extension object");
    let value: Value =
        json5::from_str(&openclaw_to_json5(&resolved.config).expect("serialize merged config"))
            .expect("merged JSON5");
    assert_eq!(
        value["plugins"]["entries"]["demo"]["config"],
        serde_json::json!({
            "type": "api-key",
            "endpoint": "https://plugin.example.test",
            "audience": "plugin",
        })
    );
}

#[test]
fn source_hot_reload_is_typed_transactional_and_tear_free() {
    let initial = parse_openclaw_json5(
        r#"{ gateway: { port: 10001 }, logging: { level: "info" } }"#,
        "a",
    )
    .expect("initial source");
    let hub = OpenClawConfigHub::new(initial);
    let subscription = hub.subscribe().expect("subscribe");
    let change = hub
        .reload_json5(
            r#"{ gateway: { port: 10002 }, logging: { level: "info" } }"#,
            "b",
        )
        .expect("publish valid source");
    assert_eq!(change.changed_domains, vec![OpenClawDomain::Gateway]);
    assert_eq!(
        subscription.recv().expect("notification").changed_domains,
        vec![OpenClawDomain::Gateway]
    );

    let before_rejection = hub.snapshot().expect("snapshot before rejection");
    let error = hub
        .reload_json5(r"{ gateway: { port: 0 } }", "invalid")
        .expect_err("invalid candidate");
    match error {
        claw_config::ConfigHubError::Config(ConfigError::Validation { path, message }) => {
            assert_eq!(path, "gateway.port");
            assert_eq!(message, "must be from 1 through 65535");
        }
        other => panic!("expected validation error, got {other}"),
    }
    assert_eq!(
        hub.snapshot().expect("snapshot after rejection"),
        before_rejection
    );

    let readers = 4;
    let iterations = 200;
    let start = Arc::new(Barrier::new(readers + 1));
    let mut handles = Vec::new();
    for _ in 0..readers {
        let reader_hub = hub.clone();
        let reader_start = Arc::clone(&start);
        handles.push(thread::spawn(move || {
            reader_start.wait();
            for _ in 0..iterations {
                let snapshot = reader_hub.snapshot().expect("reader snapshot");
                let port = snapshot
                    .gateway
                    .as_ref()
                    .and_then(|gateway| gateway.port)
                    .expect("gateway port");
                let level = snapshot
                    .logging
                    .as_ref()
                    .and_then(|logging| logging.level)
                    .expect("logging level");
                assert!(
                    (port == 10_002 && level == claw_config::domains::LogLevel::Info)
                        || (port == 20_001 && level == claw_config::domains::LogLevel::Debug)
                        || (port == 20_002 && level == claw_config::domains::LogLevel::Trace)
                );
            }
        }));
    }
    start.wait();
    for index in 0..iterations {
        let (port, level) = if index % 2 == 0 {
            (20_001, "debug")
        } else {
            (20_002, "trace")
        };
        hub.reload_json5(
            &format!(r#"{{ gateway: {{ port: {port} }}, logging: {{ level: "{level}" }} }}"#),
            "concurrent",
        )
        .expect("concurrent publication");
    }
    for handle in handles {
        handle.join().expect("reader thread");
    }
}

#[test]
fn slow_source_subscribers_receive_only_the_latest_bounded_change() {
    let initial =
        parse_openclaw_json5(r"{ gateway: { port: 10000 } }", "initial").expect("initial");
    let hub = OpenClawConfigHub::new(initial);
    let subscription = hub.subscribe().expect("subscribe");

    for port in 10_001..=11_000 {
        let logging = if port >= 10_500 {
            r#", logging: { level: "debug" }"#
        } else {
            ""
        };
        hub.reload_json5(
            &format!(r"{{ gateway: {{ port: {port} }} {logging} }}"),
            "coalesced",
        )
        .expect("publish");
    }

    let latest = subscription.recv().expect("latest notification");
    assert_eq!(
        latest
            .current
            .gateway
            .as_ref()
            .and_then(|gateway| gateway.port),
        Some(11_000)
    );
    assert_eq!(
        latest.changed_domains,
        vec![OpenClawDomain::Logging, OpenClawDomain::Gateway]
    );
    assert_eq!(
        latest
            .previous
            .gateway
            .as_ref()
            .and_then(|gateway| gateway.port),
        Some(10_000)
    );
    assert_eq!(
        subscription.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
}

#[test]
fn source_file_watcher_retains_last_known_good_bytes() {
    let directory = common::TestDirectory::create();
    let path = directory.path().join("openclaw.json5");
    std::fs::write(&path, r"{ gateway: { port: 18001 } }").expect("write initial source");
    let mut watcher = OpenClawConfigFileWatcher::from_file(&path).expect("create watcher");
    let subscription = watcher.hub().subscribe().expect("subscribe");

    std::fs::write(&path, r"{ gateway: { port: 18002 } }").expect("write changed source");
    let change = watcher.poll().expect("poll valid change").expect("change");
    assert_eq!(change.changed_domains, vec![OpenClawDomain::Gateway]);
    assert_eq!(
        subscription
            .recv()
            .expect("watch notification")
            .changed_domains,
        vec![OpenClawDomain::Gateway]
    );

    std::fs::write(&path, b"{ gateway: { port: ").expect("write genuinely truncated source");
    watcher.poll().expect_err("truncated source rejected");
    assert_eq!(
        watcher
            .hub()
            .snapshot()
            .expect("last-known-good source")
            .gateway
            .as_ref()
            .and_then(|gateway| gateway.port),
        Some(18_002)
    );

    std::fs::write(&path, r"{ gateway: { port: 18003 } }").expect("repair source");
    let repaired = watcher
        .poll()
        .expect("poll repaired source")
        .expect("change");
    assert_eq!(
        repaired
            .current
            .gateway
            .as_ref()
            .and_then(|gateway| gateway.port),
        Some(18_003)
    );
}

#[test]
fn every_frozen_domain_enforces_a_concrete_value_type() {
    let cases = [
        (
            "$schema",
            r#""https://example.test/schema.json""#,
            "1",
            "$schema",
        ),
        (
            "meta",
            r#"{ lastTouchedVersion: "2026.7.2" }"#,
            "{ lastTouchedVersion: 1 }",
            "meta.lastTouchedVersion",
        ),
        (
            "auth",
            r#"{ profiles: { primary: { provider: "openai", mode: "token" } } }"#,
            r#"{ profiles: { primary: { provider: 1, mode: "token" } } }"#,
            "auth.profiles.primary.provider",
        ),
        (
            "accessGroups",
            r#"{ owners: { type: "message.senders", members: { "*": ["alice"] } } }"#,
            r#"{ owners: { type: "message.senders", members: { "*": [1] } } }"#,
            "accessGroups.owners",
        ),
        ("acp", "{ enabled: true }", "{ enabled: 1 }", "acp.enabled"),
        (
            "env",
            r#"{ GTA_TEST: "yes" }"#,
            "{ GTA_TEST: 1 }",
            "env.GTA_TEST",
        ),
        (
            "wizard",
            r#"{ lastRunMode: "local" }"#,
            "{ lastRunMode: 1 }",
            "wizard.lastRunMode",
        ),
        (
            "diagnostics",
            "{ enabled: true }",
            "{ enabled: 1 }",
            "diagnostics.enabled",
        ),
        (
            "logging",
            r#"{ level: "info" }"#,
            "{ level: 1 }",
            "logging.level",
        ),
        (
            "audit",
            "{ enabled: true }",
            "{ enabled: 1 }",
            "audit.enabled",
        ),
        (
            "security",
            "{ installPolicy: { enabled: true } }",
            "{ installPolicy: { enabled: 1 } }",
            "security.installPolicy.enabled",
        ),
        (
            "cli",
            r#"{ banner: { taglineMode: "random" } }"#,
            "{ banner: { taglineMode: 1 } }",
            "cli.banner.taglineMode",
        ),
        (
            "crestodian",
            "{ rescue: { pendingTtlMinutes: 15 } }",
            r#"{ rescue: { pendingTtlMinutes: "15" } }"#,
            "crestodian.rescue.pendingTtlMinutes",
        ),
        (
            "update",
            r#"{ channel: "stable" }"#,
            "{ channel: 1 }",
            "update.channel",
        ),
        (
            "browser",
            "{ enabled: true }",
            "{ enabled: 1 }",
            "browser.enabled",
        ),
        (
            "ui",
            r##"{ seamColor: "#12aBc9" }"##,
            "{ seamColor: 1 }",
            "ui.seamColor",
        ),
        (
            "tui",
            "{ footer: { showRemoteHost: true } }",
            "{ footer: { showRemoteHost: 1 } }",
            "tui.footer.showRemoteHost",
        ),
        (
            "secrets",
            r#"{ defaults: { env: "default" } }"#,
            "{ defaults: { env: 1 } }",
            "secrets.defaults.env",
        ),
        (
            "marketplaces",
            r#"{ feeds: { primary: { url: "https://example.test/feed.json" } } }"#,
            "{ feeds: { primary: { url: 1 } } }",
            "marketplaces.feeds.primary.url",
        ),
        (
            "skills",
            "{ load: { watch: true } }",
            "{ load: { watch: 1 } }",
            "skills.load.watch",
        ),
        (
            "plugins",
            "{ enabled: true }",
            "{ enabled: 1 }",
            "plugins.enabled",
        ),
        (
            "surfaces",
            r#"{ chat: { silentReply: { group: "allow" } } }"#,
            "{ chat: { silentReply: { group: 1 } } }",
            "surfaces.chat.silentReply.group",
        ),
        (
            "models",
            r#"{ mode: "merge" }"#,
            "{ mode: 1 }",
            "models.mode",
        ),
        (
            "nodeHost",
            "{ browserProxy: { enabled: true } }",
            "{ browserProxy: { enabled: 1 } }",
            "nodeHost.browserProxy.enabled",
        ),
        (
            "agents",
            "{ defaults: { maxConcurrent: 2 } }",
            r#"{ defaults: { maxConcurrent: "2" } }"#,
            "agents.defaults.maxConcurrent",
        ),
        (
            "tools",
            r#"{ profile: "coding" }"#,
            "{ profile: 1 }",
            "tools.profile",
        ),
        (
            "bindings",
            r#"[{ agentId: "main", match: { channel: "discord" } }]"#,
            r#"[{ agentId: 1, match: { channel: "discord" } }]"#,
            "bindings[0].agentId",
        ),
        (
            "broadcast",
            r#"{ strategy: "parallel" }"#,
            "{ strategy: 1 }",
            "broadcast.strategy",
        ),
        (
            "audio",
            r#"{ transcription: { command: ["whisper"] } }"#,
            r#"{ transcription: { command: "whisper" } }"#,
            "audio.transcription.command",
        ),
        (
            "media",
            "{ preserveFilenames: true }",
            "{ preserveFilenames: 1 }",
            "media.preserveFilenames",
        ),
        (
            "messages",
            r#"{ ackReaction: "eyes" }"#,
            "{ ackReaction: 1 }",
            "messages.ackReaction",
        ),
        (
            "commands",
            r#"{ native: "auto" }"#,
            "{ native: 1 }",
            "commands.native",
        ),
        (
            "approvals",
            "{ exec: { enabled: true } }",
            "{ exec: { enabled: 1 } }",
            "approvals.exec.enabled",
        ),
        (
            "session",
            r#"{ scope: "per-sender" }"#,
            "{ scope: 1 }",
            "session.scope",
        ),
        ("web", "{ enabled: true }", "{ enabled: 1 }", "web.enabled"),
        (
            "channels",
            r#"{ defaults: { groupPolicy: "open" } }"#,
            "{ defaults: { groupPolicy: 1 } }",
            "channels.defaults.groupPolicy",
        ),
        (
            "cron",
            "{ maxConcurrentRuns: 2 }",
            r#"{ maxConcurrentRuns: "2" }"#,
            "cron.maxConcurrentRuns",
        ),
        (
            "transcripts",
            "{ maxUtterances: 2000 }",
            r#"{ maxUtterances: "2000" }"#,
            "transcripts.maxUtterances",
        ),
        (
            "commitments",
            "{ maxPerDay: 3 }",
            r#"{ maxPerDay: "3" }"#,
            "commitments.maxPerDay",
        ),
        (
            "hooks",
            "{ enabled: true }",
            "{ enabled: 1 }",
            "hooks.enabled",
        ),
        (
            "discovery",
            r#"{ mdns: { mode: "full" } }"#,
            "{ mdns: { mode: 1 } }",
            "discovery.mdns.mode",
        ),
        (
            "talk",
            "{ silenceTimeoutMs: 500 }",
            r#"{ silenceTimeoutMs: "500" }"#,
            "talk.silenceTimeoutMs",
        ),
        ("gateway", "{ port: 18789 }", "{ port: 0 }", "gateway.port"),
        (
            "cloudWorkers",
            r#"{ profiles: { worker: { provider: "example" } } }"#,
            "{ profiles: { worker: { provider: 1 } } }",
            "cloudWorkers.profiles.worker.provider",
        ),
        (
            "memory",
            r#"{ backend: "builtin" }"#,
            "{ backend: 1 }",
            "memory.backend",
        ),
        (
            "mcp",
            "{ apps: { enabled: true } }",
            "{ apps: { enabled: 1 } }",
            "mcp.apps.enabled",
        ),
        (
            "proxy",
            "{ enabled: true }",
            "{ enabled: 1 }",
            "proxy.enabled",
        ),
    ];

    assert_eq!(cases.len(), 47);
    let mut actual_paths = Vec::with_capacity(cases.len());
    let mut expected_paths = Vec::with_capacity(cases.len());
    for (domain, valid, invalid, expected_path) in cases {
        parse_openclaw_json5(&format!("{{ {domain}: {valid} }}"), "valid-domain.json5")
            .unwrap_or_else(|error| panic!("{domain} valid fixture failed: {error}"));
        let error = parse_openclaw_json5(
            &format!("{{ {domain}: {invalid} }}"),
            "invalid-domain.json5",
        )
        .unwrap_err();
        match error {
            ConfigError::Decode {
                source_name,
                path,
                message,
            } => {
                assert_eq!(source_name, "invalid-domain.json5", "{domain}");
                assert_ne!(message, "", "{domain}");
                actual_paths.push((domain, path));
            }
            ConfigError::Validation { path, message } => {
                assert_ne!(message, "", "{domain}");
                actual_paths.push((domain, path));
            }
            other => panic!("{domain}: expected typed decode or validation failure, got {other}"),
        }
        expected_paths.push((domain, expected_path.to_owned()));
    }
    assert_eq!(actual_paths, expected_paths);
}

fn validate_schema(root: &Value, schema: &Value, instance: &Value) -> Result<(), String> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let target = reference
            .strip_prefix("#/")
            .ok_or_else(|| format!("unsupported reference {reference}"))?
            .split('/')
            .try_fold(root, |current, segment| current.get(segment))
            .ok_or_else(|| format!("missing reference {reference}"))?;
        return validate_schema(root, target, instance);
    }
    if let Some(options) = schema.get("anyOf").and_then(Value::as_array) {
        if options
            .iter()
            .any(|option| validate_schema(root, option, instance).is_ok())
        {
            return Ok(());
        }
        return Err("no anyOf branch accepted the value".to_owned());
    }
    if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
        let accepted = options
            .iter()
            .filter(|option| validate_schema(root, option, instance).is_ok())
            .count();
        if accepted != 1 {
            return Err(format!(
                "expected exactly one oneOf branch, accepted {accepted}"
            ));
        }
    }
    if let Some(constant) = schema.get("const")
        && constant != instance
    {
        return Err(format!("expected constant {constant}"));
    }
    if let Some(excluded) = schema.get("not")
        && validate_schema(root, excluded, instance).is_ok()
    {
        return Err("value matched excluded schema".to_owned());
    }
    if let Some(expected) = schema.get("type") {
        let accepted = match expected {
            Value::String(kind) => type_matches(kind, instance),
            Value::Array(kinds) => kinds
                .iter()
                .filter_map(Value::as_str)
                .any(|kind| type_matches(kind, instance)),
            _ => false,
        };
        if !accepted {
            let label = expected
                .as_str()
                .map_or_else(|| expected.to_string(), str::to_owned);
            return Err(format!("expected {label}"));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(instance)
    {
        return Err("value is not in enum".to_owned());
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        let value = instance
            .as_str()
            .ok_or_else(|| "pattern requires a string".to_owned())?;
        if !schema_pattern_matches(pattern, value)? {
            return Err(format!("value does not match pattern {pattern}"));
        }
    }
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
        && instance.as_f64().is_none_or(|value| value < minimum)
    {
        return Err(format!("value is below minimum {minimum}"));
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64)
        && instance.as_f64().is_none_or(|value| value > maximum)
    {
        return Err(format!("value is above maximum {maximum}"));
    }
    if let Some(object) = instance.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(key) {
                    return Err(format!("missing required property {key}"));
                }
            }
        }
        for (key, value) in object {
            if let Some(property_schema) = properties.and_then(|properties| properties.get(key)) {
                validate_schema(root, property_schema, value)?;
            } else if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                return Err(format!("additional property {key}"));
            } else if let Some(additional) = schema
                .get("additionalProperties")
                .filter(|value| value.is_object())
            {
                validate_schema(root, additional, value)?;
            }
        }
    }
    if let Some(array) = instance.as_array()
        && let Some(items) = schema.get("items")
    {
        for value in array {
            validate_schema(root, items, value)?;
        }
    }
    Ok(())
}

fn schema_pattern_matches(pattern: &str, value: &str) -> Result<bool, String> {
    let matches = match pattern {
        "^[a-z][a-z0-9_-]{0,63}$" => {
            (1..=64).contains(&value.len())
                && value
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                && value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                })
        }
        "^[A-Z][A-Z0-9_]{0,127}$" => {
            (1..=128).contains(&value.len())
                && value
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_uppercase())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        }
        "^(/([^~]|~[01])*)+$" => {
            value.starts_with('/')
                && value
                    .as_bytes()
                    .windows(2)
                    .all(|pair| pair[0] != b'~' || matches!(pair.get(1), Some(b'0' | b'1')))
                && !value.ends_with('~')
        }
        "^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,255}$" => {
            (1..=256).contains(&value.len())
                && value
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b'.' | b'_' | b':' | b'/' | b'#' | b'-')
                })
        }
        "(^|/)\\.\\.?(/|$)" => value
            .split('/')
            .any(|segment| matches!(segment, "." | "..")),
        _ => return Err(format!("unsupported test schema pattern {pattern}")),
    };
    Ok(matches)
}

fn type_matches(kind: &str, instance: &Value) -> bool {
    match kind {
        "null" => instance.is_null(),
        "boolean" => instance.is_boolean(),
        "integer" => instance.as_i64().is_some() || instance.as_u64().is_some(),
        "number" => instance.is_number(),
        "string" => instance.is_string(),
        "array" => instance.is_array(),
        "object" => instance.is_object(),
        _ => false,
    }
}

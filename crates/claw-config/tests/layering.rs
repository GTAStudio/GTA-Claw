//! Exhaustive precedence and nested merge tests.

use claw_config::{
    ConfigLayerKind, ConfigLayers, LayeredConfigError, MigrationDiagnostic, MigrationError,
    to_json5,
};
use serde_json::Value;

#[test]
fn provider_layers_replace_changed_kinds_without_inheriting_credentials_or_endpoints() {
    use claw_config::ProviderKind;
    let base = ConfigLayers::new().with_system_json5(system_layer(None)).with_user_json5(r#"{core:{provider:{
        kind:"openai",model:"first-model",api_key:"env:FIRST_PROVIDER_KEY",base_url:"https://first.example.test/v1/",
        credential_origin:"https://first.example.test",completion_api:"responses",request_timeout_ms:5000
    }}}"#);
    let disabled = base
        .clone()
        .with_workspace_json5(r#"{core:{provider:{kind:"disabled"}}}"#)
        .resolve()
        .expect("explicit disabled replacement");
    let provider = disabled
        .config
        .core()
        .provider()
        .expect("disabled selection");
    assert_eq!(provider.kind(), ProviderKind::Disabled);
    assert!(provider.api_key().is_none() && provider.base_url().is_none());
    assert!(
        !to_json5(&disabled.config)
            .expect("disabled serialization")
            .contains("FIRST_PROVIDER_KEY")
    );
    let incomplete = base
        .clone()
        .with_workspace_json5(r#"{core:{provider:{kind:"anthropic",model:"next-model"}}}"#)
        .resolve();
    assert!(
        incomplete.is_err(),
        "another provider cannot inherit the first credential"
    );
    let changed = base.clone().with_workspace_json5(r#"{core:{provider:{kind:"anthropic",model:"next-model",api_key:"env:SECOND_PROVIDER_KEY"}}}"#).resolve().expect("complete replacement");
    let provider = changed.config.core().provider().expect("new provider");
    assert_eq!(provider.kind(), ProviderKind::Anthropic);
    assert_eq!(provider.base_url(), Some("https://api.anthropic.com/"));
    assert_eq!(provider.request_timeout_ms(), Some(120_000));
    assert!(provider.completion_api().is_none());
    assert_eq!(
        provider.api_key().expect("new reference").as_str(),
        "env:SECOND_PROVIDER_KEY"
    );
    let same = base
        .with_workspace_json5(r#"{core:{provider:{model:"new-exact-model"}}}"#)
        .resolve()
        .expect("same provider partial update");
    let provider = same.config.core().provider().expect("same provider");
    assert_eq!(provider.kind(), ProviderKind::Openai);
    assert_eq!(provider.model(), Some("new-exact-model"));
    assert_eq!(
        provider.api_key().expect("same reference").as_str(),
        "env:FIRST_PROVIDER_KEY"
    );
}

#[test]
fn provider_layers_reject_duplicate_selection_fields_before_merging() {
    for provider in [
        r#"{kind:"openai",kind:"anthropic",model:"model",api_key:"env:KEY"}"#,
        r#"{kind:"openai",model:"reviewed",model:"substituted",api_key:"env:KEY"}"#,
        r#"{kind:"openai",model:"model",api_key:"env:FIRST_KEY",api_key:"env:OTHER_KEY"}"#,
    ] {
        let result = ConfigLayers::new()
            .with_system_json5(system_layer(None))
            .with_workspace_json5(format!("{{core:{{provider:{provider}}}}}"))
            .resolve();
        assert!(
            result.is_err(),
            "duplicate provider selection must not become a last-value-wins configuration"
        );
    }
}

#[test]
fn every_precedence_combination_selects_the_highest_present_source() {
    for mask in 0_u8..32 {
        let system_port = (mask & 1 != 0).then_some(10_001);
        let mut layers = ConfigLayers::new().with_system_json5(system_layer(system_port));
        if mask & 2 != 0 {
            layers = layers.with_user_json5("{ core: { server: { port: 10002 } } }");
        }
        if mask & 4 != 0 {
            layers = layers.with_workspace_json5("{ core: { server: { port: 10003 } } }");
        }
        if mask & 8 != 0 {
            layers = layers.with_environment([("PORT", "10004")]);
        }
        if mask & 16 != 0 {
            layers = layers.with_command_line_json5("{ core: { server: { port: 10005 } } }");
        }

        let resolved = layers.resolve().expect("resolve precedence combination");
        let expected = if mask & 16 != 0 {
            10_005
        } else if mask & 8 != 0 {
            10_004
        } else if mask & 4 != 0 {
            10_003
        } else if mask & 2 != 0 {
            10_002
        } else if mask & 1 != 0 {
            10_001
        } else {
            3_978
        };
        assert_eq!(
            resolved.config.core().server().port(),
            expected,
            "mask {mask:05b}"
        );

        let mut expected_layers = vec![ConfigLayerKind::BuiltIn, ConfigLayerKind::System];
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
        assert_eq!(resolved.applied_layers, expected_layers);
    }
}

#[test]
fn partial_nested_objects_preserve_lower_precedence_siblings() {
    let resolved = ConfigLayers::new()
        .with_system_json5(system_layer(Some(19_001)))
        .with_user_json5(
            r#"{ core: { server: { public_domain: "user.example.test" }, logging: { level: "debug" } } }"#,
        )
        .with_workspace_json5("{ core: { server: { trust_proxy: true } } }")
        .with_command_line_json5(
            "{ core: { logging: { development_transport: true } } }",
        )
        .resolve()
        .expect("nested resolution");
    let value: Value =
        json5::from_str(&to_json5(&resolved.config).expect("serialize resolved")).expect("JSON5");

    assert_eq!(value["core"]["server"]["port"], 19_001);
    assert_eq!(
        value["core"]["server"]["public_domain"],
        "user.example.test"
    );
    assert_eq!(value["core"]["server"]["trust_proxy"], true);
    assert_eq!(value["core"]["logging"]["level"], "debug");
    assert_eq!(value["core"]["logging"]["development_transport"], true);
    assert_eq!(value["core"]["sessions"]["max_entries"], 100);
}

#[test]
fn legacy_environment_overlay_preserves_secret_references_not_values() {
    let resolved = ConfigLayers::new()
        .with_system_json5(system_layer(None))
        .with_environment([
            ("ADMIN_TOKEN", "do-not-persist-this-value"),
            ("HTTPS_PROXY", "http://user:password@proxy.example.test"),
        ])
        .resolve()
        .expect("environment overlay");
    let encoded = to_json5(&resolved.config).expect("serialize environment overlay");
    let value: Value = json5::from_str(&encoded).expect("JSON5");

    assert_eq!(value["core"]["admin"]["bearer_token"], "env:ADMIN_TOKEN");
    assert_eq!(value["core"]["network"]["proxy_url"], "env:HTTPS_PROXY");
    assert!(!encoded.contains("do-not-persist-this-value"));
    assert!(!encoded.contains("password@proxy"));
}

#[test]
fn invalid_environment_value_preserves_contract_identity() {
    let error = ConfigLayers::new()
        .with_system_json5(system_layer(None))
        .with_environment([("PORT", "0")])
        .resolve()
        .expect_err("invalid environment value");
    match error {
        LayeredConfigError::Environment(MigrationError::InvalidValue {
            legacy_env,
            target,
            message,
        }) => {
            assert_eq!(legacy_env, "PORT");
            assert_eq!(target, "server.port");
            assert_eq!(message, "must be from 1 through 65535");
        }
        other => panic!("expected environment conversion error, got {other}"),
    }
}

#[test]
fn environment_enablement_uses_lower_layer_credentials_and_cli_can_complete_it() {
    let lower_credentials = r#"
    {
      core: {
        auth: { github: { pat: "env:GITHUB_TOKEN", device: { enabled: false } } },
        role: { source_url: "https://roles.example.test/default.json" },
        channels: {
          teams: {
            enabled: false,
            app_id: "lower-layer-app",
            app_password: "env:MicrosoftAppPassword",
          },
        },
      },
    }
    "#;
    let resolved = ConfigLayers::new()
        .with_system_json5(lower_credentials)
        .with_environment([("ENABLE_TEAMS", "true")])
        .resolve()
        .expect("environment uses lower credentials");
    assert!(resolved.config.core().channels().teams().enabled());

    let completed_by_cli = ConfigLayers::new()
        .with_system_json5(system_layer(None))
        .with_environment([("ENABLE_TEAMS", "true")])
        .with_command_line_json5(
            r#"{
              core: {
                channels: {
                  teams: {
                    app_id: "cli-app",
                    app_password: "env:MicrosoftAppPassword",
                  },
                },
              },
            }"#,
        )
        .resolve()
        .expect("CLI completes environment enablement");
    assert!(completed_by_cli.config.core().channels().teams().enabled());
}

#[test]
fn invalid_lower_layer_shape_is_not_misattributed_to_environment_conversion() {
    let with_environment = ConfigLayers::new()
        .with_system_json5(
            system_layer(None).replace("core: {", "crestodian: { rescue: {} }, core: {"),
        )
        .with_environment([("PORT", "8080")])
        .resolve()
        .expect_err("foreign domain is invalid in legacy runtime envelope");
    match with_environment {
        LayeredConfigError::Result(claw_config::ConfigError::Decode {
            source_name,
            path,
            message,
        }) => {
            assert_eq!(source_name, "<lower-precedence-layers>");
            assert_eq!(path, "crestodian");
            assert!(!message.is_empty());
        }
        other => panic!("expected lower-layer decode error, got {other}"),
    }
}

#[test]
fn environment_layer_reports_exact_mappings_and_ignores_non_contributors() {
    let resolved = ConfigLayers::new()
        .with_system_json5(system_layer(None))
        .with_environment([("PORT", "8080"), ("TYPO_PORT", "8081")])
        .resolve()
        .expect("environment diagnostics");
    assert!(
        resolved
            .applied_layers
            .contains(&ConfigLayerKind::Environment)
    );
    assert!(matches!(
        resolved.environment_diagnostics.as_slice(),
        [
            MigrationDiagnostic::Applied {
                legacy_env: "PORT",
                target: "server.port"
            },
            MigrationDiagnostic::IgnoredUnknown { name }
        ] if name == "TYPO_PORT"
    ));

    let ignored = ConfigLayers::new()
        .with_system_json5(system_layer(None))
        .with_environment([("TYPO_PORT", "8081")])
        .resolve()
        .expect("unknown-only environment");
    assert!(
        !ignored
            .applied_layers
            .contains(&ConfigLayerKind::Environment)
    );
    assert!(matches!(
        ignored.environment_diagnostics.as_slice(),
        [MigrationDiagnostic::IgnoredUnknown { name }] if name == "TYPO_PORT"
    ));
}

fn system_layer(port: Option<u16>) -> String {
    let port = port.map_or_else(String::new, |port| format!("port: {port},"));
    format!(
        r#"{{
          core: {{
            auth: {{ github: {{ pat: "env:GITHUB_TOKEN", device: {{ enabled: false }} }} }},
            role: {{ source_url: "https://roles.example.test/default.json" }},
            channels: {{ teams: {{ enabled: false }} }},
            server: {{ {port} }}
          }}
        }}"#
    )
}

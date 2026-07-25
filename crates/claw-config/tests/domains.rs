//! Frozen 47-domain model and schema acceptance tests.

use std::collections::BTreeSet;

use claw_config::{
    CONFIG_DOMAIN_NAMES, ConfigError, openclaw_schema_json, openclaw_to_json5, parse_openclaw_json5,
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
                .map(str::to_owned)
                .unwrap_or_else(|| expected.to_string());
            return Err(format!("expected {label}"));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(instance)
    {
        return Err("value is not in enum".to_owned());
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

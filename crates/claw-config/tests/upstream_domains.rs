//! Fixture-driven acceptance evidence for the frozen top-level configuration
//! domain contract (`gateway.config.domains`).
//!
//! The pinned domain set is never written down in this file. Every test derives
//! it from `compat/upstream/inventories/config-domains.json`, cross-checks that
//! count against `compat/upstream/manifest.json` and against the Rust model, and
//! then drives one on-disk fixture per pinned domain. A missing fixture, an
//! extra fixture, a domain that silently drops fixture data, or a
//! contract-breaking shape that is quietly accepted all fail.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use claw_config::{CONFIG_DOMAIN_NAMES, ConfigError, openclaw_to_json5, parse_openclaw_json5};
use serde_json::Value;

const INVENTORY_PATH: &str = "compat/upstream/inventories/config-domains.json";
const MANIFEST_PATH: &str = "compat/upstream/manifest.json";
const UPSTREAM_SOURCE_PATH: &str = "src/config/types.openclaw.ts";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize repository root")
}

fn read_contract_json(relative: &str) -> Value {
    let path = repository_root().join(relative);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(source.trim_start_matches('\u{feff}'))
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// Reads the pinned top-level domain identifiers straight out of the frozen
/// inventory, in inventory order.
fn pinned_domains() -> Vec<String> {
    let inventory = read_contract_json(INVENTORY_PATH);
    let items = inventory["items"]
        .as_array()
        .expect("frozen inventory exposes an items array");
    assert!(!items.is_empty(), "frozen inventory must not be empty");

    items
        .iter()
        .map(|item| {
            item["id"]
                .as_str()
                .expect("every inventory item carries a string id")
                .to_owned()
        })
        .collect()
}

fn fixture_dir(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("upstream_domains")
        .join(kind)
}

/// Returns `(file name, file contents)` for every fixture in a corpus, sorted by
/// file name so failures are reported deterministically.
fn read_fixtures(kind: &str) -> Vec<(String, String)> {
    let directory = fixture_dir(kind);
    let mut fixtures = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("read fixture directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json5")
        })
        .map(|path| {
            let name = path
                .file_name()
                .expect("fixture file name")
                .to_string_lossy()
                .into_owned();
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            (name, source)
        })
        .collect::<Vec<_>>();
    fixtures.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(
        !fixtures.is_empty(),
        "{} holds no fixtures",
        directory.display()
    );
    fixtures
}

fn single_top_level_key(document: &Value, context: &str) -> String {
    let object = document
        .as_object()
        .unwrap_or_else(|| panic!("{context}: fixture must be a JSON object"));
    assert_eq!(
        object.len(),
        1,
        "{context}: fixture must configure exactly one top-level domain, found {:?}",
        object.keys().collect::<Vec<_>>()
    );
    object
        .keys()
        .next()
        .expect("fixture holds one top-level key")
        .clone()
}

/// Top-level domains that survived deserialization, in wire spelling.
fn populated_domains(config: &Value) -> Vec<String> {
    config
        .as_object()
        .expect("serialized configuration is an object")
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(name, _)| name.clone())
        .collect()
}

/// Asserts every scalar written in `expected` is still present, at the same
/// location and with the same value, in `actual`.
fn assert_survives(expected: &Value, actual: &Value, path: &str, context: &str) {
    match (expected, actual) {
        (Value::Object(expected_fields), Value::Object(actual_fields)) => {
            for (key, expected_value) in expected_fields {
                let actual_value = actual_fields
                    .get(key)
                    .unwrap_or_else(|| panic!("{context}: {path}.{key} was dropped"));
                assert_survives(
                    expected_value,
                    actual_value,
                    &format!("{path}.{key}"),
                    context,
                );
            }
        }
        (Value::Array(expected_items), Value::Array(actual_items)) => {
            assert_eq!(
                expected_items.len(),
                actual_items.len(),
                "{context}: {path} changed length"
            );
            for (index, (expected_item, actual_item)) in
                expected_items.iter().zip(actual_items).enumerate()
            {
                assert_survives(
                    expected_item,
                    actual_item,
                    &format!("{path}[{index}]"),
                    context,
                );
            }
        }
        (Value::Number(expected_number), Value::Number(actual_number)) => assert_eq!(
            expected_number.as_f64(),
            actual_number.as_f64(),
            "{context}: {path} changed value"
        ),
        _ => assert_eq!(expected, actual, "{context}: {path} changed value"),
    }
}

fn quoted_json_key(name: &str) -> String {
    Value::String(name.to_owned()).to_string()
}

#[test]
fn pinned_domain_set_is_derived_from_the_frozen_contract() {
    let inventory = read_contract_json(INVENTORY_PATH);
    let manifest = read_contract_json(MANIFEST_PATH);
    let domains = pinned_domains();

    let declared_total = inventory["counts"]["total"]
        .as_u64()
        .expect("inventory declares a total count");
    let canonical_total = manifest["canonical_counts"]["config_domains"]
        .as_u64()
        .expect("manifest declares a canonical config-domain count");

    assert_eq!(
        domains.len() as u64,
        declared_total,
        "inventory row count disagrees with its own declared total"
    );
    assert_eq!(
        declared_total, canonical_total,
        "inventory total disagrees with the frozen manifest"
    );
    assert_eq!(
        domains.len(),
        CONFIG_DOMAIN_NAMES.len(),
        "the Rust model covers a different number of domains than the contract pins"
    );
    assert_eq!(
        domains.iter().collect::<BTreeSet<_>>().len(),
        domains.len(),
        "the pinned domain identifiers are not unique"
    );
    assert_eq!(
        domains,
        CONFIG_DOMAIN_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
        "the Rust model and the frozen inventory disagree about the pinned domains"
    );

    for item in inventory["items"]
        .as_array()
        .expect("frozen inventory exposes an items array")
    {
        let id = item["id"].as_str().expect("inventory item id");
        assert_eq!(
            item["record_id"].as_str(),
            Some(format!("config_domain:{id}").as_str()),
            "inventory record id drifted for {id}"
        );
        assert_eq!(
            item["source_path"].as_str(),
            Some(UPSTREAM_SOURCE_PATH),
            "inventory source path drifted for {id}"
        );
    }
}

#[test]
fn every_pinned_top_level_domain_deserializes_from_its_frozen_fixture() {
    let domains = pinned_domains();
    let mut by_domain: BTreeMap<String, (String, String)> = BTreeMap::new();

    for (name, source) in read_fixtures("accepted") {
        let document: Value = json5::from_str(&source)
            .unwrap_or_else(|error| panic!("{name}: fixture is not valid JSON5: {error}"));
        let domain = single_top_level_key(&document, &name);
        if let Some((previous, _)) = by_domain.insert(domain.clone(), (name.clone(), source)) {
            panic!("{name} and {previous} both claim domain `{domain}`");
        }
    }

    let covered = by_domain.keys().cloned().collect::<BTreeSet<_>>();
    let pinned = domains.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        covered.difference(&pinned).cloned().collect::<Vec<_>>(),
        Vec::<String>::new(),
        "fixtures configure domains that the frozen contract does not pin"
    );
    assert_eq!(
        pinned.difference(&covered).cloned().collect::<Vec<_>>(),
        Vec::<String>::new(),
        "pinned domains have no accepted fixture"
    );

    for domain in &domains {
        let (name, source) = by_domain
            .get(domain)
            .unwrap_or_else(|| panic!("no accepted fixture for `{domain}`"));
        let config = parse_openclaw_json5(source, name).unwrap_or_else(|error| {
            panic!("{name}: pinned domain `{domain}` was rejected: {error}")
        });

        let serialized = serde_json::to_value(&config).expect("serialize parsed configuration");
        assert_eq!(
            populated_domains(&serialized),
            vec![domain.clone()],
            "{name}: fixture for `{domain}` did not land in exactly that domain"
        );

        let document: Value = json5::from_str(source).expect("fixture parses as JSON5");
        assert_survives(&document, &serialized, "", name);

        let reencoded = openclaw_to_json5(&config)
            .unwrap_or_else(|error| panic!("{name}: re-encoding `{domain}` failed: {error}"));
        let reparsed = parse_openclaw_json5(&reencoded, name)
            .unwrap_or_else(|error| panic!("{name}: re-parsing `{domain}` failed: {error}"));
        assert_eq!(
            reparsed, config,
            "{name}: `{domain}` does not survive a round trip"
        );
    }
}

#[test]
fn every_pinned_top_level_domain_rejects_contract_breaking_shapes() {
    for domain in pinned_domains() {
        let key = quoted_json_key(&domain);
        for (label, body) in [
            (
                "an unknown key inside the domain",
                "{ \"zzUnknownContractBreakingKey\": true }",
            ),
            ("a bare number in place of the domain", "12345"),
        ] {
            let source = format!("{{ {key}: {body} }}");
            let name = format!("{domain}: {label}");
            match parse_openclaw_json5(&source, &name) {
                Ok(_) => panic!("`{domain}` accepted {label}"),
                Err(ConfigError::Decode { path, .. }) => assert!(
                    path == domain || path.starts_with(&format!("{domain}.")),
                    "`{domain}` rejected {label} but blamed `{path}`"
                ),
                Err(other) => panic!("`{domain}` rejected {label} with the wrong error: {other}"),
            }
        }
    }
}

#[test]
fn top_level_names_outside_the_pinned_set_are_rejected() {
    let pinned = pinned_domains().into_iter().collect::<BTreeSet<_>>();
    let drifted = [
        "gatewayCore",
        "access_groups",
        "accessgroups",
        "node_host",
        "cloud_workers",
        "cloudworkers",
        "Logging",
        "logging2",
        "schema",
    ];

    for name in drifted {
        assert!(
            !pinned.contains(name),
            "`{name}` is a pinned domain and cannot be used as a drift probe"
        );
        let source = format!("{{ {}: {{}} }}", quoted_json_key(name));
        match parse_openclaw_json5(&source, name) {
            Ok(_) => panic!("unpinned top-level name `{name}` was accepted"),
            Err(ConfigError::Decode { .. }) => {}
            Err(other) => {
                panic!("unpinned top-level name `{name}` failed with the wrong error: {other}")
            }
        }
    }
}

#[test]
fn frozen_negative_fixtures_are_rejected_with_their_declared_diagnostic() {
    let mut kinds = BTreeSet::new();

    for (name, source) in read_fixtures("rejected") {
        let header = source
            .lines()
            .next()
            .unwrap_or_else(|| panic!("{name}: fixture is empty"));
        let declaration = header
            .strip_prefix("// reject: ")
            .unwrap_or_else(|| panic!("{name}: first line must declare the expected rejection"));
        let (kind, expected_path) = declaration
            .split_once(' ')
            .unwrap_or_else(|| panic!("{name}: rejection declaration must be `<kind> <path>`"));
        kinds.insert(kind.to_owned());

        let error = parse_openclaw_json5(&source, &name)
            .err()
            .unwrap_or_else(|| panic!("{name}: contract-breaking fixture was accepted"));

        match (kind, &error) {
            ("decode", ConfigError::Decode { path, .. })
            | ("validation", ConfigError::Validation { path, .. }) => assert_eq!(
                path, expected_path,
                "{name}: rejected at `{path}` instead of `{expected_path}`"
            ),
            ("syntax", ConfigError::Syntax { .. }) => {}
            _ => panic!("{name}: expected a {kind} rejection, got {error}"),
        }
    }

    assert_eq!(
        kinds,
        ["decode", "syntax", "validation"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
        "the negative corpus must exercise decode, validation and syntax rejections"
    );
}

//! Generates the frozen Gateway registry from the validator-owned inventory.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Deserialize)]
struct Inventory {
    schema_version: u8,
    inventory_id: String,
    classification: String,
    baseline_sha: String,
    counts: Counts,
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Manifest {
    baseline_sha: String,
    canonical_counts: CanonicalCounts,
}

#[derive(Deserialize)]
struct CanonicalCounts {
    gateway_methods: usize,
    gateway_advertised_methods: usize,
    gateway_events: usize,
    gateway_roles: usize,
    gateway_scopes: usize,
}

#[derive(Deserialize)]
struct Counts {
    total: usize,
    methods: usize,
    advertised_methods: usize,
    events: usize,
    roles: usize,
    scopes: usize,
    dynamic_plugin_methods: String,
}

#[derive(Deserialize)]
struct Item {
    record_id: String,
    id: String,
    classification: String,
    kind: String,
    scope: Option<String>,
    advertised: Option<bool>,
    protocol_class: Option<String>,
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let inventory_path =
        manifest_dir.join("../../compat/upstream/inventories/gateway-protocol.json");
    let upstream_manifest_path = manifest_dir.join("../../compat/upstream/manifest.json");
    println!("cargo:rerun-if-changed={}", inventory_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        upstream_manifest_path.display()
    );

    let source = fs::read_to_string(&inventory_path).expect("read gateway protocol inventory");
    let source = source.strip_prefix('\u{feff}').unwrap_or(&source);
    let inventory: Inventory =
        serde_json::from_str(source).expect("parse gateway protocol inventory");
    let manifest_source =
        fs::read_to_string(&upstream_manifest_path).expect("read upstream manifest");
    let manifest_source = manifest_source
        .strip_prefix('\u{feff}')
        .unwrap_or(&manifest_source);
    let manifest: Manifest =
        serde_json::from_str(manifest_source).expect("parse upstream manifest");
    validate_inventory(&inventory, &manifest);

    let generated = generate_registry(&inventory);
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(out_dir.join("gateway_registry.rs"), generated)
        .expect("write generated gateway registry");
}

fn validate_inventory(inventory: &Inventory, manifest: &Manifest) {
    assert_eq!(
        inventory.schema_version, 1,
        "inventory schema version drift"
    );
    assert_eq!(inventory.inventory_id, "gateway-protocol");
    assert_eq!(inventory.classification, "gateway_core");
    assert_eq!(inventory.baseline_sha, manifest.baseline_sha);
    assert_eq!(
        inventory.counts.methods,
        manifest.canonical_counts.gateway_methods
    );
    assert_eq!(
        inventory.counts.advertised_methods,
        manifest.canonical_counts.gateway_advertised_methods
    );
    assert_eq!(
        inventory.counts.events,
        manifest.canonical_counts.gateway_events
    );
    assert_eq!(
        inventory.counts.roles,
        manifest.canonical_counts.gateway_roles
    );
    assert_eq!(
        inventory.counts.scopes,
        manifest.canonical_counts.gateway_scopes
    );
    assert_eq!(inventory.counts.dynamic_plugin_methods, "runtime-dependent");
    assert_eq!(
        inventory.counts.total,
        inventory.counts.methods
            + inventory.counts.events
            + inventory.counts.roles
            + inventory.counts.scopes
    );
    assert_eq!(inventory.items.len(), inventory.counts.total);

    let mut record_ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut methods = 0;
    let mut advertised = 0;
    let mut events = 0;
    let mut roles = 0;
    let mut scopes = 0;
    for item in &inventory.items {
        assert_eq!(item.classification, "gateway_core");
        assert!(!item.id.is_empty(), "empty inventory identity");
        assert!(
            record_ids.insert(item.record_id.as_str()),
            "duplicate record id: {}",
            item.record_id
        );
        assert!(
            identities.insert((item.kind.as_str(), item.id.as_str())),
            "duplicate ordinal identity: {}:{}",
            item.kind,
            item.id
        );
        assert_eq!(
            item.record_id,
            format!("gateway_{}:{}", item.kind, item.id),
            "record identity drift"
        );
        match item.kind.as_str() {
            "method" => {
                methods += 1;
                assert!(item.scope.is_some(), "method missing scope");
                assert!(item.advertised.is_some(), "method missing advertised flag");
                advertised += usize::from(item.advertised == Some(true));
            }
            "event" => events += 1,
            "role" => roles += 1,
            "scope" => scopes += 1,
            other => panic!("unknown inventory kind: {other}"),
        }
    }
    assert_eq!(methods, inventory.counts.methods);
    assert_eq!(advertised, inventory.counts.advertised_methods);
    assert_eq!(events, inventory.counts.events);
    assert_eq!(roles, inventory.counts.roles);
    assert_eq!(scopes, inventory.counts.scopes);
}

fn generate_registry(inventory: &Inventory) -> String {
    let mut output =
        String::from("// @generated by build.rs from the validator-owned gateway-protocol.json.\n");
    writeln!(
        output,
        "pub(crate) const GENERATED_BASELINE_SHA: &str = {:?};",
        inventory.baseline_sha
    )
    .expect("write generated source");

    writeln!(
        output,
        "pub(crate) static GENERATED_CORE_METHODS: [CoreMethod; {}] = [",
        inventory.counts.methods
    )
    .expect("write generated source");
    for item in inventory.items.iter().filter(|item| item.kind == "method") {
        let scope = generated_scope(item.scope.as_deref().expect("validated method scope"));
        writeln!(
            output,
            "    CoreMethod::new({:?}, {scope}, {}),",
            item.id,
            item.advertised.expect("validated advertised flag")
        )
        .expect("write generated method");
    }
    output.push_str("];\n");

    writeln!(
        output,
        "pub(crate) static GENERATED_CORE_EVENTS: [CoreEvent; {}] = [",
        inventory.counts.events
    )
    .expect("write generated source");
    for item in inventory.items.iter().filter(|item| item.kind == "event") {
        writeln!(output, "    CoreEvent::new({:?}),", item.id).expect("write generated event");
    }
    output.push_str("];\n");

    writeln!(
        output,
        "pub(crate) static GENERATED_ROLES: [Role; {}] = [",
        inventory.counts.roles
    )
    .expect("write generated source");
    for item in inventory.items.iter().filter(|item| item.kind == "role") {
        let role = match (item.id.as_str(), item.protocol_class.as_deref()) {
            ("operator", Some("gateway")) => "Role::Operator",
            ("node", Some("gateway")) => "Role::Node",
            ("worker", Some("closed_worker")) => "Role::Worker",
            _ => panic!("unknown role inventory entry: {}", item.id),
        };
        writeln!(output, "    {role},").expect("write generated role");
    }
    output.push_str("];\n");

    writeln!(
        output,
        "pub(crate) static GENERATED_SCOPES: [OperatorScope; {}] = [",
        inventory.counts.scopes
    )
    .expect("write generated source");
    for item in inventory.items.iter().filter(|item| item.kind == "scope") {
        writeln!(
            output,
            "    {},",
            generated_operator_scope(item.id.as_str())
        )
        .expect("write generated scope");
    }
    output.push_str("];\n");
    output
}

fn generated_scope(scope: &str) -> &'static str {
    match scope {
        "operator.admin" => "MethodScope::Operator(OperatorScope::Admin)",
        "operator.read" => "MethodScope::Operator(OperatorScope::Read)",
        "operator.write" => "MethodScope::Operator(OperatorScope::Write)",
        "operator.approvals" => "MethodScope::Operator(OperatorScope::Approvals)",
        "operator.pairing" => "MethodScope::Operator(OperatorScope::Pairing)",
        "operator.talk.secrets" => "MethodScope::Operator(OperatorScope::TalkSecrets)",
        "node" => "MethodScope::Node",
        "dynamic" => "MethodScope::Dynamic",
        other => panic!("unknown method scope: {other}"),
    }
}

fn generated_operator_scope(scope: &str) -> &'static str {
    match scope {
        "operator.admin" => "OperatorScope::Admin",
        "operator.read" => "OperatorScope::Read",
        "operator.write" => "OperatorScope::Write",
        "operator.approvals" => "OperatorScope::Approvals",
        "operator.pairing" => "OperatorScope::Pairing",
        "operator.talk.secrets" => "OperatorScope::TalkSecrets",
        other => panic!("unknown operator scope: {other}"),
    }
}

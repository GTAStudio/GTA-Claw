//! Acceptance coverage for the pinned Gateway core method catalog.
//!
//! Canonical sources: `src/gateway/methods/core-descriptors.ts` and
//! `src/gateway/server-methods-list.ts` at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`, recorded row by
//! row in `compat/upstream/inventories/gateway-protocol.json`.
//!
//! Every count in this file is parsed out of the frozen inventory and the frozen
//! manifest and then compared against the generated Rust catalog; none of them is
//! a constant the catalog is compared to itself through.

use claw_protocol::gateway::{
    Codec, CodecError, Frame, GatewayMethodName, MethodScope, baseline_sha, operator_scopes,
};
use claw_protocol::methods::{
    self, MethodCatalogDrift, PinnedMethod, parse_scope_identity, scope_identity,
    verify_pinned_methods,
};
use serde::Deserialize;

const INVENTORY: &str = include_str!("../../../compat/upstream/inventories/gateway-protocol.json");
const MANIFEST: &str = include_str!("../../../compat/upstream/manifest.json");
const DESCRIPTOR_SOURCE: &str = "src/gateway/methods/core-descriptors.ts";

#[derive(Deserialize)]
struct Inventory {
    baseline_sha: String,
    counts: Counts,
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Counts {
    methods: usize,
    advertised_methods: usize,
}

#[derive(Deserialize)]
struct Item {
    id: String,
    kind: String,
    source_path: String,
    scope: Option<String>,
    advertised: Option<bool>,
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
}

fn inventory() -> Inventory {
    serde_json::from_str(INVENTORY.trim_start_matches('\u{feff}')).expect("frozen inventory")
}

fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST.trim_start_matches('\u{feff}')).expect("frozen manifest")
}

/// Owned pinned rows, so a test can mutate one field and re-verify.
fn pinned_rows(inventory: &Inventory) -> Vec<(String, String, bool)> {
    inventory
        .items
        .iter()
        .filter(|item| item.kind == "method")
        .map(|item| {
            (
                item.id.clone(),
                item.scope.clone().expect("pinned method carries a scope"),
                item.advertised.expect("pinned method carries advertised"),
            )
        })
        .collect()
}

fn borrow(rows: &[(String, String, bool)]) -> Vec<PinnedMethod<'_>> {
    rows.iter()
        .map(|(name, scope, advertised)| PinnedMethod {
            name,
            scope,
            advertised: *advertised,
        })
        .collect()
}

#[test]
fn generated_catalog_matches_every_pinned_method_name_scope_and_advertised_flag() {
    let inventory = inventory();
    let manifest = manifest();
    let rows = pinned_rows(&inventory);
    let pinned = borrow(&rows);

    // The three independently frozen statements of the same number must agree
    // before the catalog is measured against any of them.
    assert_eq!(rows.len(), inventory.counts.methods);
    assert_eq!(rows.len(), manifest.canonical_counts.gateway_methods);
    assert_eq!(methods::method_count(), rows.len());
    assert_eq!(baseline_sha(), inventory.baseline_sha);
    assert_eq!(baseline_sha(), manifest.baseline_sha);

    verify_pinned_methods(pinned.iter().copied()).expect("catalog matches the pinned inventory");

    let advertised = rows.iter().filter(|(_, _, flag)| *flag).count();
    assert_eq!(advertised, inventory.counts.advertised_methods);
    assert_eq!(
        advertised,
        manifest.canonical_counts.gateway_advertised_methods
    );
    assert_eq!(methods::advertised_count(), advertised);

    // Every pinned method row comes from the descriptor module the ledger cites.
    for item in inventory.items.iter().filter(|item| item.kind == "method") {
        assert_eq!(item.source_path, DESCRIPTOR_SOURCE, "{}", item.id);
    }
}

#[test]
fn every_pinned_scope_is_closed_and_scope_totals_match_the_inventory() {
    let inventory = inventory();
    let rows = pinned_rows(&inventory);

    let mut classifications = operator_scopes()
        .iter()
        .copied()
        .map(MethodScope::Operator)
        .collect::<Vec<_>>();
    classifications.push(MethodScope::Node);
    classifications.push(MethodScope::Dynamic);

    let mut accounted = 0;
    for classification in classifications {
        let identity = scope_identity(classification);
        assert_eq!(
            parse_scope_identity(identity),
            Some(classification),
            "scope identity `{identity}` must round-trip"
        );
        let pinned = rows
            .iter()
            .filter(|(_, scope, _)| scope == identity)
            .count();
        assert_eq!(
            methods::scope_method_count(classification),
            pinned,
            "scope `{identity}` method total"
        );
        accounted += pinned;
    }

    // Nothing in the catalog is scoped outside the closed classification set.
    assert_eq!(accounted, rows.len());

    // Case-sensitivity is part of the closed set: a near miss is not a scope.
    assert_eq!(parse_scope_identity("Operator.read"), None);
    assert_eq!(parse_scope_identity("operator.Read"), None);
    assert_eq!(parse_scope_identity(""), None);
}

#[test]
fn advertised_projection_matches_the_pinned_hello_method_list() {
    let inventory = inventory();
    let rows = pinned_rows(&inventory);

    let pinned_advertised = rows
        .iter()
        .filter(|(_, _, advertised)| *advertised)
        .map(|(name, _, _)| name.as_str())
        .collect::<Vec<_>>();
    let generated_advertised = methods::advertised_method_names().collect::<Vec<_>>();
    assert_eq!(generated_advertised, pinned_advertised);

    let pinned_unadvertised = rows
        .iter()
        .filter(|(_, _, advertised)| !*advertised)
        .map(|(name, _, _)| name.as_str())
        .collect::<Vec<_>>();
    let generated_unadvertised = methods::unadvertised_method_names().collect::<Vec<_>>();
    assert_eq!(generated_unadvertised, pinned_unadvertised);
    assert_eq!(
        generated_advertised.len() + generated_unadvertised.len(),
        methods::method_count()
    );

    // Advertisement is hello-list visibility only; an unadvertised method is
    // still a resolvable catalog member carrying its pinned classification.
    for (name, scope, _) in rows.iter().filter(|(_, _, advertised)| !*advertised) {
        let descriptor =
            methods::descriptor(name).expect("unadvertised method is still resolvable");
        assert!(!descriptor.advertised());
        assert_eq!(descriptor.scope_identity(), scope);
    }
}

#[test]
fn every_pinned_method_decodes_as_a_core_request_envelope() {
    let inventory = inventory();
    let rows = pinned_rows(&inventory);
    let codec = Codec::authenticated();

    let mut decoded = 0;
    for (position, (name, scope, advertised)) in rows.iter().enumerate() {
        let frame = format!(
            r#"{{"type":"req","id":"catalog-{position}","method":{},"params":null}}"#,
            serde_json::to_string(name).expect("method identity is encodable")
        );
        let Frame::Request(request) = codec
            .decode(frame.as_bytes())
            .unwrap_or_else(|error| panic!("`{name}` must decode as a core request: {error}"))
        else {
            panic!("`{name}` must decode as a request frame");
        };
        assert!(
            matches!(request.method(), GatewayMethodName::Core(_)),
            "`{name}` must classify as a core method, never as a plugin"
        );
        assert_eq!(request.method().as_str(), name);

        let descriptor = methods::descriptor(name).expect("catalog lookup");
        assert_eq!(descriptor.name(), name);
        assert_eq!(descriptor.scope_identity(), scope);
        assert_eq!(descriptor.advertised(), *advertised);
        decoded += 1;
    }
    assert_eq!(decoded, methods::method_count());

    // An identity outside the catalog is refused rather than admitted as core.
    let unknown = r#"{"type":"req","id":"absent","method":"catalog.absent.method"}"#;
    assert!(matches!(
        codec.decode(unknown.as_bytes()),
        Err(CodecError::UnknownMethod(name)) if name == "catalog.absent.method"
    ));
    assert_eq!(methods::descriptor("catalog.absent.method"), None);
    // Exact ordinal identity: the catalog is case-sensitive.
    assert_eq!(methods::descriptor("Health"), None);
}

#[test]
fn catalog_drift_is_detected_for_every_mutated_pinned_field() {
    let inventory = inventory();
    let rows = pinned_rows(&inventory);
    assert!(rows.len() > 1, "mutation coverage needs at least two rows");

    let mut renamed = rows.clone();
    renamed[0].0 = format!("{}.drifted", renamed[0].0);
    assert!(matches!(
        verify_pinned_methods(borrow(&renamed)),
        Err(MethodCatalogDrift::Name { position: 0, .. })
    ));

    let mut rescoped = rows.clone();
    let replacement = if rescoped[0].1 == "operator.admin" {
        "operator.read"
    } else {
        "operator.admin"
    };
    rescoped[0].1 = replacement.to_owned();
    assert!(matches!(
        verify_pinned_methods(borrow(&rescoped)),
        Err(MethodCatalogDrift::Scope { pinned, .. }) if pinned == replacement
    ));

    let mut reflagged = rows.clone();
    reflagged[0].2 = !reflagged[0].2;
    assert!(matches!(
        verify_pinned_methods(borrow(&reflagged)),
        Err(MethodCatalogDrift::Advertised { .. })
    ));

    let mut truncated = rows.clone();
    truncated.pop();
    assert!(matches!(
        verify_pinned_methods(borrow(&truncated)),
        Err(MethodCatalogDrift::Count { pinned, generated })
            if pinned + 1 == generated && generated == methods::method_count()
    ));

    let mut extended = rows.clone();
    extended.push((
        "catalog.appended".to_owned(),
        "operator.admin".to_owned(),
        true,
    ));
    assert!(matches!(
        verify_pinned_methods(borrow(&extended)),
        Err(MethodCatalogDrift::Count { .. })
    ));

    let mut duplicated = rows.clone();
    duplicated[1] = duplicated[0].clone();
    assert!(matches!(
        verify_pinned_methods(borrow(&duplicated)),
        Err(MethodCatalogDrift::DuplicateName { name }) if name == rows[0].0
    ));

    let mut reordered = rows.clone();
    reordered.swap(0, 1);
    assert!(matches!(
        verify_pinned_methods(borrow(&reordered)),
        Err(MethodCatalogDrift::Name { position: 0, .. })
    ));

    let mut unknown_scope = rows.clone();
    unknown_scope[0].1 = "operator.Read".to_owned();
    assert!(matches!(
        verify_pinned_methods(borrow(&unknown_scope)),
        Err(MethodCatalogDrift::UnknownScope { scope, .. }) if scope == "operator.Read"
    ));

    // Drift reports name the row that moved rather than a bare boolean.
    let report = verify_pinned_methods(borrow(&renamed))
        .expect_err("renamed row drifts")
        .to_string();
    assert!(report.contains(&renamed[0].0), "{report}");
}

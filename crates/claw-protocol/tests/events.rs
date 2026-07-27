//! Acceptance coverage for the pinned Gateway core event catalog and envelope.
//!
//! Canonical sources: `src/gateway/server-methods-list.ts` and
//! `src/gateway/events.ts` at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`, recorded row by
//! row in `compat/upstream/inventories/gateway-protocol.json`.
//!
//! Every count in this file is parsed out of the frozen inventory and the frozen
//! manifest and then compared against the generated Rust catalog; none of them is
//! a constant the catalog is compared to itself through.

use claw_protocol::events::{
    self, EventCatalogDrift, EventCatalogError, core_event_envelope, core_event_name,
    verify_pinned_events,
};
use claw_protocol::gateway::{
    Codec, EventName, EventSequence, Frame, NonNegativeInteger, OpaqueField, StateVersion,
    baseline_sha,
};
use serde::Deserialize;

const INVENTORY: &str = include_str!("../../../compat/upstream/inventories/gateway-protocol.json");
const MANIFEST: &str = include_str!("../../../compat/upstream/manifest.json");
const EVENT_SOURCES: [&str; 2] = [
    "src/gateway/server-methods-list.ts",
    "src/gateway/events.ts",
];

#[derive(Deserialize)]
struct Inventory {
    baseline_sha: String,
    counts: Counts,
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Counts {
    events: usize,
}

#[derive(Deserialize)]
struct Item {
    id: String,
    kind: String,
    source_path: String,
}

#[derive(Deserialize)]
struct Manifest {
    baseline_sha: String,
    canonical_counts: CanonicalCounts,
}

#[derive(Deserialize)]
struct CanonicalCounts {
    gateway_events: usize,
}

fn inventory() -> Inventory {
    serde_json::from_str(INVENTORY.trim_start_matches('\u{feff}')).expect("frozen inventory")
}

fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST.trim_start_matches('\u{feff}')).expect("frozen manifest")
}

fn pinned_names(inventory: &Inventory) -> Vec<String> {
    inventory
        .items
        .iter()
        .filter(|item| item.kind == "event")
        .map(|item| item.id.clone())
        .collect()
}

fn borrow(names: &[String]) -> Vec<&str> {
    names.iter().map(String::as_str).collect()
}

fn state_version() -> StateVersion {
    StateVersion {
        presence: NonNegativeInteger::new(3),
        health: NonNegativeInteger::new(5),
    }
}

#[test]
fn generated_catalog_matches_every_pinned_event() {
    let inventory = inventory();
    let manifest = manifest();
    let names = pinned_names(&inventory);

    assert_eq!(names.len(), inventory.counts.events);
    assert_eq!(names.len(), manifest.canonical_counts.gateway_events);
    assert_eq!(events::event_count(), names.len());
    assert_eq!(baseline_sha(), inventory.baseline_sha);
    assert_eq!(baseline_sha(), manifest.baseline_sha);

    verify_pinned_events(borrow(&names)).expect("catalog matches the pinned inventory");

    let generated = events::event_names().collect::<Vec<_>>();
    assert_eq!(generated, borrow(&names));
    for name in &names {
        assert!(events::is_core_event(name), "`{name}` must be a core event");
    }

    // Every pinned event row comes from one of the two modules the ledger cites.
    for item in inventory.items.iter().filter(|item| item.kind == "event") {
        assert!(
            EVENT_SOURCES.contains(&item.source_path.as_str()),
            "unexpected event source `{}` for `{}`",
            item.source_path,
            item.id
        );
    }
}

#[test]
fn every_pinned_event_round_trips_through_the_event_envelope() {
    let inventory = inventory();
    let names = pinned_names(&inventory);
    let codec = Codec::authenticated();
    let sequence = EventSequence::new(7).expect("positive sequence");

    let mut covered = 0;
    for name in &names {
        let quoted = serde_json::to_string(name).expect("event identity is encodable");
        let full = format!(
            r#"{{"type":"event","event":{quoted},"payload":{{"catalog":true}},"seq":7,"stateVersion":{{"presence":3,"health":5}}}}"#
        );

        let Frame::Event(event) = codec
            .decode(full.as_bytes())
            .unwrap_or_else(|error| panic!("`{name}` must decode as an event: {error}"))
        else {
            panic!("`{name}` must decode as an event frame");
        };
        assert!(
            matches!(event.event(), EventName::Core(_)),
            "`{name}` must classify as a core event, never as an extension"
        );
        assert_eq!(event.event().as_str(), name);
        assert_eq!(
            event.payload().value().expect("payload present").as_json(),
            r#"{"catalog":true}"#
        );
        assert_eq!(event.sequence(), Some(sequence));
        assert_eq!(event.state_version(), Some(state_version()));
        assert_eq!(
            codec
                .encode(&Frame::Event(event.clone()))
                .expect("re-encode"),
            full.as_bytes()
        );

        // The fail-closed constructor produces exactly the decoded envelope.
        let built = core_event_envelope(
            name,
            event.payload().clone(),
            Some(sequence),
            Some(state_version()),
        )
        .expect("pinned event builds an envelope");
        assert_eq!(built, event);

        // Optional envelope fields stay omitted rather than defaulted.
        let minimal = format!(r#"{{"type":"event","event":{quoted}}}"#);
        let Frame::Event(bare) = codec
            .decode(minimal.as_bytes())
            .unwrap_or_else(|error| panic!("`{name}` must decode without optionals: {error}"))
        else {
            panic!("`{name}` must decode as an event frame");
        };
        assert_eq!(bare.event().as_str(), name);
        assert!(bare.payload().is_omitted());
        assert_eq!(bare.sequence(), None);
        assert_eq!(bare.state_version(), None);
        assert_eq!(
            codec.encode(&Frame::Event(bare)).expect("re-encode"),
            minimal.as_bytes()
        );

        // Explicit null is preserved as null, not collapsed into omitted.
        let explicit_null = format!(r#"{{"type":"event","event":{quoted},"payload":null}}"#);
        let Frame::Event(nulled) = codec
            .decode(explicit_null.as_bytes())
            .unwrap_or_else(|error| panic!("`{name}` must decode with null payload: {error}"))
        else {
            panic!("`{name}` must decode as an event frame");
        };
        assert!(matches!(nulled.payload(), OpaqueField::Null));
        assert_eq!(
            codec.encode(&Frame::Event(nulled)).expect("re-encode"),
            explicit_null.as_bytes()
        );

        covered += 1;
    }
    assert_eq!(covered, events::event_count());
}

#[test]
fn identities_outside_the_catalog_never_classify_as_core() {
    let codec = Codec::authenticated();

    assert!(core_event_name("catalog.absent.event").is_none());
    assert!(!events::is_core_event("catalog.absent.event"));
    assert_eq!(
        core_event_envelope("catalog.absent.event", OpaqueField::Omitted, None, None),
        Err(EventCatalogError::UnknownEvent {
            name: "catalog.absent.event".to_owned()
        })
    );

    // Exact ordinal identity: a case variant of a pinned event is not pinned.
    let pinned = events::event_names().next().expect("catalog is non-empty");
    assert!(events::is_core_event(pinned));
    assert!(!events::is_core_event(&pinned.to_uppercase()));

    // The decoder still admits schema-permitted extension events; only the
    // core classification is closed.
    let Frame::Event(event) = codec
        .decode(br#"{"type":"event","event":"catalog.absent.event","seq":1}"#)
        .expect("extension event decodes")
    else {
        panic!("expected an event frame");
    };
    assert!(matches!(event.event(), EventName::Extension(_)));
    assert_eq!(event.event().as_str(), "catalog.absent.event");
}

#[test]
fn event_catalog_drift_is_detected_for_every_mutated_pinned_row() {
    let inventory = inventory();
    let names = pinned_names(&inventory);
    assert!(names.len() > 1, "mutation coverage needs at least two rows");

    let mut renamed = names.clone();
    renamed[0] = format!("{}.drifted", renamed[0]);
    assert!(matches!(
        verify_pinned_events(borrow(&renamed)),
        Err(EventCatalogDrift::Name { position: 0, .. })
    ));

    let mut truncated = names.clone();
    truncated.pop();
    assert!(matches!(
        verify_pinned_events(borrow(&truncated)),
        Err(EventCatalogDrift::Count { pinned, generated })
            if pinned + 1 == generated && generated == events::event_count()
    ));

    let mut extended = names.clone();
    extended.push("catalog.appended".to_owned());
    assert!(matches!(
        verify_pinned_events(borrow(&extended)),
        Err(EventCatalogDrift::Count { .. })
    ));

    let mut duplicated = names.clone();
    duplicated[1] = duplicated[0].clone();
    assert!(matches!(
        verify_pinned_events(borrow(&duplicated)),
        Err(EventCatalogDrift::DuplicateName { name }) if name == names[0]
    ));

    let mut reordered = names.clone();
    reordered.swap(0, 1);
    assert!(matches!(
        verify_pinned_events(borrow(&reordered)),
        Err(EventCatalogDrift::Name { position: 0, .. })
    ));

    let report = verify_pinned_events(borrow(&renamed))
        .expect_err("renamed row drifts")
        .to_string();
    assert!(report.contains(&renamed[0]), "{report}");
}

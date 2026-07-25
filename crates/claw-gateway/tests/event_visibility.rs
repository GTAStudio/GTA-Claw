//! Event visibility, stated independently of the code that decides it.
//!
//! The audit flagged the previous coverage as self-referential: it asked
//! `event_visibility` what an event's visibility was and then asserted that the
//! answer equalled itself. Everything here instead starts from `POLICY`, a
//! hand-written row per catalogued event, transcribed once from the documented
//! intent. Production is never consulted to build an expectation.
//!
//! The frozen inventory carries no visibility column — it records only event
//! identities — so `POLICY`'s *name set* is checked against
//! `compat/upstream/inventories/gateway-protocol.json` (adding or removing an
//! upstream event fails here), while each row's *visibility* is this crate's
//! own stated policy and must be changed deliberately in two places.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use claw_gateway::events::{EventVisibility, event_catalog, event_visibility};
use claw_protocol::gateway::{OperatorScope, Role};
use serde::Deserialize;

/// Every closed operator scope, in the frozen registry order.
const ALL_SCOPES: [OperatorScope; 6] = [
    OperatorScope::Admin,
    OperatorScope::Read,
    OperatorScope::Write,
    OperatorScope::Approvals,
    OperatorScope::Pairing,
    OperatorScope::TalkSecrets,
];

/// Shorthand used only to keep the policy table one row per line.
const READ: EventVisibility = EventVisibility::Operator(OperatorScope::Read);
const ADMIN: EventVisibility = EventVisibility::Operator(OperatorScope::Admin);
const APPROVALS: EventVisibility = EventVisibility::Operator(OperatorScope::Approvals);
const PAIRING: EventVisibility = EventVisibility::Operator(OperatorScope::Pairing);
const ALL_AUTH: EventVisibility = EventVisibility::AllAuthenticated;
const HANDSHAKE: EventVisibility = EventVisibility::Handshake;
const NODE: EventVisibility = EventVisibility::Node;

/// The intended visibility of all 33 catalogued events, written out by hand.
///
/// Rationale by group:
/// * `connect.challenge` is the only frame emitted before authentication, so it
///   is the only `Handshake` row.
/// * `tick`, `shutdown` and `heartbeat` carry no operator data — they are
///   liveness and lifecycle signals every authenticated peer needs.
/// * `node.invoke.request` is work dispatched *to* a node and must never reach
///   an operator console.
/// * Approval and pairing streams disclose pending security decisions, so they
///   ride their own dedicated scopes rather than `operator.read`.
/// * Terminal streams carry raw process output and are `operator.admin`.
/// * Everything else is operator telemetry readable with `operator.read`.
const POLICY: [(&str, EventVisibility); 33] = [
    ("connect.challenge", HANDSHAKE),
    ("agent", READ),
    ("chat", READ),
    ("session.approval", APPROVALS),
    ("session.message", READ),
    ("session.operation", READ),
    ("session.tool", READ),
    ("sessions.changed", READ),
    ("presence", READ),
    ("tick", ALL_AUTH),
    ("talk.mode", READ),
    ("talk.event", READ),
    ("shutdown", ALL_AUTH),
    ("health", READ),
    ("heartbeat", ALL_AUTH),
    ("cron", READ),
    ("task", READ),
    ("task.suggestion", READ),
    ("node.pair.requested", PAIRING),
    ("node.pair.resolved", PAIRING),
    ("node.presence", READ),
    ("node.invoke.request", NODE),
    ("device.pair.requested", PAIRING),
    ("device.pair.resolved", PAIRING),
    ("voicewake.changed", READ),
    ("voicewake.routing.changed", READ),
    ("exec.approval.requested", APPROVALS),
    ("exec.approval.resolved", APPROVALS),
    ("plugin.approval.requested", APPROVALS),
    ("plugin.approval.resolved", APPROVALS),
    ("terminal.data", ADMIN),
    ("terminal.exit", ADMIN),
    ("update.available", READ),
];

#[derive(Debug, Deserialize)]
struct Inventory {
    items: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    id: String,
    kind: String,
}

fn frozen_event_names() -> BTreeSet<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("compat")
        .join("upstream")
        .join("inventories")
        .join("gateway-protocol.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "frozen inventory at {} is readable: {error}",
            path.display()
        )
    });
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    let inventory: Inventory =
        serde_json::from_str(raw).expect("the frozen inventory is valid JSON");
    inventory
        .items
        .into_iter()
        .filter(|item| item.kind == "event")
        .map(|item| item.id)
        .collect()
}

/// Independent restatement of `EventVisibility::admits`.
fn admits(visibility: EventVisibility, role: Role, granted: &[OperatorScope]) -> bool {
    match visibility {
        EventVisibility::Handshake => false,
        EventVisibility::AllAuthenticated => role != Role::Worker,
        EventVisibility::Node => role == Role::Node,
        EventVisibility::Operator(required) => {
            role == Role::Operator
                && (granted.contains(&OperatorScope::Admin)
                    || granted.contains(&required)
                    || (required == OperatorScope::Read && granted.contains(&OperatorScope::Write)))
        }
    }
}

/// Expands `bits` into the corresponding subset of the six operator scopes.
fn subset(bits: u8) -> Vec<OperatorScope> {
    ALL_SCOPES
        .iter()
        .enumerate()
        .filter(|(index, _)| bits & (1 << index) != 0)
        .map(|(_, scope)| *scope)
        .collect()
}

fn names(scopes: &[OperatorScope]) -> Vec<&'static str> {
    scopes.iter().copied().map(OperatorScope::as_str).collect()
}

#[test]
fn the_hand_written_policy_names_exactly_the_frozen_event_set() {
    let written: BTreeSet<&str> = POLICY.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        written.len(),
        POLICY.len(),
        "the policy table repeats a name"
    );

    let frozen = frozen_event_names();
    let written_owned: BTreeSet<String> = written.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        frozen.difference(&written_owned).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "frozen events with no written visibility policy"
    );
    assert_eq!(
        written_owned.difference(&frozen).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "written policy rows for events the frozen inventory does not declare"
    );
    assert_eq!(frozen.len(), 33);
}

#[test]
fn the_server_resolves_every_event_to_the_written_visibility() {
    for (name, expected) in POLICY {
        assert_eq!(
            event_visibility(name),
            Some(expected),
            "`{name}` does not resolve to the visibility this policy states"
        );
    }
}

#[test]
fn the_published_catalog_matches_the_written_policy_row_for_row() {
    let catalog: BTreeMap<&str, EventVisibility> = event_catalog().into_iter().collect();
    let written: BTreeMap<&str, EventVisibility> = POLICY.into_iter().collect();
    assert_eq!(catalog.len(), 33);
    assert_eq!(catalog, written);
}

#[test]
fn every_event_admits_exactly_the_written_role_and_scope_combinations() {
    let mut visible = 0_usize;
    let mut hidden = 0_usize;
    for (name, visibility) in POLICY {
        for role in [Role::Operator, Role::Node, Role::Worker] {
            for bits in 0_u8..64 {
                let granted = subset(bits);
                let expected = admits(visibility, role, &granted);
                assert_eq!(
                    visibility.admits(role, &granted),
                    expected,
                    "event={name} role={} scopes={:?}",
                    role.as_str(),
                    names(&granted)
                );
                if expected {
                    visible += 1;
                } else {
                    hidden += 1;
                }
            }
        }
    }
    // 33 events x 3 roles x 64 subsets.
    assert_eq!(visible + hidden, 33 * 3 * 64);
    assert_eq!(visible + hidden, 6_336);
    assert!(hidden > visible, "expected the matrix to be denial-heavy");
    assert!(visible > 0);
}

#[test]
fn no_event_is_ever_delivered_to_a_worker() {
    for (name, visibility) in POLICY {
        for bits in 0_u8..64 {
            assert!(
                !visibility.admits(Role::Worker, &subset(bits)),
                "`{name}` leaked to a worker holding {:?}",
                names(&subset(bits))
            );
        }
    }
}

#[test]
fn no_operator_scoped_event_reaches_a_node_holding_every_scope() {
    let mut checked = 0_usize;
    for (name, visibility) in POLICY {
        if !matches!(visibility, EventVisibility::Operator(_)) {
            continue;
        }
        assert!(
            !visibility.admits(Role::Node, &ALL_SCOPES),
            "`{name}` leaked to a node connection"
        );
        checked += 1;
    }
    // 33 events less `connect.challenge`, `node.invoke.request` and the three
    // `AllAuthenticated` liveness signals.
    assert_eq!(checked, 33 - 1 - 1 - 3);
}

#[test]
fn no_event_reaches_an_operator_holding_no_scopes_at_all() {
    for (name, visibility) in POLICY {
        if visibility == EventVisibility::AllAuthenticated {
            continue;
        }
        assert!(
            !visibility.admits(Role::Operator, &[]),
            "`{name}` was delivered to an operator with an empty grant"
        );
    }
}

#[test]
fn the_handshake_event_is_never_delivered_over_an_authenticated_subscription() {
    for role in [Role::Operator, Role::Node, Role::Worker] {
        for bits in 0_u8..64 {
            assert!(
                !HANDSHAKE.admits(role, &subset(bits)),
                "connect.challenge escaped the pre-authentication path"
            );
        }
    }
    assert_eq!(event_visibility("connect.challenge"), Some(HANDSHAKE));
}

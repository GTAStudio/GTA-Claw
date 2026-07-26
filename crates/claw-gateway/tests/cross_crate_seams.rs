//! Binds the two cross-crate seams a second Gateway client would trip over.
//!
//! # Scope identities
//!
//! A server emits scope strings via [`OperatorScope::as_str`]; a client turns
//! them back into authority with [`Scope::parse`]. These are two independent
//! enums in two crates connected by no shared type.
//!
//! **The identity direction is already guarded, and these tests restate it
//! rather than establish it.** Each enum is independently pinned to the frozen
//! inventory — by `claw-security`'s `tests/frozen_gateway_registry.rs` and by
//! `claw-protocol`'s own registry tests — so `A == frozen` and `B == frozen`
//! gives `A == B` transitively. Renaming a scope in one crate, *including*
//! updating that crate's own test literal in the same commit, is already caught.
//! Verified by mutation, not assumed.
//!
//! **The rejection direction was guarded nowhere, and that is what
//! [`a_scope_string_from_one_crate_is_never_silently_accepted_by_the_other`]
//! adds.** Both frozen tests compare the *set of accepted identities*, so a
//! parser that additionally accepts an alias — `"operator.talkSecrets"` beside
//! `"operator.talk.secrets"`, say — changes no identity and no `as_str`, and
//! passes every existing test in both crates. Confirmed by mutation: adding
//! that one alias left all 33 `claw-security` tests green, including its
//! frozen both-directions test, and failed only here. A one-sided lenient
//! parser is how two clients come to disagree about what a scope string means.
//!
//! # Connection epochs
//!
//! A client core must be able to construct [`ConnectionState::Ready`] to prove
//! it binds authorization to a connection lifecycle rather than to a reusable
//! summary. That needs `ConnectionEpoch`, which is otherwise unconstructable
//! outside `claw-gateway-client`.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;

use claw_gateway_client::{ConnectionEpoch, ConnectionInfo, ConnectionState, ReadyConnection};
use claw_protocol::gateway::{OperatorScope, ProtocolVersion};
use claw_security::authorization::Scope;
use serde::Deserialize;

#[derive(Deserialize)]
struct Inventory {
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    kind: String,
    id: String,
}

/// Reads the frozen inventory from the repository at run time.
fn frozen_scope_identities() -> BTreeSet<String> {
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
    // The frozen inventories are checked in with a UTF-8 byte-order mark.
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
    let inventory: Inventory =
        serde_json::from_str(raw).expect("the frozen inventory is valid JSON");
    inventory
        .items
        .into_iter()
        .filter(|item| item.kind == "scope")
        .map(|item| item.id)
        .collect()
}

#[test]
fn the_frozen_scope_identities_are_exactly_the_six_this_server_was_written_against() {
    let frozen = frozen_scope_identities();
    let expected: BTreeSet<String> = [
        "operator.admin",
        "operator.approvals",
        "operator.pairing",
        "operator.read",
        "operator.talk.secrets",
        "operator.write",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(frozen, expected);
}

/// Restates a property already guaranteed transitively (see module docs); kept
/// so the seam is visible from the crate that depends on both sides.
#[test]
fn every_frozen_scope_identity_survives_the_protocol_to_security_seam() {
    for identity in frozen_scope_identities() {
        let emitted = OperatorScope::from_identity(&identity)
            .unwrap_or_else(|| panic!("claw-protocol cannot represent frozen scope `{identity}`"));
        assert_eq!(
            emitted.as_str(),
            identity,
            "claw-protocol emits a different string than the frozen identity"
        );

        let parsed = Scope::parse(&identity).unwrap_or_else(|error| {
            panic!("claw-security refuses the frozen scope `{identity}`: {error}")
        });
        assert_eq!(
            parsed.as_str(),
            identity,
            "claw-security round-trips `{identity}` to a different string"
        );

        // The seam itself: what the server writes is what the client reads.
        assert_eq!(
            Scope::parse(emitted.as_str())
                .expect("a scope emitted by claw-protocol parses in claw-security"),
            parsed,
            "the two crates disagree about `{identity}`"
        );
    }
}

/// Restates a property already guaranteed transitively (see module docs).
#[test]
fn neither_scope_enum_carries_an_identity_the_other_side_lacks() {
    let frozen = frozen_scope_identities();

    let protocol: BTreeSet<String> = frozen
        .iter()
        .filter_map(|identity| OperatorScope::from_identity(identity))
        .map(|scope| scope.as_str().to_owned())
        .collect();
    let security: BTreeSet<String> = Scope::ALL
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();

    assert_eq!(
        protocol, frozen,
        "claw-protocol and the frozen inventory disagree"
    );
    assert_eq!(
        security, frozen,
        "claw-security and the frozen inventory disagree"
    );
    assert_eq!(security, protocol, "the two scope enums have drifted apart");
}

/// The one assertion here that no existing test makes. Both crates' frozen
/// tests compare accepted-identity *sets*, so a one-sided lenient alias passes
/// them; this is what fails.
#[test]
fn a_scope_string_from_one_crate_is_never_silently_accepted_by_the_other() {
    // Casing and separator variants of real identities must fail on both sides,
    // so a mismatched pair can never be papered over by a lenient parser.
    for wrong in [
        "operator.talkSecrets",
        "Operator.read",
        "operator.READ",
        "operator.talk_secrets",
        "operator.talk.secret",
        "",
    ] {
        assert!(
            OperatorScope::from_identity(wrong).is_none(),
            "claw-protocol accepted `{wrong}`"
        );
        assert!(
            Scope::parse(wrong).is_err(),
            "claw-security accepted `{wrong}`"
        );
    }
}

fn ready(epoch: NonZeroU64, scopes: &[&str]) -> ConnectionState {
    ConnectionState::Ready(ReadyConnection {
        epoch: ConnectionEpoch::for_tests(epoch),
        info: ConnectionInfo {
            protocol: ProtocolVersion::new(4).expect("protocol 4 is positive"),
            server_version: "2026.7.2".to_owned(),
            connection_id: "conn-1".to_owned(),
            role: "operator".to_owned(),
            scopes: scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Arc<[String]>>(),
            advertised_method_count: 258,
            advertised_event_count: 33,
            max_payload_bytes: 1_048_576,
        },
    })
}

#[test]
fn a_client_core_can_build_two_distinguishable_ready_states() {
    let first = ready(
        NonZeroU64::new(1).expect("1 is non-zero"),
        &["operator.read"],
    );
    let second = ready(
        NonZeroU64::new(2).expect("2 is non-zero"),
        &["operator.read"],
    );

    let (ConnectionState::Ready(first), ConnectionState::Ready(second)) = (&first, &second) else {
        panic!("both states are Ready");
    };

    // Same server-visible summary, different lifecycle: a client that keeps only
    // `info` cannot tell these apart, which is precisely the staleness bug.
    assert_eq!(first.info, second.info);
    assert_ne!(first.epoch, second.epoch);
    assert_eq!(first.epoch.get(), 1);
    assert_eq!(second.epoch.get(), 2);
}

#[test]
fn a_ready_state_exposes_only_scopes_the_server_confirmed() {
    let state = ready(
        NonZeroU64::new(7).expect("7 is non-zero"),
        &["operator.read", "operator.write"],
    );
    let ConnectionState::Ready(ready) = state else {
        panic!("the state is Ready");
    };

    let granted: BTreeSet<Scope> = ready
        .info
        .scopes
        .iter()
        .map(|scope| Scope::parse(scope).expect("the server confirmed a real scope"))
        .collect();

    assert_eq!(
        granted,
        BTreeSet::from([Scope::OperatorRead, Scope::OperatorWrite])
    );
    assert!(!granted.contains(&Scope::OperatorAdmin));
    assert!(!granted.contains(&Scope::OperatorTalkSecrets));
}

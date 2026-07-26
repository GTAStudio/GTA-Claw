//! Proves that this crate's actions agree with the scope set the *upstream*
//! iOS client actually requests, using `claw-clients` as the subject.
//!
//! # Why this test exists
//!
//! `IosAction::required_scope` says which scope each action needs, and
//! `tests/frozen_scope_contract.rs` already proves those mappings against the
//! frozen Gateway inventory. Neither answers a different question: *which of
//! those scopes is an iOS client ever granted?*
//!
//! That question was answered to me twice in prose — once by the fleet
//! coordinator reading upstream's `NodeAppModel.swift`, and once implicitly by
//! `claw-clients`, which ports the frozen client surfaces. Prose is not a
//! subject. `compat/upstream/inventories/clients.json` records `client:ios`
//! only as `official_client_interop` with no scope grants at all, so the frozen
//! inventory in this repository cannot settle it either.
//!
//! `claw-clients` can, and it is on `main`. Every assertion below reads the
//! profile out of that crate rather than restating it here, so there is no
//! second copy of the grant set to drift. If `claw-clients` changes what iOS
//! requests, these tests change with it instead of silently disagreeing.
//!
//! One test goes further and runs the real `validate_gateway_profile` rather
//! than reading the list, because the scope set is a **ceiling, not a quota** —
//! the validator admits any subset. The enforceable claim is therefore not
//! "pairing is absent from a list" but "a profile requesting pairing is
//! refused". That framing is the Android session's, from #76.
//!
//! # What this test does not prove
//!
//! It does not prove upstream's Swift client requests these scopes. That source
//! is not vendored into this repository and cannot be read from here. It proves
//! this crate agrees with `claw-clients`, which is the closest executable
//! subject available.

use claw_clients::{
    ConnectionContract, GatewayProfile, SurfaceId, surface, validate_gateway_profile,
};
use claw_gateway_client::ConnectionInfo;
use claw_protocol::gateway::{ClientId, ClientMode, GATEWAY_PROTOCOL_VERSION, OperatorScope, Role};
use gta_claw_ios::{IosAction, ObservedAuthorization};

/// Reads the operator profile the iOS surface presents to a Gateway v4 server.
fn ios_operator_scopes() -> &'static [OperatorScope] {
    let ConnectionContract::GatewayV4(profiles) = surface(SurfaceId::Ios).connection else {
        panic!(
            "the iOS surface must connect over Gateway v4, but claw-clients describes it as {:?}",
            surface(SurfaceId::Ios).connection
        );
    };

    let operator = profiles
        .iter()
        .find(|profile| profile.mode == ClientMode::Ui)
        .unwrap_or_else(|| {
            panic!(
                "the iOS surface must offer a Ui-mode profile, but claw-clients lists modes {:?}",
                profiles.iter().map(|p| p.mode).collect::<Vec<_>>()
            )
        });

    operator.scopes
}

/// Builds the authorization this client would derive from that exact profile.
fn authorization_from_upstream_profile() -> ObservedAuthorization {
    let scopes: Vec<String> = ios_operator_scopes()
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect();

    let info = ConnectionInfo {
        protocol: GATEWAY_PROTOCOL_VERSION,
        server_version: "2026.7.2".to_owned(),
        connection_id: "upstream-profile".to_owned(),
        role: "operator".to_owned(),
        scopes: scopes.into(),
        advertised_method_count: 0,
        advertised_event_count: 0,
        max_payload_bytes: 1024,
    };

    ObservedAuthorization::from_connection(&info)
}

/// Renders an observed scope set as wire identities.
///
/// `ScopeSet`'s own `Debug` prints a bitmask (`ScopeSet(47)`), which cannot be
/// read from a CI log by anyone who is not holding the enum's discriminants.
fn readable(observed: &ObservedAuthorization) -> Vec<&'static str> {
    claw_security::authorization::Scope::ALL
        .into_iter()
        .filter(|scope| observed.scopes().contains(*scope))
        .map(claw_security::authorization::Scope::as_str)
        .collect()
}

/// Control. Runs first and must pass, or the four tests below prove nothing.
///
/// Without this, "iOS is not granted pairing" would also be satisfied by an
/// unreachable surface, an empty profile list or a scope set this crate failed
/// to parse. Each of those would make every other assertion here vacuously true.
#[test]
fn control_the_upstream_ios_profile_is_reachable_and_populated() {
    let scopes = ios_operator_scopes();
    assert!(
        !scopes.is_empty(),
        "claw-clients must describe a non-empty iOS operator scope set, but it read {scopes:?}"
    );

    let observed = authorization_from_upstream_profile();
    assert!(
        observed.unrecognized_scopes().is_empty(),
        "this crate must recognise every scope claw-clients requests for iOS; it failed to parse \
         {:?} out of the full set {scopes:?}",
        observed.unrecognized_scopes()
    );
    for requested in scopes {
        let parsed = claw_security::authorization::Scope::parse(requested.as_str())
            .unwrap_or_else(|_| panic!("this crate must understand {requested:?}"));
        assert!(
            observed.scopes().contains(parsed),
            "every scope claw-clients requests for iOS must survive into the observed set, but \
             {requested:?} did not; the full requested set was {scopes:?} and the observed set \
             was {:?}",
            readable(&observed)
        );
    }
}

#[test]
fn upstream_ios_is_not_granted_the_pairing_scope() {
    let scopes = ios_operator_scopes();

    assert!(
        !scopes.contains(&OperatorScope::Pairing),
        "claw-clients must not request operator.pairing for iOS; the full requested set read \
         {scopes:?}. If this now fails, upstream's iOS client gained pairing authority and \
         IosAction::ManagePairing has become reachable — see the module docs before changing it."
    );
}

#[test]
fn this_client_never_reports_a_pairing_grant_it_cannot_have() {
    let observed = authorization_from_upstream_profile();

    assert!(
        !observed.grants(IosAction::ManagePairing),
        "an authorization built from the upstream iOS profile must refuse ManagePairing (needs \
         {:?}), but it granted it from the observed scopes {:?}",
        IosAction::ManagePairing.required_scope(),
        readable(&observed)
    );
}

/// The other four actions must be granted, or the test above passes for the
/// wrong reason — a `grants` that always returned `false` would satisfy it.
#[test]
fn every_other_action_is_granted_by_the_upstream_profile() {
    let observed = authorization_from_upstream_profile();

    for action in IosAction::ALL {
        if action == IosAction::ManagePairing {
            continue;
        }
        assert!(
            observed.grants(action),
            "the upstream iOS profile must grant {action:?} (needs {:?}), but the observed scopes \
             {:?} did not. If ManagePairing is the only refusal, that refusal is meaningful; if \
             everything is refused, grants() is broken rather than strict.",
            action.required_scope(),
            readable(&observed)
        );
    }
}

/// Runs the *real* contract validator, not a reading of the scope list.
///
/// `validate_gateway_profile` admits any **subset** of a surface's scopes, so
/// the list is a ceiling rather than a quota. That makes the enforceable claim
/// stronger than "pairing is absent from the list": a profile requesting
/// `operator.pairing` for iOS is actively refused.
///
/// Credit where due — this framing is the Android session's, from #76.
#[test]
fn the_contract_refuses_an_ios_profile_that_requests_pairing() {
    const READ_ONLY: &[OperatorScope] = &[OperatorScope::Read];
    const READ_PLUS_PAIRING: &[OperatorScope] = &[OperatorScope::Read, OperatorScope::Pairing];

    let candidate = |scopes: &'static [OperatorScope]| GatewayProfile {
        client_id: ClientId::Ios,
        mode: ClientMode::Ui,
        role: Role::Operator,
        scopes,
        requires_device_identity: true,
    };

    let admitted = validate_gateway_profile(
        SurfaceId::Ios,
        candidate(READ_ONLY),
        GATEWAY_PROTOCOL_VERSION.get(),
    );
    assert!(
        admitted.is_ok(),
        "control: a read-only iOS profile must be admitted, or the refusal below proves nothing \
         about pairing specifically. It returned {admitted:?}"
    );

    let refused = validate_gateway_profile(
        SurfaceId::Ios,
        candidate(READ_PLUS_PAIRING),
        GATEWAY_PROTOCOL_VERSION.get(),
    );
    assert!(
        refused.is_err(),
        "the frozen contract must refuse an iOS profile requesting operator.pairing, but it \
         returned {refused:?}. The only difference from the admitted control above is the added \
         Pairing scope."
    );
}

/// Records a real gap in the other direction, so it cannot change unnoticed.
#[test]
fn talk_secrets_is_granted_to_ios_but_no_action_here_models_it() {
    let scopes = ios_operator_scopes();
    assert!(
        scopes.contains(&OperatorScope::TalkSecrets),
        "upstream iOS is expected to request operator.talk.secrets; the requested set read \
         {scopes:?}"
    );

    let modelled: Vec<_> = IosAction::ALL
        .into_iter()
        .filter(|action| action.required_scope().as_str() == OperatorScope::TalkSecrets.as_str())
        .collect();

    assert!(
        modelled.is_empty(),
        "operator.talk.secrets is granted to iOS but deliberately unmodelled by this crate, \
         because no Talk surface is built here yet. Actions now claiming it: {modelled:?}. If a \
         Talk action was added, delete this test rather than weakening it."
    );
}

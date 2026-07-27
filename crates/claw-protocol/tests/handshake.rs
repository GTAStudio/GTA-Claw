//! Acceptance evidence for `gateway.protocol.node-v3-window`.
//!
//! Wire citations: `packages/gateway-protocol/src/version.ts#L1-L8` and
//! `docs/gateway/protocol.md` at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`.
//!
//! Node-mode clients are admitted one protocol version below the current one,
//! but only through authentication: the window selects a compatibility path
//! before credentials are seen and is worthless until an authentication port
//! accepts the connection with a matching role and a verified device identity.
//! General clients never see the window at all.

use claw_protocol::gateway::{
    AuthenticationDecision, Codec, CompatibilityMode, ConnectChallenge, ConnectErrorDetailCode,
    DeviceProofDecision, Frame, HandshakeRejection, HelloOk, Negotiation, NegotiationError,
    NegotiationState, RequestId, Role,
};

fn preauth() -> Codec {
    Codec::preauthentication()
}

fn request_id(value: &str) -> RequestId {
    RequestId::new(value, 1024).expect("a short request id is within policy")
}

fn challenge() -> ConnectChallenge {
    let frame = preauth()
        .decode(
            br#"{"type":"event","event":"connect.challenge","payload":{"nonce":"nonce-1","ts":1737264000000}}"#,
        )
        .expect("the pinned challenge envelope decodes");
    let Frame::Event(event) = frame else {
        panic!("connect.challenge is carried by an event frame");
    };
    preauth()
        .decode_challenge(&event)
        .expect("the pinned challenge payload decodes")
}

fn connect_json(
    min: u64,
    max: u64,
    id: &str,
    mode: &str,
    role: Option<&str>,
    device: bool,
) -> String {
    let role = role.map_or_else(String::new, |role| format!(r#","role":"{role}""#));
    let device = if device {
        r#","device":{"id":"node-1","publicKey":"cHVi","signature":"c2ln","signedAt":1737264000000,"nonce":"nonce-1"}"#
    } else {
        ""
    };
    format!(
        r#"{{"type":"req","id":"connect-1","method":"connect","params":{{"minProtocol":{min},"maxProtocol":{max},"client":{{"id":"{id}","version":"2026.7.2","platform":"test","mode":"{mode}"}}{role}{device},"auth":{{"token":"secret"}}}}}}"#
    )
}

fn negotiate(
    min: u64,
    max: u64,
    id: &str,
    mode: &str,
    role: Option<&str>,
    device: bool,
) -> (Negotiation, Result<CompatibilityMode, NegotiationError>) {
    let mut negotiation = Negotiation::challenge_sent(challenge());
    let frame = preauth()
        .decode(connect_json(min, max, id, mode, role, device).as_bytes())
        .expect("the connect envelope decodes");
    negotiation
        .receive_first(frame, &preauth())
        .expect("a strict connect request is the legal first frame");
    let outcome = negotiation.check_protocol();
    (negotiation, outcome)
}

/// A v3 node that has passed the protocol check and is awaiting authentication.
fn legacy_node_awaiting_authentication(device: bool) -> Negotiation {
    let (negotiation, outcome) = negotiate(3, 3, "node-host", "node", Some("node"), device);
    assert_eq!(
        outcome.expect("an authenticated-mode node may offer v3"),
        CompatibilityMode::LegacyNode
    );
    assert_eq!(
        negotiation.state(),
        NegotiationState::AwaitingAuthentication
    );
    negotiation
}

fn hello_payload(role: &str) -> HelloOk {
    let response = format!(
        r#"{{"type":"res","id":"connect-1","ok":true,"payload":{{"type":"hello-ok","protocol":4,"server":{{"version":"2026.7.2","connId":"conn-1"}},"features":{{"methods":["health"],"events":["tick"]}},"snapshot":{{"presence":[],"health":null,"stateVersion":{{"presence":0,"health":0}},"uptimeMs":1}},"auth":{{"role":"{role}","scopes":[]}},"policy":{{"maxPayload":26214400,"maxBufferedBytes":52428800,"tickIntervalMs":15000}}}}}}"#
    );
    let response = preauth()
        .decode_response(response.as_bytes(), &request_id("connect-1"))
        .expect("the hello response envelope decodes");
    preauth()
        .decode_hello(&response)
        .expect("the hello payload decodes")
}

fn accepted(role: Role, device_proof: DeviceProofDecision) -> AuthenticationDecision {
    AuthenticationDecision::Accepted {
        role,
        scopes: Vec::new(),
        device_proof,
    }
}

#[test]
fn an_authenticated_node_completes_the_v3_handshake_and_still_receives_a_v4_hello() {
    let mut negotiation = Negotiation::challenge_sent(challenge());
    let frame = preauth()
        .decode(connect_json(3, 3, "node-host", "node", Some("node"), true).as_bytes())
        .expect("the v3 node connect envelope decodes");

    negotiation
        .receive_first(frame, &preauth())
        .expect("a strict connect request is the legal first frame");
    assert_eq!(negotiation.state(), NegotiationState::ConnectReceived);
    assert_eq!(
        negotiation
            .connect_id()
            .expect("the connect correlation id is retained")
            .as_str(),
        "connect-1"
    );

    assert_eq!(
        negotiation
            .check_protocol()
            .expect("a node offering only v3 is inside the N-1 window"),
        CompatibilityMode::LegacyNode
    );
    assert_eq!(
        negotiation.compatibility(),
        Some(CompatibilityMode::LegacyNode)
    );
    assert_eq!(
        negotiation.state(),
        NegotiationState::AwaitingAuthentication
    );

    negotiation
        .apply_authentication(accepted(Role::Node, DeviceProofDecision::Verified))
        .expect("a node with a verified device proof authenticates");
    assert_eq!(negotiation.state(), NegotiationState::Authenticated);

    negotiation
        .prepare_hello(hello_payload("node"))
        .expect("the legacy node is answered with the current protocol");
    negotiation.mark_hello_sent().expect("the hello is sent");
    negotiation.mark_ready().expect("the connection is ready");

    assert_eq!(negotiation.state(), NegotiationState::Ready);
    assert!(negotiation.rejection().is_none());
    assert_eq!(
        negotiation
            .hello()
            .expect("a prepared hello is retained")
            .protocol
            .get(),
        4,
        "a client admitted through the N-1 window is still told the current version"
    );
}

#[test]
fn general_clients_are_refused_the_exact_range_that_admits_a_node() {
    // Every one of these offers `3..=3` — the same range the node above used.
    const REFUSED: [(&str, &str, Option<&str>); 6] = [
        ("cli", "cli", None),
        ("openclaw-control-ui", "ui", None),
        ("cli", "cli", Some("operator")),
        ("node-host", "cli", Some("node")),
        ("node-host", "node", None),
        ("openclaw-probe", "cli", None),
    ];

    for (id, mode, role) in REFUSED {
        let (negotiation, outcome) = negotiate(3, 3, id, mode, role, false);
        let error = outcome.expect_err("only an authenticated node or probe may offer v3");
        assert!(
            matches!(error, NegotiationError::Rejected(_)),
            "client {id}/{mode}/{role:?} must fail as a typed rejection, got {error:?}"
        );
        assert_eq!(negotiation.state(), NegotiationState::Rejected);
        assert_eq!(
            negotiation
                .rejection()
                .expect("the rejection is recorded")
                .code(),
            ConnectErrorDetailCode::ProtocolMismatch,
            "client {id}/{mode}/{role:?} must be refused as a protocol mismatch"
        );
    }

    // The node claim plus node mode is what opens the window, not the product id.
    let (_, outcome) = negotiate(3, 3, "cli", "node", Some("node"), true);
    assert_eq!(
        outcome.expect("a node-mode client claiming the node role is admitted"),
        CompatibilityMode::LegacyNode
    );
}

#[test]
fn the_node_window_is_exactly_one_version_wide() {
    const CASES: [(u64, u64, Option<CompatibilityMode>); 8] = [
        (4, 4, Some(CompatibilityMode::Current)),
        (3, 4, Some(CompatibilityMode::Current)),
        (1, 9, Some(CompatibilityMode::Current)),
        (3, 3, Some(CompatibilityMode::LegacyNode)),
        (2, 3, Some(CompatibilityMode::LegacyNode)),
        (2, 2, None),
        (1, 2, None),
        (5, 5, None),
    ];

    for (min, max, expected) in CASES {
        let (negotiation, outcome) = negotiate(min, max, "node-host", "node", Some("node"), true);
        match expected {
            Some(mode) => assert_eq!(
                outcome.expect("the range is inside the admitted set"),
                mode,
                "node range {min}..={max} selected the wrong compatibility path"
            ),
            None => {
                let error = outcome.expect_err("the range is outside the admitted set");
                assert!(
                    matches!(error, NegotiationError::Rejected(_)),
                    "node range {min}..={max} must fail as a typed rejection, got {error:?}"
                );
                assert_eq!(
                    negotiation
                        .rejection()
                        .expect("the rejection is recorded")
                        .code(),
                    ConnectErrorDetailCode::ProtocolMismatch,
                    "node range {min}..={max} must be refused as a protocol mismatch"
                );
            }
        }
    }
}

#[test]
fn the_v3_node_window_never_bypasses_authentication() {
    let mut skipping = legacy_node_awaiting_authentication(true);
    let error = skipping
        .prepare_hello(hello_payload("node"))
        .expect_err("a hello may not be prepared before authentication");
    assert!(
        matches!(
            error,
            NegotiationError::IllegalTransition {
                state: NegotiationState::AwaitingAuthentication,
                expected: NegotiationState::Authenticated,
                ..
            }
        ),
        "expected an illegal transition, got {error:?}"
    );
    assert_eq!(skipping.state(), NegotiationState::AwaitingAuthentication);
    assert!(skipping.hello().is_none());

    let mut refused = legacy_node_awaiting_authentication(true);
    let error = refused
        .apply_authentication(AuthenticationDecision::Rejected(HandshakeRejection::new(
            ConnectErrorDetailCode::AuthUnauthorized,
            "node credentials were refused",
        )))
        .expect_err("a refused authentication ends the negotiation");
    assert!(matches!(error, NegotiationError::Rejected(_)));
    assert_eq!(refused.state(), NegotiationState::Rejected);
    let rejection = refused
        .rejection()
        .expect("the external rejection is recorded verbatim");
    assert_eq!(rejection.code(), ConnectErrorDetailCode::AuthUnauthorized);
    assert_eq!(rejection.message(), "node credentials were refused");

    let error = refused
        .apply_authentication(accepted(Role::Node, DeviceProofDecision::Verified))
        .expect_err("a rejected negotiation cannot be revived by a later acceptance");
    assert!(
        matches!(
            error,
            NegotiationError::IllegalTransition {
                state: NegotiationState::Rejected,
                ..
            }
        ),
        "expected an illegal transition out of the rejected state, got {error:?}"
    );
}

#[test]
fn node_authentication_inside_the_window_requires_a_verified_device_identity() {
    let mut without_device = legacy_node_awaiting_authentication(false);
    let error = without_device
        .apply_authentication(accepted(Role::Node, DeviceProofDecision::NotRequired))
        .expect_err("a node may not authenticate without device identity");
    assert!(matches!(error, NegotiationError::Rejected(_)));
    assert_eq!(
        without_device
            .rejection()
            .expect("the rejection is recorded")
            .code(),
        ConnectErrorDetailCode::DeviceIdentityRequired
    );

    let mut unverified = legacy_node_awaiting_authentication(true);
    let error = unverified
        .apply_authentication(accepted(Role::Node, DeviceProofDecision::NotRequired))
        .expect_err("a supplied device proof must actually be verified");
    assert!(matches!(error, NegotiationError::Rejected(_)));
    assert_eq!(
        unverified
            .rejection()
            .expect("the rejection is recorded")
            .code(),
        ConnectErrorDetailCode::DeviceAuthInvalid
    );
}

#[test]
fn the_window_refuses_a_role_it_did_not_admit() {
    let mut negotiation = legacy_node_awaiting_authentication(true);
    let error = negotiation
        .apply_authentication(accepted(Role::Operator, DeviceProofDecision::Verified))
        .expect_err("a node request may not authenticate as an operator");
    assert!(matches!(error, NegotiationError::Rejected(_)));
    let rejection = negotiation
        .rejection()
        .expect("the rejection is recorded on the reducer");
    assert_eq!(rejection.code(), ConnectErrorDetailCode::AuthUnauthorized);
    assert_eq!(
        rejection.message(),
        "authenticated role does not match requested role"
    );

    let mut worker = legacy_node_awaiting_authentication(true);
    let error = worker
        .apply_authentication(accepted(Role::Worker, DeviceProofDecision::Verified))
        .expect_err("the closed worker role never travels the general handshake");
    assert!(matches!(error, NegotiationError::Rejected(_)));
    assert_eq!(
        worker
            .rejection()
            .expect("the rejection is recorded")
            .code(),
        ConnectErrorDetailCode::AuthUnauthorized
    );
}

#[test]
fn the_probe_window_mirrors_the_node_window_but_needs_full_probe_identity() {
    let (mut probe, outcome) = negotiate(3, 3, "openclaw-probe", "probe", None, false);
    assert_eq!(
        outcome.expect("a probe product in probe mode may offer v3"),
        CompatibilityMode::LegacyProbe
    );
    probe
        .apply_authentication(accepted(Role::Operator, DeviceProofDecision::NotRequired))
        .expect("a probe authenticates as an operator");
    assert_eq!(probe.state(), NegotiationState::Authenticated);

    // Half a probe identity is not a probe.
    const HALF: [(&str, &str); 2] = [("openclaw-probe", "cli"), ("cli", "probe")];
    for (id, mode) in HALF {
        let (negotiation, outcome) = negotiate(3, 3, id, mode, None, false);
        assert!(
            matches!(
                outcome.expect_err("a partial probe identity stays v4-only"),
                NegotiationError::Rejected(_)
            ),
            "client {id}/{mode} must not reach the probe window"
        );
        assert_eq!(
            negotiation
                .rejection()
                .expect("the rejection is recorded")
                .code(),
            ConnectErrorDetailCode::ProtocolMismatch
        );
    }

    // A probe that claims the node role leaves the probe branch entirely.
    let (_, outcome) = negotiate(3, 3, "openclaw-probe", "probe", Some("node"), true);
    assert!(matches!(
        outcome.expect_err("a probe-mode client cannot claim the node window"),
        NegotiationError::Rejected(_)
    ));
}

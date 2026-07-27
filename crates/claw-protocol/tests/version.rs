//! Acceptance evidence for `gateway.protocol.v4`.
//!
//! Wire citation: `packages/gateway-protocol/src/version.ts#L1-L8` at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`.
//!
//! The Gateway advertises exactly one current protocol version. A general
//! client — anything that is not an authenticated node or probe travelling
//! through the N-1 window — must offer a range that contains it. Every other
//! range is refused with a typed `protocol-mismatch` rejection, and a
//! successful handshake always announces the current version back.

use claw_protocol::gateway::{
    AuthenticationDecision, Codec, CompatibilityMode, ConnectChallenge, ConnectErrorDetailCode,
    DeviceProofDecision, Frame, GATEWAY_PROTOCOL_VERSION, HelloOk, MIN_GENERAL_PROTOCOL_VERSION,
    MIN_NODE_PROTOCOL_VERSION, MIN_PROBE_PROTOCOL_VERSION, Negotiation, NegotiationError,
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

fn connect_json(min: u64, max: u64, id: &str, mode: &str, role: Option<&str>) -> String {
    let role = role.map_or_else(String::new, |role| format!(r#","role":"{role}""#));
    format!(
        r#"{{"type":"req","id":"connect-1","method":"connect","params":{{"minProtocol":{min},"maxProtocol":{max},"client":{{"id":"{id}","version":"2026.7.2","platform":"test","mode":"{mode}"}}{role},"auth":{{"token":"secret"}}}}}}"#
    )
}

/// Drives challenge -> connect -> protocol check and returns both the reducer
/// and the exact protocol outcome, so accept and reject cases assert the same
/// observable state.
fn negotiate(
    min: u64,
    max: u64,
    id: &str,
    mode: &str,
    role: Option<&str>,
) -> (Negotiation, Result<CompatibilityMode, NegotiationError>) {
    let mut negotiation = Negotiation::challenge_sent(challenge());
    let frame = preauth()
        .decode(connect_json(min, max, id, mode, role).as_bytes())
        .expect("the connect envelope decodes");
    negotiation
        .receive_first(frame, &preauth())
        .expect("a strict connect request is the legal first frame");
    let outcome = negotiation.check_protocol();
    (negotiation, outcome)
}

fn hello_payload(protocol: u64, role: &str) -> HelloOk {
    let response = format!(
        r#"{{"type":"res","id":"connect-1","ok":true,"payload":{{"type":"hello-ok","protocol":{protocol},"server":{{"version":"2026.7.2","connId":"conn-1"}},"features":{{"methods":["health"],"events":["tick"]}},"snapshot":{{"presence":[],"health":null,"stateVersion":{{"presence":0,"health":0}},"uptimeMs":1}},"auth":{{"role":"{role}","scopes":[]}},"policy":{{"maxPayload":26214400,"maxBufferedBytes":52428800,"tickIntervalMs":15000}}}}}}"#
    );
    let response = preauth()
        .decode_response(response.as_bytes(), &request_id("connect-1"))
        .expect("the hello response envelope decodes");
    preauth()
        .decode_hello(&response)
        .expect("the hello payload decodes")
}

#[test]
fn protocol_constants_pin_v4_with_a_single_version_legacy_floor() {
    assert_eq!(
        GATEWAY_PROTOCOL_VERSION.get(),
        4,
        "the current Gateway protocol is version four"
    );
    assert_eq!(
        MIN_GENERAL_PROTOCOL_VERSION, GATEWAY_PROTOCOL_VERSION,
        "general clients have no legacy window at all"
    );
    assert_eq!(MIN_NODE_PROTOCOL_VERSION.get(), 3);
    assert_eq!(MIN_PROBE_PROTOCOL_VERSION.get(), 3);
    assert_eq!(
        MIN_NODE_PROTOCOL_VERSION.get() + 1,
        GATEWAY_PROTOCOL_VERSION.get(),
        "the node window is exactly N-1, never N-2"
    );
    assert_eq!(
        MIN_PROBE_PROTOCOL_VERSION.get() + 1,
        GATEWAY_PROTOCOL_VERSION.get(),
        "the probe window is exactly N-1, never N-2"
    );
}

#[test]
fn general_clients_negotiate_exactly_the_ranges_that_contain_v4() {
    // A general client is admitted if and only if `min <= 4 <= max`.
    const CASES: [(u64, u64, bool); 12] = [
        (4, 4, true),
        (1, 4, true),
        (3, 4, true),
        (4, 9, true),
        (2, 6, true),
        (1, 3, false),
        (2, 3, false),
        (3, 3, false),
        (1, 2, false),
        (1, 1, false),
        (5, 5, false),
        (5, 9, false),
    ];

    for (min, max, admitted) in CASES {
        let (negotiation, outcome) = negotiate(min, max, "cli", "cli", None);
        if admitted {
            assert_eq!(
                outcome.expect("a range containing four is admitted"),
                CompatibilityMode::Current,
                "range {min}..={max} must take the current path"
            );
            assert_eq!(
                negotiation.state(),
                NegotiationState::AwaitingAuthentication
            );
            assert!(
                negotiation.rejection().is_none(),
                "range {min}..={max} must not record a rejection"
            );
        } else {
            let error = outcome.expect_err("a range without four is refused");
            assert!(
                matches!(error, NegotiationError::Rejected(_)),
                "range {min}..={max} must fail as a typed rejection, got {error:?}"
            );
            assert_eq!(negotiation.state(), NegotiationState::Rejected);
            let rejection = negotiation
                .rejection()
                .expect("a refused negotiation records its rejection");
            assert_eq!(rejection.code(), ConnectErrorDetailCode::ProtocolMismatch);
            assert_eq!(
                rejection.message(),
                format!("unsupported protocol range {min}..={max}; current protocol is 4")
            );
            assert!(rejection.pairing_details().is_none());
        }
    }
}

#[test]
fn an_explicit_operator_role_is_still_locked_to_v4() {
    let (rejected, outcome) = negotiate(3, 3, "cli", "cli", Some("operator"));
    assert!(matches!(
        outcome.expect_err("an operator offering only v3 is refused"),
        NegotiationError::Rejected(_)
    ));
    assert_eq!(
        rejected
            .rejection()
            .expect("the rejection is recorded")
            .code(),
        ConnectErrorDetailCode::ProtocolMismatch
    );

    let (accepted, outcome) = negotiate(4, 4, "cli", "cli", Some("operator"));
    assert_eq!(
        outcome.expect("an operator offering v4 is admitted"),
        CompatibilityMode::Current
    );
    assert_eq!(accepted.state(), NegotiationState::AwaitingAuthentication);
}

#[test]
fn inverted_protocol_ranges_are_refused_before_version_selection() {
    let (negotiation, outcome) = negotiate(9, 4, "cli", "cli", None);

    assert!(matches!(
        outcome.expect_err("an inverted range is refused"),
        NegotiationError::Rejected(_)
    ));
    let rejection = negotiation
        .rejection()
        .expect("the rejection is recorded on the reducer");
    assert_eq!(rejection.code(), ConnectErrorDetailCode::ProtocolMismatch);
    assert_eq!(
        rejection.message(),
        "invalid protocol range 9..=4",
        "an inverted range is diagnosed as invalid, not as an unsupported version"
    );
}

#[test]
fn every_general_client_identity_is_locked_to_v4() {
    // Neither a probe product id without probe mode, nor node metadata without
    // a node role claim, widens the accepted version range.
    const GENERAL: [(&str, &str); 8] = [
        ("cli", "cli"),
        ("webchat-ui", "webchat"),
        ("openclaw-control-ui", "ui"),
        ("openclaw-tui", "cli"),
        ("gateway-client", "backend"),
        ("test", "test"),
        ("openclaw-probe", "cli"),
        ("node-host", "cli"),
    ];

    for (id, mode) in GENERAL {
        let (rejected, outcome) = negotiate(3, 3, id, mode, None);
        assert!(
            matches!(
                outcome.expect_err("v3 alone is never enough for a general client"),
                NegotiationError::Rejected(_)
            ),
            "client {id}/{mode} must not reach the N-1 window"
        );
        assert_eq!(
            rejected
                .rejection()
                .expect("the rejection is recorded")
                .code(),
            ConnectErrorDetailCode::ProtocolMismatch,
            "client {id}/{mode} must be refused as a protocol mismatch"
        );

        let (accepted, outcome) = negotiate(4, 4, id, mode, None);
        assert_eq!(
            outcome.expect("the same identity is admitted at v4"),
            CompatibilityMode::Current,
            "client {id}/{mode} must be admitted at v4"
        );
        assert_eq!(accepted.state(), NegotiationState::AwaitingAuthentication);
    }
}

#[test]
fn a_successful_handshake_announces_exactly_the_current_protocol() {
    let (mut negotiation, outcome) = negotiate(1, 9, "cli", "cli", None);
    assert_eq!(
        outcome.expect("a wide range containing four is admitted"),
        CompatibilityMode::Current
    );
    negotiation
        .apply_authentication(AuthenticationDecision::Accepted {
            role: Role::Operator,
            scopes: Vec::new(),
            device_proof: DeviceProofDecision::NotRequired,
        })
        .expect("an operator without device identity authenticates");
    assert_eq!(negotiation.state(), NegotiationState::Authenticated);

    let error = negotiation
        .prepare_hello(hello_payload(3, "operator"))
        .expect_err("a hello may never announce a version other than the current one");
    assert!(
        matches!(
            error,
            NegotiationError::HelloProtocolMustBeCurrent { received: 3 }
        ),
        "expected a current-protocol failure, got {error:?}"
    );
    assert_eq!(
        negotiation.state(),
        NegotiationState::Authenticated,
        "a refused hello leaves the reducer where it was"
    );

    let error = negotiation
        .prepare_hello(hello_payload(5, "operator"))
        .expect_err("a hello may not announce a future version either");
    assert!(matches!(
        error,
        NegotiationError::HelloProtocolMustBeCurrent { received: 5 }
    ));

    negotiation
        .prepare_hello(hello_payload(4, "operator"))
        .expect("the current protocol is accepted");
    assert_eq!(negotiation.state(), NegotiationState::HelloPrepared);
    assert_eq!(
        negotiation
            .hello()
            .expect("a prepared hello is retained")
            .protocol,
        GATEWAY_PROTOCOL_VERSION
    );

    negotiation.mark_hello_sent().expect("the hello is sent");
    negotiation.mark_ready().expect("the connection is ready");
    assert_eq!(negotiation.state(), NegotiationState::Ready);
}

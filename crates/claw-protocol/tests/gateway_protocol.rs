//! Acceptance coverage for the pinned OpenClaw Gateway v4 contract.
//!
//! Wire citations:
//! - `packages/gateway-protocol/src/schema/frames.ts#L35-L212`
//! - `packages/gateway-protocol/src/schema/snapshot.ts#L10-L76`
//! - `packages/gateway-protocol/src/client-info.ts#L15-L52`
//! - `packages/gateway-protocol/src/version.ts#L1-L8`
//!
//! at `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`.

use std::collections::BTreeSet;

use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, AuthenticationDecision, AuthorizationError, ClientMode, Codec,
    CodecError, CompatibilityMode, ConnectChallenge, ConnectErrorDetailCode, CoreErrorCode,
    DeviceProofDecision, DynamicPluginRegistry, ErrorCode, EventName, EventSequence,
    EventSequenceError, EventSequenceTracker, Frame, GatewayMethod, GatewayMethodName, MethodScope,
    Negotiation, NegotiationError, NegotiationState, NonNegativeInteger, OpaqueField, OpaqueJson,
    OperatorScope, PREAUTH_MAX_FRAME_BYTES, PairingRequiredReason, PluginLookup, RegistryError,
    RequestFrame, Role, TransportPhase, ValidationPolicy, authorize_named, core_events,
    core_methods, operator_scopes, resolve_core_method, resolve_gateway_method, roles,
};
use serde::Deserialize;

const PINNED_SHA: &str = "b43e832fcc8000ed7287c7accc54e381db607f85";

fn preauth() -> Codec {
    Codec::preauthentication()
}

fn decode(bytes: &str) -> Result<Frame, CodecError> {
    preauth().decode(bytes.as_bytes())
}

fn challenge() -> ConnectChallenge {
    // `src/gateway/server/ws-connection.ts#L424-L432` at PINNED_SHA.
    let event = decode(
        r#"{"type":"event","event":"connect.challenge","payload":{"nonce":"nonce-1","ts":1737264000000}}"#,
    )
    .expect("valid challenge event");
    let Frame::Event(event) = event else {
        panic!("expected event");
    };
    preauth()
        .decode_challenge(&event)
        .expect("valid challenge payload")
}

fn connect_json(min: u64, max: u64, mode: &str, role: Option<&str>) -> String {
    let id = match mode {
        "node" => "node-host",
        "probe" => "openclaw-probe",
        "worker" => "openclaw-worker",
        _ => "cli",
    };
    connect_identity_json(min, max, id, mode, role)
}

fn connect_identity_json(min: u64, max: u64, id: &str, mode: &str, role: Option<&str>) -> String {
    let role = role.map_or_else(String::new, |role| format!(r#","role":"{role}""#));
    let device = if mode == "node" {
        r#","device":{"id":"node-1","publicKey":"cHVi","signature":"c2ln","signedAt":1737264000000,"nonce":"nonce-1"}"#
    } else {
        ""
    };
    format!(
        r#"{{"type":"req","id":"connect-1","method":"connect","params":{{"minProtocol":{min},"maxProtocol":{max},"client":{{"id":"{id}","version":"2026.7.2","platform":"test","mode":"{mode}"}}{role}{device},"auth":{{"token":"secret"}}}}}}"#
    )
}

fn hello(role: Role, scopes: &[OperatorScope]) -> claw_protocol::gateway::HelloOk {
    // `packages/gateway-protocol/src/schema/frames.ts#L89-L156` at PINNED_SHA.
    let scopes = scopes
        .iter()
        .map(|scope| format!(r#""{}""#, scope.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    let response = format!(
        r#"{{"type":"res","id":"connect-1","ok":true,"payload":{{"type":"hello-ok","protocol":4,"server":{{"version":"2026.7.2","connId":"conn-1"}},"features":{{"methods":["health"],"events":["tick"],"capabilities":["chat-send-routing-contract"]}},"snapshot":{{"presence":[],"health":null,"stateVersion":{{"presence":0,"health":0}},"uptimeMs":1,"authMode":"token","updateAvailable":{{"currentVersion":"2026.7.2","latestVersion":"2026.7.3","channel":"stable","rollout":"gradual"}}}},"controlUiTabs":[{{"pluginId":"example","id":"tab","label":"Example","group":"control","order":1.5}}],"pluginSurfaceUrls":{{"canvas":"https://gateway.invalid/canvas"}},"auth":{{"role":"{}","scopes":[{scopes}]}},"policy":{{"maxPayload":26214400,"maxBufferedBytes":52428800,"tickIntervalMs":15000}}}}}}"#,
        role.as_str()
    );
    let response = preauth()
        .decode_response(response.as_bytes(), &request_id("connect-1"))
        .expect("valid hello response");
    preauth().decode_hello(&response).expect("valid hello")
}

fn request_id(value: &str) -> claw_protocol::gateway::RequestId {
    claw_protocol::gateway::RequestId::new(value, 1024).expect("valid request id")
}

fn drive_to_authentication(min: u64, max: u64, mode: &str, role: Option<&str>) -> Negotiation {
    let mut negotiation = Negotiation::challenge_sent(challenge());
    let frame = decode(&connect_json(min, max, mode, role)).expect("valid connect envelope");
    negotiation
        .receive_first(frame, &preauth())
        .expect("strict connect");
    negotiation
}

#[test]
fn decodes_exact_envelopes_and_preserves_null() {
    // `frames.ts#L171-L204`: closed req/res/event envelopes and Unknown optionals.
    let Frame::Request(request) =
        decode(r#"{"type":"req","id":"1","method":"health","params":null}"#)
            .expect("request with explicit null")
    else {
        panic!("expected request");
    };
    assert!(matches!(
        request.params(),
        claw_protocol::gateway::OpaqueField::Null
    ));

    let Frame::Request(request) =
        decode(r#"{"type":"req","id":"2","method":"health"}"#).expect("omitted params")
    else {
        panic!("expected request");
    };
    assert!(request.params().is_omitted());

    let success_with_error = decode(
        r#"{"type":"res","id":"1","ok":true,"error":{"code":"ODD","message":"allowed","details":null}}"#,
    )
    .expect("schema permits error on success");
    let Frame::Response(response) = success_with_error else {
        panic!("expected response");
    };
    assert!(response.ok());
    assert!(matches!(
        response.error().expect("error").details,
        claw_protocol::gateway::OpaqueField::Null
    ));

    let failure_with_payload =
        decode(r#"{"type":"res","id":"1","ok":false,"payload":{"partial":true}}"#)
            .expect("schema permits payload and no error on failure");
    assert!(matches!(failure_with_payload, Frame::Response(_)));

    let Frame::Event(event) =
        decode(r#"{"type":"event","event":"future.event","payload":null,"seq":1}"#)
            .expect("extension event")
    else {
        panic!("expected event");
    };
    assert!(matches!(event.event(), EventName::Extension(_)));
    assert_eq!(event.sequence().expect("sequence").get(), 1);
}

#[test]
fn decodes_connect_and_device_proof_fixture() {
    // `frames.ts#L35-L86`; device signature fields at lines 62-71.
    let json = r#"{"type":"req","id":"connect-1","method":"connect","params":{"minProtocol":4,"maxProtocol":4,"client":{"id":"cli","displayName":"CLI","version":"2026.7.2","platform":"windows","deviceFamily":"desktop","modelIdentifier":"pc","mode":"cli","instanceId":"instance-1"},"caps":["tool-events"],"commands":[],"permissions":{"camera.capture":false},"pathEnv":"","role":"operator","scopes":["operator.read"],"device":{"id":"device-1","publicKey":"cHVi","signature":"c2ln","signedAt":1737264000000,"nonce":"nonce-1"},"auth":{"token":"","bootstrapToken":"boot","deviceToken":"device-token","password":"","approvalRuntimeToken":"approval","agentRuntimeIdentityToken":"agent"},"locale":"","userAgent":""}}"#;
    let Frame::Request(request) = decode(json).expect("valid connect") else {
        panic!("expected request");
    };
    let params = preauth().decode_connect(&request).expect("typed connect");
    assert_eq!(params.client.mode, ClientMode::Cli);
    let proof = params.device.expect("device proof");
    assert_eq!(proof.nonce.as_str(), "nonce-1");
    assert_eq!(proof.signature.as_str(), "c2ln");
    assert_eq!(
        params.auth.expect("auth").approval_runtime_token.as_deref(),
        Some("approval")
    );
}

#[test]
fn decodes_full_hello_snapshot_fixture() {
    // `packages/gateway-protocol/src/schema/frames.ts#L89-L156` and
    // `schema/snapshot.ts#L44-L76` at PINNED_SHA.
    let hello = hello(Role::Operator, &[OperatorScope::Read]);
    assert_eq!(hello.protocol.get(), 4);
    assert_eq!(hello.server.conn_id.as_str(), "conn-1");
    assert_eq!(hello.snapshot.state_version.presence.get(), 0);
    assert_eq!(hello.snapshot.health.as_json(), "null");
    assert_eq!(
        hello.control_ui_tabs.expect("tabs")[0]
            .order
            .expect("order")
            .get(),
        1.5
    );
    assert_eq!(
        hello
            .plugin_surface_urls
            .expect("surface")
            .values()
            .next()
            .expect("url")
            .as_str(),
        "https://gateway.invalid/canvas"
    );
    let update = hello
        .snapshot
        .update_available
        .as_ref()
        .expect("update metadata");
    assert_eq!(
        update
            .extensions
            .get("rollout")
            .expect("additive field")
            .as_json(),
        r#""gradual""#
    );
}

#[test]
fn rejects_hello_payload_on_unsuccessful_response() {
    // Client success branching: `packages/gateway-client/src/client.ts#L1409-L1445`.
    let payload = serde_json::to_string(&hello(Role::Operator, &[OperatorScope::Read]))
        .expect("serialize hello");
    let response = format!(
        r#"{{"type":"res","id":"connect-1","ok":false,"payload":{payload},"error":{{"code":"INVALID_REQUEST","message":"rejected"}}}}"#
    );
    let response = preauth()
        .decode_response(response.as_bytes(), &request_id("connect-1"))
        .expect("schema-valid failed response");
    assert!(matches!(
        preauth().decode_hello(&response),
        Err(CodecError::UnsuccessfulResponse { .. })
    ));
}

#[test]
fn rejects_duplicate_keys_everywhere() {
    // Raw duplicate hardening around `JSON.parse` call sites:
    // `src/gateway/server/ws-connection/message-handler.ts#L784-L830`.
    assert!(matches!(
        decode(r#"{"type":"req","type":"res","id":"1","method":"health"}"#),
        Err(CodecError::DuplicateKey { path, key }) if path == "$" && key == "type"
    ));
    assert!(matches!(
        decode(r#"{"type":"req","id":"1","method":"health","params":{"nested":{"x":1,"x":2}}}"#),
        Err(CodecError::DuplicateKey { path, key })
            if path.contains("nested") && key == "x"
    ));
}

#[test]
fn rejects_contradictory_unknown_and_malformed_frames() {
    // Discriminated closed envelopes: `schema/frames.ts#L171-L212`.
    assert!(matches!(
        decode(r#"{"type":"req","id":"1","method":"health","event":"tick"}"#),
        Err(CodecError::ContradictoryEnvelopeField { kind, field })
            if kind == "req" && field == "event"
    ));
    assert!(matches!(
        decode(r#"{"type":"event","event":"tick","ok":true}"#),
        Err(CodecError::ContradictoryEnvelopeField { kind, field })
            if kind == "event" && field == "ok"
    ));
    assert!(matches!(
        decode(r#"{"type":"future","id":"1"}"#),
        Err(CodecError::UnknownFrameKind(kind)) if kind == "future"
    ));
    assert!(matches!(
        decode(r#"{"type":"req","id":"1","method":"health"} trailing"#),
        Err(CodecError::MalformedJson { .. })
    ));
    assert!(matches!(
        decode(r#"{"type":"req""#),
        Err(CodecError::MalformedJson { .. })
    ));
    assert!(matches!(
        decode(r#"{"type":"event","event":"tick","seq":null}"#),
        Err(CodecError::TypedDecode { path, .. }) if path.contains("seq")
    ));
}

#[test]
fn enforces_size_collection_nesting_and_name_policies() {
    // Proven transport caps: `src/gateway/server-constants.ts#L1-L4`.
    let oversized = vec![b' '; AUTHENTICATED_MAX_FRAME_BYTES + 1];
    assert!(matches!(
        Codec::authenticated().decode(&oversized),
        Err(CodecError::FrameTooLarge {
            phase: TransportPhase::Authenticated,
            ..
        })
    ));

    let mut collection_policy = ValidationPolicy::for_phase(TransportPhase::PreAuthentication);
    collection_policy.max_collection_items = 4;
    let codec = Codec::new(TransportPhase::PreAuthentication, collection_policy).expect("policy");
    assert!(matches!(
        codec.decode(br#"{"type":"req","id":"1","method":"health","params":[1,2,3,4,5]}"#),
        Err(CodecError::CollectionLimit { .. })
    ));

    let mut nesting_policy = ValidationPolicy::for_phase(TransportPhase::PreAuthentication);
    nesting_policy.max_nesting_depth = 2;
    let codec = Codec::new(TransportPhase::PreAuthentication, nesting_policy).expect("policy");
    assert!(matches!(
        codec.decode(br#"{"type":"req","id":"1","method":"health","params":{"a":{"b":1}}}"#),
        Err(CodecError::NestingLimit { .. })
    ));

    let mut id_policy = ValidationPolicy::for_phase(TransportPhase::PreAuthentication);
    id_policy.max_request_id_bytes = 2;
    let codec = Codec::new(TransportPhase::PreAuthentication, id_policy).expect("policy");
    assert!(matches!(
        codec.decode(br#"{"type":"req","id":"123","method":"health"}"#),
        Err(CodecError::PolicyLimit { path, .. }) if path == "$.id"
    ));
}

#[test]
fn rejects_overflow_negative_zero_and_nonfinite_like_numbers() {
    // Integer frame fields: `schema/frames.ts#L159-L204`.
    assert!(matches!(
        decode(r#"{"type":"event","event":"tick","seq":18446744073709551616}"#),
        Err(CodecError::MalformedJson { .. }) | Err(CodecError::TypedDecode { .. })
    ));
    assert!(matches!(
        decode(r#"{"type":"event","event":"tick","seq":-1}"#),
        Err(CodecError::TypedDecode { path, .. }) if path.contains("seq")
    ));
    assert!(matches!(
        decode(r#"{"type":"event","event":"tick","seq":0}"#),
        Err(CodecError::TypedDecode { path, .. }) if path.contains("seq")
    ));
    assert!(matches!(
        decode(r#"{"type":"event","event":"tick","payload":1e400}"#),
        Err(CodecError::MalformedJson { .. }) | Err(CodecError::NonFiniteNumber { .. })
    ));
    assert!(matches!(
        decode(r#"{"type":"event","event":"tick","payload":NaN}"#),
        Err(CodecError::MalformedJson { .. })
    ));
}

#[test]
fn accepts_json_number_forms_that_are_mathematically_integers() {
    // TypeBox `Type.Integer` follows JSON Schema number semantics, so 1.0 and
    // exponent notation remain integer values (`frames.ts#L194-L204`).
    let Frame::Event(event) =
        decode(r#"{"type":"event","event":"tick","seq":1.0,"payload":{"ts":1e3}}"#)
            .expect("integral JSON number forms")
    else {
        panic!("expected event");
    };
    assert_eq!(event.sequence().expect("sequence").get(), 1);
    let tick = preauth().decode_tick(&event).expect("integral timestamp");
    assert_eq!(tick.ts.get(), 1000);
}

#[test]
fn validates_response_ids_and_event_gaps_without_panics() {
    // Echo/gap behavior: `message-handler.ts#L2687-L2694` and
    // `packages/gateway-client/src/client.ts#L1392-L1399`.
    assert!(matches!(
        preauth().decode_response(
            br#"{"type":"res","id":"other","ok":true}"#,
            &request_id("expected")
        ),
        Err(CodecError::ResponseIdMismatch { expected, received })
            if expected == "expected" && received == "other"
    ));

    let mut tracker = EventSequenceTracker::new();
    tracker
        .observe(Some(EventSequence::new(1).expect("positive")))
        .expect("first event");
    assert_eq!(
        tracker.observe(Some(EventSequence::new(3).expect("positive"))),
        Err(EventSequenceError::Gap {
            expected: 2,
            received: 3
        })
    );
    assert_eq!(tracker.last().expect("updated after gap").get(), 3);
    assert_eq!(
        tracker.observe(Some(EventSequence::new(3).expect("positive"))),
        Err(EventSequenceError::NonMonotonic {
            last: 3,
            received: 3
        })
    );
    tracker.observe(None).expect("targeted event");
}

#[test]
fn encodes_strict_frames_and_enforces_outbound_cap() {
    // Closed request envelope: `schema/frames.ts#L171-L179`.
    let frame = decode(r#"{"type":"req","id":"1","method":"health","params":{"ok":true}}"#)
        .expect("request");
    let encoded = preauth().encode(&frame).expect("encode");
    assert!(matches!(
        preauth().decode(&encoded).expect("round trip"),
        Frame::Request(_)
    ));

    let huge = format!(
        r#""{}""#,
        "x".repeat(PREAUTH_MAX_FRAME_BYTES.saturating_mul(16))
    );
    let opaque: OpaqueJson = serde_json::from_str(&huge).expect("opaque JSON");
    let health = resolve_core_method("health").expect("health method");
    let frame = Frame::Request(RequestFrame::new(
        request_id("1"),
        GatewayMethodName::Core(health),
        OpaqueField::Value(opaque),
    ));
    assert!(matches!(
        preauth().encode(&frame),
        Err(CodecError::FrameTooLarge {
            phase: TransportPhase::PreAuthentication,
            ..
        })
    ));
}

#[test]
fn negotiates_current_protocol_to_ready() {
    // Ordering: `message-handler.ts#L822-L952` and `#L2475-L2590`.
    let mut negotiation = drive_to_authentication(4, 4, "cli", Some("operator"));
    assert_eq!(
        negotiation.check_protocol().expect("v4"),
        CompatibilityMode::Current
    );
    negotiation
        .apply_authentication(AuthenticationDecision::Accepted {
            role: Role::Operator,
            scopes: vec![OperatorScope::Read],
            device_proof: DeviceProofDecision::NotRequired,
        })
        .expect("authenticated");
    negotiation
        .prepare_hello(hello(Role::Operator, &[OperatorScope::Read]))
        .expect("hello");
    negotiation.mark_hello_sent().expect("sent");
    negotiation.mark_ready().expect("ready");
    assert_eq!(negotiation.state(), NegotiationState::Ready);
}

#[test]
fn admits_only_authenticated_v3_node_and_probe() {
    // Exact predicates: `message-handler.ts#L912-L952`.
    let mut node = drive_to_authentication(3, 3, "node", Some("node"));
    assert_eq!(
        node.check_protocol().expect("node v3"),
        CompatibilityMode::LegacyNode
    );
    node.apply_authentication(AuthenticationDecision::Accepted {
        role: Role::Node,
        scopes: vec![],
        device_proof: DeviceProofDecision::Verified,
    })
    .expect("authenticated node");
    node.prepare_hello(hello(Role::Node, &[]))
        .expect("legacy hello still v4");
    node.mark_hello_sent().expect("node hello sent");
    node.mark_ready().expect("node ready");
    assert_eq!(node.state(), NegotiationState::Ready);

    let mut probe = drive_to_authentication(3, 3, "probe", None);
    assert_eq!(
        probe.check_protocol().expect("probe v3"),
        CompatibilityMode::LegacyProbe
    );
    probe
        .apply_authentication(AuthenticationDecision::Accepted {
            role: Role::Operator,
            scopes: vec![OperatorScope::Read],
            device_proof: DeviceProofDecision::NotRequired,
        })
        .expect("authenticated probe");
    probe
        .prepare_hello(hello(Role::Operator, &[OperatorScope::Read]))
        .expect("legacy probe hello remains v4");
    probe.mark_hello_sent().expect("probe hello sent");
    probe.mark_ready().expect("probe ready");
    assert_eq!(probe.state(), NegotiationState::Ready);

    let mut rejected = drive_to_authentication(3, 3, "cli", Some("operator"));
    assert!(matches!(
        rejected.check_protocol(),
        Err(NegotiationError::Rejected(rejection))
            if rejection.code() == ConnectErrorDetailCode::ProtocolMismatch
    ));

    let mut v2 = drive_to_authentication(2, 2, "node", Some("node"));
    assert!(matches!(
        v2.check_protocol(),
        Err(NegotiationError::Rejected(rejection))
            if rejection.code() == ConnectErrorDetailCode::ProtocolMismatch
    ));
}

#[test]
fn rejects_cross_role_probe_and_inverted_ranges() {
    // Review regressions around the exact N-1 predicates at
    // `message-handler.ts#L912-L952`.
    for mut negotiation in [
        drive_to_authentication(3, 3, "probe", Some("node")),
        drive_to_authentication(4, 3, "probe", None),
    ] {
        assert!(matches!(
            negotiation.check_protocol(),
            Err(NegotiationError::Rejected(rejection))
                if rejection.code() == ConnectErrorDetailCode::ProtocolMismatch
        ));
    }

    let mut explicit_operator = drive_to_authentication(3, 3, "probe", Some("operator"));
    assert_eq!(
        explicit_operator
            .check_protocol()
            .expect("explicit operator probe"),
        CompatibilityMode::LegacyProbe
    );
    explicit_operator
        .apply_authentication(AuthenticationDecision::Accepted {
            role: Role::Operator,
            scopes: vec![],
            device_proof: DeviceProofDecision::NotRequired,
        })
        .expect("operator probe authenticated");
    explicit_operator
        .prepare_hello(hello(Role::Operator, &[]))
        .expect("probe hello");
    explicit_operator.mark_hello_sent().expect("hello sent");
    explicit_operator.mark_ready().expect("ready");
    assert_eq!(explicit_operator.state(), NegotiationState::Ready);
}

#[test]
fn rejects_every_worker_identity_signal_before_negotiation() {
    // Closed worker identity: `packages/gateway-protocol/src/client-info.ts#L15-L52`
    // and `docs/gateway/protocol.md` at PINNED_SHA.
    for json in [
        connect_identity_json(3, 3, "cli", "cli", Some("worker")),
        connect_identity_json(3, 3, "openclaw-worker", "cli", Some("operator")),
        connect_identity_json(3, 3, "cli", "worker", Some("operator")),
        connect_identity_json(3, 3, "openclaw-worker", "worker", None),
    ] {
        let mut negotiation = Negotiation::challenge_sent(challenge());
        negotiation
            .receive_first(
                decode(&json).expect("schema-valid worker signal"),
                &preauth(),
            )
            .expect("receive worker connect");
        assert!(matches!(
            negotiation.check_protocol(),
            Err(NegotiationError::Rejected(rejection))
                if rejection.code() == ConnectErrorDetailCode::AuthUnauthorized
        ));
        assert_eq!(negotiation.state(), NegotiationState::Rejected);
    }

    let mut case_variant = drive_to_authentication(4, 4, "cli", Some("Worker"));
    assert!(matches!(
        case_variant.check_protocol(),
        Err(NegotiationError::Rejected(rejection))
            if rejection.code() == ConnectErrorDetailCode::AuthUnauthorized
    ));
    for json in [
        connect_identity_json(4, 4, "Openclaw-worker", "cli", None),
        connect_identity_json(4, 4, "cli", "Worker", None),
    ] {
        let Frame::Request(request) = decode(&json).expect("valid outer envelope") else {
            panic!("expected request");
        };
        assert!(preauth().decode_connect(&request).is_err());
    }
}

#[test]
fn n_minus_one_never_bypasses_authentication() {
    // Authentication remains mandatory after the v3 predicate:
    // `message-handler.ts#L912-L952`.
    let mut negotiation = drive_to_authentication(3, 3, "probe", None);
    negotiation.check_protocol().expect("eligible probe");
    let rejection = claw_protocol::gateway::HandshakeRejection::new(
        ConnectErrorDetailCode::AuthTokenMismatch,
        "bad token",
    );
    assert!(matches!(
        negotiation.apply_authentication(AuthenticationDecision::Rejected(rejection)),
        Err(NegotiationError::Rejected(rejection))
            if rejection.code() == ConnectErrorDetailCode::AuthTokenMismatch
    ));
    assert_eq!(negotiation.state(), NegotiationState::Rejected);
}

#[test]
fn rejects_bad_first_frames_device_decisions_and_illegal_transitions() {
    // First-frame ordering: `message-handler.ts#L822-L894`.
    let mut negotiation = Negotiation::challenge_sent(challenge());
    assert!(matches!(
        negotiation.check_protocol(),
        Err(NegotiationError::IllegalTransition { .. })
    ));
    let event =
        decode(r#"{"type":"event","event":"tick","payload":{"ts":1}}"#).expect("valid event");
    assert!(matches!(
        negotiation.receive_first(event, &preauth()),
        Err(NegotiationError::FirstFrameMustBeConnect)
    ));

    let device_connect = r#"{"type":"req","id":"connect-1","method":"connect","params":{"minProtocol":4,"maxProtocol":4,"client":{"id":"cli","version":"1","platform":"test","mode":"cli"},"role":"operator","device":{"id":"id","publicKey":"key","signature":"sig","signedAt":1,"nonce":"nonce"}}}"#;
    let mut negotiation = Negotiation::challenge_sent(challenge());
    negotiation
        .receive_first(decode(device_connect).expect("connect"), &preauth())
        .expect("receive");
    negotiation.check_protocol().expect("v4");
    assert!(matches!(
        negotiation.apply_authentication(AuthenticationDecision::Accepted {
            role: Role::Operator,
            scopes: vec![],
            device_proof: DeviceProofDecision::NotRequired,
        }),
        Err(NegotiationError::Rejected(rejection))
            if rejection.code() == ConnectErrorDetailCode::DeviceAuthInvalid
    ));

    let frame = decode(&connect_json(4, 4, "cli", Some("operator"))).expect("connect");
    let mut negotiation = Negotiation::challenge_sent(challenge());
    assert!(matches!(
        negotiation.receive_first(frame, &Codec::authenticated()),
        Err(NegotiationError::PreAuthenticationCodecRequired)
    ));

    let large_params = format!(
        r#"{{"minProtocol":4,"maxProtocol":4,"client":{{"id":"cli","version":"1","platform":"test","mode":"cli"}},"pathEnv":"{}"}}"#,
        "x".repeat(PREAUTH_MAX_FRAME_BYTES - 80)
    );
    let frame = Frame::Request(RequestFrame::new(
        request_id("connect-1"),
        GatewayMethodName::Core(resolve_core_method("connect").expect("connect method")),
        OpaqueField::Value(serde_json::from_str(&large_params).expect("large params")),
    ));
    let mut negotiation = Negotiation::challenge_sent(challenge());
    assert!(matches!(
        negotiation.receive_first(frame, &preauth()),
        Err(NegotiationError::Codec(CodecError::FrameTooLarge {
            phase: TransportPhase::PreAuthentication,
            ..
        }))
    ));
}

#[test]
fn node_authentication_requires_verified_device_identity() {
    // Device-less shared-auth bypass excludes nodes:
    // `src/gateway/server/ws-connection/message-handler.ts#L1162-L1234`.
    let with_device = connect_json(4, 4, "node", Some("node"));
    let without_device = with_device.replace(
        r#","device":{"id":"node-1","publicKey":"cHVi","signature":"c2ln","signedAt":1737264000000,"nonce":"nonce-1"}"#,
        "",
    );
    let mut negotiation = Negotiation::challenge_sent(challenge());
    negotiation
        .receive_first(decode(&without_device).expect("node connect"), &preauth())
        .expect("receive node connect");
    negotiation.check_protocol().expect("current protocol");
    assert!(matches!(
        negotiation.apply_authentication(AuthenticationDecision::Accepted {
            role: Role::Node,
            scopes: vec![],
            device_proof: DeviceProofDecision::NotRequired,
        }),
        Err(NegotiationError::Rejected(rejection))
            if rejection.code() == ConnectErrorDetailCode::DeviceIdentityRequired
    ));
}

#[test]
fn models_connect_error_codes_and_pairing_reasons() {
    // `packages/gateway-protocol/src/connect-error-details.ts#L27-L102`.
    assert_eq!(
        serde_json::to_string(&ConnectErrorDetailCode::DeviceAuthNonceMismatch)
            .expect("serialize code"),
        r#""DEVICE_AUTH_NONCE_MISMATCH""#
    );
    assert_eq!(
        serde_json::from_str::<PairingRequiredReason>(r#""metadata-upgrade""#)
            .expect("pairing reason"),
        PairingRequiredReason::MetadataUpgrade
    );
    assert_eq!(ConnectErrorDetailCode::ALL.len(), 29);
    assert_eq!(
        ConnectErrorDetailCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        29
    );
    assert_eq!(PairingRequiredReason::ALL.len(), 4);
    assert_eq!(
        ConnectErrorDetailCode::from_identity("AUTH_TOKEN_MISMATCH"),
        Some(ConnectErrorDetailCode::AuthTokenMismatch)
    );
    assert_eq!(
        ConnectErrorDetailCode::from_identity("auth_token_mismatch"),
        None
    );
    // `packages/gateway-protocol/src/schema/error-codes.ts#L4-L20`.
    assert_eq!(CoreErrorCode::ALL.len(), 6);
    let unavailable = ErrorCode::from_core(CoreErrorCode::Unavailable);
    assert_eq!(unavailable.as_str(), "UNAVAILABLE");
    assert_eq!(unavailable.core(), Some(CoreErrorCode::Unavailable));
    assert_eq!(CoreErrorCode::from_identity("unavailable"), None);
}

#[test]
fn decodes_proven_tick_and_shutdown_control_payloads() {
    // `packages/gateway-protocol/src/schema/frames.ts#L14-L32`.
    let Frame::Event(tick) =
        decode(r#"{"type":"event","event":"tick","payload":{"ts":1737264000000}}"#).expect("tick")
    else {
        panic!("expected event");
    };
    assert_eq!(
        preauth().decode_tick(&tick).expect("tick payload").ts.get(),
        1_737_264_000_000
    );

    let Frame::Event(shutdown) = decode(
        r#"{"type":"event","event":"shutdown","payload":{"reason":"update","restartExpectedMs":500}}"#,
    )
    .expect("shutdown") else {
        panic!("expected event");
    };
    let shutdown = preauth()
        .decode_shutdown(&shutdown)
        .expect("shutdown payload");
    assert_eq!(shutdown.reason.as_str(), "update");
    assert_eq!(shutdown.restart_expected_ms.expect("restart").get(), 500);
}

#[test]
fn authorizes_role_first_and_scopes_fail_closed() {
    // Runtime ordering: `src/gateway/server-methods.ts#L295-L331`.
    assert!(
        authorize_named(
            Role::Operator,
            "health",
            PluginLookup::Deny,
            &[OperatorScope::Write],
            None
        )
        .is_ok()
    );
    assert!(authorize_named(Role::Node, "health", PluginLookup::Deny, &[], None).is_ok());
    assert!(authorize_named(Role::Node, "node.event", PluginLookup::Deny, &[], None).is_ok());
    assert!(matches!(
        authorize_named(
            Role::Worker,
            "health",
            PluginLookup::Deny,
            &[OperatorScope::Admin],
            None
        ),
        Err(AuthorizationError::WorkerNotAdmitted)
    ));
    assert!(matches!(
        authorize_named(Role::Operator, "status", PluginLookup::Deny, &[], None),
        Err(AuthorizationError::MissingScope {
            required: OperatorScope::Read,
            ..
        })
    ));
    assert!(matches!(
        authorize_named(
            Role::Operator,
            "unknown.method",
            PluginLookup::Deny,
            &[OperatorScope::Admin],
            None
        ),
        Err(AuthorizationError::Registry(RegistryError::UnknownMethod(
            _
        )))
    ));
}

#[test]
fn authorizes_every_closed_operator_scope() {
    // Closed scopes: `src/gateway/operator-scopes.ts#L3-L27`; static method
    // assignments: `src/gateway/methods/core-descriptors.ts#L21-L346`.
    for (method, scope) in [
        ("config.set", OperatorScope::Admin),
        ("status", OperatorScope::Read),
        ("send", OperatorScope::Write),
        ("approval.get", OperatorScope::Approvals),
        ("node.pair.list", OperatorScope::Pairing),
    ] {
        assert!(
            authorize_named(Role::Operator, method, PluginLookup::Deny, &[scope], None).is_ok(),
            "{method} must accept {}",
            scope.as_str()
        );
    }

    assert!(
        authorize_named(
            Role::Operator,
            "plugins.sessionAction",
            PluginLookup::Deny,
            &[OperatorScope::TalkSecrets],
            Some(&[OperatorScope::TalkSecrets]),
        )
        .is_ok()
    );
}

#[test]
fn requires_explicit_dynamic_scope_and_keeps_plugins_distinct() {
    // Dynamic registration: `src/gateway/methods/registry.ts#L22-L82`.
    let policy = ValidationPolicy::for_phase(TransportPhase::Authenticated);
    let mut plugins = DynamicPluginRegistry::new();
    plugins
        .register(" plugin.echo ", Some(OperatorScope::Read), &policy)
        .expect("register");
    assert!(matches!(
        plugins.register("plugin.echo", Some(OperatorScope::Read), &policy),
        Err(RegistryError::DuplicatePluginMethod(_))
    ));
    assert!(matches!(
        plugins.register("health", Some(OperatorScope::Read), &policy),
        Err(RegistryError::CoreMethodShadow(_))
    ));

    let method =
        resolve_gateway_method("plugin.echo", PluginLookup::Allow(&plugins)).expect("plugin");
    assert!(matches!(method, GatewayMethod::DynamicPlugin(_)));
    assert!(
        authorize_named(
            Role::Operator,
            "plugin.echo",
            PluginLookup::Allow(&plugins),
            &[OperatorScope::Read],
            None
        )
        .is_ok()
    );

    assert!(matches!(
        authorize_named(
            Role::Operator,
            "plugins.sessionAction",
            PluginLookup::Deny,
            &[OperatorScope::Write],
            None
        ),
        Err(AuthorizationError::UnresolvedDynamicScope { .. })
    ));
    assert!(matches!(
        authorize_named(
            Role::Operator,
            "plugins.sessionAction",
            PluginLookup::Deny,
            &[OperatorScope::Write],
            Some(&[])
        ),
        Err(AuthorizationError::EmptyDynamicScope { .. })
    ));
    assert!(
        authorize_named(
            Role::Operator,
            "plugins.sessionAction",
            PluginLookup::Deny,
            &[OperatorScope::Write],
            Some(&[OperatorScope::Read, OperatorScope::Write])
        )
        .is_ok()
    );
    assert!(matches!(
        authorize_named(
            Role::Operator,
            "plugins.sessionAction",
            PluginLookup::Deny,
            &[OperatorScope::Write],
            Some(&[OperatorScope::Write, OperatorScope::Approvals])
        ),
        Err(AuthorizationError::MissingScope {
            required: OperatorScope::Approvals,
            ..
        })
    ));

    let codec = preauth()
        .allow_dynamic_plugins(&plugins)
        .expect("explicit plugin opt-in");
    let Frame::Request(request) = codec
        .decode(br#"{"type":"req","id":"1","method":"plugin.echo"}"#)
        .expect("registered plugin request")
    else {
        panic!("expected request");
    };
    assert!(matches!(
        request.method(),
        claw_protocol::gateway::GatewayMethodName::DynamicPlugin(name)
            if name.as_str() == "plugin.echo"
    ));
    assert!(matches!(
        preauth().decode(br#"{"type":"req","id":"1","method":"plugin.echo"}"#),
        Err(CodecError::UnknownMethod(_))
    ));
}

#[test]
fn enforces_plugin_reserved_namespaces_and_scope_metadata() {
    // `src/shared/gateway-method-policy.ts#L2-L42` and
    // `src/gateway/methods/registry.ts#L22-L137`.
    let policy = ValidationPolicy::for_phase(TransportPhase::Authenticated);
    let mut plugins = DynamicPluginRegistry::new();
    for name in [
        "config.pluginOnly",
        "exec.approvals.pluginOnly",
        "wizard.pluginOnly",
        "update.pluginOnly",
    ] {
        let method = plugins
            .register(name, Some(OperatorScope::Read), &policy)
            .expect("reserved plugin registration");
        assert_eq!(method.scope(), OperatorScope::Admin);
    }
    for name in [
        "config.pluginOnly",
        "exec.approvals.pluginOnly",
        "wizard.pluginOnly",
        "update.pluginOnly",
    ] {
        assert!(matches!(
            authorize_named(
                Role::Operator,
                name,
                PluginLookup::Allow(&plugins),
                &[OperatorScope::Read],
                None
            ),
            Err(AuthorizationError::MissingScope {
                required: OperatorScope::Admin,
                ..
            })
        ));
        assert!(
            authorize_named(
                Role::Operator,
                name,
                PluginLookup::Allow(&plugins),
                &[OperatorScope::Admin],
                None
            )
            .is_ok()
        );
    }
    let legacy = plugins
        .register("plugin.legacy", None, &policy)
        .expect("legacy metadata defaults");
    assert_eq!(legacy.scope(), OperatorScope::Admin);

    for scope in ["", "node", "dynamic", "Operator.Read"] {
        assert!(matches!(
            plugins.register_declared(format!("plugin.invalid.{scope}"), Some(scope), &policy),
            Err(RegistryError::InvalidPluginScope(actual)) if actual == scope
        ));
    }
    assert!(
        plugins
            .register_declared("plugin.declared", Some("operator.approvals"), &policy)
            .is_ok()
    );
}

#[derive(Deserialize)]
struct Inventory {
    baseline_sha: String,
    counts: InventoryCounts,
    items: Vec<InventoryItem>,
}

#[derive(Deserialize)]
struct InventoryCounts {
    total: usize,
    methods: usize,
    advertised_methods: usize,
    events: usize,
    roles: usize,
    scopes: usize,
}

#[derive(Deserialize)]
struct InventoryItem {
    id: String,
    kind: String,
    scope: Option<String>,
    advertised: Option<bool>,
}

fn scope_identity(scope: MethodScope) -> &'static str {
    match scope {
        MethodScope::Operator(scope) => scope.as_str(),
        MethodScope::Node => "node",
        MethodScope::Dynamic => "dynamic",
    }
}

#[test]
fn generated_registry_equals_canonical_inventory_bidirectionally() {
    // Canonical inventory sources:
    // `src/gateway/methods/core-descriptors.ts#L21-L426`,
    // `src/gateway/server-methods-list.ts#L12-L71`.
    let source = include_str!("../../../compat/upstream/inventories/gateway-protocol.json");
    let inventory: Inventory =
        serde_json::from_str(source.trim_start_matches('\u{feff}')).expect("canonical inventory");
    assert_eq!(inventory.baseline_sha, PINNED_SHA);
    assert_eq!(
        (
            inventory.counts.total,
            inventory.counts.methods,
            inventory.counts.advertised_methods,
            inventory.counts.events,
            inventory.counts.roles,
            inventory.counts.scopes,
        ),
        (320, 278, 258, 33, 3, 6)
    );

    let inventory_methods = inventory
        .items
        .iter()
        .filter(|item| item.kind == "method")
        .map(|item| {
            (
                item.id.as_str(),
                item.scope.as_deref().expect("method scope"),
                item.advertised.expect("advertised"),
            )
        })
        .collect::<Vec<_>>();
    let generated_methods = core_methods()
        .iter()
        .copied()
        .map(|method| {
            (
                method.name(),
                scope_identity(method.scope()),
                method.advertised(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(generated_methods, inventory_methods);
    assert_eq!(
        generated_methods
            .iter()
            .filter(|(_, _, advertised)| *advertised)
            .count(),
        258
    );

    let inventory_events = inventory
        .items
        .iter()
        .filter(|item| item.kind == "event")
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    let generated_events = core_events()
        .iter()
        .copied()
        .map(|event| event.name())
        .collect::<BTreeSet<_>>();
    assert_eq!(generated_events, inventory_events);

    let inventory_roles = inventory
        .items
        .iter()
        .filter(|item| item.kind == "role")
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    let generated_roles = roles()
        .iter()
        .copied()
        .map(Role::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(generated_roles, inventory_roles);

    let inventory_scopes = inventory
        .items
        .iter()
        .filter(|item| item.kind == "scope")
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    let generated_scopes = operator_scopes()
        .iter()
        .copied()
        .map(OperatorScope::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(generated_scopes, inventory_scopes);

    for method in core_methods() {
        assert_eq!(
            resolve_core_method(method.name()).copied(),
            Some(*method),
            "reverse lookup must preserve every descriptor"
        );
    }
}

#[test]
fn zero_limit_policy_is_rejected() {
    // Unproven generic limits are caller policy; the default recursion guard is
    // documented by `serde_json@1.0.150/src/de.rs#L30-L68`.
    let mut policy = ValidationPolicy::for_phase(TransportPhase::PreAuthentication);
    policy.max_nesting_depth = 0;
    assert!(matches!(
        Codec::new(TransportPhase::PreAuthentication, policy),
        Err(CodecError::InvalidPolicy(_))
    ));
}

#[test]
fn targeted_events_do_not_advance_sequence() {
    // Targeted events omit sequence: `src/gateway/server-broadcast.ts#L106-L202`.
    let mut tracker = EventSequenceTracker::new();
    tracker.observe(None).expect("no sequence");
    tracker
        .observe(Some(EventSequence::new(1).expect("positive")))
        .expect("still expects one");
    assert_eq!(tracker.last().expect("one").get(), 1);
    assert_eq!(NonNegativeInteger::new(0).get(), 0);
}

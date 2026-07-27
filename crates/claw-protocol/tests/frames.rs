//! Acceptance evidence for `gateway.protocol.frames-handshake`.
//!
//! Wire citations: `packages/gateway-protocol/src/schema/frames.ts#L35-L212`
//! and `docs/gateway/protocol.md` at
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`.
//!
//! Every frame the handshake and the steady-state connection exchange is
//! pinned here as a golden document: the exact bytes decode to the exact typed
//! value, the typed value re-encodes to the exact same bytes, and the
//! neighbouring malformed documents are refused with a typed error. The eight
//! covered shapes are `connect.challenge`, `connect`, `hello-ok`, `req`, `res`,
//! `event`, the transport limits, and the error envelope.

use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, ClientId, ClientMode, Codec, CodecError, CoreErrorCode,
    DEFAULT_JSON_NESTING_DEPTH, ErrorCode, EventName, EventSequence, EventSequenceError,
    EventSequenceTracker, Frame, FrameKind, GatewayMethodName, NonNegativeInteger, OpaqueField,
    PREAUTH_MAX_FRAME_BYTES, RequestId, TransportPhase, ValidationPolicy, resolve_core_method,
};

const fn preauth() -> Codec {
    Codec::preauthentication()
}

fn request_id(value: &str) -> RequestId {
    RequestId::new(value, 1024).expect("a short request id is within policy")
}

/// Decodes a golden document and proves the typed value re-encodes to exactly
/// the same bytes, so neither direction can drift on its own.
fn golden(codec: &Codec, document: &str) -> Frame {
    let frame = codec
        .decode(document.as_bytes())
        .unwrap_or_else(|error| panic!("golden frame must decode: {error}"));
    let encoded = codec
        .encode(&frame)
        .unwrap_or_else(|error| panic!("golden frame must re-encode: {error}"));
    assert_eq!(
        String::from_utf8(encoded).expect("encoded frames are UTF-8"),
        document,
        "golden frame must re-encode byte for byte"
    );
    frame
}

fn refuse(document: &str) -> CodecError {
    preauth()
        .decode(document.as_bytes())
        .expect_err("the document must be refused")
}

fn event_frame(document: &str) -> claw_protocol::gateway::EventFrame {
    let Frame::Event(event) = golden(&preauth(), document) else {
        panic!("expected an event frame");
    };
    event
}

#[test]
fn golden_connect_challenge_event_round_trips_and_refuses_malformed_payloads() {
    const GOLDEN: &str = r#"{"type":"event","event":"connect.challenge","payload":{"nonce":"nonce-1","ts":1737264000000}}"#;

    let event = event_frame(GOLDEN);
    assert_eq!(event.event().as_str(), "connect.challenge");
    assert!(matches!(event.event(), EventName::Core(_)));
    assert!(event.sequence().is_none(), "the challenge is not sequenced");
    assert!(event.state_version().is_none());

    let challenge = preauth()
        .decode_challenge(&event)
        .expect("the golden challenge payload decodes");
    assert_eq!(challenge.nonce.as_str(), "nonce-1");
    assert_eq!(challenge.ts.get(), 1_737_264_000_000);

    // An empty nonce, a missing timestamp, a negative timestamp and an extra
    // field are each refused.
    for document in [
        r#"{"type":"event","event":"connect.challenge","payload":{"nonce":"","ts":1737264000000}}"#,
        r#"{"type":"event","event":"connect.challenge","payload":{"nonce":"nonce-1"}}"#,
        r#"{"type":"event","event":"connect.challenge","payload":{"nonce":"nonce-1","ts":-1}}"#,
        r#"{"type":"event","event":"connect.challenge","payload":{"nonce":"nonce-1","ts":1,"extra":true}}"#,
    ] {
        let frame = preauth()
            .decode(document.as_bytes())
            .expect("the envelope itself stays opaque and decodes");
        let Frame::Event(event) = frame else {
            panic!("expected an event frame");
        };
        let error = preauth()
            .decode_challenge(&event)
            .expect_err("the challenge payload must be refused");
        assert!(
            matches!(error, CodecError::TypedDecode { .. }),
            "expected a typed decode failure for {document}, got {error:?}"
        );
    }

    // The challenge decoder is bound to its event name.
    let tick = event_frame(r#"{"type":"event","event":"tick","payload":{"ts":1737264000000}}"#);
    let error = preauth()
        .decode_challenge(&tick)
        .expect_err("a tick is not a challenge");
    assert!(matches!(error, CodecError::ExpectedChallengeEvent(name) if name == "tick"));

    // A challenge with no payload at all cannot be mistaken for a valid one.
    let empty = event_frame(r#"{"type":"event","event":"connect.challenge"}"#);
    assert!(matches!(
        preauth()
            .decode_challenge(&empty)
            .expect_err("an omitted payload is refused"),
        CodecError::MissingOpaqueField("$.payload")
    ));
    let null = event_frame(r#"{"type":"event","event":"connect.challenge","payload":null}"#);
    assert!(matches!(
        preauth()
            .decode_challenge(&null)
            .expect_err("an explicit null payload is refused"),
        CodecError::NullOpaqueField("$.payload")
    ));
}

#[test]
fn golden_connect_request_round_trips_and_refuses_malformed_params() {
    const GOLDEN: &str = r#"{"type":"req","id":"connect-1","method":"connect","params":{"minProtocol":4,"maxProtocol":4,"client":{"id":"node-host","version":"2026.7.2","platform":"test","mode":"node"},"role":"node","device":{"id":"node-1","publicKey":"cHVi","signature":"c2ln","signedAt":1737264000000,"nonce":"nonce-1"},"auth":{"token":"secret"}}}"#;

    let Frame::Request(request) = golden(&preauth(), GOLDEN) else {
        panic!("expected a request frame");
    };
    assert_eq!(request.id().as_str(), "connect-1");
    assert_eq!(request.method().as_str(), "connect");

    let params = preauth()
        .decode_connect(&request)
        .expect("the golden connect params decode");
    assert_eq!(params.min_protocol.get(), 4);
    assert_eq!(params.max_protocol.get(), 4);
    assert_eq!(params.client.id, ClientId::NodeHost);
    assert_eq!(params.client.mode, ClientMode::Node);
    assert_eq!(
        params
            .role
            .as_ref()
            .map(claw_protocol::gateway::Name::as_str),
        Some("node")
    );
    let device = params
        .device
        .as_ref()
        .expect("the device proof is retained");
    assert_eq!(device.id.as_str(), "node-1");
    assert_eq!(device.nonce.as_str(), "nonce-1");
    assert_eq!(device.signed_at.get(), 1_737_264_000_000);
    assert_eq!(
        params.auth.as_ref().and_then(|auth| auth.token.as_deref()),
        Some("secret")
    );

    // The connect decoder is bound to its method name.
    let Frame::Request(health) = golden(&preauth(), r#"{"type":"req","id":"1","method":"health"}"#)
    else {
        panic!("expected a request frame");
    };
    let error = preauth()
        .decode_connect(&health)
        .expect_err("health is not connect");
    assert!(matches!(error, CodecError::ExpectedConnectMethod(name) if name == "health"));

    // A zero protocol version, an unknown product id, a missing bound and an
    // extra parameter are each refused.
    for params in [
        r#"{"minProtocol":0,"maxProtocol":4,"client":{"id":"cli","version":"1","platform":"t","mode":"cli"}}"#,
        r#"{"minProtocol":4,"maxProtocol":4,"client":{"id":"not-a-product","version":"1","platform":"t","mode":"cli"}}"#,
        r#"{"minProtocol":4,"client":{"id":"cli","version":"1","platform":"t","mode":"cli"}}"#,
        r#"{"minProtocol":4,"maxProtocol":4,"client":{"id":"cli","version":"1","platform":"t","mode":"cli"},"unexpected":1}"#,
    ] {
        let document =
            format!(r#"{{"type":"req","id":"connect-1","method":"connect","params":{params}}}"#);
        let frame = preauth()
            .decode(document.as_bytes())
            .expect("the envelope itself stays opaque and decodes");
        let Frame::Request(request) = frame else {
            panic!("expected a request frame");
        };
        let error = preauth()
            .decode_connect(&request)
            .expect_err("the connect params must be refused");
        assert!(
            matches!(error, CodecError::TypedDecode { .. }),
            "expected a typed decode failure for {params}, got {error:?}"
        );
    }
}

#[test]
fn golden_hello_ok_response_round_trips_and_refuses_malformed_payloads() {
    const GOLDEN: &str = r#"{"type":"res","id":"connect-1","ok":true,"payload":{"type":"hello-ok","protocol":4,"server":{"version":"2026.7.2","connId":"conn-1"},"features":{"methods":["health"],"events":["tick"],"capabilities":["chat-send-routing-contract"]},"snapshot":{"presence":[],"health":null,"stateVersion":{"presence":0,"health":0},"uptimeMs":1,"authMode":"token"},"auth":{"role":"operator","scopes":["admin"]},"policy":{"maxPayload":26214400,"maxBufferedBytes":52428800,"tickIntervalMs":15000}}}"#;

    let Frame::Response(response) = golden(&preauth(), GOLDEN) else {
        panic!("expected a response frame");
    };
    assert!(response.ok());
    assert!(response.error().is_none());

    let hello = preauth()
        .decode_hello(&response)
        .expect("the golden hello payload decodes");
    assert_eq!(hello.protocol.get(), 4);
    assert_eq!(hello.server.conn_id.as_str(), "conn-1");
    assert_eq!(hello.auth.role.as_str(), "operator");
    assert_eq!(hello.auth.scopes.len(), 1);
    assert_eq!(hello.policy.max_payload.get(), 26_214_400);
    assert_eq!(hello.policy.tick_interval_ms.get(), 15_000);
    assert_eq!(hello.snapshot.uptime_ms.get(), 1);

    // The correlation identifier must be echoed exactly.
    assert!(matches!(
        preauth()
            .decode_response(GOLDEN.as_bytes(), &request_id("connect-2"))
            .expect_err("a mismatched id is refused"),
        CodecError::ResponseIdMismatch { .. }
    ));
    preauth()
        .decode_response(GOLDEN.as_bytes(), &request_id("connect-1"))
        .expect("the matching id is accepted");

    // A hello may not be read out of an unsuccessful response.
    let Frame::Response(failed) = golden(
        &preauth(),
        r#"{"type":"res","id":"connect-1","ok":false,"error":{"code":"NOT_LINKED","message":"client is not linked"}}"#,
    ) else {
        panic!("expected a response frame");
    };
    assert!(matches!(
        preauth()
            .decode_hello(&failed)
            .expect_err("an unsuccessful response carries no hello"),
        CodecError::UnsuccessfulResponse { .. }
    ));

    // A wrong discriminator, a missing protocol and an extra field are refused.
    for payload in [
        r#"{"type":"hello","protocol":4,"server":{"version":"1","connId":"c"},"features":{"methods":[],"events":[]},"snapshot":{"presence":[],"health":null,"stateVersion":{"presence":0,"health":0},"uptimeMs":1},"auth":{"role":"operator","scopes":[]},"policy":{"maxPayload":1,"maxBufferedBytes":1,"tickIntervalMs":1}}"#,
        r#"{"type":"hello-ok","server":{"version":"1","connId":"c"},"features":{"methods":[],"events":[]},"snapshot":{"presence":[],"health":null,"stateVersion":{"presence":0,"health":0},"uptimeMs":1},"auth":{"role":"operator","scopes":[]},"policy":{"maxPayload":1,"maxBufferedBytes":1,"tickIntervalMs":1}}"#,
        r#"{"type":"hello-ok","protocol":4,"server":{"version":"1","connId":"c"},"features":{"methods":[],"events":[]},"snapshot":{"presence":[],"health":null,"stateVersion":{"presence":0,"health":0},"uptimeMs":1},"auth":{"role":"operator","scopes":[]},"policy":{"maxPayload":1,"maxBufferedBytes":1,"tickIntervalMs":1},"surprise":true}"#,
    ] {
        let document =
            format!(r#"{{"type":"res","id":"connect-1","ok":true,"payload":{payload}}}"#);
        let frame = preauth()
            .decode(document.as_bytes())
            .expect("the envelope itself stays opaque and decodes");
        let Frame::Response(response) = frame else {
            panic!("expected a response frame");
        };
        let error = preauth()
            .decode_hello(&response)
            .expect_err("the hello payload must be refused");
        assert!(
            matches!(error, CodecError::TypedDecode { .. }),
            "expected a typed decode failure, got {error:?}"
        );
    }
}

#[test]
fn golden_req_frames_round_trip_and_refuse_envelope_confusion() {
    let with_params = golden(
        &preauth(),
        r#"{"type":"req","id":"req-1","method":"health","params":{"verbose":true}}"#,
    );
    assert_eq!(with_params.kind(), FrameKind::Req);
    let Frame::Request(request) = with_params else {
        panic!("expected a request frame");
    };
    assert_eq!(request.id().as_str(), "req-1");
    assert!(matches!(request.method(), GatewayMethodName::Core(_)));
    assert_eq!(
        request
            .params()
            .value()
            .expect("a non-null params value is retained")
            .as_json(),
        r#"{"verbose":true}"#
    );

    // Omitted and explicitly null parameters are distinct and both survive.
    let Frame::Request(omitted) = golden(
        &preauth(),
        r#"{"type":"req","id":"req-1","method":"health"}"#,
    ) else {
        panic!("expected a request frame");
    };
    assert!(matches!(omitted.params(), OpaqueField::Omitted));
    let Frame::Request(null) = golden(
        &preauth(),
        r#"{"type":"req","id":"req-1","method":"health","params":null}"#,
    ) else {
        panic!("expected a request frame");
    };
    assert!(matches!(null.params(), OpaqueField::Null));

    // An unregistered method, an empty id, a foreign envelope field, an extra
    // field and an unknown discriminator are each refused.
    assert!(matches!(
        refuse(r#"{"type":"req","id":"req-1","method":"not.a.method"}"#),
        CodecError::UnknownMethod(name) if name == "not.a.method"
    ));
    assert!(matches!(
        refuse(r#"{"type":"req","id":"","method":"health"}"#),
        CodecError::TypedDecode { .. }
    ));
    assert!(matches!(
        refuse(r#"{"type":"req","id":"req-1","method":"health","ok":true}"#),
        CodecError::ContradictoryEnvelopeField { kind, field } if kind == "req" && field == "ok"
    ));
    assert!(matches!(
        refuse(r#"{"type":"req","id":"req-1","method":"health","extra":1}"#),
        CodecError::TypedDecode { .. }
    ));
    assert!(matches!(
        refuse(r#"{"type":"request","id":"req-1","method":"health"}"#),
        CodecError::UnknownFrameKind(kind) if kind == "request"
    ));
    assert!(matches!(
        refuse(r#"{"type":"req","id":"req-1","method":"health","id":"req-2"}"#),
        CodecError::DuplicateKey { .. }
    ));
}

#[test]
fn golden_res_frames_round_trip_for_success_and_failure() {
    let Frame::Response(success) = golden(
        &preauth(),
        r#"{"type":"res","id":"req-1","ok":true,"payload":{"status":"ok"}}"#,
    ) else {
        panic!("expected a response frame");
    };
    assert_eq!(success.id().as_str(), "req-1");
    assert!(success.ok());
    assert!(success.error().is_none());
    assert_eq!(
        success
            .payload()
            .value()
            .expect("a non-null payload is retained")
            .as_json(),
        r#"{"status":"ok"}"#
    );

    let failure = golden(
        &preauth(),
        r#"{"type":"res","id":"req-1","ok":false,"error":{"code":"UNAVAILABLE","message":"backend is restarting"}}"#,
    );
    assert_eq!(failure.kind(), FrameKind::Res);
    let Frame::Response(failure) = failure else {
        panic!("expected a response frame");
    };
    assert!(!failure.ok());
    assert!(matches!(failure.payload(), OpaqueField::Omitted));
    assert_eq!(
        failure
            .error()
            .expect("a failure carries a structured error")
            .code
            .core(),
        Some(CoreErrorCode::Unavailable)
    );

    // A response decoder refuses a frame of another kind outright.
    let error = preauth()
        .decode_response(
            br#"{"type":"event","event":"tick","payload":{"ts":1}}"#,
            &request_id("req-1"),
        )
        .expect_err("an event is not a response");
    assert!(matches!(
        error,
        CodecError::UnexpectedFrame {
            expected: FrameKind::Res,
            received: FrameKind::Event,
        }
    ));

    // A missing discriminator, a foreign envelope field and an explicitly null
    // error are each refused.
    assert!(matches!(
        refuse(r#"{"type":"res","id":"req-1"}"#),
        CodecError::TypedDecode { .. }
    ));
    assert!(matches!(
        refuse(r#"{"type":"res","id":"req-1","ok":true,"method":"health"}"#),
        CodecError::ContradictoryEnvelopeField { kind, field } if kind == "res" && field == "method"
    ));
    assert!(matches!(
        refuse(r#"{"type":"res","id":"req-1","ok":false,"error":null}"#),
        CodecError::TypedDecode { .. }
    ));
}

#[test]
fn golden_event_frames_round_trip_with_sequence_and_state_version() {
    let broadcast = event_frame(
        r#"{"type":"event","event":"tick","payload":{"ts":1737264000000},"seq":7,"stateVersion":{"presence":3,"health":4}}"#,
    );
    assert_eq!(broadcast.event().as_str(), "tick");
    assert_eq!(
        broadcast.sequence().map(EventSequence::get),
        Some(7),
        "a broadcast carries its sequence"
    );
    let state_version = broadcast
        .state_version()
        .expect("the snapshot versions are retained");
    assert_eq!(state_version.presence.get(), 3);
    assert_eq!(state_version.health.get(), 4);
    assert_eq!(
        preauth()
            .decode_tick(&broadcast)
            .expect("the golden tick payload decodes")
            .ts
            .get(),
        1_737_264_000_000
    );

    // A shutdown notice is the other pinned control event.
    let shutdown = event_frame(
        r#"{"type":"event","event":"shutdown","payload":{"reason":"restart","restartExpectedMs":5000}}"#,
    );
    let shutdown = preauth()
        .decode_shutdown(&shutdown)
        .expect("the golden shutdown payload decodes");
    assert_eq!(shutdown.reason.as_str(), "restart");
    assert_eq!(
        shutdown.restart_expected_ms.map(NonNegativeInteger::get),
        Some(5000)
    );

    // Schema-permitted extension events keep their provenance.
    let extension = event_frame(r#"{"type":"event","event":"plugin.custom","payload":[1,2,3]}"#);
    assert!(matches!(extension.event(), EventName::Extension(_)));
    assert_eq!(extension.event().as_str(), "plugin.custom");

    // Sequences start at one, so zero and null are refused, as are foreign
    // envelope fields.
    assert!(matches!(
        refuse(r#"{"type":"event","event":"tick","payload":{"ts":1},"seq":0}"#),
        CodecError::TypedDecode { .. }
    ));
    assert!(matches!(
        refuse(r#"{"type":"event","event":"tick","payload":{"ts":1},"seq":null}"#),
        CodecError::TypedDecode { .. }
    ));
    assert!(matches!(
        refuse(r#"{"type":"event","event":"tick","payload":{"ts":1},"id":"req-1"}"#),
        CodecError::ContradictoryEnvelopeField { kind, field } if kind == "event" && field == "id"
    ));

    // Continuity is decided over the decoded sequences themselves.
    let mut tracker = EventSequenceTracker::new();
    let sequence = |value: u64| EventSequence::new(value).expect("a positive sequence");
    tracker
        .observe(Some(sequence(1)))
        .expect("the first broadcast is one");
    tracker
        .observe(None)
        .expect("a targeted event does not advance the sequence");
    assert_eq!(tracker.last().map(EventSequence::get), Some(1));
    tracker
        .observe(Some(sequence(2)))
        .expect("the next broadcast is two");
    assert_eq!(
        tracker
            .observe(Some(sequence(4)))
            .expect_err("a skipped broadcast is a gap"),
        EventSequenceError::Gap {
            expected: 3,
            received: 4,
        }
    );
}

#[test]
fn golden_frame_limits_are_enforced_per_phase_and_per_policy() {
    assert_eq!(PREAUTH_MAX_FRAME_BYTES, 64 * 1024);
    assert_eq!(AUTHENTICATED_MAX_FRAME_BYTES, 25 * 1024 * 1024);
    assert_eq!(
        TransportPhase::PreAuthentication.max_frame_bytes(),
        PREAUTH_MAX_FRAME_BYTES
    );
    assert_eq!(
        TransportPhase::Authenticated.max_frame_bytes(),
        AUTHENTICATED_MAX_FRAME_BYTES
    );
    assert_eq!(
        ValidationPolicy::for_phase(TransportPhase::Authenticated).max_nesting_depth,
        DEFAULT_JSON_NESTING_DEPTH
    );

    // One document, two phases, two verdicts.
    let padding = "a".repeat(PREAUTH_MAX_FRAME_BYTES);
    let oversized = format!(
        r#"{{"type":"req","id":"req-1","method":"health","params":{{"blob":"{padding}"}}}}"#
    );
    assert!(oversized.len() > PREAUTH_MAX_FRAME_BYTES);
    assert!(oversized.len() < AUTHENTICATED_MAX_FRAME_BYTES);
    let error = preauth()
        .decode(oversized.as_bytes())
        .expect_err("the pre-authentication cap is enforced");
    assert!(
        matches!(
            error,
            CodecError::FrameTooLarge {
                phase: TransportPhase::PreAuthentication,
                limit: PREAUTH_MAX_FRAME_BYTES,
                ..
            }
        ),
        "expected a pre-authentication cap failure, got {error:?}"
    );
    Codec::authenticated()
        .decode(oversized.as_bytes())
        .expect("the same document fits the authenticated cap");

    // The cap also applies outbound, before an oversized frame is materialised.
    let method = GatewayMethodName::Core(
        resolve_core_method("health").expect("health is a frozen core method"),
    );
    let error = preauth()
        .encode_request(&request_id("req-1"), &method, &padding)
        .expect_err("the outbound cap is enforced too");
    assert!(matches!(
        error,
        CodecError::FrameTooLarge {
            phase: TransportPhase::PreAuthentication,
            ..
        }
    ));
    assert_eq!(
        String::from_utf8(
            preauth()
                .encode_request(&request_id("req-1"), &method, "ok")
                .expect("a small request encodes")
        )
        .expect("encoded frames are UTF-8"),
        r#"{"type":"req","id":"req-1","method":"health","params":"ok"}"#
    );

    // Nesting and identifier limits come from explicit caller policy.
    let shallow = Codec::new(
        TransportPhase::PreAuthentication,
        ValidationPolicy {
            max_nesting_depth: 4,
            ..ValidationPolicy::for_phase(TransportPhase::PreAuthentication)
        },
    )
    .expect("a positive policy is accepted");
    assert!(matches!(
        shallow
            .decode(
                br#"{"type":"req","id":"req-1","method":"health","params":{"a":{"b":{"c":{"d":1}}}}}"#
            )
            .expect_err("nesting beyond policy is refused"),
        CodecError::NestingLimit { limit: 4, .. }
    ));
    shallow
        .decode(br#"{"type":"req","id":"req-1","method":"health","params":{"a":{"b":1}}}"#)
        .expect("nesting within policy is accepted");

    let short_ids = Codec::new(
        TransportPhase::PreAuthentication,
        ValidationPolicy {
            max_request_id_bytes: 4,
            ..ValidationPolicy::for_phase(TransportPhase::PreAuthentication)
        },
    )
    .expect("a positive policy is accepted");
    assert!(matches!(
        short_ids
            .decode(br#"{"type":"req","id":"req-12345","method":"health"}"#)
            .expect_err("an over-long identifier is refused"),
        CodecError::PolicyLimit { ref path, actual: 9, limit: 4 } if path == "$.id"
    ));

    // A zero limit is not a policy at all.
    let error = Codec::new(
        TransportPhase::PreAuthentication,
        ValidationPolicy {
            max_collection_items: 0,
            ..ValidationPolicy::for_phase(TransportPhase::PreAuthentication)
        },
    )
    .expect_err("a zero limit is refused");
    assert!(
        matches!(error, CodecError::InvalidPolicy(_)),
        "expected an invalid-policy failure, got {error:?}"
    );
}

#[test]
fn golden_error_envelopes_carry_every_pinned_field() {
    const GOLDEN: &str = r#"{"type":"res","id":"req-1","ok":false,"error":{"code":"NOT_LINKED","message":"client is not linked","details":{"hint":"pair the device first"},"retryable":true,"retryAfterMs":1500}}"#;

    let Frame::Response(response) = golden(&preauth(), GOLDEN) else {
        panic!("expected a response frame");
    };
    let error = response
        .error()
        .expect("the golden failure carries a structured error");
    assert_eq!(error.code.as_str(), "NOT_LINKED");
    assert_eq!(error.code.core(), Some(CoreErrorCode::NotLinked));
    assert_eq!(error.message.as_str(), "client is not linked");
    assert_eq!(
        error
            .details
            .value()
            .expect("opaque details are retained verbatim")
            .as_json(),
        r#"{"hint":"pair the device first"}"#
    );
    assert_eq!(error.retryable, Some(true));
    assert_eq!(
        error.retry_after_ms.map(NonNegativeInteger::get),
        Some(1500)
    );

    // The code is extensible: every pinned built-in classifies, anything else
    // stays an opaque wire code rather than being rejected.
    for code in CoreErrorCode::ALL {
        assert_eq!(
            ErrorCode::from_core(code).core(),
            Some(code),
            "{} must survive a round trip through the wire form",
            code.as_str()
        );
        assert_eq!(CoreErrorCode::from_identity(code.as_str()), Some(code));
    }
    assert_eq!(CoreErrorCode::from_identity("not_linked"), None);
    let Frame::Response(extension) = golden(
        &preauth(),
        r#"{"type":"res","id":"req-1","ok":false,"error":{"code":"plugin.quota_exceeded","message":"quota exceeded"}}"#,
    ) else {
        panic!("expected a response frame");
    };
    assert_eq!(
        extension
            .error()
            .expect("an extension error is still structured")
            .code
            .core(),
        None
    );

    // An empty code, an empty message, an explicitly null flag, a negative
    // delay and an unknown member are each refused.
    for error in [
        r#"{"code":"","message":"m"}"#,
        r#"{"code":"NOT_LINKED","message":""}"#,
        r#"{"code":"NOT_LINKED","message":"m","retryable":null}"#,
        r#"{"code":"NOT_LINKED","message":"m","retryAfterMs":-1}"#,
        r#"{"code":"NOT_LINKED","message":"m","severity":"fatal"}"#,
        r#"{"message":"m"}"#,
    ] {
        let document = format!(r#"{{"type":"res","id":"req-1","ok":false,"error":{error}}}"#);
        let failure = refuse(&document);
        assert!(
            matches!(failure, CodecError::TypedDecode { .. }),
            "expected a typed decode failure for {error}, got {failure:?}"
        );
    }
}

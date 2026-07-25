//! Executable channel behavior against local fixtures.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::rc::Rc;
use std::thread;

use claw_channel_sdk::{
    Channel, ChannelCredential, ChannelError, CredentialBinding, CredentialKind, CredentialRequest,
    DeliveryAcknowledgement, DeliveryState, InboundMessage, OutboundMessage, UnsupportedOperation,
};
use claw_channels::{
    LoopbackHttpTransport, QaChannel, RedirectPolicy, UnixClock, WebhookChannel, WebhookRequest,
    WebhookResponse, WebhookTransport,
};

#[derive(Clone, Copy, Debug)]
struct FixedClock(u64);

impl UnixClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CapturedRequest {
    request_line: String,
    content_type: String,
    body: Vec<u8>,
}

fn fixture_server(status: u16) -> (String, thread::JoinHandle<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture server");
    let address = listener.local_addr().expect("fixture address");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        let header_end;
        loop {
            let count = stream.read(&mut buffer).expect("read request");
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
            if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                header_end = index + 4;
                break;
            }
        }
        let headers = std::str::from_utf8(&request[..header_end])
            .expect("UTF-8 headers")
            .to_owned();
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .expect("content length")
            .parse::<usize>()
            .expect("numeric content length");
        while request.len() < header_end + content_length {
            let count = stream.read(&mut buffer).expect("read request body");
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
        }
        let response =
            format!("HTTP/1.1 {status} Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream
            .write_all(response.as_bytes())
            .expect("write response");

        CapturedRequest {
            request_line: headers.lines().next().expect("request line").to_owned(),
            content_type: headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Type: "))
                .expect("content type")
                .to_owned(),
            body: request[header_end..header_end + content_length].to_vec(),
        }
    });
    (
        format!("http://{address}/hooks/incoming?token=fixture-secret"),
        handle,
    )
}

fn outbound() -> OutboundMessage {
    OutboundMessage {
        idempotency_key: "delivery-1".to_owned(),
        account_id: "primary".to_owned(),
        conversation_id: "room-1".to_owned(),
        text: Some("hello fixture".to_owned()),
        attachments: Vec::new(),
        reply_to: None,
    }
}

fn webhook_credential(channel_id: &str, endpoint: String) -> ChannelCredential {
    ChannelCredential::bind(
        endpoint,
        CredentialRequest {
            channel_id: channel_id.to_owned(),
            account_id: "primary".to_owned(),
            kind: CredentialKind::WebhookUrl,
            binding: CredentialBinding::EmbeddedEndpoint,
        },
    )
    .expect("valid embedded-endpoint binding")
}

#[derive(Clone)]
struct InspectingTransport {
    rendered: Rc<RefCell<Vec<String>>>,
}

impl WebhookTransport for InspectingTransport {
    fn post_json(&self, request: &WebhookRequest<'_>) -> Result<WebhookResponse, ChannelError> {
        assert_eq!(request.redirect_policy(), RedirectPolicy::Reject);
        self.rendered.borrow_mut().push(format!("{request:?}"));
        Ok(WebhookResponse { status: 204 })
    }
}

#[test]
fn discord_webhook_posts_exact_payload_to_local_fixture_server() {
    let (endpoint, server) = fixture_server(204);
    let credential = webhook_credential("discord", endpoint);
    let mut channel = WebhookChannel::new(
        "discord",
        "primary",
        LoopbackHttpTransport,
        FixedClock(1_234),
    )
    .expect("valid adapter");

    assert_eq!(
        channel.send_outbound(&outbound(), Some(&credential)),
        Ok(DeliveryAcknowledgement {
            idempotency_key: "delivery-1".to_owned(),
            remote_message_id: None,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: 1_234,
        })
    );
    assert_eq!(
        server.join().expect("fixture server"),
        CapturedRequest {
            request_line: "POST /hooks/incoming?token=fixture-secret HTTP/1.1".to_owned(),
            content_type: "application/json".to_owned(),
            body: br#"{"content":"hello fixture"}"#.to_vec(),
        }
    );
    assert_eq!(
        channel.poll_inbound(),
        Err(ChannelError::Unsupported(UnsupportedOperation::Inbound))
    );
}

#[test]
fn qa_channel_round_trips_inbound_and_records_outbound() {
    let inbound = InboundMessage {
        id: "message-1".to_owned(),
        channel_id: "qa-channel".to_owned(),
        account_id: "qa".to_owned(),
        conversation_id: "room".to_owned(),
        sender_id: "fixture".to_owned(),
        text: Some("inbound".to_owned()),
        attachments: Vec::new(),
        received_at_unix_ms: 100,
    };
    let outbound = OutboundMessage {
        account_id: "qa".to_owned(),
        ..outbound()
    };
    let mut channel = QaChannel::new("qa", FixedClock(200)).expect("valid QA channel");
    assert_eq!(channel.push_inbound(inbound.clone()), Ok(()));
    assert_eq!(channel.poll_inbound(), Ok(Some(inbound)));
    assert_eq!(channel.poll_inbound(), Ok(None));
    assert_eq!(
        channel.send_outbound(&outbound, None),
        Ok(DeliveryAcknowledgement {
            idempotency_key: "delivery-1".to_owned(),
            remote_message_id: Some("qa-1".to_owned()),
            state: DeliveryState::Delivered,
            accepted_at_unix_ms: 200,
        })
    );
    assert_eq!(channel.outbound(), &[outbound]);
}

#[test]
fn webhook_authentication_failure_is_typed_and_body_free() {
    let (endpoint, server) = fixture_server(401);
    let credential = webhook_credential("slack", endpoint);
    let mut channel = WebhookChannel::new("slack", "primary", LoopbackHttpTransport, FixedClock(5))
        .expect("valid adapter");
    assert_eq!(
        channel.send_outbound(&outbound(), Some(&credential)),
        Err(ChannelError::Authentication)
    );
    let captured = server.join().expect("fixture server");
    assert_eq!(captured.body, br#"{"text":"hello fixture"}"#);
}

#[test]
fn every_partial_webhook_adapter_completes_against_a_local_server() {
    let cases = [
        ("mattermost", br#"{"text":"hello fixture"}"#.as_slice()),
        ("googlechat", br#"{"text":"hello fixture"}"#.as_slice()),
        ("slack", br#"{"text":"hello fixture"}"#.as_slice()),
        ("discord", br#"{"content":"hello fixture"}"#.as_slice()),
    ];
    for (channel_id, expected_body) in cases {
        let (endpoint, server) = fixture_server(200);
        let credential = webhook_credential(channel_id, endpoint);
        let mut channel = WebhookChannel::new(
            channel_id,
            "primary",
            LoopbackHttpTransport,
            FixedClock(900),
        )
        .expect("supported adapter");
        assert_eq!(
            channel.send_outbound(&outbound(), Some(&credential)),
            Ok(DeliveryAcknowledgement {
                idempotency_key: "delivery-1".to_owned(),
                remote_message_id: None,
                state: DeliveryState::Accepted,
                accepted_at_unix_ms: 900,
            })
        );
        assert_eq!(server.join().expect("fixture server").body, expected_body);
    }
}

#[test]
fn credential_bearing_request_debug_is_redacted_and_redirects_are_rejected() {
    let rendered = Rc::new(RefCell::new(Vec::new()));
    let transport = InspectingTransport {
        rendered: Rc::clone(&rendered),
    };
    let credential = webhook_credential(
        "discord",
        "https://discord.example/hooks/super-secret-token".to_owned(),
    );
    let mut channel = WebhookChannel::new("discord", "primary", transport, FixedClock(42))
        .expect("valid adapter");
    assert_eq!(
        channel.send_outbound(&outbound(), Some(&credential)),
        Ok(DeliveryAcknowledgement {
            idempotency_key: "delivery-1".to_owned(),
            remote_message_id: None,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: 42,
        })
    );
    assert_eq!(
        rendered.borrow().as_slice(),
        &[
            "WebhookRequest { endpoint: \"[REDACTED]\", body: [REDACTED; 27 bytes], redirect_policy: Reject }"
        ]
    );
}

#[test]
fn redirect_response_is_not_treated_as_delivery() {
    let (endpoint, server) = fixture_server(302);
    let credential = webhook_credential("discord", endpoint);
    let mut channel =
        WebhookChannel::new("discord", "primary", LoopbackHttpTransport, FixedClock(42))
            .expect("valid adapter");
    assert_eq!(
        channel.send_outbound(&outbound(), Some(&credential)),
        Err(ChannelError::RemoteRejected { status: 302 })
    );
    assert_eq!(
        server.join().expect("fixture server").body,
        br#"{"content":"hello fixture"}"#
    );
}

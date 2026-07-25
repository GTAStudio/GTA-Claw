//! Executable channel behavior against local fixtures.

use std::cell::{Cell, RefCell};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use claw_channel_sdk::{
    BackoffSleeper, Channel, ChannelCredential, ChannelError, CredentialBinding,
    CredentialBindingError, CredentialKind, CredentialRequest, DeliveryAcknowledgement,
    DeliveryState, InboundMessage, OutboundMessage, OutboundRetrySafety, RetryPolicy,
    TransportErrorKind, UnsupportedOperation, send_with_retry,
};
use claw_channels::{
    AuthMode, ChannelCapability, ImplementationStatus, LoopbackHttpTransport, QaChannel,
    RedirectPolicy, UnixClock, WebhookChannel, WebhookRequest, WebhookResponse, WebhookTransport,
    registry,
};

const FIXTURE_WEBHOOK_CASES: [(&str, &[u8]); 4] = [
    ("mattermost", br#"{"text":"hello fixture"}"#),
    ("googlechat", br#"{"text":"hello fixture"}"#),
    ("slack", br#"{"text":"hello fixture"}"#),
    ("discord", br#"{"content":"hello fixture"}"#),
];

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
        correlation_key: "delivery-1".to_owned(),
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

#[derive(Clone)]
struct FailingTransport {
    calls: Rc<Cell<usize>>,
}

impl WebhookTransport for FailingTransport {
    fn post_json(&self, _request: &WebhookRequest<'_>) -> Result<WebhookResponse, ChannelError> {
        self.calls.set(self.calls.get() + 1);
        Err(ChannelError::Transport(TransportErrorKind::Timeout))
    }
}

#[derive(Default)]
struct RecordingSleeper(Vec<Duration>);

impl BackoffSleeper for RecordingSleeper {
    fn sleep(&mut self, delay: Duration) {
        self.0.push(delay);
    }
}

#[test]
fn discord_webhook_posts_exact_payload_to_local_fixture_server() {
    let (endpoint, server) = fixture_server(204);
    let credential = webhook_credential("discord", endpoint);
    let mut channel = WebhookChannel::new(
        "discord",
        "primary",
        "room-1",
        LoopbackHttpTransport,
        FixedClock(1_234),
    )
    .expect("valid adapter");

    assert_eq!(
        channel.send_outbound(&outbound(), Some(&credential)),
        Ok(DeliveryAcknowledgement {
            correlation_key: "delivery-1".to_owned(),
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
            correlation_key: "delivery-1".to_owned(),
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
    let mut channel = WebhookChannel::new(
        "slack",
        "primary",
        "room-1",
        LoopbackHttpTransport,
        FixedClock(5),
    )
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
    let registered = registry()
        .iter()
        .filter(|entry| entry.implementation == ImplementationStatus::OutboundWebhook)
        .map(|entry| entry.id)
        .collect::<std::collections::BTreeSet<_>>();
    let exercised = FIXTURE_WEBHOOK_CASES
        .iter()
        .map(|(channel_id, _)| *channel_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(exercised, registered);

    for (channel_id, expected_body) in FIXTURE_WEBHOOK_CASES {
        let (endpoint, server) = fixture_server(200);
        let credential = webhook_credential(channel_id, endpoint);
        let mut channel = WebhookChannel::new(
            channel_id,
            "primary",
            "room-1",
            LoopbackHttpTransport,
            FixedClock(900),
        )
        .expect("supported adapter");
        assert_eq!(
            channel.send_outbound(&outbound(), Some(&credential)),
            Ok(DeliveryAcknowledgement {
                correlation_key: "delivery-1".to_owned(),
                remote_message_id: None,
                state: DeliveryState::Accepted,
                accepted_at_unix_ms: 900,
            })
        );
        assert_eq!(server.join().expect("fixture server").body, expected_body);
    }
}

fn assert_retry_capability_matches_runtime(
    capabilities: &[ChannelCapability],
    channel: &impl Channel,
) {
    assert_eq!(
        capabilities.contains(&ChannelCapability::SafeOutboundRetry),
        channel.outbound_retry_safety() == OutboundRetrySafety::SafeToRepeat
    );
}

#[test]
fn executable_channel_advertisements_match_runtime_controls() {
    let rendered = Rc::new(RefCell::new(Vec::new()));
    for entry in registry()
        .iter()
        .filter(|entry| entry.implementation == ImplementationStatus::OutboundWebhook)
    {
        assert_eq!(entry.auth_modes, &[AuthMode::WebhookUrl]);
        let transport = InspectingTransport {
            rendered: Rc::clone(&rendered),
        };
        let mut channel =
            WebhookChannel::new(entry.id, "primary", "room-1", transport, FixedClock(42))
                .expect("advertised webhook adapter");
        assert_retry_capability_matches_runtime(entry.capabilities, &channel);
        let credential = webhook_credential(
            entry.id,
            format!("https://{0}.example/hooks/fixture-secret", entry.id),
        );
        assert_eq!(
            channel.send_outbound(&outbound(), Some(&credential)),
            Ok(DeliveryAcknowledgement {
                correlation_key: "delivery-1".to_owned(),
                remote_message_id: None,
                state: DeliveryState::Accepted,
                accepted_at_unix_ms: 42,
            })
        );

        for kind in [
            CredentialKind::Token,
            CredentialKind::ClientSecret,
            CredentialKind::Password,
            CredentialKind::PrivateKey,
        ] {
            let unsupported = ChannelCredential::bind(
                "not-a-webhook",
                CredentialRequest {
                    channel_id: entry.id.to_owned(),
                    account_id: "primary".to_owned(),
                    kind,
                    binding: CredentialBinding::LocalOnly,
                },
            )
            .expect("valid non-webhook binding");
            assert_eq!(
                channel.send_outbound(&outbound(), Some(&unsupported)),
                Err(ChannelError::CredentialBinding(
                    CredentialBindingError::ScopeMismatch
                ))
            );
        }
    }
    let qa_entry = registry()
        .iter()
        .find(|entry| entry.id == "qa-channel")
        .expect("QA registry entry");
    let qa_channel = QaChannel::new("qa", FixedClock(42)).expect("valid QA adapter");
    assert_eq!(qa_entry.auth_modes, &[AuthMode::None]);
    assert_retry_capability_matches_runtime(qa_entry.capabilities, &qa_channel);
    assert_eq!(rendered.borrow().len(), FIXTURE_WEBHOOK_CASES.len());
}

#[test]
fn outbound_webhook_rejects_a_conversation_mismatch_before_transport() {
    let rendered = Rc::new(RefCell::new(Vec::new()));
    for entry in registry()
        .iter()
        .filter(|entry| entry.implementation == ImplementationStatus::OutboundWebhook)
    {
        let transport = InspectingTransport {
            rendered: Rc::clone(&rendered),
        };
        let credential = webhook_credential(
            entry.id,
            format!("https://{0}.example/hooks/fixture-secret", entry.id),
        );
        let mut channel = WebhookChannel::new(
            entry.id,
            "primary",
            "private-room",
            transport,
            FixedClock(42),
        )
        .expect("valid adapter");
        let message = OutboundMessage {
            conversation_id: "public-room".to_owned(),
            ..outbound()
        };

        assert_eq!(
            channel.send_outbound(&message, Some(&credential)),
            Err(ChannelError::Configuration(
                claw_channel_sdk::ConfigurationError::ConversationScopeMismatch
            ))
        );
    }
    assert!(rendered.borrow().is_empty());
}

#[test]
fn outbound_webhooks_do_not_retry_ambiguous_failures() {
    let policy = RetryPolicy::new(
        NonZeroU32::new(3).expect("non-zero"),
        Duration::from_millis(1),
        Duration::from_millis(4),
        NonZeroU32::new(2).expect("non-zero"),
    )
    .expect("valid retry policy");
    for entry in registry()
        .iter()
        .filter(|entry| entry.implementation == ImplementationStatus::OutboundWebhook)
    {
        let calls = Rc::new(Cell::new(0));
        let transport = FailingTransport {
            calls: Rc::clone(&calls),
        };
        let credential = webhook_credential(
            entry.id,
            format!("https://{0}.example/hooks/fixture-secret", entry.id),
        );
        let mut channel =
            WebhookChannel::new(entry.id, "primary", "room-1", transport, FixedClock(42))
                .expect("valid adapter");
        let mut sleeper = RecordingSleeper::default();

        assert_eq!(
            send_with_retry(
                &mut channel,
                &outbound(),
                Some(&credential),
                policy,
                &mut sleeper,
            ),
            Err(ChannelError::Transport(TransportErrorKind::Timeout))
        );
        assert_eq!(calls.get(), 1);
        assert!(sleeper.0.is_empty());
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
    let mut channel =
        WebhookChannel::new("discord", "primary", "room-1", transport, FixedClock(42))
            .expect("valid adapter");
    assert_eq!(
        channel.send_outbound(&outbound(), Some(&credential)),
        Ok(DeliveryAcknowledgement {
            correlation_key: "delivery-1".to_owned(),
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
    let mut channel = WebhookChannel::new(
        "discord",
        "primary",
        "room-1",
        LoopbackHttpTransport,
        FixedClock(42),
    )
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

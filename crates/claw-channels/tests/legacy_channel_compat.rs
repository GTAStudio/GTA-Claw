//! Synthetic legacy-channel payload and lifecycle fixtures.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::num::{NonZeroU32, NonZeroUsize};
use std::rc::Rc;
use std::time::Duration;

use claw_channel_sdk::{
    ApprovedOrigin, Channel, ChannelCredential, ChannelError, ConfigurationError, ConnectionState,
    CredentialBinding, CredentialBindingError, CredentialKind, CredentialRequest, InboundMessage,
    NetworkOrigin, OriginTrustError, OriginTrustStore, OutboundMessage, ProtocolErrorKind,
    TransportErrorKind, authorize_origin,
};
use claw_channels::{
    AuthenticationPrompt, COMMON_FAILURE_REPLY, ConversationService, DiagnosticCode,
    DiagnosticSink, DiscordChannel, DiscordCreateMessageRequest, DiscordGatewayClose,
    DiscordGatewayPhase, DiscordGatewayRequest, DiscordPacketOutcome, DiscordTransport,
    OperatorDiagnostic, ProviderResponse, ReplySource, TEAMS_FAILURE_REPLY, TEAMS_GREETING,
    TeamsAction, TeamsActivityError, TeamsActivityHandler, TeamsActivityOutcome, TelegramChannel,
    TelegramPollRequest, TelegramSendRequest, TelegramTransport, UnixClock,
    WHATSAPP_MAX_MESSAGES_PER_WEBHOOK, WhatsAppChannel, WhatsAppSendError, WhatsAppSendRequest,
    WhatsAppTransport, WhatsAppVerificationQuery, WhatsAppVerificationResponse,
    WhatsAppWebhookResponse, verify_whatsapp_webhook_signature,
};

const ACCOUNT: &str = "primary";

struct AllowTrust;

impl OriginTrustStore for AllowTrust {
    fn is_enrolled(
        &self,
        _channel_id: &str,
        _account_id: &str,
        _origin: &NetworkOrigin,
    ) -> Result<bool, OriginTrustError> {
        Ok(true)
    }
}

fn approved_origin(channel_id: &str, host: &str) -> ApprovedOrigin {
    let origin = NetworkOrigin::https(host, None).expect("valid fixture origin");
    authorize_origin(&AllowTrust, channel_id, ACCOUNT, &origin).expect("enrolled fixture origin")
}

fn token_credential(channel_id: &str, host: &str, secret: &str) -> ChannelCredential {
    ChannelCredential::bind(
        secret.to_owned(),
        CredentialRequest {
            channel_id: channel_id.to_owned(),
            account_id: ACCOUNT.to_owned(),
            kind: CredentialKind::Token,
            binding: CredentialBinding::Origin(approved_origin(channel_id, host)),
        },
    )
    .expect("valid token credential")
}

fn local_credential(kind: CredentialKind, secret: &str) -> ChannelCredential {
    ChannelCredential::bind(
        secret.to_owned(),
        CredentialRequest {
            channel_id: "whatsapp".to_owned(),
            account_id: ACCOUNT.to_owned(),
            kind,
            binding: CredentialBinding::LocalOnly,
        },
    )
    .expect("valid local credential")
}

#[derive(Clone, Copy, Debug)]
struct FixedClock(u64);

impl UnixClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

#[derive(Default)]
struct Diagnostics(Vec<DiagnosticCode>);

impl DiagnosticSink for Diagnostics {
    fn record(&mut self, diagnostic: OperatorDiagnostic<'_>) {
        self.0.push(diagnostic.code);
    }
}

fn outbound(conversation_id: &str, text: String) -> OutboundMessage {
    OutboundMessage {
        correlation_key: "delivery-1".to_owned(),
        account_id: ACCOUNT.to_owned(),
        conversation_id: conversation_id.to_owned(),
        text: Some(text),
        attachments: Vec::new(),
        reply_to: None,
    }
}

struct TelegramFixture {
    polls: VecDeque<Result<ProviderResponse, ChannelError>>,
    poll_offsets: Rc<RefCell<Vec<Option<i64>>>>,
    sent: Rc<RefCell<Vec<String>>>,
    debug: Rc<RefCell<Vec<String>>>,
}

impl TelegramTransport for TelegramFixture {
    fn get_updates(
        &mut self,
        request: &TelegramPollRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError> {
        assert_eq!(request.bot_token(), "telegram-secret");
        assert_eq!(request.long_poll_timeout(), Duration::from_secs(25));
        assert_eq!(request.request_timeout(), Duration::from_secs(35));
        self.poll_offsets.borrow_mut().push(request.offset());
        self.debug.borrow_mut().push(format!("{request:?}"));
        self.polls.pop_front().expect("scripted poll response")
    }

    fn send_message(
        &mut self,
        request: &TelegramSendRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError> {
        assert_eq!(request.bot_token(), "telegram-secret");
        assert_eq!(request.chat_id(), -100);
        assert!(request.disable_web_page_preview());
        assert_eq!(request.request_timeout(), Duration::from_secs(10));
        self.debug.borrow_mut().push(format!("{request:?}"));
        let mut sent = self.sent.borrow_mut();
        sent.push(request.text().to_owned());
        Ok(ProviderResponse::new(
            200,
            format!(r#"{{"ok":true,"result":{{"message_id":{}}}}}"#, sent.len()),
        ))
    }
}

#[test]
fn telegram_polling_advances_offsets_filters_bots_bounds_queues_and_segments_replies() {
    let payload = br#"{
      "ok": true,
      "result": [
        {"update_id":10},
        {"update_id":11,"message":{"message_id":1,"chat":{"id":-100},"from":{"id":9,"is_bot":true},"text":"bot"}},
        {"update_id":12,"message":{"message_id":2,"chat":{"id":-100},"from":{"id":10},"text":"   "}},
        {"update_id":13,"message":{"message_id":3,"chat":{"id":-100},"from":{"id":11},"text":"  hello  ","date":123}},
        {"update_id":14,"message":{"message_id":4,"chat":{"id":-100},"from":{"id":12},"text":"overflow"}},
        {"update_id":15,"message":{"message_id":-1,"chat":{"id":-100},"from":{"id":13},"text":"malformed"}}
      ]
    }"#;
    let poll_offsets = Rc::new(RefCell::new(Vec::new()));
    let sent = Rc::new(RefCell::new(Vec::new()));
    let debug = Rc::new(RefCell::new(Vec::new()));
    let transport = TelegramFixture {
        polls: VecDeque::from([
            Ok(ProviderResponse::new(200, payload.as_slice())),
            Err(ChannelError::Transport(TransportErrorKind::Timeout)),
        ]),
        poll_offsets: Rc::clone(&poll_offsets),
        sent: Rc::clone(&sent),
        debug: Rc::clone(&debug),
    };
    let mut channel = TelegramChannel::new(
        ACCOUNT,
        approved_origin("telegram", "api.telegram.org"),
        transport,
        FixedClock(999),
        NonZeroUsize::new(1).expect("non-zero capacity"),
        Duration::from_millis(250),
    )
    .expect("Telegram adapter");
    let credential = token_credential("telegram", "api.telegram.org", "telegram-secret");
    let mut diagnostics = Diagnostics::default();

    assert_eq!(channel.start(&mut diagnostics), Ok(true));
    assert_eq!(channel.start(&mut diagnostics), Ok(false));
    let stats = channel
        .poll_once(&credential, &mut diagnostics)
        .expect("poll payload");
    assert_eq!(stats.updates, 6);
    assert_eq!(stats.queued, 1);
    assert_eq!(stats.ignored, 4);
    assert_eq!(stats.dropped, 1);
    assert_eq!(stats.next_offset, 16);
    assert_eq!(channel.offset(), 16);
    assert_eq!(*poll_offsets.borrow(), [None]);
    assert!(diagnostics.0.contains(&DiagnosticCode::BotMessageIgnored));
    assert!(diagnostics.0.contains(&DiagnosticCode::InboundQueueFull));
    assert!(diagnostics.0.contains(&DiagnosticCode::MalformedPayload));

    let inbound = channel
        .poll_inbound()
        .expect("running")
        .expect("queued message");
    assert_eq!(
        inbound,
        InboundMessage {
            id: "3".to_owned(),
            channel_id: "telegram".to_owned(),
            account_id: ACCOUNT.to_owned(),
            conversation_id: "telegram:-100".to_owned(),
            sender_id: "11".to_owned(),
            text: Some("hello".to_owned()),
            attachments: Vec::new(),
            received_at_unix_ms: 123_000,
        }
    );
    assert_eq!(channel.poll_inbound(), Ok(None));

    assert_eq!(
        channel.poll_once(&credential, &mut diagnostics),
        Err(ChannelError::Transport(TransportErrorKind::Timeout))
    );
    assert_eq!(*poll_offsets.borrow(), [None, Some(16)]);
    assert!(diagnostics.0.contains(&DiagnosticCode::PollFailed));

    let acknowledgement = channel
        .send_outbound(
            &outbound("telegram:-100", "reply".to_owned()),
            Some(&credential),
        )
        .expect("Telegram send");
    assert_eq!(acknowledgement.remote_message_id.as_deref(), Some("1"));
    assert_eq!(sent.borrow().as_slice(), ["reply"]);
    assert!(
        debug
            .borrow()
            .iter()
            .all(|rendered| !rendered.contains("telegram-secret"))
    );

    assert_eq!(channel.stop(&mut diagnostics), Ok(true));
    assert_eq!(channel.stop(&mut diagnostics), Ok(false));
    assert_eq!(
        channel.poll_inbound(),
        Err(ChannelError::NotConnected {
            state: ConnectionState::Closed
        })
    );
}

#[test]
fn telegram_uses_json_retry_after_when_a_429_has_no_header() {
    let poll_offsets = Rc::new(RefCell::new(Vec::new()));
    let transport = TelegramFixture {
        polls: VecDeque::from([Ok(ProviderResponse::new(
            429,
            br#"{"ok":false,"error_code":429,"parameters":{"retry_after":17}}"#.as_slice(),
        ))]),
        poll_offsets,
        sent: Rc::new(RefCell::new(Vec::new())),
        debug: Rc::new(RefCell::new(Vec::new())),
    };
    let mut channel = TelegramChannel::new(
        ACCOUNT,
        approved_origin("telegram", "api.telegram.org"),
        transport,
        FixedClock(999),
        NonZeroUsize::new(1).expect("non-zero capacity"),
        Duration::from_millis(250),
    )
    .expect("Telegram adapter");
    let credential = token_credential("telegram", "api.telegram.org", "telegram-secret");
    channel.start(&mut ()).expect("started");

    assert_eq!(
        channel.poll_once(&credential, &mut ()),
        Err(ChannelError::RateLimited {
            retry_after: Duration::from_secs(17)
        })
    );
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayRecord {
    opcode: u8,
    token: Option<String>,
    intents: Option<u64>,
    session_id: Option<String>,
    sequence: Option<i64>,
}

struct DiscordFixture {
    open_results: VecDeque<Result<(), ChannelError>>,
    opens: Rc<Cell<usize>>,
    open_urls: Rc<RefCell<Vec<String>>>,
    closes: Rc<Cell<usize>>,
    gateway: Rc<RefCell<Vec<GatewayRecord>>>,
    rest: Rc<RefCell<Vec<String>>>,
    debug: Rc<RefCell<Vec<String>>>,
}

impl DiscordTransport for DiscordFixture {
    fn open_gateway(&mut self, gateway_url: &str) -> Result<(), ChannelError> {
        self.open_urls.borrow_mut().push(gateway_url.to_owned());
        self.opens.set(self.opens.get() + 1);
        self.open_results.pop_front().unwrap_or(Ok(()))
    }

    fn close_gateway(&mut self) -> Result<(), ChannelError> {
        self.closes.set(self.closes.get() + 1);
        Ok(())
    }

    fn send_gateway(&mut self, request: &DiscordGatewayRequest<'_>) -> Result<(), ChannelError> {
        self.debug.borrow_mut().push(format!("{request:?}"));
        self.gateway.borrow_mut().push(GatewayRecord {
            opcode: request.opcode(),
            token: request.bot_token().map(str::to_owned),
            intents: request.intents(),
            session_id: request.session_id().map(str::to_owned),
            sequence: request.sequence(),
        });
        Ok(())
    }

    fn create_message(
        &mut self,
        request: &DiscordCreateMessageRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError> {
        assert_eq!(request.bot_token(), "discord-rest-secret");
        assert_eq!(request.channel_id(), "room");
        assert_eq!(request.api_version(), 10);
        assert_eq!(request.request_timeout(), Duration::from_secs(10));
        self.debug.borrow_mut().push(format!("{request:?}"));
        let mut rest = self.rest.borrow_mut();
        rest.push(request.content().to_owned());
        Ok(ProviderResponse::new(
            200,
            format!(r#"{{"id":"discord-{}"}}"#, rest.len()),
        ))
    }
}

struct DiscordHarness {
    channel: DiscordChannel<DiscordFixture, FixedClock>,
    opens: Rc<Cell<usize>>,
    open_urls: Rc<RefCell<Vec<String>>>,
    closes: Rc<Cell<usize>>,
    gateway: Rc<RefCell<Vec<GatewayRecord>>>,
    rest: Rc<RefCell<Vec<String>>>,
    debug: Rc<RefCell<Vec<String>>>,
}

fn discord_channel(
    open_results: VecDeque<Result<(), ChannelError>>,
    max_reconnect_attempts: u32,
) -> DiscordHarness {
    let opens = Rc::new(Cell::new(0));
    let open_urls = Rc::new(RefCell::new(Vec::new()));
    let closes = Rc::new(Cell::new(0));
    let gateway = Rc::new(RefCell::new(Vec::new()));
    let rest = Rc::new(RefCell::new(Vec::new()));
    let debug = Rc::new(RefCell::new(Vec::new()));
    let channel = DiscordChannel::new(
        ACCOUNT,
        "wss://gateway.discord.gg/?v=10&encoding=json",
        approved_origin("discord", "gateway.discord.gg"),
        approved_origin("discord", "discord.com"),
        32_768,
        DiscordFixture {
            open_results,
            opens: Rc::clone(&opens),
            open_urls: Rc::clone(&open_urls),
            closes: Rc::clone(&closes),
            gateway: Rc::clone(&gateway),
            rest: Rc::clone(&rest),
            debug: Rc::clone(&debug),
        },
        FixedClock(456),
        NonZeroUsize::new(2).expect("non-zero capacity"),
        NonZeroU32::new(max_reconnect_attempts).expect("non-zero attempts"),
    )
    .expect("Discord adapter");
    DiscordHarness {
        channel,
        opens,
        open_urls,
        closes,
        gateway,
        rest,
        debug,
    }
}

#[test]
fn discord_gateway_contains_bad_packets_heartbeats_reconnects_and_filters_bots() {
    let DiscordHarness {
        mut channel,
        opens,
        closes,
        gateway,
        rest,
        debug,
        ..
    } = discord_channel(VecDeque::from([Ok(()), Ok(())]), 2);
    let gateway_credential =
        token_credential("discord", "gateway.discord.gg", "discord-gateway-secret");
    let rest_credential = token_credential("discord", "discord.com", "discord-rest-secret");
    let mut diagnostics = Diagnostics::default();

    assert_eq!(channel.start(Duration::ZERO, &mut diagnostics), Ok(true));
    assert_eq!(opens.get(), 1);
    assert_eq!(channel.state(), ConnectionState::Connecting);
    channel
        .gateway_opened(&mut diagnostics)
        .expect("socket opened");
    assert_eq!(channel.state(), ConnectionState::Connecting);
    assert_eq!(channel.phase(), DiscordGatewayPhase::AwaitingHello);

    assert_eq!(
        channel.handle_gateway_packet(
            b"{bad",
            Duration::ZERO,
            &gateway_credential,
            &mut diagnostics,
        ),
        Ok(DiscordPacketOutcome::Malformed)
    );
    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
            Duration::ZERO,
            &gateway_credential,
            &mut diagnostics,
        ),
        Ok(DiscordPacketOutcome::Identified)
    );
    assert_eq!(channel.phase(), DiscordGatewayPhase::Identifying);
    assert_eq!(channel.gateway_opened(&mut diagnostics), Ok(()));
    assert_eq!(channel.phase(), DiscordGatewayPhase::Identifying);
    assert_eq!(
        gateway.borrow().as_slice(),
        &[GatewayRecord {
            opcode: 2,
            token: Some("discord-gateway-secret".to_owned()),
            intents: Some(32_768),
            session_id: None,
            sequence: None,
        }]
    );
    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":0,"t":"READY","s":7,"d":{"session_id":"session-1","resume_gateway_url":"wss://gateway-us-east1-b.discord.gg"}}"#,
            Duration::ZERO,
            &gateway_credential,
            &mut diagnostics,
        ),
        Ok(DiscordPacketOutcome::Ready)
    );
    assert_eq!(channel.state(), ConnectionState::Connected);
    assert_eq!(channel.phase(), DiscordGatewayPhase::Ready);
    assert_eq!(channel.sequence(), Some(7));
    assert_eq!(channel.session_id(), Some("session-1"));

    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":0,"t":"MESSAGE_CREATE","s":8,"d":{"id":"m1","channel_id":"room","content":"bot","author":{"id":"bot","username":"robot","bot":true}}}"#,
            Duration::ZERO,
            &gateway_credential,
            &mut diagnostics,
        ),
        Ok(DiscordPacketOutcome::Ignored)
    );
    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":0,"t":"MESSAGE_CREATE","s":9,"d":{"id":"m2","channel_id":"room","content":"  hello  ","author":{"id":"user","username":"octocat"}}}"#,
            Duration::ZERO,
            &gateway_credential,
            &mut diagnostics,
        ),
        Ok(DiscordPacketOutcome::MessageQueued)
    );
    let inbound = channel
        .poll_inbound()
        .expect("connected")
        .expect("message queued");
    assert_eq!(inbound.conversation_id, "discord:room:user");
    assert_eq!(inbound.text.as_deref(), Some("hello"));
    assert_eq!(inbound.received_at_unix_ms, 456);

    let acknowledgement = channel
        .send_outbound(
            &outbound("discord:room:user", "reply".to_owned()),
            Some(&rest_credential),
        )
        .expect("REST reply");
    assert_eq!(
        acknowledgement.remote_message_id.as_deref(),
        Some("discord-1")
    );
    assert_eq!(rest.borrow().as_slice(), ["reply"]);

    assert_eq!(
        channel.tick(Duration::from_secs(1), &mut diagnostics),
        Ok(true)
    );
    assert_eq!(
        gateway.borrow().last(),
        Some(&GatewayRecord {
            opcode: 1,
            token: None,
            intents: None,
            session_id: None,
            sequence: Some(9),
        })
    );
    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":11,"t":null,"s":null,"d":null}"#,
            Duration::from_secs(1),
            &gateway_credential,
            &mut diagnostics,
        ),
        Ok(DiscordPacketOutcome::HeartbeatAcknowledged)
    );
    assert_eq!(
        channel.gateway_closed(Duration::from_secs(2), &mut diagnostics),
        Ok(true)
    );
    assert_eq!(channel.state(), ConnectionState::Reconnecting);
    assert_eq!(channel.reconnect_due(), Some(Duration::from_secs(5)));
    assert_eq!(
        channel.tick(Duration::from_millis(4_999), &mut diagnostics),
        Ok(false)
    );
    assert_eq!(
        channel.tick(Duration::from_secs(5), &mut diagnostics),
        Ok(true)
    );
    assert_eq!(opens.get(), 2);
    assert_eq!(channel.state(), ConnectionState::Connecting);

    assert_eq!(channel.stop(&mut diagnostics), Ok(true));
    assert_eq!(channel.stop(&mut diagnostics), Ok(false));
    assert_eq!(channel.state(), ConnectionState::Closed);
    assert_eq!(closes.get(), 1);
    assert_eq!(
        channel.tick(Duration::from_secs(10), &mut diagnostics),
        Ok(false)
    );
    assert!(diagnostics.0.contains(&DiagnosticCode::MalformedPayload));
    assert!(diagnostics.0.contains(&DiagnosticCode::BotMessageIgnored));
    assert!(diagnostics.0.contains(&DiagnosticCode::ReconnectScheduled));
    assert!(debug.borrow().iter().all(|rendered| {
        !rendered.contains("discord-gateway-secret") && !rendered.contains("discord-rest-secret")
    }));
}

#[test]
fn discord_reconnect_attempts_are_bounded() {
    let failure = ChannelError::Transport(TransportErrorKind::Connection);
    let DiscordHarness {
        mut channel, opens, ..
    } = discord_channel(
        VecDeque::from([Err(failure.clone()), Err(failure.clone())]),
        1,
    );
    let mut diagnostics = Diagnostics::default();

    assert_eq!(
        channel.start(Duration::ZERO, &mut diagnostics),
        Err(failure.clone())
    );
    assert_eq!(channel.state(), ConnectionState::Reconnecting);
    assert_eq!(
        channel.tick(Duration::from_secs(3), &mut diagnostics),
        Err(failure)
    );
    assert_eq!(opens.get(), 2);
    assert_eq!(channel.state(), ConnectionState::Disconnected);
    assert_eq!(channel.phase(), DiscordGatewayPhase::ReconnectExhausted);
    assert_eq!(channel.reconnect_due(), None);
    assert!(diagnostics.0.contains(&DiagnosticCode::ReconnectExhausted));
}

#[test]
fn discord_gateway_credential_failure_closes_and_schedules_reconnect() {
    let DiscordHarness {
        mut channel,
        closes,
        ..
    } = discord_channel(VecDeque::from([Ok(())]), 2);
    let wrong_origin_credential = token_credential("discord", "discord.com", "wrong-origin-secret");
    let mut diagnostics = Diagnostics::default();

    channel
        .start(Duration::ZERO, &mut diagnostics)
        .expect("opening started");
    channel
        .gateway_opened(&mut diagnostics)
        .expect("socket opened");
    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
            Duration::ZERO,
            &wrong_origin_credential,
            &mut diagnostics,
        ),
        Err(ChannelError::CredentialBinding(
            CredentialBindingError::DestinationMismatch
        ))
    );
    assert_eq!(closes.get(), 1);
    assert_eq!(channel.state(), ConnectionState::Reconnecting);
    assert_eq!(channel.phase(), DiscordGatewayPhase::Idle);
    assert_eq!(channel.reconnect_due(), Some(Duration::from_secs(3)));
    assert!(diagnostics.0.contains(&DiagnosticCode::ConnectionFailed));
}

fn establish_discord_session(
    channel: &mut DiscordChannel<DiscordFixture, FixedClock>,
    credential: &ChannelCredential,
) {
    channel
        .start(Duration::ZERO, &mut ())
        .expect("opening started");
    channel.gateway_opened(&mut ()).expect("socket opened");
    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
            Duration::ZERO,
            credential,
            &mut (),
        ),
        Ok(DiscordPacketOutcome::Identified)
    );
    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":0,"t":"READY","s":41,"d":{"session_id":"resumable-session","resume_gateway_url":"wss://gateway-us-east1-b.discord.gg"}}"#,
            Duration::ZERO,
            credential,
            &mut (),
        ),
        Ok(DiscordPacketOutcome::Ready)
    );
}

#[test]
fn discord_reconnect_and_resumable_invalid_session_send_resume() {
    let gateway_credential =
        token_credential("discord", "gateway.discord.gg", "discord-gateway-secret");
    for reconnect_packet in [
        br#"{"op":7,"t":null,"s":null,"d":null}"#.as_slice(),
        br#"{"op":9,"t":null,"s":null,"d":true}"#.as_slice(),
    ] {
        let DiscordHarness {
            mut channel,
            open_urls,
            gateway,
            ..
        } = discord_channel(VecDeque::from([Ok(()), Ok(())]), 2);
        establish_discord_session(&mut channel, &gateway_credential);

        assert_eq!(
            channel.handle_gateway_packet(
                reconnect_packet,
                Duration::from_secs(1),
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::ReconnectRequested)
        );
        assert_eq!(channel.session_id(), Some("resumable-session"));
        assert_eq!(channel.sequence(), Some(41));
        assert_eq!(
            channel.resume_gateway_url(),
            Some("wss://gateway-us-east1-b.discord.gg?v=10&encoding=json")
        );
        assert_eq!(channel.tick(Duration::from_secs(4), &mut ()), Ok(true));
        assert_eq!(
            open_urls.borrow().last().map(String::as_str),
            Some("wss://gateway-us-east1-b.discord.gg?v=10&encoding=json")
        );
        channel.gateway_opened(&mut ()).expect("reopened socket");
        assert_eq!(
            channel.handle_gateway_packet(
                br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
                Duration::from_secs(4),
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::Identified)
        );
        assert_eq!(channel.phase(), DiscordGatewayPhase::Resuming);
        assert_eq!(
            gateway.borrow().last(),
            Some(&GatewayRecord {
                opcode: 6,
                token: Some("discord-gateway-secret".to_owned()),
                intents: None,
                session_id: Some("resumable-session".to_owned()),
                sequence: Some(41),
            })
        );
        assert_eq!(
            channel.handle_gateway_packet(
                br#"{"op":0,"t":"MESSAGE_CREATE","s":42,"d":{"id":"replayed","channel_id":"room","content":"replayed message","author":{"id":"user","username":"octocat"}}}"#,
                Duration::from_secs(4),
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::MessageQueued)
        );
        assert_eq!(channel.sequence(), Some(42));
        assert_eq!(channel.queued_inbound(), 1);
        assert_eq!(channel.state(), ConnectionState::Connecting);
        assert_eq!(
            channel.handle_gateway_packet(
                br#"{"op":0,"t":"RESUMED","s":43,"d":{}}"#,
                Duration::from_secs(4),
                &gateway_credential,
                &mut (),
            ),
            Ok(DiscordPacketOutcome::Ready)
        );
        assert_eq!(channel.state(), ConnectionState::Connected);
        assert_eq!(channel.sequence(), Some(43));
        assert_eq!(
            channel
                .poll_inbound()
                .expect("resumed")
                .expect("replayed dispatch")
                .id,
            "replayed"
        );
    }
}

#[test]
fn discord_server_heartbeat_request_is_answered_immediately() {
    let DiscordHarness {
        mut channel,
        gateway,
        ..
    } = discord_channel(VecDeque::from([Ok(())]), 2);
    let gateway_credential =
        token_credential("discord", "gateway.discord.gg", "discord-gateway-secret");
    establish_discord_session(&mut channel, &gateway_credential);
    let sent_before = gateway.borrow().len();

    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":1,"t":null,"s":null,"d":null}"#,
            Duration::from_millis(100),
            &gateway_credential,
            &mut (),
        ),
        Ok(DiscordPacketOutcome::Ignored)
    );
    assert_eq!(gateway.borrow().len(), sent_before + 1);
    assert_eq!(
        gateway.borrow().last(),
        Some(&GatewayRecord {
            opcode: 1,
            token: None,
            intents: None,
            session_id: None,
            sequence: Some(41),
        })
    );
}

#[test]
fn discord_nonresumable_invalid_session_falls_back_to_identify() {
    let DiscordHarness {
        mut channel,
        open_urls,
        gateway,
        ..
    } = discord_channel(VecDeque::from([Ok(()), Ok(())]), 2);
    let gateway_credential =
        token_credential("discord", "gateway.discord.gg", "discord-gateway-secret");
    establish_discord_session(&mut channel, &gateway_credential);

    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":9,"t":null,"s":null,"d":false}"#,
            Duration::from_secs(1),
            &gateway_credential,
            &mut (),
        ),
        Ok(DiscordPacketOutcome::ReconnectRequested)
    );
    assert_eq!(channel.session_id(), None);
    assert_eq!(channel.sequence(), None);
    assert_eq!(channel.resume_gateway_url(), None);
    assert_eq!(channel.tick(Duration::from_secs(4), &mut ()), Ok(true));
    assert_eq!(
        open_urls.borrow().last().map(String::as_str),
        Some("wss://gateway.discord.gg/?v=10&encoding=json")
    );
    channel.gateway_opened(&mut ()).expect("reopened socket");
    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
            Duration::from_secs(4),
            &gateway_credential,
            &mut (),
        ),
        Ok(DiscordPacketOutcome::Identified)
    );
    assert_eq!(gateway.borrow().last().map(|record| record.opcode), Some(2));
}

#[test]
fn discord_close_codes_preserve_invalidate_or_terminate_sessions() {
    let gateway_credential =
        token_credential("discord", "gateway.discord.gg", "discord-gateway-secret");

    let DiscordHarness {
        mut channel,
        open_urls,
        ..
    } = discord_channel(VecDeque::from([Ok(()), Ok(())]), 2);
    establish_discord_session(&mut channel, &gateway_credential);
    assert_eq!(
        channel.gateway_closed_with(
            Duration::from_secs(1),
            DiscordGatewayClose::websocket(4000, "transient"),
            &mut (),
        ),
        Ok(true)
    );
    assert_eq!(channel.last_close().code(), Some(4000));
    assert_eq!(channel.last_close().reason(), "transient");
    assert_eq!(channel.session_id(), Some("resumable-session"));
    assert_eq!(channel.tick(Duration::from_secs(4), &mut ()), Ok(true));
    assert_eq!(
        open_urls.borrow().last().map(String::as_str),
        Some("wss://gateway-us-east1-b.discord.gg?v=10&encoding=json")
    );

    for code in [4003, 4005, 4007, 4009] {
        let DiscordHarness {
            mut channel,
            open_urls,
            ..
        } = discord_channel(VecDeque::from([Ok(()), Ok(())]), 2);
        establish_discord_session(&mut channel, &gateway_credential);
        assert_eq!(
            channel.gateway_closed_with(
                Duration::from_secs(1),
                DiscordGatewayClose::websocket(code, "session invalid"),
                &mut (),
            ),
            Ok(true)
        );
        assert_eq!(channel.session_id(), None, "close code {code}");
        assert_eq!(channel.sequence(), None, "close code {code}");
        assert_eq!(channel.resume_gateway_url(), None, "close code {code}");
        assert_eq!(channel.tick(Duration::from_secs(4), &mut ()), Ok(true));
        assert_eq!(
            open_urls.borrow().last().map(String::as_str),
            Some("wss://gateway.discord.gg/?v=10&encoding=json"),
            "close code {code}"
        );
    }

    for (code, expected) in [
        (4004, ChannelError::Authentication),
        (
            4010,
            ChannelError::Configuration(ConfigurationError::InvalidAdapterConfiguration),
        ),
        (
            4011,
            ChannelError::Configuration(ConfigurationError::InvalidAdapterConfiguration),
        ),
        (
            4012,
            ChannelError::Configuration(ConfigurationError::InvalidAdapterConfiguration),
        ),
        (
            4013,
            ChannelError::Configuration(ConfigurationError::InvalidAdapterConfiguration),
        ),
        (
            4014,
            ChannelError::Configuration(ConfigurationError::InvalidAdapterConfiguration),
        ),
    ] {
        let DiscordHarness { mut channel, .. } = discord_channel(VecDeque::from([Ok(())]), 2);
        establish_discord_session(&mut channel, &gateway_credential);
        assert_eq!(
            channel.gateway_closed_with(
                Duration::from_secs(1),
                DiscordGatewayClose::websocket(code, "terminal"),
                &mut (),
            ),
            Err(expected),
            "close code {code}"
        );
        assert_eq!(
            channel.state(),
            ConnectionState::Closed,
            "close code {code}"
        );
        assert_eq!(
            channel.phase(),
            DiscordGatewayPhase::ReconnectExhausted,
            "close code {code}"
        );
        assert_eq!(channel.session_id(), None, "close code {code}");
        assert_eq!(channel.resume_gateway_url(), None, "close code {code}");
    }
}

#[test]
fn discord_rejects_untrusted_ready_resume_gateway_urls() {
    let DiscordHarness { mut channel, .. } = discord_channel(VecDeque::from([Ok(())]), 2);
    let gateway_credential =
        token_credential("discord", "gateway.discord.gg", "discord-gateway-secret");
    channel
        .start(Duration::ZERO, &mut ())
        .expect("opening started");
    channel.gateway_opened(&mut ()).expect("socket opened");
    channel
        .handle_gateway_packet(
            br#"{"op":10,"t":null,"s":null,"d":{"heartbeat_interval":1000}}"#,
            Duration::ZERO,
            &gateway_credential,
            &mut (),
        )
        .expect("identified");

    assert_eq!(
        channel.handle_gateway_packet(
            br#"{"op":0,"t":"READY","s":1,"d":{"session_id":"session","resume_gateway_url":"wss://discord.gg.evil.test"}}"#,
            Duration::ZERO,
            &gateway_credential,
            &mut (),
        ),
        Ok(DiscordPacketOutcome::Malformed)
    );
    assert_eq!(channel.state(), ConnectionState::Connecting);
    assert_eq!(channel.session_id(), None);
}

struct WhatsAppFixture {
    responses: VecDeque<Result<u16, ChannelError>>,
    sent: Rc<RefCell<Vec<String>>>,
    debug: Rc<RefCell<Vec<String>>>,
}

impl WhatsAppTransport for WhatsAppFixture {
    fn send_text(
        &mut self,
        request: &WhatsAppSendRequest<'_>,
    ) -> Result<ProviderResponse, WhatsAppSendError> {
        assert_eq!(request.access_token(), "whatsapp-secret");
        assert_eq!(request.phone_number_id(), "phone-id");
        assert_eq!(request.to(), "15550001");
        assert_eq!(request.messaging_product(), "whatsapp");
        assert_eq!(request.api_version(), 20);
        assert_eq!(request.request_timeout(), Duration::from_secs(10));
        self.debug.borrow_mut().push(format!("{request:?}"));
        let mut sent = self.sent.borrow_mut();
        sent.push(request.text().to_owned());
        let status = self
            .responses
            .pop_front()
            .unwrap_or(Ok(200))
            .map_err(|error| {
                if matches!(
                    &error,
                    ChannelError::Transport(TransportErrorKind::Timeout | TransportErrorKind::Io,)
                        | ChannelError::Protocol(_)
                ) {
                    WhatsAppSendError::AmbiguousAfterSend(error)
                } else {
                    WhatsAppSendError::FailedBeforeSend(error)
                }
            })?;
        Ok(ProviderResponse::new(
            status,
            format!(r#"{{"messages":[{{"id":"whatsapp-{}"}}]}}"#, sent.len()),
        ))
    }
}

struct WhatsAppHarness {
    channel: WhatsAppChannel<WhatsAppFixture, FixedClock>,
    sent: Rc<RefCell<Vec<String>>>,
    debug: Rc<RefCell<Vec<String>>>,
}

fn whatsapp_channel(
    capacity: usize,
    responses: VecDeque<Result<u16, ChannelError>>,
) -> WhatsAppHarness {
    let sent = Rc::new(RefCell::new(Vec::new()));
    let debug = Rc::new(RefCell::new(Vec::new()));
    let channel = WhatsAppChannel::new(
        ACCOUNT,
        "phone-id",
        approved_origin("whatsapp", "graph.facebook.com"),
        WhatsAppFixture {
            responses,
            sent: Rc::clone(&sent),
            debug: Rc::clone(&debug),
        },
        FixedClock(789),
        NonZeroUsize::new(capacity).expect("non-zero capacity"),
    )
    .expect("WhatsApp adapter");
    WhatsAppHarness {
        channel,
        sent,
        debug,
    }
}

#[test]
fn whatsapp_verifies_challenges_normalizes_webhooks_and_waits_for_sends() {
    let WhatsAppHarness {
        mut channel,
        sent,
        debug,
    } = whatsapp_channel(1, VecDeque::new());
    let verification = local_credential(CredentialKind::WebhookSecret, "verify-secret");
    let access = token_credential("whatsapp", "graph.facebook.com", "whatsapp-secret");
    let mut diagnostics = Diagnostics::default();
    channel.start(&mut diagnostics).expect("started");

    let query = WhatsAppVerificationQuery {
        mode: Some("subscribe"),
        verify_token: Some("verify-secret"),
        challenge: Some("challenge-1"),
    };
    assert!(!format!("{query:?}").contains("verify-secret"));
    assert_eq!(
        channel.verify_webhook(&query, &verification, &mut diagnostics),
        Ok(WhatsAppVerificationResponse::Accepted("challenge-1"))
    );
    let accepted = WhatsAppVerificationResponse::Accepted("challenge-1");
    assert_eq!(accepted.status(), 200);
    assert_eq!(accepted.content_type(), "text/plain");
    assert_eq!(accepted.body(), "challenge-1");
    assert_eq!(
        channel.verify_webhook(
            &WhatsAppVerificationQuery {
                mode: Some("subscribe"),
                verify_token: Some("wrong"),
                challenge: Some("challenge-1"),
            },
            &verification,
            &mut diagnostics,
        ),
        Ok(WhatsAppVerificationResponse::Forbidden)
    );
    assert_eq!(WhatsAppVerificationResponse::Forbidden.status(), 403);
    assert_eq!(
        WhatsAppVerificationResponse::Forbidden.body(),
        r#"{"error":"Forbidden"}"#
    );
    assert_eq!(
        channel.verify_webhook(
            &WhatsAppVerificationQuery {
                mode: Some("subscribe"),
                verify_token: Some("verify-secret"),
                challenge: Some("challenge-1"),
            },
            &local_credential(CredentialKind::Password, "verify-secret"),
            &mut diagnostics,
        ),
        Err(ChannelError::CredentialBinding(
            CredentialBindingError::ScopeMismatch
        ))
    );

    let payload = br#"{
      "entry":[{
        "changes":[{
          "value":{"metadata":{"phone_number_id":"phone-id"},"messages":[
            {"from":"15550002","id":"image","timestamp":"1","type":"image"},
            {"from":"phone-id","id":"self","timestamp":"2","type":"text","text":{"body":"loop"}},
            {"from":"15550003","id":"blank","timestamp":"3","type":"text","text":{"body":"   "}},
            {"from":"15550001","id":"one","timestamp":"4","type":"text","text":{"body":" hello "}},
            {"from":"15550004","id":"two","timestamp":"5","type":"text","text":{"body":"overflow"}}
          ]}
        }]
      }]
    }"#;
    let stats = channel
        .ingest_webhook(payload, &mut diagnostics)
        .expect("valid webhook");
    assert_eq!(stats.messages, 5);
    assert_eq!(stats.queued, 1);
    assert_eq!(stats.ignored, 3);
    assert_eq!(stats.dropped, 1);
    let inbound = channel
        .poll_inbound()
        .expect("running")
        .expect("queued message");
    assert_eq!(inbound.conversation_id, "whatsapp:15550001");
    assert_eq!(inbound.sender_id, "15550001");
    assert_eq!(inbound.text.as_deref(), Some("hello"));
    assert_eq!(inbound.received_at_unix_ms, 4_000);

    let handled = channel.handle_webhook(
        br#"{"entry":[{"changes":[{"value":{"metadata":{"phone_number_id":"phone-id"},"messages":[{"from":"15550001","id":"reply","type":"text","text":{"body":"question"}}]}}]}]}"#,
        &access,
        |message| {
            assert_eq!(message.text.as_deref(), Some("question"));
            Ok(Some("reply".to_owned()))
        },
        &mut diagnostics,
    );
    let handling = handled.as_ref().expect("handled webhook");
    assert_eq!(handling.ingestion.queued, 1);
    assert_eq!(handling.processed, 1);
    assert_eq!(
        WhatsAppWebhookResponse::for_result(&handled),
        WhatsAppWebhookResponse::Accepted
    );
    assert_eq!(sent.borrow().as_slice(), ["reply"]);
    assert!(
        debug
            .borrow()
            .iter()
            .all(|rendered| !rendered.contains("whatsapp-secret"))
    );
    assert_eq!(WhatsAppWebhookResponse::Accepted.status(), 200);
    assert_eq!(WhatsAppWebhookResponse::Accepted.body(), r#"{"ok":true}"#);
    assert_eq!(WhatsAppWebhookResponse::Failed.status(), 500);

    assert_eq!(channel.stop(&mut diagnostics), Ok(true));
    assert_eq!(channel.stop(&mut diagnostics), Ok(false));
    assert_eq!(
        channel.ingest_webhook(b"{}", &mut diagnostics),
        Err(ChannelError::NotConnected {
            state: ConnectionState::Closed
        })
    );
}

#[test]
fn whatsapp_app_secret_hmac_covers_the_exact_request_bytes() {
    let payload = br#"{"entry":[]}"#;
    let signature = "sha256=fe6aaed5aff30b5679e782271914a2287bdd7de6bedb495c95c24ad91e5e3fdb";
    let app_secret = local_credential(CredentialKind::WebhookSecret, "app-secret");

    assert_eq!(
        verify_whatsapp_webhook_signature(ACCOUNT, payload, signature, &app_secret),
        Ok(true)
    );
    assert_eq!(
        verify_whatsapp_webhook_signature(ACCOUNT, b"{\"entry\":[ ]}", signature, &app_secret),
        Ok(false)
    );
    assert_eq!(
        verify_whatsapp_webhook_signature(ACCOUNT, payload, "sha256=not-hex", &app_secret),
        Ok(false)
    );
    assert_eq!(
        verify_whatsapp_webhook_signature(
            ACCOUNT,
            payload,
            signature,
            &local_credential(CredentialKind::Password, "app-secret"),
        ),
        Err(ChannelError::CredentialBinding(
            CredentialBindingError::ScopeMismatch
        ))
    );
}

#[test]
fn whatsapp_redelivery_skips_completed_messages_and_resumes_failed_reply() {
    let WhatsAppHarness {
        mut channel, sent, ..
    } = whatsapp_channel(2, VecDeque::from([Ok(200), Ok(500), Ok(200)]));
    let access = token_credential("whatsapp", "graph.facebook.com", "whatsapp-secret");
    channel.start(&mut ()).expect("started");
    let callback_calls = RefCell::new(Vec::new());
    let payload =
        br#"{"entry":[{"changes":[{"value":{"metadata":{"phone_number_id":"phone-id"},"messages":[
        {"from":"15550001","id":"one","type":"text","text":{"body":"first"}},
        {"from":"15550001","id":"two","type":"text","text":{"body":"second"}}
    ]}}]}]}"#;
    let handled = channel.handle_webhook(
        payload,
        &access,
        |message| {
            callback_calls.borrow_mut().push(message.id.clone());
            Ok(Some(format!("reply-{}", message.id)))
        },
        &mut (),
    );
    assert_eq!(handled, Err(ChannelError::RemoteRejected { status: 500 }));
    assert_eq!(
        WhatsAppWebhookResponse::for_result(&handled),
        WhatsAppWebhookResponse::Failed
    );
    assert_eq!(sent.borrow().len(), 2);
    assert_eq!(sent.borrow().as_slice(), ["reply-one", "reply-two"]);

    let resumed = channel.handle_webhook(
        payload,
        &access,
        |_| panic!("a checkpointed reply must not rerun the conversation"),
        &mut (),
    );
    assert_eq!(
        WhatsAppWebhookResponse::for_result(&resumed),
        WhatsAppWebhookResponse::Accepted
    );
    assert_eq!(resumed.expect("resumed webhook").processed, 1);
    assert_eq!(callback_calls.borrow().as_slice(), ["one", "two"]);
    assert_eq!(
        sent.borrow().as_slice(),
        ["reply-one", "reply-two", "reply-two"]
    );

    let duplicate = channel.handle_webhook(
        payload,
        &access,
        |_| panic!("a completed message must not run twice"),
        &mut (),
    );
    let duplicate = duplicate.expect("duplicate acknowledged");
    assert_eq!(duplicate.ingestion.ignored, 2);
    assert_eq!(duplicate.processed, 0);
    assert_eq!(sent.borrow().len(), 3);
}

#[test]
fn whatsapp_capacity_one_retains_a_four_message_batch_after_acknowledgement() {
    let WhatsAppHarness {
        mut channel, sent, ..
    } = whatsapp_channel(1, VecDeque::new());
    let access = token_credential("whatsapp", "graph.facebook.com", "whatsapp-secret");
    let payload =
        br#"{"entry":[{"changes":[{"value":{"metadata":{"phone_number_id":"phone-id"},"messages":[
        {"from":"15550001","id":"a","type":"text","text":{"body":"first"}},
        {"from":"15550001","id":"b","type":"text","text":{"body":"second"}},
        {"from":"15550001","id":"c","type":"text","text":{"body":"third"}},
        {"from":"15550001","id":"d","type":"text","text":{"body":"fourth"}}
    ]}}]}]}"#;
    let processed = RefCell::new(Vec::new());
    channel.start(&mut ()).expect("started");
    let mut process = |message: &InboundMessage| {
        processed.borrow_mut().push(message.id.clone());
        Ok(Some(format!("reply-{}", message.id)))
    };

    for expected in ["a", "b", "c"] {
        assert_eq!(
            channel.handle_webhook(payload, &access, &mut process, &mut ()),
            Err(ChannelError::RateLimited {
                retry_after: Duration::from_secs(1)
            })
        );
        assert_eq!(
            processed.borrow().last().map(String::as_str),
            Some(expected)
        );
    }

    let acknowledged = channel
        .handle_webhook(payload, &access, &mut process, &mut ())
        .expect("fourth delivery completes the batch");
    assert_eq!(acknowledged.ingestion.ignored, 3);
    assert_eq!(acknowledged.processed, 1);
    assert_eq!(processed.borrow().as_slice(), ["a", "b", "c", "d"]);
    assert_eq!(
        sent.borrow().as_slice(),
        ["reply-a", "reply-b", "reply-c", "reply-d"]
    );

    let duplicate = channel
        .handle_webhook(
            payload,
            &access,
            |_| panic!("an acknowledged message must not be processed again"),
            &mut (),
        )
        .expect("completed batch redelivery is acknowledged");
    assert_eq!(duplicate.ingestion.ignored, 4);
    assert_eq!(duplicate.processed, 0);
    assert_eq!(processed.borrow().as_slice(), ["a", "b", "c", "d"]);
    assert_eq!(
        sent.borrow().as_slice(),
        ["reply-a", "reply-b", "reply-c", "reply-d"]
    );
}

#[test]
fn whatsapp_rejects_webhooks_over_the_message_bound_before_queueing() {
    let WhatsAppHarness { mut channel, .. } = whatsapp_channel(1, VecDeque::new());
    channel.start(&mut ()).expect("started");
    let messages = (0..=WHATSAPP_MAX_MESSAGES_PER_WEBHOOK)
        .map(|index| {
            format!(
                r#"{{"from":"15550001","id":"message-{index}","type":"text","text":{{"body":"text"}}}}"#
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let payload = format!(
        r#"{{"entry":[{{"changes":[{{"value":{{"metadata":{{"phone_number_id":"phone-id"}},"messages":[{messages}]}}}}]}}]}}"#
    );

    assert_eq!(
        channel.ingest_webhook(payload.as_bytes(), &mut ()),
        Err(ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge))
    );
    assert_eq!(channel.queued_inbound(), 0);
}

#[test]
fn whatsapp_connection_failure_retries_the_unsent_checkpoint() {
    let WhatsAppHarness {
        mut channel, sent, ..
    } = whatsapp_channel(
        1,
        VecDeque::from([
            Err(ChannelError::Transport(TransportErrorKind::Connection)),
            Ok(200),
        ]),
    );
    let access = token_credential("whatsapp", "graph.facebook.com", "whatsapp-secret");
    let payload =
        br#"{"entry":[{"changes":[{"value":{"metadata":{"phone_number_id":"phone-id"},"messages":[
        {"from":"15550001","id":"one","type":"text","text":{"body":"question"}}
    ]}}]}]}"#;
    let callback_calls = Cell::new(0);
    channel.start(&mut ()).expect("started");

    assert_eq!(
        channel.handle_webhook(
            payload,
            &access,
            |_| {
                callback_calls.set(callback_calls.get() + 1);
                Ok(Some("reply".to_owned()))
            },
            &mut (),
        ),
        Err(ChannelError::Transport(TransportErrorKind::Connection))
    );
    assert_eq!(
        channel
            .handle_webhook(
                payload,
                &access,
                |_| panic!("checkpoint retry must not rerun the conversation"),
                &mut (),
            )
            .expect("redelivery completed")
            .processed,
        1
    );
    assert_eq!(callback_calls.get(), 1);
    assert_eq!(sent.borrow().as_slice(), ["reply", "reply"]);
}

#[test]
fn whatsapp_rejects_messages_for_another_configured_phone() {
    let WhatsAppHarness { mut channel, .. } = whatsapp_channel(1, VecDeque::new());
    channel.start(&mut ()).expect("started");
    let payload = br#"{"entry":[{"changes":[
        {"value":{
            "metadata":{"phone_number_id":"phone-id"},
            "messages":[{"from":"15550001","id":"safe","type":"text","text":{"body":"must not queue"}}]
        }},
        {"value":{
            "metadata":{"phone_number_id":"other-phone"},
            "messages":[{"from":"15550001","id":"one","type":"text","text":{"body":"question"}}]
        }}
    ]}]}"#;

    assert_eq!(
        channel.ingest_webhook(payload, &mut ()),
        Err(ChannelError::Protocol(ProtocolErrorKind::InvalidField))
    );
    assert_eq!(channel.queued_inbound(), 0);
}

#[test]
fn whatsapp_pending_a_does_not_livelock_b_or_repeat_processing() {
    let WhatsAppHarness {
        mut channel, sent, ..
    } = whatsapp_channel(1, VecDeque::from([Ok(500), Ok(200), Ok(500), Ok(200)]));
    let access = token_credential("whatsapp", "graph.facebook.com", "whatsapp-secret");
    let payload = br#"{"entry":[{"changes":[{"value":{
        "metadata":{"phone_number_id":"phone-id"},
        "messages":[
            {"from":"15550001","id":"a","type":"text","text":{"body":"first"}},
            {"from":"15550001","id":"b","type":"text","text":{"body":"second"}}
        ]
    }}]}]}"#;
    let processed = RefCell::new(Vec::new());
    channel.start(&mut ()).expect("started");
    let mut process = |message: &InboundMessage| {
        processed.borrow_mut().push(message.id.clone());
        Ok(Some(format!("reply-{}", message.id)))
    };

    assert_eq!(
        channel.handle_webhook(payload, &access, &mut process, &mut ()),
        Err(ChannelError::RemoteRejected { status: 500 })
    );
    assert_eq!(processed.borrow().as_slice(), ["a"]);

    assert_eq!(
        channel.handle_webhook(payload, &access, &mut process, &mut ()),
        Err(ChannelError::RemoteRejected { status: 500 })
    );
    assert_eq!(
        processed.borrow().as_slice(),
        ["a", "b"],
        "a pending reply must not consume b's redelivery slot"
    );

    let completed = channel
        .handle_webhook(payload, &access, &mut process, &mut ())
        .expect("remaining checkpoint completes");
    assert_eq!(completed.processed, 1);
    assert_eq!(processed.borrow().as_slice(), ["a", "b"]);
    assert_eq!(
        sent.borrow().as_slice(),
        ["reply-a", "reply-b", "reply-a", "reply-a"]
    );
}

#[derive(Default)]
struct Engine {
    reply: String,
    fail: bool,
    calls: Vec<(String, String)>,
}

impl ConversationService for Engine {
    type Error = ();

    fn chat(&mut self, conversation_id: &str, text: &str) -> Result<String, Self::Error> {
        self.calls
            .push((conversation_id.to_owned(), text.to_owned()));
        if self.fail {
            Err(())
        } else {
            Ok(self.reply.clone())
        }
    }
}

fn teams_handler(capacity: usize) -> TeamsActivityHandler {
    TeamsActivityHandler::new(
        ACCOUNT,
        "bot-id",
        Some("clawbot".to_owned()),
        NonZeroUsize::new(capacity).expect("non-zero capacity"),
    )
    .expect("Teams handler")
}

fn teams_message(kind: &str, text: &str, conversation: bool, bot: bool) -> Vec<u8> {
    let conversation = if conversation {
        r#","conversation":{"id":"teams-room"}"#
    } else {
        ""
    };
    format!(
        r#"{{"type":"{kind}","text":{text:?},"from":{{"id":"{}","role":"{}"}},"recipient":{{"id":"bot-id"}}{conversation}}}"#,
        if bot { "bot-id" } else { "user-id" },
        if bot { "bot" } else { "user" },
    )
    .into_bytes()
}

#[test]
fn teams_activity_handler_preserves_auth_typing_edit_greeting_and_queue_contracts() {
    let mut handler = teams_handler(10);
    let mut diagnostics = Diagnostics::default();
    assert_eq!(handler.start(&mut diagnostics), Ok(true));

    assert_eq!(
        handler.handle_activity::<Engine>(
            &teams_message("message", "hello", true, false),
            None,
            AuthenticationPrompt::Unconfigured,
            &mut diagnostics,
        ),
        Ok(TeamsActivityOutcome::ActionsQueued { count: 1 })
    );
    assert_eq!(
        handler.poll_action(),
        Ok(Some(TeamsAction::Reply(
            "GTA-Claw is not authenticated yet. No active GitHub token is configured.".to_owned()
        )))
    );

    assert_eq!(
        handler
            .handle_activity::<Engine>(
                &teams_message("message", "/help", true, false),
                None,
                AuthenticationPrompt::Unconfigured,
                &mut diagnostics,
            )
            .expect("help"),
        TeamsActivityOutcome::ActionsQueued { count: 1 }
    );
    let TeamsAction::Reply(help) = handler
        .poll_action()
        .expect("running")
        .expect("help action")
    else {
        panic!("help must be a reply");
    };
    assert!(help.contains("/help - "));

    let mut engine = Engine {
        reply: "answer".to_owned(),
        ..Engine::default()
    };
    assert_eq!(
        handler.handle_activity(
            &teams_message("message", " question ", true, false),
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            &mut diagnostics,
        ),
        Ok(TeamsActivityOutcome::ActionsQueued { count: 2 })
    );
    assert_eq!(handler.poll_action(), Ok(Some(TeamsAction::Typing)));
    assert_eq!(
        handler.poll_action(),
        Ok(Some(TeamsAction::Reply("answer".to_owned())))
    );
    assert_eq!(
        engine.calls,
        [("teams-room".to_owned(), "question".to_owned())]
    );

    engine.reply = "edited".to_owned();
    assert_eq!(
        handler.handle_activity(
            &teams_message("messageUpdate", "edit", true, false),
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            &mut diagnostics,
        ),
        Ok(TeamsActivityOutcome::ActionsQueued { count: 2 })
    );
    assert_eq!(handler.poll_action(), Ok(Some(TeamsAction::Typing)));
    assert_eq!(
        handler.poll_action(),
        Ok(Some(TeamsAction::Reply("edited".to_owned())))
    );
    assert_eq!(
        handler.handle_activity(
            &teams_message("message", "loop", true, true),
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            &mut diagnostics,
        ),
        Ok(TeamsActivityOutcome::Ignored)
    );
    assert_eq!(
        handler.handle_activity(
            &teams_message("message", "missing", false, false),
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            &mut diagnostics,
        ),
        Ok(TeamsActivityOutcome::Ignored)
    );

    assert_eq!(
        handler.handle_activity::<Engine>(
            br#"{"type":"conversationUpdate","conversation":{"id":"teams-room"},"recipient":{"id":"bot-id"},"membersAdded":[{"id":"bot-id"},{"id":"new-user","role":"user"},{"id":"other-bot","role":"bot"}]}"#,
            None,
            AuthenticationPrompt::Unconfigured,
            &mut diagnostics,
        ),
        Ok(TeamsActivityOutcome::ActionsQueued { count: 1 })
    );
    assert_eq!(
        handler.poll_action(),
        Ok(Some(TeamsAction::Reply(TEAMS_GREETING.to_owned())))
    );

    engine.fail = true;
    assert_eq!(
        handler.handle_activity(
            &teams_message("message", "fail", true, false),
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            &mut diagnostics,
        ),
        Ok(TeamsActivityOutcome::ActionsQueued { count: 2 })
    );
    assert_eq!(handler.poll_action(), Ok(Some(TeamsAction::Typing)));
    assert_eq!(
        handler.poll_action(),
        Ok(Some(TeamsAction::Reply(TEAMS_FAILURE_REPLY.to_owned())))
    );
    assert!(diagnostics.0.contains(&DiagnosticCode::BotMessageIgnored));
    assert!(diagnostics.0.contains(&DiagnosticCode::MissingConversation));
    assert!(diagnostics.0.contains(&DiagnosticCode::ConversationFailed));

    assert_eq!(handler.stop(&mut diagnostics), Ok(true));
    assert_eq!(handler.stop(&mut diagnostics), Ok(false));
    assert_eq!(
        handler.poll_action(),
        Err(ChannelError::NotConnected {
            state: ConnectionState::Closed
        })
    );
}

#[test]
fn teams_action_queue_is_transactional_and_runtime_commands_are_deferred() {
    let mut handler = teams_handler(1);
    handler.start(&mut ()).expect("started");
    let mut engine = Engine {
        reply: "reply".to_owned(),
        ..Engine::default()
    };
    assert_eq!(
        handler.handle_activity(
            &teams_message("message", "hello", true, false),
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            &mut (),
        ),
        Err(TeamsActivityError::ActionQueueFull)
    );
    assert_eq!(handler.queued_actions(), 0);

    assert!(matches!(
        handler.handle_activity(
            &teams_message("message", "/reset", true, false),
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            &mut (),
        ),
        Ok(TeamsActivityOutcome::DeferredCommand(_))
    ));
    assert_eq!(handler.queued_actions(), 0);
}

#[test]
fn teams_strips_the_recipient_mention_before_command_routing() {
    let mut handler = teams_handler(2);
    handler.start(&mut ()).expect("started");
    let mut engine = Engine {
        reply: "must not run".to_owned(),
        ..Engine::default()
    };
    let payload = br#"{
        "type":"message",
        "text":"<at>GTA-Claw</at> /reset",
        "from":{"id":"user-id","role":"user"},
        "recipient":{"id":"bot-id"},
        "conversation":{"id":"teams-room"},
        "entities":[{
            "type":"mention",
            "text":"<at>GTA-Claw</at>",
            "mentioned":{"id":"bot-id","name":"GTA-Claw"}
        }]
    }"#;

    assert!(matches!(
        handler.handle_activity(
            payload,
            Some(&mut engine),
            AuthenticationPrompt::Unconfigured,
            &mut (),
        ),
        Ok(TeamsActivityOutcome::DeferredCommand(_))
    ));
    assert!(engine.calls.is_empty());
    assert_eq!(handler.queued_actions(), 0);
}

#[test]
fn stable_failure_constants_do_not_drift() {
    assert_eq!(
        COMMON_FAILURE_REPLY,
        "Sorry, an error occurred while processing your message. Please try again."
    );
    assert_eq!(
        TEAMS_FAILURE_REPLY,
        "I'm sorry, an error occurred while processing your message. Please try again."
    );
    assert_eq!(ReplySource::Failure, ReplySource::Failure);
    assert_eq!(
        ChannelError::Protocol(ProtocolErrorKind::PayloadTooLarge).to_string(),
        "channel protocol failed: PayloadTooLarge"
    );
}

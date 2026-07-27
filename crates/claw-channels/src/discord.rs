//! Discord Gateway lifecycle and REST reply compatibility adapter.

use std::fmt::{self, Debug, Formatter};
use std::num::{NonZeroU32, NonZeroUsize};
use std::time::Duration;

use claw_channel_sdk::{
    ApprovedOrigin, Channel, ChannelCredential, ChannelError, ConfigurationError, ConnectionState,
    ConnectionStateMachine, CredentialBindingError, CredentialKind, DeliveryAcknowledgement,
    DeliveryState, InboundMessage, InvalidMessageReason, LifecycleEvent, OutboundMessage,
    OutboundRetrySafety, ProtocolErrorKind, SecretStoreError, UnsupportedOperation,
};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::bounded::BoundedQueue;
use crate::diagnostics::{DiagnosticCode, DiagnosticLevel, DiagnosticSink, OperatorDiagnostic};
use crate::transport::{MAX_PROVIDER_RESPONSE_BYTES, ProviderResponse, require_official_origin};
use crate::{UnixClock, invalid_routing_identifier, segment_outbound_text};

/// Delay before a disconnected gateway reconnects.
pub const DISCORD_RECONNECT_DELAY: Duration = Duration::from_secs(3);

/// Client-side timeout for one Discord REST message request.
pub const DISCORD_SEND_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Browser and device label sent in Discord IDENTIFY.
pub const DISCORD_CLIENT_LABEL: &str = "gta-claw";

/// Discord Gateway protocol phase inside an open connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DiscordGatewayPhase {
    /// No protocol handshake is active.
    #[default]
    Idle,
    /// The socket opened and the adapter is waiting for HELLO.
    AwaitingHello,
    /// IDENTIFY was sent and READY has not arrived.
    Identifying,
    /// READY established a usable Discord session.
    Ready,
    /// No more automatic reconnect attempts remain.
    ReconnectExhausted,
}

/// Result of handling one Gateway packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscordPacketOutcome {
    /// Packet was malformed and safely contained.
    Malformed,
    /// Packet was valid but required no state or message action.
    Ignored,
    /// HELLO configured heartbeat and sent IDENTIFY.
    Identified,
    /// READY established a session.
    Ready,
    /// A user message was queued for dispatch.
    MessageQueued,
    /// A user message was dropped because the bounded queue was full.
    MessageDropped,
    /// Discord requested a reconnect.
    ReconnectRequested,
    /// A heartbeat acknowledgement was recorded.
    HeartbeatAcknowledged,
}

enum DiscordGatewayRequestKind<'a> {
    Identify {
        bot_token: &'a str,
        intents: u64,
        platform: &'static str,
    },
    Heartbeat {
        sequence: Option<i64>,
    },
}

/// Borrowed Discord Gateway control request.
pub struct DiscordGatewayRequest<'a> {
    kind: DiscordGatewayRequestKind<'a>,
}

impl DiscordGatewayRequest<'_> {
    /// Returns the Discord Gateway opcode.
    #[must_use]
    pub const fn opcode(&self) -> u8 {
        match self.kind {
            DiscordGatewayRequestKind::Identify { .. } => 2,
            DiscordGatewayRequestKind::Heartbeat { .. } => 1,
        }
    }

    /// Returns the bot token for IDENTIFY.
    ///
    /// Implementations must not log, persist, or include it in errors.
    #[must_use]
    pub const fn bot_token(&self) -> Option<&str> {
        match self.kind {
            DiscordGatewayRequestKind::Identify { bot_token, .. } => Some(bot_token),
            DiscordGatewayRequestKind::Heartbeat { .. } => None,
        }
    }

    /// Returns configured Gateway intents for IDENTIFY.
    #[must_use]
    pub const fn intents(&self) -> Option<u64> {
        match self.kind {
            DiscordGatewayRequestKind::Identify { intents, .. } => Some(intents),
            DiscordGatewayRequestKind::Heartbeat { .. } => None,
        }
    }

    /// Returns the process platform for IDENTIFY.
    #[must_use]
    pub const fn platform(&self) -> Option<&str> {
        match self.kind {
            DiscordGatewayRequestKind::Identify { platform, .. } => Some(platform),
            DiscordGatewayRequestKind::Heartbeat { .. } => None,
        }
    }

    /// Returns the fixed IDENTIFY browser and device label.
    #[must_use]
    pub const fn client_label(&self) -> Option<&str> {
        match self.kind {
            DiscordGatewayRequestKind::Identify { .. } => Some(DISCORD_CLIENT_LABEL),
            DiscordGatewayRequestKind::Heartbeat { .. } => None,
        }
    }

    /// Returns the last Gateway sequence for a heartbeat.
    #[must_use]
    pub const fn sequence(&self) -> Option<i64> {
        match self.kind {
            DiscordGatewayRequestKind::Heartbeat { sequence } => sequence,
            DiscordGatewayRequestKind::Identify { .. } => None,
        }
    }
}

impl Debug for DiscordGatewayRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self.kind {
            DiscordGatewayRequestKind::Identify {
                intents, platform, ..
            } => formatter
                .debug_struct("DiscordGatewayRequest")
                .field("opcode", &2)
                .field("bot_token", &"[REDACTED]")
                .field("intents", &intents)
                .field("platform", &platform)
                .field("browser", &DISCORD_CLIENT_LABEL)
                .field("device", &DISCORD_CLIENT_LABEL)
                .finish(),
            DiscordGatewayRequestKind::Heartbeat { sequence } => formatter
                .debug_struct("DiscordGatewayRequest")
                .field("opcode", &1)
                .field("sequence", &sequence)
                .finish(),
        }
    }
}

/// Borrowed Discord REST message request.
pub struct DiscordCreateMessageRequest<'a> {
    bot_token: &'a str,
    channel_id: &'a str,
    content: &'a str,
}

impl DiscordCreateMessageRequest<'_> {
    /// Returns the bot token for the Authorization header.
    ///
    /// Implementations must prefix it with `Bot ` and must not log or persist it.
    #[must_use]
    pub const fn bot_token(&self) -> &str {
        self.bot_token
    }

    /// Returns the Discord channel receiving the message.
    #[must_use]
    pub const fn channel_id(&self) -> &str {
        self.channel_id
    }

    /// Returns one already-bounded message chunk.
    #[must_use]
    pub const fn content(&self) -> &str {
        self.content
    }

    /// Returns the Discord REST API version.
    #[must_use]
    pub const fn api_version(&self) -> u8 {
        10
    }

    /// Returns the client-side request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        DISCORD_SEND_REQUEST_TIMEOUT
    }
}

impl Debug for DiscordCreateMessageRequest<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscordCreateMessageRequest")
            .field("bot_token", &"[REDACTED]")
            .field("channel_id", &self.channel_id)
            .field(
                "content",
                &format_args!("[REDACTED; {} bytes]", self.content.len()),
            )
            .field("api_version", &10)
            .field("request_timeout", &DISCORD_SEND_REQUEST_TIMEOUT)
            .finish()
    }
}

/// Daemon-owned Discord WebSocket and REST transport.
pub trait DiscordTransport {
    /// Starts opening the configured Gateway URL.
    ///
    /// # Errors
    ///
    /// Returns a typed transport or configuration failure.
    fn open_gateway(&mut self, gateway_url: &str) -> Result<(), ChannelError>;

    /// Closes the current Gateway socket. Repeated closes must be harmless.
    ///
    /// # Errors
    ///
    /// Returns a typed transport failure when the close could not be initiated.
    fn close_gateway(&mut self) -> Result<(), ChannelError>;

    /// Sends one Gateway control payload on an open socket.
    ///
    /// # Errors
    ///
    /// Returns a typed transport or protocol failure.
    fn send_gateway(&mut self, request: &DiscordGatewayRequest<'_>) -> Result<(), ChannelError>;

    /// Creates one Discord channel message through REST v10.
    ///
    /// # Errors
    ///
    /// Returns typed transport or framing failures. Provider statuses remain in
    /// [`ProviderResponse`].
    fn create_message(
        &mut self,
        request: &DiscordCreateMessageRequest<'_>,
    ) -> Result<ProviderResponse, ChannelError>;
}

/// Discord Gateway plus REST message adapter.
pub struct DiscordChannel<T, C> {
    account_id: String,
    gateway_url: String,
    gateway_origin: ApprovedOrigin,
    rest_origin: ApprovedOrigin,
    intents: u64,
    transport: T,
    clock: C,
    lifecycle: ConnectionStateMachine,
    phase: DiscordGatewayPhase,
    sequence: Option<i64>,
    session_id: Option<String>,
    heartbeat_interval: Option<Duration>,
    next_heartbeat: Option<Duration>,
    awaiting_heartbeat_ack: bool,
    reconnect_due: Option<Duration>,
    reconnect_attempts: u32,
    max_reconnect_attempts: NonZeroU32,
    inbound: BoundedQueue<InboundMessage>,
}

impl<T, C> DiscordChannel<T, C> {
    /// Creates a disconnected Discord adapter.
    ///
    /// The Gateway credential origin uses the SDK's canonical HTTPS origin as
    /// the TLS-equivalent identity for the configured `wss://` endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Configuration`] for invalid account or Gateway
    /// routing, a Gateway origin that does not match the `wss://` authority, or
    /// a REST origin other than the enrolled `https://discord.com` origin.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: impl Into<String>,
        gateway_url: impl Into<String>,
        gateway_origin: ApprovedOrigin,
        rest_origin: ApprovedOrigin,
        intents: u64,
        transport: T,
        clock: C,
        inbound_capacity: NonZeroUsize,
        max_reconnect_attempts: NonZeroU32,
    ) -> Result<Self, ChannelError> {
        let account_id = account_id.into();
        let gateway_url = gateway_url.into();
        if invalid_routing_identifier(&account_id) {
            return Err(ChannelError::Configuration(
                ConfigurationError::InvalidAdapterConfiguration,
            ));
        }
        require_gateway_origin(&gateway_origin, &account_id, &gateway_url)?;
        require_official_origin(&rest_origin, "discord", &account_id, "discord.com")?;
        Ok(Self {
            account_id,
            gateway_url,
            gateway_origin,
            rest_origin,
            intents,
            transport,
            clock,
            lifecycle: ConnectionStateMachine::new(),
            phase: DiscordGatewayPhase::Idle,
            sequence: None,
            session_id: None,
            heartbeat_interval: None,
            next_heartbeat: None,
            awaiting_heartbeat_ack: false,
            reconnect_due: None,
            reconnect_attempts: 0,
            max_reconnect_attempts,
            inbound: BoundedQueue::new(inbound_capacity),
        })
    }

    /// Returns the shared connection state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.lifecycle.state()
    }

    /// Returns the Gateway protocol phase.
    #[must_use]
    pub const fn phase(&self) -> DiscordGatewayPhase {
        self.phase
    }

    /// Returns the latest Gateway sequence.
    #[must_use]
    pub const fn sequence(&self) -> Option<i64> {
        self.sequence
    }

    /// Returns the READY session identifier.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Returns the scheduled reconnect deadline.
    #[must_use]
    pub const fn reconnect_due(&self) -> Option<Duration> {
        self.reconnect_due
    }

    /// Returns the number of queued inbound user messages.
    #[must_use]
    pub fn queued_inbound(&self) -> usize {
        self.inbound.len()
    }

    /// Returns the transport for inspection.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    const fn require_connected(&self) -> Result<(), ChannelError> {
        if self.lifecycle.state().can_exchange() {
            Ok(())
        } else {
            Err(ChannelError::NotConnected {
                state: self.lifecycle.state(),
            })
        }
    }

    fn diagnostic<'a>(
        &'a self,
        level: DiagnosticLevel,
        code: DiagnosticCode,
        conversation_id: Option<&'a str>,
        remote_status: Option<u16>,
        retry_after: Option<Duration>,
    ) -> OperatorDiagnostic<'a> {
        OperatorDiagnostic {
            level,
            code,
            channel_id: "discord",
            account_id: &self.account_id,
            conversation_id,
            remote_status,
            retry_after,
        }
    }
}

impl<T: DiscordTransport, C: UnixClock> DiscordChannel<T, C> {
    /// Starts one Gateway connection attempt.
    ///
    /// Repeated calls while connecting, connected, or waiting to reconnect are
    /// harmless. An opening failure is returned after scheduling a bounded
    /// reconnect.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Lifecycle`] after terminal stop, or the transport
    /// error from [`DiscordTransport::open_gateway`].
    pub fn start(
        &mut self,
        now: Duration,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<bool, ChannelError> {
        match self.lifecycle.state() {
            ConnectionState::Connecting
            | ConnectionState::Connected
            | ConnectionState::Reconnecting => return Ok(false),
            ConnectionState::Closed => {
                self.lifecycle
                    .apply(LifecycleEvent::ConnectRequested, &mut ())?;
                unreachable!("closed lifecycle must refuse reconnect")
            }
            ConnectionState::Disconnected => {}
        }
        self.phase = DiscordGatewayPhase::Idle;
        self.reconnect_attempts = 0;
        self.lifecycle
            .apply(LifecycleEvent::ConnectRequested, &mut ())?;
        match self.transport.open_gateway(&self.gateway_url) {
            Ok(()) => {
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Info,
                    DiagnosticCode::ChannelStarted,
                    None,
                    None,
                    None,
                ));
                Ok(true)
            }
            Err(error) => {
                self.lifecycle
                    .apply(LifecycleEvent::ConnectionLost, &mut ())?;
                self.schedule_reconnect(now, diagnostics)?;
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Error,
                    DiagnosticCode::ConnectionFailed,
                    None,
                    None,
                    error.retry_after(),
                ));
                Err(error)
            }
        }
    }

    /// Records that the WebSocket transport opened.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::NotConnected`] unless a connection attempt is active.
    pub fn gateway_opened(
        &mut self,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<(), ChannelError> {
        if self.lifecycle.state() != ConnectionState::Connecting {
            return Err(ChannelError::NotConnected {
                state: self.lifecycle.state(),
            });
        }
        if self.phase != DiscordGatewayPhase::Idle {
            return Ok(());
        }
        self.phase = DiscordGatewayPhase::AwaitingHello;
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Info,
            DiagnosticCode::GatewayConnected,
            None,
            None,
            None,
        ));
        Ok(())
    }

    /// Records a socket close and schedules bounded reconnect while running.
    ///
    /// A close callback arriving after [`Self::stop`] is ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::Lifecycle`] for an out-of-order close.
    pub fn gateway_closed(
        &mut self,
        now: Duration,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<bool, ChannelError> {
        if self.lifecycle.state() == ConnectionState::Closed {
            return Ok(false);
        }
        if self.lifecycle.state() == ConnectionState::Reconnecting {
            return Ok(false);
        }
        self.lifecycle
            .apply(LifecycleEvent::ConnectionLost, &mut ())?;
        self.reset_connection_protocol();
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Warning,
            DiagnosticCode::GatewayDisconnected,
            None,
            None,
            None,
        ));
        self.schedule_reconnect(now, diagnostics)
    }

    /// Advances reconnect and heartbeat timers using caller-supplied monotonic time.
    ///
    /// # Errors
    ///
    /// Returns typed transport failures. Connection state is moved to a
    /// reconnecting or exhausted state before the error is returned.
    pub fn tick(
        &mut self,
        now: Duration,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<bool, ChannelError> {
        if self.lifecycle.state() == ConnectionState::Reconnecting
            && self.reconnect_due.is_some_and(|due| now >= due)
        {
            self.reconnect_due = None;
            self.lifecycle
                .apply(LifecycleEvent::ConnectRequested, &mut ())?;
            if let Err(error) = self.transport.open_gateway(&self.gateway_url) {
                self.lifecycle
                    .apply(LifecycleEvent::ConnectionLost, &mut ())?;
                self.schedule_reconnect(now, diagnostics)?;
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Error,
                    DiagnosticCode::ConnectionFailed,
                    None,
                    None,
                    error.retry_after(),
                ));
                return Err(error);
            }
            return Ok(true);
        }

        if matches!(
            self.lifecycle.state(),
            ConnectionState::Connecting | ConnectionState::Connected
        ) && self.next_heartbeat.is_some_and(|due| now >= due)
        {
            if self.awaiting_heartbeat_ack {
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Warning,
                    DiagnosticCode::HeartbeatMissed,
                    None,
                    None,
                    None,
                ));
                let close_result = self.transport.close_gateway();
                self.gateway_closed(now, diagnostics)?;
                close_result?;
                return Ok(true);
            }
            if let Err(error) = self.transport.send_gateway(&DiscordGatewayRequest {
                kind: DiscordGatewayRequestKind::Heartbeat {
                    sequence: self.sequence,
                },
            }) {
                let _ = self.transport.close_gateway();
                self.gateway_closed(now, diagnostics)?;
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Error,
                    DiagnosticCode::ConnectionFailed,
                    None,
                    None,
                    error.retry_after(),
                ));
                return Err(error);
            }
            self.awaiting_heartbeat_ack = true;
            self.next_heartbeat = self
                .heartbeat_interval
                .map(|interval| now.saturating_add(interval));
            return Ok(true);
        }
        Ok(false)
    }

    /// Parses and contains one Gateway packet.
    ///
    /// Malformed JSON and malformed dispatch payloads emit a safe diagnostic and
    /// return [`DiscordPacketOutcome::Malformed`] instead of escaping the event
    /// listener task.
    ///
    /// # Errors
    ///
    /// Returns [`ChannelError::NotConnected`] when no socket is open, credential
    /// binding failures while sending IDENTIFY, and transport failures while
    /// sending Gateway control traffic or closing for reconnect.
    pub fn handle_gateway_packet(
        &mut self,
        raw: &[u8],
        now: Duration,
        gateway_credential: &ChannelCredential,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<DiscordPacketOutcome, ChannelError> {
        self.require_gateway_open()?;
        if raw.len() > MAX_PROVIDER_RESPONSE_BYTES {
            self.record_malformed(diagnostics);
            return Ok(DiscordPacketOutcome::Malformed);
        }
        let Ok(packet) = serde_json::from_slice::<DiscordPacket<'_>>(raw) else {
            self.record_malformed(diagnostics);
            return Ok(DiscordPacketOutcome::Malformed);
        };
        if let Some(sequence) = packet.sequence {
            self.sequence = Some(sequence);
        }

        match packet.opcode {
            10 if self.phase == DiscordGatewayPhase::AwaitingHello => {
                self.handle_hello(packet.data.get(), now, gateway_credential, diagnostics)
            }
            0 => self.handle_dispatch(packet.event_type, packet.data.get(), diagnostics),
            7 | 9 => {
                if packet.opcode == 9 {
                    self.sequence = None;
                    self.session_id = None;
                }
                let close_result = self.transport.close_gateway();
                self.gateway_closed(now, diagnostics)?;
                close_result?;
                Ok(DiscordPacketOutcome::ReconnectRequested)
            }
            11 => {
                self.awaiting_heartbeat_ack = false;
                Ok(DiscordPacketOutcome::HeartbeatAcknowledged)
            }
            _ => Ok(DiscordPacketOutcome::Ignored),
        }
    }

    /// Permanently stops the Gateway and clears timers and queued input.
    ///
    /// Repeated stops are idempotent. State becomes terminal before transport
    /// close, so a close failure can never permit reconnect.
    ///
    /// # Errors
    ///
    /// Returns the typed close failure from [`DiscordTransport::close_gateway`].
    pub fn stop(&mut self, diagnostics: &mut impl DiagnosticSink) -> Result<bool, ChannelError> {
        if self.lifecycle.state() == ConnectionState::Closed {
            return Ok(false);
        }
        let should_close = matches!(
            self.lifecycle.state(),
            ConnectionState::Connecting | ConnectionState::Connected
        );
        self.lifecycle
            .apply(LifecycleEvent::ShutdownRequested, &mut ())?;
        self.reset_connection_protocol();
        self.reconnect_due = None;
        self.inbound.clear();
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Info,
            DiagnosticCode::ChannelStopped,
            None,
            None,
            None,
        ));
        if should_close {
            self.transport.close_gateway()?;
        }
        Ok(true)
    }

    fn handle_hello(
        &mut self,
        data: &str,
        now: Duration,
        gateway_credential: &ChannelCredential,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<DiscordPacketOutcome, ChannelError> {
        let hello: DiscordHello = match serde_json::from_str::<DiscordHello>(data) {
            Ok(hello) if hello.heartbeat_interval > 0 => hello,
            Ok(_) | Err(_) => {
                self.record_malformed(diagnostics);
                return Ok(DiscordPacketOutcome::Malformed);
            }
        };
        let heartbeat_interval = Duration::from_millis(hello.heartbeat_interval);
        let send_result = match gateway_credential
            .expose_for_origin(
                "discord",
                &self.account_id,
                CredentialKind::Token,
                &self.gateway_origin,
                |bot_token| {
                    self.transport.send_gateway(&DiscordGatewayRequest {
                        kind: DiscordGatewayRequestKind::Identify {
                            bot_token,
                            intents: self.intents,
                            platform: std::env::consts::OS,
                        },
                    })
                },
            )
            .map_err(map_credential_binding)
        {
            Ok(send_result) => send_result,
            Err(error) => {
                let _ = self.transport.close_gateway();
                self.gateway_closed(now, diagnostics)?;
                diagnostics.record(self.diagnostic(
                    DiagnosticLevel::Error,
                    DiagnosticCode::ConnectionFailed,
                    None,
                    None,
                    None,
                ));
                return Err(error);
            }
        };
        if let Err(error) = send_result {
            let _ = self.transport.close_gateway();
            self.gateway_closed(now, diagnostics)?;
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Error,
                DiagnosticCode::ConnectionFailed,
                None,
                None,
                error.retry_after(),
            ));
            return Err(error);
        }
        self.heartbeat_interval = Some(heartbeat_interval);
        self.next_heartbeat = Some(now.saturating_add(heartbeat_interval));
        self.awaiting_heartbeat_ack = false;
        self.phase = DiscordGatewayPhase::Identifying;
        Ok(DiscordPacketOutcome::Identified)
    }

    fn handle_dispatch(
        &mut self,
        event_type: Option<&str>,
        data: &str,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<DiscordPacketOutcome, ChannelError> {
        match event_type {
            Some("READY") if self.phase == DiscordGatewayPhase::Identifying => {
                let ready: DiscordReady<'_> = match serde_json::from_str::<DiscordReady<'_>>(data) {
                    Ok(ready)
                        if !invalid_routing_identifier(ready.session_id)
                            && ready.session_id.len() <= 256 =>
                    {
                        ready
                    }
                    Ok(_) | Err(_) => {
                        self.record_malformed(diagnostics);
                        return Ok(DiscordPacketOutcome::Malformed);
                    }
                };
                self.lifecycle.apply(LifecycleEvent::Established, &mut ())?;
                self.session_id = Some(ready.session_id.to_owned());
                self.phase = DiscordGatewayPhase::Ready;
                self.reconnect_attempts = 0;
                Ok(DiscordPacketOutcome::Ready)
            }
            Some("MESSAGE_CREATE") if self.phase == DiscordGatewayPhase::Ready => {
                let Ok(message) = serde_json::from_str::<DiscordMessage<'_>>(data) else {
                    self.record_malformed(diagnostics);
                    return Ok(DiscordPacketOutcome::Malformed);
                };
                if message.author.bot {
                    diagnostics.record(self.diagnostic(
                        DiagnosticLevel::Info,
                        DiagnosticCode::BotMessageIgnored,
                        None,
                        None,
                        None,
                    ));
                    return Ok(DiscordPacketOutcome::Ignored);
                }
                let text = message.content.trim();
                if text.is_empty() {
                    diagnostics.record(self.diagnostic(
                        DiagnosticLevel::Info,
                        DiagnosticCode::EmptyMessageIgnored,
                        None,
                        None,
                        None,
                    ));
                    return Ok(DiscordPacketOutcome::Ignored);
                }
                if [
                    message.id,
                    message.channel_id,
                    message.author.id,
                    message.author.username,
                ]
                .into_iter()
                .any(invalid_routing_identifier)
                {
                    self.record_malformed(diagnostics);
                    return Ok(DiscordPacketOutcome::Malformed);
                }
                let normalized = InboundMessage {
                    id: message.id.to_owned(),
                    channel_id: "discord".to_owned(),
                    account_id: self.account_id.clone(),
                    conversation_id: format!(
                        "discord:{}:{}",
                        message.channel_id, message.author.id
                    ),
                    sender_id: message.author.id.to_owned(),
                    text: Some(text.to_owned()),
                    attachments: Vec::new(),
                    received_at_unix_ms: self.clock.now_unix_ms(),
                };
                if let Err(dropped) = self.inbound.push(normalized) {
                    diagnostics.record(self.diagnostic(
                        DiagnosticLevel::Warning,
                        DiagnosticCode::InboundQueueFull,
                        Some(&dropped.conversation_id),
                        None,
                        None,
                    ));
                    Ok(DiscordPacketOutcome::MessageDropped)
                } else {
                    Ok(DiscordPacketOutcome::MessageQueued)
                }
            }
            Some(_) | None => Ok(DiscordPacketOutcome::Ignored),
        }
    }

    fn schedule_reconnect(
        &mut self,
        now: Duration,
        diagnostics: &mut impl DiagnosticSink,
    ) -> Result<bool, ChannelError> {
        if self.reconnect_attempts >= self.max_reconnect_attempts.get() {
            self.phase = DiscordGatewayPhase::ReconnectExhausted;
            self.reconnect_due = None;
            diagnostics.record(self.diagnostic(
                DiagnosticLevel::Error,
                DiagnosticCode::ReconnectExhausted,
                None,
                None,
                None,
            ));
            return Ok(false);
        }
        self.reconnect_attempts += 1;
        self.lifecycle
            .apply(LifecycleEvent::ReconnectScheduled, &mut ())?;
        self.reconnect_due = Some(now.saturating_add(DISCORD_RECONNECT_DELAY));
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Warning,
            DiagnosticCode::ReconnectScheduled,
            None,
            None,
            Some(DISCORD_RECONNECT_DELAY),
        ));
        Ok(true)
    }

    const fn reset_connection_protocol(&mut self) {
        self.phase = DiscordGatewayPhase::Idle;
        self.heartbeat_interval = None;
        self.next_heartbeat = None;
        self.awaiting_heartbeat_ack = false;
    }

    fn record_malformed(&self, diagnostics: &mut impl DiagnosticSink) {
        diagnostics.record(self.diagnostic(
            DiagnosticLevel::Warning,
            DiagnosticCode::MalformedPayload,
            None,
            None,
            None,
        ));
    }

    const fn require_gateway_open(&self) -> Result<(), ChannelError> {
        if matches!(
            self.lifecycle.state(),
            ConnectionState::Connecting | ConnectionState::Connected
        ) && !matches!(
            self.phase,
            DiscordGatewayPhase::Idle | DiscordGatewayPhase::ReconnectExhausted
        ) {
            Ok(())
        } else {
            Err(ChannelError::NotConnected {
                state: self.lifecycle.state(),
            })
        }
    }
}

impl<T: DiscordTransport, C: UnixClock> Channel for DiscordChannel<T, C> {
    fn id(&self) -> &'static str {
        "discord"
    }

    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
        self.require_connected()?;
        Ok(self.inbound.pop())
    }

    fn outbound_retry_safety(&self) -> OutboundRetrySafety {
        OutboundRetrySafety::NotSafeToRepeat
    }

    fn send_outbound(
        &mut self,
        message: &OutboundMessage,
        credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, ChannelError> {
        self.require_connected()?;
        message.validate().map_err(ChannelError::InvalidMessage)?;
        if message.account_id != self.account_id {
            return Err(ChannelError::Configuration(
                ConfigurationError::CredentialScopeMismatch,
            ));
        }
        if !message.attachments.is_empty() {
            return Err(ChannelError::Unsupported(UnsupportedOperation::Attachments));
        }
        if message.reply_to.is_some() {
            return Err(ChannelError::Unsupported(UnsupportedOperation::Replies));
        }
        let route =
            message
                .conversation_id
                .strip_prefix("discord:")
                .ok_or(ChannelError::Configuration(
                    ConfigurationError::ConversationScopeMismatch,
                ))?;
        let (channel_id, sender_id) = route.split_once(':').ok_or(ChannelError::Configuration(
            ConfigurationError::ConversationScopeMismatch,
        ))?;
        if invalid_routing_identifier(channel_id) || invalid_routing_identifier(sender_id) {
            return Err(ChannelError::Configuration(
                ConfigurationError::ConversationScopeMismatch,
            ));
        }
        let text = message.text.as_deref().ok_or(ChannelError::InvalidMessage(
            InvalidMessageReason::EmptyContent,
        ))?;
        let credential = credential.ok_or(ChannelError::Credential(SecretStoreError::NotFound))?;
        let segments = segment_outbound_text("discord", text).map_err(|_| {
            ChannelError::Configuration(ConfigurationError::InvalidAdapterConfiguration)
        })?;
        let mut remote_message_id = None;
        credential
            .expose_for_origin(
                "discord",
                &self.account_id,
                CredentialKind::Token,
                &self.rest_origin,
                |bot_token| -> Result<(), ChannelError> {
                    for chunk in segments {
                        let response =
                            self.transport
                                .create_message(&DiscordCreateMessageRequest {
                                    bot_token,
                                    channel_id,
                                    content: chunk.as_ref(),
                                })?;
                        classify_rest_response(&response)?;
                        response.require_bounded()?;
                        if !response.body().is_empty() {
                            let created: DiscordCreatedMessage<'_> =
                                serde_json::from_slice(response.body()).map_err(|_| {
                                    ChannelError::Protocol(ProtocolErrorKind::MalformedResponse)
                                })?;
                            if invalid_routing_identifier(created.id) {
                                return Err(ChannelError::Protocol(
                                    ProtocolErrorKind::InvalidField,
                                ));
                            }
                            remote_message_id = Some(created.id.to_owned());
                        }
                    }
                    Ok(())
                },
            )
            .map_err(map_credential_binding)??;
        Ok(DeliveryAcknowledgement {
            correlation_key: message.correlation_key.clone(),
            remote_message_id,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: self.clock.now_unix_ms(),
        })
    }
}

#[derive(Deserialize)]
struct DiscordPacket<'a> {
    #[serde(rename = "op")]
    opcode: u8,
    #[serde(rename = "t")]
    event_type: Option<&'a str>,
    #[serde(rename = "s")]
    sequence: Option<i64>,
    #[serde(rename = "d", borrow)]
    data: &'a RawValue,
}

#[derive(Deserialize)]
struct DiscordHello {
    heartbeat_interval: u64,
}

#[derive(Deserialize)]
struct DiscordReady<'a> {
    session_id: &'a str,
}

#[derive(Deserialize)]
struct DiscordMessage<'a> {
    id: &'a str,
    channel_id: &'a str,
    content: &'a str,
    #[serde(borrow)]
    author: DiscordAuthor<'a>,
}

#[derive(Deserialize)]
struct DiscordAuthor<'a> {
    id: &'a str,
    username: &'a str,
    #[serde(default)]
    bot: bool,
}

#[derive(Deserialize)]
struct DiscordCreatedMessage<'a> {
    id: &'a str,
}

fn require_gateway_origin(
    origin: &ApprovedOrigin,
    account_id: &str,
    gateway_url: &str,
) -> Result<(), ChannelError> {
    if origin.channel_id() != "discord" || origin.account_id() != account_id {
        return Err(ChannelError::Configuration(
            ConfigurationError::CredentialScopeMismatch,
        ));
    }
    if gateway_url.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
        return Err(ChannelError::Configuration(
            ConfigurationError::InvalidAdapterConfiguration,
        ));
    }
    let remainder = gateway_url
        .strip_prefix("wss://")
        .ok_or(ChannelError::Configuration(
            ConfigurationError::InvalidAdapterConfiguration,
        ))?;
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty() && !authority.contains('@'))
        .ok_or(ChannelError::Configuration(
            ConfigurationError::InvalidAdapterConfiguration,
        ))?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            Some(port.parse::<u16>().map_err(|_| {
                ChannelError::Configuration(ConfigurationError::InvalidAdapterConfiguration)
            })?),
        ),
        None => (authority, None),
    };
    let network = origin.network_origin();
    let expected_port = network.port().unwrap_or(443);
    if !host.eq_ignore_ascii_case(network.host()) || port.unwrap_or(443) != expected_port {
        return Err(ChannelError::Configuration(
            ConfigurationError::InvalidAdapterConfiguration,
        ));
    }
    Ok(())
}

fn classify_rest_response(response: &ProviderResponse) -> Result<(), ChannelError> {
    match response.status() {
        200..=299 => Ok(()),
        401 | 403 => Err(ChannelError::Authentication),
        429 => Err(ChannelError::RateLimited {
            retry_after: response
                .retry_after()
                .unwrap_or_else(|| Duration::from_secs(1)),
        }),
        status => Err(ChannelError::RemoteRejected { status }),
    }
}

const fn map_credential_binding(error: CredentialBindingError) -> ChannelError {
    ChannelError::CredentialBinding(error)
}

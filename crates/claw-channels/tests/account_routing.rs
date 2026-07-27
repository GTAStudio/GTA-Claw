//! Account routing across the frozen official channel registry.

mod support;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use claw_channel_sdk::{
    Channel, ChannelCredential, ChannelError, CredentialBinding, CredentialBindingError,
    CredentialKind, CredentialRequest, DeliveryAcknowledgement, DeliveryState, InboundMessage,
    InvalidMessageReason, OutboundMessage,
};
use claw_channels::{
    ChannelRouter, ExchangeSupport, QaChannel, RouterError, RoutingError, UnixClock,
    WebhookChannel, WebhookRequest, WebhookResponse, WebhookTransport, descriptor,
    exchange_support, registry,
};

use support::frozen_channel_ids;

#[derive(Clone, Copy, Debug)]
struct FixedClock(u64);

impl UnixClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

#[derive(Debug)]
struct StubChannel {
    id: &'static str,
    sent: Vec<OutboundMessage>,
}

impl StubChannel {
    const fn new(id: &'static str) -> Self {
        Self {
            id,
            sent: Vec::new(),
        }
    }
}

impl Channel for StubChannel {
    fn id(&self) -> &str {
        self.id
    }

    fn poll_inbound(&mut self) -> Result<Option<InboundMessage>, ChannelError> {
        Ok(None)
    }

    fn send_outbound(
        &mut self,
        message: &OutboundMessage,
        _credential: Option<&ChannelCredential>,
    ) -> Result<DeliveryAcknowledgement, ChannelError> {
        message.validate().map_err(ChannelError::InvalidMessage)?;
        self.sent.push(message.clone());
        Ok(DeliveryAcknowledgement {
            correlation_key: message.correlation_key.clone(),
            remote_message_id: Some(format!("{}-{}", self.id, self.sent.len())),
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: 11,
        })
    }
}

#[derive(Debug)]
struct RecordingTransport {
    calls: CapturedRequests,
}

type CapturedRequest = (String, Vec<u8>);
type CapturedRequests = Rc<RefCell<Vec<CapturedRequest>>>;

impl WebhookTransport for RecordingTransport {
    fn post_json(&self, request: &WebhookRequest<'_>) -> Result<WebhookResponse, ChannelError> {
        self.calls
            .borrow_mut()
            .push((request.endpoint().to_owned(), request.body().to_vec()));
        Ok(WebhookResponse { status: 200 })
    }
}

fn webhook_credential(channel_id: &str, account_id: &str, endpoint: &str) -> ChannelCredential {
    ChannelCredential::bind(
        endpoint.to_owned(),
        CredentialRequest {
            channel_id: channel_id.to_owned(),
            account_id: account_id.to_owned(),
            kind: CredentialKind::WebhookUrl,
            binding: CredentialBinding::EmbeddedEndpoint,
        },
    )
    .expect("valid embedded-endpoint binding")
}

fn outbound(account_id: &str, text: &str) -> OutboundMessage {
    OutboundMessage {
        correlation_key: format!("delivery-{account_id}"),
        account_id: account_id.to_owned(),
        conversation_id: "room-1".to_owned(),
        text: Some(text.to_owned()),
        attachments: Vec::new(),
        reply_to: None,
    }
}

fn inbound(channel_id: &str, account_id: &str, text: &str) -> InboundMessage {
    InboundMessage {
        id: format!("message-{account_id}"),
        channel_id: channel_id.to_owned(),
        account_id: account_id.to_owned(),
        conversation_id: "room-1".to_owned(),
        sender_id: "fixture".to_owned(),
        text: Some(text.to_owned()),
        attachments: Vec::new(),
        received_at_unix_ms: 1,
    }
}

#[test]
fn every_frozen_channel_identifier_routes_to_its_own_accounts() {
    let frozen_ids = frozen_channel_ids();
    let mut router = ChannelRouter::new();

    for id in &frozen_ids {
        let entry = descriptor(id).unwrap_or_else(|| panic!("frozen channel {id} is unregistered"));
        assert_eq!(entry.id, id);
        for account in ["primary", "secondary"] {
            assert_eq!(
                router
                    .register(id, account, StubChannel::new(entry.id))
                    .map(|registered| registered.id),
                Ok(entry.id)
            );
        }
        assert_eq!(
            router.register(id, "primary", StubChannel::new(entry.id)),
            Err(RoutingError::DuplicateAccount)
        );
        assert_eq!(router.accounts(id), Ok(vec!["primary", "secondary"]));
        assert_eq!(
            router.route(id, "absent").err(),
            Some(RoutingError::UnroutedAccount)
        );
    }

    assert_eq!(router.len(), frozen_ids.len() * 2);
    assert_eq!(
        router.channels(),
        registry()
            .iter()
            .map(|entry| entry.id)
            .collect::<BTreeSet<_>>(),
        "the router must reach every registry entry and no other"
    );
    assert_eq!(
        registry().len(),
        frozen_ids.len(),
        "the registry must not carry entries the frozen inventory does not define"
    );
    assert_eq!(
        frozen_ids.iter().collect::<BTreeSet<_>>().len(),
        frozen_ids.len(),
        "frozen channel identifiers must be unique"
    );

    for unknown in [
        "",
        "Slack",
        "slackk",
        "discord ",
        "qa_channel",
        "channel:slack",
    ] {
        assert_eq!(
            router.register(unknown, "primary", StubChannel::new("slack")),
            Err(RoutingError::UnknownChannel),
            "{unknown}"
        );
        assert_eq!(
            router.accounts(unknown).err(),
            Some(RoutingError::UnknownChannel),
            "{unknown}"
        );
    }
    for invalid in ["", " padded", "padded ", "line\nbreak"] {
        assert_eq!(
            router.register("slack", invalid, StubChannel::new("slack")),
            Err(RoutingError::InvalidAccountId),
            "{invalid:?}"
        );
    }
    assert_eq!(
        router.register("slack", "third", StubChannel::new("discord")),
        Err(RoutingError::AdapterIdentityMismatch)
    );
}

#[test]
fn outbound_delivery_is_isolated_between_two_accounts_of_one_channel() {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut router = ChannelRouter::new();
    for account in ["primary", "secondary"] {
        let channel = WebhookChannel::new(
            "discord",
            account,
            "room-1",
            RecordingTransport {
                calls: Rc::clone(&calls),
            },
            FixedClock(77),
        )
        .expect("webhook-capable channel");
        router
            .register("discord", account, channel)
            .expect("registered account");
    }
    let primary = webhook_credential(
        "discord",
        "primary",
        "https://discord.example/hooks/primary",
    );
    let secondary = webhook_credential(
        "discord",
        "secondary",
        "https://discord.example/hooks/secondary",
    );

    assert_eq!(
        router.send("discord", &outbound("primary", "one"), Some(&primary)),
        Ok(DeliveryAcknowledgement {
            correlation_key: "delivery-primary".to_owned(),
            remote_message_id: None,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: 77,
        })
    );
    assert_eq!(
        router.send("discord", &outbound("secondary", "two"), Some(&secondary)),
        Ok(DeliveryAcknowledgement {
            correlation_key: "delivery-secondary".to_owned(),
            remote_message_id: None,
            state: DeliveryState::Accepted,
            accepted_at_unix_ms: 77,
        })
    );
    assert_eq!(
        calls.borrow().as_slice(),
        &[
            (
                "https://discord.example/hooks/primary".to_owned(),
                br#"{"content":"one"}"#.to_vec()
            ),
            (
                "https://discord.example/hooks/secondary".to_owned(),
                br#"{"content":"two"}"#.to_vec()
            ),
        ]
    );

    assert_eq!(
        router.send("discord", &outbound("primary", "three"), Some(&secondary)),
        Err(RouterError::Channel(ChannelError::CredentialBinding(
            CredentialBindingError::ScopeMismatch
        ))),
        "one account's credential must never be usable by another account"
    );
    assert_eq!(
        router.send("discord", &outbound("tertiary", "four"), Some(&primary)),
        Err(RouterError::Routing(RoutingError::UnroutedAccount))
    );
    assert_eq!(
        router.send("slack", &outbound("primary", "five"), Some(&primary)),
        Err(RouterError::Routing(RoutingError::UnroutedAccount))
    );
    assert_eq!(
        router.send("not-a-channel", &outbound("primary", "six"), Some(&primary)),
        Err(RouterError::Routing(RoutingError::UnknownChannel))
    );
    assert_eq!(
        calls.borrow().len(),
        2,
        "a refused route must never reach a transport"
    );
}

#[test]
fn inbound_is_delivered_only_to_the_account_that_owns_it() {
    let mut router = ChannelRouter::new();
    for account in ["primary", "secondary"] {
        router
            .register(
                "qa-channel",
                account,
                QaChannel::new(account, FixedClock(5)).expect("valid QA adapter"),
            )
            .expect("registered account");
    }
    for account in ["primary", "secondary"] {
        router
            .route_mut("qa-channel", account)
            .expect("routed account")
            .push_inbound(inbound("qa-channel", account, account))
            .expect("queued fixture message");
    }

    for account in ["primary", "secondary"] {
        let message = inbound("qa-channel", account, account);
        assert_eq!(
            router
                .route_inbound(&message)
                .expect("routed inbound")
                .poll_inbound(),
            Ok(Some(message))
        );
        assert_eq!(router.poll_inbound("qa-channel", account), Ok(None));
    }

    assert_eq!(
        router
            .route_inbound(&inbound("qa-channel", "tertiary", "hello"))
            .err(),
        Some(RoutingError::UnroutedAccount)
    );
    assert_eq!(
        router
            .route_inbound(&inbound("not-a-channel", "primary", "hello"))
            .err(),
        Some(RoutingError::UnknownChannel)
    );
    assert_eq!(
        router
            .route_inbound(&inbound("discord", "primary", "hello"))
            .err(),
        Some(RoutingError::InboundUnsupported)
    );
    assert_eq!(
        router
            .route_inbound(&inbound("qa-channel", "primary", ""))
            .err(),
        Some(RoutingError::InvalidMessage(
            InvalidMessageReason::EmptyContent
        ))
    );
}

#[test]
fn inbound_is_refused_for_every_frozen_channel_without_an_inbound_implementation() {
    let frozen_ids = frozen_channel_ids();
    let mut router = ChannelRouter::new();
    let mut inbound_capable = BTreeSet::new();
    let mut outbound_capable = BTreeSet::new();

    for id in &frozen_ids {
        let entry = descriptor(id).unwrap_or_else(|| panic!("frozen channel {id} is unregistered"));
        router
            .register(id, "primary", StubChannel::new(entry.id))
            .expect("registered account");
        match exchange_support(id).expect("registered channel") {
            ExchangeSupport::Bidirectional => {
                inbound_capable.insert(entry.id);
                outbound_capable.insert(entry.id);
            }
            ExchangeSupport::InboundOnly => {
                inbound_capable.insert(entry.id);
            }
            ExchangeSupport::OutboundOnly => {
                outbound_capable.insert(entry.id);
            }
            ExchangeSupport::None => {}
        }
    }

    for id in &frozen_ids {
        let polled = router.poll_inbound(id, "primary");
        if inbound_capable.contains(id.as_str()) {
            assert_eq!(polled, Ok(None), "{id}");
        } else {
            assert_eq!(
                polled,
                Err(RouterError::Routing(RoutingError::InboundUnsupported)),
                "{id}"
            );
        }
    }

    assert_eq!(inbound_capable, BTreeSet::from(["qa-channel"]));
    assert_eq!(
        outbound_capable,
        BTreeSet::from(["discord", "googlechat", "mattermost", "qa-channel", "slack"])
    );
    assert_eq!(
        exchange_support("not-a-channel"),
        Err(RoutingError::UnknownChannel)
    );
}

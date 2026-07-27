//! Declared outbound length limits and the segmentation they drive.
//!
//! The point of these tests is provenance discipline as much as behavior: a
//! limit exists here only because a file in this repository states it, and a
//! channel without such a file must refuse to segment rather than guess a
//! bound and silently truncate somebody's message.

use std::cell::RefCell;
use std::num::NonZeroU32;
use std::rc::Rc;

use claw_channel_sdk::{
    Channel, ChannelCredential, ChannelError, CredentialBinding, CredentialKind, CredentialRequest,
    LengthUnit, OutboundMessage, SegmentationError,
};
use claw_channels::{
    ChannelCapability, ImplementationStatus, OutboundTextError, RoutingError, UnixClock,
    WebhookChannel, WebhookRequest, WebhookResponse, WebhookTransport, descriptor, output_limit,
    registry, segment_outbound_text,
};

/// Every limit this repository can prove, and nothing else.
///
/// `msteams`, `telegram` and `whatsapp` appear here as metadata only: the
/// legacy program states their limits, so modelling them is honest, but this
/// crate has no transport for them and they stay `RegistrationOnly`.
const PROVEN_LIMITS: [(&str, u32); 4] = [
    ("discord", 1900),
    ("msteams", 4000),
    ("telegram", 4000),
    ("whatsapp", 3500),
];

#[derive(Clone, Copy, Debug)]
struct FixedClock(u64);

impl UnixClock for FixedClock {
    fn now_unix_ms(&self) -> u64 {
        self.0
    }
}

type PostedBodies = Rc<RefCell<Vec<String>>>;

/// Records the text of every posted payload and fails from a chosen call on.
#[derive(Debug)]
struct RecordingTransport {
    field: &'static str,
    posts: PostedBodies,
    fail_from: Option<usize>,
}

impl RecordingTransport {
    fn new(field: &'static str, posts: &PostedBodies) -> Self {
        Self {
            field,
            posts: Rc::clone(posts),
            fail_from: None,
        }
    }

    fn failing_from(field: &'static str, posts: &PostedBodies, fail_from: usize) -> Self {
        Self {
            field,
            posts: Rc::clone(posts),
            fail_from: Some(fail_from),
        }
    }
}

impl WebhookTransport for RecordingTransport {
    fn post_json(&self, request: &WebhookRequest<'_>) -> Result<WebhookResponse, ChannelError> {
        let payload: serde_json::Value =
            serde_json::from_slice(request.body()).expect("adapter emits JSON");
        let text = payload[self.field]
            .as_str()
            .expect("adapter emits the payload field as a string");
        self.posts.borrow_mut().push(text.to_owned());
        let status = match self.fail_from {
            Some(first) if self.posts.borrow().len() > first => 500,
            _ => 200,
        };
        Ok(WebhookResponse { status })
    }
}

fn webhook_credential(channel_id: &str) -> ChannelCredential {
    ChannelCredential::bind(
        format!("https://{channel_id}.example/hooks/primary"),
        CredentialRequest {
            channel_id: channel_id.to_owned(),
            account_id: "primary".to_owned(),
            kind: CredentialKind::WebhookUrl,
            binding: CredentialBinding::EmbeddedEndpoint,
        },
    )
    .expect("valid embedded-endpoint binding")
}

fn outbound(text: &str) -> OutboundMessage {
    OutboundMessage {
        correlation_key: "delivery-1".to_owned(),
        account_id: "primary".to_owned(),
        conversation_id: "room-1".to_owned(),
        text: Some(text.to_owned()),
        attachments: Vec::new(),
        reply_to: None,
    }
}

#[test]
fn exactly_the_four_channels_with_a_stated_limit_declare_one() {
    let mut declared: Vec<(&str, u32)> = registry()
        .iter()
        .filter_map(|entry| {
            entry
                .output_limit
                .map(|limit| (entry.id, limit.max().get()))
        })
        .collect();
    declared.sort_unstable();

    assert_eq!(declared, PROVEN_LIMITS.to_vec());
}

#[test]
fn the_other_twenty_five_channels_declare_no_limit() {
    let absent = registry()
        .iter()
        .filter(|entry| entry.output_limit.is_none())
        .count();

    assert_eq!(absent, 25);
    assert_eq!(registry().len(), 25 + PROVEN_LIMITS.len());
}

#[test]
fn declared_limits_count_utf16_code_units_like_the_legacy_call_sites() {
    for (id, _) in PROVEN_LIMITS {
        let limit = output_limit(id)
            .expect("registered channel")
            .expect("proven limit");

        assert_eq!(limit.unit(), LengthUnit::Utf16CodeUnits, "{id}");
    }
}

#[test]
fn a_declared_limit_does_not_promote_a_registration_only_channel() {
    for id in ["msteams", "telegram", "whatsapp"] {
        let entry = descriptor(id).expect("registered channel");

        assert!(entry.output_limit.is_some(), "{id}");
        assert_eq!(
            entry.implementation,
            ImplementationStatus::RegistrationOnly,
            "{id}"
        );
        assert!(entry.capabilities.is_empty(), "{id}");
    }
}

#[test]
fn the_other_webhook_channels_still_have_no_proven_limit() {
    for id in ["slack", "googlechat", "mattermost"] {
        let entry = descriptor(id).expect("registered channel");

        assert_eq!(
            entry.implementation,
            ImplementationStatus::OutboundWebhook,
            "{id}"
        );
        assert!(
            entry
                .capabilities
                .contains(&ChannelCapability::OutboundText)
        );
        assert_eq!(entry.output_limit, None, "{id}");
    }
}

#[test]
fn output_limit_separates_an_unknown_channel_from_an_unknown_limit() {
    assert_eq!(
        output_limit("not-a-channel"),
        Err(RoutingError::UnknownChannel)
    );
    assert_eq!(output_limit("slack"), Ok(None));
    assert!(
        output_limit("discord")
            .expect("registered channel")
            .is_some()
    );
}

#[test]
fn segmentation_refuses_a_channel_whose_limit_is_unproven() {
    assert_eq!(
        segment_outbound_text("slack", &"a".repeat(10_000)),
        Err(OutboundTextError::NoProvenLimit)
    );
}

#[test]
fn segmentation_refuses_an_unregistered_channel() {
    assert_eq!(
        segment_outbound_text("not-a-channel", "hello"),
        Err(OutboundTextError::UnknownChannel)
    );
}

#[test]
fn segmentation_reports_text_it_cannot_split() {
    // One zero-width-joined cluster wider than the whole budget has no legal
    // cut anywhere inside it, so refusing beats emitting half a glyph.
    let mut indivisible = String::from("\u{1f469}");
    for _ in 0..1_000 {
        indivisible.push_str("\u{200d}\u{1f469}");
    }

    assert_eq!(
        segment_outbound_text("discord", &indivisible),
        Err(OutboundTextError::Segmentation(
            SegmentationError::IndivisibleCluster
        ))
    );
}

#[test]
fn a_run_of_joined_emoji_is_cut_only_between_clusters() {
    let cluster = "\u{1f469}\u{200d}\u{1f4bb}";
    let run = cluster.repeat(2_000);
    let segments = segment_outbound_text("discord", &run).expect("segmented");

    assert!(segments.len() > 1);
    for segment in &segments {
        assert_eq!(segment.len() % cluster.len(), 0);
        assert!(segment.starts_with(cluster));
        assert!(segment.ends_with(cluster));
    }
}

#[test]
fn text_at_the_declared_limit_stays_one_segment() {
    let exact = "a".repeat(1_900);
    let segments = segment_outbound_text("discord", &exact).expect("segmented");

    assert_eq!(segments, vec![exact.as_str()]);
}

#[test]
fn text_one_unit_over_the_declared_limit_becomes_two_segments() {
    let over = "a".repeat(1_901);
    let segments = segment_outbound_text("discord", &over).expect("segmented");

    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].len(), 1_900);
    assert_eq!(segments[1].len(), 1);
}

#[test]
fn every_segment_respects_the_declared_limit_of_every_proven_channel() {
    let text = "paragraph one\n\nparagraph two with several words\n"
        .repeat(400)
        .replace("two", "two \u{1f469}\u{200d}\u{1f469}\u{200d}\u{1f466}");

    for (id, max) in PROVEN_LIMITS {
        let limit = NonZeroU32::new(max).expect("nonzero limit");
        let segments = segment_outbound_text(id, &text).expect("segmented");

        assert!(!segments.is_empty(), "{id}");
        for segment in &segments {
            let units: usize = segment.chars().map(char::len_utf16).sum();
            assert!(!segment.is_empty(), "{id}");
            assert!(units <= limit.get() as usize, "{id}: {units} > {max}");
        }
    }
}

#[test]
fn a_short_message_posts_exactly_one_request() {
    let posts: PostedBodies = Rc::new(RefCell::new(Vec::new()));
    let mut channel = WebhookChannel::new(
        "discord",
        "primary",
        "room-1",
        RecordingTransport::new("content", &posts),
        FixedClock(77),
    )
    .expect("webhook-capable channel");

    channel
        .send_outbound(
            &outbound("hello fixture"),
            Some(&webhook_credential("discord")),
        )
        .expect("accepted");

    assert_eq!(*posts.borrow(), vec!["hello fixture".to_owned()]);
}

#[test]
fn a_message_over_the_discord_limit_posts_one_request_per_segment() {
    let posts: PostedBodies = Rc::new(RefCell::new(Vec::new()));
    let mut channel = WebhookChannel::new(
        "discord",
        "primary",
        "room-1",
        RecordingTransport::new("content", &posts),
        FixedClock(77),
    )
    .expect("webhook-capable channel");
    let text = "a".repeat(4_000);

    channel
        .send_outbound(&outbound(&text), Some(&webhook_credential("discord")))
        .expect("accepted");

    let posted = posts.borrow();
    assert_eq!(posted.len(), 3);
    assert_eq!(
        posted.iter().map(String::len).collect::<Vec<_>>(),
        vec![1_900, 1_900, 200]
    );
    assert_eq!(posted.concat(), text);
}

#[test]
fn a_long_message_on_a_channel_without_a_proven_limit_posts_unsegmented() {
    let posts: PostedBodies = Rc::new(RefCell::new(Vec::new()));
    let mut channel = WebhookChannel::new(
        "slack",
        "primary",
        "room-1",
        RecordingTransport::new("text", &posts),
        FixedClock(77),
    )
    .expect("webhook-capable channel");
    let text = "a".repeat(4_000);

    channel
        .send_outbound(&outbound(&text), Some(&webhook_credential("slack")))
        .expect("accepted");

    assert_eq!(*posts.borrow(), vec![text]);
}

#[test]
fn a_segmented_send_stops_at_the_first_rejected_segment() {
    let posts: PostedBodies = Rc::new(RefCell::new(Vec::new()));
    let mut channel = WebhookChannel::new(
        "discord",
        "primary",
        "room-1",
        RecordingTransport::failing_from("content", &posts, 1),
        FixedClock(77),
    )
    .expect("webhook-capable channel");

    let result = channel.send_outbound(
        &outbound(&"a".repeat(4_000)),
        Some(&webhook_credential("discord")),
    );

    assert_eq!(result, Err(ChannelError::RemoteRejected { status: 500 }));
    // The first segment was already delivered, which is exactly why this
    // adapter reports its outbound sends as unsafe to repeat.
    assert_eq!(posts.borrow().len(), 2);
}

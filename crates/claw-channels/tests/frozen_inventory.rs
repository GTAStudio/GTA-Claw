//! Frozen official channel inventory parity.

use std::collections::BTreeSet;
use std::path::Path;

use claw_channels::{AuthMode, ChannelCapability, ImplementationStatus, descriptor, registry};
use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct Inventory {
    counts: InventoryCounts,
    items: Vec<InventoryItem>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct InventoryCounts {
    total: usize,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct InventoryItem {
    record_id: String,
    id: String,
    classification: String,
    source_path: String,
    plugin_id: Option<String>,
    package_name: Option<String>,
    provenance: String,
    catalog_package: Option<String>,
    catalog_source_path: Option<String>,
}

fn frozen_inventory() -> Inventory {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compat/upstream/inventories/channels.json");
    let json = std::fs::read_to_string(path).expect("read frozen inventory");
    serde_json::from_str(json.trim_start_matches('\u{feff}')).expect("valid frozen inventory")
}

#[test]
fn registry_matches_every_frozen_identity_and_provenance_field() {
    let frozen = frozen_inventory();
    let actual = registry()
        .iter()
        .map(|entry| InventoryItem {
            record_id: entry.record_id.to_owned(),
            id: entry.id.to_owned(),
            classification: entry.classification.to_owned(),
            source_path: entry.source_path.to_owned(),
            plugin_id: entry.plugin_id.map(str::to_owned),
            package_name: entry.package_name.map(str::to_owned),
            provenance: entry.provenance.to_owned(),
            catalog_package: entry.catalog_package.map(str::to_owned),
            catalog_source_path: entry.catalog_source_path.map(str::to_owned),
        })
        .collect::<Vec<_>>();

    assert_eq!(frozen.counts.total, 29);
    assert_eq!(frozen.items.len(), frozen.counts.total);
    assert_eq!(actual.len(), frozen.counts.total);
    assert_eq!(actual, frozen.items);
}

#[test]
fn frozen_channel_identifiers_are_unique_and_individually_resolvable() {
    let frozen = frozen_inventory();
    let ids = frozen
        .items
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    let record_ids = frozen
        .items
        .iter()
        .map(|item| item.record_id.as_str())
        .collect::<BTreeSet<_>>();

    assert_eq!(ids.len(), frozen.counts.total);
    assert_eq!(record_ids.len(), frozen.counts.total);
    for item in &frozen.items {
        let entry = descriptor(&item.id)
            .unwrap_or_else(|| panic!("frozen channel {} is unregistered", item.id));
        assert_eq!(entry.id, item.id);
        assert_eq!(entry.record_id, item.record_id);
        assert_eq!(entry.record_id, format!("channel:{}", item.id));
    }
    assert_eq!(registry().len(), frozen.counts.total);
    assert_eq!(
        registry()
            .iter()
            .map(|entry| entry.id)
            .collect::<BTreeSet<_>>(),
        ids,
        "the registry must hold every frozen identifier and no other"
    );
    for absent in ["", "channel:slack", "SLACK", "slack ", " slack", "slack/"] {
        assert!(descriptor(absent).is_none(), "{absent:?}");
    }
}

#[test]
fn executable_capabilities_are_never_claimed_by_registration_only_entries() {
    let registration_only = registry()
        .iter()
        .filter(|entry| entry.implementation == ImplementationStatus::RegistrationOnly)
        .map(|entry| (entry.id, entry.capabilities))
        .collect::<Vec<_>>();
    assert!(
        registration_only
            .iter()
            .all(|(_, capabilities)| capabilities.is_empty())
    );

    let qa = registry()
        .iter()
        .find(|entry| entry.id == "qa-channel")
        .expect("QA descriptor");
    assert_eq!(qa.auth_modes, &[AuthMode::None]);
    assert_eq!(
        qa.capabilities,
        &[
            ChannelCapability::InboundText,
            ChannelCapability::OutboundText
        ]
    );
    assert_eq!(qa.implementation, ImplementationStatus::Full);
}

#[test]
fn declared_auth_policy_covers_frozen_channel_ids_exactly() {
    // Authentication is crate-owned policy: the frozen inventory has no auth
    // fields. Keeping this table independent makes policy changes deliberate,
    // while exact ID-set equality prevents upstream additions or removals from
    // silently escaping review.
    let expected = [
        ("mattermost", vec![AuthMode::WebhookUrl]),
        ("msteams", vec![AuthMode::AppCredentials]),
        ("feishu", vec![AuthMode::AppCredentials]),
        ("sms", vec![AuthMode::AppCredentials]),
        ("openclaw-weixin", vec![AuthMode::ExternalPlugin]),
        ("googlechat", vec![AuthMode::WebhookUrl]),
        ("clickclack", vec![AuthMode::BotToken]),
        ("line", vec![AuthMode::AccessToken, AuthMode::WebhookSecret]),
        ("zalouser", vec![AuthMode::PlatformSession]),
        ("zalo", vec![AuthMode::BotToken, AuthMode::WebhookSecret]),
        ("imessage", vec![AuthMode::PlatformSession]),
        ("matrix", vec![AuthMode::AccessToken]),
        ("yuanbao", vec![AuthMode::ExternalPlugin]),
        ("signal", vec![AuthMode::LocalService]),
        ("qa-channel", vec![AuthMode::None]),
        ("wecom", vec![AuthMode::AppCredentials]),
        (
            "nextcloud-talk",
            vec![AuthMode::BotToken, AuthMode::Password],
        ),
        ("slack", vec![AuthMode::WebhookUrl]),
        ("discord", vec![AuthMode::WebhookUrl]),
        ("twitch", vec![AuthMode::OAuth2]),
        ("openclaw-zaloclawbot", vec![AuthMode::ExternalPlugin]),
        (
            "synology-chat",
            vec![AuthMode::AccessToken, AuthMode::WebhookSecret],
        ),
        ("raft", vec![AuthMode::Profile]),
        ("tlon", vec![AuthMode::Password]),
        ("nostr", vec![AuthMode::PrivateKey]),
        ("whatsapp", vec![AuthMode::PlatformSession]),
        ("telegram", vec![AuthMode::BotToken]),
        ("qqbot", vec![AuthMode::AppCredentials]),
        ("irc", vec![AuthMode::OptionalPassword]),
    ];
    let actual = registry()
        .iter()
        .map(|entry| (entry.id, entry.auth_modes.to_vec()))
        .collect::<Vec<_>>();
    let frozen_ids = frozen_inventory()
        .items
        .into_iter()
        .map(|entry| entry.id)
        .collect::<BTreeSet<_>>();
    let expected_ids = expected
        .iter()
        .map(|(id, _)| (*id).to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(expected_ids, frozen_ids);
    assert_eq!(actual, expected);
}

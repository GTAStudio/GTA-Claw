//! Frozen official channel inventory parity.

use claw_channels::{AuthMode, ChannelCapability, ImplementationStatus, registry};
use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct Inventory {
    items: Vec<InventoryItem>,
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

#[test]
fn registry_matches_every_frozen_identity_and_provenance_field() {
    let json = include_str!("../../../compat/upstream/inventories/channels.json")
        .trim_start_matches('\u{feff}');
    let frozen: Inventory = serde_json::from_str(json).expect("valid frozen inventory");
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

    assert_eq!(frozen.items.len(), 29);
    assert_eq!(actual, frozen.items);
}

#[test]
fn executable_capabilities_are_never_claimed_by_registration_only_entries() {
    let registration_only = registry()
        .iter()
        .filter(|entry| entry.implementation == ImplementationStatus::RegistrationOnly)
        .map(|entry| (entry.id, entry.capabilities))
        .collect::<Vec<_>>();
    assert_eq!(registration_only.len(), 24);
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
fn registry_auth_modes_match_frozen_plugin_configuration_contracts() {
    let expected = [
        ("mattermost", vec![AuthMode::BotToken]),
        ("msteams", vec![AuthMode::AppCredentials]),
        ("feishu", vec![AuthMode::AppCredentials]),
        ("sms", vec![AuthMode::AppCredentials]),
        ("openclaw-weixin", vec![AuthMode::ExternalPlugin]),
        ("googlechat", vec![AuthMode::ServiceAccount]),
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
        ("slack", vec![AuthMode::BotToken]),
        ("discord", vec![AuthMode::BotToken]),
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
    assert_eq!(actual, expected);
}

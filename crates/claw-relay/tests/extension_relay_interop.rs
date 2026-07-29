//! Acceptance tests for the Chrome MV3 extension relay and its CDP bridge.
//!
//! Each test covers exactly one required interop dimension: MV3 pairing, relay
//! authentication, WebSocket subprotocol negotiation, CDP target addressing,
//! the screenshot request/response contract, and disconnect cleanup.
//!
//! No browser is launched and no socket is opened. The relay crate is transport
//! independent, so an HTTP/WebSocket adapter is modelled by feeding it the
//! upgrade metadata, the discovery requests and the complete text frames a real
//! adapter would hand over. `tests/fixtures/chrome-extension/manifest.json` is
//! the upstream MV3 manifest, used here as data under test.

use claw_relay::{
    BridgeEffect, CdpBridge, CdpErrorObject, CdpRequest, CdpResponse, DiscoveryRequest,
    EndpointError, ExtensionCommand, ExtensionId, ExtensionMessage, ExtensionPairing, Mv3Manifest,
    NOT_PAIRED_MESSAGE, PairingError, PairingOffer, PeerKind, RELAY_SUBPROTOCOL,
    RELAY_TOKEN_SUBPROTOCOL_PREFIX, RelayEndpoint, RelayTab, RelayToken, UpgradeRequest,
    credential_from_authorization, serve_discovery,
};
use serde_json::{Map, Value, json};

/// Upstream Chrome MV3 manifest, byte-for-byte, as test data.
const UPSTREAM_MANIFEST: &[u8] = include_bytes!("fixtures/chrome-extension/manifest.json");

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER_TOKEN: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const PAIRED_EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";
const UNPAIRED_EXTENSION_ID: &str = "ponmlkjihgfedcbaponmlkjihgfedcba";
const AUTHORITY: &str = "127.0.0.1:18792";
/// `Basic` credentials carrying `gta-claw:<TOKEN>`.
const BASIC_HEADER: &str = "Basic Z3RhLWNsYXc6MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZg==";

fn manifest() -> Mv3Manifest {
    Mv3Manifest::parse(UPSTREAM_MANIFEST).expect("upstream MV3 manifest")
}

fn variant_manifest(mutate: impl FnOnce(&mut Map<String, Value>)) -> Vec<u8> {
    let mut document: Map<String, Value> =
        serde_json::from_slice(UPSTREAM_MANIFEST).expect("upstream MV3 manifest object");
    mutate(&mut document);
    serde_json::to_vec(&Value::Object(document)).expect("re-encoded manifest")
}

fn offer() -> PairingOffer {
    PairingOffer::new(AUTHORITY, TOKEN).expect("loopback pairing offer")
}

fn pairing(extension_id: &str) -> ExtensionPairing {
    ExtensionPairing::new(
        ExtensionId::new(extension_id).expect("canonical extension ID"),
        manifest(),
        offer(),
    )
}

fn endpoint() -> RelayEndpoint {
    RelayEndpoint::new(
        RelayToken::from_hex(TOKEN).expect("canonical relay token"),
        [ExtensionId::new(PAIRED_EXTENSION_ID).expect("canonical extension ID")],
        4096,
        8,
    )
    .expect("relay endpoint")
}

fn cdp_upgrade(token: Option<&str>) -> UpgradeRequest {
    UpgradeRequest {
        path: "/cdp".to_owned(),
        host: AUTHORITY.to_owned(),
        origin: None,
        subprotocols: Vec::new(),
        authorization_token: token.map(str::to_owned),
    }
}

fn discovery_request(method: &str, path: &str, token: Option<&str>) -> DiscoveryRequest {
    DiscoveryRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        host: AUTHORITY.to_owned(),
        authorization_token: token.map(str::to_owned),
    }
}

fn tab(tab_id: u64, title: &str, active: bool) -> RelayTab {
    RelayTab {
        tab_id,
        url: format!("https://example.test/{tab_id}"),
        title: title.to_owned(),
        active,
    }
}

fn hello(tabs: Vec<RelayTab>) -> ExtensionMessage {
    ExtensionMessage::Hello {
        user_agent: "FixtureBrowser/1".to_owned(),
        browser_version: "Chrome/144.0.0.0".to_owned(),
        extension_version: "2.0.0".to_owned(),
        tabs,
    }
}

/// A paired extension, one CDP client, and one shared tab already attached.
struct AttachedRelay {
    endpoint: RelayEndpoint,
    bridge: CdpBridge,
    extension: claw_relay::ConnectionId,
    client: claw_relay::ConnectionId,
}

fn attached_relay() -> AttachedRelay {
    let mut endpoint = endpoint();
    let extension = endpoint
        .negotiate(&pairing(PAIRED_EXTENSION_ID).upgrade_request())
        .expect("paired extension")
        .connection;
    let client = endpoint
        .negotiate(&cdp_upgrade(Some(TOKEN)))
        .expect("authenticated CDP client")
        .connection;
    let mut bridge = CdpBridge::new();
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(client).expect("first CDP client");
    assert_eq!(
        bridge
            .receive_extension(extension, hello(vec![tab(41, "Shared", true)]))
            .expect("mandatory hello"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_cdp(
                client,
                CdpRequest {
                    id: 1,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "tab-41" })),
                    session_id: None,
                },
            )
            .expect("attach request"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 1,
            tab_id: 41,
        })]
    );
    let attached = bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "chrome-target-41" })),
            },
        )
        .expect("attach result");
    assert_eq!(
        attached.last(),
        Some(&BridgeEffect::ToCdp {
            connection: client,
            response: CdpResponse {
                id: 1,
                session_id: None,
                result: Some(json!({ "sessionId": "gta-claw-tab-1" })),
                error: None,
            },
        })
    );
    AttachedRelay {
        endpoint,
        bridge,
        extension,
        client,
    }
}

#[test]
fn mv3_pairing_admits_the_paired_extension_and_refuses_unpaired_ones() {
    let manifest = manifest();
    assert_eq!(manifest.name(), "OpenClaw");
    assert_eq!(manifest.version(), "2.0.0");
    assert_eq!(manifest.service_worker(), "background.js");
    assert_eq!(manifest.minimum_chrome_version(), 125);
    assert_eq!(
        manifest.permissions().collect::<Vec<_>>(),
        vec!["alarms", "debugger", "storage", "tabGroups", "tabs"]
    );

    for (mutation, reason) in [
        (
            variant_manifest(|document| {
                document.insert("manifest_version".to_owned(), json!(2));
            }),
            PairingError::NotManifestV3,
        ),
        (
            variant_manifest(|document| {
                document.insert("host_permissions".to_owned(), json!(["<all_urls>"]));
            }),
            PairingError::ForbiddenManifestKey("host_permissions"),
        ),
        (
            variant_manifest(|document| {
                document.insert(
                    "content_scripts".to_owned(),
                    json!([{ "matches": ["<all_urls>"], "js": ["inject.js"] }]),
                );
            }),
            PairingError::ForbiddenManifestKey("content_scripts"),
        ),
        (
            variant_manifest(|document| {
                document.insert(
                    "permissions".to_owned(),
                    json!(["tabs", "tabGroups", "storage", "alarms"]),
                );
            }),
            PairingError::MissingPermission("debugger"),
        ),
        (
            variant_manifest(|document| {
                document.insert(
                    "permissions".to_owned(),
                    json!([
                        "debugger",
                        "tabs",
                        "tabGroups",
                        "storage",
                        "alarms",
                        "cookies"
                    ]),
                );
            }),
            PairingError::ForbiddenPermission("cookies".to_owned()),
        ),
        (
            variant_manifest(|document| {
                document.insert(
                    "background".to_owned(),
                    json!({ "service_worker": "background.js" }),
                );
            }),
            PairingError::MissingServiceWorker,
        ),
        (
            variant_manifest(|document| {
                document.insert(
                    "optional_permissions".to_owned(),
                    json!(["cookies", "history"]),
                );
            }),
            PairingError::ForbiddenManifestKey("optional_permissions"),
        ),
        (
            variant_manifest(|document| {
                document.insert("minimum_chrome_version".to_owned(), json!("120"));
            }),
            PairingError::UnsupportedChromeVersion,
        ),
    ] {
        assert_eq!(Mv3Manifest::parse(&mutation), Err(reason));
    }

    let offer = offer();
    assert_eq!(
        offer.pairing_string(),
        format!("ws://{AUTHORITY}/extension#{TOKEN}")
    );
    assert_eq!(offer.relay_url(), format!("ws://{AUTHORITY}/extension"));
    assert!(!format!("{offer:?}").contains(TOKEN));
    assert_eq!(PairingOffer::parse(&offer.pairing_string()), Ok(offer));
    for (raw, reason) in [
        (
            format!("ws://{AUTHORITY}/extension"),
            PairingError::MalformedPairingString,
        ),
        (
            format!("http://{AUTHORITY}/extension#{TOKEN}"),
            PairingError::MalformedPairingString,
        ),
        (
            format!("ws://{AUTHORITY}/cdp#{TOKEN}"),
            PairingError::MalformedPairingString,
        ),
        (
            format!("ws://relay.attacker.test:18792/extension#{TOKEN}"),
            PairingError::NonLoopbackRelay,
        ),
        (
            format!("ws://127.0.0.1/extension#{TOKEN}"),
            PairingError::NonLoopbackRelay,
        ),
        (
            format!("ws://localhost:0/extension#{TOKEN}"),
            PairingError::NonLoopbackRelay,
        ),
        (
            format!("ws://127.0.0.1:18792 /extension#{TOKEN}"),
            PairingError::NonLoopbackRelay,
        ),
        (
            format!("ws://{AUTHORITY}/extension#{}", TOKEN.to_uppercase()),
            PairingError::MalformedToken,
        ),
    ] {
        assert_eq!(PairingOffer::parse(&raw), Err(reason), "{raw}");
    }

    let paired = pairing(PAIRED_EXTENSION_ID);
    let request = paired.upgrade_request();
    assert_eq!(request.path, "/extension");
    assert_eq!(request.host, AUTHORITY);
    assert_eq!(
        request.origin.as_deref(),
        Some(format!("chrome-extension://{PAIRED_EXTENSION_ID}").as_str())
    );

    let mut endpoint = endpoint();
    let accepted = endpoint.negotiate(&request).expect("paired MV3 extension");
    assert_eq!(accepted.peer, PeerKind::Extension);
    assert_eq!(
        endpoint.peer(accepted.connection),
        Some(PeerKind::Extension)
    );

    let unpaired = pairing(UNPAIRED_EXTENSION_ID).upgrade_request();
    assert_eq!(
        endpoint.negotiate(&unpaired),
        Err(EndpointError::UnknownExtension)
    );
    assert_eq!(endpoint.connection_count(), 1);
}

#[test]
fn relay_auth_rejects_every_wrong_credential_and_names_the_reason() {
    let mut endpoint = endpoint();

    let mut wrong_secret = pairing(PAIRED_EXTENSION_ID).upgrade_request();
    wrong_secret.subprotocols = vec![
        RELAY_SUBPROTOCOL.to_owned(),
        format!("{RELAY_TOKEN_SUBPROTOCOL_PREFIX}{OTHER_TOKEN}"),
    ];
    assert_eq!(
        endpoint.negotiate(&wrong_secret),
        Err(EndpointError::AuthenticationFailed)
    );

    let mut no_secret = pairing(PAIRED_EXTENSION_ID).upgrade_request();
    no_secret.subprotocols = vec![RELAY_SUBPROTOCOL.to_owned()];
    assert_eq!(
        endpoint.negotiate(&no_secret),
        Err(EndpointError::AuthenticationFailed)
    );

    for candidate in [
        None,
        Some(OTHER_TOKEN.to_owned()),
        Some(TOKEN[..63].to_owned()),
        Some(TOKEN.to_uppercase()),
        Some(String::new()),
    ] {
        assert_eq!(
            endpoint.negotiate(&cdp_upgrade(candidate.as_deref())),
            Err(EndpointError::AuthenticationFailed),
            "{candidate:?}"
        );
    }
    assert_eq!(
        EndpointError::AuthenticationFailed.to_string(),
        "relay authentication failed"
    );
    assert_eq!(endpoint.connection_count(), 0);

    assert_eq!(
        credential_from_authorization(&format!("Bearer {TOKEN}")).as_deref(),
        Some(TOKEN)
    );
    assert_eq!(
        credential_from_authorization(BASIC_HEADER).as_deref(),
        Some(TOKEN)
    );
    assert_eq!(
        credential_from_authorization("Basic dXNlcjpwYXNz").as_deref(),
        Some("pass")
    );
    assert_eq!(
        credential_from_authorization("Basic cGFzcw==").as_deref(),
        Some("pass")
    );
    for header in [
        "Bearer ",
        "Basic ",
        "Basic ****",
        "Basic dXNlcjo=",
        &format!("Digest {TOKEN}"),
        TOKEN,
    ] {
        assert_eq!(credential_from_authorization(header), None, "{header}");
    }

    let recovered = credential_from_authorization(BASIC_HEADER).expect("basic credential");
    let accepted = endpoint
        .negotiate(&cdp_upgrade(Some(&recovered)))
        .expect("authenticated CDP client");
    assert_eq!(accepted.peer, PeerKind::Cdp);
    assert_eq!(endpoint.connection_count(), 1);
}

#[test]
fn websocket_subprotocol_negotiation_selects_relay_and_refuses_unsupported_offers() {
    let mut endpoint = endpoint();
    let request = pairing(PAIRED_EXTENSION_ID).upgrade_request();
    assert_eq!(
        request.subprotocols,
        vec![
            RELAY_SUBPROTOCOL.to_owned(),
            format!("{RELAY_TOKEN_SUBPROTOCOL_PREFIX}{TOKEN}"),
        ]
    );

    let extension = endpoint.negotiate(&request).expect("paired extension");
    let selected = extension.subprotocol.expect("negotiated subprotocol");
    assert_eq!(selected, RELAY_SUBPROTOCOL);
    assert!(
        !format!("{extension:?}").contains(TOKEN),
        "no part of the handshake response may carry the relay secret"
    );

    let client = endpoint
        .negotiate(&cdp_upgrade(Some(TOKEN)))
        .expect("authenticated CDP client");
    assert_eq!(client.subprotocol, None);

    let mut missing_relay = request.clone();
    missing_relay.subprotocols = vec![format!("{RELAY_TOKEN_SUBPROTOCOL_PREFIX}{TOKEN}")];
    assert_eq!(
        endpoint.negotiate(&missing_relay),
        Err(EndpointError::MissingRelaySubprotocol)
    );

    let mut unknown = request.clone();
    unknown.subprotocols.push("chrome-devtools".to_owned());
    assert_eq!(
        endpoint.negotiate(&unknown),
        Err(EndpointError::UnsupportedSubprotocol)
    );

    let mut repeated_relay = request.clone();
    repeated_relay
        .subprotocols
        .push(RELAY_SUBPROTOCOL.to_owned());
    assert_eq!(
        endpoint.negotiate(&repeated_relay),
        Err(EndpointError::UnsupportedSubprotocol)
    );

    let mut duplicated = request.clone();
    duplicated
        .subprotocols
        .push(format!("{RELAY_TOKEN_SUBPROTOCOL_PREFIX}{OTHER_TOKEN}"));
    assert_eq!(
        endpoint.negotiate(&duplicated),
        Err(EndpointError::DuplicateTokenSubprotocol)
    );

    let mut cdp_offer = cdp_upgrade(Some(TOKEN));
    cdp_offer.subprotocols = vec![RELAY_SUBPROTOCOL.to_owned()];
    assert_eq!(
        endpoint.negotiate(&cdp_offer),
        Err(EndpointError::UnsupportedSubprotocol)
    );

    assert_eq!(endpoint.connection_count(), 2);
    assert_eq!(
        EndpointError::UnsupportedSubprotocol.to_string(),
        "relay WebSocket subprotocol is not supported"
    );
}

#[test]
fn cdp_target_discovery_addresses_only_explicitly_shared_tabs() {
    let mut endpoint = endpoint();
    let extension = endpoint
        .negotiate(&pairing(PAIRED_EXTENSION_ID).upgrade_request())
        .expect("paired extension")
        .connection;
    let client = endpoint
        .negotiate(&cdp_upgrade(Some(TOKEN)))
        .expect("authenticated CDP client")
        .connection;
    let mut bridge = CdpBridge::new();
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(client).expect("first CDP client");

    assert!(!bridge.is_paired());
    for path in ["/json/version", "/json", "/json/list"] {
        let unpaired = serve_discovery(
            &endpoint,
            &bridge,
            &discovery_request("GET", path, Some(TOKEN)),
        );
        assert_eq!(unpaired.status, 503, "{path}");
        assert_eq!(
            unpaired.body,
            json!({ "error": NOT_PAIRED_MESSAGE }),
            "{path}"
        );
    }

    assert_eq!(
        bridge
            .receive_extension(
                extension,
                hello(vec![tab(41, "First", true), tab(42, "Second", false)]),
            )
            .expect("mandatory hello"),
        Vec::new()
    );
    assert!(bridge.is_paired());

    let version = serve_discovery(
        &endpoint,
        &bridge,
        &discovery_request("GET", "/json/version", Some(TOKEN)),
    );
    assert_eq!(version.status, 200);
    assert_eq!(
        version.body,
        json!({
            "Browser": "Chrome/144.0.0.0",
            "Protocol-Version": "1.3",
            "User-Agent": "FixtureBrowser/1",
            "webSocketDebuggerUrl": format!("ws://{AUTHORITY}/cdp"),
        })
    );

    let list = serve_discovery(
        &endpoint,
        &bridge,
        &discovery_request("GET", "/json/list", Some(TOKEN)),
    );
    assert_eq!(list.status, 200);
    assert_eq!(
        list.body,
        json!([
            { "tabId": 41, "url": "https://example.test/41", "title": "First", "active": true },
            { "tabId": 42, "url": "https://example.test/42", "title": "Second", "active": false },
        ])
    );

    for (request, status) in [
        (discovery_request("GET", "/json/version", None), 401),
        (
            discovery_request("GET", "/json/version", Some(OTHER_TOKEN)),
            401,
        ),
        (discovery_request("GET", "/json/protocol", Some(TOKEN)), 404),
        (discovery_request("POST", "/json/version", Some(TOKEN)), 405),
    ] {
        let response = serve_discovery(&endpoint, &bridge, &request);
        assert_eq!(response.status, status, "{request:?}");
        assert_eq!(response.authenticate, status == 401, "{request:?}");
    }
    let mut foreign = discovery_request("GET", "/json/version", Some(TOKEN));
    foreign.host = "relay.attacker.test".to_owned();
    assert_eq!(serve_discovery(&endpoint, &bridge, &foreign).status, 403);
    assert!(
        !format!("{foreign:?}").contains(TOKEN),
        "a logged discovery request may not carry the relay secret"
    );

    let discovery = bridge
        .receive_cdp(
            client,
            CdpRequest {
                id: 1,
                method: "Target.getTargets".to_owned(),
                params: None,
                session_id: None,
            },
        )
        .expect("target discovery");
    assert_eq!(
        discovery,
        vec![BridgeEffect::ToCdp {
            connection: client,
            response: CdpResponse {
                id: 1,
                session_id: None,
                result: Some(json!({
                    "targetInfos": [
                        {
                            "targetId": "tab-41",
                            "type": "page",
                            "title": "First",
                            "url": "https://example.test/41",
                            "browserContextId": "openclaw-extension-context",
                            "attached": false,
                            "canAccessOpener": false,
                        },
                        {
                            "targetId": "tab-42",
                            "type": "page",
                            "title": "Second",
                            "url": "https://example.test/42",
                            "browserContextId": "openclaw-extension-context",
                            "attached": false,
                            "canAccessOpener": false,
                        },
                    ]
                })),
                error: None,
            },
        }]
    );

    assert_eq!(
        bridge
            .receive_cdp(
                client,
                CdpRequest {
                    id: 2,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "tab-42" })),
                    session_id: None,
                },
            )
            .expect("attach to a shared target"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 1,
            tab_id: 42,
        })]
    );

    let unshared = bridge
        .receive_cdp(
            client,
            CdpRequest {
                id: 3,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-99" })),
                session_id: None,
            },
        )
        .expect("unshared target is answered, not routed");
    assert_eq!(
        unshared,
        vec![BridgeEffect::ToCdp {
            connection: client,
            response: CdpResponse {
                id: 3,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32602,
                    message: "target not found".to_owned(),
                }),
            },
        }]
    );
}

#[test]
fn page_capture_screenshot_round_trips_through_the_paired_extension() {
    let AttachedRelay {
        mut endpoint,
        mut bridge,
        extension,
        client,
    } = attached_relay();

    let forwarded = bridge
        .receive_cdp(
            client,
            CdpRequest {
                id: 2,
                method: "Page.captureScreenshot".to_owned(),
                params: Some(json!({ "format": "png", "captureBeyondViewport": false })),
                session_id: Some("gta-claw-tab-1".to_owned()),
            },
        )
        .expect("policy-allowed screenshot");
    assert_eq!(
        forwarded,
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 2,
            tab_id: 41,
            session_id: None,
            method: "Page.captureScreenshot".to_owned(),
            params: Some(json!({ "format": "png", "captureBeyondViewport": false })),
        })]
    );

    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 2,
                    result: Some(json!({ "data": "iVBORw0KGgo=" })),
                },
            )
            .expect("screenshot result"),
        vec![BridgeEffect::ToCdp {
            connection: client,
            response: CdpResponse {
                id: 2,
                session_id: Some("gta-claw-tab-1".to_owned()),
                result: Some(json!({ "data": "iVBORw0KGgo=" })),
                error: None,
            },
        }]
    );

    assert_eq!(
        bridge
            .receive_cdp(
                client,
                CdpRequest {
                    id: 3,
                    method: "Page.captureScreenshot".to_owned(),
                    params: None,
                    session_id: Some("gta-claw-tab-1".to_owned()),
                },
            )
            .expect("second screenshot"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 3,
            tab_id: 41,
            session_id: None,
            method: "Page.captureScreenshot".to_owned(),
            params: None,
        })]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Error {
                    seq: 3,
                    message: "Chrome refused the capture".to_owned(),
                },
            )
            .expect("screenshot failure"),
        vec![BridgeEffect::ToCdp {
            connection: client,
            response: CdpResponse {
                id: 3,
                session_id: Some("gta-claw-tab-1".to_owned()),
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "Chrome refused the capture".to_owned(),
                }),
            },
        }]
    );

    let sessionless = bridge
        .receive_cdp(
            client,
            CdpRequest {
                id: 4,
                method: "Page.captureScreenshot".to_owned(),
                params: None,
                session_id: None,
            },
        )
        .expect("session-less screenshot is answered, not routed");
    assert_eq!(
        sessionless,
        vec![BridgeEffect::ToCdp {
            connection: client,
            response: CdpResponse {
                id: 4,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32601,
                    message: "CDP method is not allowed by relay policy".to_owned(),
                }),
            },
        }]
    );

    let intruder = endpoint
        .negotiate(&cdp_upgrade(Some(TOKEN)))
        .expect("second CDP client")
        .connection;
    bridge.connect_cdp(intruder).expect("second CDP client");
    let hijack = bridge
        .receive_cdp(
            intruder,
            CdpRequest {
                id: 5,
                method: "Page.captureScreenshot".to_owned(),
                params: None,
                session_id: Some("gta-claw-tab-1".to_owned()),
            },
        )
        .expect("foreign session is answered, not routed");
    assert_eq!(
        hijack,
        vec![BridgeEffect::ToCdp {
            connection: intruder,
            response: CdpResponse {
                id: 5,
                session_id: Some("gta-claw-tab-1".to_owned()),
                result: None,
                error: Some(CdpErrorObject {
                    code: -32001,
                    message: "session not found".to_owned(),
                }),
            },
        }]
    );
}

#[test]
fn disconnect_releases_sessions_targets_and_pending_commands() {
    let AttachedRelay {
        mut endpoint,
        mut bridge,
        extension,
        client,
    } = attached_relay();

    assert_eq!(
        bridge
            .receive_cdp(
                client,
                CdpRequest {
                    id: 2,
                    method: "Page.captureScreenshot".to_owned(),
                    params: None,
                    session_id: Some("gta-claw-tab-1".to_owned()),
                },
            )
            .expect("in-flight screenshot"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 2,
            tab_id: 41,
            session_id: None,
            method: "Page.captureScreenshot".to_owned(),
            params: None,
        })]
    );

    let dropped = bridge.disconnect_extension(extension);
    assert_eq!(
        dropped,
        vec![
            BridgeEffect::ToCdp {
                connection: client,
                response: CdpResponse {
                    id: 2,
                    session_id: Some("gta-claw-tab-1".to_owned()),
                    result: None,
                    error: Some(CdpErrorObject {
                        code: -32000,
                        message: "Chrome extension disconnected".to_owned(),
                    }),
                },
            },
            BridgeEffect::EventToCdp {
                connection: client,
                event: claw_relay::CdpEvent {
                    session_id: None,
                    method: "Target.detachedFromTarget".to_owned(),
                    params: json!({ "sessionId": "gta-claw-tab-1", "targetId": "chrome-target-41" }),
                },
            },
        ]
    );
    assert!(!bridge.is_paired());
    assert_eq!(bridge.identity(), None);
    assert_eq!(bridge.targets(), Vec::new());
    assert_eq!(bridge.shared_tabs(), Vec::new());
    assert_eq!(bridge.disconnect_extension(extension), Vec::new());
    assert_eq!(
        serve_discovery(
            &endpoint,
            &bridge,
            &discovery_request("GET", "/json/version", Some(TOKEN)),
        )
        .status,
        503
    );

    endpoint.close(extension).expect("active extension");
    assert_eq!(endpoint.peer(extension), None);
    assert_eq!(endpoint.peer(client), Some(PeerKind::Cdp));
    assert_eq!(endpoint.connection_count(), 1);
    assert_eq!(
        endpoint.close(extension),
        Err(EndpointError::UnknownConnection)
    );

    let reconnected = endpoint
        .negotiate(&pairing(PAIRED_EXTENSION_ID).upgrade_request())
        .expect("extension reconnects")
        .connection;
    assert_eq!(bridge.connect_extension(reconnected), Vec::new());
    assert_eq!(
        bridge
            .receive_extension(reconnected, hello(vec![tab(41, "Shared", true)]))
            .expect("mandatory hello"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_cdp(
                client,
                CdpRequest {
                    id: 3,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "tab-41" })),
                    session_id: None,
                },
            )
            .expect("re-attach"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 3,
            tab_id: 41,
        })]
    );
    assert!(
        bridge
            .receive_extension(
                reconnected,
                ExtensionMessage::Result {
                    seq: 3,
                    result: Some(json!({ "targetId": "chrome-target-41" })),
                },
            )
            .expect("attach result")
            .contains(&BridgeEffect::ToCdp {
                connection: client,
                response: CdpResponse {
                    id: 3,
                    session_id: None,
                    result: Some(json!({ "sessionId": "gta-claw-tab-2" })),
                    error: None,
                },
            })
    );

    assert_eq!(
        bridge.disconnect_cdp(client),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 4,
            tab_id: 41,
        })]
    );
    assert_eq!(bridge.disconnect_cdp(client), Vec::new());
    endpoint.close(client).expect("active CDP client");
    assert_eq!(endpoint.connection_count(), 1);
    assert_eq!(
        bridge.receive_cdp(
            client,
            CdpRequest {
                id: 6,
                method: "Target.getTargets".to_owned(),
                params: None,
                session_id: None,
            },
        ),
        Err(claw_relay::BridgeError::UnknownCdpConnection)
    );
}

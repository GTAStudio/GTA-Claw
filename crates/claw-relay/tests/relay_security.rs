//! Security and fixture-CDP acceptance tests for the Chrome relay.

use claw_relay::{
    BridgeEffect, BridgeError, CdpBridge, CdpErrorObject, CdpRequest, EndpointError,
    ExtensionCommand, ExtensionId, ExtensionMessage, FrameError, PeerKind, RelayEndpoint, RelayTab,
    RelayToken, UpgradeRequest, decode_cdp_frame, decode_extension_frame,
};
use serde_json::json;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

fn endpoint(max_frame_bytes: usize) -> RelayEndpoint {
    RelayEndpoint::new(
        RelayToken::from_hex(TOKEN).expect("valid fixture token"),
        [ExtensionId::new(EXTENSION_ID).expect("valid fixture extension ID")],
        max_frame_bytes,
        8,
    )
    .expect("valid endpoint")
}

fn extension_upgrade(origin: &str, token: &str) -> UpgradeRequest {
    UpgradeRequest {
        path: "/extension".to_owned(),
        host: "127.0.0.1:18792".to_owned(),
        origin: Some(origin.to_owned()),
        subprotocols: vec![
            "openclaw-extension-relay".to_owned(),
            format!("openclaw-extension-token.{token}"),
        ],
        authorization_token: None,
    }
}

fn cdp_upgrade() -> UpgradeRequest {
    UpgradeRequest {
        path: "/cdp".to_owned(),
        host: "localhost:18792".to_owned(),
        origin: None,
        subprotocols: Vec::new(),
        authorization_token: Some(TOKEN.to_owned()),
    }
}

fn tab() -> RelayTab {
    RelayTab {
        tab_id: 41,
        url: "https://example.test/".to_owned(),
        title: "Fixture".to_owned(),
        active: true,
    }
}

#[test]
fn endpoint_authenticates_exact_extension_origin_and_token() {
    let mut endpoint = endpoint(1024);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("known paired extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("authenticated CDP");
    assert_eq!(endpoint.peer(extension), Some(PeerKind::Extension));
    assert_eq!(endpoint.peer(cdp), Some(PeerKind::Cdp));
    assert_eq!(endpoint.connection_count(), 2);

    endpoint.close(extension).expect("active extension");
    assert_eq!(endpoint.peer(extension), None);
    assert_eq!(endpoint.peer(cdp), Some(PeerKind::Cdp));
    assert_eq!(endpoint.connection_count(), 1);
}

#[test]
fn upgrade_request_debug_redacts_credentials_at_ingress() {
    let request = UpgradeRequest {
        path: "/extension".to_owned(),
        host: "127.0.0.1:18792".to_owned(),
        origin: Some(format!("chrome-extension://{EXTENSION_ID}")),
        subprotocols: vec![
            "openclaw-extension-relay".to_owned(),
            format!("openclaw-extension-token.{TOKEN}"),
        ],
        authorization_token: Some(TOKEN.to_owned()),
    };

    assert_eq!(
        format!("{request:?}"),
        format!(
            "UpgradeRequest {{ path: \"/extension\", host: \"127.0.0.1:18792\", origin: Some(\"chrome-extension://{EXTENSION_ID}\"), subprotocols: \"[REDACTED]\", authorization_token: \"[REDACTED]\" }}"
        )
    );
}

#[test]
fn endpoint_rejects_unknown_extension_id_and_forged_origins() {
    let unknown = "pppppppppppppppppppppppppppppppp";
    assert_eq!(
        endpoint(1024).accept(&extension_upgrade(
            &format!("chrome-extension://{unknown}"),
            TOKEN,
        )),
        Err(EndpointError::UnknownExtension)
    );
    for origin in [
        "https://abcdefghijklmnopabcdefghijklmnop",
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop.evil.test",
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/path",
    ] {
        assert_eq!(
            endpoint(1024).accept(&extension_upgrade(origin, TOKEN)),
            Err(EndpointError::ForgedOrigin)
        );
    }
    let mut missing = extension_upgrade(&format!("chrome-extension://{EXTENSION_ID}"), TOKEN);
    missing.origin = None;
    assert_eq!(
        endpoint(1024).accept(&missing),
        Err(EndpointError::MissingExtensionOrigin)
    );
}

#[test]
fn endpoint_rejects_bad_tokens_foreign_hosts_and_page_cdp_origins() {
    let origin = format!("chrome-extension://{EXTENSION_ID}");
    assert_eq!(
        endpoint(1024).accept(&extension_upgrade(
            &origin,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )),
        Err(EndpointError::AuthenticationFailed)
    );
    let mut foreign = extension_upgrade(&origin, TOKEN);
    foreign.host = "relay.attacker.test".to_owned();
    assert_eq!(
        endpoint(1024).accept(&foreign),
        Err(EndpointError::NonLoopbackHost)
    );
    let mut page = cdp_upgrade();
    page.origin = Some("https://example.test".to_owned());
    assert_eq!(
        endpoint(1024).accept(&page),
        Err(EndpointError::CdpOriginForbidden)
    );
}

#[test]
fn oversized_and_shape_invalid_frames_are_rejected_before_allocation_use() {
    assert_eq!(
        decode_extension_frame(br#"{"type":"pong"}"#, 8),
        Err(FrameError::TooLarge {
            actual: 15,
            limit: 8,
        })
    );
    assert_eq!(
        decode_extension_frame(br#"{"type":"pong","unknown":true}"#, 128),
        Err(FrameError::InvalidJson)
    );
}

#[test]
fn cdp_frames_obey_the_endpoint_configured_bound_and_strict_shape() {
    let endpoint = endpoint(64);
    let valid = br#"{"id":7,"method":"Browser.getVersion"}"#;
    assert_eq!(
        decode_cdp_frame(valid, endpoint.max_frame_bytes()),
        Ok(CdpRequest {
            id: 7,
            method: "Browser.getVersion".to_owned(),
            params: None,
            session_id: None,
        })
    );

    let oversized = br#"{"id":8,"method":"Browser.getVersion","params":{"padding":"xxxxxxxx"}}"#;
    assert_eq!(
        decode_cdp_frame(oversized, endpoint.max_frame_bytes()),
        Err(FrameError::TooLarge {
            actual: oversized.len(),
            limit: 64,
        })
    );
    assert_eq!(decode_cdp_frame(valid, 0), Err(FrameError::InvalidBound));
    assert_eq!(
        decode_cdp_frame(
            br#"{"id":9,"method":"Browser.getVersion","unexpected":true}"#,
            64,
        ),
        Err(FrameError::InvalidJson)
    );
}

#[test]
fn fixture_cdp_server_discovers_attaches_dispatches_and_streams() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP client");
    let mut bridge = CdpBridge::new();
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(cdp).expect("new CDP client");
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Hello {
                    user_agent: "FixtureBrowser/1".to_owned(),
                    browser_version: "Chrome/144.0.0.0".to_owned(),
                    extension_version: "2.0.0".to_owned(),
                    tabs: vec![tab()],
                },
            )
            .expect("hello"),
        Vec::new()
    );

    let discovery = bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 1,
                method: "Target.getTargets".to_owned(),
                params: None,
                session_id: None,
            },
        )
        .expect("target discovery");
    assert_eq!(discovery.len(), 1);
    let BridgeEffect::ToCdp {
        connection,
        response,
    } = &discovery[0]
    else {
        panic!("expected discovery response");
    };
    assert_eq!(*connection, cdp);
    assert_eq!(response.id, 1);
    assert_eq!(response.session_id, None);
    assert_eq!(
        response.result,
        Some(json!({
            "targetInfos": [{
                "targetId": "tab-41",
                "type": "page",
                "title": "Fixture",
                "url": "https://example.test/",
                "browserContextId": "openclaw-extension-context",
                "attached": false,
                "canAccessOpener": false
            }]
        }))
    );
    assert_eq!(response.error, None);

    let attach = bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 2,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("attach request");
    assert_eq!(
        attach,
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
    assert_eq!(attached.len(), 2);
    let BridgeEffect::ToCdp {
        connection,
        response,
    } = &attached[1]
    else {
        panic!("expected attach response");
    };
    assert_eq!(*connection, cdp);
    assert_eq!(response.id, 2);
    assert_eq!(
        response.result,
        Some(json!({ "sessionId": "gta-claw-tab-1" }))
    );
    assert_eq!(response.error, None);

    let screenshot = bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 3,
                method: "Page.captureScreenshot".to_owned(),
                params: Some(json!({ "format": "png" })),
                session_id: Some("gta-claw-tab-1".to_owned()),
            },
        )
        .expect("allowed screenshot");
    assert_eq!(
        screenshot,
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 2,
            tab_id: 41,
            session_id: None,
            method: "Page.captureScreenshot".to_owned(),
            params: Some(json!({ "format": "png" })),
        })]
    );
    let screenshot_result = bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 2,
                result: Some(json!({ "data": "cG5n" })),
            },
        )
        .expect("screenshot result");
    assert_eq!(
        screenshot_result,
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 3,
                session_id: Some("gta-claw-tab-1".to_owned()),
                result: Some(json!({ "data": "cG5n" })),
                error: None,
            },
        }]
    );

    let event = bridge
        .receive_extension(
            extension,
            ExtensionMessage::CdpEvent {
                tab_id: 41,
                session_id: None,
                method: "Page.loadEventFired".to_owned(),
                params: Some(json!({ "timestamp": 9 })),
            },
        )
        .expect("allowed page event");
    assert_eq!(event.len(), 1);
    let BridgeEffect::EventToCdp { connection, event } = &event[0] else {
        panic!("expected routed event");
    };
    assert_eq!(*connection, cdp);
    assert_eq!(event.session_id.as_deref(), Some("gta-claw-tab-1"));
    assert_eq!(event.method, "Page.loadEventFired");
    assert_eq!(event.params, json!({ "timestamp": 9 }));
}

#[test]
fn unauthorized_commands_and_cross_connection_session_hijacks_are_denied() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let mut bridge = CdpBridge::new();
    bridge.connect_extension(extension);
    bridge.connect_cdp(first).expect("first client");
    bridge.connect_cdp(second).expect("second client");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab()],
            },
        )
        .expect("hello");
    bridge
        .receive_cdp(
            first,
            CdpRequest {
                id: 1,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "target-41" })),
            },
        )
        .expect("attached");

    let unauthorized = bridge
        .receive_cdp(
            first,
            CdpRequest {
                id: 2,
                method: "SystemInfo.getProcessInfo".to_owned(),
                params: None,
                session_id: Some("gta-claw-tab-1".to_owned()),
            },
        )
        .expect("policy response");
    assert_eq!(
        unauthorized,
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: Some("gta-claw-tab-1".to_owned()),
                result: None,
                error: Some(CdpErrorObject {
                    code: -32601,
                    message: "CDP method is not allowed by relay policy".to_owned(),
                }),
            },
        }]
    );
    let hijack = bridge
        .receive_cdp(
            second,
            CdpRequest {
                id: 3,
                method: "Runtime.evaluate".to_owned(),
                params: Some(json!({ "expression": "document.title" })),
                session_id: Some("gta-claw-tab-1".to_owned()),
            },
        )
        .expect("isolated session response");
    assert_eq!(
        hijack,
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 3,
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
fn browser_policy_controls_and_unapproved_event_prefixes_fail_closed() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::new();
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(cdp).expect("CDP");
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Hello {
                    user_agent: "Fixture".to_owned(),
                    browser_version: "Chrome/144".to_owned(),
                    extension_version: "2.0.0".to_owned(),
                    tabs: vec![tab()],
                },
            )
            .expect("hello"),
        Vec::new()
    );

    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 1,
                    method: "Browser.setDownloadBehavior".to_owned(),
                    params: Some(json!({ "behavior": "deny" })),
                    session_id: None,
                },
            )
            .expect("policy denial response"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 1,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32601,
                    message: "CDP method is not allowed by relay policy".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 2,
                    method: "Security.setIgnoreCertificateErrors".to_owned(),
                    params: Some(json!({ "ignore": true })),
                    session_id: None,
                },
            )
            .expect("browser method denial response"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32601,
                    message: "CDP method is not allowed by relay policy".to_owned(),
                }),
            },
        }]
    );

    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 3,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "tab-41" })),
                    session_id: None,
                },
            )
            .expect("attach"),
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
                result: Some(json!({ "targetId": "target-41" })),
            },
        )
        .expect("attached");
    assert_eq!(attached.len(), 2);
    assert_eq!(
        bridge.receive_extension(
            extension,
            ExtensionMessage::CdpEvent {
                tab_id: 41,
                session_id: None,
                method: "SystemInfo.processInfoChanged".to_owned(),
                params: Some(json!({})),
            },
        ),
        Err(BridgeError::ExtensionEventNotAllowed)
    );
}

#[test]
fn abrupt_browser_and_tab_disconnects_emit_detach_and_reap_sessions() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::new();
    bridge.connect_extension(extension);
    bridge.connect_cdp(cdp).expect("CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab()],
            },
        )
        .expect("hello");
    bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 1,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "target-41" })),
            },
        )
        .expect("attached");

    let tab_death = bridge
        .receive_extension(extension, ExtensionMessage::Tabs { tabs: Vec::new() })
        .expect("tab refresh");
    assert_eq!(tab_death.len(), 1);
    let BridgeEffect::EventToCdp { connection, event } = &tab_death[0] else {
        panic!("expected tab detach event");
    };
    assert_eq!(*connection, cdp);
    assert_eq!(event.session_id, None);
    assert_eq!(event.method, "Target.detachedFromTarget");
    assert_eq!(
        event.params,
        json!({
            "sessionId": "gta-claw-tab-1",
            "targetId": "target-41"
        })
    );

    bridge
        .receive_extension(extension, ExtensionMessage::Tabs { tabs: vec![tab()] })
        .expect("tab returned");
    bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 2,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("reattach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 2,
                result: Some(json!({ "targetId": "target-41b" })),
            },
        )
        .expect("reattached");
    let browser_death = bridge.disconnect_extension();
    assert_eq!(browser_death.len(), 1);
    assert!(bridge.targets().is_empty());
    let BridgeEffect::EventToCdp { connection, event } = &browser_death[0] else {
        panic!("expected browser detach event");
    };
    assert_eq!(*connection, cdp);
    assert_eq!(event.method, "Target.detachedFromTarget");
}

#[test]
fn playwright_browser_session_and_auto_attach_sequence_is_supported() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::new();
    bridge.connect_extension(extension);
    bridge.connect_cdp(cdp).expect("CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab()],
            },
        )
        .expect("hello");

    let browser_session = bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 1,
                method: "Target.attachToBrowserTarget".to_owned(),
                params: None,
                session_id: None,
            },
        )
        .expect("browser session");
    assert_eq!(
        browser_session,
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 1,
                session_id: None,
                result: Some(json!({ "sessionId": "gta-claw-browser-1" })),
                error: None,
            },
        }]
    );

    let auto_attach = bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 2,
                method: "Target.setAutoAttach".to_owned(),
                params: Some(json!({
                    "autoAttach": true,
                    "waitForDebuggerOnStart": false,
                    "flatten": true
                })),
                session_id: Some("gta-claw-browser-1".to_owned()),
            },
        )
        .expect("auto attach");
    assert_eq!(
        auto_attach,
        vec![
            BridgeEffect::ToCdp {
                connection: cdp,
                response: claw_relay::CdpResponse {
                    id: 2,
                    session_id: Some("gta-claw-browser-1".to_owned()),
                    result: Some(json!({})),
                    error: None,
                },
            },
            BridgeEffect::ToExtension(ExtensionCommand::Attach { seq: 1, tab_id: 41 }),
        ]
    );
    let attached = bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "target-41" })),
            },
        )
        .expect("auto attach result");
    assert_eq!(attached.len(), 1);
    let BridgeEffect::EventToCdp { connection, event } = &attached[0] else {
        panic!("expected auto-attach event");
    };
    assert_eq!(*connection, cdp);
    assert_eq!(event.session_id, None);
    assert_eq!(event.method, "Target.attachedToTarget");
    assert_eq!(
        event.params,
        json!({
            "sessionId": "gta-claw-tab-2",
            "targetInfo": {
                "targetId": "target-41",
                "type": "page",
                "title": "Fixture",
                "url": "https://example.test/",
                "browserContextId": "openclaw-extension-context",
                "attached": true,
                "canAccessOpener": false
            },
            "waitingForDebugger": false
        })
    );

    let new_tab = RelayTab {
        tab_id: 42,
        url: "https://new.example.test/".to_owned(),
        title: "New fixture".to_owned(),
        active: false,
    };
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Tabs {
                    tabs: vec![tab(), new_tab],
                },
            )
            .expect("auto-attach new shared tab"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 2,
            tab_id: 42,
        })]
    );
}

#[test]
fn pending_work_is_bounded_expires_and_disconnect_cleanup_cannot_leak_ownership() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    bridge.connect_extension(extension);
    bridge.connect_cdp(cdp).expect("CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab()],
            },
        )
        .expect("hello");
    let request = CdpRequest {
        id: 1,
        method: "Target.attachToTarget".to_owned(),
        params: Some(json!({ "targetId": "tab-41" })),
        session_id: None,
    };
    assert_eq!(
        bridge
            .receive_cdp(cdp, request.clone())
            .expect("first pending command"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 1,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge.receive_cdp(
            cdp,
            CdpRequest {
                id: 2,
                method: request.method.clone(),
                params: request.params.clone(),
                session_id: request.session_id.clone(),
            },
        ),
        Err(BridgeError::PendingLimit)
    );
    assert_eq!(
        bridge.expire_command(1).expect("pending timeout"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 1,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "extension relay command timed out".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Error {
                    seq: 1,
                    message: "attach cancelled".to_owned(),
                },
            )
            .expect("late cancellation"),
        Vec::new()
    );

    bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 3,
                method: request.method,
                params: request.params,
                session_id: request.session_id,
            },
        )
        .expect("slot was released after timeout");
    assert_eq!(
        bridge.disconnect_extension(),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 3,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "Chrome extension disconnected".to_owned(),
                }),
            },
        }]
    );

    let mut cleanup = CdpBridge::with_pending_limit(2).expect("positive pending bound");
    cleanup.connect_extension(extension);
    cleanup.connect_cdp(cdp).expect("CDP");
    cleanup
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab()],
            },
        )
        .expect("hello");
    cleanup
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 4,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("attach");
    cleanup
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "target-41" })),
            },
        )
        .expect("attached");
    assert!(cleanup.targets()[0].attached);
    assert_eq!(
        cleanup.disconnect_cdp(cdp),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 2,
            tab_id: 41,
        })]
    );
    assert!(!cleanup.targets()[0].attached);
    assert_eq!(
        cleanup
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 2,
                    result: Some(json!({})),
                },
            )
            .expect("cleanup result"),
        Vec::new()
    );
}

#[test]
fn playwright_page_bootstrap_commands_are_explicitly_policy_allowed() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::new();
    bridge.connect_extension(extension);
    bridge.connect_cdp(cdp).expect("CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab()],
            },
        )
        .expect("hello");
    bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 1,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "target-41" })),
            },
        )
        .expect("attached");

    let methods = [
        "Page.getFrameTree",
        "Log.enable",
        "Page.setLifecycleEventsEnabled",
        "Page.addScriptToEvaluateOnNewDocument",
        "Target.setAutoAttach",
        "Runtime.runIfWaitingForDebugger",
    ];
    for (index, method) in methods.into_iter().enumerate() {
        let request_id = u64::try_from(index).expect("small index") + 2;
        let seq = u64::try_from(index).expect("small index") + 2;
        assert_eq!(
            bridge
                .receive_cdp(
                    cdp,
                    CdpRequest {
                        id: request_id,
                        method: method.to_owned(),
                        params: Some(json!({})),
                        session_id: Some("gta-claw-tab-1".to_owned()),
                    },
                )
                .expect("bootstrap command"),
            vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
                seq,
                tab_id: 41,
                session_id: None,
                method: method.to_owned(),
                params: Some(json!({})),
            })],
            "method {method}"
        );
        assert_eq!(
            bridge
                .receive_extension(
                    extension,
                    ExtensionMessage::Result {
                        seq,
                        result: Some(json!({})),
                    },
                )
                .expect("bootstrap result"),
            vec![BridgeEffect::ToCdp {
                connection: cdp,
                response: claw_relay::CdpResponse {
                    id: request_id,
                    session_id: Some("gta-claw-tab-1".to_owned()),
                    result: Some(json!({})),
                    error: None,
                },
            }]
        );
    }
}

#[test]
fn auto_attach_reservation_is_atomic_and_internal_failures_emit_no_fake_response() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let second_tab = RelayTab {
        tab_id: 42,
        url: "https://second.example.test/".to_owned(),
        title: "Second".to_owned(),
        active: false,
    };
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    bridge.connect_extension(extension);
    bridge.connect_cdp(cdp).expect("CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab(), second_tab],
            },
        )
        .expect("hello");
    assert_eq!(
        bridge.receive_cdp(
            cdp,
            CdpRequest {
                id: 1,
                method: "Target.setAutoAttach".to_owned(),
                params: Some(json!({ "autoAttach": true })),
                session_id: None,
            },
        ),
        Err(BridgeError::PendingLimit)
    );
    assert_eq!(
        bridge.expire_command(1),
        Err(BridgeError::UnknownCommandSequence)
    );
    let third_tab = RelayTab {
        tab_id: 43,
        url: "https://third.example.test/".to_owned(),
        title: "Third".to_owned(),
        active: false,
    };
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Tabs {
                    tabs: vec![tab(), third_tab],
                },
            )
            .expect("failed auto-attach did not remain enabled"),
        Vec::new()
    );

    let mut single = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    single.connect_extension(extension);
    single.connect_cdp(cdp).expect("CDP");
    single
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab()],
            },
        )
        .expect("hello");
    single
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 2,
                method: "Target.setAutoAttach".to_owned(),
                params: Some(json!({ "autoAttach": true })),
                session_id: None,
            },
        )
        .expect("auto attach");
    let new_tab = RelayTab {
        tab_id: 42,
        url: "https://new.example.test/".to_owned(),
        title: "New".to_owned(),
        active: false,
    };
    assert_eq!(
        single.receive_extension(
            extension,
            ExtensionMessage::Tabs {
                tabs: vec![tab(), new_tab.clone()],
            },
        ),
        Err(BridgeError::PendingLimit)
    );
    assert_eq!(
        single
            .receive_extension(
                extension,
                ExtensionMessage::Error {
                    seq: 1,
                    message: "attach cancelled".to_owned(),
                },
            )
            .expect("internal attach cancellation"),
        Vec::new()
    );
    assert_eq!(
        single
            .receive_extension(
                extension,
                ExtensionMessage::Tabs {
                    tabs: vec![tab(), new_tab],
                },
            )
            .expect("retry sees the tab as new"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 2,
            tab_id: 42,
        })]
    );
    assert_eq!(single.disconnect_extension(), Vec::new());
}

#[test]
fn late_pending_attach_after_cdp_disconnect_is_immediately_detached() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    bridge.connect_extension(extension);
    bridge.connect_cdp(cdp).expect("CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![tab()],
            },
        )
        .expect("hello");
    bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 1,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("pending attach");
    assert_eq!(bridge.disconnect_cdp(cdp), Vec::new());
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 1,
                    result: Some(json!({ "targetId": "target-41" })),
                },
            )
            .expect("late attach result"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 2,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 2,
                    result: Some(json!({})),
                },
            )
            .expect("cleanup result"),
        Vec::new()
    );
    assert!(!bridge.targets()[0].attached);
}

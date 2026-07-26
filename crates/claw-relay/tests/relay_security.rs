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
fn child_sessions_route_real_ids_enforce_ownership_and_reap_descendants() {
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
    assert_eq!(bridge.connect_extension(extension), Vec::new());
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
    assert_eq!(
        bridge.receive_extension(
            extension,
            ExtensionMessage::Detached {
                tab_id: 999,
                reason: "unknown".to_owned(),
            },
        ),
        Err(BridgeError::UnknownTab)
    );
    assert_eq!(
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
            .expect("root attach"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 1,
            tab_id: 41,
        })]
    );
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "chrome-target-41" })),
            },
        )
        .expect("root attached");

    let worker_params = json!({
        "sessionId": "chrome-worker-1",
        "targetInfo": {
            "targetId": "worker-1",
            "type": "worker",
            "title": "fixture worker",
            "url": "https://example.test/worker.js",
            "attached": true
        },
        "waitingForDebugger": false
    });
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::CdpEvent {
                    tab_id: 41,
                    session_id: None,
                    method: "Target.attachedToTarget".to_owned(),
                    params: Some(worker_params.clone()),
                },
            )
            .expect("worker attached"),
        vec![BridgeEffect::EventToCdp {
            connection: first,
            event: claw_relay::CdpEvent {
                session_id: Some("gta-claw-tab-1".to_owned()),
                method: "Target.attachedToTarget".to_owned(),
                params: worker_params,
            },
        }]
    );

    let frame_params = json!({
        "sessionId": "chrome-frame-1",
        "targetInfo": {
            "targetId": "frame-1",
            "type": "iframe",
            "title": "fixture frame",
            "url": "https://frame.example.test/",
            "attached": true
        },
        "waitingForDebugger": false
    });
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::CdpEvent {
                    tab_id: 41,
                    session_id: Some("chrome-worker-1".to_owned()),
                    method: "Target.attachedToTarget".to_owned(),
                    params: Some(frame_params.clone()),
                },
            )
            .expect("nested frame attached"),
        vec![BridgeEffect::EventToCdp {
            connection: first,
            event: claw_relay::CdpEvent {
                session_id: Some("chrome-worker-1".to_owned()),
                method: "Target.attachedToTarget".to_owned(),
                params: frame_params,
            },
        }]
    );

    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 2,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "document.title" })),
                    session_id: Some("chrome-frame-1".to_owned()),
                },
            )
            .expect("child command"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 2,
            tab_id: 41,
            session_id: Some("chrome-frame-1".to_owned()),
            method: "Runtime.evaluate".to_owned(),
            params: Some(json!({ "expression": "document.title" })),
        })]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 3,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "document.cookie" })),
                    session_id: Some("chrome-frame-1".to_owned()),
                },
            )
            .expect("cross-owner denial"),
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 3,
                session_id: Some("chrome-frame-1".to_owned()),
                result: None,
                error: Some(CdpErrorObject {
                    code: -32001,
                    message: "session not found".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 2,
                    result: Some(json!({ "result": { "type": "string", "value": "Fixture" } })),
                },
            )
            .expect("child result"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: Some("chrome-frame-1".to_owned()),
                result: Some(json!({ "result": { "type": "string", "value": "Fixture" } })),
                error: None,
            },
        }]
    );

    let detached_params = json!({ "sessionId": "chrome-worker-1", "targetId": "worker-1" });
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::CdpEvent {
                    tab_id: 41,
                    session_id: None,
                    method: "Target.detachedFromTarget".to_owned(),
                    params: Some(detached_params.clone()),
                },
            )
            .expect("worker detached"),
        vec![BridgeEffect::EventToCdp {
            connection: first,
            event: claw_relay::CdpEvent {
                session_id: Some("gta-claw-tab-1".to_owned()),
                method: "Target.detachedFromTarget".to_owned(),
                params: detached_params,
            },
        }]
    );
    let late_frame_detach = json!({ "sessionId": "chrome-frame-1", "targetId": "frame-1" });
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::CdpEvent {
                    tab_id: 41,
                    session_id: Some("chrome-worker-1".to_owned()),
                    method: "Target.detachedFromTarget".to_owned(),
                    params: Some(late_frame_detach.clone()),
                },
            )
            .expect("late descendant detach is idempotent"),
        vec![BridgeEffect::EventToCdp {
            connection: first,
            event: claw_relay::CdpEvent {
                session_id: Some("chrome-worker-1".to_owned()),
                method: "Target.detachedFromTarget".to_owned(),
                params: late_frame_detach,
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 4,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "1" })),
                    session_id: Some("chrome-frame-1".to_owned()),
                },
            )
            .expect("descendant was reaped"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 4,
                session_id: Some("chrome-frame-1".to_owned()),
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
fn child_sessions_reject_reserved_ids_and_contain_untracked_traffic() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(cdp).expect("client");
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
        .expect("root attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "chrome-target-41" })),
            },
        )
        .expect("root attached");

    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::CdpEvent {
                    tab_id: 41,
                    session_id: Some("unknown-child".to_owned()),
                    method: "Runtime.consoleAPICalled".to_owned(),
                    params: Some(json!({ "type": "log", "args": [] })),
                },
            )
            .expect("unknown child traffic is contained"),
        Vec::new()
    );
    assert_eq!(
        bridge.receive_extension(
            extension,
            ExtensionMessage::CdpEvent {
                tab_id: 41,
                session_id: None,
                method: "Target.attachedToTarget".to_owned(),
                params: Some(json!({
                    "sessionId": "gta-claw-tab-999",
                    "targetInfo": { "targetId": "worker-reserved", "type": "worker" }
                })),
            },
        ),
        Err(BridgeError::InvalidChildSessionId)
    );
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::CdpEvent {
                tab_id: 41,
                session_id: None,
                method: "Target.attachedToTarget".to_owned(),
                params: Some(json!({
                    "sessionId": "chrome-child-1",
                    "targetInfo": { "targetId": "worker-1", "type": "worker" }
                })),
            },
        )
        .expect("first bounded child");
    let overflow_params = json!({
        "sessionId": "chrome-child-2",
        "targetInfo": { "targetId": "worker-2", "type": "worker" }
    });
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::CdpEvent {
                    tab_id: 41,
                    session_id: None,
                    method: "Target.attachedToTarget".to_owned(),
                    params: Some(overflow_params),
                },
            )
            .expect("overflow closes only the owning CDP connection"),
        vec![BridgeEffect::CloseCdp {
            connection: cdp,
            code: 1013,
            reason: "relay child session limit reached",
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::CdpEvent {
                    tab_id: 41,
                    session_id: Some("chrome-child-2".to_owned()),
                    method: "Runtime.consoleAPICalled".to_owned(),
                    params: Some(json!({ "type": "log", "args": [] })),
                },
            )
            .expect("overflow child event is contained"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 2,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "1" })),
                    session_id: Some("chrome-child-2".to_owned()),
                },
            )
            .expect("untracked overflow child fails locally"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: Some("chrome-child-2".to_owned()),
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
fn child_session_capacity_is_partitioned_and_overflow_is_never_announced() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(first).expect("first client");
    bridge.connect_cdp(second).expect("second client");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![
                    tab(),
                    RelayTab {
                        tab_id: 42,
                        url: "https://second.example.test/".to_owned(),
                        title: "Second".to_owned(),
                        active: false,
                    },
                ],
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
        .expect("first root attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "chrome-target-41" })),
            },
        )
        .expect("first root attached");
    bridge
        .receive_cdp(
            second,
            CdpRequest {
                id: 2,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-42" })),
                session_id: None,
            },
        )
        .expect("second root attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 2,
                result: Some(json!({ "targetId": "chrome-target-42" })),
            },
        )
        .expect("second root attached");

    let child_event = |tab_id, session_id: &str, target_id: &str| ExtensionMessage::CdpEvent {
        tab_id,
        session_id: None,
        method: "Target.attachedToTarget".to_owned(),
        params: Some(json!({
            "sessionId": session_id,
            "targetInfo": { "targetId": target_id, "type": "worker" }
        })),
    };
    bridge
        .receive_extension(
            extension,
            child_event(41, "chrome-first-child", "first-worker"),
        )
        .expect("first owner child");
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                child_event(41, "chrome-first-overflow", "overflow-worker"),
            )
            .expect("overflow closes only the first owner"),
        vec![BridgeEffect::CloseCdp {
            connection: first,
            code: 1013,
            reason: "relay child session limit reached",
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                child_event(42, "chrome-second-child", "second-worker"),
            )
            .expect("second owner keeps its child partition"),
        vec![BridgeEffect::EventToCdp {
            connection: second,
            event: claw_relay::CdpEvent {
                session_id: Some("gta-claw-tab-2".to_owned()),
                method: "Target.attachedToTarget".to_owned(),
                params: json!({
                    "sessionId": "chrome-second-child",
                    "targetInfo": { "targetId": "second-worker", "type": "worker" }
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 3,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "1" })),
                    session_id: Some("chrome-second-child".to_owned()),
                },
            )
            .expect("second owner child command"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 3,
            tab_id: 42,
            session_id: Some("chrome-second-child".to_owned()),
            method: "Runtime.evaluate".to_owned(),
            params: Some(json!({ "expression": "1" })),
        })]
    );
}

#[test]
fn root_detach_disconnect_and_tab_death_reap_child_session_generations() {
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
    assert_eq!(bridge.connect_extension(extension), Vec::new());
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

    assert_eq!(
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
            .expect("first root attach"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 1,
            tab_id: 41,
        })]
    );
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "chrome-target-41" })),
            },
        )
        .expect("first root attached");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::CdpEvent {
                tab_id: 41,
                session_id: None,
                method: "Target.attachedToTarget".to_owned(),
                params: Some(json!({
                    "sessionId": "chrome-child-reused",
                    "targetInfo": { "targetId": "worker-1", "type": "worker" },
                    "waitingForDebugger": false
                })),
            },
        )
        .expect("first child attached");

    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 2,
                    method: "Target.detachFromTarget".to_owned(),
                    params: Some(json!({ "sessionId": "gta-claw-tab-1" })),
                    session_id: None,
                },
            )
            .expect("root detach"),
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
                    result: None,
                },
            )
            .expect("root detached"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: None,
                result: Some(json!({})),
                error: None,
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 3,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "1" })),
                    session_id: Some("chrome-child-reused".to_owned()),
                },
            )
            .expect("detached child rejected"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 3,
                session_id: Some("chrome-child-reused".to_owned()),
                result: None,
                error: Some(CdpErrorObject {
                    code: -32001,
                    message: "session not found".to_owned(),
                }),
            },
        }]
    );

    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 4,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "chrome-target-41" })),
                    session_id: None,
                },
            )
            .expect("second root attach"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 3,
            tab_id: 41,
        })]
    );
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 3,
                result: Some(json!({ "targetId": "chrome-target-41" })),
            },
        )
        .expect("second root attached");
    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 5,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "1" })),
                    session_id: Some("chrome-child-reused".to_owned()),
                },
            )
            .expect("stale generation rejected"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 5,
                session_id: Some("chrome-child-reused".to_owned()),
                result: None,
                error: Some(CdpErrorObject {
                    code: -32001,
                    message: "session not found".to_owned(),
                }),
            },
        }]
    );
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::CdpEvent {
                tab_id: 41,
                session_id: None,
                method: "Target.attachedToTarget".to_owned(),
                params: Some(json!({
                    "sessionId": "chrome-child-reused",
                    "targetInfo": { "targetId": "worker-2", "type": "worker" },
                    "waitingForDebugger": false
                })),
            },
        )
        .expect("child ID may be reused only after a new announcement");

    assert_eq!(
        bridge.disconnect_cdp(first),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 4,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 6,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "document.cookie" })),
                    session_id: Some("chrome-child-reused".to_owned()),
                },
            )
            .expect("disconnected owner's child rejected"),
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 6,
                session_id: Some("chrome-child-reused".to_owned()),
                result: None,
                error: Some(CdpErrorObject {
                    code: -32001,
                    message: "session not found".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 4,
                    result: None,
                },
            )
            .expect("disconnect cleanup"),
        Vec::new()
    );

    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 7,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "chrome-target-41" })),
                    session_id: None,
                },
            )
            .expect("third root attach"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 5,
            tab_id: 41,
        })]
    );
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 5,
                result: Some(json!({ "targetId": "chrome-target-41" })),
            },
        )
        .expect("third root attached");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::CdpEvent {
                tab_id: 41,
                session_id: None,
                method: "Target.attachedToTarget".to_owned(),
                params: Some(json!({
                    "sessionId": "chrome-child-reused",
                    "targetInfo": { "targetId": "worker-3", "type": "worker" },
                    "waitingForDebugger": false
                })),
            },
        )
        .expect("third child attached");
    assert_eq!(
        bridge
            .receive_extension(extension, ExtensionMessage::Tabs { tabs: Vec::new() })
            .expect("tab death"),
        vec![BridgeEffect::EventToCdp {
            connection: second,
            event: claw_relay::CdpEvent {
                session_id: None,
                method: "Target.detachedFromTarget".to_owned(),
                params: json!({
                    "sessionId": "gta-claw-tab-3",
                    "targetId": "chrome-target-41"
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 8,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "1" })),
                    session_id: Some("chrome-child-reused".to_owned()),
                },
            )
            .expect("dead tab child rejected"),
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 8,
                session_id: Some("chrome-child-reused".to_owned()),
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
fn pending_capacity_is_partitioned_per_authenticated_connection() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(first).expect("first client");
    bridge.connect_cdp(second).expect("second client");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![
                    tab(),
                    RelayTab {
                        tab_id: 42,
                        url: "https://second.example.test/".to_owned(),
                        title: "Second".to_owned(),
                        active: false,
                    },
                ],
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
        .expect("first root attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "chrome-target-41" })),
            },
        )
        .expect("first root attached");
    bridge
        .receive_cdp(
            second,
            CdpRequest {
                id: 2,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-42" })),
                session_id: None,
            },
        )
        .expect("second root attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 2,
                result: Some(json!({ "targetId": "chrome-target-42" })),
            },
        )
        .expect("second root attached");

    let screenshot = |id, session_id: &str| CdpRequest {
        id,
        method: "Page.captureScreenshot".to_owned(),
        params: Some(json!({ "format": "png" })),
        session_id: Some(session_id.to_owned()),
    };
    assert_eq!(
        bridge
            .receive_cdp(first, screenshot(3, "gta-claw-tab-1"))
            .expect("first owner uses its slot"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 3,
            tab_id: 41,
            session_id: None,
            method: "Page.captureScreenshot".to_owned(),
            params: Some(json!({ "format": "png" })),
        })]
    );
    assert_eq!(
        bridge.receive_cdp(first, screenshot(4, "gta-claw-tab-1")),
        Err(BridgeError::PendingLimit)
    );
    assert_eq!(
        bridge
            .receive_cdp(second, screenshot(5, "gta-claw-tab-2"))
            .expect("second owner has an independent slot"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 4,
            tab_id: 42,
            session_id: None,
            method: "Page.captureScreenshot".to_owned(),
            params: Some(json!({ "format": "png" })),
        })]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 3,
                    result: Some(json!({ "data": "first" })),
                },
            )
            .expect("first screenshot completed"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 3,
                session_id: Some("gta-claw-tab-1".to_owned()),
                result: Some(json!({ "data": "first" })),
                error: None,
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_cdp(first, screenshot(6, "gta-claw-tab-1"))
            .expect("first owner reacquires only its own slot"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
            seq: 5,
            tab_id: 41,
            session_id: None,
            method: "Page.captureScreenshot".to_owned(),
            params: Some(json!({ "format": "png" })),
        })]
    );
}

#[test]
fn bridge_caps_authenticated_cdp_connections_and_global_limit_arithmetic() {
    let mut endpoint = RelayEndpoint::new(
        RelayToken::from_hex(TOKEN).expect("valid fixture token"),
        [ExtensionId::new(EXTENSION_ID).expect("valid fixture extension ID")],
        4096,
        9,
    )
    .expect("endpoint above the bridge-level cap");
    let connections = (0..9)
        .map(|_| endpoint.accept(&cdp_upgrade()).expect("CDP"))
        .collect::<Vec<_>>();
    let mut bridge = CdpBridge::new();
    for connection in connections.iter().take(8) {
        bridge
            .connect_cdp(*connection)
            .expect("connection within the bridge cap");
    }
    assert_eq!(
        bridge.connect_cdp(connections[8]),
        Err(BridgeError::CdpConnectionLimit)
    );
    assert!(matches!(
        CdpBridge::with_pending_limit(usize::MAX),
        Err(BridgeError::InvalidPendingLimit)
    ));
}

#[test]
fn root_session_capacity_is_partitioned_per_authenticated_connection() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(first).expect("first CDP");
    bridge.connect_cdp(second).expect("second CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![
                    tab(),
                    RelayTab {
                        tab_id: 42,
                        url: "https://second.example.test/".to_owned(),
                        title: "Second".to_owned(),
                        active: false,
                    },
                    RelayTab {
                        tab_id: 43,
                        url: "https://third.example.test/".to_owned(),
                        title: "Third".to_owned(),
                        active: false,
                    },
                ],
            },
        )
        .expect("hello");
    let attach = |id, target_id| CdpRequest {
        id,
        method: "Target.attachToTarget".to_owned(),
        params: Some(json!({ "targetId": target_id })),
        session_id: None,
    };

    bridge
        .receive_cdp(first, attach(1, "tab-41"))
        .expect("first owner attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({})),
            },
        )
        .expect("first owner attached");
    assert_eq!(
        bridge.receive_cdp(first, attach(2, "tab-43")),
        Err(BridgeError::SessionLimit)
    );
    assert_eq!(
        bridge
            .receive_cdp(second, attach(3, "tab-42"))
            .expect("first owner cannot consume the second owner's root partition"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 2,
            tab_id: 42,
        })]
    );
}

#[test]
fn cleanup_quarantine_capacity_is_partitioned_per_authenticated_connection() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let second_tab = RelayTab {
        tab_id: 42,
        url: "https://second.example.test/".to_owned(),
        title: "Second".to_owned(),
        active: false,
    };
    let connect = |bridge: &mut CdpBridge| {
        assert_eq!(bridge.connect_extension(extension), Vec::new());
        bridge.connect_cdp(first).expect("first CDP");
        bridge.connect_cdp(second).expect("second CDP");
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Hello {
                    user_agent: "Fixture".to_owned(),
                    browser_version: "Chrome/144".to_owned(),
                    extension_version: "2.0.0".to_owned(),
                    tabs: vec![tab(), second_tab.clone()],
                },
            )
            .expect("hello");
    };
    let attach = |id, target_id| CdpRequest {
        id,
        method: "Target.attachToTarget".to_owned(),
        params: Some(json!({ "targetId": target_id })),
        session_id: None,
    };

    let mut abandoned = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    connect(&mut abandoned);
    abandoned
        .receive_cdp(first, attach(1, "tab-41"))
        .expect("first pending attach");
    abandoned
        .receive_cdp(second, attach(2, "tab-42"))
        .expect("second pending attach");
    assert_eq!(abandoned.disconnect_cdp(first), Vec::new());
    assert_eq!(abandoned.disconnect_cdp(second), Vec::new());
    for seq in [1, 2] {
        assert_eq!(
            abandoned
                .receive_extension(
                    extension,
                    ExtensionMessage::Error {
                        seq,
                        message: "attach cancelled".to_owned(),
                    },
                )
                .expect("each owner has an independent abandoned-attach partition"),
            Vec::new()
        );
    }
    assert_eq!(
        abandoned
            .receive_extension(extension, ExtensionMessage::Pong)
            .expect("one owner's quarantine cannot close the shared extension"),
        Vec::new()
    );

    let mut cleanup = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    connect(&mut cleanup);
    cleanup
        .receive_cdp(first, attach(3, "tab-41"))
        .expect("first attach");
    cleanup
        .receive_cdp(second, attach(4, "tab-42"))
        .expect("second attach");
    for seq in [1, 2] {
        cleanup
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq,
                    result: Some(json!({})),
                },
            )
            .expect("attach completion");
    }
    assert_eq!(
        cleanup.disconnect_cdp(first),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 3,
            tab_id: 41,
        })]
    );
    assert_eq!(
        cleanup.disconnect_cdp(second),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 4,
            tab_id: 42,
        })]
    );
    for seq in [3, 4] {
        assert_eq!(
            cleanup
                .receive_extension(
                    extension,
                    ExtensionMessage::Result {
                        seq,
                        result: Some(json!({})),
                    },
                )
                .expect("each owner has an independent cleanup-detach partition"),
            Vec::new()
        );
    }
}

#[test]
fn draining_lifecycle_owners_reserve_connection_partitions_for_active_clients() {
    const DRAINING_AGGRESSOR_OWNERS: u64 = 7;

    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let victim = endpoint.accept(&cdp_upgrade()).expect("victim CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(victim).expect("victim CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: (41..=50)
                    .map(|tab_id| RelayTab {
                        tab_id,
                        url: format!("https://tab-{tab_id}.example.test/"),
                        title: format!("Tab {tab_id}"),
                        active: tab_id == 41,
                    })
                    .collect(),
            },
        )
        .expect("hello");
    let attach = |id, tab_id| CdpRequest {
        id,
        method: "Target.attachToTarget".to_owned(),
        params: Some(json!({ "targetId": format!("tab-{tab_id}") })),
        session_id: None,
    };
    let complete_aggressor_cycle = |bridge: &mut CdpBridge, aggressor, request_id, tab_id| {
        let effects = bridge
            .receive_cdp(aggressor, attach(request_id, tab_id))
            .expect("aggressor acquires a root lifecycle slot");
        let [
            BridgeEffect::ToExtension(ExtensionCommand::Attach {
                seq,
                tab_id: attached,
            }),
        ] = effects.as_slice()
        else {
            panic!("aggressor attach emitted an unexpected effect");
        };
        assert_eq!(*attached, tab_id);
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: *seq,
                    result: Some(json!({})),
                },
            )
            .expect("aggressor attach completed");
        assert!(matches!(
            bridge.disconnect_cdp(aggressor).as_slice(),
            [BridgeEffect::ToExtension(ExtensionCommand::Detach {
                tab_id: detached,
                ..
            })] if *detached == tab_id
        ));
    };

    let mut completed_aggressor_cycles = 0;
    for offset in 0..DRAINING_AGGRESSOR_OWNERS {
        let aggressor = endpoint
            .accept(&cdp_upgrade())
            .expect("authenticated aggressor reconnect");
        bridge
            .connect_cdp(aggressor)
            .expect("aggressor partition available");
        complete_aggressor_cycle(&mut bridge, aggressor, offset + 1, 41 + offset);
        endpoint.close(aggressor).expect("aggressor disconnected");
        completed_aggressor_cycles += 1;
    }

    let extra_aggressor = endpoint
        .accept(&cdp_upgrade())
        .expect("extra authenticated aggressor reconnect");
    let extra_aggressor_connected = match bridge.connect_cdp(extra_aggressor) {
        Ok(()) => {
            complete_aggressor_cycle(&mut bridge, extra_aggressor, 8, 48);
            true
        }
        Err(BridgeError::CdpConnectionLimit) => false,
        Err(error) => panic!("unexpected extra aggressor admission error: {error}"),
    };
    endpoint
        .close(extra_aggressor)
        .expect("extra aggressor disconnected");

    assert!(
        completed_aggressor_cycles > 0,
        "the aggressor must complete a disconnect cycle before victim acquisition is tested"
    );
    assert!(matches!(
        bridge
            .receive_cdp(victim, attach(9, 49))
            .expect("the connected victim retains lifecycle availability")
            .as_slice(),
        [BridgeEffect::ToExtension(ExtensionCommand::Attach {
            tab_id: 49,
            ..
        })]
    ));
    assert!(
        !extra_aggressor_connected,
        "draining lifecycle owners must keep their bounded connection partitions"
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
                tabs: vec![
                    tab(),
                    RelayTab {
                        tab_id: 42,
                        url: "https://second.example.test/".to_owned(),
                        title: "Second".to_owned(),
                        active: false,
                    },
                ],
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
                params: Some(json!({ "targetId": "tab-42" })),
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
fn auto_attach_capacity_is_bounded_without_blocking_tab_synchronization() {
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
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 1,
                    method: "Target.setAutoAttach".to_owned(),
                    params: Some(json!({ "autoAttach": true })),
                    session_id: None,
                },
            )
            .expect("auto attach admits work within the connection partition"),
        vec![
            BridgeEffect::ToCdp {
                connection: cdp,
                response: claw_relay::CdpResponse {
                    id: 1,
                    session_id: None,
                    result: Some(json!({})),
                    error: None,
                },
            },
            BridgeEffect::ToExtension(ExtensionCommand::Attach { seq: 1, tab_id: 41 }),
        ]
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
                    tabs: vec![tab(), third_tab.clone()],
                },
            )
            .expect("the full auto-attach partition does not block tab synchronization"),
        Vec::new()
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
            .expect("internal attach cancellation"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 2,
            tab_id: 43,
        })]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Error {
                    seq: 2,
                    message: "second attach cancelled".to_owned(),
                },
            )
            .expect("the second failure suppresses the whole failed wave"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Tabs {
                    tabs: vec![tab(), third_tab],
                },
            )
            .expect("a fresh snapshot begins a controlled retry wave"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 3,
            tab_id: 41,
        })]
    );
    assert_eq!(bridge.disconnect_extension(), Vec::new());
}

#[test]
fn browser_detach_pumps_auto_attach_without_retrying_the_detached_tab() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    bridge.connect_extension(extension);
    bridge.connect_cdp(cdp).expect("CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![
                    tab(),
                    RelayTab {
                        tab_id: 42,
                        url: "https://second.example.test/".to_owned(),
                        title: "Second".to_owned(),
                        active: false,
                    },
                ],
            },
        )
        .expect("hello");
    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 1,
                    method: "Target.setAutoAttach".to_owned(),
                    params: Some(json!({ "autoAttach": true })),
                    session_id: None,
                },
            )
            .expect("auto attach"),
        vec![
            BridgeEffect::ToCdp {
                connection: cdp,
                response: claw_relay::CdpResponse {
                    id: 1,
                    session_id: None,
                    result: Some(json!({})),
                    error: None,
                },
            },
            BridgeEffect::ToExtension(ExtensionCommand::Attach { seq: 1, tab_id: 41 }),
        ]
    );
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "target-41" })),
            },
        )
        .expect("first tab attached");
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Detached {
                    tab_id: 41,
                    reason: "target_closed".to_owned(),
                },
            )
            .expect("browser detach releases lifecycle capacity"),
        vec![
            BridgeEffect::EventToCdp {
                connection: cdp,
                event: claw_relay::CdpEvent {
                    session_id: None,
                    method: "Target.detachedFromTarget".to_owned(),
                    params: json!({
                        "sessionId": "gta-claw-tab-1",
                        "targetId": "target-41"
                    }),
                },
            },
            BridgeEffect::ToExtension(ExtensionCommand::Attach { seq: 2, tab_id: 42 }),
        ]
    );
}

#[test]
fn auto_attach_capacity_advances_across_enabled_connections() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    bridge.connect_extension(extension);
    bridge.connect_cdp(first).expect("first CDP");
    bridge.connect_cdp(second).expect("second CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![
                    tab(),
                    RelayTab {
                        tab_id: 42,
                        url: "https://second.example.test/".to_owned(),
                        title: "Second".to_owned(),
                        active: false,
                    },
                ],
            },
        )
        .expect("hello");
    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 1,
                    method: "Target.setAutoAttach".to_owned(),
                    params: Some(json!({ "autoAttach": true })),
                    session_id: None,
                },
            )
            .expect("first auto-attach owner"),
        vec![
            BridgeEffect::ToCdp {
                connection: first,
                response: claw_relay::CdpResponse {
                    id: 1,
                    session_id: None,
                    result: Some(json!({})),
                    error: None,
                },
            },
            BridgeEffect::ToExtension(ExtensionCommand::Attach { seq: 1, tab_id: 41 }),
        ]
    );
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({})),
            },
        )
        .expect("first owner reaches its root limit");
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 2,
                    method: "Target.setAutoAttach".to_owned(),
                    params: Some(json!({ "autoAttach": true })),
                    session_id: None,
                },
            )
            .expect("scheduler advances past the full first partition"),
        vec![
            BridgeEffect::ToCdp {
                connection: second,
                response: claw_relay::CdpResponse {
                    id: 2,
                    session_id: None,
                    result: Some(json!({})),
                    error: None,
                },
            },
            BridgeEffect::ToExtension(ExtensionCommand::Attach { seq: 2, tab_id: 42 }),
        ]
    );
}

#[test]
fn failed_auto_attach_is_handed_to_another_enabled_owner() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive per-client bound");
    bridge.connect_extension(extension);
    bridge.connect_cdp(first).expect("first CDP");
    bridge.connect_cdp(second).expect("second CDP");
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
                method: "Target.setAutoAttach".to_owned(),
                params: Some(json!({ "autoAttach": true })),
                session_id: None,
            },
        )
        .expect("first owner reserves the tab");
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 2,
                    method: "Target.setAutoAttach".to_owned(),
                    params: Some(json!({ "autoAttach": true })),
                    session_id: None,
                },
            )
            .expect("second owner waits on the reservation"),
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: None,
                result: Some(json!({})),
                error: None,
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Error {
                    seq: 1,
                    message: "first owner attach failed".to_owned(),
                },
            )
            .expect("failure suppression is scoped to the failed owner"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 2,
            tab_id: 41,
        })]
    );
}

#[test]
fn auto_attach_pumps_when_an_ordinary_command_releases_capacity() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::with_pending_limit(2).expect("positive per-client bound");
    bridge.connect_extension(extension);
    bridge.connect_cdp(cdp).expect("CDP");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: vec![
                    tab(),
                    RelayTab {
                        tab_id: 42,
                        url: "https://second.example.test/".to_owned(),
                        title: "Second".to_owned(),
                        active: false,
                    },
                ],
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
        .expect("root attach");
    bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({})),
            },
        )
        .expect("root attached");
    for (id, seq) in [(2, 2), (3, 3)] {
        assert_eq!(
            bridge
                .receive_cdp(
                    cdp,
                    CdpRequest {
                        id,
                        method: "Page.captureScreenshot".to_owned(),
                        params: Some(json!({ "format": "png" })),
                        session_id: Some("gta-claw-tab-1".to_owned()),
                    },
                )
                .expect("ordinary command fills pending capacity"),
            vec![BridgeEffect::ToExtension(ExtensionCommand::Cdp {
                seq,
                tab_id: 41,
                session_id: None,
                method: "Page.captureScreenshot".to_owned(),
                params: Some(json!({ "format": "png" })),
            })]
        );
    }
    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 4,
                    method: "Target.setAutoAttach".to_owned(),
                    params: Some(json!({ "autoAttach": true })),
                    session_id: None,
                },
            )
            .expect("auto attach waits for pending capacity"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 4,
                session_id: None,
                result: Some(json!({})),
                error: None,
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 2,
                    result: Some(json!({ "data": "first" })),
                },
            )
            .expect("ordinary completion pumps queued auto-attach work"),
        vec![
            BridgeEffect::ToCdp {
                connection: cdp,
                response: claw_relay::CdpResponse {
                    id: 2,
                    session_id: Some("gta-claw-tab-1".to_owned()),
                    result: Some(json!({ "data": "first" })),
                    error: None,
                },
            },
            BridgeEffect::ToExtension(ExtensionCommand::Attach { seq: 4, tab_id: 42 }),
        ]
    );
}

#[test]
fn concurrent_attach_is_rejected_before_either_extension_response() {
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
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(first).expect("first CDP");
    bridge.connect_cdp(second).expect("second CDP");
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
                first,
                CdpRequest {
                    id: 1,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "tab-41" })),
                    session_id: None,
                },
            )
            .expect("first attach"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 1,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 2,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "tab-41" })),
                    session_id: None,
                },
            )
            .expect("exclusive reservation response"),
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target is attached by another connection".to_owned(),
                }),
            },
        }]
    );

    let attached = bridge
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "target-41" })),
            },
        )
        .expect("first attach completion");
    assert_eq!(attached.len(), 2);
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 3,
                    method: "Runtime.evaluate".to_owned(),
                    params: Some(json!({ "expression": "document.title" })),
                    session_id: Some("gta-claw-tab-1".to_owned()),
                },
            )
            .expect("second client cannot steal first session"),
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
fn attach_reservations_release_into_bounded_timeout_and_disconnect_quarantine() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let mut bridge = CdpBridge::with_pending_limit(8).expect("positive pending bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(first).expect("first CDP");
    bridge.connect_cdp(second).expect("second CDP");
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

    let attach = |id| CdpRequest {
        id,
        method: "Target.attachToTarget".to_owned(),
        params: Some(json!({ "targetId": "tab-41" })),
        session_id: None,
    };
    assert_eq!(
        bridge
            .receive_cdp(first, attach(1))
            .expect("failure candidate"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 1,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Error {
                    seq: 1,
                    message: "attach failed".to_owned(),
                },
            )
            .expect("attach failure"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 1,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "attach failed".to_owned(),
                }),
            },
        }]
    );

    assert_eq!(
        bridge
            .receive_cdp(second, attach(2))
            .expect("reservation released after failure"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 2,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge.expire_command(2).expect("attach timeout"),
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 2,
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
            .receive_cdp(first, attach(3))
            .expect("target remains quarantined during late-response grace"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 3,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target is attached by another connection".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge.expire_command(2).expect("tombstone grace timeout"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 3,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge
            .receive_cdp(first, attach(4))
            .expect("cleanup detach keeps target quarantined"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 4,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target is attached by another connection".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 3,
                    result: Some(json!({})),
                },
            )
            .expect("cleanup detach completed"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_cdp(first, attach(5))
            .expect("reservation released after cleanup completion"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 4,
            tab_id: 41,
        })]
    );
    assert_eq!(bridge.disconnect_cdp(first), Vec::new());
    assert_eq!(
        bridge
            .receive_cdp(second, attach(6))
            .expect("target remains quarantined after owner disconnect"),
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 6,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target is attached by another connection".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .expire_command(4)
            .expect("disconnected attach tombstone grace timeout"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 5,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge
            .receive_cdp(second, attach(7))
            .expect("disconnect cleanup remains in flight"),
        vec![BridgeEffect::ToCdp {
            connection: second,
            response: claw_relay::CdpResponse {
                id: 7,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target is attached by another connection".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 5,
                    result: Some(json!({})),
                },
            )
            .expect("disconnect cleanup completed"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_cdp(second, attach(8))
            .expect("reservation released after disconnect cleanup"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 6,
            tab_id: 41,
        })]
    );
}

#[test]
fn abandoned_tombstones_release_pending_but_hold_lifecycle_capacity() {
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
    assert_eq!(bridge.connect_extension(extension), Vec::new());
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

    let attach = |id, target_id| CdpRequest {
        id,
        method: "Target.attachToTarget".to_owned(),
        params: Some(json!({ "targetId": target_id })),
        session_id: None,
    };
    bridge
        .receive_cdp(cdp, attach(1, "tab-41"))
        .expect("first attach");
    assert_eq!(
        bridge.expire_command(1).expect("first timeout"),
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
        bridge.receive_cdp(cdp, attach(2, "tab-42")),
        Err(BridgeError::SessionLimit)
    );
    assert_eq!(
        bridge.expire_command(1).expect("first tombstone grace"),
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
            .expect("first cleanup completion"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_cdp(cdp, attach(2, "tab-42"))
            .expect("cleanup completion releases lifecycle capacity"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 3,
            tab_id: 42,
        })]
    );
    assert_eq!(
        bridge.expire_command(3).expect("second timeout"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "extension relay command timed out".to_owned(),
                }),
            },
        }]
    );
}

#[test]
fn cleanup_failure_is_fail_closed_but_capacity_exhaustion_is_owner_local() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut failed_cleanup = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    assert_eq!(failed_cleanup.connect_extension(extension), Vec::new());
    failed_cleanup.connect_cdp(cdp).expect("CDP");
    failed_cleanup
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
    failed_cleanup
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
    failed_cleanup
        .expire_command(1)
        .expect("attach command timeout");
    assert_eq!(
        failed_cleanup
            .expire_command(1)
            .expect("late-response grace timeout"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 2,
            tab_id: 41,
        })]
    );
    assert_eq!(
        failed_cleanup
            .receive_extension(
                extension,
                ExtensionMessage::Error {
                    seq: 2,
                    message: "detach failed".to_owned(),
                },
            )
            .expect("cleanup failure closes extension"),
        vec![BridgeEffect::CloseExtension {
            connection: extension,
            code: 1011,
            reason: "Chrome debugger cleanup failed",
        }]
    );
    assert_eq!(
        failed_cleanup.receive_extension(extension, ExtensionMessage::Pong),
        Err(BridgeError::UnknownExtensionConnection)
    );

    let second_tab = RelayTab {
        tab_id: 42,
        url: "https://second.example.test/".to_owned(),
        title: "Second".to_owned(),
        active: false,
    };
    let mut exhausted = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    assert_eq!(exhausted.connect_extension(extension), Vec::new());
    exhausted.connect_cdp(cdp).expect("CDP");
    exhausted
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
    exhausted
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 2,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("first attach");
    exhausted.expire_command(1).expect("first attach timeout");
    assert_eq!(
        exhausted.receive_cdp(
            cdp,
            CdpRequest {
                id: 3,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-42" })),
                session_id: None,
            },
        ),
        Err(BridgeError::SessionLimit)
    );
    assert_eq!(
        exhausted
            .receive_extension(extension, ExtensionMessage::Pong)
            .expect("one owner's lifecycle exhaustion preserves the shared extension"),
        Vec::new()
    );
}

#[test]
fn cleanup_timeout_is_fail_closed_but_root_admission_prevents_disconnect_overflow() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut timed_out = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    assert_eq!(timed_out.connect_extension(extension), Vec::new());
    timed_out.connect_cdp(cdp).expect("CDP");
    timed_out
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
    timed_out
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
    timed_out.expire_command(1).expect("attach timeout");
    assert_eq!(
        timed_out
            .expire_command(1)
            .expect("late-response grace timeout"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 2,
            tab_id: 41,
        })]
    );
    assert_eq!(
        timed_out
            .expire_command(2)
            .expect("cleanup timeout closes extension"),
        vec![BridgeEffect::CloseExtension {
            connection: extension,
            code: 1011,
            reason: "Chrome debugger cleanup timed out",
        }]
    );

    let second_tab = RelayTab {
        tab_id: 42,
        url: "https://second.example.test/".to_owned(),
        title: "Second".to_owned(),
        active: false,
    };
    let mut overflow = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    assert_eq!(overflow.connect_extension(extension), Vec::new());
    overflow.connect_cdp(cdp).expect("CDP");
    overflow
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
    overflow
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 2,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("first attach");
    overflow
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 1,
                result: Some(json!({ "targetId": "tab-41" })),
            },
        )
        .expect("first attached");
    assert_eq!(
        overflow.receive_cdp(
            cdp,
            CdpRequest {
                id: 3,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-42" })),
                session_id: None,
            },
        ),
        Err(BridgeError::SessionLimit)
    );
    assert_eq!(
        overflow.disconnect_cdp(cdp),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 2,
            tab_id: 41,
        })]
    );
    assert_eq!(
        overflow
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 2,
                    result: Some(json!({})),
                },
            )
            .expect("bounded disconnect cleanup"),
        Vec::new()
    );
    assert_eq!(
        overflow
            .receive_extension(extension, ExtensionMessage::Pong)
            .expect("one owner's root limit preserves the shared extension"),
        Vec::new()
    );
}

#[test]
fn disconnect_promotes_existing_detach_without_queuing_a_duplicate() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let first = endpoint.accept(&cdp_upgrade()).expect("first CDP");
    let second = endpoint.accept(&cdp_upgrade()).expect("second CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
    bridge.connect_cdp(first).expect("first CDP");
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
    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 2,
                    method: "Target.detachFromTarget".to_owned(),
                    params: Some(json!({ "sessionId": "gta-claw-tab-1" })),
                    session_id: None,
                },
            )
            .expect("detach"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 2,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 8,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "target-41" })),
                    session_id: None,
                },
            )
            .expect("attach cannot overtake detach"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 8,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target detach is already pending".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_cdp(
                first,
                CdpRequest {
                    id: 9,
                    method: "Target.detachFromTarget".to_owned(),
                    params: Some(json!({ "sessionId": "gta-claw-tab-1" })),
                    session_id: None,
                },
            )
            .expect("duplicate detach is rejected"),
        vec![BridgeEffect::ToCdp {
            connection: first,
            response: claw_relay::CdpResponse {
                id: 9,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target detach is already pending".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(bridge.disconnect_cdp(first), Vec::new());
    assert!(!bridge.targets()[0].attached);
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 2,
                    result: Some(json!({})),
                },
            )
            .expect("promoted cleanup completed"),
        Vec::new()
    );
    bridge.connect_cdp(second).expect("second CDP");
    assert_eq!(
        bridge
            .receive_cdp(
                second,
                CdpRequest {
                    id: 3,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "target-41" })),
                    session_id: None,
                },
            )
            .expect("target reusable after cleanup"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 3,
            tab_id: 41,
        })]
    );
}

#[test]
fn detach_error_and_success_release_reservation_without_attach_overtaking() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
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
    let detach = |id| CdpRequest {
        id,
        method: "Target.detachFromTarget".to_owned(),
        params: Some(json!({ "sessionId": "gta-claw-tab-1" })),
        session_id: None,
    };
    let attach = |id| CdpRequest {
        id,
        method: "Target.attachToTarget".to_owned(),
        params: Some(json!({ "targetId": "target-41" })),
        session_id: None,
    };

    bridge.receive_cdp(cdp, detach(2)).expect("first detach");
    assert_eq!(
        bridge
            .receive_cdp(cdp, attach(3))
            .expect("attach denied during first detach"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 3,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target detach is already pending".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Error {
                    seq: 2,
                    message: "detach denied".to_owned(),
                },
            )
            .expect("detach error"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "detach denied".to_owned(),
                }),
            },
        }]
    );
    assert!(bridge.targets()[0].attached);
    assert_eq!(
        bridge
            .receive_cdp(cdp, attach(4))
            .expect("failed detach leaves existing session"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 4,
                session_id: None,
                result: Some(json!({ "sessionId": "gta-claw-tab-1" })),
                error: None,
            },
        }]
    );

    bridge.receive_cdp(cdp, detach(5)).expect("second detach");
    assert_eq!(
        bridge
            .receive_cdp(cdp, attach(6))
            .expect("attach denied during second detach"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 6,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target detach is already pending".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 3,
                    result: Some(json!({})),
                },
            )
            .expect("detach success"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 5,
                session_id: None,
                result: Some(json!({})),
                error: None,
            },
        }]
    );
    assert!(!bridge.targets()[0].attached);
    assert_eq!(
        bridge
            .receive_cdp(cdp, attach(7))
            .expect("successful detach releases target"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 4,
            tab_id: 41,
        })]
    );
}

#[test]
fn ordinary_cdp_detach_and_mixed_quarantine_timeouts_are_distinct() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut bridge = CdpBridge::with_pending_limit(2).expect("positive pending bound");
    assert_eq!(bridge.connect_extension(extension), Vec::new());
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
    bridge
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 2,
                method: "Runtime.evaluate".to_owned(),
                params: Some(json!({ "expression": "document.title" })),
                session_id: Some("gta-claw-tab-1".to_owned()),
            },
        )
        .expect("ordinary CDP command");
    assert_eq!(
        bridge.expire_command(2).expect("ordinary CDP timeout"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 2,
                session_id: Some("gta-claw-tab-1".to_owned()),
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
            .expire_command(2)
            .expect("ordinary CDP response needs no tombstone"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 3,
                    method: "Target.detachFromTarget".to_owned(),
                    params: Some(json!({ "sessionId": "gta-claw-tab-1" })),
                    session_id: None,
                },
            )
            .expect("detach"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Detach {
            seq: 3,
            tab_id: 41,
        })]
    );
    assert_eq!(
        bridge.expire_command(3).expect("detach timeout"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 3,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "extension relay command timed out".to_owned(),
                }),
            },
        }]
    );
    assert!(!bridge.targets()[0].attached);
    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 4,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "target-41" })),
                    session_id: None,
                },
            )
            .expect("cleanup quarantine"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 4,
                session_id: None,
                result: None,
                error: Some(CdpErrorObject {
                    code: -32000,
                    message: "target is attached by another connection".to_owned(),
                }),
            },
        }]
    );
    assert_eq!(
        bridge
            .receive_extension(
                extension,
                ExtensionMessage::Result {
                    seq: 3,
                    result: Some(json!({})),
                },
            )
            .expect("timed-out detach completed"),
        Vec::new()
    );
    assert_eq!(
        bridge
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 5,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "target-41" })),
                    session_id: None,
                },
            )
            .expect("cleanup released target"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 4,
            tab_id: 41,
        })]
    );

    let tabs = vec![
        tab(),
        RelayTab {
            tab_id: 42,
            url: "https://second.example.test/".to_owned(),
            title: "Second".to_owned(),
            active: false,
        },
        RelayTab {
            tab_id: 43,
            url: "https://third.example.test/".to_owned(),
            title: "Third".to_owned(),
            active: false,
        },
    ];
    let mut mixed = CdpBridge::with_pending_limit(2).expect("positive pending bound");
    assert_eq!(mixed.connect_extension(extension), Vec::new());
    mixed.connect_cdp(cdp).expect("CDP");
    mixed
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs,
            },
        )
        .expect("hello");
    mixed
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 6,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-41" })),
                session_id: None,
            },
        )
        .expect("first attach");
    mixed.expire_command(1).expect("abandoned attach");
    mixed
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 7,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-42" })),
                session_id: None,
            },
        )
        .expect("second attach");
    mixed
        .receive_extension(
            extension,
            ExtensionMessage::Result {
                seq: 2,
                result: Some(json!({ "targetId": "target-42" })),
            },
        )
        .expect("second attached");
    mixed
        .receive_cdp(
            cdp,
            CdpRequest {
                id: 8,
                method: "Target.detachFromTarget".to_owned(),
                params: Some(json!({ "sessionId": "gta-claw-tab-1" })),
                session_id: None,
            },
        )
        .expect("detach second");
    mixed.expire_command(3).expect("tracked cleanup");
    assert_eq!(
        mixed.receive_cdp(
            cdp,
            CdpRequest {
                id: 9,
                method: "Target.attachToTarget".to_owned(),
                params: Some(json!({ "targetId": "tab-43" })),
                session_id: None,
            },
        ),
        Err(BridgeError::SessionLimit)
    );
    assert_eq!(
        mixed
            .receive_extension(extension, ExtensionMessage::Pong)
            .expect("mixed quarantine exhaustion remains owner-local"),
        Vec::new()
    );
}

#[test]
fn tab_death_clears_quarantine_without_poisoning_auto_attach() {
    let mut endpoint = endpoint(4096);
    let extension = endpoint
        .accept(&extension_upgrade(
            &format!("chrome-extension://{EXTENSION_ID}"),
            TOKEN,
        ))
        .expect("extension");
    let cdp = endpoint.accept(&cdp_upgrade()).expect("CDP");
    let mut cleared = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    assert_eq!(cleared.connect_extension(extension), Vec::new());
    cleared.connect_cdp(cdp).expect("CDP");
    cleared
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
    cleared
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
    cleared.expire_command(1).expect("attach timeout");
    assert_eq!(
        cleared
            .receive_extension(extension, ExtensionMessage::Tabs { tabs: Vec::new() })
            .expect("tab death"),
        Vec::new()
    );
    assert_eq!(
        cleared
            .receive_extension(extension, ExtensionMessage::Tabs { tabs: vec![tab()] },)
            .expect("tab identity reused"),
        Vec::new()
    );
    assert_eq!(
        cleared
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 2,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": "tab-41" })),
                    session_id: None,
                },
            )
            .expect("authoritative death cleared quarantine"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 2,
            tab_id: 41,
        })]
    );

    let tabs = [
        tab(),
        RelayTab {
            tab_id: 42,
            url: "https://second.example.test/".to_owned(),
            title: "Second".to_owned(),
            active: false,
        },
        RelayTab {
            tab_id: 43,
            url: "https://third.example.test/".to_owned(),
            title: "Third".to_owned(),
            active: false,
        },
    ];
    let mut preserved = CdpBridge::with_pending_limit(2).expect("positive pending bound");
    assert_eq!(preserved.connect_extension(extension), Vec::new());
    preserved.connect_cdp(cdp).expect("CDP");
    preserved
        .receive_extension(
            extension,
            ExtensionMessage::Hello {
                user_agent: "Fixture".to_owned(),
                browser_version: "Chrome/144".to_owned(),
                extension_version: "2.0.0".to_owned(),
                tabs: tabs.to_vec(),
            },
        )
        .expect("hello");
    for (request_id, sequence, target_id) in [(3, 1, "tab-41"), (4, 2, "tab-42")] {
        preserved
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: request_id,
                    method: "Target.attachToTarget".to_owned(),
                    params: Some(json!({ "targetId": target_id })),
                    session_id: None,
                },
            )
            .expect("attach");
        preserved
            .expire_command(sequence)
            .expect("fills cleanup quarantine");
    }
    assert_eq!(
        preserved
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 5,
                    method: "Target.setAutoAttach".to_owned(),
                    params: Some(json!({ "autoAttach": true })),
                    session_id: None,
                },
            )
            .expect("auto attach third tab"),
        vec![BridgeEffect::ToCdp {
            connection: cdp,
            response: claw_relay::CdpResponse {
                id: 5,
                session_id: None,
                result: Some(json!({})),
                error: None,
            },
        }]
    );
    let fourth_tab = RelayTab {
        tab_id: 44,
        url: "https://fourth.example.test/".to_owned(),
        title: "Fourth".to_owned(),
        active: false,
    };
    assert_eq!(
        preserved
            .receive_extension(
                extension,
                ExtensionMessage::Tabs {
                    tabs: vec![tabs[1].clone(), fourth_tab],
                },
            )
            .expect("authoritative death releases one quarantined lifecycle slot"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 3,
            tab_id: 44,
        })]
    );

    let replacement_tab = RelayTab {
        tab_id: 42,
        url: "https://replacement.example.test/".to_owned(),
        title: "Replacement".to_owned(),
        active: false,
    };
    let mut replacement = CdpBridge::with_pending_limit(1).expect("positive pending bound");
    assert_eq!(replacement.connect_extension(extension), Vec::new());
    replacement.connect_cdp(cdp).expect("CDP");
    replacement
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
    assert_eq!(
        replacement
            .receive_cdp(
                cdp,
                CdpRequest {
                    id: 6,
                    method: "Target.setAutoAttach".to_owned(),
                    params: Some(json!({ "autoAttach": true })),
                    session_id: None,
                },
            )
            .expect("auto attach"),
        vec![
            BridgeEffect::ToCdp {
                connection: cdp,
                response: claw_relay::CdpResponse {
                    id: 6,
                    session_id: None,
                    result: Some(json!({})),
                    error: None,
                },
            },
            BridgeEffect::ToExtension(ExtensionCommand::Attach { seq: 1, tab_id: 41 }),
        ]
    );
    assert_eq!(
        replacement
            .receive_extension(
                extension,
                ExtensionMessage::Tabs {
                    tabs: vec![replacement_tab],
                },
            )
            .expect("dead pending target is reaped before replacement preflight"),
        vec![BridgeEffect::ToExtension(ExtensionCommand::Attach {
            seq: 2,
            tab_id: 42,
        })]
    );
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

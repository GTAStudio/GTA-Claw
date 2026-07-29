//! End-to-end TUI worker coverage over a real local WebSocket double.

#[expect(
    dead_code,
    reason = "the Gateway test double is shared with claw-gateway-client, which owns the file; \
              this binary exercises only the subset the TUI worker needs"
)]
#[path = "../../../crates/claw-gateway-client/tests/support/mod.rs"]
mod support;

use std::time::Duration;

use claw_protocol::gateway::{AUTHENTICATED_MAX_FRAME_BYTES, Codec};
use gta_claw_tui::gateway::{GatewayOptions, UiCommand, WorkerEvent, spawn_gateway_worker};
use gta_claw_tui::model::{RunState, SessionSummary, TranscriptEntry};
use serde_json::json;
use support::{
    TestGateway, complete_handshake, handler, raw_stalled_server, receive_request, send_json,
    wait_for_close,
};

#[tokio::test]
async fn gateway_worker_loads_sessions_and_streams_transcript() {
    let gateway = TestGateway::spawn(handler(|mut socket, _| async move {
        let (_, params) = complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        assert_eq!(
            params
                .scopes
                .expect("TUI requests scopes")
                .iter()
                .map(claw_protocol::gateway::Name::as_str)
                .collect::<Vec<_>>(),
            vec!["operator.read", "operator.write", "operator.approvals"]
        );
        let request = receive_request(&mut socket).await;
        assert_eq!(request.method().as_str(), "sessions.list");
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": request.id().as_str(),
                "ok": true,
                "payload": {
                    "sessions": [{
                        "id": "session-42",
                        "title": "Repair updater",
                        "workspace": "D:\\work\\gta-claw",
                        "state": "running",
                        "progress": 37
                    }]
                }
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "event",
                "event": "session.message",
                "payload": {
                    "sessionId": "session-42",
                    "role": "assistant",
                    "text": "Downloaded manifest"
                },
                "seq": 1
            }),
        )
        .await;
        send_json(
            &mut socket,
            json!({
                "type": "event",
                "event": "sessions.changed",
                "seq": 2
            }),
        )
        .await;
        let list = receive_request(&mut socket).await;
        assert_eq!(list.method().as_str(), "artifacts.list");
        let list_params = Codec::authenticated()
            .decode_opaque::<serde_json::Value>(
                list.params().value().expect("artifact list params"),
            )
            .expect("decode artifact list params");
        assert_eq!(list_params, json!({"sessionId": "session-42"}));
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": list.id().as_str(),
                "ok": true,
                "payload": {
                    "artifacts": [{
                        "id": "artifact-7",
                        "name": "report.json"
                    }]
                }
            }),
        )
        .await;
        let get = receive_request(&mut socket).await;
        assert_eq!(get.method().as_str(), "artifacts.get");
        let get_params = Codec::authenticated()
            .decode_opaque::<serde_json::Value>(get.params().value().expect("artifact get params"))
            .expect("decode artifact get params");
        assert_eq!(
            get_params,
            json!({"sessionId": "session-42", "artifactId": "artifact-7"})
        );
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": get.id().as_str(),
                "ok": true,
                "payload": {"content": "{\n  \"status\": \"ok\"\n}"}
            }),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;

    let mut worker = spawn_gateway_worker(GatewayOptions {
        url: gateway.url.clone(),
        token: None,
    });
    let connecting = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("connecting event timeout")
        .expect("connecting event");
    assert_eq!(
        connecting,
        WorkerEvent::Connection("Gateway: connecting (bounded retries)".to_owned())
    );
    let connection = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("connection event timeout")
        .expect("connection event");
    assert_eq!(
        connection,
        WorkerEvent::Connection("Gateway: ready (protocol 4, epoch 1)".to_owned())
    );
    let sessions = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("sessions event timeout")
        .expect("sessions event");
    assert_eq!(
        sessions,
        WorkerEvent::Sessions(vec![SessionSummary {
            id: "session-42".to_owned(),
            title: "Repair updater".to_owned(),
            workspace: "D:\\work\\gta-claw".to_owned(),
            state: RunState::Running,
            progress: Some(37),
        }])
    );
    let message = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("message event timeout")
        .expect("message event");
    assert_eq!(
        message,
        WorkerEvent::Message(TranscriptEntry {
            role: "assistant".to_owned(),
            text: "Downloaded manifest".to_owned(),
        })
    );
    let changed = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("changed event timeout")
        .expect("changed event");
    assert_eq!(
        changed,
        WorkerEvent::Notice("Sessions changed; press r to refresh".to_owned())
    );
    worker
        .commands
        .send(UiCommand::LoadArtifacts("session-42".to_owned()))
        .await
        .expect("request artifacts");
    let artifacts = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("artifacts event timeout")
        .expect("artifacts event");
    assert_eq!(
        artifacts,
        WorkerEvent::Artifacts(vec!["report.json".to_owned()])
    );
    let preview = tokio::time::timeout(Duration::from_secs(3), worker.events.recv())
        .await
        .expect("artifact preview timeout")
        .expect("artifact preview");
    assert_eq!(
        preview,
        WorkerEvent::ArtifactContent(vec![
            "{".to_owned(),
            "  \"status\": \"ok\"".to_owned(),
            "}".to_owned(),
        ])
    );

    worker.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn failed_connections_can_be_retried_without_restarting_the_tui() {
    let gateway = TestGateway::spawn(handler(|mut socket, index| async move {
        if index < 3 {
            return;
        }
        complete_handshake(&mut socket, AUTHENTICATED_MAX_FRAME_BYTES).await;
        let request = receive_request(&mut socket).await;
        assert_eq!(request.method().as_str(), "sessions.list");
        send_json(
            &mut socket,
            json!({
                "type": "res",
                "id": request.id().as_str(),
                "ok": true,
                "payload": {"sessions": []}
            }),
        )
        .await;
        wait_for_close(&mut socket).await;
    }))
    .await;
    let mut worker = spawn_gateway_worker(GatewayOptions {
        url: gateway.url.clone(),
        token: None,
    });

    assert_eq!(
        worker.events.recv().await,
        Some(WorkerEvent::Connection(
            "Gateway: connecting (bounded retries)".to_owned()
        ))
    );
    let unavailable = tokio::time::timeout(Duration::from_secs(5), worker.events.recv())
        .await
        .expect("bounded connection attempts")
        .expect("unavailable event");
    assert_eq!(
        unavailable,
        WorkerEvent::Connection("Gateway: unavailable (press r to retry)".to_owned())
    );
    let _notice = worker.events.recv().await.expect("actionable error notice");
    worker
        .commands
        .send(UiCommand::Refresh)
        .await
        .expect("retry command");
    assert_eq!(
        worker.events.recv().await,
        Some(WorkerEvent::Connection(
            "Gateway: connecting (bounded retries)".to_owned()
        ))
    );
    assert!(matches!(
        worker.events.recv().await,
        Some(WorkerEvent::Connection(connection)) if connection.starts_with("Gateway: ready")
    ));
    assert_eq!(
        worker.events.recv().await,
        Some(WorkerEvent::Sessions(Vec::new()))
    );

    worker.shutdown().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn shutdown_cancels_a_stalled_connection_attempt() {
    let (url, cancellation, tasks, handshake_received) = raw_stalled_server().await;
    let mut worker = spawn_gateway_worker(GatewayOptions { url, token: None });
    assert!(matches!(
        worker.events.recv().await,
        Some(WorkerEvent::Connection(_))
    ));
    tokio::time::timeout(Duration::from_secs(2), handshake_received)
        .await
        .expect("server received the WebSocket handshake")
        .expect("handshake readiness signal sent");
    tokio::time::timeout(Duration::from_secs(2), worker.shutdown())
        .await
        .expect("worker shutdown is bounded");

    cancellation.cancel();
    tasks.close();
    tokio::time::timeout(Duration::from_secs(2), tasks.wait())
        .await
        .expect("stalled test server shuts down");
}

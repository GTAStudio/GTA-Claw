//! Frozen legacy `src/server.ts` HTTP acceptance and resource-bound regressions.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_http_api::{
    DeterministicRuntime, LEGACY_TEAMS_AUTHORIZATION_BYTES, LegacyAdminAction,
    LegacyAdminCredential, LegacyApiConfig, LegacyApiServices, LegacyChannelMessage,
    LegacyChannelMessagePort, LegacyConfigError, LegacyDeviceFlowPort, LegacyExecResult,
    LegacyHostAdminPort, LegacyHttpApi, LegacyOsInfo, LegacyProcessInfo, LegacyProcessMemory,
    LegacyReloadError, LegacyReloadPort, LegacyReloadResult, LegacyRuntimePort,
    LegacyRuntimeSnapshot, LegacySystemInfo, LegacyTeamsPort, LegacyTeamsRequestContext,
    LegacyWhatsAppConfig, LegacyWhatsAppPort, LegacyWhatsAppServices, PortError, PortErrorKind,
    PortFuture, ProviderLegacyRuntime, ProviderLegacyRuntimeConfig, ServingStateHandle,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

const DEVICE_INSTRUCTIONS: &str = "Please authorize GTA-Claw with your GitHub account:\n1. Open: https://github.com/login/device\n2. Enter code: **ABCD-EFGH**";
const ADMIN_TOKEN: &str = "legacy-admin-token";

#[derive(Clone)]
struct ScriptedRuntime {
    snapshot: Arc<Mutex<LegacyRuntimeSnapshot>>,
    reply: Arc<Mutex<String>>,
    fail_chat: Arc<AtomicBool>,
    degrade_chat_durability: Arc<AtomicBool>,
    chats: Arc<Mutex<Vec<(String, String)>>>,
}

impl ScriptedRuntime {
    fn new(snapshot: LegacyRuntimeSnapshot) -> Arc<Self> {
        Arc::new(Self {
            snapshot: Arc::new(Mutex::new(snapshot)),
            reply: Arc::new(Mutex::new("Hello.".to_owned())),
            fail_chat: Arc::new(AtomicBool::new(false)),
            degrade_chat_durability: Arc::new(AtomicBool::new(false)),
            chats: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn set_authenticated(&self, authenticated: bool) {
        self.snapshot.lock().expect("snapshot lock").authenticated = authenticated;
    }

    fn chats(&self) -> Vec<(String, String)> {
        self.chats.lock().expect("chat log").clone()
    }
}

impl LegacyRuntimePort for ScriptedRuntime {
    fn snapshot(&self) -> Result<LegacyRuntimeSnapshot, PortError> {
        Ok(self.snapshot.lock().expect("snapshot lock").clone())
    }

    fn chat(
        &self,
        conversation_id: String,
        message: String,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>> {
        self.chats
            .lock()
            .expect("chat log")
            .push((conversation_id, message));
        let fail = self.fail_chat.load(Ordering::Acquire);
        let degraded_durability = self.degrade_chat_durability.load(Ordering::Acquire);
        let reply = self.reply.lock().expect("reply lock").clone();
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(PortError::new(PortErrorKind::Unavailable, "cancelled"));
            }
            if fail {
                Err(PortError::new(PortErrorKind::Internal, "scripted failure"))
            } else if degraded_durability {
                Err(PortError::new(
                    PortErrorKind::CommittedButNotDurable,
                    "State may already be committed; durability is unconfirmed. Do not retry.",
                ))
            } else {
                Ok(reply)
            }
        })
    }
}

#[derive(Default)]
struct ScriptedDeviceFlow {
    fail: AtomicBool,
}

impl LegacyDeviceFlowPort for ScriptedDeviceFlow {
    fn instructions(
        &self,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>> {
        let fail = self.fail.load(Ordering::Acquire);
        Box::pin(async move {
            if fail {
                Err(PortError::new(PortErrorKind::Unavailable, "offline"))
            } else {
                Ok(DEVICE_INSTRUCTIONS.to_owned())
            }
        })
    }
}

#[derive(Default)]
struct ScriptedTeams {
    calls: AtomicUsize,
    contexts: Mutex<Vec<LegacyTeamsRequestContext>>,
    activities: Mutex<Vec<Value>>,
    reject_missing_authorization: AtomicBool,
}

impl LegacyTeamsPort for ScriptedTeams {
    fn handle_activity(
        &self,
        context: LegacyTeamsRequestContext,
        activity: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let missing_authorization = context.authorization().is_none();
        self.contexts
            .lock()
            .expect("Teams context log")
            .push(context);
        self.activities
            .lock()
            .expect("Teams activity log")
            .push(activity);
        let reject_missing = self.reject_missing_authorization.load(Ordering::Acquire);
        Box::pin(async move {
            if reject_missing && missing_authorization {
                Err(PortError::new(
                    PortErrorKind::InvalidRequest,
                    "Teams authorization is required",
                ))
            } else {
                Ok(())
            }
        })
    }
}

struct ScriptedMessages {
    reply: Mutex<String>,
    received: Mutex<Vec<LegacyChannelMessage>>,
}

impl ScriptedMessages {
    fn new(reply: String) -> Arc<Self> {
        Arc::new(Self {
            reply: Mutex::new(reply),
            received: Mutex::new(Vec::new()),
        })
    }
}

impl LegacyChannelMessagePort for ScriptedMessages {
    fn process(
        &self,
        message: LegacyChannelMessage,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>> {
        self.received.lock().expect("message log").push(message);
        let reply = self.reply.lock().expect("reply lock").clone();
        Box::pin(async move { Ok(reply) })
    }
}

#[derive(Default)]
struct ScriptedWhatsApp {
    fail: AtomicBool,
    sent: Mutex<Vec<(String, String)>>,
    signature_calls: AtomicUsize,
    signature_payloads: Mutex<Vec<Vec<u8>>>,
    webhook_calls: AtomicUsize,
    webhook_payloads: Mutex<Vec<Vec<u8>>>,
}

impl LegacyWhatsAppPort for ScriptedWhatsApp {
    fn verify_webhook_signature(&self, payload: &[u8], signature: &str) -> Result<bool, PortError> {
        self.signature_calls.fetch_add(1, Ordering::AcqRel);
        self.signature_payloads
            .lock()
            .expect("signature payloads")
            .push(payload.to_vec());
        Ok(signature == whatsapp_signature(payload))
    }

    fn handle_webhook(
        &self,
        payload: Vec<u8>,
        messages: Arc<dyn LegacyChannelMessagePort>,
        max_reply_bytes: usize,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>> {
        self.webhook_calls.fetch_add(1, Ordering::AcqRel);
        self.webhook_payloads
            .lock()
            .expect("webhook payloads")
            .push(payload.clone());
        let fail = self.fail.load(Ordering::Acquire);
        Box::pin(async move {
            if fail {
                return Err(PortError::new(PortErrorKind::Unavailable, "webhook failed"));
            }
            let body: Value = serde_json::from_slice(&payload)
                .map_err(|_| PortError::new(PortErrorKind::InvalidRequest, "invalid webhook"))?;
            let entries = body
                .get("entry")
                .and_then(Value::as_array)
                .into_iter()
                .flatten();
            for entry in entries {
                let changes = entry
                    .get("changes")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten();
                for change in changes {
                    let webhook_messages = change
                        .get("value")
                        .and_then(|value| value.get("messages"))
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten();
                    for message in webhook_messages {
                        if message.get("type").and_then(Value::as_str) != Some("text") {
                            continue;
                        }
                        let Some(from) = message
                            .get("from")
                            .and_then(Value::as_str)
                            .filter(|from| !from.trim().is_empty())
                        else {
                            continue;
                        };
                        let Some(text) = message
                            .get("text")
                            .and_then(|text| text.get("body"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|text| !text.is_empty())
                        else {
                            continue;
                        };
                        let reply = messages
                            .process(
                                LegacyChannelMessage {
                                    channel: "whatsapp",
                                    conversation_id: format!("whatsapp:{from}"),
                                    user_name: from.to_owned(),
                                    text: text.to_owned(),
                                },
                                cancellation.clone(),
                            )
                            .await?;
                        if reply.len() > max_reply_bytes {
                            return Err(PortError::new(
                                PortErrorKind::InvalidRequest,
                                "WhatsApp reply exceeds the byte limit",
                            ));
                        }
                        for chunk in reply_chunks(&reply, 3_500) {
                            self.sent
                                .lock()
                                .expect("send log")
                                .push((from.to_owned(), chunk));
                        }
                    }
                }
            }
            Ok(())
        })
    }

    fn send_text(
        &self,
        to: String,
        text: String,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>> {
        let fail = self.fail.load(Ordering::Acquire);
        if !fail {
            self.sent.lock().expect("send log").push((to, text));
        }
        Box::pin(async move {
            if fail {
                Err(PortError::new(PortErrorKind::Unavailable, "send failed"))
            } else {
                Ok(())
            }
        })
    }
}

#[derive(Default)]
struct ScriptedReload {
    mode: AtomicU8,
}

impl LegacyReloadPort for ScriptedReload {
    fn reload(
        &self,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacyReloadResult, LegacyReloadError>> {
        let mode = self.mode.load(Ordering::Acquire);
        Box::pin(async move {
            match mode {
                1 => Err(LegacyReloadError::InProgress),
                2 => Err(LegacyReloadError::Failed),
                _ => Ok(LegacyReloadResult {
                    role_model: Some("gpt-4o".to_owned()),
                    skill_count: 10,
                }),
            }
        })
    }
}

struct ScriptedAdmin {
    outcome: Mutex<LegacyExecResult>,
    calls: Mutex<Vec<(LegacyAdminAction, Option<String>)>>,
}

impl ScriptedAdmin {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            outcome: Mutex::new(LegacyExecResult {
                success: true,
                output: Some("up 1 day\n".to_owned()),
                error: None,
                stderr: None,
            }),
            calls: Mutex::new(Vec::new()),
        })
    }
}

impl LegacyHostAdminPort for ScriptedAdmin {
    fn system_info(
        &self,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacySystemInfo, PortError>> {
        Box::pin(async {
            Ok(LegacySystemInfo {
                node: LegacyProcessInfo {
                    version: "v20.0.0".to_owned(),
                    pid: 100,
                    uptime_s: 12,
                    memory_mb: LegacyProcessMemory {
                        rss: 100,
                        heap_used: 50,
                        heap_total: 75,
                    },
                },
                os: LegacyOsInfo {
                    hostname: "fixture".to_owned(),
                    platform: "linux".to_owned(),
                    arch: "x64".to_owned(),
                    cpus: 4,
                    total_memory_mb: 8_192,
                    free_memory_mb: 4_096,
                    uptime_s: 1_000,
                    loadavg: [0.1, 0.2, 0.3],
                },
            })
        })
    }

    fn execute(
        &self,
        action: LegacyAdminAction,
        target: Option<String>,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacyExecResult, PortError>> {
        self.calls
            .lock()
            .expect("admin calls")
            .push((action, target));
        let outcome = self.outcome.lock().expect("admin outcome").clone();
        Box::pin(async move { Ok(outcome) })
    }
}

struct Fixtures {
    runtime: Arc<ScriptedRuntime>,
    readiness: Arc<DeterministicRuntime>,
    device: Arc<ScriptedDeviceFlow>,
    teams: Arc<ScriptedTeams>,
    messages: Arc<ScriptedMessages>,
    whatsapp: Arc<ScriptedWhatsApp>,
    reload: Arc<ScriptedReload>,
    admin: Arc<ScriptedAdmin>,
}

impl Fixtures {
    fn new(authenticated: bool) -> Self {
        Self {
            runtime: ScriptedRuntime::new(LegacyRuntimeSnapshot {
                skill_count: 10,
                active_model: "gpt-4o".to_owned(),
                session_count: 0,
                authenticated,
            }),
            readiness: DeterministicRuntime::new(),
            device: Arc::new(ScriptedDeviceFlow::default()),
            teams: Arc::new(ScriptedTeams::default()),
            messages: ScriptedMessages::new("reply".to_owned()),
            whatsapp: Arc::new(ScriptedWhatsApp::default()),
            reload: Arc::new(ScriptedReload::default()),
            admin: ScriptedAdmin::new(),
        }
    }

    fn services(&self) -> LegacyApiServices {
        LegacyApiServices {
            runtime: self.runtime.clone(),
            readiness: self.readiness.clone(),
            device_flow: Some(self.device.clone()),
            teams: Some(self.teams.clone()),
            whatsapp: Some(LegacyWhatsAppServices {
                phone_number_id: "fixture-phone".to_owned(),
                messages: self.messages.clone(),
                sender: self.whatsapp.clone(),
            }),
            reload: Some(self.reload.clone()),
            admin: Some(self.admin.clone()),
        }
    }
}

#[tokio::test]
async fn legacy_root_device_chat_and_health_match_frozen_shapes() {
    let fixtures = Fixtures::new(false);
    let config = LegacyApiConfig {
        device_flow_enabled: true,
        ..LegacyApiConfig::default()
    };
    let server = spawn(config, fixtures.services()).await;

    let root = request(&server, "GET", "/", None, &[], b"").await;
    assert_eq!(root.status, 200);
    assert_eq!(
        root.json(),
        frozen_response("root", "unauthenticated-no-channels")
    );

    let health = request(&server, "GET", "/health", None, &[], b"").await;
    assert_eq!(health.status, 200);
    let mut expected_health = frozen_response("health", "healthy-unauthenticated");
    expected_health["uptime"] = health.json()["uptime"].clone();
    expected_health["channels"] = json!({
        "teams":false,"telegram":false,"discord":false,"whatsapp":false
    });
    assert_eq!(health.json(), expected_health);

    let instructions = request(&server, "GET", "/auth/device", None, &[], b"").await;
    assert_eq!(instructions.status, 200);
    assert_eq!(
        instructions.json(),
        frozen_response("device-auth", "instructions")
    );

    let missing = request(
        &server,
        "POST",
        "/chat",
        None,
        &[("Content-Type", "application/json")],
        b"{}",
    )
    .await;
    assert_eq!(missing.status, 400);
    assert_eq!(missing.json(), frozen_response("chat", "missing-message"));

    let help = json_request(&server, "/chat", None, &json!({"message":"/START"})).await;
    assert_eq!(help.status, 200);
    assert_eq!(help.json(), frozen_response("chat", "help-before-auth"));

    let unauthenticated = json_request(&server, "/chat", None, &json!({"prompt":"hello"})).await;
    assert_eq!(unauthenticated.status, 401);
    assert_eq!(
        unauthenticated.json(),
        frozen_response("chat", "unauthenticated-device-flow")
    );

    fixtures.runtime.set_authenticated(true);
    let already = request(&server, "GET", "/auth/device", None, &[], b"").await;
    assert_eq!(
        already.json(),
        frozen_response("device-auth", "already-authenticated")
    );
    let success = json_request(
        &server,
        "/chat",
        None,
        &json!({
            "message":" hello ",
            "conversation_id":"demo-1",
            "conversationId":"ignored"
        }),
    )
    .await;
    assert_eq!(success.status, 200);
    assert_eq!(success.json(), frozen_response("chat", "success"));
    assert_eq!(
        fixtures.runtime.chats().last(),
        Some(&("demo-1".to_owned(), "hello".to_owned()))
    );

    fixtures.runtime.fail_chat.store(true, Ordering::Release);
    let failed = json_request(&server, "/chat", None, &json!({"message":"hello"})).await;
    assert_eq!(failed.status, 500);
    assert_eq!(failed.json(), frozen_response("chat", "endpoint-error"));

    fixtures.runtime.set_authenticated(false);
    fixtures.device.fail.store(true, Ordering::Release);
    let device_failed = request(&server, "GET", "/auth/device", None, &[], b"").await;
    assert_eq!(device_failed.status, 500);
    assert_eq!(
        device_failed.json(),
        frozen_response("device-auth", "unexpected-error")
    );

    let token_fixtures = Fixtures::new(false);
    let token_server = spawn(
        LegacyApiConfig::default(),
        LegacyApiServices {
            device_flow: None,
            ..token_fixtures.services()
        },
    )
    .await;
    let disabled = request(&token_server, "GET", "/auth/device", None, &[], b"").await;
    assert_eq!(disabled.status, 400);
    assert_eq!(disabled.json(), frozen_response("device-auth", "disabled"));
    let token_mode = json_request(&token_server, "/chat", None, &json!({"text":"hello"})).await;
    assert_eq!(token_mode.status, 401);
    assert_eq!(
        token_mode.json(),
        frozen_response("chat", "unauthenticated-token-mode")
    );
}

#[tokio::test]
async fn legacy_chat_preserves_committed_but_not_durable_outcome() {
    let fixtures = Fixtures::new(true);
    fixtures
        .runtime
        .degrade_chat_durability
        .store(true, Ordering::Release);
    let server = spawn(LegacyApiConfig::default(), fixtures.services()).await;

    let response = json_request(&server, "/chat", None, &json!({"message":"set goal"})).await;

    assert_eq!(response.status, 409);
    assert_eq!(
        response.json(),
        json!({
            "error":"State may already be committed; durability is unconfirmed. Do not retry.",
            "type":"committed_but_not_durable",
            "retryable":false,
            "stateMayAlreadyBeCommitted":true
        })
    );
}

#[tokio::test]
async fn teams_route_is_conditional_rate_limited_and_body_bounded() {
    let fixtures = Fixtures::new(true);
    let mut config = LegacyApiConfig::default();
    config.channels.set_teams(true);
    config.trust_proxy = true;
    config.teams_rate_limit_per_minute = 1;
    config.limits.rate_limit_clients = 1;
    config.limits.rate_limit_idle_timeout = Duration::from_millis(20);
    let server = spawn(config, fixtures.services()).await;

    let accepted = request(
        &server,
        "POST",
        "/api/messages",
        None,
        &[
            ("Content-Type", "application/json"),
            ("x-forwarded-for", "198.51.100.1, 10.0.0.1"),
        ],
        b"{}",
    )
    .await;
    assert_eq!(accepted.status, 200);
    assert_eq!(
        accepted.json(),
        frozen_response("teams-messages", "adapter-ack")
    );
    assert!(
        fixtures
            .teams
            .contexts
            .lock()
            .expect("Teams contexts")
            .first()
            .expect("accepted Teams context")
            .authorization()
            .is_none(),
        "a missing header must be delegated to the Teams adapter"
    );

    let limited = request(
        &server,
        "POST",
        "/api/messages",
        None,
        &[
            ("Content-Type", "application/json"),
            ("x-forwarded-for", "198.51.100.1"),
        ],
        b"{}",
    )
    .await;
    assert_eq!(limited.status, 429);
    assert_eq!(
        limited.json(),
        frozen_response("teams-messages", "rate-limited")
    );

    let saturated = request(
        &server,
        "POST",
        "/api/messages",
        None,
        &[
            ("Content-Type", "application/json"),
            ("x-forwarded-for", "198.51.100.2"),
        ],
        b"{}",
    )
    .await;
    assert_eq!(
        saturated.status, 429,
        "identity churn must not evict a live rate-limit bucket"
    );
    sleep(Duration::from_millis(25)).await;
    let after_idle = request(
        &server,
        "POST",
        "/api/messages",
        None,
        &[
            ("Content-Type", "application/json"),
            ("x-forwarded-for", "198.51.100.2"),
        ],
        b"{}",
    )
    .await;
    assert_eq!(
        after_idle.status, 200,
        "an idle bucket must be reclaimed for a new client"
    );

    let disabled = spawn(LegacyApiConfig::default(), fixtures.services()).await;
    assert_eq!(
        request(&disabled, "POST", "/api/messages", None, &[], b"{}")
            .await
            .status,
        404
    );

    let mut bounded = LegacyApiConfig::default();
    bounded.channels.set_teams(true);
    bounded.limits.body_bytes = 8;
    let bounded_server = spawn(bounded, fixtures.services()).await;
    let oversized = request(
        &bounded_server,
        "POST",
        "/api/messages",
        None,
        &[("Content-Type", "application/json")],
        br#"{"activity":"too large"}"#,
    )
    .await;
    assert_eq!(oversized.status, 413);
    assert_eq!(oversized.header("connection"), Some("close"));
}

#[tokio::test]
async fn teams_authorization_context_is_validated_forwarded_and_redacted() {
    let fixtures = Fixtures::new(true);
    let mut config = LegacyApiConfig::default();
    config.channels.set_teams(true);
    config.teams_rate_limit_per_minute = 100;
    let server = spawn(config, fixtures.services()).await;
    let exact_header = "bEaReR aaa.BBB_cc-1~+/==";
    let activity = json!({"type":"message","id":"activity-1"});

    let accepted = request(
        &server,
        "POST",
        "/api/messages",
        None,
        &[
            ("Content-Type", "application/json"),
            ("Authorization", exact_header),
        ],
        &serde_json::to_vec(&activity).expect("serialize Teams activity"),
    )
    .await;
    assert_eq!(accepted.status, 200);
    {
        let contexts = fixtures.teams.contexts.lock().expect("Teams contexts");
        let context = contexts.last().expect("forwarded Teams context");
        let authorization = context.authorization().expect("forwarded authorization");
        assert_eq!(authorization.as_str(), exact_header);
        assert_eq!(authorization.bearer_token(), "aaa.BBB_cc-1~+/==");
        for rendered in [format!("{authorization:?}"), format!("{context:?}")] {
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains("aaa.BBB"));
        }
        drop(contexts);
    }
    assert_eq!(
        fixtures
            .teams
            .activities
            .lock()
            .expect("Teams activities")
            .last(),
        Some(&activity)
    );

    fixtures
        .teams
        .reject_missing_authorization
        .store(true, Ordering::Release);
    let missing = request(
        &server,
        "POST",
        "/api/messages",
        None,
        &[("Content-Type", "application/json")],
        b"{}",
    )
    .await;
    assert_eq!(
        missing.status, 500,
        "the adapter, not the generic HTTP crate, decides whether missing auth is allowed"
    );

    let calls_before_invalid = fixtures.teams.calls.load(Ordering::Acquire);
    let invalid_response = json!({"error":"Invalid Authorization header"});
    for invalid in [
        "Basic opaque",
        "Bearer",
        "Bearer two tokens",
        "Bearer token,second",
        "Bearer =",
    ] {
        let response = request(
            &server,
            "POST",
            "/api/messages",
            None,
            &[
                ("Content-Type", "application/json"),
                ("Authorization", invalid),
            ],
            b"{}",
        )
        .await;
        assert_eq!(response.status, 400, "{invalid}");
        assert_eq!(response.json(), invalid_response, "{invalid}");
        assert!(!response.text().contains(invalid), "{invalid}");
    }

    let duplicate = request(
        &server,
        "POST",
        "/api/messages",
        None,
        &[
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer first"),
            ("Authorization", "Bearer second"),
        ],
        b"{}",
    )
    .await;
    assert_eq!(duplicate.status, 400);
    assert_eq!(duplicate.json(), invalid_response);

    let oversized = format!(
        "Bearer {}",
        "a".repeat(LEGACY_TEAMS_AUTHORIZATION_BYTES - "Bearer ".len() + 1)
    );
    let oversized_response = request(
        &server,
        "POST",
        "/api/messages",
        None,
        &[
            ("Content-Type", "application/json"),
            ("Authorization", &oversized),
        ],
        b"{}",
    )
    .await;
    assert_eq!(oversized_response.status, 400);
    assert_eq!(oversized_response.json(), invalid_response);
    assert!(!oversized_response.text().contains(&oversized));
    assert_eq!(
        fixtures.teams.calls.load(Ordering::Acquire),
        calls_before_invalid,
        "invalid headers must never reach the Teams adapter"
    );
}

#[tokio::test]
async fn whatsapp_reload_system_and_exec_match_frozen_shapes() {
    let fixtures = Fixtures::new(true);
    *fixtures.messages.reply.lock().expect("reply lock") = "x".repeat(7_001);
    let mut config = LegacyApiConfig::default();
    config.channels.set_whatsapp(true);
    config.whatsapp = Some(
        LegacyWhatsAppConfig::new("/whatsapp/webhook", "fixture-token").expect("valid webhook"),
    );
    config.admin_credential = Some(LegacyAdminCredential::new(ADMIN_TOKEN));
    let server = spawn(config, fixtures.services()).await;

    let verified = request(
        &server,
        "GET",
        "/whatsapp/webhook?hub.mode=subscribe&hub.verify_token=fixture-token&hub.challenge=12345",
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(verified.status, 200);
    assert_eq!(verified.text(), "12345");
    assert_eq!(
        verified
            .header("content-type")
            .map(|value| value.split(';').next().unwrap_or(value)),
        Some("text/plain")
    );
    let forbidden = request(
        &server,
        "GET",
        "/whatsapp/webhook?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=12345",
        None,
        &[],
        b"",
    )
    .await;
    assert_eq!(
        forbidden.json(),
        frozen_response("whatsapp-verify", "forbidden")
    );

    let webhook = json!({
        "entry":[{
            "changes":[{
                "value":{
                    "metadata":{"phone_number_id":"fixture-phone"},
                    "messages":[
                    {"from":"15551234567","id":"image","type":"image"},
                    {"from":"15551234567","id":"message-1","type":"text","text":{"body":" hello "}}
                ]}
            }]
        }]
    });
    let unsigned = json_request(&server, "/whatsapp/webhook", None, &webhook).await;
    assert_eq!(unsigned.status, 403);
    let wrong_signature = request(
        &server,
        "POST",
        "/whatsapp/webhook",
        None,
        &[
            ("Content-Type", "application/json"),
            ("X-Hub-Signature-256", "sha256=wrong"),
        ],
        &serde_json::to_vec(&webhook).expect("serialize webhook"),
    )
    .await;
    assert_eq!(wrong_signature.status, 403);
    let incoming = signed_whatsapp_request(&server, &webhook).await;
    assert_eq!(
        incoming.json(),
        frozen_response("whatsapp-incoming", "accepted")
    );
    {
        let sent = fixtures.whatsapp.sent.lock().expect("send log");
        assert_eq!(
            sent.iter()
                .map(|(_, chunk)| chunk.chars().count())
                .collect::<Vec<_>>(),
            vec![3_500, 3_500, 1]
        );
        drop(sent);
    }
    {
        let received = fixtures.messages.received.lock().expect("messages");
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].conversation_id, "whatsapp:15551234567");
        assert_eq!(received[0].text, "hello");
        drop(received);
    }

    fixtures.whatsapp.fail.store(true, Ordering::Release);
    let failed = signed_whatsapp_request(&server, &webhook).await;
    assert_eq!(
        failed.json(),
        frozen_response("whatsapp-incoming", "handling-failed")
    );

    let reload_forbidden = json_request(&server, "/admin/reload", None, &json!({})).await;
    assert_eq!(
        reload_forbidden.json(),
        frozen_response("admin-reload", "forbidden")
    );
    let reloaded = json_request(&server, "/admin/reload", Some(ADMIN_TOKEN), &json!({})).await;
    assert_eq!(reloaded.json(), frozen_response("admin-reload", "reloaded"));
    fixtures.reload.mode.store(1, Ordering::Release);
    let conflict = json_request(&server, "/admin/reload", Some(ADMIN_TOKEN), &json!({})).await;
    assert_eq!(conflict.json(), frozen_response("admin-reload", "conflict"));
    fixtures.reload.mode.store(2, Ordering::Release);
    let reload_failed = json_request(&server, "/admin/reload", Some(ADMIN_TOKEN), &json!({})).await;
    assert_eq!(
        reload_failed.json(),
        frozen_response("admin-reload", "failed")
    );

    let system = request(&server, "GET", "/admin/system", None, &[], b"").await;
    assert_eq!(
        system.json(),
        frozen_response("admin-system", "system-info")
    );
    let unknown = json_request(
        &server,
        "/admin/exec",
        Some(ADMIN_TOKEN),
        &json!({"action":"rm"}),
    )
    .await;
    assert_eq!(
        unknown.json(),
        frozen_response("admin-exec", "unknown-action")
    );
    let command = json_request(
        &server,
        "/admin/exec",
        Some(ADMIN_TOKEN),
        &json!({"action":"uptime"}),
    )
    .await;
    assert_eq!(
        command.json(),
        frozen_response("admin-exec", "command-success")
    );

    *fixtures.admin.outcome.lock().expect("admin outcome") = LegacyExecResult {
        success: false,
        output: None,
        error: Some("Command failed".to_owned()),
        stderr: Some("No such container".to_owned()),
    };
    let command_failed = json_request(
        &server,
        "/admin/exec",
        Some(ADMIN_TOKEN),
        &json!({"action":"docker_logs","target":"missing-;container"}),
    )
    .await;
    assert_eq!(
        command_failed.json(),
        frozen_response("admin-exec", "command-failure")
    );
    assert_eq!(
        fixtures.admin.calls.lock().expect("admin calls").last(),
        Some(&(
            LegacyAdminAction::DockerLogs,
            Some("missing-container".to_owned())
        ))
    );
}

#[tokio::test]
async fn whatsapp_webhook_authenticates_bounded_raw_bytes_before_parse_and_scope() {
    const BODY_LIMIT: usize = 512;

    let fixtures = Fixtures::new(true);
    let mut config = LegacyApiConfig::default();
    config.channels.set_whatsapp(true);
    config.whatsapp = Some(
        LegacyWhatsAppConfig::new("/whatsapp/webhook", "fixture-token").expect("valid webhook"),
    );
    config.limits.body_bytes = BODY_LIMIT;
    let server = spawn(config, fixtures.services()).await;

    let mut exact_body = br#"{"entry":[{"changes":[{"value":{"metadata":{"phone_number_id":"fixture-phone"},"messages":[{"from":"15551234567","id":"exact","type":"text","text":{"body":"hello"}}]}}]}]}"#.to_vec();
    assert!(exact_body.len() < BODY_LIMIT);
    exact_body.resize(BODY_LIMIT, b' ');
    let exact = signed_whatsapp_bytes(&server, &exact_body).await;
    assert_eq!(exact.status, 200);
    assert_eq!(fixtures.whatsapp.signature_calls.load(Ordering::Acquire), 1);
    {
        let payloads = fixtures
            .whatsapp
            .signature_payloads
            .lock()
            .expect("signature payloads");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].as_slice(), exact_body.as_slice());
        drop(payloads);
    }
    {
        let payloads = fixtures
            .whatsapp
            .webhook_payloads
            .lock()
            .expect("webhook payloads");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].as_slice(), exact_body.as_slice());
        drop(payloads);
    }

    let malformed = br#"{"entry":["#;
    let malformed_response = signed_whatsapp_bytes(&server, malformed).await;
    assert_eq!(malformed_response.status, 400);
    assert_eq!(
        fixtures.whatsapp.signature_calls.load(Ordering::Acquire),
        2,
        "a signed malformed body must be authenticated before JSON parsing"
    );
    assert_eq!(
        fixtures.whatsapp.webhook_calls.load(Ordering::Acquire),
        1,
        "malformed JSON must not reach the stateful adapter"
    );
    assert_eq!(
        fixtures
            .whatsapp
            .signature_payloads
            .lock()
            .expect("signature payloads")
            .last()
            .map(Vec::as_slice),
        Some(&malformed[..])
    );

    for metadata in [Value::Null, json!({"phone_number_id":"other-phone"})] {
        let payload = serde_json::to_vec(&json!({
            "entry":[{
                "changes":[{
                    "value":{
                        "metadata":metadata,
                        "messages":[{
                            "from":"15551234567",
                            "id":"cross-phone",
                            "type":"text",
                            "text":{"body":"must not process"}
                        }]
                    }
                }]
            }]
        }))
        .expect("serialize scoped webhook");
        let response = signed_whatsapp_bytes(&server, &payload).await;
        assert_eq!(response.status, 400);
        assert_eq!(response.json(), json!({"error":"Webhook handling failed"}));
    }
    assert_eq!(
        fixtures.whatsapp.webhook_calls.load(Ordering::Acquire),
        1,
        "missing or mismatched phone metadata must not reach the adapter"
    );

    let signature_calls = fixtures.whatsapp.signature_calls.load(Ordering::Acquire);
    let oversized = vec![b'x'; BODY_LIMIT + 1];
    let oversized_response = signed_whatsapp_bytes(&server, &oversized).await;
    assert_eq!(oversized_response.status, 413);
    assert_eq!(oversized_response.header("connection"), Some("close"));
    assert_eq!(
        fixtures.whatsapp.signature_calls.load(Ordering::Acquire),
        signature_calls,
        "an over-limit body must be rejected before HMAC verification"
    );
    assert_eq!(
        fixtures.messages.received.lock().expect("messages").len(),
        1
    );
}

#[tokio::test]
async fn whatsapp_empty_and_whitespace_bodies_authenticate_before_parse() {
    let fixtures = Fixtures::new(true);
    let mut config = LegacyApiConfig::default();
    config.channels.set_whatsapp(true);
    config.whatsapp = Some(
        LegacyWhatsAppConfig::new("/whatsapp/webhook", "fixture-token").expect("valid webhook"),
    );
    let server = spawn(config, fixtures.services()).await;
    let bodies = [b"".as_slice(), b" \t\r\n".as_slice()];

    for body in bodies {
        let unsigned = request(
            &server,
            "POST",
            "/whatsapp/webhook",
            None,
            &[("Content-Type", "application/json")],
            body,
        )
        .await;
        assert_eq!(unsigned.status, 403);
    }
    assert_eq!(
        fixtures.whatsapp.signature_calls.load(Ordering::Acquire),
        0,
        "unsigned bodies must not reach HMAC verification"
    );

    for body in bodies {
        let signed = signed_whatsapp_bytes(&server, body).await;
        assert_eq!(signed.status, 400);
        assert_eq!(signed.json(), json!({"error":"Webhook handling failed"}));
    }
    assert_eq!(fixtures.whatsapp.signature_calls.load(Ordering::Acquire), 2);
    {
        let payloads = fixtures
            .whatsapp
            .signature_payloads
            .lock()
            .expect("signature payloads");
        assert_eq!(payloads.as_slice(), [Vec::new(), b" \t\r\n".to_vec()]);
        drop(payloads);
    }
    assert_eq!(
        fixtures.whatsapp.webhook_calls.load(Ordering::Acquire),
        0,
        "empty and whitespace JSON must fail before stateful processing"
    );
    assert!(
        fixtures
            .messages
            .received
            .lock()
            .expect("messages")
            .is_empty()
    );
}

#[tokio::test]
async fn legacy_facade_exposes_readiness_and_refuses_new_work_while_draining() {
    let fixtures = Fixtures::new(true);
    let serving = ServingStateHandle::serving();
    let config = LegacyApiConfig {
        admin_credential: Some(LegacyAdminCredential::new(ADMIN_TOKEN)),
        ..LegacyApiConfig::default()
    };
    let server = spawn_with_serving(config, fixtures.services(), serving.clone()).await;

    let ready = request(&server, "GET", "/ready", Some(ADMIN_TOKEN), &[], b"").await;
    assert_eq!(ready.status, 200);
    assert_eq!(ready.json()["ready"], true);
    assert_eq!(ready.json()["failing"], json!([]));

    serving.begin_draining();
    let unready = request(&server, "GET", "/readyz", Some(ADMIN_TOKEN), &[], b"").await;
    assert_eq!(unready.status, 503);
    assert_eq!(unready.json()["failing"], json!(["draining"]));
    let live = request(&server, "GET", "/healthz", None, &[], b"").await;
    assert_eq!(
        live.json(),
        json!({"ok":true,"status":"live","phase":"draining"})
    );
    assert_eq!(
        request(&server, "GET", "/health", None, &[], b"")
            .await
            .status,
        200,
        "legacy health remains observable during a drain"
    );
    let chat_count = fixtures.runtime.chats().len();
    let refused = json_request(&server, "/chat", None, &json!({"message":"hello"})).await;
    assert_eq!(refused.status, 503);
    assert_eq!(refused.json(), json!({"error":"Service draining"}));
    assert_eq!(
        fixtures.runtime.chats().len(),
        chat_count,
        "draining requests must not reach the runtime"
    );
}

#[tokio::test]
async fn provider_legacy_runtime_bounds_sessions_and_propagates_cancellation() {
    let provider = DeterministicRuntime::new();
    let runtime = ProviderLegacyRuntime::new(
        provider.clone(),
        ProviderLegacyRuntimeConfig {
            model: "openclaw".to_owned(),
            skill_count: 7,
            max_sessions: 2,
            session_idle_timeout: Duration::from_mins(1),
        },
    )
    .expect("valid provider adapter");

    for conversation in ["one", "two", "three"] {
        let reply = runtime
            .chat(
                conversation.to_owned(),
                "hello".to_owned(),
                CancellationToken::new(),
            )
            .await
            .expect("provider reply");
        assert_eq!(reply, "deterministic response");
    }
    let snapshot = runtime.snapshot().expect("runtime snapshot");
    assert_eq!(snapshot.skill_count, 7);
    assert_eq!(snapshot.session_count, 2);
    assert!(snapshot.authenticated);
    let request = provider
        .last_generation_request()
        .expect("provider request lock")
        .expect("provider request");
    assert_eq!(request.model, "openclaw");
    assert_eq!(request.session_id, "three");

    runtime
        .set_authenticated(false)
        .expect("clear sessions on logout");
    let snapshot = runtime.snapshot().expect("logged-out snapshot");
    assert!(!snapshot.authenticated);
    assert_eq!(snapshot.session_count, 0);

    runtime
        .set_authenticated(true)
        .expect("restore authentication");
    provider.set_delay(Duration::from_secs(5));
    let cancellation = CancellationToken::new();
    let call = tokio::spawn({
        let runtime = runtime.clone();
        let cancellation = cancellation.clone();
        async move {
            runtime
                .chat("cancelled".to_owned(), "wait".to_owned(), cancellation)
                .await
        }
    });
    sleep(Duration::from_millis(20)).await;
    cancellation.cancel();
    let error = timeout(Duration::from_secs(1), call)
        .await
        .expect("cancelled call completed")
        .expect("join call")
        .expect_err("call is cancelled");
    assert_eq!(error.kind, PortErrorKind::Unavailable);
}

#[test]
fn invalid_legacy_compositions_fail_before_binding() {
    let fixtures = Fixtures::new(true);
    let mut missing_teams = LegacyApiConfig::default();
    missing_teams.channels.set_teams(true);
    let services = LegacyApiServices {
        teams: None,
        ..fixtures.services()
    };
    assert!(matches!(
        LegacyHttpApi::new(missing_teams, services),
        Err(LegacyConfigError::MissingTeamsAdapter)
    ));

    assert!(matches!(
        LegacyWhatsAppConfig::new("relative", "token"),
        Err(LegacyConfigError::InvalidWebhookPath)
    ));
    for path in ["/chat", "/:route", "/*tail", "/double//segment"] {
        assert!(
            matches!(
                LegacyWhatsAppConfig::new(path, "token"),
                Err(LegacyConfigError::InvalidWebhookPath)
            ),
            "{path} must be rejected before Axum route construction"
        );
    }
}

struct Server {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct HttpResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON response")
    }

    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).expect("UTF-8 response")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

async fn spawn(config: LegacyApiConfig, services: LegacyApiServices) -> Server {
    spawn_with_serving(config, services, ServingStateHandle::serving()).await
}

async fn spawn_with_serving(
    config: LegacyApiConfig,
    services: LegacyApiServices,
    serving: ServingStateHandle,
) -> Server {
    let api = LegacyHttpApi::with_serving_state(config, services, Arc::new(serving))
        .expect("valid legacy API");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind legacy API");
    let address = listener.local_addr().expect("legacy API address");
    let task = tokio::spawn(async move {
        api.serve(listener).await.expect("serve legacy API");
    });
    Server { address, task }
}

async fn json_request(
    server: &Server,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> HttpResponse {
    let body = serde_json::to_vec(body).expect("serialize request");
    request(
        server,
        "POST",
        path,
        token,
        &[("Content-Type", "application/json")],
        &body,
    )
    .await
}

async fn signed_whatsapp_request(server: &Server, body: &Value) -> HttpResponse {
    let body = serde_json::to_vec(body).expect("serialize request");
    signed_whatsapp_bytes(server, &body).await
}

async fn signed_whatsapp_bytes(server: &Server, body: &[u8]) -> HttpResponse {
    let signature = whatsapp_signature(body);
    request(
        server,
        "POST",
        "/whatsapp/webhook",
        None,
        &[
            ("Content-Type", "application/json"),
            ("X-Hub-Signature-256", &signature),
        ],
        body,
    )
    .await
}

fn whatsapp_signature(payload: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"fixture-app-secret");
    let tag = ring::hmac::sign(&key, payload);
    let mut encoded = String::with_capacity(64);
    for byte in tag.as_ref() {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    format!("sha256={encoded}")
}

fn reply_chunks(text: &str, max_chars: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for character in text.chars() {
        if current.chars().count() == max_chars {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(character);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

async fn request(
    server: &Server,
    method: &str,
    path: &str,
    token: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = TcpStream::connect(server.address)
        .await
        .expect("connect legacy API");
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        server.address,
        body.len()
    );
    if let Some(token) = token {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("write request head");
    stream.write_all(body).await.expect("write request body");
    let mut raw = Vec::new();
    let read = timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .expect("legacy response timeout");
    if let Err(error) = read {
        assert!(
            error.kind() == std::io::ErrorKind::ConnectionReset && !raw.is_empty(),
            "read legacy response: {error}"
        );
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response header terminator");
    let head = std::str::from_utf8(&raw[..split]).expect("UTF-8 headers");
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .expect("numeric status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    HttpResponse {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

fn frozen_response(endpoint_id: &str, case_id: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("compat")
        .join("legacy")
        .join("fixtures")
        .join("http")
        .join("examples.json");
    let source = fs::read_to_string(path).expect("read frozen HTTP examples");
    let fixture: Value = serde_json::from_str(&source).expect("parse frozen HTTP examples");
    fixture["endpoints"]
        .as_array()
        .expect("endpoint array")
        .iter()
        .find(|endpoint| endpoint["endpoint_id"] == endpoint_id)
        .and_then(|endpoint| endpoint["cases"].as_array())
        .and_then(|cases| cases.iter().find(|case| case["case_id"] == case_id))
        .map_or_else(
            || panic!("missing frozen case {endpoint_id}/{case_id}"),
            |case| case["response"].clone(),
        )
}

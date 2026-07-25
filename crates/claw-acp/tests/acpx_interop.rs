//! ACPX harness runtime integration tests.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use agent_client_protocol::schema::{ContentBlock, TextContent};
use claw_acp::{
    acpx::{
        AcpxRuntime, AcpxSessionStore, AcpxTurn, HarnessConfig, LeaseState, MemoryAcpxSessionStore,
        MemoryProcessLeaseStore, ProcessLease, ProcessLeaseStore, RuntimeSessionMode,
        StoredSession, mcp_bridge_from_registry,
    },
    debug_client::DebugClientConfig,
    error::{AcpInteropError, Result as AcpResult},
};
use claw_mcp::registry::{ServerConfig, ServerTransportConfig};
use serde_json::json;

fn turn(harness: &str, session_key: &str, session_mode: RuntimeSessionMode) -> AcpxTurn {
    AcpxTurn {
        harness: harness.into(),
        session_key: session_key.into(),
        cwd: std::env::current_dir().expect("test cwd must resolve"),
        prompt: vec![ContentBlock::Text(TextContent::new("ACPX fixture turn"))],
        mode: None,
        session_mode,
        cancel_after: None,
        mcp_servers: Vec::new(),
    }
}

#[derive(Debug)]
struct FailingSaveStore;

impl AcpxSessionStore for FailingSaveStore {
    fn load(&self, _session_key: &str) -> AcpResult<Option<StoredSession>> {
        Ok(None)
    }

    fn save(&self, _session_key: &str, _session: StoredSession) -> AcpResult<()> {
        Err(AcpInteropError::Lifecycle(
            "fixture session save failed".into(),
        ))
    }

    fn delete(&self, _session_key: &str) -> AcpResult<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct FailFirstCloseLeaseStore {
    inner: MemoryProcessLeaseStore,
    fail_close: AtomicBool,
}

impl FailFirstCloseLeaseStore {
    fn new() -> Self {
        Self {
            inner: MemoryProcessLeaseStore::default(),
            fail_close: AtomicBool::new(true),
        }
    }
}

impl ProcessLeaseStore for FailFirstCloseLeaseStore {
    fn acquire(&self, lease: ProcessLease) -> AcpResult<()> {
        self.inner.acquire(lease)
    }

    fn finish(&self, lease_id: &str, state: LeaseState) -> AcpResult<ProcessLease> {
        if state == LeaseState::Closed && self.fail_close.swap(false, Ordering::SeqCst) {
            return Err(AcpInteropError::Lifecycle(
                "fixture lease close failed".into(),
            ));
        }
        self.inner.finish(lease_id, state)
    }

    fn list(&self) -> AcpResult<Vec<ProcessLease>> {
        self.inner.list()
    }
}

#[tokio::test]
async fn runtime_resolves_aliases_persists_sessions_and_completes_leases() {
    let mut client = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    client.timeout = Duration::from_secs(5);
    client
        .environment
        .insert("REQUEST_PERMISSION".into(), "1".into());
    let mut harness = HarnessConfig::new("Codex", client);
    harness.aliases = vec!["code".into()];
    harness.mcp_servers = vec![
        mcp_bridge_from_registry(&ServerConfig::new(
            "fixture-mcp",
            ServerTransportConfig::Stdio {
                command: PathBuf::from("fixture-mcp"),
                arguments: vec!["--readonly".into()],
                environment: BTreeMap::from([("FIXTURE_MODE".into(), "readonly".into())]),
            },
        ))
        .expect("fixture MCP bridge must convert"),
    ];
    let leases = Arc::new(MemoryProcessLeaseStore::default());
    let sessions = Arc::new(MemoryAcpxSessionStore::default());
    let runtime = AcpxRuntime::new(vec![harness], leases.clone(), sessions.clone())
        .expect("runtime must initialize");

    let first = runtime
        .run_turn(turn(
            " CODE ",
            "conversation-1",
            RuntimeSessionMode::Persistent,
        ))
        .await
        .expect("first persistent turn must succeed");
    assert_eq!(first.lease.harness, "Codex");
    assert_eq!(first.lease.session_key, "conversation-1");
    assert_eq!(first.lease.state, LeaseState::Closed);
    assert!(first.lease.ended_at.is_some());
    assert!(first.debug.close.is_none());
    assert_eq!(first.debug.session_id.to_string(), "fixture-session");

    let second = runtime
        .run_turn(turn(
            "Codex",
            "conversation-1",
            RuntimeSessionMode::Persistent,
        ))
        .await
        .expect("stored session must load on the second turn");
    assert_eq!(second.lease.state, LeaseState::Closed);
    assert_ne!(second.lease.lease_id, first.lease.lease_id);
    assert_eq!(
        sessions
            .load("conversation-1")
            .expect("session store must be readable")
            .expect("persistent session must exist")
            .session_id
            .to_string(),
        "fixture-session"
    );

    let one_shot = runtime
        .run_turn(turn("code", "ephemeral-1", RuntimeSessionMode::OneShot))
        .await
        .expect("one-shot turn must succeed");
    assert!(one_shot.debug.close.is_some());
    assert_eq!(
        sessions
            .load("ephemeral-1")
            .expect("session store must be readable"),
        None
    );

    let lease_records = leases.list().expect("lease store must be readable");
    assert_eq!(lease_records.len(), 3);
    assert!(
        lease_records
            .iter()
            .all(|lease| lease.state == LeaseState::Closed)
    );
    assert_eq!(runtime.doctor().len(), 1);
    assert!(runtime.doctor()[0].healthy);
}

#[tokio::test]
async fn session_store_failure_finishes_the_lease_and_allows_retry() {
    let mut client = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    client.timeout = Duration::from_secs(5);
    let harness = HarnessConfig::new("Codex", client);
    let leases = Arc::new(MemoryProcessLeaseStore::default());
    let runtime = AcpxRuntime::new(vec![harness], leases.clone(), Arc::new(FailingSaveStore))
        .expect("runtime must initialize");

    for _ in 0..2 {
        let error = runtime
            .run_turn(turn(
                "Codex",
                "retryable-session",
                RuntimeSessionMode::Persistent,
            ))
            .await
            .expect_err("session persistence failure must fail the turn");
        assert_eq!(
            error.to_string(),
            "ACP lifecycle conflict: fixture session save failed"
        );
    }

    let lease_records = leases.list().expect("lease store must be readable");
    assert_eq!(lease_records.len(), 2);
    assert!(
        lease_records
            .iter()
            .all(|lease| lease.state == LeaseState::Failed && lease.ended_at.is_some())
    );
}

#[tokio::test]
async fn lease_close_failure_is_reconciled_and_allows_retry() {
    let mut client = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    client.timeout = Duration::from_secs(5);
    let harness = HarnessConfig::new("Codex", client);
    let leases = Arc::new(FailFirstCloseLeaseStore::new());
    let runtime = AcpxRuntime::new(
        vec![harness],
        leases.clone(),
        Arc::new(MemoryAcpxSessionStore::default()),
    )
    .expect("runtime must initialize");

    let error = runtime
        .run_turn(turn(
            "Codex",
            "reconciled-session",
            RuntimeSessionMode::OneShot,
        ))
        .await
        .expect_err("first close failure must fail the turn");
    let failed_lease = leases
        .list()
        .expect("failed lease must be readable")
        .into_iter()
        .next()
        .expect("failed lease must exist");
    assert_eq!(failed_lease.state, LeaseState::Failed);
    assert_eq!(
        error.to_string(),
        format!(
            "ACP lifecycle conflict: failed to close ACPX lease `{}`; reconciled it as failed: ACP lifecycle conflict: fixture lease close failed",
            failed_lease.lease_id
        )
    );

    let retry = runtime
        .run_turn(turn(
            "Codex",
            "reconciled-session",
            RuntimeSessionMode::OneShot,
        ))
        .await
        .expect("reconciled lease must permit retry");
    assert_eq!(retry.lease.state, LeaseState::Closed);
    assert_eq!(
        leases
            .list()
            .expect("leases readable")
            .into_iter()
            .map(|lease| lease.state)
            .collect::<Vec<_>>(),
        vec![LeaseState::Failed, LeaseState::Closed]
    );
}

#[tokio::test]
async fn cancelling_a_turn_fails_its_lease_and_allows_retry() {
    let mut client = DebugClientConfig::new(PathBuf::from(env!("CARGO_BIN_EXE_claw-acp-fixture")));
    client.timeout = Duration::from_secs(5);
    client
        .environment
        .insert("WAIT_FOR_CANCEL".into(), "1".into());
    let harness = HarnessConfig::new("Codex", client);
    let leases = Arc::new(MemoryProcessLeaseStore::default());
    let runtime = AcpxRuntime::new(
        vec![harness],
        leases.clone(),
        Arc::new(MemoryAcpxSessionStore::default()),
    )
    .expect("runtime must initialize");

    let cancelled = turn("Codex", "cancelled-session", RuntimeSessionMode::OneShot);
    tokio::time::timeout(Duration::from_millis(200), runtime.run_turn(cancelled))
        .await
        .expect_err("outer timeout must cancel the ACPX turn");
    let records = leases.list().expect("cancelled lease must be readable");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, LeaseState::Failed);
    assert!(records[0].ended_at.is_some());

    let mut retry = turn("Codex", "cancelled-session", RuntimeSessionMode::OneShot);
    retry.cancel_after = Some(Duration::from_millis(20));
    let result = runtime
        .run_turn(retry)
        .await
        .expect("cancelled lease must permit a retry");
    assert_eq!(result.lease.state, LeaseState::Closed);
}

#[test]
fn registry_stdio_configuration_maps_to_exact_acp_mcp_shape() {
    let config = ServerConfig::new(
        "filesystem",
        ServerTransportConfig::Stdio {
            command: PathBuf::from("fixture-mcp"),
            arguments: vec!["--root".into(), "C:\\workspace".into()],
            environment: BTreeMap::from([("FIXTURE_MODE".into(), "readonly".into())]),
        },
    );

    let bridge = mcp_bridge_from_registry(&config).expect("stdio bridge must convert");

    assert_eq!(
        serde_json::to_value(bridge).expect("bridge must serialize"),
        json!({
            "name": "filesystem",
            "command": "fixture-mcp",
            "args": ["--root", "C:\\workspace"],
            "env": [{"name": "FIXTURE_MODE", "value": "readonly"}]
        })
    );
}

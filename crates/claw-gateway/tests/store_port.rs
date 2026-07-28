//! A second, deliberately hostile in-crate [`GatewayStore`] adapter.
//!
//! [`claw_gateway::InMemoryGatewayStore`] is the only adapter this crate ships,
//! and it is the only one every other test runs against. It cannot fail: no
//! write is ever refused for a reason the caller did not ask for, no read is
//! ever stale, and nothing it holds outlives the process, so a restart is
//! indistinguishable from a fresh start. A durable adapter — a file, a
//! database, anything that survives the process — has none of those
//! properties, and the failures it *does* have are the ones no existing test
//! reaches.
//!
//! [`ChaoticStore`] is that adapter. It is written from scratch rather than
//! wrapping the shipped one, which is the second half of the point: the port
//! has to be implementable twice.
//!
//! It answers a fault script, one entry consumed per operation:
//!
//! * [`Fault::TornWrite`] — the write is committed and *then* the call reports
//!   [`StoreError::Backend`]. This is the failure a durable adapter cannot rule
//!   out: the record is on disk, the caller was told it is not.
//! * [`Fault::StaleRead`] — the read answers from the snapshot taken before the
//!   most recent commit, the way a replica or an uncheckpointed reader would.
//! * [`Fault::Restart`] — everything is dropped before the operation runs, the
//!   way a process that died and came back would see it.
//! * [`Fault::Refuse`] — the operation fails without writing anything.
//!
//! No filesystem and no database: the fault modes are what matter, not the
//! medium.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use claw_gateway::error::{DispatchError, StoreError};
use claw_gateway::store::{
    GatewayStore, HeartbeatRecord, PendingInvocation, SessionDraft, SessionPatch, SessionRecord,
    StoreFuture,
};
use claw_gateway::{
    ConnectionDirectory, ConnectionId, CredentialPolicy, Delivery, EventBus, Exposure,
    GatewayServer, GatewayServerConfig, Grant, ManualClock, MethodContext, MethodRegistry,
    ServerHandle, ServerLimits, ServerTimeouts, StaticAuthenticator, SystemClock, TopicFilter,
    methods,
};
use claw_gateway_client::{GatewayClient, GatewayClientConfig, ReconnectPolicy};
use claw_protocol::gateway::{
    ClientId, ClientMode, GatewayMethodName, OperatorScope, PREAUTH_MAX_FRAME_BYTES, RequestId,
    ResponseFrame, Role, resolve_core_method,
};
use claw_security::authorization::{Role as SecurityRole, Scope, ScopeSet};
use claw_security::identity::DeviceIdentity;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use serde_json::{Value, json};
use url::Url;

/// What the adapter does to the next operation it is asked to perform.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Fault {
    /// Behave, but consume one script entry, so a later fault lands on a
    /// chosen operation rather than on the handler's first store call.
    Healthy,
    /// Commit the write, then report a backend failure for it.
    TornWrite,
    /// Answer from the snapshot before the last commit.
    StaleRead,
    /// Lose everything, as a process that died and restarted would.
    Restart,
    /// Fail without writing anything.
    Refuse,
}

/// Everything the port persists, in one cloneable snapshot.
#[derive(Clone, Debug, Default)]
struct Snapshot {
    sessions: BTreeMap<String, SessionRecord>,
    heartbeat: Option<HeartbeatRecord>,
    heartbeats_enabled: bool,
    pending: BTreeMap<String, Vec<PendingInvocation>>,
    awaiting: BTreeMap<String, Vec<PendingInvocation>>,
}

impl Snapshot {
    fn fresh() -> Self {
        Self {
            heartbeats_enabled: true,
            ..Self::default()
        }
    }
}

#[derive(Debug)]
struct Chaos {
    committed: Snapshot,
    previous: Snapshot,
    script: VecDeque<Fault>,
    calls: Vec<&'static str>,
    /// Detail text used by every failure this adapter reports.
    detail: String,
}

/// A [`GatewayStore`] adapter that behaves the way a durable one can.
#[derive(Debug)]
struct ChaoticStore {
    state: Mutex<Chaos>,
}

impl ChaoticStore {
    fn new() -> Self {
        Self::with_detail("chaotic adapter".to_owned())
    }

    fn with_detail(detail: String) -> Self {
        Self {
            state: Mutex::new(Chaos {
                committed: Snapshot::fresh(),
                previous: Snapshot::fresh(),
                script: VecDeque::new(),
                calls: Vec::new(),
                detail,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Chaos> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queues one fault to be applied to the next operation.
    fn schedule(&self, fault: Fault) {
        self.lock().script.push_back(fault);
    }

    /// Queues `count` copies of one fault.
    fn schedule_many(&self, fault: &Fault, count: usize) {
        let mut state = self.lock();
        for _ in 0..count {
            state.script.push_back(fault.clone());
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.lock().calls.clone()
    }

    /// Begins one operation, returning the fault it must obey.
    fn begin(&self, call: &'static str) -> Option<Fault> {
        let mut state = self.lock();
        state.calls.push(call);
        let fault = state.script.pop_front();
        if fault == Some(Fault::Restart) {
            state.committed = Snapshot::fresh();
            state.previous = Snapshot::fresh();
        }
        fault
    }

    /// Reads under the scheduled fault.
    fn read<T>(&self, call: &'static str, project: impl Fn(&Snapshot) -> T) -> Result<T, StoreError>
    where
        T: Send + 'static,
    {
        let fault = self.begin(call);
        let state = self.lock();
        match fault {
            Some(Fault::Refuse | Fault::TornWrite) => {
                Err(StoreError::Backend(state.detail.clone()))
            }
            Some(Fault::StaleRead) => Ok(project(&state.previous)),
            Some(Fault::Healthy | Fault::Restart) | None => Ok(project(&state.committed)),
        }
    }

    /// Commits one mutation under the scheduled fault.
    ///
    /// The mutation runs first and the fault is applied to the *answer*, which
    /// is exactly the ordering that makes a torn write undetectable.
    fn write<T>(
        &self,
        call: &'static str,
        mutate: impl FnOnce(&mut Snapshot) -> Result<T, StoreError>,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
    {
        let fault = self.begin(call);
        let mut state = self.lock();
        let outcome = Self::commit(&mut state, fault.as_ref(), mutate);
        drop(state);
        outcome
    }

    fn commit<T>(
        state: &mut Chaos,
        fault: Option<&Fault>,
        mutate: impl FnOnce(&mut Snapshot) -> Result<T, StoreError>,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
    {
        if fault == Some(&Fault::Refuse) {
            return Err(StoreError::Backend(state.detail.clone()));
        }
        let mut next = state.committed.clone();
        let outcome = mutate(&mut next)?;
        state.previous = std::mem::replace(&mut state.committed, next);
        if fault == Some(&Fault::TornWrite) {
            return Err(StoreError::Backend(state.detail.clone()));
        }
        Ok(outcome)
    }
}

fn ready<T>(value: Result<T, StoreError>) -> StoreFuture<'static, T>
where
    T: Send + 'static,
{
    Box::pin(std::future::ready(value))
}

impl GatewayStore for ChaoticStore {
    fn create_session(&self, draft: SessionDraft) -> StoreFuture<'_, SessionRecord> {
        ready(self.write("create_session", |snapshot| {
            if snapshot.sessions.contains_key(&draft.id) {
                return Err(StoreError::Conflict { id: draft.id });
            }
            let record = SessionRecord {
                id: draft.id.clone(),
                agent_id: draft.agent_id,
                title: draft.title,
                created_at_ms: draft.created_at_ms,
                updated_at_ms: draft.created_at_ms,
                revision: 1,
                archived: false,
            };
            snapshot.sessions.insert(draft.id, record.clone());
            Ok(record)
        }))
    }

    fn get_session<'a>(&'a self, id: &'a str) -> StoreFuture<'a, Option<SessionRecord>> {
        ready(self.read("get_session", |snapshot| snapshot.sessions.get(id).cloned()))
    }

    fn list_sessions(&self) -> StoreFuture<'_, Vec<SessionRecord>> {
        ready(self.read("list_sessions", |snapshot| {
            snapshot.sessions.values().cloned().collect()
        }))
    }

    fn patch_session<'a>(
        &'a self,
        id: &'a str,
        patch: SessionPatch,
    ) -> StoreFuture<'a, Option<SessionRecord>> {
        ready(self.write("patch_session", |snapshot| {
            let Some(record) = snapshot.sessions.get_mut(id) else {
                return Ok(None);
            };
            if let Some(title) = patch.title {
                record.title = title;
            }
            if let Some(archived) = patch.archived {
                record.archived = archived;
            }
            record.updated_at_ms = patch.updated_at_ms;
            record.revision = record.revision.saturating_add(1);
            Ok(Some(record.clone()))
        }))
    }

    fn delete_session<'a>(&'a self, id: &'a str) -> StoreFuture<'a, bool> {
        ready(self.write("delete_session", |snapshot| {
            Ok(snapshot.sessions.remove(id).is_some())
        }))
    }

    fn record_heartbeat(&self, record: HeartbeatRecord) -> StoreFuture<'_, ()> {
        ready(self.write("record_heartbeat", |snapshot| {
            if snapshot.heartbeats_enabled {
                snapshot.heartbeat = Some(record);
            }
            Ok(())
        }))
    }

    fn last_heartbeat(&self) -> StoreFuture<'_, Option<HeartbeatRecord>> {
        ready(self.read("last_heartbeat", |snapshot| snapshot.heartbeat.clone()))
    }

    fn set_heartbeats_enabled(&self, enabled: bool) -> StoreFuture<'_, bool> {
        ready(self.write("set_heartbeats_enabled", |snapshot| {
            let previous = snapshot.heartbeats_enabled;
            snapshot.heartbeats_enabled = enabled;
            Ok(previous)
        }))
    }

    fn heartbeats_enabled(&self) -> StoreFuture<'_, bool> {
        ready(self.read("heartbeats_enabled", |snapshot| snapshot.heartbeats_enabled))
    }

    fn enqueue_pending<'a>(
        &'a self,
        node_id: &'a str,
        invocation: PendingInvocation,
    ) -> StoreFuture<'a, usize> {
        ready(self.write("enqueue_pending", |snapshot| {
            let pending = snapshot.pending.entry(node_id.to_owned()).or_default();
            let awaiting = snapshot.awaiting.get(node_id).map_or(0, Vec::len);
            if pending.iter().any(|held| held.id == invocation.id) {
                return Err(StoreError::Conflict { id: invocation.id });
            }
            pending.push(invocation);
            Ok(pending.len() + awaiting)
        }))
    }

    fn pull_pending<'a>(
        &'a self,
        node_id: &'a str,
        max: usize,
    ) -> StoreFuture<'a, Vec<PendingInvocation>> {
        ready(self.write("pull_pending", |snapshot| {
            let pending = snapshot.pending.entry(node_id.to_owned()).or_default();
            let count = max.min(pending.len());
            let pulled: Vec<PendingInvocation> = pending.drain(..count).collect();
            snapshot
                .awaiting
                .entry(node_id.to_owned())
                .or_default()
                .extend(pulled.iter().cloned());
            Ok(pulled)
        }))
    }

    fn ack_pending<'a>(
        &'a self,
        node_id: &'a str,
        invocation_id: &'a str,
    ) -> StoreFuture<'a, bool> {
        ready(self.write("ack_pending", |snapshot| {
            let awaiting = snapshot.awaiting.entry(node_id.to_owned()).or_default();
            let Some(index) = awaiting.iter().position(|held| held.id == invocation_id) else {
                return Ok(false);
            };
            awaiting.remove(index);
            Ok(true)
        }))
    }

    fn reclaim_pending<'a>(&'a self, node_id: &'a str) -> StoreFuture<'a, usize> {
        ready(self.write("reclaim_pending", |snapshot| {
            let mut reclaimed = snapshot.awaiting.remove(node_id).unwrap_or_default();
            let count = reclaimed.len();
            let pending = snapshot.pending.entry(node_id.to_owned()).or_default();
            reclaimed.append(pending);
            *pending = reclaimed;
            Ok(count)
        }))
    }

    fn drain_pending<'a>(&'a self, node_id: &'a str) -> StoreFuture<'a, Vec<PendingInvocation>> {
        ready(self.write("drain_pending", |snapshot| {
            let mut drained = snapshot.pending.remove(node_id).unwrap_or_default();
            drained.extend(snapshot.awaiting.remove(node_id).unwrap_or_default());
            Ok(drained)
        }))
    }
}

/// Drives real handlers against a store without a socket.
struct Harness {
    registry: MethodRegistry,
    store: Arc<ChaoticStore>,
    events: EventBus,
    clock: ManualClock,
    directory: ConnectionDirectory,
    filter: Mutex<TopicFilter>,
}

impl Harness {
    fn new(store: Arc<ChaoticStore>) -> Self {
        Self {
            registry: methods::registry().expect("handlers install"),
            store,
            events: EventBus::new(64, 1_048_576),
            clock: ManualClock::new(1_700_000_000_000),
            directory: ConnectionDirectory::new(),
            filter: Mutex::new(TopicFilter::default()),
        }
    }

    async fn call(
        &self,
        role: Role,
        scopes: &[OperatorScope],
        method: &str,
        params: Value,
    ) -> Result<Value, DispatchError> {
        let method = self
            .registry
            .canonical_name(method)
            .expect("the method is catalogued");
        let context = MethodContext {
            method,
            connection: ConnectionId::new(1),
            role,
            scopes,
            device_id: "node-a",
            store: self.store.as_ref(),
            events: &self.events,
            clock: &self.clock,
            directory: &self.directory,
            filter: &self.filter,
            server_version: "store-port-test",
        };
        self.registry.dispatch(context, params).await
    }

    async fn operator(&self, method: &str, params: Value) -> Result<Value, DispatchError> {
        self.call(Role::Operator, &[OperatorScope::Admin], method, params)
            .await
    }

    async fn node(&self, method: &str, params: Value) -> Result<Value, DispatchError> {
        self.call(Role::Node, &[], method, params).await
    }
}

fn create_params(id: &str) -> Value {
    json!({ "id": id, "agentId": "agent-main", "title": "first" })
}

/// Every implemented method that touches the store, with parameters that would
/// succeed against a healthy adapter.
fn store_backed_calls() -> Vec<(Role, &'static str, Value)> {
    vec![
        (Role::Operator, "sessions.create", create_params("s-fault")),
        (Role::Operator, "sessions.list", json!({})),
        (Role::Operator, "sessions.get", json!({ "id": "s1" })),
        (Role::Operator, "sessions.describe", json!({ "id": "s1" })),
        (
            Role::Operator,
            "sessions.patch",
            json!({ "id": "s1", "title": "renamed" }),
        ),
        (Role::Operator, "sessions.delete", json!({ "id": "s1" })),
        (Role::Operator, "last-heartbeat", json!({})),
        (Role::Operator, "set-heartbeats", json!({ "enabled": true })),
        (Role::Node, "node.pending.pull", json!({ "limit": 4 })),
        (Role::Node, "node.pending.ack", json!({ "id": "i1" })),
        (Role::Node, "node.pending.drain", json!({})),
    ]
}

/// The frozen wire codes a dispatch failure is allowed to carry.
const WIRE_CODES: [&str; 6] = [
    "METHOD_NOT_FOUND",
    "NOT_IMPLEMENTED",
    "UNAUTHORIZED",
    "INVALID_REQUEST",
    "NOT_FOUND",
    "UNAVAILABLE",
];

#[tokio::test]
async fn a_refused_write_reaches_the_client_as_a_typed_retryable_failure() {
    for (role, method, params) in store_backed_calls() {
        let store = Arc::new(ChaoticStore::new());
        let harness = Harness::new(Arc::clone(&store));
        // Enough faults to cover the handler's first store call whichever it is.
        store.schedule_many(&Fault::Refuse, 4);

        let error = harness
            .call(role, &[OperatorScope::Admin], method, params)
            .await
            .expect_err("the adapter refused every write");
        assert!(
            matches!(error, DispatchError::Store(StoreError::Backend(_))),
            "`{method}` turned an adapter failure into {error:?}"
        );
        assert_eq!(
            error.wire_code(),
            "UNAVAILABLE",
            "`{method}` must stay retryable"
        );
        assert!(error.retryable(), "`{method}` must stay retryable");
        assert!(WIRE_CODES.contains(&error.wire_code()));
    }
}

#[tokio::test]
async fn a_torn_write_is_never_announced_as_an_event() {
    let store = Arc::new(ChaoticStore::new());
    let harness = Harness::new(Arc::clone(&store));
    let mut subscription = harness.events.subscribe(
        ConnectionId::new(9),
        Role::Operator,
        vec![OperatorScope::Admin],
        Arc::new(Mutex::new(TopicFilter::default())),
    );

    store.schedule(Fault::TornWrite);
    let error = harness
        .operator("sessions.create", create_params("s1"))
        .await
        .expect_err("the adapter reported the commit as a failure");
    assert!(matches!(
        error,
        DispatchError::Store(StoreError::Backend(_))
    ));

    assert!(
        subscription.try_recv().is_none(),
        "a write the caller was told failed must not be broadcast as fact"
    );

    // The other half of a torn write: the record really is there, and the only
    // thing the client can do about it is observe the conflict on retry.
    let listed = harness
        .operator("sessions.list", json!({}))
        .await
        .expect("the adapter answers reads");
    assert_eq!(listed["count"], json!(1));
    let retried = harness
        .operator("sessions.create", create_params("s1"))
        .await
        .expect_err("the identity is taken by the write that 'failed'");
    assert!(matches!(
        retried,
        DispatchError::Store(StoreError::Conflict { .. })
    ));
    assert!(
        !retried.retryable(),
        "a conflict is deliberately not retryable"
    );
}

#[tokio::test]
async fn set_heartbeats_reports_failure_after_committing_the_flag() {
    let store = Arc::new(ChaoticStore::new());
    let harness = Harness::new(Arc::clone(&store));

    // The toggle commits; the heartbeat write behind it is refused.
    store.schedule(Fault::Refuse);
    let error = harness
        .operator("set-heartbeats", json!({ "enabled": false }))
        .await
        .expect_err("the first store call is refused");
    assert_eq!(error.wire_code(), "UNAVAILABLE");
    assert_eq!(store.calls(), vec!["set_heartbeats_enabled"]);

    // Now let the toggle through and refuse only the heartbeat that follows it.
    let store = Arc::new(ChaoticStore::new());
    let harness = Harness::new(Arc::clone(&store));
    store.schedule(Fault::Healthy);
    store.schedule(Fault::TornWrite);
    let observed = harness
        .operator("set-heartbeats", json!({ "enabled": true }))
        .await;
    // With `enabled: true` the handler writes twice; the second write decides
    // the answer, and the first is already committed either way.
    assert_eq!(
        store.calls(),
        vec!["set_heartbeats_enabled", "record_heartbeat"]
    );
    assert!(
        observed.is_err(),
        "a failed second write must not be reported as success"
    );
    let flag = harness
        .operator("last-heartbeat", json!({}))
        .await
        .expect("reads still work");
    assert_eq!(
        flag["enabled"],
        json!(true),
        "this is the documented non-atomic seam: the request failed and the flag still moved"
    );
}

#[tokio::test]
async fn a_stale_read_cannot_make_the_gateway_announce_a_delete_it_did_not_do() {
    let store = Arc::new(ChaoticStore::new());
    let harness = Harness::new(Arc::clone(&store));
    let mut subscription = harness.events.subscribe(
        ConnectionId::new(9),
        Role::Operator,
        vec![OperatorScope::Admin],
        Arc::new(Mutex::new(TopicFilter::default())),
    );

    harness
        .operator("sessions.create", create_params("s1"))
        .await
        .expect("create");
    assert!(matches!(subscription.try_recv(), Some(Delivery::Event(_))));
    harness
        .operator("sessions.delete", json!({ "id": "s1" }))
        .await
        .expect("delete");
    assert!(matches!(subscription.try_recv(), Some(Delivery::Event(_))));

    // The session is gone, but the next read answers from before the delete.
    store.schedule(Fault::StaleRead);
    let error = harness
        .operator("sessions.delete", json!({ "id": "s1" }))
        .await
        .expect_err("the record the stale read promised is not there");
    assert!(
        matches!(
            error,
            DispatchError::NotFound {
                kind: "session",
                ..
            }
        ),
        "unexpected outcome: {error:?}"
    );
    assert!(
        subscription.try_recv().is_none(),
        "a delete that did not happen must not be broadcast"
    );
}

#[tokio::test]
async fn a_restart_between_calls_is_answered_rather_than_panicked_over() {
    let store = Arc::new(ChaoticStore::new());
    let harness = Harness::new(Arc::clone(&store));

    harness
        .operator("sessions.create", create_params("s1"))
        .await
        .expect("create");

    store.schedule(Fault::Restart);
    let body = harness
        .operator("sessions.get", json!({ "id": "s1" }))
        .await
        .expect("a restart is not a failure, it is an empty store");
    assert_eq!(body["session"], Value::Null);

    store.schedule(Fault::Restart);
    let error = harness
        .operator("sessions.patch", json!({ "id": "s1", "archived": true }))
        .await
        .expect_err("patching a session the restart lost");
    assert!(matches!(
        error,
        DispatchError::NotFound {
            kind: "session",
            ..
        }
    ));

    store.schedule(Fault::Restart);
    let body = harness
        .node("node.pending.pull", json!({ "limit": 4 }))
        .await
        .expect("pulling from a restarted store");
    assert_eq!(body["count"], json!(0));
}

/// The gap the reclaim operation closes, stated as the failure it used to be.
#[tokio::test]
async fn work_claimed_before_a_restart_is_reachable_again_only_through_a_reclaim() {
    let store = Arc::new(ChaoticStore::new());
    let harness = Harness::new(Arc::clone(&store));

    harness.directory.insert(claw_gateway::ConnectionInfo {
        id: ConnectionId::new(1),
        role: Role::Node,
        scopes: Vec::new(),
        device_id: "node-a".to_owned(),
        client_id: "node-host".to_owned(),
        client_mode: "node".to_owned(),
        client_version: "1".to_owned(),
        protocol: 4,
        compatibility: "current",
        connected_at_ms: 1,
        commands: Vec::new(),
    });

    harness
        .operator(
            "node.pending.enqueue",
            json!({ "nodeId": "node-a", "id": "i1", "command": "skills.run", "payload": "{}" }),
        )
        .await
        .expect("enqueue");
    let pulled = harness
        .node("node.pending.pull", json!({ "limit": 4 }))
        .await
        .expect("pull");
    assert_eq!(pulled["count"], json!(1));

    // The claimant dies here. A durable adapter keeps the claim; nothing
    // acknowledges it, and no pull can see it.
    let empty = harness
        .node("node.pending.pull", json!({ "limit": 4 }))
        .await
        .expect("pull");
    assert_eq!(
        empty["count"],
        json!(0),
        "an unacknowledged claim is invisible to every later pull"
    );

    let reclaimed = store
        .reclaim_pending("node-a")
        .await
        .expect("the adapter reclaims");
    assert_eq!(reclaimed, 1);
    let again = harness
        .node("node.pending.pull", json!({ "limit": 4 }))
        .await
        .expect("pull");
    assert_eq!(again["count"], json!(1));
    assert_eq!(again["invocations"][0]["id"], json!("i1"));
}

fn device(seed: u8) -> Arc<DeviceIdentity> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    Arc::new(DeviceIdentity::generate(&mut rng))
}

fn config() -> GatewayServerConfig {
    GatewayServerConfig {
        server_version: "store-port".to_owned(),
        limits: ServerLimits::default(),
        timeouts: ServerTimeouts {
            tick_interval: Duration::from_hours(1),
            ..ServerTimeouts::default()
        },
        exposure: Exposure::LoopbackOnly,
    }
}

async fn start_with(
    authenticator: StaticAuthenticator,
    store: Arc<dyn GatewayStore>,
) -> ServerHandle {
    let devices = authenticator.devices();
    GatewayServer::new(config(), Arc::new(authenticator), Arc::new(devices))
        .expect("the configuration and registry are valid")
        .with_store(store)
        .with_clock(Arc::new(SystemClock))
        .bind("127.0.0.1:0".parse().expect("loopback address parses"))
        .await
        .expect("an ephemeral loopback port is available")
        .start()
}

fn client_config(
    handle: &ServerHandle,
    identity: Arc<DeviceIdentity>,
    role: SecurityRole,
    scopes: &[Scope],
) -> GatewayClientConfig {
    let endpoint = Url::parse(&format!(
        "ws://127.0.0.1:{}/",
        handle.local_address().port()
    ))
    .expect("the loopback endpoint parses");
    let mut config = GatewayClientConfig::new(endpoint, identity);
    config.role = role;
    config.scopes = ScopeSet::from_scopes(scopes.iter().copied());
    config.reconnect = ReconnectPolicy::Never;
    config.timeouts.request = Duration::from_secs(5);
    config
}

fn request_id(value: &str) -> RequestId {
    RequestId::new(value, PREAUTH_MAX_FRAME_BYTES).expect("the request identity is bounded")
}

fn method(name: &str) -> GatewayMethodName {
    GatewayMethodName::Core(resolve_core_method(name).expect("the method is catalogued"))
}

/// A backend detail no adapter should send and every adapter eventually will.
fn shouty_detail() -> String {
    let mut detail = "\u{7f}\u{1b}[2Jtorn\n\r".to_owned();
    detail.push_str(&"x".repeat(64 * 1024));
    detail
}

/// Decodes the JSON body of a successful response.
fn response_body(response: &ResponseFrame) -> Value {
    serde_json::from_str(
        response
            .payload()
            .value()
            .expect("a successful response carries a payload")
            .as_json(),
    )
    .expect("the payload is valid JSON")
}

/// Waits until the directory reports `expected` connected nodes.
///
/// A client shutdown returns as soon as the socket is closed; the server side
/// deregisters a moment later. Reconnecting before that happens would make the
/// gateway see the dead connection as still live, so the reclaim test has to
/// observe the deregistration rather than assume it.
async fn await_node_count(operator: &GatewayClient, expected: u64) {
    for attempt in 0..200_u32 {
        let response = operator
            .request(
                request_id(&format!("list-{attempt}")),
                method("node.list"),
                &json!({}),
            )
            .await
            .expect("the listing completes");
        if response_body(&response)["count"] == json!(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("the directory never settled at {expected} connected nodes");
}

#[tokio::test]
async fn an_adapter_supplied_from_a_composition_root_serves_real_requests() {
    let identity = device(41);
    let store = Arc::new(ChaoticStore::with_detail(shouty_detail()));
    let handle = start_with(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(SystemClock)).with_paired_device(
            identity.device_id().gateway_wire_id(),
            Grant::new(Role::Operator, [OperatorScope::Admin]),
        ),
        Arc::clone(&store) as Arc<dyn GatewayStore>,
    )
    .await;

    let (client, _events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&identity),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the client configuration is valid");
    client.wait_ready().await.expect("the handshake succeeds");

    let response = client
        .request(
            request_id("create-1"),
            method("sessions.create"),
            &create_params("s1"),
        )
        .await
        .expect("the swapped adapter serves the call");
    assert!(response.ok(), "{:?}", response.error());

    // An adapter that answers with 64 KiB of control characters must not be
    // able to take the connection down or put its text on the wire unbounded.
    store.schedule(Fault::Refuse);
    let response = client
        .request(request_id("list-1"), method("sessions.list"), &json!({}))
        .await
        .expect("a backend failure is a response, not a disconnection");
    assert!(!response.ok());
    let error = response.error().expect("a failure carries an error shape");
    assert_eq!(error.code.as_str(), "UNAVAILABLE");
    assert_eq!(error.retryable, Some(true));
    assert!(
        error.message.as_str().len() <= PREAUTH_MAX_FRAME_BYTES,
        "the adapter's detail text reached the wire unbounded"
    );

    // The connection is still usable afterwards.
    let response = client
        .request(request_id("list-2"), method("sessions.list"), &json!({}))
        .await
        .expect("the connection survived the failure");
    assert!(response.ok(), "{:?}", response.error());

    client.shutdown().await.expect("the client stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_reconnecting_node_is_handed_back_the_work_its_previous_connection_claimed() {
    let node = device(42);
    let wire_id = node.device_id().gateway_wire_id();
    let operator = device(43);
    let store = Arc::new(ChaoticStore::new());
    let handle = start_with(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(SystemClock))
            .with_paired_device(wire_id.clone(), Grant::new(Role::Node, []))
            .with_paired_device(
                operator.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Admin]),
            ),
        Arc::clone(&store) as Arc<dyn GatewayStore>,
    )
    .await;

    let node_config = |handle: &ServerHandle| {
        let mut config = client_config(handle, Arc::clone(&node), SecurityRole::Node, &[]);
        config.client.id = ClientId::NodeHost;
        config.client.mode = ClientMode::Node;
        config
    };
    let (node_client, _node_events) =
        GatewayClient::start(node_config(&handle)).expect("the node configuration is valid");
    node_client.wait_ready().await.expect("the node connects");

    let (operator_client, _operator_events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&operator),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the operator configuration is valid");
    operator_client
        .wait_ready()
        .await
        .expect("the operator connects");

    let response = operator_client
        .request(
            request_id("enqueue-1"),
            method("node.pending.enqueue"),
            &json!({ "nodeId": wire_id, "id": "i1", "command": "skills.run", "payload": "{}" }),
        )
        .await
        .expect("the enqueue completes");
    assert!(response.ok(), "{:?}", response.error());

    let response = node_client
        .request(
            request_id("pull-1"),
            method("node.pending.pull"),
            &json!({ "limit": 4 }),
        )
        .await
        .expect("the pull completes");
    assert!(response.ok(), "{:?}", response.error());

    // The node dies holding an unacknowledged claim.
    node_client.shutdown().await.expect("the node stops");
    await_node_count(&operator_client, 0).await;

    let (node_client, _node_events) =
        GatewayClient::start(node_config(&handle)).expect("the node configuration is valid");
    node_client.wait_ready().await.expect("the node reconnects");
    let response = node_client
        .request(
            request_id("pull-2"),
            method("node.pending.pull"),
            &json!({ "limit": 4 }),
        )
        .await
        .expect("the pull completes");
    assert!(response.ok(), "{:?}", response.error());
    let body = response_body(&response);
    assert_eq!(
        body["count"],
        json!(1),
        "the claim the dead connection held was never redelivered"
    );
    assert_eq!(body["invocations"][0]["id"], json!("i1"));

    node_client
        .shutdown()
        .await
        .expect("the node stops cleanly");
    operator_client
        .shutdown()
        .await
        .expect("the operator stops cleanly");
    handle.shutdown().await;
}

#[tokio::test]
async fn a_second_connection_does_not_take_work_away_from_a_node_that_is_still_live() {
    let node = device(44);
    let wire_id = node.device_id().gateway_wire_id();
    let operator = device(45);
    let store = Arc::new(ChaoticStore::new());
    let handle = start_with(
        StaticAuthenticator::new(CredentialPolicy::None, Arc::new(SystemClock))
            .with_paired_device(wire_id.clone(), Grant::new(Role::Node, []))
            .with_paired_device(
                operator.device_id().gateway_wire_id(),
                Grant::new(Role::Operator, [OperatorScope::Admin]),
            ),
        Arc::clone(&store) as Arc<dyn GatewayStore>,
    )
    .await;

    let node_config = |handle: &ServerHandle| {
        let mut config = client_config(handle, Arc::clone(&node), SecurityRole::Node, &[]);
        config.client.id = ClientId::NodeHost;
        config.client.mode = ClientMode::Node;
        config
    };
    let (first, _first_events) =
        GatewayClient::start(node_config(&handle)).expect("the node configuration is valid");
    first.wait_ready().await.expect("the first node connects");

    let (operator_client, _operator_events) = GatewayClient::start(client_config(
        &handle,
        Arc::clone(&operator),
        SecurityRole::Operator,
        &[Scope::OperatorAdmin],
    ))
    .expect("the operator configuration is valid");
    operator_client
        .wait_ready()
        .await
        .expect("the operator connects");
    operator_client
        .request(
            request_id("enqueue-1"),
            method("node.pending.enqueue"),
            &json!({ "nodeId": wire_id, "id": "i1", "command": "skills.run", "payload": "{}" }),
        )
        .await
        .expect("the enqueue completes");
    first
        .request(
            request_id("pull-1"),
            method("node.pending.pull"),
            &json!({ "limit": 4 }),
        )
        .await
        .expect("the first node claims the invocation");

    // A second connection for the same device arrives while the first is still
    // serving. Its claim is not stale, so nothing may be handed out twice.
    let (second, _second_events) =
        GatewayClient::start(node_config(&handle)).expect("the node configuration is valid");
    second.wait_ready().await.expect("the second node connects");
    let response = second
        .request(
            request_id("pull-2"),
            method("node.pending.pull"),
            &json!({ "limit": 4 }),
        )
        .await
        .expect("the pull completes");
    let body = response_body(&response);
    assert_eq!(
        body["count"],
        json!(0),
        "a live claimant's work was reclaimed out from under it"
    );

    first.shutdown().await.expect("the first node stops");
    second.shutdown().await.expect("the second node stops");
    operator_client
        .shutdown()
        .await
        .expect("the operator stops cleanly");
    handle.shutdown().await;
}

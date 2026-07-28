//! The narrow persistence port used by this crate and its in-memory adapter.
//!
//! `crates/claw-state` is owned by a different workstream and is deliberately
//! not referenced here. Everything this server needs to persist is expressed by
//! [`GatewayStore`]; the shipped [`InMemoryGatewayStore`] is the only adapter in
//! this crate. A durable adapter can be supplied by a composition root without
//! changing any Gateway code.
//!
//! # What a durable adapter must provide that this one does not
//!
//! The port is what a restart reads state back through, so every operation here
//! is a read or a *single* record mutation, and none of them are batched into a
//! transaction. Two consequences an adapter author has to plan for:
//!
//! * **A failed write may still have landed.** [`crate::error::StoreError`] can
//!   report [`crate::error::StoreError::Backend`], but nothing distinguishes
//!   "refused before writing" from "committed and then failed to answer". The
//!   only handler that issues two writes for one request is `set-heartbeats`,
//!   and it is documented in [`crate::methods`] as non-atomic for that reason.
//! * **Idempotency is per operation, not per request.**
//!   [`GatewayStore::enqueue_pending`] and [`GatewayStore::create_session`]
//!   reject a duplicate identity, so a retry after an unacknowledged write is
//!   *detectable* by the caller — but it is reported as a conflict, not as a
//!   confirmation, and [`GatewayStore::patch_session`] bumps the revision on
//!   every call, so a retried patch is not the same as one patch.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::StoreError;

/// A boxed future returned by every [`GatewayStore`] operation.
///
/// A boxed future keeps the port object-safe while still allowing genuinely
/// asynchronous adapters (for example a database) behind the same trait.
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// A persisted conversation session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    /// Stable session identity.
    pub id: String,
    /// Owning agent identity.
    pub agent_id: String,
    /// Optional human-readable title.
    pub title: Option<String>,
    /// Creation time in Unix milliseconds.
    pub created_at_ms: u64,
    /// Last mutation time in Unix milliseconds.
    pub updated_at_ms: u64,
    /// Monotonic per-record revision, starting at one.
    pub revision: u64,
    /// Whether the session has been archived.
    pub archived: bool,
}

/// Fields accepted when creating a session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDraft {
    /// Stable session identity.
    pub id: String,
    /// Owning agent identity.
    pub agent_id: String,
    /// Optional human-readable title.
    pub title: Option<String>,
    /// Creation time in Unix milliseconds.
    pub created_at_ms: u64,
}

/// Fields accepted when patching a session.
///
/// `None` leaves a field untouched; `Some(None)` clears an optional field.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionPatch {
    /// Replacement title, or an explicit clear.
    #[serde(default)]
    pub title: Option<Option<String>>,
    /// Replacement archive flag.
    #[serde(default)]
    pub archived: Option<bool>,
    /// Mutation time in Unix milliseconds.
    pub updated_at_ms: u64,
}

impl SessionPatch {
    /// Reports whether this patch would change any persisted field.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.title.is_none() && self.archived.is_none()
    }
}

/// A recorded heartbeat observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRecord {
    /// Identity that produced the heartbeat.
    pub source: String,
    /// Observation time in Unix milliseconds.
    pub observed_at_ms: u64,
}

/// One invocation queued for a capability-host node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingInvocation {
    /// Stable invocation identity, unique per node.
    pub id: String,
    /// Command the node should execute.
    pub command: String,
    /// Opaque JSON-encoded invocation payload.
    pub payload: String,
    /// Enqueue time in Unix milliseconds.
    pub enqueued_at_ms: u64,
}

/// The complete persistence surface required by this Gateway server.
pub trait GatewayStore: Debug + Send + Sync {
    /// Inserts a session, rejecting duplicate identities.
    fn create_session(&self, draft: SessionDraft) -> StoreFuture<'_, SessionRecord>;

    /// Returns one session by exact identity.
    fn get_session<'a>(&'a self, id: &'a str) -> StoreFuture<'a, Option<SessionRecord>>;

    /// Returns every session ordered by identity.
    fn list_sessions(&self) -> StoreFuture<'_, Vec<SessionRecord>>;

    /// Applies a patch and returns the new record, or `None` when absent.
    fn patch_session<'a>(
        &'a self,
        id: &'a str,
        patch: SessionPatch,
    ) -> StoreFuture<'a, Option<SessionRecord>>;

    /// Removes a session and reports whether it existed.
    fn delete_session<'a>(&'a self, id: &'a str) -> StoreFuture<'a, bool>;

    /// Records the newest heartbeat observation.
    fn record_heartbeat(&self, record: HeartbeatRecord) -> StoreFuture<'_, ()>;

    /// Returns the newest heartbeat observation.
    fn last_heartbeat(&self) -> StoreFuture<'_, Option<HeartbeatRecord>>;

    /// Enables or disables heartbeat recording and returns the previous value.
    fn set_heartbeats_enabled(&self, enabled: bool) -> StoreFuture<'_, bool>;

    /// Reports whether heartbeat recording is enabled.
    fn heartbeats_enabled(&self) -> StoreFuture<'_, bool>;

    /// Appends one invocation to a node's bounded pending queue.
    ///
    /// Returns the queue depth after the append, counting both pending and
    /// awaiting-acknowledgement invocations.
    fn enqueue_pending<'a>(
        &'a self,
        node_id: &'a str,
        invocation: PendingInvocation,
    ) -> StoreFuture<'a, usize>;

    /// Moves up to `max` invocations from pending to awaiting-acknowledgement.
    fn pull_pending<'a>(
        &'a self,
        node_id: &'a str,
        max: usize,
    ) -> StoreFuture<'a, Vec<PendingInvocation>>;

    /// Acknowledges one pulled invocation and reports whether it was awaited.
    fn ack_pending<'a>(&'a self, node_id: &'a str, invocation_id: &'a str)
    -> StoreFuture<'a, bool>;

    /// Returns every claimed-but-unacknowledged invocation to the pending set.
    ///
    /// Returns how many invocations were reclaimed, which is zero when the node
    /// holds no outstanding claim.
    ///
    /// [`Self::pull_pending`] moves work into an awaiting-acknowledgement set
    /// that only [`Self::ack_pending`] and [`Self::drain_pending`] can leave.
    /// A claimant that dies between the pull and the acknowledgement — a node
    /// that crashes, or a Gateway process that restarts on top of a durable
    /// adapter — therefore strands that work permanently: no later
    /// [`Self::pull_pending`] can see it, and the entries keep occupying the
    /// per-node bound until something discards the whole queue. This is the one
    /// operation a durable adapter needs that reading state back cannot
    /// substitute for, because the claim it must undo was made by a process
    /// that no longer exists.
    ///
    /// Reclaimed invocations are placed **before** entries still pending, in
    /// their original pull order, so redelivery preserves the order the
    /// enqueuing operator chose. Delivery is therefore at-least-once: a node
    /// that executed an invocation and died before acknowledging it will be
    /// handed that invocation again.
    fn reclaim_pending<'a>(&'a self, node_id: &'a str) -> StoreFuture<'a, usize>;

    /// Removes and returns every pending and awaiting-acknowledgement invocation.
    fn drain_pending<'a>(&'a self, node_id: &'a str) -> StoreFuture<'a, Vec<PendingInvocation>>;
}

#[derive(Debug, Default)]
struct NodeQueue {
    pending: Vec<PendingInvocation>,
    awaiting_ack: Vec<PendingInvocation>,
}

impl NodeQueue {
    const fn len(&self) -> usize {
        self.pending.len() + self.awaiting_ack.len()
    }

    const fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.awaiting_ack.is_empty()
    }
}

#[derive(Debug)]
struct StoreState {
    sessions: BTreeMap<String, SessionRecord>,
    heartbeat: Option<HeartbeatRecord>,
    heartbeats_enabled: bool,
    nodes: BTreeMap<String, NodeQueue>,
}

/// A bounded, process-local [`GatewayStore`] adapter.
#[derive(Debug)]
pub struct InMemoryGatewayStore {
    state: Mutex<StoreState>,
    max_sessions: usize,
    max_pending_per_node: usize,
}

impl InMemoryGatewayStore {
    /// Creates an adapter with explicit collection bounds.
    #[must_use]
    pub const fn new(max_sessions: usize, max_pending_per_node: usize) -> Self {
        Self {
            state: Mutex::new(StoreState {
                sessions: BTreeMap::new(),
                heartbeat: None,
                heartbeats_enabled: true,
                nodes: BTreeMap::new(),
            }),
            max_sessions,
            max_pending_per_node,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StoreState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The synchronous half of every [`GatewayStore`] operation.
///
/// Each method below is the entire critical section, so the boxed future the
/// port returns is allocated only after the guard has been released. Doing the
/// allocation inside the lock would serialise every connection behind one
/// process-wide allocator call for no benefit.
impl InMemoryGatewayStore {
    fn insert_session(&self, draft: SessionDraft) -> Result<SessionRecord, StoreError> {
        let mut state = self.lock();
        if state.sessions.contains_key(&draft.id) {
            return Err(StoreError::Conflict { id: draft.id });
        }
        if state.sessions.len() >= self.max_sessions {
            return Err(StoreError::CapacityExceeded {
                collection: "sessions",
                limit: self.max_sessions,
            });
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
        state.sessions.insert(draft.id, record.clone());
        drop(state);
        Ok(record)
    }

    fn read_session(&self, id: &str) -> Option<SessionRecord> {
        self.lock().sessions.get(id).cloned()
    }

    fn read_sessions(&self) -> Vec<SessionRecord> {
        self.lock().sessions.values().cloned().collect()
    }

    fn apply_patch(&self, id: &str, patch: SessionPatch) -> Option<SessionRecord> {
        let mut state = self.lock();
        let record = state.sessions.get_mut(id)?;
        if let Some(title) = patch.title {
            record.title = title;
        }
        if let Some(archived) = patch.archived {
            record.archived = archived;
        }
        record.updated_at_ms = patch.updated_at_ms;
        record.revision = record.revision.saturating_add(1);
        let patched = record.clone();
        drop(state);
        Some(patched)
    }

    fn remove_session(&self, id: &str) -> bool {
        self.lock().sessions.remove(id).is_some()
    }

    fn store_heartbeat(&self, record: HeartbeatRecord) {
        let mut state = self.lock();
        if state.heartbeats_enabled {
            state.heartbeat = Some(record);
        }
    }

    fn read_heartbeat(&self) -> Option<HeartbeatRecord> {
        self.lock().heartbeat.clone()
    }

    fn toggle_heartbeats(&self, enabled: bool) -> bool {
        let mut state = self.lock();
        let previous = state.heartbeats_enabled;
        state.heartbeats_enabled = enabled;
        drop(state);
        previous
    }

    fn read_heartbeats_enabled(&self) -> bool {
        self.lock().heartbeats_enabled
    }

    fn push_pending(
        &self,
        node_id: &str,
        invocation: PendingInvocation,
    ) -> Result<usize, StoreError> {
        let mut state = self.lock();
        let queue = state.nodes.entry(node_id.to_owned()).or_default();
        if queue.len() >= self.max_pending_per_node {
            let limit = self.max_pending_per_node;
            Self::forget_empty(&mut state, node_id);
            return Err(StoreError::CapacityExceeded {
                collection: "node.pending",
                limit,
            });
        }
        if queue
            .pending
            .iter()
            .chain(queue.awaiting_ack.iter())
            .any(|existing| existing.id == invocation.id)
        {
            let id = invocation.id;
            Self::forget_empty(&mut state, node_id);
            return Err(StoreError::Conflict { id });
        }
        queue.pending.push(invocation);
        let depth = queue.len();
        drop(state);
        Ok(depth)
    }

    fn take_pending(&self, node_id: &str, max: usize) -> Vec<PendingInvocation> {
        let mut state = self.lock();
        let Some(queue) = state.nodes.get_mut(node_id) else {
            return Vec::new();
        };
        let count = max.min(queue.pending.len());
        let pulled: Vec<PendingInvocation> = queue.pending.drain(..count).collect();
        queue.awaiting_ack.extend(pulled.iter().cloned());
        Self::forget_empty(&mut state, node_id);
        drop(state);
        pulled
    }

    fn acknowledge_pending(&self, node_id: &str, invocation_id: &str) -> bool {
        let mut state = self.lock();
        let Some(queue) = state.nodes.get_mut(node_id) else {
            return false;
        };
        let Some(index) = queue
            .awaiting_ack
            .iter()
            .position(|invocation| invocation.id == invocation_id)
        else {
            Self::forget_empty(&mut state, node_id);
            return false;
        };
        queue.awaiting_ack.remove(index);
        Self::forget_empty(&mut state, node_id);
        drop(state);
        true
    }

    fn take_all_pending(&self, node_id: &str) -> Vec<PendingInvocation> {
        let mut state = self.lock();
        let Some(queue) = state.nodes.get_mut(node_id) else {
            return Vec::new();
        };
        let mut drained = std::mem::take(&mut queue.pending);
        drained.append(&mut queue.awaiting_ack);
        Self::forget_empty(&mut state, node_id);
        drop(state);
        drained
    }

    fn requeue_awaiting(&self, node_id: &str) -> usize {
        let mut state = self.lock();
        let Some(queue) = state.nodes.get_mut(node_id) else {
            return 0;
        };
        let mut reclaimed = std::mem::take(&mut queue.awaiting_ack);
        let count = reclaimed.len();
        // The reclaimed entries were pulled before anything still pending was,
        // so they go back at the head to keep the enqueue order intact.
        reclaimed.append(&mut queue.pending);
        queue.pending = reclaimed;
        Self::forget_empty(&mut state, node_id);
        drop(state);
        count
    }

    /// Drops a node's queue once it holds nothing.
    ///
    /// Node identities are verified device identities, so they are attacker
    /// influenced and unbounded over the process lifetime. Without this the map
    /// would keep one empty entry per node that ever enqueued — including the
    /// entry `entry().or_default()` creates for a call that is then refused —
    /// and nothing would ever remove them.
    fn forget_empty(state: &mut StoreState, node_id: &str) {
        if state.nodes.get(node_id).is_some_and(NodeQueue::is_empty) {
            state.nodes.remove(node_id);
        }
    }
}

fn ready<T>(value: Result<T, StoreError>) -> StoreFuture<'static, T>
where
    T: Send + 'static,
{
    Box::pin(std::future::ready(value))
}

impl GatewayStore for InMemoryGatewayStore {
    fn create_session(&self, draft: SessionDraft) -> StoreFuture<'_, SessionRecord> {
        ready(self.insert_session(draft))
    }

    fn get_session<'a>(&'a self, id: &'a str) -> StoreFuture<'a, Option<SessionRecord>> {
        ready(Ok(self.read_session(id)))
    }

    fn list_sessions(&self) -> StoreFuture<'_, Vec<SessionRecord>> {
        ready(Ok(self.read_sessions()))
    }

    fn patch_session<'a>(
        &'a self,
        id: &'a str,
        patch: SessionPatch,
    ) -> StoreFuture<'a, Option<SessionRecord>> {
        ready(Ok(self.apply_patch(id, patch)))
    }

    fn delete_session<'a>(&'a self, id: &'a str) -> StoreFuture<'a, bool> {
        ready(Ok(self.remove_session(id)))
    }

    fn record_heartbeat(&self, record: HeartbeatRecord) -> StoreFuture<'_, ()> {
        self.store_heartbeat(record);
        ready(Ok(()))
    }

    fn last_heartbeat(&self) -> StoreFuture<'_, Option<HeartbeatRecord>> {
        ready(Ok(self.read_heartbeat()))
    }

    fn set_heartbeats_enabled(&self, enabled: bool) -> StoreFuture<'_, bool> {
        ready(Ok(self.toggle_heartbeats(enabled)))
    }

    fn heartbeats_enabled(&self) -> StoreFuture<'_, bool> {
        ready(Ok(self.read_heartbeats_enabled()))
    }

    fn enqueue_pending<'a>(
        &'a self,
        node_id: &'a str,
        invocation: PendingInvocation,
    ) -> StoreFuture<'a, usize> {
        ready(self.push_pending(node_id, invocation))
    }

    fn pull_pending<'a>(
        &'a self,
        node_id: &'a str,
        max: usize,
    ) -> StoreFuture<'a, Vec<PendingInvocation>> {
        ready(Ok(self.take_pending(node_id, max)))
    }

    fn ack_pending<'a>(
        &'a self,
        node_id: &'a str,
        invocation_id: &'a str,
    ) -> StoreFuture<'a, bool> {
        ready(Ok(self.acknowledge_pending(node_id, invocation_id)))
    }

    fn drain_pending<'a>(&'a self, node_id: &'a str) -> StoreFuture<'a, Vec<PendingInvocation>> {
        ready(Ok(self.take_all_pending(node_id)))
    }

    fn reclaim_pending<'a>(&'a self, node_id: &'a str) -> StoreFuture<'a, usize> {
        ready(Ok(self.requeue_awaiting(node_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> InMemoryGatewayStore {
        InMemoryGatewayStore::new(2, 2)
    }

    fn draft(id: &str) -> SessionDraft {
        SessionDraft {
            id: id.to_owned(),
            agent_id: "agent-main".to_owned(),
            title: Some("first".to_owned()),
            created_at_ms: 1_000,
        }
    }

    fn invocation(id: &str) -> PendingInvocation {
        PendingInvocation {
            id: id.to_owned(),
            command: "skills.run".to_owned(),
            payload: "{}".to_owned(),
            enqueued_at_ms: 5,
        }
    }

    #[tokio::test]
    async fn create_returns_a_fully_populated_first_revision() {
        let store = store();
        let record = store.create_session(draft("s1")).await.expect("create");
        assert_eq!(record.id, "s1");
        assert_eq!(record.agent_id, "agent-main");
        assert_eq!(record.title.as_deref(), Some("first"));
        assert_eq!(record.created_at_ms, 1_000);
        assert_eq!(record.updated_at_ms, 1_000);
        assert_eq!(record.revision, 1);
        assert!(!record.archived);
    }

    #[tokio::test]
    async fn duplicate_create_conflicts_on_the_exact_identity() {
        let store = store();
        store.create_session(draft("s1")).await.expect("create");
        assert_eq!(
            store.create_session(draft("s1")).await.unwrap_err(),
            StoreError::Conflict {
                id: "s1".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn session_capacity_is_enforced_at_the_configured_bound() {
        let store = store();
        store.create_session(draft("s1")).await.expect("create");
        store.create_session(draft("s2")).await.expect("create");
        assert_eq!(
            store.create_session(draft("s3")).await.unwrap_err(),
            StoreError::CapacityExceeded {
                collection: "sessions",
                limit: 2,
            }
        );
    }

    #[tokio::test]
    async fn patch_clears_title_bumps_revision_and_sets_timestamp() {
        let store = store();
        store.create_session(draft("s1")).await.expect("create");
        let patched = store
            .patch_session(
                "s1",
                SessionPatch {
                    title: Some(None),
                    archived: Some(true),
                    updated_at_ms: 4_242,
                },
            )
            .await
            .expect("patch")
            .expect("session exists");
        assert_eq!(patched.title, None);
        assert!(patched.archived);
        assert_eq!(patched.updated_at_ms, 4_242);
        assert_eq!(patched.revision, 2);
        assert_eq!(patched.created_at_ms, 1_000);
    }

    #[tokio::test]
    async fn patch_of_absent_session_returns_none_without_creating_it() {
        let store = store();
        let patched = store
            .patch_session(
                "ghost",
                SessionPatch {
                    updated_at_ms: 1,
                    ..SessionPatch::default()
                },
            )
            .await
            .expect("patch");
        assert_eq!(patched, None);
        assert_eq!(store.list_sessions().await.expect("list").len(), 0);
    }

    #[tokio::test]
    async fn list_is_ordered_by_identity() {
        let store = InMemoryGatewayStore::new(8, 2);
        for id in ["s3", "s1", "s2"] {
            store.create_session(draft(id)).await.expect("create");
        }
        let ids: Vec<String> = store
            .list_sessions()
            .await
            .expect("list")
            .into_iter()
            .map(|record| record.id)
            .collect();
        assert_eq!(ids, vec!["s1".to_owned(), "s2".to_owned(), "s3".to_owned()]);
    }

    #[tokio::test]
    async fn delete_reports_presence_exactly_once() {
        let store = store();
        store.create_session(draft("s1")).await.expect("create");
        assert!(store.delete_session("s1").await.expect("delete"));
        assert!(!store.delete_session("s1").await.expect("delete"));
    }

    #[tokio::test]
    async fn disabled_heartbeats_do_not_overwrite_the_last_record() {
        let store = store();
        store
            .record_heartbeat(HeartbeatRecord {
                source: "node-a".to_owned(),
                observed_at_ms: 10,
            })
            .await
            .expect("record");
        assert!(
            store
                .set_heartbeats_enabled(false)
                .await
                .expect("set heartbeats")
        );
        store
            .record_heartbeat(HeartbeatRecord {
                source: "node-b".to_owned(),
                observed_at_ms: 20,
            })
            .await
            .expect("record");
        assert_eq!(
            store.last_heartbeat().await.expect("last"),
            Some(HeartbeatRecord {
                source: "node-a".to_owned(),
                observed_at_ms: 10,
            })
        );
        assert!(!store.heartbeats_enabled().await.expect("enabled"));
    }

    #[tokio::test]
    async fn pull_moves_records_into_awaiting_ack_and_ack_removes_them() {
        let store = store();
        assert_eq!(
            store
                .enqueue_pending("node-a", invocation("i1"))
                .await
                .expect("enqueue"),
            1
        );
        assert_eq!(
            store
                .enqueue_pending("node-a", invocation("i2"))
                .await
                .expect("enqueue"),
            2
        );
        let pulled = store.pull_pending("node-a", 1).await.expect("pull");
        assert_eq!(pulled, vec![invocation("i1")]);
        assert!(store.ack_pending("node-a", "i1").await.expect("ack"));
        assert!(!store.ack_pending("node-a", "i1").await.expect("ack"));
        assert_eq!(
            store.drain_pending("node-a").await.expect("drain"),
            vec![invocation("i2")]
        );
    }

    #[tokio::test]
    async fn unacknowledged_pulls_still_occupy_the_queue_bound() {
        let store = store();
        store
            .enqueue_pending("node-a", invocation("i1"))
            .await
            .expect("enqueue");
        store
            .enqueue_pending("node-a", invocation("i2"))
            .await
            .expect("enqueue");
        store.pull_pending("node-a", 2).await.expect("pull");
        assert_eq!(
            store
                .enqueue_pending("node-a", invocation("i3"))
                .await
                .unwrap_err(),
            StoreError::CapacityExceeded {
                collection: "node.pending",
                limit: 2,
            }
        );
    }

    #[tokio::test]
    async fn reported_depth_counts_awaiting_acknowledgement_entries() {
        let store = store();
        assert_eq!(
            store
                .enqueue_pending("node-a", invocation("i1"))
                .await
                .expect("enqueue"),
            1
        );
        store.pull_pending("node-a", 1).await.expect("pull");
        assert_eq!(
            store
                .enqueue_pending("node-a", invocation("i2"))
                .await
                .expect("enqueue"),
            2
        );
        assert!(store.ack_pending("node-a", "i1").await.expect("ack"));
        assert_eq!(
            store
                .enqueue_pending("node-a", invocation("i3"))
                .await
                .expect("enqueue"),
            2
        );
    }

    #[tokio::test]
    async fn duplicate_invocation_identity_is_refused() {
        let store = store();
        store
            .enqueue_pending("node-a", invocation("i1"))
            .await
            .expect("enqueue");
        assert_eq!(
            store
                .enqueue_pending("node-a", invocation("i1"))
                .await
                .unwrap_err(),
            StoreError::Conflict {
                id: "i1".to_owned()
            }
        );
    }

    #[tokio::test]
    async fn queues_are_isolated_per_node() {
        let store = store();
        store
            .enqueue_pending("node-a", invocation("i1"))
            .await
            .expect("enqueue");
        assert_eq!(store.pull_pending("node-b", 8).await.expect("pull"), vec![]);
        assert_eq!(store.drain_pending("node-b").await.expect("drain"), vec![]);
        assert_eq!(
            store.pull_pending("node-a", 8).await.expect("pull"),
            vec![invocation("i1")]
        );
    }

    #[tokio::test]
    async fn reclaim_returns_unacknowledged_claims_to_the_front_of_the_queue() {
        let store = InMemoryGatewayStore::new(2, 8);
        for id in ["i1", "i2", "i3"] {
            store
                .enqueue_pending("node-a", invocation(id))
                .await
                .expect("enqueue");
        }
        assert_eq!(
            store.pull_pending("node-a", 2).await.expect("pull"),
            vec![invocation("i1"), invocation("i2")]
        );
        assert_eq!(store.reclaim_pending("node-a").await.expect("reclaim"), 2);
        assert_eq!(
            store.pull_pending("node-a", 8).await.expect("pull"),
            vec![invocation("i1"), invocation("i2"), invocation("i3")]
        );
    }

    #[tokio::test]
    async fn reclaim_leaves_acknowledged_work_alone_and_is_idempotent() {
        let store = store();
        store
            .enqueue_pending("node-a", invocation("i1"))
            .await
            .expect("enqueue");
        store.pull_pending("node-a", 1).await.expect("pull");
        assert!(store.ack_pending("node-a", "i1").await.expect("ack"));
        assert_eq!(store.reclaim_pending("node-a").await.expect("reclaim"), 0);
        assert_eq!(store.reclaim_pending("node-a").await.expect("reclaim"), 0);
        assert_eq!(store.pull_pending("node-a", 8).await.expect("pull"), vec![]);
    }

    #[tokio::test]
    async fn reclaim_frees_the_bound_a_dead_claimant_was_holding() {
        let store = store();
        for id in ["i1", "i2"] {
            store
                .enqueue_pending("node-a", invocation(id))
                .await
                .expect("enqueue");
        }
        store.pull_pending("node-a", 2).await.expect("pull");
        // Without a reclaim the queue is full of claims nobody will ever ack.
        assert_eq!(
            store
                .enqueue_pending("node-a", invocation("i3"))
                .await
                .unwrap_err(),
            StoreError::CapacityExceeded {
                collection: "node.pending",
                limit: 2,
            }
        );
        assert_eq!(store.reclaim_pending("node-a").await.expect("reclaim"), 2);
        // Reclaiming redelivers rather than discarding, so the bound is still
        // occupied — by work that can now actually be pulled again.
        assert_eq!(
            store.pull_pending("node-a", 8).await.expect("pull"),
            vec![invocation("i1"), invocation("i2")]
        );
    }

    #[tokio::test]
    async fn reclaiming_an_unknown_node_creates_no_queue_entry() {
        let store = store();
        assert_eq!(store.reclaim_pending("ghost").await.expect("reclaim"), 0);
        assert_eq!(store.drain_pending("ghost").await.expect("drain"), vec![]);
    }
}

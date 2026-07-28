//! Node discovery and node pending-invocation queue handlers.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::directory::ConnectionInfo;
use crate::dispatch::{MethodContext, MethodFuture, MethodHandler, MethodRegistry};
use crate::error::DispatchError;
use crate::events::EventDraft;
use crate::store::PendingInvocation;

use super::{MAX_INVOCATION_PAYLOAD_BYTES, bounded_text, identity, params_of};

pub(super) fn install(registry: &mut MethodRegistry) -> Result<(), DispatchError> {
    registry.register("node.list", Arc::new(NodeList))?;
    registry.register("node.describe", Arc::new(NodeDescribe))?;
    registry.register("node.pending.enqueue", Arc::new(PendingEnqueue))?;
    registry.register("node.pending.pull", Arc::new(PendingPull))?;
    registry.register("node.pending.ack", Arc::new(PendingAck))?;
    registry.register("node.pending.drain", Arc::new(PendingDrain))?;
    registry.register("node.event", Arc::new(NodeEvent))?;
    Ok(())
}

fn render_node(info: &ConnectionInfo) -> Value {
    json!({
        "connectionId": info.id.get(),
        "deviceId": info.device_id,
        "clientId": info.client_id,
        "clientMode": info.client_mode,
        "clientVersion": info.client_version,
        "protocol": info.protocol,
        "compatibility": info.compatibility,
        "connectedAtMs": info.connected_at_ms,
        "commands": info.commands,
    })
}

fn render_invocation(invocation: &PendingInvocation) -> Value {
    json!({
        "id": invocation.id,
        "command": invocation.command,
        "payload": invocation.payload,
        "enqueuedAtMs": invocation.enqueued_at_ms,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

/// `node.list` — every connected node.
#[derive(Debug)]
struct NodeList;

impl MethodHandler for NodeList {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            params_of::<NoParams>(context.method, params)?;
            let nodes = context.directory.nodes();
            Ok(json!({
                "nodes": nodes.iter().map(render_node).collect::<Vec<_>>(),
                "count": nodes.len(),
            }))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NodeIdParams {
    node_id: String,
}

/// `node.describe` — one connected node and its queue depth.
#[derive(Debug)]
struct NodeDescribe;

impl MethodHandler for NodeDescribe {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: NodeIdParams = params_of(context.method, params)?;
            identity(context.method, "nodeId", &request.node_id)?;
            let info = context.directory.node(&request.node_id).ok_or_else(|| {
                DispatchError::NotFound {
                    kind: "node",
                    id: request.node_id.clone(),
                }
            })?;
            Ok(json!({ "node": render_node(&info) }))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EnqueueParams {
    node_id: String,
    id: String,
    command: String,
    #[serde(default)]
    payload: String,
}

/// `node.pending.enqueue` — operator-side enqueue of one node invocation.
///
/// The target node must be connected. A `node.invoke.request` event is
/// published to that node's connection only.
#[derive(Debug)]
struct PendingEnqueue;

impl MethodHandler for PendingEnqueue {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: EnqueueParams = params_of(context.method, params)?;
            identity(context.method, "nodeId", &request.node_id)?;
            identity(context.method, "id", &request.id)?;
            identity(context.method, "command", &request.command)?;
            bounded_text(
                context.method,
                "payload",
                &request.payload,
                MAX_INVOCATION_PAYLOAD_BYTES,
            )?;
            let target = context.directory.node(&request.node_id).ok_or_else(|| {
                DispatchError::NotFound {
                    kind: "node",
                    id: request.node_id.clone(),
                }
            })?;
            let invocation = PendingInvocation {
                id: request.id.clone(),
                command: request.command.clone(),
                payload: request.payload.clone(),
                enqueued_at_ms: context.clock.unix_millis(),
            };
            let depth = context
                .store
                .enqueue_pending(&request.node_id, invocation.clone())
                .await?;
            let draft = EventDraft::targeted(
                "node.invoke.request",
                &json!({
                    "nodeId": request.node_id,
                    "invocation": render_invocation(&invocation),
                }),
                target.id,
            )
            .map_err(|error| DispatchError::InvalidParams {
                method: context.method.to_owned(),
                detail: error.to_string(),
            })?;
            context.events.publish(draft);
            Ok(json!({
                "nodeId": request.node_id,
                "id": request.id,
                "queueDepth": depth,
            }))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PullParams {
    #[serde(default = "default_pull_limit")]
    limit: usize,
}

const fn default_pull_limit() -> usize {
    16
}

/// `node.pending.pull` — a node claims up to `limit` queued invocations.
///
/// Nodes may only pull their own queue: the queue key is the caller's verified
/// device identity, never a caller-supplied value.
#[derive(Debug)]
struct PendingPull;

impl MethodHandler for PendingPull {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: PullParams = params_of(context.method, params)?;
            if request.limit == 0 || request.limit > 256 {
                return Err(DispatchError::InvalidParams {
                    method: context.method.to_owned(),
                    detail: "`limit` must be between 1 and 256".to_owned(),
                });
            }
            let claimed = context
                .store
                .pull_pending(context.device_id, request.limit)
                .await?;
            Ok(json!({
                "nodeId": context.device_id,
                "invocations": claimed.iter().map(render_invocation).collect::<Vec<_>>(),
                "count": claimed.len(),
            }))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AckParams {
    id: String,
}

/// `node.pending.ack` — a node acknowledges one claimed invocation.
#[derive(Debug)]
struct PendingAck;

impl MethodHandler for PendingAck {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: AckParams = params_of(context.method, params)?;
            identity(context.method, "id", &request.id)?;
            let acknowledged = context
                .store
                .ack_pending(context.device_id, &request.id)
                .await?;
            if !acknowledged {
                return Err(DispatchError::NotFound {
                    kind: "pending invocation",
                    id: request.id,
                });
            }
            Ok(json!({ "nodeId": context.device_id, "id": request.id, "acked": true }))
        })
    }
}

/// `node.pending.drain` — a node discards its entire queue.
#[derive(Debug)]
struct PendingDrain;

impl MethodHandler for PendingDrain {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            params_of::<NoParams>(context.method, params)?;
            let drained = context.store.drain_pending(context.device_id).await?;
            Ok(json!({
                "nodeId": context.device_id,
                "invocations": drained.iter().map(render_invocation).collect::<Vec<_>>(),
                "count": drained.len(),
            }))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NodeEventParams {
    kind: String,
    #[serde(default)]
    detail: String,
}

/// `node.event` — a node reports one lifecycle event.
///
/// The report is republished to operators as `node.presence`, attributed to the
/// caller's verified device identity rather than any caller-supplied identity.
#[derive(Debug)]
struct NodeEvent;

impl MethodHandler for NodeEvent {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: NodeEventParams = params_of(context.method, params)?;
            identity(context.method, "kind", &request.kind)?;
            bounded_text(
                context.method,
                "detail",
                &request.detail,
                super::MAX_TEXT_BYTES,
            )?;
            let observed_at_ms = context.clock.unix_millis();
            let draft = EventDraft::broadcast(
                "node.presence",
                &json!({
                    "nodeId": context.device_id,
                    "kind": request.kind,
                    "detail": request.detail,
                    "observedAtMs": observed_at_ms,
                }),
            )
            .map_err(|error| DispatchError::InvalidParams {
                method: context.method.to_owned(),
                detail: error.to_string(),
            })?;
            let ordinal = context.events.publish(draft);
            Ok(json!({
                "accepted": true,
                "nodeId": context.device_id,
                "observedAtMs": observed_at_ms,
                "ordinal": ordinal.get(),
            }))
        })
    }
}

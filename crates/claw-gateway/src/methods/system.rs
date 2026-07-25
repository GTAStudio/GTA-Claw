//! Informational, presence, and heartbeat handlers.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::directory::ConnectionInfo;
use crate::dispatch::{MethodContext, MethodFuture, MethodHandler, MethodRegistry};
use crate::error::DispatchError;
use crate::store::HeartbeatRecord;

use super::{MAX_IDENTITY_BYTES, identity, params_of};

pub(super) fn install(registry: &mut MethodRegistry) -> Result<(), DispatchError> {
    registry.register("health", Arc::new(Health))?;
    registry.register("system.info", Arc::new(SystemInfo))?;
    registry.register("gateway.identity.get", Arc::new(IdentityGet))?;
    registry.register("system-presence", Arc::new(SystemPresence))?;
    registry.register("last-heartbeat", Arc::new(LastHeartbeat))?;
    registry.register("set-heartbeats", Arc::new(SetHeartbeats))?;
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

fn presence_entry(info: &ConnectionInfo) -> Value {
    json!({
        "connectionId": info.id.get(),
        "role": info.role.as_str(),
        "scopes": info.scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
        "deviceId": info.device_id,
        "clientId": info.client_id,
        "clientMode": info.client_mode,
        "clientVersion": info.client_version,
        "protocol": info.protocol,
        "compatibility": info.compatibility,
        "connectedAtMs": info.connected_at_ms,
    })
}

/// `health` — liveness probe reachable by both ordinary roles.
#[derive(Debug)]
struct Health;

impl MethodHandler for Health {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            params_of::<NoParams>(context.method, params)?;
            Ok(json!({
                "ok": true,
                "version": context.server_version,
                "protocol": claw_protocol::gateway::GATEWAY_PROTOCOL_VERSION.get(),
                "nowMs": context.clock.unix_millis(),
            }))
        })
    }
}

/// `system.info` — server build and live connection counters.
#[derive(Debug)]
struct SystemInfo;

impl MethodHandler for SystemInfo {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            params_of::<NoParams>(context.method, params)?;
            let all = context.directory.all();
            let nodes = all
                .iter()
                .filter(|info| info.role == claw_protocol::gateway::Role::Node)
                .count();
            Ok(json!({
                "version": context.server_version,
                "protocol": claw_protocol::gateway::GATEWAY_PROTOCOL_VERSION.get(),
                "connections": all.len(),
                "nodes": nodes,
                "operators": all.len() - nodes,
                "eventOrdinal": context.events.last_ordinal(),
                "nowMs": context.clock.unix_millis(),
            }))
        })
    }
}

/// `gateway.identity.get` — the caller's own authenticated identity.
#[derive(Debug)]
struct IdentityGet;

impl MethodHandler for IdentityGet {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            params_of::<NoParams>(context.method, params)?;
            Ok(json!({
                "connectionId": context.connection.get(),
                "deviceId": context.device_id,
                "role": context.role.as_str(),
                "scopes": context.scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            }))
        })
    }
}

/// `system-presence` — every live authenticated connection.
#[derive(Debug)]
struct SystemPresence;

impl MethodHandler for SystemPresence {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            params_of::<NoParams>(context.method, params)?;
            let entries: Vec<Value> = context.directory.all().iter().map(presence_entry).collect();
            Ok(json!({ "entries": entries }))
        })
    }
}

/// `last-heartbeat` — the most recent recorded heartbeat and the enable flag.
#[derive(Debug)]
struct LastHeartbeat;

impl MethodHandler for LastHeartbeat {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            params_of::<NoParams>(context.method, params)?;
            let enabled = context.store.heartbeats_enabled().await?;
            let record = context.store.last_heartbeat().await?;
            Ok(json!({
                "enabled": enabled,
                "heartbeat": record.map(|record| json!({
                    "source": record.source,
                    "observedAtMs": record.observed_at_ms,
                })),
            }))
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetHeartbeatsParams {
    enabled: bool,
    #[serde(default)]
    source: Option<String>,
}

/// `set-heartbeats` — toggles heartbeat recording and records one immediately.
#[derive(Debug)]
struct SetHeartbeats;

impl MethodHandler for SetHeartbeats {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let request: SetHeartbeatsParams = params_of(context.method, params)?;
            let source = request
                .source
                .unwrap_or_else(|| context.device_id.to_owned());
            identity(context.method, "source", &source)?;
            let previous = context
                .store
                .set_heartbeats_enabled(request.enabled)
                .await?;
            let observed_at_ms = context.clock.unix_millis();
            if request.enabled {
                context
                    .store
                    .record_heartbeat(HeartbeatRecord {
                        source: source.clone(),
                        observed_at_ms,
                    })
                    .await?;
                let draft = crate::events::EventDraft::broadcast(
                    "heartbeat",
                    &json!({ "source": source, "observedAtMs": observed_at_ms }),
                )
                .map_err(|error| DispatchError::InvalidParams {
                    method: context.method.to_owned(),
                    detail: error.to_string(),
                })?;
                context.events.publish(draft);
            }
            Ok(json!({
                "enabled": request.enabled,
                "previous": previous,
                "maxSourceBytes": MAX_IDENTITY_BYTES,
            }))
        })
    }
}

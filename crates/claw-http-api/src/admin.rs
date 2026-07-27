//! Authenticated, allowlisted Admin HTTP RPC.

use axum::extract::{Request, State};
use axum::response::Response;

use crate::state::ApiState;

/// Exact frozen upstream Admin HTTP RPC allowlist.
pub const ADMIN_HTTP_RPC_METHODS: &[&str] = &[
    "health",
    "status",
    "logs.tail",
    "usage.status",
    "usage.cost",
    "gateway.restart.request",
    "gateway.suspend.prepare",
    "gateway.suspend.status",
    "gateway.suspend.resume",
    "commands.list",
    "config.get",
    "config.schema",
    "config.schema.lookup",
    "config.set",
    "config.patch",
    "config.apply",
    "channels.status",
    "channels.start",
    "channels.stop",
    "channels.logout",
    "web.login.start",
    "web.login.wait",
    "models.list",
    "models.authStatus",
    "agents.list",
    "agents.create",
    "agents.update",
    "agents.delete",
    "exec.approvals.get",
    "exec.approvals.set",
    "exec.approvals.node.get",
    "exec.approvals.node.set",
    "cron.status",
    "cron.list",
    "cron.get",
    "cron.runs",
    "cron.add",
    "cron.update",
    "cron.remove",
    "cron.run",
    "device.pair.list",
    "device.pair.approve",
    "device.pair.reject",
    "device.pair.remove",
    "node.list",
    "node.describe",
    "node.pair.list",
    "node.pair.approve",
    "node.pair.reject",
    "node.pair.remove",
    "node.rename",
    "tasks.list",
    "tasks.get",
    "tasks.cancel",
    "doctor.memory.status",
    "update.status",
];

pub(crate) async fn rpc(State(state): State<ApiState>, request: Request) -> Response {
    state.inner.admin_rpc.handle(request).await
}

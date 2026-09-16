//! Runtime approval presentation and decisions on the authenticated Gateway.

use std::sync::{Arc, OnceLock};

use claw_application::model::approval::{ApprovalDecision, ApprovalRequest, ApprovalWithdrawal};
use claw_application::model::ids::ApprovalId;
use claw_application::ports::approval::ApprovalPort;
use claw_application::ports::{PortError, PortFuture};
use claw_gateway::dispatch::MethodFuture;
use claw_gateway::{DispatchError, EventBus, EventDraft, MethodContext, MethodHandler};
use claw_observability::redaction::{REDACTED, is_sensitive_field};
use claw_runtime::ApprovalBroker;
use serde::Deserialize;
use serde_json::{Value, json};

use super::agent_runtime::AgentRuntime;

fn runtime_dispatch_error(method: &str, error: &claw_http_api::PortError) -> DispatchError {
    match error.kind {
        claw_http_api::PortErrorKind::InvalidRequest => DispatchError::InvalidParams {
            method: method.to_owned(), detail: "native request was rejected before acceptance or conflicts with an existing request".to_owned(),
        },
        _ => DispatchError::OutcomeUnknown { method: method.to_owned() },
    }
}

const MAX_APPROVAL_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_APPROVAL_PREVIEW_BYTES: usize = 32 * 1024;
const APPROVAL_PAGE_SIZE: usize = 32;

fn state_dispatch_error(method: &str, error: &PortError) -> DispatchError {
    match error {
        PortError::Invalid(_) | PortError::Conflict(_) | PortError::NotFound(_) => {
            DispatchError::InvalidParams {
                method: method.to_owned(),
                detail: "native request was rejected by the state contract".to_owned(),
            }
        }
        PortError::OutcomeUnknown(_)
        | PortError::CommittedButNotDurable(_)
        | PortError::Unavailable(_)
        | PortError::Cancelled => DispatchError::OutcomeUnknown {
            method: method.to_owned(),
        },
    }
}

fn approval_metadata(request: &ApprovalRequest) -> Value {
    json!({
        "id": request.approval_id.as_str(),
        "approvalId": request.approval_id.as_str(),
        "sessionId": request.session_id.as_str(),
        "tool": request.tool_name,
        "requestedAtMs": request.requested_at.as_millis(),
        "expiresAtMs": request.expires_at.as_millis(),
    })
}

fn redact_arguments(value: &mut Value) -> bool {
    let mut redacted = false;
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                if is_sensitive_field(name) {
                    *value = Value::String(REDACTED.to_owned());
                    redacted = true;
                } else {
                    redacted |= redact_arguments(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redacted |= redact_arguments(value);
            }
        }
        _ => {}
    }
    redacted
}

fn approval_preview(request: &ApprovalRequest) -> Result<Value, PortError> {
    if request.arguments.len() > MAX_APPROVAL_ARGUMENT_BYTES || request.tool_name.len() > 256 {
        return Err(PortError::Invalid(
            "approval arguments exceed the display limit".to_owned(),
        ));
    }
    let mut arguments: Value = serde_json::from_str(&request.arguments)
        .map_err(|_| PortError::Invalid("approval arguments must be bounded JSON".to_owned()))?;
    let redacted = redact_arguments(&mut arguments);
    let prompt = format!("{}\n{arguments}", request.tool_name);
    if prompt.len() > MAX_APPROVAL_PREVIEW_BYTES {
        return Err(PortError::Invalid(
            "approval preview exceeds the display limit".to_owned(),
        ));
    }
    let mut payload = approval_metadata(request);
    payload["prompt"] = Value::String(prompt);
    payload["previewComplete"] = Value::Bool(true);
    payload["redacted"] = Value::Bool(redacted);
    Ok(payload)
}

#[derive(Debug, Default)]
pub(super) struct GatewayApprovalPort {
    events: OnceLock<EventBus>,
}

impl GatewayApprovalPort {
    pub(super) fn attach(&self, events: EventBus) -> Result<(), PortError> {
        self.events
            .set(events)
            .map_err(|_| PortError::Unavailable("approval Gateway is already attached".to_owned()))
    }

    fn publish(&self, event: &str, payload: &Value) -> Result<(), PortError> {
        let events = self.events.get().ok_or_else(|| {
            PortError::Unavailable("approval Gateway is not available".to_owned())
        })?;
        let draft = EventDraft::broadcast(event, payload).map_err(|_| {
            PortError::Unavailable("approval event could not be encoded".to_owned())
        })?;
        events.publish(draft);
        Ok(())
    }

    fn dismiss(&self, id: &ApprovalId, status: &str) -> Result<(), PortError> {
        self.publish(
            "exec.approval.resolved",
            &json!({"id": id.as_str(), "approvalId": id.as_str(), "status": status}),
        )
    }
}

impl ApprovalPort for GatewayApprovalPort {
    fn binding_token(&self) -> Result<String, PortError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| {
            PortError::Unavailable("secure approval token source unavailable".to_owned())
        })?;
        Ok(random
            .iter()
            .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
            .map(char::from)
            .collect())
    }

    fn present_authorized(
        &self,
        request: ApprovalRequest,
        authority: claw_application::ports::tool::InvocationAuthority,
    ) -> PortFuture<'_, Result<(), PortError>> {
        if !authority.can_execute() {
            return Box::pin(std::future::ready(Err(PortError::Invalid(
                "caller cannot request tool execution".to_owned(),
            ))));
        }
        self.present(request)
    }

    fn present(&self, request: ApprovalRequest) -> PortFuture<'_, Result<(), PortError>> {
        Box::pin(async move {
            approval_preview(&request)?;
            self.publish("exec.approval.requested", &approval_metadata(&request))
        })
    }

    fn settle(&self, id: &ApprovalId) -> PortFuture<'_, Result<(), PortError>> {
        let result = self.dismiss(id, "resolved");
        Box::pin(async move { result })
    }

    fn withdraw(
        &self,
        id: &ApprovalId,
        reason: ApprovalWithdrawal,
    ) -> PortFuture<'_, Result<(), PortError>> {
        let result = self.dismiss(id, reason.label());
        Box::pin(async move { result })
    }

    fn abandon(&self, id: &ApprovalId) {
        let _ = self.dismiss(id, "abandoned");
    }
}

#[derive(Debug)]
pub(super) struct RuntimeApprovalHandler {
    broker: ApprovalBroker,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionParams {
    id: String,
    decision: Decision,
    #[serde(rename = "bindingToken")]
    binding_token: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ApprovalListParams {
    session_id: Option<String>,
    after: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalGetParams {
    id: String,
}

#[derive(Clone, Copy, Deserialize)]
enum Decision {
    #[serde(rename = "approve", alias = "allow-once")]
    Approve,
    #[serde(rename = "deny")]
    Deny,
}

impl RuntimeApprovalHandler {
    pub(super) fn new(broker: ApprovalBroker) -> Arc<Self> {
        Arc::new(Self { broker })
    }

    fn dispatch(&self, method: &str, params: Value) -> Result<Value, DispatchError> {
        let invalid = || DispatchError::InvalidParams {
            method: method.to_owned(),
            detail: "request does not match the native approval contract".to_owned(),
        };
        match method {
            "approval.resolve" | "exec.approval.resolve" => self.resolve(method, params),
            "approval.get" | "exec.approval.get" => {
                let params: ApprovalGetParams =
                    serde_json::from_value(params).map_err(|_| invalid())?;
                let id = ApprovalId::new(params.id).map_err(|_| invalid())?;
                let request = self
                    .broker
                    .outstanding()
                    .into_iter()
                    .find(|request| request.approval_id == id)
                    .ok_or_else(|| DispatchError::NotFound {
                        kind: "pending approval",
                        id: id.to_string(),
                    })?;
                let mut preview = approval_preview(&request).map_err(|_| invalid())?;
                if let Some((binding, token)) = self.broker.binding(&id) {
                    use sha2::Digest;
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    let authority = self.broker.authority(&id).ok_or_else(invalid)?;
                    let digest: String = sha2::Sha256::digest(request.arguments.as_bytes())
                        .iter()
                        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
                        .map(char::from)
                        .collect();
                    preview["bindingToken"] = json!(token);
                    preview["previewFingerprint"] = json!(
                        claw_security::authorization::approval_preview_fingerprint(&token)
                    );
                    preview["toolRevision"] = json!(binding.revision());
                    preview["toolPublication"] = json!(binding.identity());
                    let resource = binding.resource().unwrap_or("not declared by adapter");
                    preview["resourceScope"] = json!(resource);
                    preview["caller"] = json!({"source": format!("{:?}", authority.source()), "subject": authority.subject(), "account": authority.account(), "permissionGeneration": authority.generation(), "owner": authority.is_owner()});
                    let header =
                        claw_protocol::native_approval::bound_approval_context_header(&preview)
                            .ok_or_else(invalid)?;
                    let prompt = format!(
                        "{header}{}",
                        preview["prompt"].as_str().ok_or_else(invalid)?
                    );
                    if prompt.len() > MAX_APPROVAL_PREVIEW_BYTES {
                        return Err(invalid());
                    }
                    preview["prompt"] = json!(prompt);
                    if preview["redacted"] != true {
                        preview["argumentsSha256"] = json!(digest);
                    }
                }
                Ok(preview)
            }
            "exec.approval.list" => {
                let params: ApprovalListParams = if params.is_null() {
                    ApprovalListParams::default()
                } else {
                    serde_json::from_value(params).map_err(|_| invalid())?
                };
                let session = params
                    .session_id
                    .map(claw_domain::SessionId::new)
                    .transpose()
                    .map_err(|_| invalid())?;
                let after = params
                    .after
                    .map(ApprovalId::new)
                    .transpose()
                    .map_err(|_| invalid())?;
                let mut requests = self.broker.outstanding();
                requests.retain(|request| {
                    session
                        .as_ref()
                        .is_none_or(|session| request.session_id == *session)
                        && after
                            .as_ref()
                            .is_none_or(|after| request.approval_id > *after)
                });
                requests.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
                let next = (requests.len() > APPROVAL_PAGE_SIZE).then(|| {
                    requests[APPROVAL_PAGE_SIZE - 1]
                        .approval_id
                        .as_str()
                        .to_owned()
                });
                let page: Vec<Value> = requests
                    .iter()
                    .take(APPROVAL_PAGE_SIZE)
                    .map(approval_metadata)
                    .collect();
                Ok(json!({"requests": page, "nextCursor": next}))
            }
            _ => Err(invalid()),
        }
    }

    fn resolve(&self, method: &str, params: Value) -> Result<Value, DispatchError> {
        let invalid = || DispatchError::InvalidParams {
            method: method.to_owned(),
            detail: "expected a pending approval id and a once-scoped approve or deny decision"
                .to_owned(),
        };
        let params: DecisionParams = serde_json::from_value(params).map_err(|_| invalid())?;
        let id = ApprovalId::new(params.id).map_err(|_| invalid())?;
        let decision = match params.decision {
            Decision::Approve => ApprovalDecision::approve_once(),
            Decision::Deny => ApprovalDecision::deny_once(),
        };
        let resolved = params.binding_token.as_deref().map_or_else(
            || self.broker.resolve(&id, decision),
            |token| self.broker.resolve_bound(&id, decision, token),
        );
        resolved.map_err(|_| DispatchError::NotFound {
            kind: "pending approval",
            id: id.to_string(),
        })?;
        Ok(
            json!({"ok": true, "id": id.as_str(), "decision": decision.verdict.label(), "scope": "once"}),
        )
    }
}

impl MethodHandler for RuntimeApprovalHandler {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move { self.dispatch(context.method, params) })
    }
}

#[derive(Debug)]
pub(super) struct RuntimeHealthHandler {
    runtime: std::sync::Weak<AgentRuntime>,
    original: claw_gateway::MethodRegistry,
}

impl RuntimeHealthHandler {
    pub(super) fn new(
        runtime: &Arc<AgentRuntime>,
        original: claw_gateway::MethodRegistry,
    ) -> Arc<Self> {
        Arc::new(Self {
            runtime: Arc::downgrade(runtime),
            original,
        })
    }
}

impl MethodHandler for RuntimeHealthHandler {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let runtime = self
                .runtime
                .upgrade()
                .ok_or_else(|| DispatchError::NotFound {
                    kind: "runtime",
                    id: "stopped".to_owned(),
                })?;
            let mut health = self.original.dispatch(context, params).await?;
            health["native"] = runtime.native_capabilities();
            Ok(health)
        })
    }
}

#[derive(Debug)]
pub(super) struct RuntimeModelHandler {
    provider: Arc<super::http_api::SwappableProvider>,
    original: claw_gateway::MethodRegistry,
}

impl RuntimeModelHandler {
    pub(super) fn new(
        provider: Arc<super::http_api::SwappableProvider>,
        original: claw_gateway::MethodRegistry,
    ) -> Arc<Self> {
        Arc::new(Self { provider, original })
    }
}

impl MethodHandler for RuntimeModelHandler {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            if let Some(refresh) = params.get("nativeCatalogRefresh") {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Refresh {
                    sha256: String,
                }
                let invalid = || {
                    DispatchError::InvalidParams {method:context.method.to_owned(),detail:"catalogue refresh requires a pinned snapshot, write scope and no mixed operation".to_owned()}
                };
                if params.as_object().is_none_or(|fields| fields.len() != 1)
                    || !context.scopes.iter().any(|scope| {
                        matches!(
                            scope,
                            claw_protocol::gateway::OperatorScope::Write
                                | claw_protocol::gateway::OperatorScope::Admin
                        )
                    })
                {
                    return Err(invalid());
                }
                let refresh: Refresh =
                    serde_json::from_value(refresh.clone()).map_err(|_| invalid())?;
                return self
                    .provider
                    .refresh_catalogue(&refresh.sha256, tokio_util::sync::CancellationToken::new())
                    .await
                    .map_err(|error| runtime_dispatch_error(context.method, &error));
            }
            if let Some(page) = params.get("nativeCatalogPage") {
                if params.as_object().is_none_or(|fields| fields.len() != 1) {
                    return Err(DispatchError::InvalidParams {
                        method: context.method.to_owned(),
                        detail: "native catalogue request cannot mix operations".to_owned(),
                    });
                }
                self.provider
                    .catalogue_page(page)
                    .map_err(|error| runtime_dispatch_error(context.method, &error))
            } else {
                self.original.dispatch(context, params).await
            }
        })
    }
}

#[derive(Debug)]
pub(super) struct RuntimeSessionHandler {
    runtime: std::sync::Weak<AgentRuntime>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SendParams {
    #[serde(alias = "sessionId")]
    session_key: String,
    message: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SessionSendParams {
    #[serde(alias = "sessionKey", alias = "sessionId")]
    key: String,
    message: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DescribeParams {
    #[serde(alias = "id")]
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HistoryParams {
    #[serde(alias = "sessionId")]
    session_key: String,
    #[serde(default = "default_history_limit")]
    limit: u16,
}

const fn default_history_limit() -> u16 {
    256
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AbortParams {
    #[serde(alias = "sessionId")]
    session_key: String,
    run_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RunParams {
    run_id: String,
    #[serde(default)]
    timeout_ms: u64,
    acknowledge_revision: Option<u64>,
    partial_page: Option<RunPageParams>,
    accounting_page: Option<RunPageParams>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RunPageParams {
    revision: u64,
    offset: usize,
    sha256: Option<String>,
}

impl RunParams {
    fn decode(params: Value) -> Result<Self, ()> {
        let params: Self = serde_json::from_value(params).map_err(|_| ())?;
        if params.partial_page.is_some() && params.accounting_page.is_some() {
            return Err(());
        }
        for (page, limit) in [
            (
                params.partial_page.as_ref(),
                claw_runtime::stream::MAX_ASSEMBLED_BYTES,
            ),
            (
                params.accounting_page.as_ref(),
                claw_application::ports::provider::MAX_PROVIDER_ROUND_RECORDS,
            ),
        ] {
            if let Some(page) = page
                && (params.timeout_ms != 0
                    || params.acknowledge_revision.is_some()
                    || page.revision == 0
                    || page.offset > limit
                    || (page.offset > 0 && page.sha256.is_none())
                    || page.sha256.as_ref().is_some_and(|digest| {
                        digest.len() != 64
                            || !digest
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    }))
            {
                return Err(());
            }
        }
        Ok(params)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PendingResultParams {
    #[serde(alias = "sessionId")]
    session_key: String,
    after: Option<String>,
    active_after: Option<String>,
}

impl SendParams {
    fn decode(method: &str, params: Value) -> Result<Self, serde_json::Error> {
        if method == "sessions.send" {
            serde_json::from_value::<SessionSendParams>(params).map(|params| Self {
                session_key: params.key,
                message: params.message,
                idempotency_key: params.idempotency_key,
            })
        } else {
            serde_json::from_value(params)
        }
    }
}

impl RuntimeSessionHandler {
    pub(super) fn new(runtime: &Arc<AgentRuntime>) -> Arc<Self> {
        Arc::new(Self {
            runtime: Arc::downgrade(runtime),
        })
    }
}

impl MethodHandler for RuntimeSessionHandler {
    fn handle<'a>(&'a self, context: MethodContext<'a>, params: Value) -> MethodFuture<'a> {
        Box::pin(async move {
            let runtime = self
                .runtime
                .upgrade()
                .ok_or_else(|| DispatchError::NotFound {
                    kind: "runtime",
                    id: "stopped".to_owned(),
                })?;
            let invalid = || DispatchError::InvalidParams {
                method: context.method.to_owned(),
                detail: "request does not match the native session contract".to_owned(),
            };
            match context.method {
                "sessions.list" => {
                    if !params.is_null()
                        && !params.as_object().is_some_and(serde_json::Map::is_empty)
                    {
                        return Err(invalid());
                    }
                    runtime
                        .gateway_sessions(context.device_id)
                        .await
                        .map_err(|error| state_dispatch_error(context.method, &error))
                }
                "sessions.get" => {
                    let params: PendingResultParams =
                        serde_json::from_value(params).map_err(|_| invalid())?;
                    runtime
                        .gateway_pending_results(
                            context.device_id,
                            &params.session_key,
                            params.after.as_deref(),
                            params.active_after.as_deref(),
                        )
                        .await
                        .map_err(|error| state_dispatch_error(context.method, &error))
                }
                "sessions.describe" => {
                    let params: DescribeParams =
                        serde_json::from_value(params).map_err(|_| invalid())?;
                    runtime
                        .gateway_describe(context.device_id, &params.key)
                        .await
                        .map_err(|error| state_dispatch_error(context.method, &error))?
                        .ok_or(DispatchError::NotFound {
                            kind: "session",
                            id: params.key,
                        })
                }
                "agent.wait" => {
                    let params = RunParams::decode(params).map_err(|()| invalid())?;
                    if let Some(page) = params.accounting_page {
                        return runtime
                            .gateway_accounting_run(
                                context.device_id,
                                &params.run_id,
                                page.revision,
                                page.offset,
                                page.sha256.as_deref(),
                            )
                            .await
                            .map_err(|error| state_dispatch_error(context.method, &error))?
                            .ok_or(DispatchError::NotFound {
                                kind: "run",
                                id: params.run_id,
                            });
                    }
                    if let Some(page) = params.partial_page {
                        return runtime
                            .gateway_partial_run(
                                context.device_id,
                                &params.run_id,
                                page.revision,
                                page.offset,
                                page.sha256.as_deref(),
                            )
                            .await
                            .map_err(|error| state_dispatch_error(context.method, &error))?
                            .ok_or(DispatchError::NotFound {
                                kind: "run",
                                id: params.run_id,
                            });
                    }
                    runtime
                        .gateway_run(
                            context.device_id,
                            &params.run_id,
                            params.timeout_ms,
                            params.acknowledge_revision,
                        )
                        .await
                        .map_err(|error| state_dispatch_error(context.method, &error))?
                        .ok_or(DispatchError::NotFound {
                            kind: "run",
                            id: params.run_id,
                        })
                }
                "chat.send" | "sessions.send" => {
                    let params =
                        SendParams::decode(context.method, params).map_err(|_| invalid())?;
                    let authority = runtime
                        .gateway_authority(context.device_id, context.scopes)
                        .map_err(|error| runtime_dispatch_error(context.method, &error))?;
                    runtime
                        .gateway_submit(
                            authority,
                            &params.session_key,
                            &params.message,
                            &params.idempotency_key,
                            context.events.clone(),
                        )
                        .await
                        .map_err(|error| runtime_dispatch_error(context.method, &error))
                }
                "chat.history" => {
                    let params: HistoryParams =
                        serde_json::from_value(params).map_err(|_| invalid())?;
                    runtime
                        .gateway_history(context.device_id, &params.session_key, params.limit)
                        .await
                        .map_err(|error| runtime_dispatch_error(context.method, &error))
                }
                "chat.abort" => {
                    let params: AbortParams =
                        serde_json::from_value(params).map_err(|_| invalid())?;
                    runtime
                        .gateway_abort(
                            context.device_id,
                            &params.session_key,
                            params.run_id.as_deref(),
                        )
                        .await
                        .map_err(|error| runtime_dispatch_error(context.method, &error))
                }
                _ => Err(invalid()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future as _;
    use std::sync::Mutex;
    use std::task::{Context, Waker};
    use std::time::Duration;

    use claw_application::model::ids::{ToolCallId, TurnId};
    use claw_domain::SessionId;
    use claw_gateway::{ConnectionId, Delivery, TopicFilter};
    use claw_protocol::gateway::{OperatorScope, Role};
    use claw_runtime::approval::ApprovalTicket;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::adapters::agent_runtime::RuntimeClock;

    fn ticket() -> ApprovalTicket {
        ApprovalTicket {
            session_id: SessionId::new("approval-session").expect("session"),
            turn: TurnId::FIRST,
            call_id: ToolCallId::new("call").expect("call"),
            tool_name: "write-file".to_owned(),
            arguments: r#"{"path":"example.txt"}"#.to_owned(),
        }
    }

    #[test]
    fn native_accounting_page_requires_a_bound_read_without_other_operations() {
        let valid = json!({"runId":"owned-run","accountingPage":{"revision":3,"offset":0}});
        assert!(RunParams::decode(valid.clone()).is_ok());
        let mut next = valid.clone();
        next["accountingPage"]["offset"] = json!(16);
        assert!(RunParams::decode(next.clone()).is_err());
        next["accountingPage"]["sha256"] = json!("a".repeat(64));
        assert!(RunParams::decode(next).is_ok());
        for (field, value) in [
            ("revision", json!(0)),
            ("offset", json!(1025)),
            ("offset", json!(-1)),
            ("offset", json!(0.5)),
            ("sha256", json!("A".repeat(64))),
            ("includeContent", json!(true)),
        ] {
            let mut changed = valid.clone();
            changed["accountingPage"][field] = value;
            assert!(RunParams::decode(changed).is_err());
        }
        for (field, value) in [
            ("timeoutMs", json!(1)),
            ("acknowledgeRevision", json!(3)),
            ("partialPage", json!({"revision":3,"offset":0})),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(RunParams::decode(changed).is_err());
        }
    }

    #[test]
    fn native_partial_page_requires_revision_and_digest_without_ack_or_wait() {
        let valid = json!({"runId":"owned-run","partialPage":{"revision":3,"offset":0}});
        assert!(RunParams::decode(valid.clone()).is_ok());
        let mut next = valid.clone();
        next["partialPage"]["offset"] = json!(2048);
        assert!(RunParams::decode(next.clone()).is_err());
        next["partialPage"]["sha256"] = json!("a".repeat(64));
        assert!(RunParams::decode(next).is_ok());
        for (pointer, value) in [
            ("revision", json!(0)),
            ("offset", json!(-1)),
            ("offset", json!(1.5)),
            (
                "offset",
                json!(claw_runtime::stream::MAX_ASSEMBLED_BYTES + 1),
            ),
            ("sha256", json!("A".repeat(64))),
            ("includeReasoning", json!(true)),
        ] {
            let mut changed = valid.clone();
            changed["partialPage"][pointer] = value;
            assert!(RunParams::decode(changed).is_err());
        }
        for (field, value) in [("timeoutMs", json!(1)), ("acknowledgeRevision", json!(3))] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(RunParams::decode(changed).is_err());
        }
        assert!(
            RunParams::decode(json!({"runId":"owned-run","timeoutMs":0,"acknowledgeRevision":3}))
                .is_ok()
        );
    }

    #[test]
    fn native_description_requires_one_exact_key_and_refuses_unimplemented_options() {
        for field in ["key", "id"] {
            let mut parameters = json!({});
            parameters[field] = json!("session-one");
            assert_eq!(
                serde_json::from_value::<DescribeParams>(parameters)
                    .expect("one description key")
                    .key,
                "session-one"
            );
        }
        for parameters in [
            json!({"key":"session-one","id":"other"}),
            json!({"key":"session-one","includeLastMessage":true}),
            json!({"key":"session-one","agentId":"other"}),
            json!({"key":null}),
        ] {
            assert!(serde_json::from_value::<DescribeParams>(parameters).is_err());
        }
    }

    #[test]
    fn native_history_limit_preserves_default_and_rejects_ambiguous_input() {
        let default: HistoryParams =
            serde_json::from_value(json!({"sessionKey":"session-one"})).expect("default history");
        assert_eq!(default.limit, 256);
        let bounded: HistoryParams =
            serde_json::from_value(json!({"sessionKey":"session-one","limit":1}))
                .expect("bounded history");
        assert_eq!(bounded.limit, 1);
        for parameters in [
            json!({"sessionKey":"session-one","limit":null}),
            json!({"sessionKey":"session-one","limit":1.5}),
            json!({"sessionKey":"session-one","sessionId":"other","limit":1}),
            json!({"sessionKey":"session-one","limit":1,"cursor":"unsupported"}),
        ] {
            assert!(serde_json::from_value::<HistoryParams>(parameters).is_err());
        }
    }

    #[test]
    fn native_session_send_accepts_upstream_key_without_erasing_identity_conflicts() {
        for field in ["key", "sessionKey", "sessionId"] {
            let mut parameters = json!({"message":"content","idempotencyKey":"input-one"});
            parameters[field] = json!("session-one");
            let parsed = SendParams::decode("sessions.send", parameters).expect("session input");
            assert_eq!(parsed.session_key, "session-one");
            assert_eq!(parsed.message, "content");
            assert_eq!(parsed.idempotency_key, "input-one");
        }
        let accepted =
            json!({"key":"session-one","message":"content","idempotencyKey":"input-one"});
        assert!(SendParams::decode("chat.send", accepted.clone()).is_err());
        for (field, value) in [
            ("sessionKey", json!("session-one")),
            ("sessionId", json!("session-two")),
            ("agentId", json!("unsupported-agent")),
            ("expectedLeafEntryId", json!(null)),
        ] {
            let mut parameters = accepted.clone();
            parameters[field] = value;
            assert!(
                SendParams::decode("sessions.send", parameters).is_err(),
                "{field}"
            );
        }
        assert!(
            SendParams::decode(
                "sessions.send",
                json!({"key":"session-one","message":"content"})
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn unknown_state_commit_reaches_gateway_as_nonretryable_uncertainty() {
        let error = state_dispatch_error(
            "agent.wait",
            &PortError::OutcomeUnknown("internal storage detail".to_owned()),
        );
        assert_eq!(error.wire_code(), "OUTCOME_UNKNOWN");
        assert!(!error.retryable());
        assert!(!error.to_string().contains("internal storage detail"));
    }

    #[tokio::test]
    async fn unavailable_run_admission_never_becomes_a_safe_invalid_request() {
        let error = runtime_dispatch_error(
            "chat.send",
            &claw_http_api::PortError::new(
                claw_http_api::PortErrorKind::Unavailable,
                "unconfirmed write",
            ),
        );
        assert_eq!(error.wire_code(), "OUTCOME_UNKNOWN");
        assert!(!error.retryable());
        let rejected = runtime_dispatch_error(
            "chat.send",
            &claw_http_api::PortError::new(
                claw_http_api::PortErrorKind::InvalidRequest,
                "invalid input",
            ),
        );
        assert_eq!(rejected.wire_code(), "INVALID_REQUEST");
    }

    #[tokio::test]
    async fn gateway_bound_approval_requires_the_exact_preview_token() {
        use claw_application::ports::tool::{
            InvocationAccess, InvocationAuthority, InvocationSource, ToolBinding,
        };
        let port = Arc::new(GatewayApprovalPort::default());
        port.attach(EventBus::new(8, 1024 * 1024))
            .expect("transport");
        let first = port.binding_token().expect("random token");
        let second = port.binding_token().expect("independent token");
        assert_eq!(first.len(), 64);
        assert_ne!(first, second);
        let broker = ApprovalBroker::new(port, Arc::new(RuntimeClock), Duration::from_secs(30));
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "verified-device",
            None,
            InvocationAccess::Execute,
            9,
        )
        .expect("verified actor");
        let cancel = CancellationToken::new();
        let mut pending = Box::pin(
            broker.request_bound(
                ticket(),
                authority,
                ToolBinding::new("write-file", 4)
                    .expect("publication")
                    .with_resource("workspace: example.txt".to_owned())
                    .expect("resource"),
                &cancel,
            ),
        );
        assert!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let id = broker.outstanding()[0].approval_id.clone();
        let handler = RuntimeApprovalHandler::new(broker.clone());
        let preview = handler
            .dispatch("exec.approval.get", json!({"id": id.as_str()}))
            .expect("reviewed preview");
        assert_eq!(preview["caller"]["subject"], "verified-device");
        assert_eq!(preview["caller"]["permissionGeneration"], 9);
        assert_eq!(preview["toolRevision"], 4);
        assert_eq!(preview["toolPublication"], "write-file");
        let prompt = preview["prompt"]
            .as_str()
            .expect("complete displayed preview");
        for visible in [
            "Caller: Gateway / verified-device",
            "Access: execute",
            "Permission generation: 9",
            "Tool publication: write-file (revision 4)",
            "Resource: workspace: example.txt",
        ] {
            assert!(prompt.contains(visible), "missing {visible}");
        }
        assert!(
            preview["argumentsSha256"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64)
        );
        assert!(
            handler
                .resolve(
                    "approval.resolve",
                    json!({"id": id.as_str(), "decision": "approve"})
                )
                .is_err()
        );
        assert!(
            handler
                .resolve(
                    "approval.resolve",
                    json!({"id": id.as_str(), "decision": "approve", "bindingToken": first})
                )
                .is_err()
        );
        let decision = json!({"id": id.as_str(), "decision": "approve", "bindingToken": preview["bindingToken"]});
        assert!(
            handler
                .resolve("approval.resolve", decision.clone())
                .is_ok()
        );
        assert!(pending.await.expect("bound decision").is_approved());
        assert!(handler.resolve("approval.resolve", decision).is_err());
    }

    #[tokio::test]
    async fn gateway_approval_fails_closed_without_presentation_transport() {
        let port = Arc::new(GatewayApprovalPort::default());
        let broker = ApprovalBroker::new(port, Arc::new(RuntimeClock), Duration::from_secs(30));
        assert!(
            broker
                .request(ticket(), &CancellationToken::new())
                .await
                .is_err()
        );
        assert!(broker.outstanding().is_empty());
    }

    #[tokio::test]
    async fn gateway_approval_event_and_once_scoped_decision_share_the_runtime_broker() {
        let port = Arc::new(GatewayApprovalPort::default());
        let events = EventBus::new(8, 1024 * 1024);
        let mut subscriber = events.subscribe(
            ConnectionId::new(1),
            Role::Operator,
            vec![OperatorScope::Approvals],
            Arc::new(Mutex::new(TopicFilter::default())),
        );
        port.attach(events).expect("attach transport");
        let broker = ApprovalBroker::new(port, Arc::new(RuntimeClock), Duration::from_secs(30));
        let cancel = CancellationToken::new();
        let mut waiting = Box::pin(broker.request(ticket(), &cancel));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let Delivery::Event(requested) = subscriber.recv().await else {
            panic!("approval event missing")
        };
        assert_eq!(requested.name(), "exec.approval.requested");
        let id = broker.outstanding()[0].approval_id.clone();
        let handler = RuntimeApprovalHandler::new(broker.clone());
        let listed = handler
            .dispatch(
                "exec.approval.list",
                json!({"sessionId": "approval-session"}),
            )
            .expect("pending snapshot");
        assert_eq!(listed["requests"][0]["id"], id.as_str());
        assert!(listed["requests"][0].get("prompt").is_none());
        assert!(listed["nextCursor"].is_null());
        let preview = handler
            .dispatch("exec.approval.get", json!({"id": id.as_str()}))
            .expect("complete preview");
        assert_eq!(preview["previewComplete"], true);
        assert!(
            preview["prompt"]
                .as_str()
                .expect("prompt")
                .contains("example.txt")
        );
        for decision in ["allow-always", "", "unknown"] {
            assert!(
                handler
                    .resolve(
                        "approval.resolve",
                        json!({"id": id.as_str(), "decision": decision})
                    )
                    .is_err()
            );
        }
        assert!(
            handler
                .resolve(
                    "approval.resolve",
                    json!({"id": id.as_str(), "decision": "approve", "sender_is_owner": true})
                )
                .is_err()
        );
        assert!(
            handler
                .resolve(
                    "approval.resolve",
                    json!({"id": id.as_str(), "decision": "allow-once"})
                )
                .is_ok()
        );
        assert!(waiting.await.expect("approved request").is_approved());
        assert!(
            broker
                .remembered(
                    &SessionId::new("approval-session").expect("session"),
                    "write-file"
                )
                .is_none()
        );
        assert!(
            handler
                .resolve(
                    "approval.resolve",
                    json!({"id": id.as_str(), "decision": "approve"})
                )
                .is_err()
        );
        let Delivery::Event(resolved) = subscriber.recv().await else {
            panic!("resolved event missing")
        };
        assert_eq!(resolved.name(), "exec.approval.resolved");
        assert_eq!(
            handler
                .dispatch("exec.approval.list", json!({}))
                .expect("settled snapshot")["requests"],
            json!([])
        );
        assert!(
            handler
                .dispatch("exec.approval.get", json!({"id": id.as_str()}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn gateway_approval_redacts_structured_secrets_and_rejects_incomplete_previews() {
        let port = Arc::new(GatewayApprovalPort::default());
        port.attach(EventBus::new(8, 1024 * 1024))
            .expect("transport");
        let broker = ApprovalBroker::new(port, Arc::new(RuntimeClock), Duration::from_secs(30));
        let cancel = CancellationToken::new();
        let mut secret_ticket = ticket();
        secret_ticket.arguments = json!({"path": "example.txt", "nested": [{"apiKey": "fixture-secret", "authorization": "Bearer fixture"}]}).to_string();
        let mut waiting = Box::pin(broker.request(secret_ticket, &cancel));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let pending = broker.outstanding();
        let preview = approval_preview(&pending[0]).expect("redacted preview");
        let encoded = preview.to_string();
        assert!(encoded.contains(REDACTED));
        assert!(!encoded.contains("fixture-secret"));
        assert!(!encoded.contains("Bearer fixture"));
        assert_eq!(preview["redacted"], true);
        assert_eq!(preview["previewComplete"], true);
        assert!(approval_metadata(&pending[0]).get("prompt").is_none());
        drop(waiting);
        let mut oversized = ticket();
        oversized.arguments =
            json!({"content": "x".repeat(MAX_APPROVAL_ARGUMENT_BYTES)}).to_string();
        assert!(broker.request(oversized, &cancel).await.is_err());
        let mut malformed = ticket();
        malformed.arguments = "not json".to_owned();
        assert!(broker.request(malformed, &cancel).await.is_err());
        assert!(broker.outstanding().is_empty());
    }
}

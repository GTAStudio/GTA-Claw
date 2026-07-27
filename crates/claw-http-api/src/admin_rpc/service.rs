//! Bounded dispatch for `POST /api/v1/admin/rpc`.
//!
//! The service owns the ordering of the surface's gates and nothing else:
//! authentication is injected through [`AdminRpcAuthenticator`], the method
//! gates live in [`AdminMethodPolicy`], the scope decision belongs to
//! `claw-security`, and every refusal is one class of [`AdminRpcError`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use claw_security::audit::{AuditEvent, AuditSink};
use claw_security::authorization::{AuthorizationRequest, authorize_audited};
use serde_json::{Value, json};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::admin_rpc::caller::{AdminRpcAuthenticator, DenyAllAuthenticator};
use crate::admin_rpc::error::{AdminRpcError, admin_rpc_response};
use crate::admin_rpc::policy::AdminMethodPolicy;
use crate::error::ApiError;
use crate::http_support::{CancelOnDrop, read_json_value, rejected_response};
use crate::ports::{AdminFailure, AdminPort, AdminSuccess, AuditPort, PortError};

/// The frozen path this surface is mounted at.
pub const ADMIN_RPC_PATH: &str = "/api/v1/admin/rpc";

/// The self-describing method that enumerates the allowlist without dispatching.
const COMMANDS_LIST_METHOD: &str = "commands.list";

/// Bounds applied to one Admin HTTP RPC call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminRpcLimits {
    /// Maximum accepted request body size in bytes.
    pub body_bytes: usize,
    /// Deadline for receiving the whole request body.
    pub body_timeout: Duration,
    /// Deadline for the dispatched Gateway method.
    pub dispatch_timeout: Duration,
}

impl Default for AdminRpcLimits {
    fn default() -> Self {
        Self {
            body_bytes: 1024 * 1024,
            body_timeout: Duration::from_secs(30),
            dispatch_timeout: Duration::from_secs(120),
        }
    }
}

struct ServiceInner {
    authenticator: Arc<dyn AdminRpcAuthenticator>,
    policy: AdminMethodPolicy,
    admin: Arc<dyn AdminPort>,
    audit: Arc<dyn AuditPort>,
    limits: AdminRpcLimits,
    next_id: AtomicU64,
}

/// The Admin HTTP RPC dispatch surface.
#[derive(Clone)]
pub struct AdminRpcService {
    inner: Arc<ServiceInner>,
}

impl AdminRpcService {
    /// Builds a service that denies every request until an authenticator is attached.
    #[must_use]
    pub fn new(admin: Arc<dyn AdminPort>, audit: Arc<dyn AuditPort>) -> Self {
        Self {
            inner: Arc::new(ServiceInner {
                authenticator: Arc::new(DenyAllAuthenticator),
                policy: AdminMethodPolicy::frozen(),
                admin,
                audit,
                limits: AdminRpcLimits::default(),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    /// Attaches the authentication implementation for this surface.
    #[must_use]
    pub fn with_authenticator(self, authenticator: Arc<dyn AdminRpcAuthenticator>) -> Self {
        self.rebuild(|inner| ServiceInner {
            authenticator,
            ..inner
        })
    }

    /// Replaces the method policy.
    #[must_use]
    pub fn with_policy(self, policy: AdminMethodPolicy) -> Self {
        self.rebuild(|inner| ServiceInner { policy, ..inner })
    }

    /// Replaces the request bounds.
    #[must_use]
    pub fn with_limits(self, limits: AdminRpcLimits) -> Self {
        self.rebuild(|inner| ServiceInner { limits, ..inner })
    }

    /// Returns the method policy in force.
    #[must_use]
    pub fn policy(&self) -> &AdminMethodPolicy {
        &self.inner.policy
    }

    /// Returns the bounds in force.
    #[must_use]
    pub fn limits(&self) -> &AdminRpcLimits {
        &self.inner.limits
    }

    /// Returns a router mounting `POST /api/v1/admin/rpc` on this service.
    pub fn router(&self) -> Router {
        Router::new()
            .route(ADMIN_RPC_PATH, post(dispatch_route))
            .with_state(self.clone())
    }

    fn rebuild(self, edit: impl FnOnce(ServiceInner) -> ServiceInner) -> Self {
        let inner = Arc::try_unwrap(self.inner).unwrap_or_else(|shared| ServiceInner {
            authenticator: shared.authenticator.clone(),
            policy: shared.policy.clone(),
            admin: shared.admin.clone(),
            audit: shared.audit.clone(),
            limits: shared.limits.clone(),
            next_id: AtomicU64::new(shared.next_id.load(Ordering::Relaxed)),
        });
        Self {
            inner: Arc::new(edit(inner)),
        }
    }

    /// Handles one request end to end, independently of any router.
    pub async fn handle(&self, request: Request) -> Response {
        let caller = match self.inner.authenticator.authenticate(request.headers()) {
            Ok(caller) => caller,
            Err(_) => {
                let rejection = AdminRpcError::Unauthenticated.to_response("");
                return rejected_response(
                    request,
                    self.inner.limits.body_bytes,
                    self.inner.limits.body_timeout,
                    rejection,
                )
                .await;
            }
        };
        let value = match read_json_value(
            request,
            self.inner.limits.body_bytes,
            self.inner.limits.body_timeout,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => return body_error(&error).to_response(""),
        };
        let Some(object) = value.as_object() else {
            return AdminRpcError::MalformedRequest {
                message: "request body must be an object".to_owned(),
            }
            .to_response("");
        };
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map_or_else(|| self.next_id(), str::to_owned);
        let Some(method) = object
            .get("method")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|method| !method.is_empty())
            .map(str::to_owned)
        else {
            return AdminRpcError::MalformedRequest {
                message: "method must be a non-empty string".to_owned(),
            }
            .to_response("");
        };
        let required = match self.inner.policy.required_scope(&method) {
            Ok(required) => required,
            Err(error) => return error.to_response(&id),
        };
        let mut sink = AuditAdapter(self.inner.audit.as_ref());
        let decision = authorize_audited(
            AuthorizationRequest {
                authenticated: true,
                role: caller.role(),
                granted_scopes: caller.scopes(),
                required_scope: required,
                approved: true,
            },
            unix_millis(),
            &mut sink,
        );
        match decision {
            Err(_) => return AdminRpcError::AuthorizationUnavailable.to_response(&id),
            Ok(decision) if !decision.granted => {
                return AdminRpcError::Forbidden(required).to_response(&id);
            }
            Ok(_) => {}
        }
        if method == COMMANDS_LIST_METHOD {
            return admin_rpc_response(
                StatusCode::OK,
                json!({"id":id,"ok":true,"payload":{"methods":self.inner.policy.methods()}}),
            );
        }
        let params = object.get("params").cloned();
        let cancellation = CancellationToken::new();
        let _cancel_on_drop = CancelOnDrop::new(&cancellation);
        let dispatched = timeout(
            self.inner.limits.dispatch_timeout,
            self.inner.admin.dispatch(method, params, cancellation),
        )
        .await;
        match dispatched {
            Err(_) => AdminRpcError::DispatchTimeout.to_response(&id),
            Ok(Ok(success)) => success_response(&id, success),
            Ok(Err(failure)) => dispatch_failure_response(&id, failure),
        }
    }

    fn next_id(&self) -> String {
        let sequence = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        format!("rpc_{sequence:016x}")
    }
}

async fn dispatch_route(State(service): State<AdminRpcService>, request: Request) -> Response {
    service.handle(request).await
}

fn success_response(id: &str, success: AdminSuccess) -> Response {
    let mut body = json!({"id":id,"ok":true,"payload":success.payload});
    if let Some(meta) = success.meta {
        body["meta"] = meta;
    }
    admin_rpc_response(StatusCode::OK, body)
}

fn dispatch_failure_response(id: &str, failure: AdminFailure) -> Response {
    AdminRpcError::Dispatch(failure).to_response(id)
}

fn body_error(error: &ApiError) -> AdminRpcError {
    match error.status {
        StatusCode::PAYLOAD_TOO_LARGE => AdminRpcError::BodyTooLarge,
        StatusCode::REQUEST_TIMEOUT => AdminRpcError::BodyTimeout,
        _ => AdminRpcError::MalformedRequest {
            message: "request body must be valid JSON".to_owned(),
        },
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

struct AuditAdapter<'a>(&'a dyn AuditPort);

impl AuditSink for AuditAdapter<'_> {
    type Error = PortError;

    fn persist(&mut self, event: &AuditEvent) -> Result<(), Self::Error> {
        self.0.persist(event)
    }
}

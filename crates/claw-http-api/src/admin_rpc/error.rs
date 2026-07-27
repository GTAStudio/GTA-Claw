//! The complete Admin HTTP RPC failure taxonomy and its HTTP mapping.
//!
//! Every way this surface can refuse or fail a request is one variant of
//! [`AdminRpcError`], and every variant names its own status. Nothing collapses
//! into a catch-all `500`: only a Gateway failure whose stable code is outside
//! the frozen mapping is reported as an internal error, and that is the
//! deliberate fail-closed default rather than the common case.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use claw_security::authorization::Scope;
use serde_json::{Value, json};

use crate::http_support::json_response;
use crate::ports::AdminFailure;

/// The two response envelopes the Admin HTTP RPC surface emits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminRpcEnvelope {
    /// `{"ok":false,"error":{"type":..,"message":..}}`.
    ///
    /// Used for failures decided before the request could yield an RPC `id`,
    /// which is every transport, authentication and authorization refusal.
    Transport,
    /// `{"id":..,"ok":false,"error":{"code":..,"message":..}}`.
    ///
    /// Used once the request is well formed enough to carry or be assigned an
    /// `id`, so a client can correlate the failure with the call it made.
    Rpc,
}

/// Every distinct Admin HTTP RPC failure class.
#[derive(Clone, Debug, PartialEq)]
pub enum AdminRpcError {
    /// No verified admin caller was produced for the request.
    Unauthenticated,
    /// The caller authenticated but lacks the operator scope the method needs.
    Forbidden(Scope),
    /// The authorization decision could not be durably audited, so it was not made.
    AuthorizationUnavailable,
    /// The method is not on the Admin HTTP RPC allowlist.
    ///
    /// This is the fail-closed default: an unknown or newly added Gateway
    /// method lands here until it is explicitly allowlisted.
    MethodNotAllowlisted {
        /// The exact method identity the caller asked for.
        method: String,
    },
    /// The method is allowlisted but the frozen Gateway registry does not define it.
    MethodNotRegistered {
        /// The exact method identity the caller asked for.
        method: String,
    },
    /// The method exists but is not reachable from the trusted operator surface.
    MethodNotOperatorSurface {
        /// The exact method identity the caller asked for.
        method: String,
    },
    /// The request body is not a JSON object carrying a usable `method`.
    MalformedRequest {
        /// A safe, caller-facing explanation.
        message: String,
    },
    /// The request body exceeded the configured byte budget.
    BodyTooLarge,
    /// The request body was not fully received before its deadline.
    BodyTimeout,
    /// The dispatched method exceeded its deadline inside this process.
    DispatchTimeout,
    /// The Gateway itself rejected the dispatch.
    Dispatch(AdminFailure),
}

impl AdminRpcError {
    /// Returns the HTTP status this class maps to.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) | Self::MethodNotOperatorSurface { .. } => StatusCode::FORBIDDEN,
            Self::AuthorizationUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::MethodNotAllowlisted { .. }
            | Self::MethodNotRegistered { .. }
            | Self::MalformedRequest { .. } => StatusCode::BAD_REQUEST,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::DispatchTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Dispatch(failure) => dispatch_status(&failure.code),
        }
    }

    /// Returns the envelope this class is rendered into.
    #[must_use]
    pub const fn envelope(&self) -> AdminRpcEnvelope {
        match self {
            Self::Unauthenticated
            | Self::Forbidden(_)
            | Self::AuthorizationUnavailable
            | Self::MethodNotOperatorSurface { .. }
            | Self::MethodNotRegistered { .. }
            | Self::MalformedRequest { .. }
            | Self::BodyTooLarge
            | Self::BodyTimeout => AdminRpcEnvelope::Transport,
            Self::MethodNotAllowlisted { .. } | Self::DispatchTimeout | Self::Dispatch(_) => {
                AdminRpcEnvelope::Rpc
            }
        }
    }

    /// Returns the stable machine-readable code carried by the response body.
    ///
    /// Transport-envelope classes carry a lowercase `error.type`; RPC-envelope
    /// classes carry an upper-snake Gateway `error.code`.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Unauthenticated => "unauthorized",
            Self::Forbidden(_) | Self::MethodNotOperatorSurface { .. } => "forbidden",
            Self::AuthorizationUnavailable => "unavailable",
            Self::MethodNotRegistered { .. }
            | Self::MalformedRequest { .. }
            | Self::BodyTooLarge
            | Self::BodyTimeout => "invalid_request",
            Self::MethodNotAllowlisted { .. } => "INVALID_REQUEST",
            Self::DispatchTimeout => "AGENT_TIMEOUT",
            Self::Dispatch(failure) => &failure.code,
        }
    }

    /// Returns the safe caller-facing message carried by the response body.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Unauthenticated => "Unauthorized".to_owned(),
            Self::Forbidden(scope) => format!("missing scope: {}", scope.as_str()),
            Self::AuthorizationUnavailable => "authorization is unavailable".to_owned(),
            Self::MethodNotAllowlisted { method } => {
                format!("admin HTTP RPC method is not supported: {method}")
            }
            Self::MethodNotRegistered { .. } => {
                "method is not in the frozen Gateway registry".to_owned()
            }
            Self::MethodNotOperatorSurface { .. } => {
                "method is not available to the trusted operator surface".to_owned()
            }
            Self::MalformedRequest { message } => message.clone(),
            Self::BodyTooLarge => "Payload too large".to_owned(),
            Self::BodyTimeout => "request body timed out".to_owned(),
            Self::DispatchTimeout => "gateway method timed out".to_owned(),
            Self::Dispatch(failure) => failure.message.clone(),
        }
    }

    /// Renders the failure, correlating it with `id` when the envelope carries one.
    #[must_use]
    pub fn to_response(&self, id: &str) -> Response {
        let body = match self.envelope() {
            AdminRpcEnvelope::Transport => {
                json!({"ok":false,"error":{"type":self.code(),"message":self.message()}})
            }
            AdminRpcEnvelope::Rpc => {
                json!({"id":id,"ok":false,"error":self.rpc_error_object()})
            }
        };
        let mut response = admin_rpc_response(self.status(), body);
        if matches!(self, Self::Unauthenticated) {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"admin\""),
            );
        }
        response
    }

    fn rpc_error_object(&self) -> Value {
        let mut error = json!({"code":self.code(),"message":self.message()});
        if let Self::Dispatch(failure) = self {
            if let Some(details) = failure.details.clone() {
                error["details"] = details;
            }
            if let Some(retryable) = failure.retryable {
                error["retryable"] = json!(retryable);
            }
            if let Some(retry_after_ms) = failure.retry_after_ms {
                error["retryAfterMs"] = json!(retry_after_ms);
            }
        }
        if matches!(self, Self::DispatchTimeout) {
            error["retryable"] = json!(true);
        }
        error
    }
}

/// Maps a stable Gateway failure code onto its HTTP status.
///
/// The mapping is exhaustive over the codes the Gateway is known to emit;
/// anything outside it is an internal error, which is the only case that
/// legitimately produces a `500`.
#[must_use]
pub fn dispatch_status(code: &str) -> StatusCode {
    match code {
        "INVALID_REQUEST" => StatusCode::BAD_REQUEST,
        "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
        "FORBIDDEN" => StatusCode::FORBIDDEN,
        "APPROVAL_NOT_FOUND" | "NOT_FOUND" => StatusCode::NOT_FOUND,
        "NOT_LINKED" | "NOT_PAIRED" => StatusCode::CONFLICT,
        "RATE_LIMITED" => StatusCode::TOO_MANY_REQUESTS,
        "UNAVAILABLE" => StatusCode::SERVICE_UNAVAILABLE,
        "AGENT_TIMEOUT" => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Renders an Admin HTTP RPC body with the headers the surface always sets.
pub(crate) fn admin_rpc_response(status: StatusCode, body: Value) -> Response {
    let mut response = json_response(status, body);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

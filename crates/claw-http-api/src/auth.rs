//! Bearer authentication and claw-security authorization integration.

use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use claw_security::audit::{AuditEvent, AuditSink};
use claw_security::authorization::{
    AuthorizationRequest, Role, Scope, ScopeSet, authorize_audited,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::HttpLimits;
use crate::error::ApiError;
use crate::http_support::rejected_response;
use crate::ports::{AuditPort, PortError};

/// Authenticated HTTP principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Principal {
    /// Closed Gateway role.
    pub role: Role,
    /// Closed granted operator scopes.
    pub scopes: ScopeSet,
    pub(crate) subject: [u8; 32],
}

/// One pre-hashed bearer credential.
#[derive(Clone)]
pub struct BearerCredential {
    digest: [u8; 32],
    principal: Principal,
}

impl BearerCredential {
    /// Creates a bearer credential without retaining the plaintext token.
    #[must_use]
    pub fn new(token: &str, role: Role, scopes: ScopeSet) -> Self {
        let digest = Sha256::digest(token.as_bytes()).into();
        Self {
            digest,
            principal: Principal {
                role,
                scopes,
                subject: digest,
            },
        }
    }
}

impl Debug for BearerCredential {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BearerCredential")
            .field("digest", &"[REDACTED]")
            .field("principal", &self.principal)
            .finish()
    }
}

/// Immutable bearer authenticator shared by middleware and special routes.
#[derive(Clone, Debug, Default)]
pub struct BearerAuthenticator {
    credentials: Arc<[BearerCredential]>,
}

impl BearerAuthenticator {
    /// Creates an authenticator from a bounded credential set.
    #[must_use]
    pub fn new(credentials: Vec<BearerCredential>) -> Self {
        Self {
            credentials: credentials.into(),
        }
    }

    /// Authenticates an exact bearer token using constant-time digest comparison.
    #[must_use]
    pub fn authenticate_token(&self, token: &str) -> Option<Principal> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut matched = None;
        for credential in self.credentials.iter() {
            if bool::from(credential.digest.ct_eq(&digest)) {
                matched = Some(credential.principal);
            }
        }
        matched
    }

    /// Authenticates an Authorization header.
    #[must_use]
    pub fn authenticate_headers(&self, headers: &HeaderMap) -> Option<Principal> {
        bearer_token(headers).and_then(|token| self.authenticate_token(token))
    }
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.trim().is_empty() {
        return None;
    }
    Some(token.trim())
}

/// State consumed by the protected-route authentication middleware.
#[derive(Clone)]
pub(crate) struct AuthMiddlewareState {
    pub(crate) authenticator: BearerAuthenticator,
    pub(crate) limits: HttpLimits,
}

impl AuthMiddlewareState {
    fn body_limit(&self, path: &str) -> usize {
        match path {
            "/v1/embeddings" => self.limits.embeddings_body_bytes,
            "/tools/invoke" => self.limits.tools_body_bytes,
            "/api/v1/admin/rpc" => self.limits.admin_body_bytes,
            _ => self.limits.openai_body_bytes,
        }
    }
}

pub(crate) async fn require_bearer(
    State(state): State<AuthMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(principal) = state.authenticator.authenticate_headers(request.headers()) else {
        let body_limit = state.body_limit(request.uri().path());
        return rejected_response(
            request,
            body_limit,
            state.limits.body_timeout,
            ApiError::openai(StatusCode::UNAUTHORIZED, "Unauthorized", "unauthorized"),
        )
        .await;
    };
    request.extensions_mut().insert(principal);
    next.run(request).await
}

struct AuditAdapter<'a>(&'a dyn AuditPort);

impl AuditSink for AuditAdapter<'_> {
    type Error = PortError;

    fn persist(&mut self, event: &AuditEvent) -> Result<(), Self::Error> {
        self.0.persist(event)
    }
}

pub(crate) fn authorize_scope(
    principal: Principal,
    required_scope: Scope,
    audit: &dyn AuditPort,
) -> Result<(), ApiError> {
    let mut adapter = AuditAdapter(audit);
    let unix_millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    let decision = authorize_audited(
        AuthorizationRequest {
            authenticated: true,
            role: principal.role,
            granted_scopes: principal.scopes,
            required_scope,
            approved: true,
        },
        unix_millis,
        &mut adapter,
    )
    .map_err(|_| {
        ApiError::openai(
            StatusCode::SERVICE_UNAVAILABLE,
            "internal error",
            "api_error",
        )
    })?;
    if decision.granted {
        Ok(())
    } else {
        Err(ApiError::forbidden(required_scope.as_str()))
    }
}

pub(crate) const fn protocol_scope_to_security(
    scope: claw_protocol::gateway::OperatorScope,
) -> Scope {
    use claw_protocol::gateway::OperatorScope as ProtocolScope;
    match scope {
        ProtocolScope::Admin => Scope::OperatorAdmin,
        ProtocolScope::Read => Scope::OperatorRead,
        ProtocolScope::Write => Scope::OperatorWrite,
        ProtocolScope::Approvals => Scope::OperatorApprovals,
        ProtocolScope::Pairing => Scope::OperatorPairing,
        ProtocolScope::TalkSecrets => Scope::OperatorTalkSecrets,
    }
}

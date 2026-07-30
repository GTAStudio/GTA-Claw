//! Shared immutable API state and monotonic identifiers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;

use crate::config::ApiConfig;
use crate::error::ApiError;
use crate::lifecycle::ServingStatePort;
use crate::ports::ApiServices;
use crate::watch::WatchRuntime;
use crate::{AdminRpcLimits, AdminRpcService, BearerAdminRpcAuthenticator};

const RESPONSE_SESSION_TTL: Duration = Duration::from_mins(30);
const MAX_RESPONSE_SESSIONS: usize = 500;

#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) inner: Arc<ApiStateInner>,
}

pub(crate) struct ApiStateInner {
    pub(crate) config: ApiConfig,
    pub(crate) services: ApiServices,
    pub(crate) watch: WatchRuntime,
    pub(crate) admin_rpc: AdminRpcService,
    pub(crate) serving: Arc<dyn ServingStatePort>,
    response_sessions: Mutex<HashMap<String, ResponseSession>>,
    next_id: AtomicU64,
}

#[derive(Clone)]
struct ResponseSession {
    subject: [u8; 32],
    model: String,
    session_id: String,
    created: Instant,
}

impl ApiState {
    pub(crate) fn with_serving_state(
        config: ApiConfig,
        services: ApiServices,
        serving: Arc<dyn ServingStatePort>,
    ) -> Self {
        let watch = WatchRuntime::new(config.limits.clone(), services.watch_results.clone());
        let admin_rpc = AdminRpcService::new(services.admin.clone(), services.audit.clone())
            .with_authenticator(Arc::new(BearerAdminRpcAuthenticator::new(
                config.authenticator.clone(),
            )))
            .with_limits(AdminRpcLimits {
                body_bytes: config.limits.admin_body_bytes,
                body_timeout: config.limits.body_timeout,
                dispatch_timeout: config.limits.operation_timeout,
            });
        Self {
            inner: Arc::new(ApiStateInner {
                config,
                services,
                watch,
                admin_rpc,
                serving,
                response_sessions: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(1),
            }),
        }
    }

    pub(crate) fn id(&self, prefix: &str) -> String {
        let sequence = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        format!("{prefix}_{nanos:032x}{sequence:016x}")
    }

    pub(crate) async fn resolve_response_session(
        &self,
        previous_response_id: Option<&str>,
        subject: [u8; 32],
        model: &str,
    ) -> Result<(String, u64), ApiError> {
        if self.inner.services.provider.owns_response_continuity() {
            let resolved = self
                .inner
                .services
                .provider
                .resolve_response_session(
                    previous_response_id.map(str::to_owned),
                    subject,
                    model.to_owned(),
                )
                .await
                .map_err(|_| response_session_error())?;
            return Ok((
                resolved
                    .session_id
                    .unwrap_or_else(|| self.id("response_session")),
                resolved.epoch,
            ));
        }
        let now = Instant::now();
        let mut sessions = self
            .inner
            .response_sessions
            .lock()
            .map_err(|_| response_session_error())?;
        sessions.retain(|_, entry| now.duration_since(entry.created) < RESPONSE_SESSION_TTL);
        let resumed = previous_response_id
            .and_then(|previous_response_id| sessions.get(previous_response_id))
            .filter(|entry| entry.subject == subject && entry.model == model)
            .map(|entry| entry.session_id.clone());
        drop(sessions);
        Ok((resumed.unwrap_or_else(|| self.id("response_session")), 0))
    }

    pub(crate) async fn remember_response_session(
        &self,
        response_id: String,
        subject: [u8; 32],
        model: String,
        session_id: String,
        epoch: u64,
    ) -> Result<(), ApiError> {
        if self.inner.services.provider.owns_response_continuity() {
            return self
                .inner
                .services
                .provider
                .remember_response_session(response_id, subject, model, session_id, epoch)
                .await
                .map_err(|_| response_session_error());
        }
        let mut sessions = self
            .inner
            .response_sessions
            .lock()
            .map_err(|_| response_session_error())?;
        if sessions.len() >= MAX_RESPONSE_SESSIONS
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, entry)| entry.created)
                .map(|(id, _)| id.clone())
        {
            sessions.remove(&oldest);
        }
        sessions.insert(
            response_id,
            ResponseSession {
                subject,
                model,
                session_id,
                created: Instant::now(),
            },
        );
        drop(sessions);
        Ok(())
    }
}

/// Wall-clock seconds since the Unix epoch, clamped to `0` before it.
///
/// Every OpenAI-compatible `created`/`created_at` field is rendered from this,
/// so a host whose clock predates the epoch reports `0` rather than failing the
/// request.
pub(crate) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn response_session_error() -> ApiError {
    ApiError::openai(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error",
        "api_error",
    )
}

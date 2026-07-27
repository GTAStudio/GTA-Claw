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

const RESPONSE_SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_RESPONSE_SESSIONS: usize = 500;

#[derive(Clone)]
pub(crate) struct ApiState {
    pub(crate) inner: Arc<ApiStateInner>,
}

pub(crate) struct ApiStateInner {
    pub(crate) config: ApiConfig,
    pub(crate) services: ApiServices,
    pub(crate) watch: WatchRuntime,
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
        Self {
            inner: Arc::new(ApiStateInner {
                config,
                services,
                watch,
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

    pub(crate) fn unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }

    pub(crate) fn resolve_response_session(
        &self,
        previous_response_id: Option<&str>,
        subject: [u8; 32],
        model: &str,
    ) -> Result<String, ApiError> {
        let now = Instant::now();
        let mut sessions = self
            .inner
            .response_sessions
            .lock()
            .map_err(|_| response_session_error())?;
        sessions.retain(|_, entry| now.duration_since(entry.created) < RESPONSE_SESSION_TTL);
        if let Some(previous_response_id) = previous_response_id
            && let Some(entry) = sessions.get(previous_response_id)
            && entry.subject == subject
            && entry.model == model
        {
            return Ok(entry.session_id.clone());
        }
        drop(sessions);
        Ok(self.id("session"))
    }

    pub(crate) fn remember_response_session(
        &self,
        response_id: String,
        subject: [u8; 32],
        model: String,
        session_id: String,
    ) -> Result<(), ApiError> {
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
        Ok(())
    }
}

fn response_session_error() -> ApiError {
    ApiError::openai(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error",
        "api_error",
    )
}

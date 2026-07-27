//! Concrete legacy chat/session adapter over [`crate::ProviderPort`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use super::ports::{
    LegacyChannelMessage, LegacyChannelMessagePort, LegacyRuntimePort, LegacyRuntimeSnapshot,
};
use crate::{
    ClientTool, GenerationRequest, InputMedia, PortError, PortErrorKind, PortFuture, ProviderPort,
    ToolChoice,
};

/// Session bounds for [`ProviderLegacyRuntime`].
#[derive(Clone, Debug)]
pub struct ProviderLegacyRuntimeConfig {
    /// Model identifier supplied to provider generations.
    pub model: String,
    /// Number of loaded skills reported by legacy health.
    pub skill_count: usize,
    /// Maximum retained conversation identities.
    pub max_sessions: usize,
    /// Inactive conversation retention.
    pub session_idle_timeout: Duration,
}

impl Default for ProviderLegacyRuntimeConfig {
    fn default() -> Self {
        Self {
            model: "openclaw".to_owned(),
            skill_count: 0,
            max_sessions: 500,
            session_idle_timeout: Duration::from_mins(30),
        }
    }
}

/// Provider-backed implementation of legacy chat and channel-message ports.
pub struct ProviderLegacyRuntime {
    provider: Arc<dyn ProviderPort>,
    model: String,
    skill_count: AtomicUsize,
    authenticated: AtomicBool,
    max_sessions: usize,
    session_idle_timeout: Duration,
    sessions: Mutex<HashMap<String, Instant>>,
    next_request_id: AtomicU64,
}

impl ProviderLegacyRuntime {
    /// Creates a provider-backed adapter.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::InvalidRequest`] when the model is empty or the
    /// session capacity is zero.
    pub fn new(
        provider: Arc<dyn ProviderPort>,
        config: ProviderLegacyRuntimeConfig,
    ) -> Result<Arc<Self>, PortError> {
        let ProviderLegacyRuntimeConfig {
            model,
            skill_count,
            max_sessions,
            session_idle_timeout,
        } = config;
        let model = model.trim();
        if model.is_empty() || max_sessions == 0 {
            return Err(PortError::new(
                PortErrorKind::InvalidRequest,
                "legacy provider runtime configuration is invalid",
            ));
        }
        Ok(Arc::new(Self {
            provider,
            model: model.to_owned(),
            skill_count: AtomicUsize::new(skill_count),
            authenticated: AtomicBool::new(true),
            max_sessions,
            session_idle_timeout,
            sessions: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1),
        }))
    }

    /// Changes the authentication status exposed by the facade.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Internal`] when clearing sessions after logout
    /// cannot acquire the session state.
    pub fn set_authenticated(&self, authenticated: bool) -> Result<(), PortError> {
        if !authenticated {
            self.sessions
                .lock()
                .map_err(|_| PortError::new(PortErrorKind::Internal, "session state unavailable"))?
                .clear();
        }
        self.authenticated.store(authenticated, Ordering::Release);
        Ok(())
    }

    /// Changes the loaded-skill count exposed by the facade.
    pub fn set_skill_count(&self, skill_count: usize) {
        self.skill_count.store(skill_count, Ordering::Release);
    }

    /// Clears every retained conversation identity.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Internal`] if the session state was poisoned.
    pub fn clear_sessions(&self) -> Result<(), PortError> {
        self.sessions
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "session state unavailable"))?
            .clear();
        Ok(())
    }

    fn touch_session(&self, conversation_id: &str) -> Result<(), PortError> {
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "session state unavailable"))?;
        sessions.retain(|_, seen| now.duration_since(*seen) < self.session_idle_timeout);
        if !sessions.contains_key(conversation_id)
            && sessions.len() >= self.max_sessions
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(id, _)| id.clone())
        {
            sessions.remove(&oldest);
        }
        sessions.insert(conversation_id.to_owned(), now);
        drop(sessions);
        Ok(())
    }

    fn generation(&self, conversation_id: String, message: String) -> GenerationRequest {
        let sequence = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        GenerationRequest {
            model: self.model.clone(),
            prompt: message,
            instructions: None,
            media: Vec::<InputMedia>::new(),
            tools: Vec::<ClientTool>::new(),
            tool_choice: ToolChoice::None,
            max_tokens: None,
            max_tool_calls: None,
            temperature: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            stop: None,
            response_format: None,
            request_id: format!("legacy_{sequence:016x}"),
            session_id: conversation_id,
        }
    }
}

impl LegacyRuntimePort for ProviderLegacyRuntime {
    fn snapshot(&self) -> Result<LegacyRuntimeSnapshot, PortError> {
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "session state unavailable"))?;
        sessions.retain(|_, seen| now.duration_since(*seen) < self.session_idle_timeout);
        Ok(LegacyRuntimeSnapshot {
            skill_count: self.skill_count.load(Ordering::Acquire),
            active_model: self.model.clone(),
            session_count: sessions.len(),
            authenticated: self.authenticated.load(Ordering::Acquire),
        })
    }

    fn chat(
        &self,
        conversation_id: String,
        message: String,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>> {
        Box::pin(async move {
            if !self.authenticated.load(Ordering::Acquire) {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "provider is not authenticated",
                ));
            }
            self.touch_session(&conversation_id)?;
            let output = self
                .provider
                .generate(self.generation(conversation_id, message), cancellation)
                .await?;
            Ok(output.text)
        })
    }
}

impl LegacyChannelMessagePort for ProviderLegacyRuntime {
    fn process(
        &self,
        message: LegacyChannelMessage,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>> {
        self.chat(message.conversation_id, message.text, cancellation)
    }
}

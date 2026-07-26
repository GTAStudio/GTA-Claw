//! Runtime adapters supplied to the HTTP surface by the daemon process.
//!
//! Channel adapters, the agent engine, skill and role loading, and the updater
//! are owned elsewhere and are deliberately absent here. Every port that would
//! require them reports `Unavailable` instead of pretending to work, and
//! readiness names those dependencies so `/ready` tells the truth.

use std::sync::Arc;
use std::time::Instant;

use claw_http_api::{
    AdminFailure, AdminPort, AdminSuccess, ApiServices, AuditPort, EmbeddingRequest,
    GenerationEvent, GenerationOutput, GenerationRequest, Model, PortError, PortErrorKind,
    PortFuture, ProviderPort, ReadinessPort, ReadinessSnapshot, ToolDefinition, ToolInvocation,
    ToolOutcome, ToolPort, Usage, WatchAuthPort, WatchIdentity, WatchResultPort, WebhookOutcome,
    WebhookPort,
};
use claw_protocol::gateway::ConnectParams;
use claw_security::audit::AuditEvent;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Dependencies this process cannot serve yet, reported verbatim by `/ready`.
pub const UNCONFIGURED_DEPENDENCIES: &[&str] =
    &["admin", "audit", "provider", "tools", "watch", "webhooks"];

/// Runtime state owned by the daemon process.
#[derive(Debug)]
pub struct HttpServices {
    started: Instant,
}

impl HttpServices {
    /// Creates runtime state whose uptime starts now.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
        })
    }

    /// Creates the complete service bundle required by the HTTP surface.
    pub fn services(self: &Arc<Self>) -> ApiServices {
        ApiServices {
            provider: self.clone(),
            readiness: self.clone(),
            tools: self.clone(),
            admin: self.clone(),
            watch_auth: self.clone(),
            watch_results: self.clone(),
            webhooks: self.clone(),
            audit: self.clone(),
        }
    }

    fn uptime_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

fn unavailable(dependency: &str) -> PortError {
    PortError::new(
        PortErrorKind::Unavailable,
        format!("{dependency} adapter is not configured"),
    )
}

impl ReadinessPort for HttpServices {
    fn snapshot(&self) -> Result<ReadinessSnapshot, PortError> {
        let failing: Vec<String> = UNCONFIGURED_DEPENDENCIES
            .iter()
            .map(|dependency| (*dependency).to_owned())
            .collect();

        Ok(ReadinessSnapshot {
            ready: failing.is_empty(),
            failing,
            uptime_ms: self.uptime_ms(),
        })
    }
}

impl ProviderPort for HttpServices {
    fn models(&self) -> PortFuture<'_, Result<Vec<Model>, PortError>> {
        Box::pin(async { Err(unavailable("provider")) })
    }

    fn generate(
        &self,
        _request: GenerationRequest,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<GenerationOutput, PortError>> {
        Box::pin(async { Err(unavailable("provider")) })
    }

    fn stream(
        &self,
        _request: GenerationRequest,
        _events: mpsc::Sender<GenerationEvent>,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Usage, PortError>> {
        Box::pin(async { Err(unavailable("provider")) })
    }

    fn embed(
        &self,
        _request: EmbeddingRequest,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Vec<Vec<f32>>, PortError>> {
        Box::pin(async { Err(unavailable("provider")) })
    }
}

impl ToolPort for HttpServices {
    fn list(&self) -> PortFuture<'_, Result<Vec<ToolDefinition>, PortError>> {
        Box::pin(async { Err(unavailable("tools")) })
    }

    fn invoke(
        &self,
        _invocation: ToolInvocation,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<ToolOutcome, PortError>> {
        Box::pin(async { Err(unavailable("tools")) })
    }
}

impl AdminPort for HttpServices {
    fn dispatch(
        &self,
        _method: String,
        _params: Option<Value>,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<AdminSuccess, AdminFailure>> {
        Box::pin(async {
            Err(AdminFailure {
                code: "UNAVAILABLE".to_owned(),
                message: "admin gateway is not configured".to_owned(),
                details: None,
                retryable: Some(false),
                retry_after_ms: None,
            })
        })
    }
}

impl WatchAuthPort for HttpServices {
    fn authenticate(
        &self,
        _connect: ConnectParams,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WatchIdentity, PortError>> {
        Box::pin(async { Err(unavailable("watch")) })
    }
}

impl WatchResultPort for HttpServices {
    fn handle(
        &self,
        _node_id: String,
        _result: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<bool, PortError>> {
        Box::pin(async { Err(unavailable("watch")) })
    }
}

impl WebhookPort for HttpServices {
    fn invoke(
        &self,
        _route_id: String,
        _action: Value,
        _cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WebhookOutcome, PortError>> {
        Box::pin(async { Err(unavailable("webhooks")) })
    }
}

impl AuditPort for HttpServices {
    fn persist(&self, _event: &AuditEvent) -> Result<(), PortError> {
        Err(unavailable("audit"))
    }
}

#[cfg(test)]
mod tests {
    use claw_http_api::ReadinessPort;

    use super::{HttpServices, UNCONFIGURED_DEPENDENCIES};

    #[test]
    fn readiness_names_every_unconfigured_dependency() {
        let runtime = HttpServices::new();

        let snapshot = runtime.snapshot().expect("readiness snapshot");

        assert!(
            !snapshot.ready,
            "readiness must not claim dependencies that are absent"
        );
        assert_eq!(snapshot.failing, UNCONFIGURED_DEPENDENCIES);
    }
}

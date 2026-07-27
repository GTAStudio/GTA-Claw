//! Deterministic in-process adapters for tests and embedding smoke checks.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_protocol::gateway::ConnectParams;
use claw_security::audit::AuditEvent;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::ports::{
    AdminFailure, AdminPort, AdminSuccess, ApiServices, AuditPort, EmbeddingRequest,
    GenerationEvent, GenerationOutput, GenerationRequest, Model, PortError, PortErrorKind,
    PortFuture, ProviderPort, ReadinessPort, ReadinessSnapshot, ToolDefinition, ToolInvocation,
    ToolOutcome, ToolPort, Usage, WatchAuthPort, WatchIdentity, WatchResultPort, WebhookOutcome,
    WebhookPort,
};

/// Deterministic adapter implementing every runtime port.
pub struct DeterministicRuntime {
    ready: AtomicBool,
    started: std::time::Instant,
    output: Mutex<GenerationOutput>,
    last_generation_request: Mutex<Option<GenerationRequest>>,
    last_tool_invocation: Mutex<Option<ToolInvocation>>,
    delay_ms: AtomicU64,
    stream_cancelled: AtomicBool,
    audits: Mutex<Vec<AuditEvent>>,
}

impl Default for DeterministicRuntime {
    fn default() -> Self {
        Self {
            ready: AtomicBool::new(true),
            started: std::time::Instant::now(),
            output: Mutex::new(GenerationOutput {
                text: "deterministic response".to_owned(),
                tool_calls: Vec::new(),
                usage: Usage {
                    input_tokens: 3,
                    output_tokens: 2,
                    total_tokens: 5,
                },
            }),
            last_generation_request: Mutex::new(None),
            last_tool_invocation: Mutex::new(None),
            delay_ms: AtomicU64::new(0),
            stream_cancelled: AtomicBool::new(false),
            audits: Mutex::new(Vec::new()),
        }
    }
}

impl DeterministicRuntime {
    /// Creates deterministic services.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Creates a complete service bundle backed by this runtime.
    #[must_use]
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

    /// Changes dependency readiness.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    /// Replaces the provider result.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Internal`] when the output mutex is poisoned,
    /// which only happens after an earlier test panicked while holding it.
    pub fn set_output(&self, output: GenerationOutput) -> Result<(), PortError> {
        *self
            .output
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "output lock failed"))? = output;
        Ok(())
    }

    /// Adds a deterministic provider delay.
    pub fn set_delay(&self, delay: Duration) {
        self.delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
    }

    /// Reports whether a streaming request observed cancellation.
    #[must_use]
    pub fn stream_was_cancelled(&self) -> bool {
        self.stream_cancelled.load(Ordering::Acquire)
    }

    /// Returns the last generation request observed by the test double.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Internal`] when the recording mutex is poisoned,
    /// which only happens after an earlier test panicked while holding it.
    pub fn last_generation_request(&self) -> Result<Option<GenerationRequest>, PortError> {
        self.last_generation_request
            .lock()
            .map(|request| request.clone())
            .map_err(|_| PortError::new(PortErrorKind::Internal, "request lock failed"))
    }

    /// Returns the last tool invocation observed by the test double.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Internal`] when the recording mutex is poisoned,
    /// which only happens after an earlier test panicked while holding it.
    pub fn last_tool_invocation(&self) -> Result<Option<ToolInvocation>, PortError> {
        self.last_tool_invocation
            .lock()
            .map(|invocation| invocation.clone())
            .map_err(|_| PortError::new(PortErrorKind::Internal, "tool invocation lock failed"))
    }

    /// Returns persisted security audit events.
    ///
    /// # Errors
    ///
    /// Returns [`PortErrorKind::Internal`] when the audit mutex is poisoned,
    /// which only happens after an earlier test panicked while holding it.
    pub fn audit_events(&self) -> Result<Vec<AuditEvent>, PortError> {
        self.audits
            .lock()
            .map(|events| events.clone())
            .map_err(|_| PortError::new(PortErrorKind::Internal, "audit lock failed"))
    }

    async fn delay(&self, cancellation: &CancellationToken) -> Result<(), PortError> {
        let delay = Duration::from_millis(self.delay_ms.load(Ordering::Acquire));
        if delay.is_zero() {
            return Ok(());
        }
        tokio::select! {
            () = sleep(delay) => Ok(()),
            () = cancellation.cancelled() => Err(PortError::new(
                PortErrorKind::Unavailable,
                "request cancelled",
            )),
        }
    }

    fn output(&self) -> Result<GenerationOutput, PortError> {
        self.output
            .lock()
            .map(|output| output.clone())
            .map_err(|_| PortError::new(PortErrorKind::Internal, "output lock failed"))
    }
}

impl ReadinessPort for DeterministicRuntime {
    fn snapshot(&self) -> Result<ReadinessSnapshot, PortError> {
        let ready = self.ready.load(Ordering::Acquire);
        Ok(ReadinessSnapshot {
            ready,
            failing: if ready {
                Vec::new()
            } else {
                vec!["provider".to_owned()]
            },
            uptime_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

impl ProviderPort for DeterministicRuntime {
    fn models(&self) -> PortFuture<'_, Result<Vec<Model>, PortError>> {
        Box::pin(async {
            Ok(vec![Model {
                id: "openclaw".to_owned(),
            }])
        })
    }

    fn generate(
        &self,
        request: GenerationRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<GenerationOutput, PortError>> {
        Box::pin(async move {
            *self
                .last_generation_request
                .lock()
                .map_err(|_| PortError::new(PortErrorKind::Internal, "request lock failed"))? =
                Some(request);
            self.delay(&cancellation).await?;
            if cancellation.is_cancelled() {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "request cancelled",
                ));
            }
            self.output()
        })
    }

    fn stream(
        &self,
        request: GenerationRequest,
        events: mpsc::Sender<GenerationEvent>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Usage, PortError>> {
        Box::pin(async move {
            *self
                .last_generation_request
                .lock()
                .map_err(|_| PortError::new(PortErrorKind::Internal, "request lock failed"))? =
                Some(request);
            if let Err(error) = self.delay(&cancellation).await {
                if cancellation.is_cancelled() {
                    self.stream_cancelled.store(true, Ordering::Release);
                }
                return Err(error);
            }
            let output = self.output()?;
            for text in output.text.split_inclusive(' ') {
                tokio::select! {
                    result = events.send(GenerationEvent::Text(text.to_owned())) => {
                        if result.is_err() {
                            self.stream_cancelled.store(true, Ordering::Release);
                            return Err(PortError::new(
                                PortErrorKind::Unavailable,
                                "stream receiver disconnected",
                            ));
                        }
                    }
                    () = cancellation.cancelled() => {
                        self.stream_cancelled.store(true, Ordering::Release);
                        return Err(PortError::new(
                            PortErrorKind::Unavailable,
                            "request cancelled",
                        ));
                    }
                }
            }
            for call in output.tool_calls {
                if events.send(GenerationEvent::ToolCall(call)).await.is_err() {
                    self.stream_cancelled.store(true, Ordering::Release);
                    return Err(PortError::new(
                        PortErrorKind::Unavailable,
                        "stream receiver disconnected",
                    ));
                }
            }
            Ok(output.usage)
        })
    }

    fn embed(
        &self,
        request: EmbeddingRequest,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<Vec<Vec<f32>>, PortError>> {
        Box::pin(async move {
            self.delay(&cancellation).await?;
            let dimensions = request.dimensions.unwrap_or(3);
            #[expect(
                clippy::cast_precision_loss,
                reason = "the double derives each component from small input indices; an `f32` embedding is inherently approximate and callers only assert the fixed vectors these sizes produce"
            )]
            let vectors: Vec<Vec<f32>> = request
                .input
                .iter()
                .enumerate()
                .map(|(index, text)| {
                    (0..dimensions)
                        .map(|dimension| {
                            (text.len() + index + dimension) as f32 / dimensions as f32
                        })
                        .collect()
                })
                .collect();
            Ok(vectors)
        })
    }
}

impl ToolPort for DeterministicRuntime {
    fn list(&self) -> PortFuture<'_, Result<Vec<ToolDefinition>, PortError>> {
        Box::pin(async {
            Ok(vec![ToolDefinition {
                name: "echo".to_owned(),
                description: Some("Returns its arguments".to_owned()),
                input_schema: json!({"type":"object"}),
            }])
        })
    }

    fn invoke(
        &self,
        invocation: ToolInvocation,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<ToolOutcome, PortError>> {
        Box::pin(async move {
            self.delay(&cancellation).await?;
            *self.last_tool_invocation.lock().map_err(|_| {
                PortError::new(PortErrorKind::Internal, "tool invocation lock failed")
            })? = Some(invocation.clone());
            if invocation.name != "echo" {
                return Ok(ToolOutcome {
                    status: 404,
                    ok: false,
                    result: None,
                    error_type: Some("not_found".to_owned()),
                    error_message: Some(format!("Tool not available: {}", invocation.name)),
                    requires_approval: None,
                });
            }
            Ok(ToolOutcome {
                status: 200,
                ok: true,
                result: Some(invocation.arguments),
                error_type: None,
                error_message: None,
                requires_approval: None,
            })
        })
    }
}

impl AdminPort for DeterministicRuntime {
    fn dispatch(
        &self,
        method: String,
        params: Option<Value>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<AdminSuccess, AdminFailure>> {
        Box::pin(async move {
            if self.delay(&cancellation).await.is_err() {
                return Err(AdminFailure {
                    code: "AGENT_TIMEOUT".to_owned(),
                    message: "gateway method timed out".to_owned(),
                    details: None,
                    retryable: Some(true),
                    retry_after_ms: None,
                });
            }
            Ok(AdminSuccess {
                payload: json!({"method":method,"params":params}),
                meta: None,
            })
        })
    }
}

impl WatchAuthPort for DeterministicRuntime {
    fn authenticate(
        &self,
        connect: ConnectParams,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WatchIdentity, PortError>> {
        Box::pin(async move {
            self.delay(&cancellation).await?;
            let node_id = connect
                .device
                .as_ref()
                .map(|device| device.id.as_str().to_owned())
                .ok_or_else(|| {
                    PortError::new(PortErrorKind::InvalidRequest, "missing device proof")
                })?;
            Ok(WatchIdentity {
                node_id,
                device_token: Some("deterministic-device-token".to_owned()),
            })
        })
    }
}

impl WatchResultPort for DeterministicRuntime {
    fn handle(
        &self,
        _node_id: String,
        _result: Value,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<bool, PortError>> {
        Box::pin(async move {
            self.delay(&cancellation).await?;
            Ok(true)
        })
    }
}

impl WebhookPort for DeterministicRuntime {
    fn invoke(
        &self,
        route_id: String,
        action: Value,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<WebhookOutcome, PortError>> {
        Box::pin(async move {
            self.delay(&cancellation).await?;
            Ok(WebhookOutcome {
                status: 200,
                code: None,
                error: None,
                result: json!({"routeId":route_id,"action":action}),
            })
        })
    }
}

impl AuditPort for DeterministicRuntime {
    fn persist(&self, event: &AuditEvent) -> Result<(), PortError> {
        self.audits
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "audit lock failed"))?
            .push(event.clone());
        Ok(())
    }
}

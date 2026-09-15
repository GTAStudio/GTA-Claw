//! Reliability plumbing shared by every provider client in this crate.
//!
//! One [`ProviderRuntime`] owns the HTTP transport, the retry policy, the
//! circuit breaker, the concurrency limiter, the clock and the jitter source for
//! a single provider instance. Client modules only build requests and decode
//! payloads; every retry, backoff, cancellation and failure-classification
//! decision lives here.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use claw_provider_sdk::cancel::CancelToken;
use claw_provider_sdk::circuit::{
    CircuitBreaker, CircuitBreakerConfig, CircuitState, OwnedCircuitPermit,
};
use claw_provider_sdk::clock::{Clock, JitterSource, PseudoRandomJitter, SystemClock};
use claw_provider_sdk::error::{ErrorKind, Operation, ProviderError};
use claw_provider_sdk::http::{
    HttpRequest, HttpResponse, HttpStream, HttpTransport, TlsPolicy, TransportConfig,
    error_from_response,
};
use claw_provider_sdk::limit::{ConcurrencyLimiter, ConcurrencyPermit};
use claw_provider_sdk::provider::{Provider, RequestContext};
use claw_provider_sdk::retry::{RetryExecutor, RetryPolicy};
use futures_core::Stream;
use tokio::sync::{Mutex, RwLock};

/// Default number of simultaneous requests allowed against one provider.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// Reliability configuration applied to a provider client.
#[derive(Clone, Copy, Debug)]
pub struct ReliabilityConfig {
    /// Retry policy for idempotent-by-construction provider calls.
    pub retry: RetryPolicy,
    /// Circuit-breaker configuration.
    pub circuit: CircuitBreakerConfig,
    /// Maximum number of in-flight requests.
    pub max_concurrency: usize,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            retry: RetryPolicy::default(),
            circuit: CircuitBreakerConfig::default(),
            max_concurrency: DEFAULT_CONCURRENCY,
        }
    }
}

/// Monotonic fence assigned to one activated provider instance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderGeneration(u64);

impl ProviderGeneration {
    /// No provider has been activated yet.
    pub const NONE: Self = Self(0);

    /// Returns the raw generation number for diagnostics and persistence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A generation-fenced snapshot of the active provider.
#[derive(Clone)]
pub struct ProviderLease {
    generation: ProviderGeneration,
    provider: Arc<dyn Provider>,
}

impl std::fmt::Debug for ProviderLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderLease")
            .field("generation", &self.generation)
            .field("provider", &self.provider.id())
            .finish()
    }
}

impl ProviderLease {
    /// Returns the generation captured by this lease.
    #[must_use]
    pub const fn generation(&self) -> ProviderGeneration {
        self.generation
    }

    /// Returns the provider snapshot retained by this lease.
    #[must_use]
    pub fn provider(&self) -> &(dyn Provider + 'static) {
        self.provider.as_ref()
    }

    /// Clones the provider snapshot for a conversation-owned session.
    #[must_use]
    pub fn provider_arc(&self) -> Arc<dyn Provider> {
        Arc::clone(&self.provider)
    }

    /// Rejects work completed after a newer provider generation became active.
    ///
    /// Hosts call this after asynchronous conversation-session creation and
    /// before publishing that session. It closes the legacy race where a
    /// pre-reload creation could reinsert stale model/tool state after a clear.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Cancelled`] with code `reload_fenced` when this
    /// lease is no longer current.
    pub fn ensure_current(
        &self,
        slot: &ProviderSlot,
        operation: Operation,
    ) -> Result<(), ProviderError> {
        if slot.current_generation() == self.generation {
            return Ok(());
        }
        Err(ProviderError::new(
            ErrorKind::Cancelled,
            self.provider.id().as_str(),
            operation,
            "provider generation changed while the operation was in flight",
        )
        .with_upstream_code("reload_fenced"))
    }
}

/// Serializes provider startup and atomically publishes only healthy candidates.
///
/// Existing callers retain their [`ProviderLease`] and can finish gracefully;
/// new callers see the replacement immediately. The generation fence lets a
/// caller discard stale asynchronous setup completed after a reload.
pub struct ProviderSlot {
    switch: Mutex<()>,
    active: RwLock<Option<ProviderLease>>,
    generation: AtomicU64,
}

impl std::fmt::Debug for ProviderSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderSlot")
            .field("generation", &self.current_generation())
            .finish_non_exhaustive()
    }
}

impl ProviderSlot {
    /// Creates an empty activation slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            switch: Mutex::const_new(()),
            active: RwLock::const_new(None),
            generation: AtomicU64::new(0),
        }
    }

    /// Starts and pings `candidate`, then atomically makes it active.
    ///
    /// Concurrent activations serialize through one switch lock. A failed
    /// candidate never replaces the current provider.
    ///
    /// # Errors
    ///
    /// Returns the candidate's typed startup failure, or
    /// [`ErrorKind::Cancelled`] when the activation context is cancelled.
    pub async fn activate(
        &self,
        candidate: Arc<dyn Provider>,
        context: &RequestContext,
    ) -> Result<ProviderLease, ProviderError> {
        self.activate_validated(candidate, context, |_| async { Ok(()) }, |()| Ok(()))
            .await
    }

    /// Prepares host state after startup and publishes it with the provider lease.
    ///
    /// Both callbacks run under the switch lock. `commit` must check all fallible
    /// host preconditions before mutation; it runs synchronously immediately before
    /// the infallible slot publication. Its return value may retain a host lock and
    /// is dropped only after the new generation is visible. Cancellation or preparation failure leaves
    /// the old provider and generation unchanged.
    ///
    /// # Errors
    ///
    /// Returns startup, preparation or commit errors without publishing a candidate.
    pub async fn activate_validated<Prepared, Prepare, PrepareFuture, Commit, CommitGuard>(
        &self,
        candidate: Arc<dyn Provider>,
        context: &RequestContext,
        prepare: Prepare,
        commit: Commit,
    ) -> Result<ProviderLease, ProviderError>
    where
        Prepare: FnOnce(Arc<dyn Provider>) -> PrepareFuture,
        PrepareFuture: std::future::Future<Output = Result<Prepared, ProviderError>>,
        Commit: FnOnce(Prepared) -> Result<CommitGuard, ProviderError>,
    {
        let switch = tokio::select! {
            biased;
            () = context.cancel().cancelled() => {
                return Err(ProviderError::new(
                    ErrorKind::Cancelled,
                    candidate.id().as_str(),
                    Operation::Startup,
                    "provider activation was cancelled before startup",
                ));
            }
            switch = self.switch.lock() => switch,
        };
        candidate.startup(context).await?;
        candidate.ping(context).await?;
        let prepared = tokio::select! {
            biased;
            () = context.cancel().cancelled() => {
                return Err(ProviderError::new(ErrorKind::Cancelled, candidate.id().as_str(), Operation::Startup, "provider activation was cancelled before host preparation"));
            }
            prepared = prepare(Arc::clone(&candidate)) => prepared?,
        };
        let mut active = tokio::select! {
            biased;
            () = context.cancel().cancelled() => {
                return Err(ProviderError::new(ErrorKind::Cancelled, candidate.id().as_str(), Operation::Startup, "provider activation was cancelled before publication"));
            }
            active = self.active.write() => active,
        };
        if context.cancel().is_cancelled() {
            return Err(ProviderError::new(
                ErrorKind::Cancelled,
                candidate.id().as_str(),
                Operation::Startup,
                "provider activation was cancelled after startup",
            ));
        }

        let generation = ProviderGeneration(
            self.generation
                .load(Ordering::Acquire)
                .checked_add(1)
                .filter(|generation| *generation < u64::MAX)
                .ok_or_else(|| {
                    ProviderError::new(
                        ErrorKind::InvalidRequest,
                        candidate.id().as_str(),
                        Operation::Startup,
                        "provider generation capacity is exhausted",
                    )
                })?,
        );
        let lease = ProviderLease {
            generation,
            provider: candidate,
        };
        let committed = commit(prepared)?;
        *active = Some(lease.clone());
        self.generation.store(generation.get(), Ordering::Release);
        drop(committed);
        drop(active);
        drop(switch);
        Ok(lease)
    }

    /// Returns a snapshot of the active provider.
    #[must_use]
    pub async fn active(&self) -> Option<ProviderLease> {
        self.active.read().await.clone()
    }

    /// Fences and removes the active provider.
    ///
    /// The returned lease lets a host perform any adapter-specific terminal
    /// cleanup after the slot has stopped admitting new work.
    pub async fn clear(&self) -> Option<ProviderLease> {
        self.clear_with(|| {}).await
    }

    /// Clears synchronous host state under the same lock as provider retirement.
    ///
    /// The callback must not block on or reenter this slot. No activation can
    /// publish between the host-state clear and the lease retirement.
    pub async fn clear_with(&self, clear_host: impl FnOnce()) -> Option<ProviderLease> {
        let _switch = self.switch.lock().await;
        let mut active = self.active.write().await;
        clear_host();
        self.generation.store(
            self.generation.load(Ordering::Acquire).saturating_add(1),
            Ordering::Release,
        );
        active.take()
    }

    /// Returns the currently published generation fence.
    #[must_use]
    pub fn current_generation(&self) -> ProviderGeneration {
        ProviderGeneration(self.generation.load(Ordering::Acquire))
    }
}

impl Default for ProviderSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Raw byte chunks produced by a provider HTTP response.
pub type ProviderChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, ProviderError>> + Send>>;

/// A decoded provider stream whose terminal outcome updates reliability state.
pub type ProviderDecodedStream<T> = Pin<Box<dyn Stream<Item = Result<T, ProviderError>> + Send>>;

/// Successful streaming handshake awaiting provider-level decoding.
pub struct ProviderStream {
    stream: HttpStream,
    permit: OwnedCircuitPermit,
    slot: ConcurrencyPermit,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ProviderStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderStream")
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl ProviderStream {
    /// Decodes the raw response and retains reliability permits through the
    /// decoded stream's terminal result.
    #[must_use]
    pub fn decode<T, F>(self, decode: F) -> ProviderDecodedStream<T>
    where
        T: Send + 'static,
        F: FnOnce(ProviderChunkStream) -> ProviderDecodedStream<T>,
    {
        let inner = decode(self.stream.into_chunks());
        Box::pin(ObservedProviderStream {
            inner,
            permit: Some(self.permit),
            slot: Some(self.slot),
            clock: self.clock,
            done: false,
        })
    }

    /// Returns raw chunks while still accounting their terminal outcome.
    #[must_use]
    pub fn into_chunks(self) -> ProviderChunkStream {
        self.decode(|chunks| chunks)
    }
}

struct ObservedProviderStream<T> {
    inner: ProviderDecodedStream<T>,
    permit: Option<OwnedCircuitPermit>,
    slot: Option<ConcurrencyPermit>,
    clock: Arc<dyn Clock>,
    done: bool,
}

impl<T> Stream for ObservedProviderStream<T> {
    type Item = Result<T, ProviderError>;

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the circuit and concurrency permits intentionally remain attached to the decoded stream until this poll observes its terminal result"
    )]
    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_next(context) {
            Poll::Ready(None) => {
                this.done = true;
                if let Some(permit) = this.permit.take() {
                    permit.success(this.clock.now_millis());
                }
                drop(this.slot.take());
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                this.done = true;
                if let Some(permit) = this.permit.take() {
                    permit.failure(error.kind(), this.clock.now_millis());
                }
                drop(this.slot.take());
                Poll::Ready(Some(Err(error)))
            }
            item => item,
        }
    }
}

/// Owns the transport and the reliability policies of one provider client.
pub struct ProviderRuntime {
    provider: String,
    transport: HttpTransport,
    retry: RetryPolicy,
    breaker: Arc<CircuitBreaker>,
    limiter: ConcurrencyLimiter,
    clock: Arc<dyn Clock>,
    jitter: Arc<dyn JitterSource>,
}

impl std::fmt::Debug for ProviderRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderRuntime")
            .field("provider", &self.provider)
            .field("retry", &self.retry)
            .field("breaker", &self.breaker)
            .field("limiter", &self.limiter)
            .finish_non_exhaustive()
    }
}

impl ProviderRuntime {
    /// Builds a runtime with the production clock and a seeded jitter source.
    ///
    /// # Errors
    ///
    /// Returns [`claw_provider_sdk::error::ErrorKind::Transport`] when the TLS stack cannot be built.
    pub fn new(
        provider: impl Into<String>,
        tls_policy: TlsPolicy,
        config: ReliabilityConfig,
    ) -> Result<Self, ProviderError> {
        let transport = HttpTransport::with_config(&TransportConfig {
            tls_policy,
            ..TransportConfig::default()
        })?;
        Ok(Self::with_parts(
            provider,
            transport,
            config,
            Arc::new(SystemClock),
            Arc::new(PseudoRandomJitter::from_entropy()),
        ))
    }

    /// Builds a runtime from explicit parts, so tests can inject a fake clock.
    #[must_use]
    pub fn with_parts(
        provider: impl Into<String>,
        transport: HttpTransport,
        config: ReliabilityConfig,
        clock: Arc<dyn Clock>,
        jitter: Arc<dyn JitterSource>,
    ) -> Self {
        let provider = provider.into();
        let limiter = ConcurrencyLimiter::new(config.max_concurrency, &[]);
        Self {
            breaker: Arc::new(CircuitBreaker::new(provider.clone(), config.circuit)),
            provider,
            transport,
            retry: config.retry,
            limiter,
            clock,
            jitter,
        }
    }

    /// Returns the provider identifier used in errors and metrics.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the current circuit state.
    #[must_use]
    pub fn circuit_state(&self) -> CircuitState {
        self.breaker.state(self.clock.now_millis())
    }

    /// Returns the number of requests currently in flight.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.limiter.in_flight(&self.provider)
    }

    /// Returns the clock the reliability policies use.
    ///
    /// Clients that maintain their own expiring state, such as an OAuth token
    /// cache, read time through this handle so a test can drive them with a
    /// [`claw_provider_sdk::clock::ManualClock`].
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Sends a request under the retry policy and returns a successful response.
    ///
    /// `build` is called once per attempt so each retry gets a fresh request.
    /// A non-2xx status is converted into a typed [`ProviderError`], which the
    /// retry executor then classifies as retryable or terminal.
    ///
    /// # Errors
    ///
    /// Returns the last [`ProviderError`] observed, or an
    /// [`claw_provider_sdk::error::ErrorKind::Cancelled`] error when `cancel` fires.
    pub async fn execute<F>(
        &self,
        operation: Operation,
        cancel: &CancelToken,
        build: F,
    ) -> Result<HttpResponse, ProviderError>
    where
        F: Fn() -> Result<HttpRequest, ProviderError> + Send + Sync,
    {
        self.execute_decoded(operation, cancel, build, Ok).await
    }

    /// Sends and decodes a request under one reliability outcome.
    ///
    /// Provider protocol decoding runs before the circuit permit is reported,
    /// so malformed successful responses correctly count as protocol failures.
    ///
    /// # Errors
    ///
    /// Returns the transport, status, or decoder error from the final attempt.
    pub async fn execute_decoded<F, D, T>(
        &self,
        operation: Operation,
        cancel: &CancelToken,
        build: F,
        decode: D,
    ) -> Result<T, ProviderError>
    where
        F: Fn() -> Result<HttpRequest, ProviderError> + Send + Sync,
        D: Fn(HttpResponse) -> Result<T, ProviderError> + Send + Sync,
    {
        let executor = RetryExecutor::new(self.retry, self.clock.as_ref(), self.jitter.as_ref());
        let build = &build;
        let decode = &decode;
        let this = self;
        executor
            .run(
                &self.provider,
                operation,
                cancel,
                move |_attempt| async move {
                    let request = build()?;
                    let _slot = this
                        .limiter
                        .acquire_cancellable(&this.provider, operation, cancel)
                        .await?;
                    let permit = this
                        .breaker
                        .acquire_owned(operation, this.clock.now_millis())?;
                    let response = match this
                        .transport
                        .send(&this.provider, operation, request, cancel)
                        .await
                    {
                        Ok(response) => response,
                        Err(error) => {
                            permit.failure(error.kind(), this.clock.now_millis());
                            return Err(error);
                        }
                    };
                    if response.is_success() {
                        return match decode(response) {
                            Ok(value) => {
                                permit.success(this.clock.now_millis());
                                Ok(value)
                            }
                            Err(error) => {
                                permit.failure(error.kind(), this.clock.now_millis());
                                Err(error)
                            }
                        };
                    }
                    let error =
                        error_from_response(&this.provider, operation, &response, this.clock.now());
                    permit.failure(error.kind(), this.clock.now_millis());
                    Err(error)
                },
            )
            .await
    }

    /// Opens a streaming response under the retry policy.
    ///
    /// Only the handshake is retried: once the first byte of the body has been
    /// delivered to the caller, replaying the request would duplicate output.
    ///
    /// # Errors
    ///
    /// Returns the last [`ProviderError`] observed, or an
    /// [`claw_provider_sdk::error::ErrorKind::Cancelled`] error when `cancel` fires.
    pub async fn execute_streaming<F>(
        &self,
        operation: Operation,
        cancel: &CancelToken,
        build: F,
    ) -> Result<ProviderStream, ProviderError>
    where
        F: Fn() -> Result<HttpRequest, ProviderError> + Send + Sync,
    {
        let executor = RetryExecutor::new(self.retry, self.clock.as_ref(), self.jitter.as_ref());
        let build = &build;
        let this = self;
        executor
            .run(
                &self.provider,
                operation,
                cancel,
                move |_attempt| async move {
                    let request = build()?;
                    let slot = this
                        .limiter
                        .acquire_cancellable(&this.provider, operation, cancel)
                        .await?;
                    let permit = this
                        .breaker
                        .acquire_owned(operation, this.clock.now_millis())?;
                    let stream = match this
                        .transport
                        .send_streaming(&this.provider, operation, request, cancel)
                        .await
                    {
                        Ok(stream) => stream,
                        Err(error) => {
                            permit.failure(error.kind(), this.clock.now_millis());
                            drop(slot);
                            return Err(error);
                        }
                    };
                    if stream.is_success() {
                        return Ok(ProviderStream {
                            stream,
                            permit,
                            slot,
                            clock: Arc::clone(&this.clock),
                        });
                    }
                    let status = stream.status();
                    let retry_after = stream.header("retry-after").map(str::to_owned);
                    let body = drain(stream, cancel).await;
                    let response = HttpResponse::new(
                        status,
                        retry_after
                            .map(|value| vec![("retry-after".to_owned(), value)])
                            .unwrap_or_default(),
                        body,
                    );
                    let error =
                        error_from_response(&this.provider, operation, &response, this.clock.now());
                    permit.failure(error.kind(), this.clock.now_millis());
                    drop(slot);
                    Err(error)
                },
            )
            .await
    }
}

/// Reads an error body from a streaming response, bounded so a hostile server
/// cannot make the client allocate without limit.
async fn drain(stream: HttpStream, cancel: &CancelToken) -> Vec<u8> {
    use futures_util::StreamExt as _;

    const MAX_ERROR_BODY: usize = 64 * 1024;

    let mut chunks = stream.into_chunks();
    let mut body = Vec::new();
    while let Some(chunk) = chunks.next().await {
        if cancel.is_cancelled() {
            break;
        }
        match chunk {
            Ok(bytes) => {
                let remaining = MAX_ERROR_BODY.saturating_sub(body.len());
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(bytes.len());
                body.extend_from_slice(&bytes[..take]);
            }
            Err(_) => break,
        }
    }
    body
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::time::Duration;

    use claw_provider_sdk::clock::{FixedJitter, ManualClock};
    use claw_provider_sdk::model::{CapabilitySet, ProviderId};
    use claw_provider_sdk::provider::{BoxFuture, ProviderPhase, ProviderStatus};
    use claw_provider_sdk::retry::JitterMode;

    use super::*;

    fn runtime_with(clock: Arc<ManualClock>, config: ReliabilityConfig) -> ProviderRuntime {
        ProviderRuntime::with_parts(
            "test",
            HttpTransport::with_config(&TransportConfig {
                tls_policy: TlsPolicy::AllowLoopbackPlaintext,
                ..TransportConfig::default()
            })
            .expect("transport"),
            config,
            clock,
            Arc::new(FixedJitter::new(1.0)),
        )
    }

    struct ProbeProvider {
        id: ProviderId,
        starts: AtomicUsize,
        pings: AtomicUsize,
        fail_startup: bool,
        fail_ping: bool,
    }

    impl ProbeProvider {
        fn new(id: &str, fail: bool) -> Arc<Self> {
            Arc::new(Self {
                id: ProviderId::new(id).expect("valid provider id"),
                starts: AtomicUsize::new(0),
                pings: AtomicUsize::new(0),
                fail_startup: fail,
                fail_ping: false,
            })
        }

        fn ping_failure(id: &str) -> Arc<Self> {
            Arc::new(Self {
                id: ProviderId::new(id).expect("valid provider id"),
                starts: AtomicUsize::new(0),
                pings: AtomicUsize::new(0),
                fail_startup: false,
                fail_ping: true,
            })
        }
    }

    impl Provider for ProbeProvider {
        fn id(&self) -> &ProviderId {
            &self.id
        }

        fn capabilities(&self) -> CapabilitySet {
            CapabilitySet::EMPTY
        }

        fn startup<'a>(
            &'a self,
            _context: &'a RequestContext,
        ) -> BoxFuture<'a, Result<ProviderStatus, ProviderError>> {
            Box::pin(async move {
                self.starts.fetch_add(1, AtomicOrdering::SeqCst);
                if self.fail_startup {
                    return Err(ProviderError::new(
                        ErrorKind::Authentication,
                        self.id.as_str(),
                        Operation::Startup,
                        "synthetic startup refusal",
                    ));
                }
                Ok(ProviderStatus::new(self.id.clone(), ProviderPhase::Started))
            })
        }

        fn ping<'a>(
            &'a self,
            _context: &'a RequestContext,
        ) -> BoxFuture<'a, Result<ProviderStatus, ProviderError>> {
            Box::pin(async move {
                self.pings.fetch_add(1, AtomicOrdering::SeqCst);
                if self.fail_ping {
                    return Err(ProviderError::new(
                        ErrorKind::Server,
                        self.id.as_str(),
                        Operation::Ping,
                        "synthetic ping refusal",
                    ));
                }
                Ok(ProviderStatus::new(
                    self.id.clone(),
                    ProviderPhase::Reachable,
                ))
            })
        }
    }

    #[test]
    fn a_fresh_runtime_reports_a_closed_circuit_and_no_traffic() {
        let clock = Arc::new(ManualClock::new(0));
        let runtime = runtime_with(Arc::clone(&clock), ReliabilityConfig::default());
        assert_eq!(runtime.provider(), "test");
        assert_eq!(runtime.circuit_state(), CircuitState::Closed);
        assert_eq!(runtime.in_flight(), 0);
    }

    #[tokio::test]
    async fn a_cancelled_token_short_circuits_before_any_attempt() {
        let clock = Arc::new(ManualClock::new(0));
        let runtime = runtime_with(Arc::clone(&clock), ReliabilityConfig::default());
        let cancel = CancelToken::cancelled_token();
        let error = runtime
            .execute(Operation::Complete, &cancel, || {
                panic!("the request must never be built once cancelled")
            })
            .await
            .expect_err("cancelled");
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(error.operation(), Operation::Complete);
        assert_eq!(clock.recorded_sleeps(), Vec::<Duration>::new());
    }

    #[tokio::test]
    async fn transport_failures_retry_on_the_fake_clock_and_then_open_the_circuit() {
        let clock = Arc::new(ManualClock::new(0));
        let runtime = runtime_with(
            Arc::clone(&clock),
            ReliabilityConfig {
                retry: RetryPolicy {
                    max_attempts: 3,
                    initial_backoff: Duration::from_millis(100),
                    max_backoff: Duration::from_secs(10),
                    multiplier_centi: 200,
                    jitter: JitterMode::None,
                    respect_retry_after: true,
                    max_retry_after: Duration::from_mins(1),
                },
                circuit: CircuitBreakerConfig {
                    failure_threshold: 3,
                    open_duration: Duration::from_secs(30),
                    half_open_probes: 1,
                    success_threshold: 1,
                },
                max_concurrency: 2,
            },
        );
        let cancel = CancelToken::new();
        // Port 1 on the loopback interface has no listener, so every attempt
        // fails at connect time without touching a third-party network.
        let error = runtime
            .execute(Operation::Complete, &cancel, || {
                Ok(HttpRequest::new(
                    claw_provider_sdk::http::Method::Get,
                    "http://127.0.0.1:1/v1/models".parse().expect("url"),
                ))
            })
            .await
            .expect_err("no listener");
        assert_eq!(error.kind(), ErrorKind::Transport);
        assert_eq!(
            clock.recorded_sleeps(),
            vec![Duration::from_millis(100), Duration::from_millis(200)]
        );
        assert_eq!(runtime.circuit_state(), CircuitState::Open);
        assert_eq!(runtime.in_flight(), 0);

        // The open circuit now rejects immediately, without a further sleep.
        let rejected = runtime
            .execute(Operation::Complete, &cancel, || {
                Ok(HttpRequest::new(
                    claw_provider_sdk::http::Method::Get,
                    "http://127.0.0.1:1/v1/models".parse().expect("url"),
                ))
            })
            .await
            .expect_err("circuit open");
        assert_eq!(rejected.kind(), ErrorKind::CircuitOpen);
        assert_eq!(
            clock.recorded_sleeps(),
            vec![Duration::from_millis(100), Duration::from_millis(200)]
        );
    }

    #[tokio::test]
    async fn activation_publishes_only_a_candidate_that_passed_startup() {
        let slot = ProviderSlot::new();
        let first = ProbeProvider::new("first", false);
        let first_provider: Arc<dyn Provider> = first.clone();
        let first_lease = slot
            .activate(first_provider, &RequestContext::new())
            .await
            .expect("first provider starts");
        assert_eq!(first_lease.generation().get(), 1);
        assert_eq!(first.starts.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(first.pings.load(AtomicOrdering::SeqCst), 1);

        let rejected = ProbeProvider::new("rejected", true);
        let rejected_provider: Arc<dyn Provider> = rejected.clone();
        let error = slot
            .activate(rejected_provider, &RequestContext::new())
            .await
            .expect_err("failed startup must not replace the provider");
        assert_eq!(error.kind(), ErrorKind::Authentication);
        assert_eq!(slot.current_generation(), first_lease.generation());
        assert_eq!(
            slot.active()
                .await
                .expect("first remains active")
                .provider()
                .id(),
            first.id()
        );

        let unreachable = ProbeProvider::ping_failure("unreachable");
        let unreachable_provider: Arc<dyn Provider> = unreachable;
        let error = slot
            .activate(unreachable_provider, &RequestContext::new())
            .await
            .expect_err("failed ping must not replace the provider");
        assert_eq!(error.operation(), Operation::Ping);
        assert_eq!(slot.current_generation(), first_lease.generation());
    }

    #[tokio::test]
    async fn activation_host_failures_preserve_the_previous_provider_without_restarting_it() {
        let slot = ProviderSlot::new();
        let original = ProbeProvider::new("original", false);
        let lease = slot
            .activate(original.clone(), &RequestContext::new())
            .await
            .expect("original");
        let commits = AtomicUsize::new(0);
        for reject_prepare in [false, true] {
            let candidate = ProbeProvider::new("candidate", false);
            let result = slot
                .activate_validated(
                    candidate.clone(),
                    &RequestContext::new(),
                    |_| async {
                        if reject_prepare {
                            Err(ProviderError::new(
                                ErrorKind::InvalidRequest,
                                "candidate",
                                Operation::ListModels,
                                "model unavailable",
                            ))
                        } else {
                            Ok(())
                        }
                    },
                    |()| {
                        commits.fetch_add(1, AtomicOrdering::SeqCst);
                        Err::<(), _>(ProviderError::new(
                            ErrorKind::Cancelled,
                            "candidate",
                            Operation::Startup,
                            "configuration changed",
                        ))
                    },
                )
                .await;
            assert!(result.is_err());
            assert_eq!(slot.current_generation(), lease.generation());
            assert_eq!(
                slot.active().await.expect("old retained").provider().id(),
                original.id()
            );
            assert_eq!(candidate.starts.load(AtomicOrdering::SeqCst), 1);
            assert_eq!(candidate.pings.load(AtomicOrdering::SeqCst), 1);
        }
        assert_eq!(commits.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(original.starts.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(original.pings.load(AtomicOrdering::SeqCst), 1);
    }

    #[tokio::test]
    async fn activation_cancelled_while_waiting_to_publish_cannot_commit_host_state() {
        let slot = ProviderSlot::new();
        let original = ProbeProvider::new("original", false);
        let lease = slot
            .activate(original.clone(), &RequestContext::new())
            .await
            .expect("original");
        let held = slot.active.read().await;
        let prepared = tokio::sync::Notify::new();
        let cancel = CancelToken::new();
        let context = RequestContext::with_cancel(cancel.clone());
        let mut pending = Box::pin(slot.activate_validated(
            ProbeProvider::new("candidate", false),
            &context,
            |_| async {
                prepared.notify_one();
                Ok(())
            },
            |()| -> Result<(), ProviderError> {
                panic!("cancelled publication must not commit host state")
            },
        ));
        tokio::select! {
            result = &mut pending => panic!("publication must wait for reader: {result:?}"),
            () = prepared.notified() => {}
        }
        cancel.cancel();
        assert_eq!(
            pending.await.expect_err("cancelled while locked").kind(),
            ErrorKind::Cancelled
        );
        drop(held);
        assert_eq!(slot.current_generation(), lease.generation());
        assert_eq!(
            slot.active().await.expect("old retained").provider().id(),
            original.id()
        );
    }

    #[tokio::test]
    async fn activation_serializes_host_preparation_and_retirement() {
        use std::future::Future as _;
        let slot = ProviderSlot::new();
        let prepared = tokio::sync::Notify::new();
        let release = tokio::sync::Notify::new();
        let context = RequestContext::new();
        let host_state = AtomicUsize::new(0);
        let mut first = Box::pin(slot.activate_validated(
            ProbeProvider::new("first", false),
            &context,
            |_| async {
                prepared.notify_one();
                release.notified().await;
                Ok(())
            },
            |()| {
                host_state.store(1, AtomicOrdering::SeqCst);
                Ok(())
            },
        ));
        tokio::select! {
            result = &mut first => panic!("preparation must wait: {result:?}"),
            () = prepared.notified() => {}
        }
        let candidate = ProbeProvider::new("second", false);
        let mut second = Box::pin(slot.activate(candidate.clone(), &context));
        std::future::poll_fn(|context| {
            assert!(second.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(candidate.starts.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(slot.current_generation(), ProviderGeneration::NONE);
        assert_eq!(host_state.load(AtomicOrdering::SeqCst), 0);
        release.notify_one();
        let first = first.await.expect("prepared first");
        let second = second.await.expect("serialized second");
        assert_eq!(host_state.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(second.generation().get(), first.generation().get() + 1);
        let retired = slot
            .clear_with(|| host_state.store(0, AtomicOrdering::SeqCst))
            .await
            .expect("retirement");
        assert_eq!(retired.generation(), second.generation());
        assert_eq!(host_state.load(AtomicOrdering::SeqCst), 0);
        assert!(slot.active().await.is_none());
    }

    #[tokio::test]
    async fn activation_releases_host_guard_after_generation_and_never_wraps_capacity() {
        struct CommitGuard<'slot> {
            slot: &'slot ProviderSlot,
            released: &'slot AtomicUsize,
        }
        impl Drop for CommitGuard<'_> {
            fn drop(&mut self) {
                assert_eq!(self.slot.current_generation().get(), 1);
                self.released.fetch_add(1, AtomicOrdering::SeqCst);
            }
        }
        let slot = ProviderSlot::new();
        let released = AtomicUsize::new(0);
        let lease = slot
            .activate_validated(
                ProbeProvider::new("original", false),
                &RequestContext::new(),
                |_| async { Ok(()) },
                |()| {
                    Ok(CommitGuard {
                        slot: &slot,
                        released: &released,
                    })
                },
            )
            .await
            .expect("host and slot published");
        assert_eq!(released.load(AtomicOrdering::SeqCst), 1);
        slot.generation.store(u64::MAX - 1, Ordering::Release);
        let result = slot
            .activate_validated(
                ProbeProvider::new("candidate", false),
                &RequestContext::new(),
                |_| async { Ok(()) },
                |()| -> Result<(), ProviderError> {
                    panic!("exhausted generation must refuse before host commit")
                },
            )
            .await;
        assert_eq!(
            result.expect_err("capacity refused").kind(),
            ErrorKind::InvalidRequest
        );
        assert_eq!(
            slot.active()
                .await
                .expect("old slot unchanged")
                .generation(),
            lease.generation()
        );
        slot.clear().await.expect("old instance retired");
        assert_eq!(slot.current_generation().get(), u64::MAX);
        assert!(
            slot.activate(ProbeProvider::new("another", false), &RequestContext::new())
                .await
                .is_err()
        );
        assert!(slot.active().await.is_none());
    }

    #[tokio::test]
    async fn generation_leases_fence_stale_session_creation_after_reload() {
        let slot = ProviderSlot::new();
        let first = ProbeProvider::new("first", false);
        let first_provider: Arc<dyn Provider> = first;
        let stale = slot
            .activate(first_provider, &RequestContext::new())
            .await
            .expect("first provider starts");

        let second = ProbeProvider::new("second", false);
        let second_provider: Arc<dyn Provider> = second;
        let current = slot
            .activate(second_provider, &RequestContext::new())
            .await
            .expect("replacement starts");

        let error = stale
            .ensure_current(&slot, Operation::Startup)
            .expect_err("the old generation is fenced");
        assert_eq!(error.kind(), ErrorKind::Cancelled);
        assert_eq!(error.upstream_code(), Some("reload_fenced"));
        current
            .ensure_current(&slot, Operation::Startup)
            .expect("the replacement is current");

        let removed = slot.clear().await.expect("active provider");
        assert_eq!(removed.generation(), current.generation());
        assert!(slot.active().await.is_none());
        assert!(current.ensure_current(&slot, Operation::Ping).is_err());
    }
}

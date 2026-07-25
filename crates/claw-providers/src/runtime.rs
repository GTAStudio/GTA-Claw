//! Reliability plumbing shared by every provider client in this crate.
//!
//! One [`ProviderRuntime`] owns the HTTP transport, the retry policy, the
//! circuit breaker, the concurrency limiter, the clock and the jitter source for
//! a single provider instance. Client modules only build requests and decode
//! payloads; every retry, backoff, cancellation and failure-classification
//! decision lives here.

use std::sync::Arc;

use claw_provider_sdk::cancel::CancelToken;
use claw_provider_sdk::circuit::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
use claw_provider_sdk::clock::{Clock, JitterSource, PseudoRandomJitter, SystemClock};
use claw_provider_sdk::error::{Operation, ProviderError};
use claw_provider_sdk::http::{
    HttpRequest, HttpResponse, HttpStream, HttpTransport, TlsPolicy, TransportConfig,
    error_from_response,
};
use claw_provider_sdk::limit::ConcurrencyLimiter;
use claw_provider_sdk::retry::{RetryExecutor, RetryPolicy};

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

/// Owns the transport and the reliability policies of one provider client.
pub struct ProviderRuntime {
    provider: String,
    transport: HttpTransport,
    retry: RetryPolicy,
    breaker: CircuitBreaker,
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
            breaker: CircuitBreaker::new(provider.clone(), config.circuit),
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
                    let _slot = this.limiter.acquire(&this.provider, operation).await?;
                    let permit = this.breaker.acquire(operation, this.clock.now_millis())?;
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
                        permit.success(this.clock.now_millis());
                        return Ok(response);
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
    ) -> Result<HttpStream, ProviderError>
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
                    let permit = this.breaker.acquire(operation, this.clock.now_millis())?;
                    let stream = match this
                        .transport
                        .send_streaming(&this.provider, operation, request, cancel)
                        .await
                    {
                        Ok(stream) => stream,
                        Err(error) => {
                            permit.failure(error.kind(), this.clock.now_millis());
                            return Err(error);
                        }
                    };
                    if stream.is_success() {
                        permit.success(this.clock.now_millis());
                        return Ok(stream);
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
    use std::time::Duration;

    use claw_provider_sdk::clock::{FixedJitter, ManualClock};
    use claw_provider_sdk::error::ErrorKind;
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
                    max_retry_after: Duration::from_secs(60),
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
}

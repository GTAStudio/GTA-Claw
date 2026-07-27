//! Legacy HTTP+SSE client transport for MCP servers predating streamable HTTP.

use std::{collections::VecDeque, fmt, time::Duration};

use futures_util::StreamExt;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
    header::{ACCEPT, CONTENT_TYPE},
};
use rmcp::{
    RoleClient,
    transport::{
        common::client_side_sse::{ExponentialBackoff, SseRetryPolicy},
        worker::{Worker, WorkerContext, WorkerQuitReason, WorkerSendRequest},
    },
};
use serde_json::Value;
use sse_stream::Sse;
use thiserror::Error;
use tokio::time::{sleep, timeout};
use url::Url;

use crate::http_client::{HttpClient, HttpClientError, HttpResponse};

const MAX_PENDING_MESSAGES: usize = 64;

/// Configuration for the legacy MCP SSE transport.
#[derive(Clone)]
pub struct LegacySseConfig {
    /// URL of the server's SSE endpoint.
    pub endpoint: Url,
    /// HTTP headers applied to the SSE GET and message POST requests.
    pub headers: HeaderMap,
    /// Timeout for establishing an SSE stream and posting a message.
    pub request_timeout: Duration,
    /// Maximum number of reconnects after a previously established stream ends.
    pub max_reconnects: usize,
    /// Initial delay before reconnecting.
    pub reconnect_delay: Duration,
}

impl fmt::Debug for LegacySseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacySseConfig")
            .field("endpoint", &self.endpoint)
            .field("headers", &"[REDACTED]")
            .field("request_timeout", &self.request_timeout)
            .field("max_reconnects", &self.max_reconnects)
            .field("reconnect_delay", &self.reconnect_delay)
            .finish()
    }
}

impl LegacySseConfig {
    /// Creates a legacy SSE configuration with bounded default timeouts.
    #[must_use]
    pub fn new(endpoint: Url) -> Self {
        Self {
            endpoint,
            headers: HeaderMap::new(),
            request_timeout: Duration::from_secs(30),
            max_reconnects: 3,
            reconnect_delay: Duration::from_millis(250),
        }
    }
}

/// Errors produced by the legacy SSE transport.
#[derive(Debug, Error)]
pub enum LegacySseError {
    /// The HTTP client could not be constructed.
    #[error("failed to construct the HTTP client: {0}")]
    Client(#[source] HttpClientError),
    /// An HTTP operation failed.
    #[error("legacy SSE HTTP request failed: {0}")]
    Http(#[source] HttpClientError),
    /// An HTTP response had a non-success status.
    #[error("legacy SSE endpoint returned HTTP {0}")]
    HttpStatus(StatusCode),
    /// An operation exceeded its configured deadline.
    #[error("legacy SSE operation timed out")]
    Timeout,
    /// The SSE response contained an invalid event.
    #[error("invalid server-sent event: {0}")]
    Event(#[source] sse_stream::Error),
    /// A message event was not valid MCP JSON-RPC.
    #[error("invalid MCP JSON-RPC event: {0}")]
    Json(#[source] serde_json::Error),
    /// The server advertised an unsafe or malformed POST endpoint.
    #[error("invalid legacy SSE message endpoint")]
    Endpoint,
    /// The server did not advertise a message endpoint.
    #[error("legacy SSE stream ended before advertising a message endpoint")]
    MissingEndpoint,
    /// Too many messages arrived before endpoint discovery.
    #[error("legacy SSE pending-message limit exceeded")]
    PendingLimit,
    /// The server exhausted the configured reconnect budget.
    #[error("legacy SSE reconnect budget exhausted")]
    ReconnectExhausted,
    /// The local MCP service stopped receiving transport messages.
    #[error("MCP service receive channel closed")]
    ReceiveClosed,
    /// The transport worker task could not be joined.
    #[error("legacy SSE worker task failed: {0}")]
    Join(#[source] tokio::task::JoinError),
}

/// Legacy MCP transport that receives JSON-RPC over SSE and sends it over POST.
pub struct LegacySseTransport {
    config: LegacySseConfig,
    client: HttpClient,
}

impl LegacySseTransport {
    /// Creates a legacy SSE transport without starting network work.
    ///
    /// # Errors
    ///
    /// Returns [`LegacySseError::Client`] when the shared HTTPS client cannot be
    /// built — no usable platform trust anchors, or a `rustls` provider that the
    /// process has already installed with an incompatible configuration.
    pub fn new(config: LegacySseConfig) -> Result<Self, LegacySseError> {
        let client = HttpClient::new(config.request_timeout).map_err(LegacySseError::Client)?;
        Ok(Self { config, client })
    }
}

impl LegacySseTransport {
    async fn connect(&self, last_event_id: Option<&str>) -> Result<HttpResponse, LegacySseError> {
        let mut headers = self.config.headers.clone();
        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let Some(id) = last_event_id {
            headers.insert(
                HeaderName::from_static("last-event-id"),
                HeaderValue::from_str(id).map_err(|_| LegacySseError::Endpoint)?,
            );
        }
        let response = timeout(
            self.config.request_timeout,
            self.client
                .request(Method::GET, &self.config.endpoint, headers, Vec::new()),
        )
        .await
        .map_err(|_| LegacySseError::Timeout)?
        .map_err(LegacySseError::Http)?;
        if !response.status.is_success() {
            return Err(LegacySseError::HttpStatus(response.status));
        }
        Ok(response)
    }

    async fn post(
        &self,
        endpoint: &Url,
        message: &rmcp::service::TxJsonRpcMessage<RoleClient>,
    ) -> Result<(), LegacySseError> {
        let mut headers = self.config.headers.clone();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = serde_json::to_vec(message).map_err(LegacySseError::Json)?;
        let response = timeout(
            self.config.request_timeout,
            self.client.request(Method::POST, endpoint, headers, body),
        )
        .await
        .map_err(|_| LegacySseError::Timeout)?
        .map_err(LegacySseError::Http)?;
        if !response.status.is_success() {
            return Err(LegacySseError::HttpStatus(response.status));
        }
        Ok(())
    }

    fn parse_endpoint(&self, advertised: &str) -> Result<Url, LegacySseError> {
        let endpoint = self
            .config
            .endpoint
            .join(advertised)
            .map_err(|_| LegacySseError::Endpoint)?;
        if endpoint.scheme() != self.config.endpoint.scheme()
            || endpoint.host_str() != self.config.endpoint.host_str()
            || endpoint.port_or_known_default() != self.config.endpoint.port_or_known_default()
        {
            return Err(LegacySseError::Endpoint);
        }
        Ok(endpoint)
    }

    async fn handle_event(
        &self,
        event: Sse,
        post_endpoint: &mut Option<Url>,
        last_event_id: &mut Option<String>,
        context: &mut WorkerContext<Self>,
    ) -> Result<(), LegacySseError> {
        if let Some(id) = event.id.filter(|id| !id.is_empty()) {
            *last_event_id = Some(id);
        }
        let Some(data) = event.data else {
            return Ok(());
        };
        match event.event.as_deref() {
            Some("endpoint") => {
                *post_endpoint = Some(self.parse_endpoint(data.trim())?);
            }
            Some("message") | None => {
                let value: Value = serde_json::from_str(&data).map_err(LegacySseError::Json)?;
                let message = serde_json::from_value(value).map_err(LegacySseError::Json)?;
                context
                    .send_to_handler(message)
                    .await
                    .map_err(|_| LegacySseError::ReceiveClosed)?;
            }
            Some(_) => {}
        }
        Ok(())
    }

    async fn run(
        self,
        mut context: WorkerContext<Self>,
    ) -> Result<(), WorkerQuitReason<LegacySseError>> {
        let mut post_endpoint = None;
        let mut last_event_id = None;
        let mut pending: VecDeque<WorkerSendRequest<Self>> = VecDeque::new();
        let mut reconnects = 0;
        let mut backoff = ExponentialBackoff::default();
        backoff.max_times = Some(self.config.max_reconnects);
        backoff.base_duration = self.config.reconnect_delay;
        let cancellation = context.cancellation_token.clone();

        loop {
            let response = tokio::select! {
                () = cancellation.cancelled() => {
                    return Err(WorkerQuitReason::Cancelled);
                }
                response = self.connect(last_event_id.as_deref()) => response
                    .map_err(|error| WorkerQuitReason::fatal(
                        error,
                        "connecting legacy SSE stream",
                    ))?,
            };
            let mut stream = response.into_sse_stream();
            loop {
                tokio::select! {
                    () = cancellation.cancelled() => {
                        return Err(WorkerQuitReason::Cancelled);
                    }
                    outgoing = context.recv_from_handler() => {
                        let outgoing = outgoing?;
                        if let Some(endpoint) = post_endpoint.as_ref() {
                            self.post(endpoint, &outgoing.message).await
                                .map_err(|error| WorkerQuitReason::fatal(error, "posting legacy SSE message"))?;
                            let _ = outgoing.responder.send(Ok(()));
                        } else {
                            if pending.len() >= MAX_PENDING_MESSAGES {
                                return Err(WorkerQuitReason::fatal(
                                    LegacySseError::PendingLimit,
                                    "queueing legacy SSE message",
                                ));
                            }
                            pending.push_back(outgoing);
                        }
                    }
                    event = stream.next() => {
                        match event {
                            Some(Ok(event)) => {
                                self.handle_event(
                                    event,
                                    &mut post_endpoint,
                                    &mut last_event_id,
                                    &mut context,
                                )
                                .await
                                .map_err(|error| WorkerQuitReason::fatal(error, "handling legacy SSE event"))?;
                                if let Some(endpoint) = post_endpoint.as_ref() {
                                    while let Some(outgoing) = pending.pop_front() {
                                        self.post(endpoint, &outgoing.message).await
                                            .map_err(|error| WorkerQuitReason::fatal(
                                                error,
                                                "posting queued legacy SSE message",
                                            ))?;
                                        let _ = outgoing.responder.send(Ok(()));
                                    }
                                }
                            }
                            Some(Err(error)) => {
                                return Err(WorkerQuitReason::fatal(
                                    LegacySseError::Event(error),
                                    "parsing legacy SSE event",
                                ));
                            }
                            None => break,
                        }
                    }
                }
            }

            if post_endpoint.is_none() {
                return Err(WorkerQuitReason::fatal(
                    LegacySseError::MissingEndpoint,
                    "closing legacy SSE stream",
                ));
            }
            let Some(delay) = backoff.retry(reconnects) else {
                return Err(WorkerQuitReason::fatal(
                    LegacySseError::ReconnectExhausted,
                    "reconnecting legacy SSE stream",
                ));
            };
            reconnects += 1;
            tokio::select! {
                () = cancellation.cancelled() => {
                    return Err(WorkerQuitReason::Cancelled);
                }
                () = sleep(delay) => {}
            }
        }
    }
}

impl Worker for LegacySseTransport {
    type Error = LegacySseError;
    type Role = RoleClient;

    fn err_closed() -> Self::Error {
        LegacySseError::ReceiveClosed
    }

    fn err_join(error: tokio::task::JoinError) -> Self::Error {
        LegacySseError::Join(error)
    }

    async fn run(self, context: WorkerContext<Self>) -> Result<(), WorkerQuitReason<Self::Error>> {
        self.run(context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_headers() {
        let mut config =
            LegacySseConfig::new(Url::parse("http://127.0.0.1:43210/sse").expect("valid test URL"));
        let mut header = HeaderValue::from_static("test-bearer-value");
        header.set_sensitive(true);
        config.headers.insert(http::header::AUTHORIZATION, header);

        let output = format!("{config:?}");

        assert!(!output.contains("test-bearer-value"));
        assert!(output.contains("[REDACTED]"));
    }
}

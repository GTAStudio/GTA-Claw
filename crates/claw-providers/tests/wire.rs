//! End-to-end tests for the three implemented provider clients.
//!
//! Every test runs against a loopback HTTP/1.1 server started by the test
//! itself; no third-party API is contacted. The assertions check both
//! directions of the wire: the exact bytes the client puts on the socket, and
//! the typed values it produces from the bytes the server sends back.

mod support;

use std::sync::Arc;
use std::time::Duration;

use claw_provider_sdk::cancel::CancelToken;
use claw_provider_sdk::clock::{Clock, FixedJitter, ManualClock};
use claw_provider_sdk::error::{ErrorKind, Operation};
use claw_provider_sdk::http::{HttpTransport, TlsPolicy, TransportConfig};
use claw_provider_sdk::model::{
    AssistantMessage, CapabilitySet, ChatMessage, CompletionRequest, ContentPart, FinishReason,
    ModelId, ProviderId, ToolArguments, ToolCall, ToolDefinition, ToolParameters, Usage,
};
use claw_provider_sdk::origin::{BoundApiKey, Origin, OriginApproval};
use claw_provider_sdk::provider::{Provider as _, RequestContext};
use claw_provider_sdk::retry::{JitterMode, RetryPolicy};
use claw_provider_sdk::secret::{ApiKey, SecretString};
use claw_provider_sdk::stream::{StreamAccumulator, StreamEvent};
use claw_providers::anthropic::{Anthropic, AnthropicConfig};
use claw_providers::descriptor::{ANTHROPIC_CAPABILITIES, OPENAI_CAPABILITIES};
use claw_providers::github_copilot::{
    DeviceFlow, DeviceFlowConfig, DevicePollOutcome, GitHubCopilot, GitHubCopilotConfig,
};
use claw_providers::openai_compatible::{AuthStyle, OpenAiCompatible, OpenAiConfig};
use claw_providers::runtime::{ProviderRuntime, ReliabilityConfig};
use futures_util::StreamExt as _;
use serde_json::json;
use support::{Reply, TestServer};

const OPENAI_KEY: &str = "sk-test-DO-NOT-LEAK-openai";
const ANTHROPIC_KEY: &str = "sk-ant-test-DO-NOT-LEAK";
const GITHUB_TOKEN: &str = "gho_test_DO_NOT_LEAK";

fn model(id: &str) -> ModelId {
    ModelId::new(id).expect("valid model id")
}

fn provider_id(id: &str) -> ProviderId {
    ProviderId::new(id).expect("valid provider id")
}

/// Builds a runtime whose clock is a [`ManualClock`], so backoff never sleeps in
/// real time and every requested delay is recorded exactly.
fn manual_runtime(provider: &str, clock: &Arc<ManualClock>, retry: RetryPolicy) -> ProviderRuntime {
    let transport = HttpTransport::with_config(&TransportConfig {
        tls_policy: TlsPolicy::AllowLoopbackPlaintext,
        ..TransportConfig::default()
    })
    .expect("build transport");
    ProviderRuntime::with_parts(
        provider,
        transport,
        ReliabilityConfig {
            retry,
            ..ReliabilityConfig::default()
        },
        Arc::clone(clock) as Arc<dyn Clock>,
        Arc::new(FixedJitter::new(1.0)),
    )
}

/// Enrolls the loopback test server as an operator-approved origin.
///
/// A test owns its own server, so this is exactly the "a human decided"
/// situation [`OriginApproval::enroll`] exists for.
fn approve(server: &TestServer) -> OriginApproval {
    OriginApproval::enroll(Origin::of(&server.base_url()).expect("loopback origin"))
}

fn openai_client(server: &TestServer) -> OpenAiCompatible {
    let base_url = server.base_url();
    OpenAiCompatible::new(OpenAiConfig {
        provider: provider_id("openai"),
        api_key: Some(
            BoundApiKey::for_endpoint(&base_url, ApiKey::new(OPENAI_KEY)).expect("bind key"),
        ),
        base_url,
        auth: AuthStyle::Bearer,
        extra_headers: Vec::new(),
        capabilities: OPENAI_CAPABILITIES,
        stream_usage: true,
        reliability: ReliabilityConfig::default(),
    })
    .expect("build client")
}

fn anthropic_client(server: &TestServer) -> Anthropic {
    let config = AnthropicConfig::for_enrolled_origin(
        ApiKey::new(ANTHROPIC_KEY),
        server.base_url(),
        &approve(server),
    )
    .expect("config");
    Anthropic::new(config).expect("build client")
}

// ---------------------------------------------------------------------------
// OpenAI dialect
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_openai_completion_round_trips_over_the_wire() {
    let server = TestServer::start(vec![Reply::json(
        r#"{
            "id": "chatcmpl-abc",
            "object": "chat.completion",
            "model": "gpt-4o-mini-2024-07-18",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hei fra Oslo.",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"Oslo\"}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {
                "prompt_tokens": 31,
                "completion_tokens": 12,
                "prompt_tokens_details": {"cached_tokens": 8},
                "completion_tokens_details": {"reasoning_tokens": 4}
            }
        }"#,
    )])
    .await;
    let client = openai_client(&server);

    let mut request = CompletionRequest::new(
        model("gpt-4o-mini"),
        vec![
            ChatMessage::System("be terse".to_owned()),
            ChatMessage::user_text("weather in Oslo?"),
        ],
    );
    request.max_output_tokens = Some(256);
    request.tools = vec![ToolDefinition {
        name: "get_weather".to_owned(),
        description: "look up the weather".to_owned(),
        parameters: ToolParameters::new(json!({
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"]
        }))
        .expect("schema"),
    }];

    let response = client
        .complete(&request, &RequestContext::new())
        .await
        .expect("completion must succeed");

    assert_eq!(response.id, "chatcmpl-abc");
    assert_eq!(response.model.as_str(), "gpt-4o-mini-2024-07-18");
    assert_eq!(
        response.message,
        AssistantMessage {
            content: vec![ContentPart::Text("Hei fra Oslo.".to_owned())],
            reasoning: None,
            tool_calls: vec![ToolCall {
                id: "call_1".to_owned(),
                name: "get_weather".to_owned(),
                arguments: ToolArguments::new(r#"{"city":"Oslo"}"#).expect("arguments"),
            }],
        }
    );
    assert_eq!(response.finish_reason, FinishReason::ToolCalls);
    assert_eq!(
        response.usage,
        Usage {
            input_tokens: 31,
            output_tokens: 12,
            cached_input_tokens: 8,
            reasoning_tokens: 4,
        }
    );

    let requests = server.requests().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].target, "/chat/completions");
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("Bearer {OPENAI_KEY}").as_str())
    );
    assert_eq!(
        requests[0].json(),
        json!({
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "weather in Oslo?"}
            ],
            "max_tokens": 256,
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "look up the weather",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"]
                    }
                }
            }],
            "tool_choice": "auto"
        })
    );
}

#[tokio::test]
async fn an_openai_stream_round_trips_over_the_wire() {
    let server = TestServer::start(vec![Reply::sse(&[
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hei\"}}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" der\"}}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"id\":\"chatcmpl-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}\n\n",
        "data: [DONE]\n\n",
    ])])
    .await;
    let client = openai_client(&server);
    let request = CompletionRequest::new(model("gpt-4o-mini"), vec![ChatMessage::user_text("hei")]);

    let mut stream = client
        .stream(&request, &RequestContext::new())
        .await
        .expect("stream must open");
    assert_eq!(stream.provider(), "openai");

    let mut events = Vec::new();
    let mut accumulator = StreamAccumulator::new();
    while let Some(event) = stream.next().await {
        let event = event.expect("no stream error");
        accumulator.accept(&event);
        events.push(event);
    }

    assert_eq!(
        events,
        vec![
            StreamEvent::Started {
                id: "chatcmpl-1".to_owned(),
                model: "gpt-4o-mini".to_owned(),
            },
            StreamEvent::TextDelta("Hei".to_owned()),
            StreamEvent::TextDelta(" der".to_owned()),
            StreamEvent::UsageUpdate(Usage {
                input_tokens: 5,
                output_tokens: 3,
                cached_input_tokens: 0,
                reasoning_tokens: 0,
            }),
            StreamEvent::Completed {
                finish_reason: FinishReason::Stop,
                usage: Usage {
                    input_tokens: 5,
                    output_tokens: 3,
                    cached_input_tokens: 0,
                    reasoning_tokens: 0,
                },
            },
        ]
    );
    assert_eq!(
        accumulator.message(),
        AssistantMessage {
            content: vec![ContentPart::Text("Hei der".to_owned())],
            reasoning: None,
            tool_calls: Vec::new(),
        }
    );
    assert_eq!(accumulator.finish_reason(), Some(&FinishReason::Stop));

    let requests = server.requests().await;
    let body = requests[0].json();
    assert_eq!(body["stream"], json!(true));
    assert_eq!(body["stream_options"], json!({"include_usage": true}));
    assert_eq!(requests[0].header("accept"), Some("text/event-stream"));
}

#[tokio::test]
async fn cancelling_an_openai_stream_closes_the_socket_and_stops_events() {
    let server = TestServer::start(vec![Reply::sse_hold(&[
        "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"one\"}}]}\n\n",
    ])])
    .await;
    let client = openai_client(&server);
    let request = CompletionRequest::new(model("gpt-4o-mini"), vec![ChatMessage::user_text("hei")]);

    let mut stream = client
        .stream(&request, &RequestContext::new())
        .await
        .expect("stream must open");

    let first = stream
        .next()
        .await
        .expect("an event arrives")
        .expect("no error");
    assert_eq!(
        first,
        StreamEvent::Started {
            id: "chatcmpl-1".to_owned(),
            model: "gpt-4o-mini".to_owned(),
        }
    );
    assert!(!server.peer_closed(), "the socket is open while streaming");

    stream.cancel();

    let cancelled = stream
        .next()
        .await
        .expect("a terminal item")
        .expect_err("cancellation is reported");
    assert_eq!(cancelled.kind(), ErrorKind::Cancelled);
    assert_eq!(cancelled.operation(), Operation::StreamCompletion);
    assert!(
        stream.next().await.is_none(),
        "a cancelled stream is finished"
    );

    drop(stream);
    assert!(
        server.wait_for_peer_close(Duration::from_secs(5)).await,
        "cancelling must close the TCP connection, not just stop polling"
    );
}

#[tokio::test]
async fn dropping_an_openai_stream_cancels_it_and_closes_the_socket() {
    let server = TestServer::start(vec![Reply::sse_hold(&[
        "data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n\n",
    ])])
    .await;
    let client = openai_client(&server);
    let request = CompletionRequest::new(model("m"), vec![ChatMessage::user_text("hei")]);

    let mut stream = client
        .stream(&request, &RequestContext::new())
        .await
        .expect("stream must open");
    let token = stream.cancel_token();
    stream.next().await.expect("an event").expect("no error");
    assert!(!token.is_cancelled());

    drop(stream);

    assert!(
        token.is_cancelled(),
        "dropping the stream must cancel its token"
    );
    assert!(
        server.wait_for_peer_close(Duration::from_secs(5)).await,
        "dropping the stream must close the TCP connection"
    );
}

#[tokio::test]
async fn a_rate_limited_call_waits_exactly_the_retry_after_interval() {
    let server = TestServer::start(vec![
        Reply::status_with_header(
            429,
            "retry-after",
            "3",
            r#"{"error":{"message":"slow down","code":"rate_limit_exceeded"}}"#,
        ),
        Reply::json(
            r#"{"id":"chatcmpl-2","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}"#,
        ),
    ])
    .await;
    let clock = Arc::new(ManualClock::new(1_700_000_000_000));
    let client = openai_client(&server).with_runtime(manual_runtime(
        "openai",
        &clock,
        RetryPolicy::default(),
    ));

    let request = CompletionRequest::new(model("m"), vec![ChatMessage::user_text("hei")]);
    let response = client
        .complete(&request, &RequestContext::new())
        .await
        .expect("the second attempt succeeds");

    assert_eq!(response.id, "chatcmpl-2");
    assert_eq!(
        clock.recorded_sleeps(),
        vec![Duration::from_secs(3)],
        "the server's Retry-After must win over the computed backoff"
    );
    assert_eq!(server.request_count().await, 2);
}

#[tokio::test]
async fn exponential_backoff_grows_and_then_gives_up() {
    let server = TestServer::start(vec![
        Reply::status(503, r#"{"error":{"message":"unavailable"}}"#),
        Reply::status(503, r#"{"error":{"message":"unavailable"}}"#),
        Reply::status(503, r#"{"error":{"message":"unavailable"}}"#),
        Reply::status(503, r#"{"error":{"message":"unavailable"}}"#),
    ])
    .await;
    let clock = Arc::new(ManualClock::new(0));
    let policy = RetryPolicy {
        max_attempts: 4,
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(30),
        multiplier_centi: 200,
        jitter: JitterMode::None,
        respect_retry_after: true,
        max_retry_after: Duration::from_secs(120),
    };
    let client = openai_client(&server).with_runtime(manual_runtime("openai", &clock, policy));

    let request = CompletionRequest::new(model("m"), vec![ChatMessage::user_text("hei")]);
    let error = client
        .complete(&request, &RequestContext::new())
        .await
        .expect_err("every attempt fails");

    assert_eq!(error.kind(), ErrorKind::Server);
    assert_eq!(error.status(), Some(503));
    assert_eq!(error.detail(), "unavailable");
    assert_eq!(
        clock.recorded_sleeps(),
        vec![
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400),
        ],
        "three waits between four attempts, doubling each time"
    );
    assert_eq!(server.request_count().await, 4);
}

#[tokio::test]
async fn an_authentication_failure_is_not_retried() {
    let server = TestServer::start(vec![
        Reply::status(
            401,
            r#"{"error":{"message":"Incorrect API key provided","code":"invalid_api_key"}}"#,
        ),
        Reply::json(r#"{"id":"never","model":"m","choices":[]}"#),
    ])
    .await;
    let clock = Arc::new(ManualClock::new(0));
    let client = openai_client(&server).with_runtime(manual_runtime(
        "openai",
        &clock,
        RetryPolicy::default(),
    ));

    let request = CompletionRequest::new(model("m"), vec![ChatMessage::user_text("hei")]);
    let error = client
        .complete(&request, &RequestContext::new())
        .await
        .expect_err("a bad key is terminal");

    assert_eq!(error.kind(), ErrorKind::Authentication);
    assert_eq!(error.status(), Some(401));
    assert_eq!(error.upstream_code(), Some("invalid_api_key"));
    assert!(!error.is_retryable());
    assert_eq!(clock.recorded_sleeps(), Vec::new());
    assert_eq!(server.request_count().await, 1);
}

#[tokio::test]
async fn a_failing_call_never_reveals_the_api_key() {
    let server = TestServer::start(vec![Reply::status(
        500,
        r#"{"error":{"message":"internal boom","code":"server_error"}}"#,
    )])
    .await;
    let clock = Arc::new(ManualClock::new(0));
    let client =
        openai_client(&server).with_runtime(manual_runtime("openai", &clock, RetryPolicy::never()));

    let request = CompletionRequest::new(model("m"), vec![ChatMessage::user_text("hei")]);
    let error = client
        .complete(&request, &RequestContext::new())
        .await
        .expect_err("the server fails");

    // The key really was sent…
    let requests = server.requests().await;
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("Bearer {OPENAI_KEY}").as_str())
    );
    // …and it appears in none of the renderings the application can log.
    for rendering in [
        format!("{error}"),
        format!("{error:?}"),
        format!("{client:?}"),
    ] {
        assert!(
            !rendering.contains(OPENAI_KEY),
            "a credential leaked into `{rendering}`"
        );
    }
}

#[tokio::test]
async fn embeddings_and_model_listing_round_trip_over_the_wire() {
    let server = TestServer::start(vec![
        Reply::json(
            r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.5,-0.25]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":4,"total_tokens":4}}"#,
        ),
        Reply::json(
            r#"{"object":"list","data":[{"id":"gpt-4o-mini","object":"model"},{"id":"o3","object":"model"}]}"#,
        ),
    ])
    .await;
    let client = openai_client(&server);
    let context = RequestContext::new();

    let embeddings = client
        .embed(
            &claw_provider_sdk::model::EmbeddingsRequest {
                model: model("text-embedding-3-small"),
                inputs: vec!["hei".to_owned()],
                dimensions: Some(2),
            },
            &context,
        )
        .await
        .expect("embeddings must succeed");
    assert_eq!(embeddings.embeddings.len(), 1);
    assert_eq!(embeddings.embeddings[0].index, 0);
    assert_eq!(embeddings.embeddings[0].vector, vec![0.5, -0.25]);
    assert_eq!(embeddings.usage.input_tokens, 4);

    let models = client
        .list_models(&context)
        .await
        .expect("model listing must succeed");
    assert_eq!(
        models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        vec!["gpt-4o-mini", "o3"]
    );

    let requests = server.requests().await;
    assert_eq!(requests[0].target, "/embeddings");
    assert_eq!(
        requests[0].json(),
        json!({"model": "text-embedding-3-small", "input": ["hei"], "dimensions": 2})
    );
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].target, "/models");
}

// ---------------------------------------------------------------------------
// Anthropic
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_anthropic_completion_round_trips_over_the_wire() {
    let server = TestServer::start(vec![Reply::json(
        r#"{
            "id": "msg_017",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-5-20250929",
            "content": [{"type": "text", "text": "Det er 12 grader."}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 18, "output_tokens": 7, "cache_read_input_tokens": 3}
        }"#,
    )])
    .await;
    let client = anthropic_client(&server);

    let request = CompletionRequest::new(
        model("claude-sonnet-4-5"),
        vec![
            ChatMessage::System("svar kort".to_owned()),
            ChatMessage::user_text("vaeret i Oslo?"),
        ],
    );
    let response = client
        .complete(&request, &RequestContext::new())
        .await
        .expect("completion must succeed");

    assert_eq!(response.id, "msg_017");
    assert_eq!(response.model.as_str(), "claude-sonnet-4-5-20250929");
    assert_eq!(
        response.message.content,
        vec![ContentPart::Text("Det er 12 grader.".to_owned())]
    );
    assert_eq!(response.finish_reason, FinishReason::Stop);
    assert_eq!(
        response.usage,
        Usage {
            input_tokens: 18,
            output_tokens: 7,
            cached_input_tokens: 3,
            reasoning_tokens: 0,
        }
    );

    let requests = server.requests().await;
    assert_eq!(requests[0].target, "/v1/messages");
    assert_eq!(requests[0].header("x-api-key"), Some(ANTHROPIC_KEY));
    assert_eq!(requests[0].header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(
        requests[0].header("authorization"),
        None,
        "Anthropic authenticates with x-api-key, not a bearer token"
    );
    assert_eq!(
        requests[0].json(),
        json!({
            "model": "claude-sonnet-4-5",
            "max_tokens": 4096,
            "system": "svar kort",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "vaeret i Oslo?"}]}
            ]
        })
    );
}

#[tokio::test]
async fn an_anthropic_stream_round_trips_over_the_wire() {
    let server = TestServer::start(vec![Reply::sse(&[
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":9}}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hei\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    ])])
    .await;
    let client = anthropic_client(&server);
    let request = CompletionRequest::new(
        model("claude-sonnet-4-5"),
        vec![ChatMessage::user_text("hei")],
    );

    let mut stream = client
        .stream(&request, &RequestContext::new())
        .await
        .expect("stream must open");
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event.expect("no stream error"));
    }

    assert_eq!(
        events,
        vec![
            StreamEvent::Started {
                id: "msg_1".to_owned(),
                model: "claude-sonnet-4-5".to_owned(),
            },
            StreamEvent::UsageUpdate(Usage {
                input_tokens: 9,
                output_tokens: 0,
                cached_input_tokens: 0,
                reasoning_tokens: 0,
            }),
            StreamEvent::TextDelta("Hei".to_owned()),
            StreamEvent::UsageUpdate(Usage {
                input_tokens: 9,
                output_tokens: 4,
                cached_input_tokens: 0,
                reasoning_tokens: 0,
            }),
            StreamEvent::Completed {
                finish_reason: FinishReason::Stop,
                usage: Usage {
                    input_tokens: 9,
                    output_tokens: 4,
                    cached_input_tokens: 0,
                    reasoning_tokens: 0,
                },
            },
        ]
    );

    let requests = server.requests().await;
    assert_eq!(requests[0].json()["stream"], json!(true));
    assert_eq!(requests[0].header("accept"), Some("text/event-stream"));
}

#[tokio::test]
async fn cancelling_an_anthropic_stream_closes_the_socket() {
    let server = TestServer::start(vec![Reply::sse_hold(&[
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"x\",\"usage\":{}}}\n\n",
    ])])
    .await;
    let client = anthropic_client(&server);
    let request = CompletionRequest::new(model("x"), vec![ChatMessage::user_text("hei")]);

    let mut stream = client
        .stream(&request, &RequestContext::new())
        .await
        .expect("stream must open");
    stream.next().await.expect("an event").expect("no error");
    stream.cancel();
    let cancelled = stream
        .next()
        .await
        .expect("a terminal item")
        .expect_err("cancellation is reported");
    assert_eq!(cancelled.kind(), ErrorKind::Cancelled);
    drop(stream);

    assert!(
        server.wait_for_peer_close(Duration::from_secs(5)).await,
        "cancelling must close the TCP connection"
    );
}

#[tokio::test]
async fn an_anthropic_overload_is_retried_and_the_key_never_leaks() {
    let server = TestServer::start(vec![
        Reply::status(
            529,
            r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        ),
        Reply::json(
            r#"{"id":"msg_2","type":"message","role":"assistant","model":"x","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#,
        ),
    ])
    .await;
    let clock = Arc::new(ManualClock::new(0));
    let policy = RetryPolicy {
        max_attempts: 2,
        initial_backoff: Duration::from_millis(250),
        max_backoff: Duration::from_secs(10),
        multiplier_centi: 200,
        jitter: JitterMode::None,
        respect_retry_after: true,
        max_retry_after: Duration::from_secs(120),
    };
    let client =
        anthropic_client(&server).with_runtime(manual_runtime("anthropic", &clock, policy));

    let request = CompletionRequest::new(model("x"), vec![ChatMessage::user_text("hei")]);
    let response = client
        .complete(&request, &RequestContext::new())
        .await
        .expect("the retry succeeds");

    assert_eq!(response.id, "msg_2");
    assert_eq!(clock.recorded_sleeps(), vec![Duration::from_millis(250)]);
    assert_eq!(server.request_count().await, 2);
    for rendering in [format!("{client:?}"), format!("{response:?}")] {
        assert!(
            !rendering.contains(ANTHROPIC_KEY),
            "a credential leaked into `{rendering}`"
        );
    }
}

#[tokio::test]
async fn anthropic_advertises_no_embeddings_support() {
    let server = TestServer::start(Vec::new()).await;
    let client = anthropic_client(&server);
    assert_eq!(client.capabilities(), ANTHROPIC_CAPABILITIES);

    let error = client
        .embed(
            &claw_provider_sdk::model::EmbeddingsRequest {
                model: model("x"),
                inputs: vec!["hei".to_owned()],
                dimensions: None,
            },
            &RequestContext::new(),
        )
        .await
        .expect_err("Anthropic has no embeddings endpoint");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert_eq!(server.request_count().await, 0);
}

// ---------------------------------------------------------------------------
// GitHub Copilot
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_copilot_device_flow_polls_until_the_grant_is_approved() {
    let server = TestServer::start(vec![
        Reply::json(
            r#"{"device_code":"dc-secret","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#,
        ),
        Reply::json(r#"{"error":"authorization_pending","error_description":"pending"}"#),
        Reply::json(r#"{"error":"slow_down","error_description":"too fast","interval":10}"#),
        Reply::json(r#"{"access_token":"gho_granted_token","token_type":"bearer","scope":"read:user"}"#),
    ])
    .await;
    let clock = Arc::new(ManualClock::new(0));
    let flow = DeviceFlow::new(DeviceFlowConfig {
        client_id: "Iv1.test".to_owned(),
        scope: "read:user".to_owned(),
        device_code_url: server.url("login/device/code"),
        access_token_url: server.url("login/oauth/access_token"),
        approved_origins: vec![approve(&server)],
        reliability: ReliabilityConfig::default(),
    })
    .expect("build flow")
    .with_runtime(manual_runtime(
        "github-copilot",
        &clock,
        RetryPolicy::never(),
    ));

    let cancel = CancelToken::new();
    let authorization = flow.start(&cancel).await.expect("device code");
    assert_eq!(authorization.user_code, "WDJB-MJHT");
    assert_eq!(authorization.interval, 5);
    assert_eq!(authorization.device_code.expose(), "dc-secret");

    let token = flow
        .wait_for_token(&authorization, &cancel)
        .await
        .expect("the grant is approved");
    assert_eq!(token.expose(), "gho_granted_token");

    assert_eq!(
        clock.recorded_sleeps(),
        vec![
            Duration::from_secs(5),
            Duration::from_secs(5),
            Duration::from_secs(10),
        ],
        "a slow_down answer must widen the interval by five seconds"
    );

    let requests = server.requests().await;
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].target, "/login/device/code");
    assert_eq!(
        requests[0].header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        requests[0].body_text(),
        "client_id=Iv1.test&scope=read%3Auser"
    );
    for poll in &requests[1..] {
        assert_eq!(poll.target, "/login/oauth/access_token");
        assert_eq!(
            poll.body_text(),
            "client_id=Iv1.test&device_code=dc-secret&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"
        );
    }
}

#[tokio::test]
async fn a_denied_device_grant_stops_polling_immediately() {
    let server = TestServer::start(vec![Reply::json(
        r#"{"error":"access_denied","error_description":"The user denied the request"}"#,
    )])
    .await;
    let clock = Arc::new(ManualClock::new(0));
    let flow = DeviceFlow::new(DeviceFlowConfig {
        client_id: "Iv1.test".to_owned(),
        scope: "read:user".to_owned(),
        device_code_url: server.url("login/device/code"),
        access_token_url: server.url("login/oauth/access_token"),
        approved_origins: vec![approve(&server)],
        reliability: ReliabilityConfig::default(),
    })
    .expect("build flow")
    .with_runtime(manual_runtime(
        "github-copilot",
        &clock,
        RetryPolicy::never(),
    ));

    let outcome = flow
        .poll_once(&SecretString::new("dc"), &CancelToken::new())
        .await
        .expect_err("a denial is terminal");
    assert_eq!(outcome.kind(), ErrorKind::Authentication);
    assert_eq!(outcome.upstream_code(), Some("access_denied"));
    assert_eq!(server.request_count().await, 1);
}

#[tokio::test]
async fn a_cancelled_device_flow_stops_before_polling() {
    let server = TestServer::start(vec![Reply::json(r#"{"error":"authorization_pending"}"#)]).await;
    let clock = Arc::new(ManualClock::new(0));
    let flow = DeviceFlow::new(DeviceFlowConfig {
        client_id: "Iv1.test".to_owned(),
        scope: "read:user".to_owned(),
        device_code_url: server.url("login/device/code"),
        access_token_url: server.url("login/oauth/access_token"),
        approved_origins: vec![approve(&server)],
        reliability: ReliabilityConfig::default(),
    })
    .expect("build flow")
    .with_runtime(manual_runtime(
        "github-copilot",
        &clock,
        RetryPolicy::never(),
    ));

    let authorization = claw_providers::github_copilot::decode_device_authorization(
        br#"{"device_code":"dc","user_code":"u","verification_uri":"v","expires_in":900,"interval":5}"#,
    )
    .expect("decode");

    let error = flow
        .wait_for_token(&authorization, &CancelToken::cancelled_token())
        .await
        .expect_err("a cancelled flow must stop");
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(clock.recorded_sleeps(), Vec::new());
    assert_eq!(server.request_count().await, 0);
}

#[tokio::test]
async fn the_device_poll_reports_a_pending_grant_without_erroring() {
    let server = TestServer::start(vec![Reply::json(r#"{"error":"authorization_pending"}"#)]).await;
    let clock = Arc::new(ManualClock::new(0));
    let flow = DeviceFlow::new(DeviceFlowConfig {
        client_id: "Iv1.test".to_owned(),
        scope: "read:user".to_owned(),
        device_code_url: server.url("login/device/code"),
        access_token_url: server.url("login/oauth/access_token"),
        approved_origins: vec![approve(&server)],
        reliability: ReliabilityConfig::default(),
    })
    .expect("build flow")
    .with_runtime(manual_runtime(
        "github-copilot",
        &clock,
        RetryPolicy::never(),
    ));

    assert_eq!(
        flow.poll_once(&SecretString::new("dc"), &CancelToken::new())
            .await
            .expect("pending is not an error"),
        DevicePollOutcome::Pending
    );
}

#[tokio::test]
async fn copilot_exchanges_the_github_token_once_and_reuses_it() {
    let server = TestServer::start(vec![
        Reply::json(
            r#"{"token":"tid=copilot_secret;exp=9999999999","expires_at":9999999999,"refresh_in":1500}"#,
        ),
        Reply::json(
            r#"{"id":"chatcmpl-c1","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hei"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":1}}"#,
        ),
        Reply::json(
            r#"{"id":"chatcmpl-c2","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hei igjen"},"finish_reason":"stop"}]}"#,
        ),
    ])
    .await;
    let mut config = GitHubCopilotConfig::new(SecretString::new(GITHUB_TOKEN)).expect("config");
    config.token_exchange_url = server.url("copilot_internal/v2/token");
    config.api_base_url = Some(server.base_url());
    config.approved_origins = vec![approve(&server)];
    let client = GitHubCopilot::new(config).expect("build client");

    let request = CompletionRequest::new(model("gpt-4o"), vec![ChatMessage::user_text("hei")]);
    let context = RequestContext::new();

    let first = client
        .complete(&request, &context)
        .await
        .expect("first completion");
    assert_eq!(first.id, "chatcmpl-c1");

    let second = client
        .complete(&request, &context)
        .await
        .expect("second completion");
    assert_eq!(second.id, "chatcmpl-c2");

    let requests = server.requests().await;
    assert_eq!(
        requests.len(),
        3,
        "the token exchange happens once, not once per call"
    );
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].target, "/copilot_internal/v2/token");
    assert_eq!(
        requests[0].header("authorization"),
        Some(format!("token {GITHUB_TOKEN}").as_str())
    );

    for chat in &requests[1..] {
        assert_eq!(chat.target, "/chat/completions");
        assert_eq!(
            chat.header("authorization"),
            Some("Bearer tid=copilot_secret;exp=9999999999")
        );
        assert_eq!(chat.header("copilot-integration-id"), Some("vscode-chat"));
        assert_eq!(chat.header("editor-version"), Some("GTAClaw/0.1.0"));
        assert_eq!(
            chat.header("editor-plugin-version"),
            Some("claw-providers/0.1.0")
        );
        assert_eq!(chat.header("copilot-vision-request"), None);
    }

    let cached = client.cached_token().await.expect("a token is cached");
    assert_eq!(cached.expires_at, 9_999_999_999);
    assert!(
        !format!("{client:?}").contains(GITHUB_TOKEN),
        "the client debug rendering leaked the GitHub token"
    );
    assert!(
        !format!("{cached:?}").contains("tid=copilot_secret"),
        "the token debug rendering leaked the Copilot token"
    );
}

#[tokio::test]
async fn copilot_re_exchanges_an_expired_token() {
    let server = TestServer::start(vec![
        Reply::json(r#"{"token":"tid=first","expires_at":1000}"#),
        Reply::json(
            r#"{"id":"c1","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"a"},"finish_reason":"stop"}]}"#,
        ),
        Reply::json(r#"{"token":"tid=second","expires_at":99999}"#),
        Reply::json(
            r#"{"id":"c2","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"b"},"finish_reason":"stop"}]}"#,
        ),
    ])
    .await;
    let clock = Arc::new(ManualClock::new(0));
    let mut config = GitHubCopilotConfig::new(SecretString::new(GITHUB_TOKEN)).expect("config");
    config.token_exchange_url = server.url("copilot_internal/v2/token");
    config.api_base_url = Some(server.base_url());
    config.approved_origins = vec![approve(&server)];
    let client = GitHubCopilot::new(config)
        .expect("build client")
        .with_runtime(manual_runtime(
            "github-copilot",
            &clock,
            RetryPolicy::never(),
        ));

    let request = CompletionRequest::new(model("m"), vec![ChatMessage::user_text("hei")]);
    let context = RequestContext::new();

    assert_eq!(
        client.complete(&request, &context).await.expect("first").id,
        "c1"
    );
    clock.advance(Duration::from_secs(1_000));
    assert_eq!(
        client
            .complete(&request, &context)
            .await
            .expect("second")
            .id,
        "c2"
    );

    let requests = server.requests().await;
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].target, "/copilot_internal/v2/token");
    assert_eq!(
        requests[1].header("authorization"),
        Some("Bearer tid=first")
    );
    assert_eq!(requests[2].target, "/copilot_internal/v2/token");
    assert_eq!(
        requests[3].header("authorization"),
        Some("Bearer tid=second")
    );
}

#[tokio::test]
async fn copilot_streams_and_lists_models_over_the_wire() {
    let server = TestServer::start(vec![
        Reply::json(r#"{"token":"tid=stream","expires_at":9999999999}"#),
        Reply::sse(&[
            "data: {\"id\":\"c\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hei\"}}]}\n\n",
            "data: {\"id\":\"c\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        ]),
        Reply::json(
            r#"{"object":"list","data":[{"id":"gpt-4o","name":"GPT-4o","capabilities":{"limits":{"max_context_window_tokens":128000,"max_output_tokens":16384},"supports":{"streaming":true,"tool_calls":true,"vision":true}}}]}"#,
        ),
    ])
    .await;
    let mut config = GitHubCopilotConfig::new(SecretString::new(GITHUB_TOKEN)).expect("config");
    config.token_exchange_url = server.url("copilot_internal/v2/token");
    config.api_base_url = Some(server.base_url());
    config.approved_origins = vec![approve(&server)];
    let client = GitHubCopilot::new(config).expect("build client");
    let context = RequestContext::new();

    let request = CompletionRequest::new(model("gpt-4o"), vec![ChatMessage::user_text("hei")]);
    let mut stream = client
        .stream(&request, &context)
        .await
        .expect("stream must open");
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        events.push(event.expect("no stream error"));
    }
    assert_eq!(
        events,
        vec![
            StreamEvent::Started {
                id: "c".to_owned(),
                model: "gpt-4o".to_owned(),
            },
            StreamEvent::TextDelta("Hei".to_owned()),
            StreamEvent::Completed {
                finish_reason: FinishReason::Stop,
                usage: Usage::default(),
            },
        ]
    );

    let models = client.list_models(&context).await.expect("model listing");
    assert_eq!(models.len(), 1);
    assert_eq!(models[0].id.as_str(), "gpt-4o");
    assert_eq!(models[0].display_name.as_deref(), Some("GPT-4o"));
    assert_eq!(models[0].context_window, Some(128_000));
    assert_eq!(models[0].max_output_tokens, Some(16_384));
    assert_eq!(
        models[0].capabilities,
        CapabilitySet::from_slice(&[
            claw_provider_sdk::model::Capability::Completion,
            claw_provider_sdk::model::Capability::Streaming,
            claw_provider_sdk::model::Capability::ToolCalling,
            claw_provider_sdk::model::Capability::Vision,
        ])
    );

    let requests = server.requests().await;
    assert_eq!(requests[1].target, "/chat/completions");
    assert_eq!(requests[2].method, "GET");
    assert_eq!(requests[2].target, "/models");
}

#[tokio::test]
async fn copilot_sends_the_vision_header_only_for_image_prompts() {
    let server = TestServer::start(vec![
        Reply::json(r#"{"token":"tid=v","expires_at":9999999999}"#),
        Reply::json(
            r#"{"id":"c","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}"#,
        ),
    ])
    .await;
    let mut config = GitHubCopilotConfig::new(SecretString::new(GITHUB_TOKEN)).expect("config");
    config.token_exchange_url = server.url("copilot_internal/v2/token");
    config.api_base_url = Some(server.base_url());
    config.approved_origins = vec![approve(&server)];
    let client = GitHubCopilot::new(config).expect("build client");

    let request = CompletionRequest::new(
        model("gpt-4o"),
        vec![ChatMessage::User(vec![
            ContentPart::text("what is this?"),
            ContentPart::Image(claw_provider_sdk::model::ImagePart {
                media_type: claw_provider_sdk::model::ImageMediaType::Png,
                source: claw_provider_sdk::model::ImageSource::Base64("AAAA".to_owned()),
            }),
        ])],
    );
    client
        .complete(&request, &RequestContext::new())
        .await
        .expect("completion must succeed");

    let requests = server.requests().await;
    assert_eq!(requests[1].header("copilot-vision-request"), Some("true"));
    assert_eq!(
        requests[1].json()["messages"][0]["content"],
        json!([
            {"type": "text", "text": "what is this?"},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
        ])
    );
}

#[tokio::test]
async fn a_failed_copilot_token_exchange_is_typed_and_leaks_nothing() {
    let server = TestServer::start(vec![Reply::status(
        403,
        r#"{"message":"You don't have a Copilot subscription"}"#,
    )])
    .await;
    let clock = Arc::new(ManualClock::new(0));
    let mut config = GitHubCopilotConfig::new(SecretString::new(GITHUB_TOKEN)).expect("config");
    config.token_exchange_url = server.url("copilot_internal/v2/token");
    config.api_base_url = Some(server.base_url());
    config.approved_origins = vec![approve(&server)];
    let client = GitHubCopilot::new(config)
        .expect("build client")
        .with_runtime(manual_runtime(
            "github-copilot",
            &clock,
            RetryPolicy::never(),
        ));

    let request = CompletionRequest::new(model("m"), vec![ChatMessage::user_text("hei")]);
    let error = client
        .complete(&request, &RequestContext::new())
        .await
        .expect_err("the exchange fails");

    assert_eq!(error.kind(), ErrorKind::Authentication);
    assert_eq!(error.status(), Some(403));
    assert_eq!(error.operation(), Operation::Authorize);
    assert!(client.cached_token().await.is_none());
    for rendering in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendering.contains(GITHUB_TOKEN),
            "a credential leaked into `{rendering}`"
        );
    }
}

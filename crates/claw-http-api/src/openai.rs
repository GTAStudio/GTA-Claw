//! OpenAI-compatible model, embeddings, Chat Completions, and Responses handlers.

use std::collections::HashSet;
use std::convert::Infallible;

use axum::extract::{Extension, Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use claw_security::authorization::Scope;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::auth::{Principal, authorize_scope};
use crate::error::ApiError;
use crate::http_support::{
    CancelOnDrop, json_response, read_json, read_json_value, rejected_response,
};
use crate::ports::{
    ClientTool, EmbeddingRequest, EmbeddingsBody, GenerationEvent, GenerationOutput,
    GenerationRequest, InputMedia, InputMediaKind, InputMediaSource, PortError, PortErrorKind,
    ToolCall, ToolChoice, Usage,
};
use crate::state::{ApiState, unix_seconds};

/// Largest embedding width `POST /v1/embeddings` will ask a provider to build.
///
/// Nothing upstream bounds this: the route has no configured maximum, and the
/// routing identifiers it exposes (`openclaw`, `openclaw/<agentId>`) declare no
/// dimensionality to derive one from, so the ceiling is pinned here. 8192 is the
/// widest vector `claw-memory` will store, and matches the per-input character
/// cap this module already enforces; it is also far above the widest embedding
/// any current model emits (3072). Without it a single request can ask for
/// `usize::MAX` floats per input, and the provider allocating them takes down
/// every other request sharing the host.
const MAX_EMBEDDING_DIMENSIONS: u16 = 8_192;

/// Largest provider output one streaming request may retain before it is refused.
///
/// Both streaming coordinators hold part of the provider response in memory:
/// `/v1/chat/completions` withholds every delta while an output constraint is
/// pending, and `/v1/responses` must retain the whole message because
/// `response.output_text.done` and the terminal `response.completed` resource
/// carry it in full. Neither is optional — the first is what makes constraint
/// enforcement meaningful, the second is the Responses wire contract — but
/// nothing else bounds the buffer: the body limits cap the *request*, and
/// `stream_buffer` caps only the in-flight channel. Without a ceiling a single
/// caller can set `max_tokens` and let one broken or hostile upstream grow that
/// buffer until the process dies, taking every other in-flight request with it.
///
/// 8 MiB is far above any honest response. The widest published output ceiling
/// is around 128k tokens and even CJK- or emoji-dense text stays under six UTF-8
/// bytes per token, so a complete maximal response is well under 1 MiB.
const MAX_STREAM_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Bytes of provider output one requested output token is allowed to expand to.
///
/// A request carrying `max_tokens`/`max_output_tokens` has already stated its
/// own bound, so the buffer is sized from the request rather than from the
/// absolute ceiling. The factor is an order of magnitude above any real
/// tokenizer ratio, so a provider that honours the requested limit is never
/// refused; one that ignores it by a factor of sixty is already failing
/// [`enforce_output_constraints`].
const STREAM_OUTPUT_BYTES_PER_TOKEN: usize = 64;

/// Smallest per-request output buffer, whatever the request asked for.
///
/// A very small `max_tokens` would otherwise derive a buffer of a few hundred
/// bytes — exactly the range where the token-to-byte ratio is least predictable
/// and where bounding the buffer saves no memory worth having.
const MIN_STREAM_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatBody {
    model: Option<Value>,
    stream: Option<Value>,
    stream_options: Option<Value>,
    tools: Option<Value>,
    tool_choice: Option<Value>,
    messages: Option<Value>,
    user: Option<Value>,
    max_tokens: Option<Value>,
    max_completion_tokens: Option<Value>,
    temperature: Option<Value>,
    top_p: Option<Value>,
    response_format: Option<Value>,
    frequency_penalty: Option<Value>,
    presence_penalty: Option<Value>,
    seed: Option<Value>,
    stop: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponsesBody {
    model: String,
    input: Value,
    instructions: Option<String>,
    tools: Option<Vec<ResponseTool>>,
    tool_choice: Option<Value>,
    stream: Option<bool>,
    max_output_tokens: Option<u64>,
    max_tool_calls: Option<u64>,
    user: Option<String>,
    temperature: Option<f64>,
    top_p: Option<f64>,
    metadata: Option<Map<String, Value>>,
    store: Option<bool>,
    previous_response_id: Option<String>,
    reasoning: Option<Value>,
    truncation: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseTool {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    description: Option<String>,
    parameters: Option<Value>,
    strict: Option<bool>,
}

pub(crate) async fn models(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    if let Err(error) = authorize_scope(
        principal,
        Scope::OperatorRead,
        state.inner.services.audit.as_ref(),
    ) {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.openai_body_bytes,
            state.inner.config.limits.body_timeout,
            error,
        )
        .await);
    }
    let _ = timeout(
        state.inner.config.limits.operation_timeout,
        state.inner.services.provider.models(),
    )
    .await
    .map_err(|_| provider_api_error(PortError::new(PortErrorKind::Timeout, "request timed out")))?
    .map_err(provider_api_error)?;
    let data = model_ids(&state)
        .iter()
        .map(String::as_str)
        .map(model_object)
        .collect::<Vec<_>>();
    Ok(json_response(
        StatusCode::OK,
        &json!({"object": "list", "data": data}),
    ))
}

pub(crate) async fn model(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Response, ApiError> {
    if let Err(error) = authorize_scope(
        principal,
        Scope::OperatorRead,
        state.inner.services.audit.as_ref(),
    ) {
        return Ok(rejected_response(
            request,
            state.inner.config.limits.openai_body_bytes,
            state.inner.config.limits.body_timeout,
            error,
        )
        .await);
    }
    if !is_model_reference(&id) {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "Invalid model id.",
            "invalid_request_error",
        ));
    }
    if !model_ids(&state).contains(&id) {
        return Err(ApiError::openai(
            StatusCode::NOT_FOUND,
            format!("Model '{id}' not found."),
            "invalid_request_error",
        ));
    }
    Ok(json_response(StatusCode::OK, &model_object(&id)))
}

fn model_ids(state: &ApiState) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut ids = Vec::new();
    for id in ["openclaw".to_owned(), "openclaw/default".to_owned()]
        .into_iter()
        .chain(
            state
                .inner
                .config
                .agents
                .iter()
                .map(|agent| format!("openclaw/{agent}")),
        )
    {
        if seen.insert(id.clone()) {
            ids.push(id);
        }
    }
    ids
}

fn model_object(id: &str) -> Value {
    json!({
        "id": id,
        "object": "model",
        "created": 0,
        "owned_by": "openclaw",
        "permission": []
    })
}

pub(crate) async fn embeddings(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let limits = &state.inner.config.limits;
    if let Err(error) = authorize_scope(
        principal,
        Scope::OperatorWrite,
        state.inner.services.audit.as_ref(),
    ) {
        return Ok(rejected_response(
            request,
            limits.embeddings_body_bytes,
            limits.body_timeout,
            error,
        )
        .await);
    }
    let body: EmbeddingsBody =
        read_json(request, limits.embeddings_body_bytes, limits.body_timeout).await?;
    let model = body
        .model
        .and_then(|value| value.as_str().map(str::to_owned))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::openai(
                StatusCode::BAD_REQUEST,
                "Missing `model`.",
                "invalid_request_error",
            )
        })?;
    validate_model(&state, &model)?;
    let input = embedding_inputs(body.input)?;
    validate_embedding_inputs(&input)?;
    let dimensions = embedding_dimensions(body.dimensions.as_ref())?;
    let base64 = matches!(
        body.encoding_format.as_ref().and_then(Value::as_str),
        Some("base64")
    );
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    let embeddings = timeout(
        limits.operation_timeout,
        state.inner.services.provider.embed(
            EmbeddingRequest {
                model: model.clone(),
                input,
                dimensions,
            },
            cancellation,
        ),
    )
    .await
    .map_err(|_| provider_api_error(PortError::new(PortErrorKind::Timeout, "request timed out")))?
    .map_err(provider_api_error)?;
    let data = embeddings
        .into_iter()
        .enumerate()
        .map(|(index, embedding)| {
            let embedding = if base64 {
                let bytes = embedding
                    .iter()
                    .flat_map(|number| number.to_le_bytes())
                    .collect::<Vec<_>>();
                Value::String(STANDARD.encode(bytes))
            } else {
                serde_json::to_value(embedding).expect("finite embeddings serialize")
            };
            json!({"object": "embedding", "index": index, "embedding": embedding})
        })
        .collect::<Vec<_>>();
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "object": "list",
            "data": data,
            "model": model,
            "usage": {"prompt_tokens": 0, "total_tokens": 0}
        }),
    ))
}

pub(crate) async fn chat(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let limits = &state.inner.config.limits;
    if let Err(error) = authorize_scope(
        principal,
        Scope::OperatorWrite,
        state.inner.services.audit.as_ref(),
    ) {
        return Ok(rejected_response(
            request,
            limits.openai_body_bytes,
            limits.body_timeout,
            error,
        )
        .await);
    }
    let body: ChatBody = read_json(request, limits.openai_body_bytes, limits.body_timeout).await?;
    let model = body
        .model
        .as_ref()
        .and_then(Value::as_str)
        .unwrap_or("openclaw")
        .to_owned();
    validate_model(&state, &model)?;
    validate_sampling(&body)?;
    let prompt = chat_prompt(body.messages.as_ref())?;
    let tools = parse_chat_tools(body.tools.as_ref())?;
    let tool_choice = parse_tool_choice(body.tool_choice.as_ref(), &tools)?;
    let tools = tools_for_choice(tools, &tool_choice);
    let max_tokens = positive_u64(
        body.max_completion_tokens
            .as_ref()
            .or(body.max_tokens.as_ref()),
        "max_tokens",
    )?;
    let generation = GenerationRequest {
        model: model.clone(),
        prompt: prompt.message,
        instructions: prompt.instructions,
        media: prompt.media,
        tools,
        tool_choice: tool_choice.clone(),
        max_tokens,
        max_tool_calls: None,
        temperature: body.temperature.as_ref().and_then(Value::as_f64),
        top_p: body.top_p.as_ref().and_then(Value::as_f64),
        frequency_penalty: body.frequency_penalty.as_ref().and_then(Value::as_f64),
        presence_penalty: body.presence_penalty.as_ref().and_then(Value::as_f64),
        seed: body.seed.as_ref().and_then(Value::as_i64),
        stop: parse_stop(body.stop.as_ref())?,
        response_format: parse_response_format(body.response_format.as_ref())?,
        request_id: state.id("chatcmpl"),
        session_id: state.id("session"),
    };
    let stream = body
        .stream
        .as_ref()
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let include_usage = stream
        && body
            .stream_options
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|options| options.get("include_usage"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let _user = body.user;
    if stream {
        return Ok(chat_stream(&state, generation, include_usage));
    }
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    let mut output = timeout(
        limits.operation_timeout,
        state
            .inner
            .services
            .provider
            .generate(generation.clone(), cancellation),
    )
    .await
    .map_err(|_| provider_api_error(PortError::new(PortErrorKind::Timeout, "request timed out")))?
    .map_err(provider_api_error)?;
    enforce_tool_choice(&tool_choice, &generation.tools, &output.tool_calls)?;
    enforce_output_constraints(&generation, &mut output)?;
    Ok(json_response(
        StatusCode::OK,
        &chat_completion(&generation, &output, unix_seconds()),
    ))
}

pub(crate) async fn responses(
    State(state): State<ApiState>,
    Extension(principal): Extension<Principal>,
    request: Request,
) -> Result<Response, ApiError> {
    let limits = &state.inner.config.limits;
    if let Err(error) = authorize_scope(
        principal,
        Scope::OperatorWrite,
        state.inner.services.audit.as_ref(),
    ) {
        return Ok(rejected_response(
            request,
            limits.openai_body_bytes,
            limits.body_timeout,
            error,
        )
        .await);
    }
    let value = read_json_value(request, limits.openai_body_bytes, limits.body_timeout).await?;
    validate_responses_body(&value)?;
    let body: ResponsesBody = serde_json::from_value(value).map_err(|error| {
        ApiError::openai(
            StatusCode::BAD_REQUEST,
            error.to_string(),
            "invalid_request_error",
        )
    })?;
    validate_model(&state, &body.model)?;
    if body
        .temperature
        .is_some_and(|value| !(0.0..=2.0).contains(&value))
        || body
            .top_p
            .is_some_and(|value| !(0.0..=1.0).contains(&value))
    {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "invalid request",
            "invalid_request_error",
        ));
    }
    let prompt = responses_prompt(&body.input)?;
    let tools = parse_response_tools(body.tools)?;
    let tool_choice = parse_tool_choice(body.tool_choice.as_ref(), &tools)?;
    let tools = tools_for_choice(tools, &tool_choice);
    let response_id = state.id("resp");
    let output_item_id = state.id("msg");
    let session_id = state.resolve_response_session(
        body.previous_response_id.as_deref(),
        principal.subject,
        &body.model,
    )?;
    let generation = GenerationRequest {
        model: body.model.clone(),
        prompt: prompt.message,
        instructions: join_instructions(body.instructions, prompt.instructions),
        media: prompt.media,
        tools,
        tool_choice: tool_choice.clone(),
        max_tokens: body.max_output_tokens,
        max_tool_calls: body.max_tool_calls,
        temperature: body.temperature,
        top_p: body.top_p,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        stop: None,
        response_format: None,
        request_id: response_id.clone(),
        session_id: session_id.clone(),
    };
    state.remember_response_session(
        response_id.clone(),
        principal.subject,
        body.model.clone(),
        session_id,
    )?;
    let _compat_fields = (
        body.user,
        body.metadata,
        body.store,
        body.reasoning,
        body.truncation,
    );
    if body.stream.unwrap_or(false) {
        return Ok(responses_stream(
            &state,
            generation,
            response_id,
            output_item_id,
        ));
    }
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(&cancellation);
    let output = timeout(
        limits.operation_timeout,
        state
            .inner
            .services
            .provider
            .generate(generation.clone(), cancellation),
    )
    .await;
    let mut output = match output {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            return Ok(response_failure(
                &response_id,
                &generation.model,
                error,
                unix_seconds(),
            ));
        }
        Err(_) => {
            return Ok(response_failure(
                &response_id,
                &generation.model,
                PortError::new(PortErrorKind::Timeout, "request timed out"),
                unix_seconds(),
            ));
        }
    };
    if let Err(error) = enforce_tool_choice(&tool_choice, &generation.tools, &output.tool_calls) {
        return Ok(constrained_response_failure(
            &response_id,
            &generation.model,
            output.usage,
            &error,
        ));
    }
    if let Err(error) = enforce_output_constraints(&generation, &mut output) {
        return Ok(constrained_response_failure(
            &response_id,
            &generation.model,
            output.usage,
            &error,
        ));
    }
    let items = response_items(&state, &output_item_id, &output);
    let status = if output.tool_calls.is_empty() {
        "completed"
    } else {
        "incomplete"
    };
    Ok(json_response(
        StatusCode::OK,
        &response_resource(
            &response_id,
            &generation.model,
            status,
            &items,
            output.usage,
            None,
            unix_seconds(),
        ),
    ))
}

fn chat_stream(state: &ApiState, request: GenerationRequest, include_usage: bool) -> Response {
    let capacity = state.inner.config.limits.stream_buffer.max(1);
    let (sse_tx, sse_rx) = mpsc::channel::<Result<Event, Infallible>>(capacity);
    let (provider_tx, mut provider_rx) = mpsc::channel::<GenerationEvent>(capacity);
    let cancellation = CancellationToken::new();
    let provider_cancellation = cancellation.clone();
    let provider = state.inner.services.provider.clone();
    let operation_timeout = state.inner.config.limits.operation_timeout;
    let created = unix_seconds();
    let stream_request = request.clone();
    let coordinator_cancellation = cancellation.clone();
    tokio::spawn(async move {
        let cancellation = coordinator_cancellation;
        let provider_task = tokio::spawn(async move {
            timeout(
                operation_timeout,
                provider.stream(stream_request, provider_tx, provider_cancellation),
            )
            .await
        });
        if !send_event(
            &sse_tx,
            json_event(chat_chunk(
                &request,
                created,
                &json!({"role": "assistant"}),
                &Value::Null,
            )),
            &cancellation,
        )
        .await
        {
            return;
        }
        let mut tool_calls = Vec::new();
        let mut buffered_text = String::new();
        let buffer_until_validation = generation_requires_output_validation(&request);
        let mut budget = StreamBudget::new(&request);
        while let Some(event) = provider_rx.recv().await {
            if !budget.admits(retained_bytes(&event, buffer_until_validation)) {
                cancellation.cancel();
                let error = oversized_stream_error();
                if send_event(&sse_tx, json_event(error.body), &cancellation).await {
                    let _ = sse_tx.send(Ok(Event::default().data("[DONE]"))).await;
                }
                return;
            }
            let value = match event {
                GenerationEvent::Text(text) => {
                    if buffer_until_validation {
                        buffered_text.push_str(&text);
                        continue;
                    }
                    chat_chunk(&request, created, &json!({"content": text}), &Value::Null)
                }
                GenerationEvent::ToolCall(call) => {
                    if let Err(error) = enforce_tool_choice(
                        &request.tool_choice,
                        &request.tools,
                        std::slice::from_ref(&call),
                    ) {
                        cancellation.cancel();
                        if send_event(&sse_tx, json_event(error.body), &cancellation).await {
                            let _ = sse_tx.send(Ok(Event::default().data("[DONE]"))).await;
                        }
                        return;
                    }
                    let index = tool_calls.len();
                    tool_calls.push(call.clone());
                    if buffer_until_validation {
                        continue;
                    }
                    if !send_chat_tool_call(&sse_tx, &request, created, index, &call, &cancellation)
                        .await
                    {
                        return;
                    }
                    continue;
                }
            };
            if !send_event(&sse_tx, json_event(value), &cancellation).await {
                return;
            }
        }
        let provider_result = match provider_task.await {
            Ok(Ok(Ok(usage))) => Ok(usage),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(PortError::new(PortErrorKind::Timeout, "request timed out")),
            Err(_) => Err(PortError::new(PortErrorKind::Internal, "internal error")),
        };
        match provider_result {
            Ok(usage) => {
                if let Err(error) =
                    enforce_tool_choice(&request.tool_choice, &request.tools, &tool_calls)
                {
                    if send_event(&sse_tx, json_event(error.body), &cancellation).await {
                        let _ = sse_tx.send(Ok(Event::default().data("[DONE]"))).await;
                    }
                    return;
                }
                let mut output = GenerationOutput {
                    text: buffered_text,
                    tool_calls,
                    usage,
                };
                if let Err(error) = enforce_output_constraints(&request, &mut output) {
                    if send_event(&sse_tx, json_event(error.body), &cancellation).await {
                        let _ = sse_tx.send(Ok(Event::default().data("[DONE]"))).await;
                    }
                    return;
                }
                if buffer_until_validation {
                    if !output.text.is_empty()
                        && !send_event(
                            &sse_tx,
                            json_event(chat_chunk(
                                &request,
                                created,
                                &json!({"content":output.text}),
                                &Value::Null,
                            )),
                            &cancellation,
                        )
                        .await
                    {
                        return;
                    }
                    for (index, call) in output.tool_calls.iter().enumerate() {
                        if !send_chat_tool_call(
                            &sse_tx,
                            &request,
                            created,
                            index,
                            call,
                            &cancellation,
                        )
                        .await
                        {
                            return;
                        }
                    }
                }
                let finish = if output.tool_calls.is_empty() {
                    "stop"
                } else {
                    "tool_calls"
                };
                if !send_event(
                    &sse_tx,
                    json_event(chat_chunk(&request, created, &json!({}), &json!(finish))),
                    &cancellation,
                )
                .await
                {
                    return;
                }
                if include_usage
                    && !send_event(
                        &sse_tx,
                        json_event(json!({
                            "id": request.request_id,
                            "object": "chat.completion.chunk",
                            "created": created,
                            "model": request.model,
                            "choices": [],
                            "usage": chat_usage(usage)
                        })),
                        &cancellation,
                    )
                    .await
                {
                    return;
                }
            }
            Err(error) => {
                cancellation.cancel();
                let api = provider_api_error(error);
                if !send_event(&sse_tx, json_event(api.body), &cancellation).await {
                    return;
                }
            }
        }
        let _ = sse_tx.send(Ok(Event::default().data("[DONE]"))).await;
    });
    sse_response(
        sse_rx,
        state.inner.config.limits.heartbeat_interval,
        cancellation,
    )
}

fn responses_stream(
    state: &ApiState,
    request: GenerationRequest,
    response_id: String,
    item_id: String,
) -> Response {
    let capacity = state.inner.config.limits.stream_buffer.max(1);
    let (sse_tx, sse_rx) = mpsc::channel::<Result<Event, Infallible>>(capacity);
    let (provider_tx, mut provider_rx) = mpsc::channel::<GenerationEvent>(capacity);
    let cancellation = CancellationToken::new();
    let provider_cancellation = cancellation.clone();
    let provider = state.inner.services.provider.clone();
    let operation_timeout = state.inner.config.limits.operation_timeout;
    let created = unix_seconds();
    let stream_request = request.clone();
    let state_for_ids = state.clone();
    let coordinator_cancellation = cancellation.clone();
    tokio::spawn(async move {
        let cancellation = coordinator_cancellation;
        let empty = response_resource(
            &response_id,
            &request.model,
            "in_progress",
            &[],
            Usage::default(),
            None,
            created,
        );
        for event in [
            named_event(
                "response.created",
                json!({"type":"response.created","response":empty}),
            ),
            named_event(
                "response.in_progress",
                json!({"type":"response.in_progress","response":empty}),
            ),
            named_event(
                "response.output_item.added",
                json!({
                    "type":"response.output_item.added",
                    "output_index":0,
                    "item":assistant_item(&item_id, "", None, Some("in_progress"))
                }),
            ),
            named_event(
                "response.content_part.added",
                json!({
                    "type":"response.content_part.added",
                    "item_id":item_id,
                    "output_index":0,
                    "content_index":0,
                    "part":{"type":"output_text","text":""}
                }),
            ),
        ] {
            if !send_event(&sse_tx, event, &cancellation).await {
                return;
            }
        }
        let provider_task = tokio::spawn(async move {
            timeout(
                operation_timeout,
                provider.stream(stream_request, provider_tx, provider_cancellation),
            )
            .await
        });
        let mut text = String::new();
        let mut calls = Vec::new();
        let buffer_until_validation = generation_requires_output_validation(&request);
        let mut budget = StreamBudget::new(&request);
        while let Some(event) = provider_rx.recv().await {
            // Unlike chat, this coordinator retains every delta whether or not
            // it forwards it, because the terminal events carry the whole text.
            if !budget.admits(retained_bytes(&event, true)) {
                cancellation.cancel();
                let error = oversized_stream_error();
                send_response_failure(
                    &sse_tx,
                    &response_id,
                    &request.model,
                    PortError::new(
                        PortErrorKind::Unavailable,
                        constraint_error_message(&error).to_owned(),
                    ),
                    Usage::default(),
                    created,
                )
                .await;
                return;
            }
            match event {
                GenerationEvent::Text(delta) => {
                    text.push_str(&delta);
                    if buffer_until_validation {
                        continue;
                    }
                    let event = named_event(
                        "response.output_text.delta",
                        json!({
                            "type":"response.output_text.delta",
                            "item_id":item_id,
                            "output_index":0,
                            "content_index":0,
                            "delta":delta
                        }),
                    );
                    if !send_event(&sse_tx, event, &cancellation).await {
                        return;
                    }
                }
                GenerationEvent::ToolCall(call) => {
                    if let Err(error) = enforce_tool_choice(
                        &request.tool_choice,
                        &request.tools,
                        std::slice::from_ref(&call),
                    ) {
                        cancellation.cancel();
                        send_response_failure(
                            &sse_tx,
                            &response_id,
                            &request.model,
                            PortError::new(
                                PortErrorKind::Unavailable,
                                constraint_error_message(&error).to_owned(),
                            ),
                            Usage::default(),
                            created,
                        )
                        .await;
                        return;
                    }
                    calls.push(call);
                    if request
                        .max_tool_calls
                        .is_some_and(|limit| calls.len() as u64 > limit)
                    {
                        cancellation.cancel();
                        send_response_failure(
                            &sse_tx,
                            &response_id,
                            &request.model,
                            PortError::new(
                                PortErrorKind::Unavailable,
                                "The provider exceeded the requested tool call limit.",
                            ),
                            Usage::default(),
                            created,
                        )
                        .await;
                        return;
                    }
                }
            }
        }
        let provider_result = match provider_task.await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(PortError::new(PortErrorKind::Timeout, "request timed out")),
            Err(_) => Err(PortError::new(PortErrorKind::Internal, "internal error")),
        };
        let usage = match provider_result {
            Ok(usage) => usage,
            Err(error) => {
                cancellation.cancel();
                send_response_failure(
                    &sse_tx,
                    &response_id,
                    &request.model,
                    error,
                    Usage::default(),
                    created,
                )
                .await;
                return;
            }
        };
        if let Err(error) = enforce_tool_choice(&request.tool_choice, &request.tools, &calls) {
            send_response_failure(
                &sse_tx,
                &response_id,
                &request.model,
                PortError::new(
                    PortErrorKind::Unavailable,
                    error.body["error"]["message"]
                        .as_str()
                        .unwrap_or("The model did not call the required tool."),
                ),
                usage,
                created,
            )
            .await;
            return;
        }
        let mut output = GenerationOutput {
            text,
            tool_calls: calls,
            usage,
        };
        if let Err(error) = enforce_output_constraints(&request, &mut output) {
            send_response_failure(
                &sse_tx,
                &response_id,
                &request.model,
                PortError::new(
                    PortErrorKind::Unavailable,
                    constraint_error_message(&error).to_owned(),
                ),
                output.usage,
                created,
            )
            .await;
            return;
        }
        let GenerationOutput {
            text,
            tool_calls: calls,
            usage,
        } = output;
        if buffer_until_validation
            && !text.is_empty()
            && !send_event(
                &sse_tx,
                named_event(
                    "response.output_text.delta",
                    json!({
                        "type":"response.output_text.delta",
                        "item_id":item_id,
                        "output_index":0,
                        "content_index":0,
                        "delta":text
                    }),
                ),
                &cancellation,
            )
            .await
        {
            return;
        }
        let assistant = assistant_item(
            &item_id,
            &text,
            Some(if calls.is_empty() {
                "final_answer"
            } else {
                "commentary"
            }),
            Some("completed"),
        );
        for event in [
            named_event(
                "response.output_text.done",
                json!({
                    "type":"response.output_text.done","item_id":item_id,
                    "output_index":0,"content_index":0,"text":text
                }),
            ),
            named_event(
                "response.content_part.done",
                json!({
                    "type":"response.content_part.done","item_id":item_id,
                    "output_index":0,"content_index":0,
                    "part":{"type":"output_text","text":text}
                }),
            ),
            named_event(
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":0,"item":assistant}),
            ),
        ] {
            if !send_event(&sse_tx, event, &cancellation).await {
                return;
            }
        }
        let mut output = vec![assistant];
        for (offset, call) in calls.iter().enumerate() {
            let call_item = function_call_item(&state_for_ids.id("call"), call, Some("completed"));
            for event in [
                named_event(
                    "response.output_item.added",
                    json!({"type":"response.output_item.added","output_index":offset+1,"item":call_item}),
                ),
                named_event(
                    "response.output_item.done",
                    json!({"type":"response.output_item.done","output_index":offset+1,"item":call_item}),
                ),
            ] {
                if !send_event(&sse_tx, event, &cancellation).await {
                    return;
                }
            }
            output.push(call_item);
        }
        let status = if calls.is_empty() {
            "completed"
        } else {
            "incomplete"
        };
        let final_response = response_resource(
            &response_id,
            &request.model,
            status,
            &output,
            usage,
            None,
            created,
        );
        let _ = sse_tx
            .send(Ok(named_event(
                "response.completed",
                json!({"type":"response.completed","response":final_response}),
            )))
            .await;
        let _ = sse_tx.send(Ok(Event::default().data("[DONE]"))).await;
    });
    sse_response(
        sse_rx,
        state.inner.config.limits.heartbeat_interval,
        cancellation,
    )
}

async fn send_event(
    sender: &mpsc::Sender<Result<Event, Infallible>>,
    event: Event,
    cancellation: &CancellationToken,
) -> bool {
    if sender.send(Ok(event)).await.is_err() {
        cancellation.cancel();
        false
    } else {
        true
    }
}

async fn send_chat_tool_call(
    sender: &mpsc::Sender<Result<Event, Infallible>>,
    request: &GenerationRequest,
    created: u64,
    index: usize,
    call: &ToolCall,
    cancellation: &CancellationToken,
) -> bool {
    if !send_event(
        sender,
        json_event(chat_chunk(
            request,
            created,
            &json!({"tool_calls":[{
                "index":index,
                "id":call.id,
                "type":"function",
                "function":{"name":call.name,"arguments":""}
            }]}),
            &Value::Null,
        )),
        cancellation,
    )
    .await
    {
        return false;
    }
    let deltas = split_arguments_for_streaming(&call.arguments);
    for delta in deltas {
        if !send_event(
            sender,
            json_event(chat_chunk(
                request,
                created,
                &json!({"tool_calls":[{
                    "index":index,
                    "function":{"arguments":delta}
                }]}),
                &Value::Null,
            )),
            cancellation,
        )
        .await
        {
            return false;
        }
    }
    true
}

fn split_arguments_for_streaming(arguments: &str) -> Vec<String> {
    if arguments.is_empty() {
        return vec![String::new()];
    }
    let mut chunks = Vec::new();
    let mut chunk = String::new();
    let mut characters = 0;
    for character in arguments.chars() {
        if characters == 256 {
            chunks.push(chunk);
            chunk = String::new();
            characters = 0;
        }
        chunk.push(character);
        characters += 1;
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    chunks
}

async fn send_response_failure(
    sender: &mpsc::Sender<Result<Event, Infallible>>,
    response_id: &str,
    model: &str,
    error: PortError,
    usage: Usage,
    created: u64,
) {
    let api = provider_api_error(error);
    let code = api.body["error"]["type"].as_str().unwrap_or("api_error");
    let message = api.body["error"]["message"]
        .as_str()
        .unwrap_or("internal error");
    let failed = response_resource(
        response_id,
        model,
        "failed",
        &[],
        usage,
        Some((code, message)),
        created,
    );
    let _ = sender
        .send(Ok(named_event(
            "response.failed",
            json!({"type":"response.failed","response":failed}),
        )))
        .await;
    let _ = sender.send(Ok(Event::default().data("[DONE]"))).await;
}

fn sse_response(
    receiver: mpsc::Receiver<Result<Event, Infallible>>,
    heartbeat: std::time::Duration,
    cancellation: CancellationToken,
) -> Response {
    let stream = CancelOnDropStream {
        inner: ReceiverStream::new(receiver),
        cancellation,
    };
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(heartbeat).text(""))
        .into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

struct CancelOnDropStream {
    inner: ReceiverStream<Result<Event, Infallible>>,
    cancellation: CancellationToken,
}

impl futures_core::Stream for CancelOnDropStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(context)
    }
}

impl Drop for CancelOnDropStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn json_event(value: Value) -> Event {
    Event::default()
        .json_data(value)
        .expect("JSON value is serializable")
}

fn named_event(name: &'static str, value: Value) -> Event {
    Event::default()
        .event(name)
        .json_data(value)
        .expect("JSON value is serializable")
}

fn chat_completion(request: &GenerationRequest, output: &GenerationOutput, created: u64) -> Value {
    let (message, finish_reason) = if output.tool_calls.is_empty() {
        (json!({"role": "assistant", "content": output.text}), "stop")
    } else {
        (
            json!({
                "role": "assistant",
                "content": output.text,
                "tool_calls": output.tool_calls.iter().map(|call| json!({
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": call.arguments}
                })).collect::<Vec<_>>()
            }),
            "tool_calls",
        )
    };
    json!({
        "id": request.request_id,
        "object": "chat.completion",
        "created": created,
        "model": request.model,
        "choices": [{"index":0,"message":message,"finish_reason":finish_reason}],
        "usage": chat_usage(output.usage)
    })
}

fn chat_usage(usage: Usage) -> Value {
    json!({
        "prompt_tokens":usage.input_tokens,
        "completion_tokens":usage.output_tokens,
        "total_tokens":usage.total_tokens
    })
}

fn response_failure(response_id: &str, model: &str, error: PortError, created: u64) -> Response {
    let api = provider_api_error(error);
    let code = api.body["error"]["type"].as_str().unwrap_or("api_error");
    let message = api.body["error"]["message"]
        .as_str()
        .unwrap_or("internal error");
    json_response(
        api.status,
        &response_resource(
            response_id,
            model,
            "failed",
            &[],
            Usage::default(),
            Some((code, message)),
            created,
        ),
    )
}

fn chat_chunk(
    request: &GenerationRequest,
    created: u64,
    delta: &Value,
    finish_reason: &Value,
) -> Value {
    json!({
        "id": request.request_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": request.model,
        "choices": [{"index":0,"delta":delta,"finish_reason":finish_reason}]
    })
}

fn response_items(state: &ApiState, item_id: &str, output: &GenerationOutput) -> Vec<Value> {
    let mut items = Vec::new();
    if !output.text.is_empty() || output.tool_calls.is_empty() {
        items.push(assistant_item(
            item_id,
            if output.text.is_empty() {
                "No response from OpenClaw."
            } else {
                &output.text
            },
            Some(if output.tool_calls.is_empty() {
                "final_answer"
            } else {
                "commentary"
            }),
            Some("completed"),
        ));
    }
    items.extend(
        output
            .tool_calls
            .iter()
            .map(|call| function_call_item(&state.id("call"), call, Some("completed"))),
    );
    items
}

fn assistant_item(id: &str, text: &str, phase: Option<&str>, status: Option<&str>) -> Value {
    let mut value = json!({
        "type":"message",
        "id":id,
        "role":"assistant",
        "content":[{"type":"output_text","text":text}]
    });
    if let Some(phase) = phase {
        value["phase"] = json!(phase);
    }
    if let Some(status) = status {
        value["status"] = json!(status);
    }
    value
}

fn function_call_item(id: &str, call: &ToolCall, status: Option<&str>) -> Value {
    let mut value = json!({
        "type":"function_call",
        "id":id,
        "call_id":call.id,
        "name":call.name,
        "arguments":call.arguments
    });
    if let Some(status) = status {
        value["status"] = json!(status);
    }
    value
}

fn response_resource(
    id: &str,
    model: &str,
    status: &str,
    output: &[Value],
    usage: Usage,
    error: Option<(&str, &str)>,
    created: u64,
) -> Value {
    let mut value = json!({
        "id":id,
        "object":"response",
        "created_at":created,
        "status":status,
        "model":model,
        "output":output,
        "usage":usage
    });
    if let Some((code, message)) = error {
        value["error"] = json!({"code":code,"message":message});
    }
    value
}

fn embedding_inputs(input: Option<Value>) -> Result<Vec<String>, ApiError> {
    match input {
        Some(Value::String(value)) => Ok(vec![value]),
        Some(Value::Array(values)) if values.iter().all(Value::is_string) => Ok(values
            .into_iter()
            .map(|value| value.as_str().expect("checked string").to_owned())
            .collect()),
        _ => Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "`input` must be a string or an array of strings.",
            "invalid_request_error",
        )),
    }
}

/// Resolves the optional `dimensions` request field into a provider width.
///
/// A value that cannot be a width at all — absent, `null`, non-numeric,
/// negative, or below one — keeps its long-standing meaning of "let the provider
/// choose", so `0` and `0.5` now take the same path instead of `0.5` flooring
/// into a zero-width vector. A well-formed width above
/// [`MAX_EMBEDDING_DIMENSIONS`] is the only shape that is refused, because it is
/// the only one that can exhaust the host.
///
/// # Errors
///
/// Returns a `400` [`ApiError::openai`] with type `invalid_request_error` when
/// the requested width exceeds [`MAX_EMBEDDING_DIMENSIONS`], matching how the
/// route already refuses an oversized `input`.
fn embedding_dimensions(dimensions: Option<&Value>) -> Result<Option<usize>, ApiError> {
    let Some(requested) = dimensions.and_then(Value::as_f64) else {
        return Ok(None);
    };
    if !requested.is_finite() || requested < 1.0 {
        return Ok(None);
    }
    // `MAX_EMBEDDING_DIMENSIONS` converts to `f64` exactly, so this comparison
    // is exact and rejects every larger value — including infinities-adjacent
    // magnitudes like `1e300` — before anything is converted to an integer.
    let width = requested.floor();
    if width > f64::from(MAX_EMBEDDING_DIMENSIONS) {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            format!("Dimensions too large (max {MAX_EMBEDDING_DIMENSIONS})."),
            "invalid_request_error",
        ));
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the checks above prove `width` is an integral `f64` in `1..=MAX_EMBEDDING_DIMENSIONS`, which every `usize` represents exactly, so neither truncation nor a sign change is reachable"
    )]
    let width = width as usize;
    Ok(Some(width))
}

fn validate_embedding_inputs(input: &[String]) -> Result<(), ApiError> {
    if input.len() > 128 {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "Too many inputs (max 128).",
            "invalid_request_error",
        ));
    }
    let mut total = 0;
    for value in input {
        let length = value.encode_utf16().count();
        if length > 8_192 {
            return Err(ApiError::openai(
                StatusCode::BAD_REQUEST,
                "Input too long (max 8192 chars).",
                "invalid_request_error",
            ));
        }
        total += length;
        if total > 65_536 {
            return Err(ApiError::openai(
                StatusCode::BAD_REQUEST,
                "Total input too large (max 65536 chars).",
                "invalid_request_error",
            ));
        }
    }
    Ok(())
}

fn validate_model(state: &ApiState, model: &str) -> Result<(), ApiError> {
    if !is_model_reference(model) || !model_ids(state).contains(&model.to_owned()) {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "Invalid `model`. Use `openclaw` or `openclaw/<agentId>`.",
            "invalid_request_error",
        ));
    }
    Ok(())
}

fn is_model_reference(model: &str) -> bool {
    model == "openclaw"
        || model == "openclaw/default"
        || model.strip_prefix("openclaw/").is_some_and(|agent| {
            !agent.is_empty()
                && agent.len() <= 64
                && agent.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'-'))
                })
        })
}

struct ParsedPrompt {
    message: String,
    instructions: Option<String>,
    media: Vec<InputMedia>,
}

fn chat_prompt(messages: Option<&Value>) -> Result<ParsedPrompt, ApiError> {
    let messages = messages.and_then(Value::as_array).ok_or_else(|| {
        ApiError::openai(
            StatusCode::BAD_REQUEST,
            "Missing user message in `messages`.",
            "invalid_request_error",
        )
    })?;
    let active_user_index = messages
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, message)| {
            let role = message.as_object()?.get("role")?.as_str()?;
            matches!(role, "user" | "tool" | "function").then_some((index, role))
        });
    let mut lines = Vec::new();
    let mut instructions = Vec::new();
    let mut media = Vec::new();
    for (index, message) in messages.iter().enumerate() {
        let Some(object) = message.as_object() else {
            continue;
        };
        let Some(role) = object.get("role").and_then(Value::as_str) else {
            continue;
        };
        let mut content = content_text(object.get("content")).trim().to_owned();
        if matches!(role, "system" | "developer") {
            if !content.is_empty() {
                instructions.push(content);
            }
            continue;
        }
        let normalized_role = if role == "function" { "tool" } else { role };
        if !matches!(normalized_role, "user" | "assistant" | "tool") {
            continue;
        }
        if active_user_index == Some((index, "user")) {
            let active_media = chat_media(object.get("content"))?;
            if content.is_empty() && !active_media.is_empty() {
                "User sent image(s) with no text.".clone_into(&mut content);
            }
            media = active_media;
        }
        if !content.is_empty() {
            lines.push(format!("{normalized_role}: {content}"));
        }
    }
    if lines.is_empty() && media.is_empty() {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "Missing user message in `messages`.",
            "invalid_request_error",
        ));
    }
    Ok(ParsedPrompt {
        message: lines.join("\n\n"),
        instructions: (!instructions.is_empty()).then(|| instructions.join("\n\n")),
        media,
    })
}

fn responses_prompt(input: &Value) -> Result<ParsedPrompt, ApiError> {
    if let Some(text) = input.as_str()
        && !text.is_empty()
    {
        return Ok(ParsedPrompt {
            message: text.to_owned(),
            instructions: None,
            media: Vec::new(),
        });
    }
    let mut lines = Vec::new();
    let mut instructions = Vec::new();
    let mut media = Vec::new();
    let items = input.as_array().ok_or_else(invalid_responses)?;
    let active_user_index = items.iter().rposition(|item| {
        item.as_object().is_some_and(|object| {
            object.get("type").and_then(Value::as_str) == Some("message")
                && object.get("role").and_then(Value::as_str) == Some("user")
        })
    });
    if let Some(items) = input.as_array() {
        for (index, item) in items.iter().enumerate() {
            let Some(object) = item.as_object() else {
                return Err(invalid_responses());
            };
            match object.get("type").and_then(Value::as_str) {
                Some("message") => {
                    let role = object.get("role").and_then(Value::as_str).unwrap_or("");
                    let mut text = content_text(object.get("content")).trim().to_owned();
                    let item_media = response_media(object.get("content"))?;
                    if role == "user" && active_user_index == Some(index) && text.is_empty() {
                        if item_media
                            .iter()
                            .any(|input| input.kind == InputMediaKind::Image)
                        {
                            "User sent image(s) with no text.".clone_into(&mut text);
                        } else if !item_media.is_empty() {
                            "User sent file(s) with no text.".clone_into(&mut text);
                        }
                    }
                    media.extend(item_media);
                    if matches!(role, "system" | "developer") {
                        if !text.is_empty() {
                            instructions.push(text);
                        }
                    } else if !text.is_empty() {
                        lines.push(format!("{role}: {text}"));
                    }
                }
                Some("function_call_output") => {
                    if let (Some(call_id), Some(output)) = (
                        object.get("call_id").and_then(Value::as_str),
                        object.get("output").and_then(Value::as_str),
                    ) {
                        lines.push(format!("tool {call_id}: {output}"));
                    }
                }
                Some("function_call" | "reasoning" | "item_reference") => {}
                _ => return Err(invalid_responses()),
            }
        }
    }
    if lines.is_empty() {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "Missing user message in `input`.",
            "invalid_request_error",
        ));
    }
    validate_media_limits(&media)?;
    Ok(ParsedPrompt {
        message: lines.join("\n\n"),
        instructions: (!instructions.is_empty()).then(|| instructions.join("\n\n")),
        media,
    })
}

fn content_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| {
                let object = part.as_object()?;
                match object.get("type").and_then(Value::as_str) {
                    Some("text" | "input_text" | "output_text") => {
                        object.get("text").and_then(Value::as_str)
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

const MAX_MEDIA_PARTS: usize = 8;
const MAX_TOTAL_MEDIA_BYTES: usize = 20 * 1024 * 1024;
const IMAGE_MEDIA_TYPES: [&str; 6] = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/heic",
    "image/heif",
];

fn chat_media(content: Option<&Value>) -> Result<Vec<InputMedia>, ApiError> {
    let Some(parts) = content.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut media = Vec::new();
    for part in parts {
        let Some(object) = part.as_object() else {
            continue;
        };
        if object.get("type").and_then(Value::as_str) != Some("image_url") {
            continue;
        }
        let image_url = object.get("image_url");
        let source = image_url
            .and_then(Value::as_str)
            .or_else(|| {
                image_url
                    .and_then(Value::as_object)
                    .and_then(|value| value.get("url"))
                    .and_then(Value::as_str)
            })
            .ok_or_else(invalid_chat_image)?;
        media.push(InputMedia {
            kind: InputMediaKind::Image,
            source: parse_chat_image_source(source)?,
        });
    }
    validate_media_limits(&media).map_err(|_| invalid_chat_image())?;
    Ok(media)
}

fn parse_chat_image_source(source: &str) -> Result<InputMediaSource, ApiError> {
    let source = source.trim();
    let Some(data_uri) = source.strip_prefix("data:") else {
        return Err(invalid_chat_image());
    };
    let (metadata, data) = data_uri.split_once(',').ok_or_else(invalid_chat_image)?;
    let mut metadata = metadata.split(';');
    let media_type = metadata.next().unwrap_or("").trim().to_ascii_lowercase();
    let base64 = metadata.any(|part| part.eq_ignore_ascii_case("base64"));
    if !base64 || data.is_empty() || !IMAGE_MEDIA_TYPES.contains(&media_type.as_str()) {
        return Err(invalid_chat_image());
    }
    STANDARD.decode(data).map_err(|_| invalid_chat_image())?;
    Ok(InputMediaSource::Base64 {
        media_type,
        data: data.to_owned(),
        filename: None,
    })
}

fn response_media(content: Option<&Value>) -> Result<Vec<InputMedia>, ApiError> {
    let Some(parts) = content.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut media = Vec::new();
    for part in parts {
        let Some(object) = part.as_object() else {
            return Err(invalid_responses());
        };
        let kind = match object.get("type").and_then(Value::as_str) {
            Some("input_image") => InputMediaKind::Image,
            Some("input_file") => InputMediaKind::File,
            _ => continue,
        };
        let source = object
            .get("source")
            .and_then(Value::as_object)
            .ok_or_else(invalid_responses)?;
        let source = match source.get("type").and_then(Value::as_str) {
            Some("url") => {
                let url = source
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or_else(invalid_responses)?;
                let parsed = Url::parse(url).map_err(|_| invalid_responses())?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err(invalid_responses());
                }
                InputMediaSource::Url(url.to_owned())
            }
            Some("base64") => {
                let media_type = source
                    .get("media_type")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(invalid_responses)?;
                if kind == InputMediaKind::Image && !IMAGE_MEDIA_TYPES.contains(&media_type) {
                    return Err(invalid_responses());
                }
                let data = source
                    .get("data")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(invalid_responses)?;
                STANDARD.decode(data).map_err(|_| invalid_responses())?;
                InputMediaSource::Base64 {
                    media_type: media_type.to_owned(),
                    data: data.to_owned(),
                    filename: source
                        .get("filename")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                }
            }
            _ => return Err(invalid_responses()),
        };
        media.push(InputMedia { kind, source });
    }
    Ok(media)
}

fn validate_media_limits(media: &[InputMedia]) -> Result<(), ApiError> {
    if media.len() > MAX_MEDIA_PARTS {
        return Err(invalid_responses());
    }
    let total = media.iter().try_fold(0_usize, |total, input| {
        let bytes = match &input.source {
            InputMediaSource::Url(_) => 0,
            InputMediaSource::Base64 { data, .. } => STANDARD
                .decode(data)
                .map_err(|_| invalid_responses())?
                .len(),
        };
        total.checked_add(bytes).ok_or_else(invalid_responses)
    })?;
    if total > MAX_TOTAL_MEDIA_BYTES {
        return Err(invalid_responses());
    }
    Ok(())
}

fn validate_responses_body(value: &Value) -> Result<(), ApiError> {
    let object = value.as_object().ok_or_else(invalid_responses)?;
    require_only_keys(
        object,
        &[
            "model",
            "input",
            "instructions",
            "tools",
            "tool_choice",
            "stream",
            "max_output_tokens",
            "max_tool_calls",
            "user",
            "temperature",
            "top_p",
            "metadata",
            "store",
            "previous_response_id",
            "reasoning",
            "truncation",
        ],
    )?;
    validate_response_input(object.get("input").ok_or_else(invalid_responses)?)?;
    if let Some(metadata) = object.get("metadata") {
        let metadata = metadata.as_object().ok_or_else(invalid_responses)?;
        if !metadata.values().all(Value::is_string) {
            return Err(invalid_responses());
        }
    }
    for field in ["max_output_tokens", "max_tool_calls"] {
        if object
            .get(field)
            .is_some_and(|value| value.as_u64().is_none_or(|value| value == 0))
        {
            return Err(invalid_responses());
        }
    }
    if let Some(reasoning) = object.get("reasoning") {
        let reasoning = reasoning.as_object().ok_or_else(invalid_responses)?;
        require_only_keys(reasoning, &["effort", "summary"])?;
        if reasoning
            .get("effort")
            .is_some_and(|value| !matches!(value.as_str(), Some("low" | "medium" | "high")))
            || reasoning.get("summary").is_some_and(|value| {
                !matches!(value.as_str(), Some("auto" | "concise" | "detailed"))
            })
        {
            return Err(invalid_responses());
        }
    }
    if object
        .get("truncation")
        .is_some_and(|value| value.as_str() != Some("auto"))
    {
        return Err(invalid_responses());
    }
    if object.get("store").and_then(Value::as_bool) == Some(false) {
        return Err(invalid_responses());
    }
    if let Some(tools) = object.get("tools") {
        let tools = tools.as_array().ok_or_else(invalid_responses)?;
        for tool in tools {
            let tool = tool.as_object().ok_or_else(invalid_responses)?;
            require_only_keys(
                tool,
                &["type", "name", "description", "parameters", "strict"],
            )?;
            if tool.get("type").and_then(Value::as_str) != Some("function")
                || tool
                    .get("name")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || tool
                    .get("parameters")
                    .is_some_and(|value| !value.is_object())
            {
                return Err(invalid_responses());
            }
        }
    }
    if let Some(choice) = object.get("tool_choice") {
        validate_response_tool_choice(choice)?;
    }
    Ok(())
}

fn validate_response_input(input: &Value) -> Result<(), ApiError> {
    if input.is_string() {
        return Ok(());
    }
    let items = input.as_array().ok_or_else(invalid_responses)?;
    for item in items {
        let object = item.as_object().ok_or_else(invalid_responses)?;
        match object.get("type").and_then(Value::as_str) {
            Some("message") => {
                require_only_keys(object, &["type", "role", "content", "phase"])?;
                let role = object.get("role").and_then(Value::as_str);
                if !matches!(role, Some("system" | "developer" | "user" | "assistant")) {
                    return Err(invalid_responses());
                }
                if object.get("phase").is_some_and(|phase| {
                    role != Some("assistant")
                        || !matches!(phase.as_str(), Some("commentary" | "final_answer"))
                }) {
                    return Err(invalid_responses());
                }
                validate_response_content(object.get("content").ok_or_else(invalid_responses)?)?;
            }
            Some("function_call") => {
                require_only_keys(object, &["type", "id", "call_id", "name", "arguments"])?;
                if !["name", "arguments"]
                    .iter()
                    .all(|field| object.get(*field).is_some_and(Value::is_string))
                    || ["id", "call_id"]
                        .iter()
                        .any(|field| object.get(*field).is_some_and(|value| !value.is_string()))
                {
                    return Err(invalid_responses());
                }
            }
            Some("function_call_output") => {
                require_only_keys(object, &["type", "call_id", "output"])?;
                if !["call_id", "output"]
                    .iter()
                    .all(|field| object.get(*field).is_some_and(Value::is_string))
                {
                    return Err(invalid_responses());
                }
            }
            Some("reasoning") => {
                require_only_keys(object, &["type", "content", "encrypted_content", "summary"])?;
                if ["content", "encrypted_content", "summary"]
                    .iter()
                    .any(|field| object.get(*field).is_some_and(|value| !value.is_string()))
                {
                    return Err(invalid_responses());
                }
            }
            Some("item_reference") => {
                require_only_keys(object, &["type", "id"])?;
                if !object.get("id").is_some_and(Value::is_string) {
                    return Err(invalid_responses());
                }
            }
            _ => return Err(invalid_responses()),
        }
    }
    Ok(())
}

fn validate_response_content(content: &Value) -> Result<(), ApiError> {
    if content.is_string() {
        return Ok(());
    }
    let parts = content.as_array().ok_or_else(invalid_responses)?;
    for part in parts {
        let part = part.as_object().ok_or_else(invalid_responses)?;
        match part.get("type").and_then(Value::as_str) {
            Some("input_text" | "output_text") => {
                require_only_keys(part, &["type", "text"])?;
                if !part.get("text").is_some_and(Value::is_string) {
                    return Err(invalid_responses());
                }
            }
            Some("input_image" | "input_file") => {
                require_only_keys(part, &["type", "source"])?;
                validate_response_media_source(
                    part.get("source").ok_or_else(invalid_responses)?,
                    part.get("type").and_then(Value::as_str) == Some("input_file"),
                )?;
            }
            _ => return Err(invalid_responses()),
        }
    }
    Ok(())
}

fn validate_response_media_source(source: &Value, file: bool) -> Result<(), ApiError> {
    let source = source.as_object().ok_or_else(invalid_responses)?;
    match source.get("type").and_then(Value::as_str) {
        Some("url") => {
            require_only_keys(source, &["type", "url"])?;
            let url = source
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(invalid_responses)?;
            let url = Url::parse(url).map_err(|_| invalid_responses())?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(invalid_responses());
            }
        }
        Some("base64") => {
            let keys = if file {
                &["type", "media_type", "data", "filename"][..]
            } else {
                &["type", "media_type", "data"][..]
            };
            require_only_keys(source, keys)?;
            let media_type = source
                .get("media_type")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(invalid_responses)?;
            if !file && !IMAGE_MEDIA_TYPES.contains(&media_type) {
                return Err(invalid_responses());
            }
            let data = source
                .get("data")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(invalid_responses)?;
            STANDARD.decode(data).map_err(|_| invalid_responses())?;
            if source
                .get("filename")
                .is_some_and(|value| !value.is_string())
            {
                return Err(invalid_responses());
            }
        }
        _ => return Err(invalid_responses()),
    }
    Ok(())
}

fn validate_response_tool_choice(choice: &Value) -> Result<(), ApiError> {
    if matches!(choice.as_str(), Some("auto" | "none" | "required")) {
        return Ok(());
    }
    let object = choice.as_object().ok_or_else(invalid_responses)?;
    if object.get("type").and_then(Value::as_str) != Some("function") {
        return Err(invalid_responses());
    }
    let name = if object.contains_key("name") {
        require_only_keys(object, &["type", "name"])?;
        object.get("name").and_then(Value::as_str)
    } else {
        require_only_keys(object, &["type", "function"])?;
        object
            .get("function")
            .and_then(Value::as_object)
            .and_then(|function| {
                require_only_keys(function, &["name"]).ok()?;
                function.get("name").and_then(Value::as_str)
            })
    };
    if name.is_none_or(str::is_empty) {
        return Err(invalid_responses());
    }
    Ok(())
}

fn require_only_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), ApiError> {
    if object.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(invalid_responses())
    }
}

fn parse_stop(stop: Option<&Value>) -> Result<Option<Vec<String>>, ApiError> {
    let Some(stop) = stop.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let values = match stop {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| invalid_stop("stop entries must be non-empty strings"))?,
        _ => return Err(invalid_stop("stop must be a string or array of strings")),
    };
    if values.len() > 4 {
        return Err(invalid_stop("stop supports at most 4 sequences"));
    }
    if values.iter().any(String::is_empty) {
        return Err(invalid_stop("stop entries must be non-empty strings"));
    }
    Ok((!values.is_empty()).then_some(values))
}

fn parse_response_format(value: Option<&Value>) -> Result<Option<Value>, ApiError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let object = value.as_object().ok_or_else(|| {
        ApiError::openai(
            StatusCode::BAD_REQUEST,
            "Invalid response_format: response_format must be an object",
            "invalid_request_error",
        )
    })?;
    if !matches!(
        object.get("type").and_then(Value::as_str),
        Some("text" | "json_object")
    ) || object.len() != 1
    {
        return Err(ApiError::openai(
            StatusCode::BAD_REQUEST,
            "Invalid response_format: only text and json_object are supported",
            "invalid_request_error",
        ));
    }
    Ok(Some(value.clone()))
}

fn invalid_stop(message: &str) -> ApiError {
    ApiError::openai(
        StatusCode::BAD_REQUEST,
        format!("Invalid stop: {message}"),
        "invalid_request_error",
    )
}

fn invalid_chat_image() -> ApiError {
    ApiError::openai(
        StatusCode::BAD_REQUEST,
        "Invalid image_url content in `messages`.",
        "invalid_request_error",
    )
}

fn join_instructions(first: Option<String>, second: Option<String>) -> Option<String> {
    let parts = [first, second]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| parts.join("\n\n"))
}

fn parse_chat_tools(value: Option<&Value>) -> Result<Vec<ClientTool>, ApiError> {
    let Some(values) = value else {
        return Ok(Vec::new());
    };
    let values = values.as_array().ok_or_else(invalid_tools)?;
    values
        .iter()
        .map(|value| {
            let object = value.as_object().ok_or_else(invalid_tools)?;
            if object.get("type").and_then(Value::as_str) != Some("function") {
                return Err(invalid_tools());
            }
            let function = object
                .get("function")
                .and_then(Value::as_object)
                .ok_or_else(invalid_tools)?;
            let name = function
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(invalid_tools)?;
            if function
                .get("strict")
                .is_some_and(|strict| !strict.is_null() && strict.as_bool() != Some(false))
            {
                return Err(invalid_tools());
            }
            Ok(ClientTool {
                name: name.to_owned(),
                description: function
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                parameters: function.get("parameters").cloned(),
            })
        })
        .collect()
}

fn parse_response_tools(tools: Option<Vec<ResponseTool>>) -> Result<Vec<ClientTool>, ApiError> {
    tools
        .unwrap_or_default()
        .into_iter()
        .map(|tool| {
            if tool.kind != "function" || tool.name.trim().is_empty() || tool.strict == Some(true) {
                return Err(invalid_tools());
            }
            Ok(ClientTool {
                name: tool.name,
                description: tool.description,
                parameters: tool.parameters,
            })
        })
        .collect()
}

fn parse_tool_choice(value: Option<&Value>, tools: &[ClientTool]) -> Result<ToolChoice, ApiError> {
    let Some(value) = value else {
        return Ok(ToolChoice::Auto);
    };
    if let Some(choice) = value.as_str() {
        return match choice {
            "auto" => Ok(ToolChoice::Auto),
            "none" => Ok(ToolChoice::None),
            "required" if !tools.is_empty() => Ok(ToolChoice::Required),
            _ => Err(invalid_tools()),
        };
    }
    let object = value.as_object().ok_or_else(invalid_tools)?;
    if object.get("type").and_then(Value::as_str) != Some("function") {
        return Err(invalid_tools());
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| {
            object
                .get("function")
                .and_then(Value::as_object)
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
        })
        .filter(|name| tools.iter().any(|tool| tool.name == *name))
        .ok_or_else(invalid_tools)?;
    Ok(ToolChoice::Function(name.to_owned()))
}

fn enforce_tool_choice(
    choice: &ToolChoice,
    tools: &[ClientTool],
    calls: &[ToolCall],
) -> Result<(), ApiError> {
    if matches!(choice, ToolChoice::None) && !calls.is_empty() {
        return Err(output_constraint_error(
            "The provider called a tool despite tool_choice being none.",
        ));
    }
    if calls
        .iter()
        .any(|call| !tools.iter().any(|tool| tool.name == call.name))
    {
        return Err(output_constraint_error(
            "The provider called a tool that was not supplied by the client.",
        ));
    }
    let satisfied = match choice {
        ToolChoice::Auto | ToolChoice::None => true,
        ToolChoice::Required => !calls.is_empty(),
        ToolChoice::Function(name) => calls.iter().any(|call| call.name == *name),
    };
    if satisfied {
        Ok(())
    } else {
        let message = match choice {
            ToolChoice::None => "The provider called a tool despite tool_choice being none.",
            ToolChoice::Required | ToolChoice::Function(_) => {
                "The model did not call the required tool."
            }
            ToolChoice::Auto => "The provider violated the requested tool policy.",
        };
        Err(output_constraint_error(message))
    }
}

const fn tool_choice_requires_validation(choice: &ToolChoice) -> bool {
    !matches!(choice, ToolChoice::Auto)
}

const fn generation_requires_output_validation(request: &GenerationRequest) -> bool {
    tool_choice_requires_validation(&request.tool_choice)
        || request.max_tokens.is_some()
        || request.max_tool_calls.is_some()
        || request.stop.is_some()
        || request.response_format.is_some()
}

/// The ceiling on provider output one streaming request may retain.
///
/// A request that states `max_tokens` bounds its own legitimate response, so the
/// ceiling is derived from it; anything else gets the absolute ceiling.
fn stream_output_limit(request: &GenerationRequest) -> usize {
    request
        .max_tokens
        .and_then(|tokens| usize::try_from(tokens).ok())
        .and_then(|tokens| tokens.checked_mul(STREAM_OUTPUT_BYTES_PER_TOKEN))
        .map_or(MAX_STREAM_OUTPUT_BYTES, |bytes| {
            bytes.clamp(MIN_STREAM_OUTPUT_BYTES, MAX_STREAM_OUTPUT_BYTES)
        })
}

/// Remaining bytes of provider output one streaming coordinator may still hold.
///
/// The coordinators differ in *what* they retain — chat keeps text only while a
/// constraint is pending, Responses always keeps it, both always keep tool calls
/// — so the budget only counts bytes and the caller decides which ones it is
/// about to store.
struct StreamBudget {
    remaining: usize,
}

impl StreamBudget {
    /// Opens a budget sized for one request.
    fn new(request: &GenerationRequest) -> Self {
        Self {
            remaining: stream_output_limit(request),
        }
    }

    /// Charges `bytes` against the budget, reporting whether they still fit.
    ///
    /// A refusal leaves the budget unchanged, so the caller can only ever hold
    /// the bytes it was granted.
    const fn admits(&mut self, bytes: usize) -> bool {
        let Some(remaining) = self.remaining.checked_sub(bytes) else {
            return false;
        };
        self.remaining = remaining;
        true
    }
}

/// Bytes one provider event adds to what a coordinator keeps until the stream ends.
///
/// Chat forwards text deltas immediately unless a constraint is pending, so
/// `retains_text` is what that coordinator decided; both coordinators retain
/// every tool call, because the terminal framing and the final tool-choice check
/// are computed from the complete list.
const fn retained_bytes(event: &GenerationEvent, retains_text: bool) -> usize {
    match event {
        GenerationEvent::Text(text) => {
            if retains_text {
                text.len()
            } else {
                0
            }
        }
        GenerationEvent::ToolCall(call) => call.id.len() + call.name.len() + call.arguments.len(),
    }
}

/// The upstream fault reported when a provider overruns the retained-output ceiling.
fn oversized_stream_error() -> ApiError {
    output_constraint_error("The provider exceeded the maximum buffered response size.")
}

fn enforce_output_constraints(
    request: &GenerationRequest,
    output: &mut GenerationOutput,
) -> Result<(), ApiError> {
    if request
        .max_tokens
        .is_some_and(|limit| output.usage.output_tokens > limit)
    {
        return Err(output_constraint_error(
            "The provider exceeded the requested output token limit.",
        ));
    }
    if request
        .max_tool_calls
        .is_some_and(|limit| output.tool_calls.len() as u64 > limit)
    {
        return Err(output_constraint_error(
            "The provider exceeded the requested tool call limit.",
        ));
    }
    if let Some(stop) = &request.stop
        && let Some(index) = stop
            .iter()
            .filter_map(|sequence| output.text.find(sequence))
            .min()
    {
        output.text.truncate(index);
    }
    if output.tool_calls.is_empty()
        && request
            .response_format
            .as_ref()
            .and_then(|format| format.get("type"))
            .and_then(Value::as_str)
            == Some("json_object")
    {
        let value = serde_json::from_str::<Value>(&output.text).map_err(|_| {
            output_constraint_error("The provider did not return the requested JSON object.")
        })?;
        if !value.is_object() {
            return Err(output_constraint_error(
                "The provider did not return the requested JSON object.",
            ));
        }
    }
    Ok(())
}

fn output_constraint_error(message: &str) -> ApiError {
    ApiError::openai(StatusCode::BAD_GATEWAY, message, "api_error")
}

fn constraint_error_message(error: &ApiError) -> &str {
    error.body["error"]["message"]
        .as_str()
        .unwrap_or("The provider violated an output constraint.")
}

fn constrained_response_failure(
    response_id: &str,
    model: &str,
    usage: Usage,
    error: &ApiError,
) -> Response {
    json_response(
        StatusCode::BAD_GATEWAY,
        &response_resource(
            response_id,
            model,
            "failed",
            &[],
            usage,
            Some(("api_error", constraint_error_message(error))),
            unix_seconds(),
        ),
    )
}

fn tools_for_choice(mut tools: Vec<ClientTool>, choice: &ToolChoice) -> Vec<ClientTool> {
    match choice {
        ToolChoice::None => Vec::new(),
        ToolChoice::Function(name) => {
            tools.retain(|tool| tool.name == *name);
            tools
        }
        ToolChoice::Auto | ToolChoice::Required => tools,
    }
}

fn validate_sampling(body: &ChatBody) -> Result<(), ApiError> {
    for (name, value, min, max) in [
        ("temperature", body.temperature.as_ref(), 0.0, 2.0),
        ("top_p", body.top_p.as_ref(), 0.0, 1.0),
        (
            "frequency_penalty",
            body.frequency_penalty.as_ref(),
            -2.0,
            2.0,
        ),
        (
            "presence_penalty",
            body.presence_penalty.as_ref(),
            -2.0,
            2.0,
        ),
    ] {
        if let Some(value) = value {
            let Some(number) = value.as_f64() else {
                return Err(invalid_parameter(name));
            };
            if !number.is_finite() || !(min..=max).contains(&number) {
                return Err(invalid_parameter(name));
            }
        }
    }
    if body
        .seed
        .as_ref()
        .is_some_and(|value| value.as_i64().is_none())
    {
        return Err(invalid_parameter("seed"));
    }
    Ok(())
}

fn positive_u64(value: Option<&Value>, name: &str) -> Result<Option<u64>, ApiError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|number| *number > 0)
            .map(Some)
            .ok_or_else(|| invalid_parameter(name)),
    }
}

fn invalid_parameter(name: &str) -> ApiError {
    ApiError::openai(
        StatusCode::BAD_REQUEST,
        format!("Invalid {name}."),
        "invalid_request_error",
    )
}

fn invalid_tools() -> ApiError {
    ApiError::openai(
        StatusCode::BAD_REQUEST,
        "Invalid tools/tool_choice: invalid tool configuration",
        "invalid_request_error",
    )
}

fn invalid_responses() -> ApiError {
    ApiError::openai(
        StatusCode::BAD_REQUEST,
        "invalid request",
        "invalid_request_error",
    )
}

fn provider_api_error(error: PortError) -> ApiError {
    match error.kind {
        PortErrorKind::InvalidRequest => ApiError::openai(
            StatusCode::BAD_REQUEST,
            error.message,
            "invalid_request_error",
        ),
        PortErrorKind::NotFound => ApiError::openai(
            StatusCode::NOT_FOUND,
            error.message,
            "invalid_request_error",
        ),
        PortErrorKind::Unavailable => {
            ApiError::openai(StatusCode::SERVICE_UNAVAILABLE, error.message, "api_error")
        }
        PortErrorKind::Timeout => {
            ApiError::openai(StatusCode::GATEWAY_TIMEOUT, error.message, "api_error")
        }
        PortErrorKind::Internal => ApiError::openai(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal error",
            "api_error",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GenerationRequest, MAX_STREAM_OUTPUT_BYTES, MIN_STREAM_OUTPUT_BYTES,
        STREAM_OUTPUT_BYTES_PER_TOKEN, ToolChoice, stream_output_limit,
    };

    /// A request carrying nothing but the output token bound under test.
    fn request(max_tokens: Option<u64>) -> GenerationRequest {
        GenerationRequest {
            model: "openclaw".to_owned(),
            prompt: String::new(),
            instructions: None,
            media: Vec::new(),
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            max_tokens,
            max_tool_calls: None,
            temperature: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            stop: None,
            response_format: None,
            request_id: String::new(),
            session_id: String::new(),
        }
    }

    /// A request that states no output bound falls back to the absolute ceiling.
    ///
    /// This is the branch every unconstrained `/v1/responses` stream takes, and
    /// the one no wire test can reach without moving eight megabytes.
    #[test]
    fn an_unbounded_request_gets_the_absolute_ceiling() {
        assert_eq!(stream_output_limit(&request(None)), MAX_STREAM_OUTPUT_BYTES);
    }

    /// A stated bound sizes the buffer instead of the absolute ceiling.
    #[test]
    fn a_stated_token_bound_sizes_the_buffer() {
        const TOKENS: u64 = 32_768;
        const EXPECTED: usize = 32_768 * STREAM_OUTPUT_BYTES_PER_TOKEN;

        assert_eq!(stream_output_limit(&request(Some(TOKENS))), EXPECTED);
    }

    /// A tiny bound still gets the floor, where the byte ratio is least predictable.
    #[test]
    fn a_tiny_token_bound_still_gets_the_floor() {
        for tokens in [1, 16, 512] {
            assert_eq!(
                stream_output_limit(&request(Some(tokens))),
                MIN_STREAM_OUTPUT_BYTES,
                "a {tokens}-token request must keep the floor"
            );
        }
    }

    /// A bound a caller cannot honestly mean is clamped rather than trusted.
    ///
    /// `u64::MAX` also proves the derivation cannot overflow into a small or
    /// panicking limit, which is the one way this ceiling could be turned into
    /// the defect it exists to prevent.
    #[test]
    fn an_absurd_token_bound_is_clamped_to_the_ceiling() {
        for tokens in [u64::from(u32::MAX), u64::MAX] {
            assert_eq!(
                stream_output_limit(&request(Some(tokens))),
                MAX_STREAM_OUTPUT_BYTES,
                "a {tokens}-token request must not raise the ceiling"
            );
        }
    }
}

//! Explicit `OpenAI` Responses encoding and bounded response decoding.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use claw_provider_sdk::cancel::CancelToken;
use claw_provider_sdk::error::{ErrorKind, Operation, ProviderError};
use claw_provider_sdk::model::{
    AssistantMessage, ChatMessage, CompletionRequest, CompletionResponse, ContentPart,
    FinishReason, ImageSource, ModelId, ResponseFormat, ToolArguments, ToolCall, ToolChoice, Usage,
};
use claw_provider_sdk::sse::{SseDecoder, SseEvent};
use claw_provider_sdk::stream::{CompletionStream, StreamEvent};
use futures_util::StreamExt as _;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::openai_compatible::{ChunkStream, EventStream};

const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_OUTPUT_ITEMS: usize = 1024;

fn invalid(provider: &str, operation: Operation, detail: &'static str) -> ProviderError {
    ProviderError::new(ErrorKind::Protocol, provider, operation, detail)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

/// Encodes a stateless Responses request without server-side storage or built-in tools.
///
/// # Errors
/// Rejects invalid portable requests, unsupported stop/seed options, assistant images
/// and inconsistent function-result history. No network or local file access occurs.
pub fn encode_completion(
    provider: &str,
    request: &CompletionRequest,
    stream: bool,
) -> Result<String, ProviderError> {
    let operation = if stream {
        Operation::StreamCompletion
    } else {
        Operation::Complete
    };
    request.validate().map_err(|_| {
        ProviderError::new(
            ErrorKind::InvalidRequest,
            provider,
            operation,
            "Responses request violates the portable message or tool contract",
        )
    })?;
    if request.seed.is_some() || !request.stop_sequences.is_empty() {
        return Err(ProviderError::new(
            ErrorKind::Unsupported,
            provider,
            operation,
            "Responses does not support this adapter's stop-sequence or seed options",
        ));
    }
    let mut input = Vec::new();
    let mut pending_calls = BTreeSet::new();
    let mut seen_calls = BTreeSet::new();
    for message in &request.messages {
        match message {
            ChatMessage::System(text) => {
                input.push(json!({"role":"system","content":[{"type":"input_text","text":text}]}));
            }
            ChatMessage::User(parts) => {
                let content = parts
                    .iter()
                    .map(|part| match part {
                        ContentPart::Text(text) => json!({"type":"input_text","text":text}),
                        ContentPart::Image(image) => {
                            let url = match &image.source {
                                ImageSource::Url(url) => url.to_string(),
                                ImageSource::Base64(encoded) => {
                                    format!("data:{};base64,{encoded}", image.media_type.as_str())
                                }
                            };
                            json!({"type":"input_image","image_url":url})
                        }
                    })
                    .collect::<Vec<_>>();
                input.push(json!({"role":"user","content":content}));
            }
            ChatMessage::Assistant(assistant) => {
                let mut content = Vec::new();
                for part in &assistant.content {
                    let ContentPart::Text(text) = part else {
                        return Err(ProviderError::new(
                            ErrorKind::Unsupported,
                            provider,
                            operation,
                            "Responses assistant image history is not supported",
                        ));
                    };
                    content.push(json!({"type":"input_text","text":text}));
                }
                if !content.is_empty() {
                    input.push(json!({"role":"assistant","content":content}));
                }
                for call in &assistant.tool_calls {
                    if !identifier(&call.id)
                        || !identifier(&call.name)
                        || !seen_calls.insert(call.id.as_str())
                    {
                        return Err(ProviderError::new(
                            ErrorKind::InvalidRequest,
                            provider,
                            operation,
                            "Responses function history has invalid or duplicate identifiers",
                        ));
                    }
                    pending_calls.insert(call.id.as_str());
                    input.push(json!({"type":"function_call","call_id":call.id,"name":call.name,"arguments":call.arguments.as_str()}));
                }
            }
            ChatMessage::ToolResult(result) => {
                if !pending_calls.remove(result.tool_call_id.as_str()) {
                    return Err(ProviderError::new(
                        ErrorKind::InvalidRequest,
                        provider,
                        operation,
                        "Responses function output has no unmatched prior call",
                    ));
                }
                let output = if result.is_error {
                    json!({"is_error":true,"content":result.content}).to_string()
                } else {
                    result.content.clone()
                };
                input.push(json!({"type":"function_call_output","call_id":result.tool_call_id,"output":output}));
            }
        }
    }
    if !pending_calls.is_empty() {
        return Err(ProviderError::new(
            ErrorKind::InvalidRequest,
            provider,
            operation,
            "Responses history contains unanswered function calls",
        ));
    }
    let mut document =
        json!({"model":request.model.as_str(),"input":input,"stream":stream,"store":false});
    if let Some(value) = request.max_output_tokens {
        document["max_output_tokens"] = json!(value);
    }
    if let Some(value) = request.temperature() {
        document["temperature"] = json!(value);
    }
    if let Some(value) = request.top_p() {
        document["top_p"] = json!(value);
    }
    if let Some(value) = request.parallel_tool_calls {
        document["parallel_tool_calls"] = json!(value);
    }
    if !request.tools.is_empty() {
        document["tools"] = json!(request.tools.iter().map(|tool| json!({"type":"function","name":tool.name,"description":tool.description,"parameters":tool.parameters.as_map(),"strict":false})).collect::<Vec<_>>());
        document["tool_choice"] = match &request.tool_choice {
            ToolChoice::Auto => json!("auto"),
            ToolChoice::None => json!("none"),
            ToolChoice::Required => json!("required"),
            ToolChoice::Function(name) => json!({"type":"function","name":name}),
        };
    } else if matches!(
        request.tool_choice,
        ToolChoice::Required | ToolChoice::Function(_)
    ) {
        return Err(ProviderError::new(
            ErrorKind::InvalidRequest,
            provider,
            operation,
            "Responses cannot require an undeclared function",
        ));
    }
    if request.response_format == ResponseFormat::JsonObject {
        document["text"] = json!({"format":{"type":"json_object"}});
    }
    let encoded = serde_json::to_string(&document).map_err(|_| {
        ProviderError::new(
            ErrorKind::InvalidRequest,
            provider,
            operation,
            "Responses request could not be encoded",
        )
    })?;
    if encoded.len() > MAX_BODY_BYTES {
        return Err(ProviderError::new(
            ErrorKind::InvalidRequest,
            provider,
            operation,
            "Responses request exceeds its byte budget",
        ));
    }
    Ok(encoded)
}

#[derive(Deserialize)]
struct ResponseWire {
    id: String,
    model: String,
    status: String,
    output: Vec<OutputItem>,
    usage: Option<ResponseUsage>,
    incomplete_details: Option<IncompleteDetails>,
    error: Option<Value>,
}

#[derive(Deserialize)]
struct IncompleteDetails {
    reason: String,
}

#[derive(Clone, Copy, Default, Deserialize)]
struct CachedTokens {
    #[serde(default)]
    cached_tokens: u64,
}

#[derive(Clone, Copy, Default, Deserialize)]
struct ReasoningTokens {
    #[serde(default)]
    reasoning_tokens: u64,
}

#[derive(Clone, Copy, Deserialize)]
struct ResponseUsage {
    input_tokens: u64,
    output_tokens: u64,
    input_tokens_details: Option<CachedTokens>,
    output_tokens_details: Option<ReasoningTokens>,
}

impl ResponseUsage {
    fn validated(self, provider: &str, operation: Operation) -> Result<Usage, ProviderError> {
        let usage = Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cached_input_tokens: self.input_tokens_details.unwrap_or_default().cached_tokens,
            reasoning_tokens: self
                .output_tokens_details
                .unwrap_or_default()
                .reasoning_tokens,
        };
        if usage.cached_input_tokens > usage.input_tokens
            || usage.reasoning_tokens > usage.output_tokens
            || usage
                .input_tokens
                .checked_add(usage.output_tokens)
                .is_none()
        {
            return Err(invalid(
                provider,
                operation,
                "Responses usage counters are inconsistent",
            ));
        }
        Ok(usage)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum OutputItem {
    #[serde(rename = "message")]
    Message {
        id: String,
        role: String,
        status: String,
        content: Vec<OutputContent>,
    },
    #[serde(rename = "function_call")]
    Function {
        id: String,
        call_id: String,
        name: String,
        arguments: String,
        status: Option<String>,
    },
    #[serde(rename = "reasoning")]
    Reasoning {
        id: String,
        summary: Vec<SummaryText>,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum OutputContent {
    #[serde(rename = "output_text")]
    Text { text: String },
    #[serde(rename = "refusal")]
    Refusal { refusal: String },
}

#[derive(Deserialize)]
struct SummaryText {
    #[serde(rename = "type")]
    kind: String,
    text: String,
}

/// Decodes a bounded Responses result; unsupported remote built-in tools fail closed.
///
/// # Errors
/// Rejects incomplete protocol states, invalid IDs/tool arguments/usage or unsupported
/// output variants. Known output-token or content-filter stops retain visible partial text.
pub fn decode_completion(provider: &str, body: &[u8]) -> Result<CompletionResponse, ProviderError> {
    decode_response(provider, body, Operation::Complete)
}

fn decode_response(
    provider: &str,
    body: &[u8],
    operation: Operation,
) -> Result<CompletionResponse, ProviderError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(invalid(
            provider,
            operation,
            "Responses body exceeds its byte budget",
        ));
    }
    let response: ResponseWire = serde_json::from_slice(body).map_err(|_| {
        invalid(
            provider,
            operation,
            "Responses result is malformed or contains unsupported output",
        )
    })?;
    decode_wire(provider, response, operation)
}

fn decode_wire(
    provider: &str,
    response: ResponseWire,
    operation: Operation,
) -> Result<CompletionResponse, ProviderError> {
    if !identifier(&response.id)
        || response.output.len() > MAX_OUTPUT_ITEMS
        || response.error.is_some()
    {
        return Err(invalid(
            provider,
            operation,
            "Responses result has invalid identity, output count or error state",
        ));
    }
    let model = ModelId::new(response.model)
        .map_err(|_| invalid(provider, operation, "Responses result model is invalid"))?;
    let usage = response
        .usage
        .ok_or_else(|| invalid(provider, operation, "Responses terminal usage is missing"))?
        .validated(provider, operation)?;
    let mut finish_reason = match response.status.as_str() {
        "completed" if response.incomplete_details.is_none() => FinishReason::Stop,
        "incomplete" => match response
            .incomplete_details
            .as_ref()
            .map(|details| details.reason.as_str())
        {
            Some("max_output_tokens") => FinishReason::Length,
            Some("content_filter") => FinishReason::ContentFilter,
            _ => {
                return Err(invalid(
                    provider,
                    operation,
                    "Responses incomplete result has an unsupported reason",
                ));
            }
        },
        _ => {
            return Err(invalid(
                provider,
                operation,
                "Responses result is not a supported terminal state",
            ));
        }
    };
    let mut message = AssistantMessage::default();
    let mut identifiers = BTreeSet::new();
    let mut call_ids = BTreeSet::new();
    let mut bytes = 0_usize;
    let mut part_count = 0_usize;
    for item in response.output {
        let id = match &item {
            OutputItem::Message { id, .. }
            | OutputItem::Function { id, .. }
            | OutputItem::Reasoning { id, .. } => id,
        };
        if !identifier(id) || !identifiers.insert(id.clone()) {
            return Err(invalid(
                provider,
                operation,
                "Responses output IDs are invalid or duplicated",
            ));
        }
        match item {
            OutputItem::Message {
                role,
                status,
                content,
                ..
            } => {
                part_count = part_count.saturating_add(content.len());
                if role != "assistant"
                    || part_count > MAX_OUTPUT_ITEMS
                    || !(status == "completed"
                        || (response.status == "incomplete" && status == "incomplete"))
                {
                    return Err(invalid(
                        provider,
                        operation,
                        "Responses message role or status is invalid",
                    ));
                }
                for part in content {
                    let text = match part {
                        OutputContent::Text { text } => text,
                        OutputContent::Refusal { refusal } => {
                            finish_reason = FinishReason::ContentFilter;
                            refusal
                        }
                    };
                    bytes = bytes.saturating_add(text.len());
                    if bytes > MAX_OUTPUT_BYTES {
                        return Err(invalid(
                            provider,
                            operation,
                            "Responses content exceeds its output budget",
                        ));
                    }
                    message.content.push(ContentPart::Text(text));
                }
            }
            OutputItem::Function {
                call_id,
                name,
                arguments,
                status,
                ..
            } => {
                if response.status != "completed"
                    || !identifier(&call_id)
                    || !identifier(&name)
                    || !call_ids.insert(call_id.clone())
                    || status.as_ref().is_some_and(|status| status != "completed")
                    || arguments.len() > claw_provider_sdk::stream::MAX_TOOL_ARGUMENT_BYTES
                {
                    return Err(invalid(
                        provider,
                        operation,
                        "Responses function is incomplete, duplicated or invalid",
                    ));
                }
                bytes = bytes.saturating_add(arguments.len());
                if bytes > MAX_OUTPUT_BYTES {
                    return Err(invalid(
                        provider,
                        operation,
                        "Responses output exceeds its aggregate budget",
                    ));
                }
                message.tool_calls.push(ToolCall {
                    id: call_id,
                    name,
                    arguments: ToolArguments::new(arguments).map_err(|_| {
                        invalid(
                            provider,
                            operation,
                            "Responses function arguments are not a JSON object",
                        )
                    })?,
                });
            }
            OutputItem::Reasoning { summary, .. } => {
                part_count = part_count.saturating_add(summary.len());
                if part_count > MAX_OUTPUT_ITEMS {
                    return Err(invalid(
                        provider,
                        operation,
                        "Responses reasoning summary exceeds its aggregate item limit",
                    ));
                }
                for part in summary {
                    if part.kind != "summary_text" {
                        return Err(invalid(
                            provider,
                            operation,
                            "Responses reasoning content is unsupported",
                        ));
                    }
                    bytes = bytes.saturating_add(part.text.len());
                    if bytes > MAX_OUTPUT_BYTES {
                        return Err(invalid(
                            provider,
                            operation,
                            "Responses reasoning exceeds its output budget",
                        ));
                    }
                    message
                        .reasoning
                        .get_or_insert_with(String::new)
                        .push_str(&part.text);
                }
            }
        }
    }
    if !message.tool_calls.is_empty() {
        if finish_reason != FinishReason::Stop {
            return Err(invalid(
                provider,
                operation,
                "Responses stopped output cannot authorize function calls",
            ));
        }
        finish_reason = FinishReason::ToolCalls;
    }
    Ok(CompletionResponse {
        id: response.id,
        model,
        message,
        finish_reason,
        usage,
        usage_reporting: claw_provider_sdk::model::UsageReporting::Complete,
    })
}

#[derive(Deserialize)]
struct ResponseEvent {
    #[serde(rename = "type")]
    kind: String,
    sequence_number: u64,
    response: Option<ResponseWire>,
    item: Option<OutputItem>,
    part: Option<StreamPartWire>,
    output_index: Option<usize>,
    item_id: Option<String>,
    content_index: Option<usize>,
    summary_index: Option<usize>,
    delta: Option<String>,
    text: Option<String>,
    refusal: Option<String>,
    arguments: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum StreamPartWire {
    #[serde(rename = "output_text")]
    Text { text: String },
    #[serde(rename = "refusal")]
    Refusal { refusal: String },
    #[serde(rename = "summary_text")]
    Summary { text: String },
}

struct StreamPart {
    refusal: bool,
    text: String,
    finished: bool,
    closed: bool,
}

impl StreamPart {
    const fn new(refusal: bool) -> Self {
        Self {
            refusal,
            text: String::new(),
            finished: false,
            closed: false,
        }
    }
}

struct StreamItem {
    id: String,
    kind: &'static str,
    parts: BTreeMap<usize, StreamPart>,
    call: Option<(String, String, String)>,
    arguments_done: bool,
    done: bool,
}

#[derive(Default)]
struct ResponsesDecoder {
    identity: Option<(String, String)>,
    sequence: Option<u64>,
    items: BTreeMap<usize, StreamItem>,
    retained_bytes: usize,
    part_count: usize,
    text_position: Option<(usize, usize)>,
    reasoning_position: Option<(usize, usize)>,
    completed: bool,
}

impl ResponsesDecoder {
    fn accept(
        &mut self,
        provider: &str,
        event: &SseEvent,
    ) -> Result<Vec<StreamEvent>, ProviderError> {
        let failure = || {
            invalid(
                provider,
                Operation::StreamCompletion,
                "Responses stream is inconsistent, incomplete or unsupported",
            )
        };
        if event.data.trim().is_empty() {
            return Ok(Vec::new());
        }
        if self.completed || event.data.len() > MAX_BODY_BYTES {
            return Err(failure());
        }
        let frame: ResponseEvent = serde_json::from_str(&event.data).map_err(|_| failure())?;
        if event.event != "message" && !event.event.is_empty() && event.event != frame.kind {
            return Err(failure());
        }
        if self
            .sequence
            .map_or(frame.sequence_number != 0, |previous| {
                previous.checked_add(1) != Some(frame.sequence_number)
            })
        {
            return Err(failure());
        }
        self.sequence = Some(frame.sequence_number);
        if frame.kind == "response.created" {
            let response = frame.response.ok_or_else(failure)?;
            if self.identity.is_some()
                || !identifier(&response.id)
                || !identifier(&response.model)
                || !response.output.is_empty()
                || !matches!(response.status.as_str(), "queued" | "in_progress")
            {
                return Err(failure());
            }
            self.identity = Some((response.id.clone(), response.model.clone()));
            return Ok(vec![StreamEvent::Started {
                id: response.id,
                model: response.model,
            }]);
        }
        let (id, model) = self.identity.as_ref().ok_or_else(failure)?;
        if matches!(
            frame.kind.as_str(),
            "response.completed" | "response.incomplete"
        ) {
            let response = frame.response.ok_or_else(failure)?;
            if response.id != *id
                || response.model != *model
                || frame.kind != format!("response.{}", response.status)
                || response.output.len() != self.items.len()
            {
                return Err(failure());
            }
            for (index, item) in response.output.iter().enumerate() {
                if !self.matches_item(index, item) {
                    return Err(failure());
                }
            }
            let response = decode_wire(provider, response, Operation::StreamCompletion)?;
            let mut events = Vec::new();
            for (index, call) in response.message.tool_calls.into_iter().enumerate() {
                events.push(StreamEvent::ToolCallStarted {
                    index,
                    id: call.id.clone(),
                    name: call.name.clone(),
                });
                events.push(StreamEvent::ToolCallArgumentsDelta {
                    index,
                    delta: call.arguments.as_str().to_owned(),
                });
                events.push(StreamEvent::ToolCallCompleted { index, call });
            }
            events.push(StreamEvent::UsageReported {
                usage: response.usage,
                reporting: response.usage_reporting,
            });
            events.push(StreamEvent::Completed {
                finish_reason: response.finish_reason,
                usage: response.usage,
            });
            self.completed = true;
            return Ok(events);
        }
        if matches!(
            frame.kind.as_str(),
            "response.queued" | "response.in_progress"
        ) {
            let response = frame.response.ok_or_else(failure)?;
            if response.id != *id
                || response.model != *model
                || frame.kind != format!("response.{}", response.status)
            {
                return Err(failure());
            }
            return Ok(Vec::new());
        }
        let index = frame
            .output_index
            .filter(|index| *index < MAX_OUTPUT_ITEMS)
            .ok_or_else(failure)?;
        if frame.kind == "response.output_item.added" {
            let item = match frame.item.ok_or_else(failure)? {
                OutputItem::Message {
                    id, role, content, ..
                } if role == "assistant" && content.is_empty() => StreamItem {
                    id,
                    kind: "message",
                    parts: BTreeMap::new(),
                    call: None,
                    arguments_done: false,
                    done: false,
                },
                OutputItem::Reasoning { id, summary } if summary.is_empty() => StreamItem {
                    id,
                    kind: "reasoning",
                    parts: BTreeMap::new(),
                    call: None,
                    arguments_done: false,
                    done: false,
                },
                OutputItem::Function {
                    id,
                    call_id,
                    name,
                    arguments,
                    ..
                } if identifier(&call_id) && identifier(&name) && arguments.is_empty() => {
                    StreamItem {
                        id,
                        kind: "function_call",
                        parts: BTreeMap::new(),
                        call: Some((call_id, name, arguments)),
                        arguments_done: false,
                        done: false,
                    }
                }
                _ => return Err(failure()),
            };
            if !identifier(&item.id)
                || self.items.contains_key(&index)
                || self.items.values().any(|existing| existing.id == item.id)
            {
                return Err(failure());
            }
            self.items.insert(index, item);
            return Ok(Vec::new());
        }
        if frame.kind == "response.output_item.done" {
            if !self.matches_item(index, &frame.item.ok_or_else(failure)?) {
                return Err(failure());
            }
            let item = self.items.get_mut(&index).ok_or_else(failure)?;
            if item.done {
                return Err(failure());
            }
            item.done = true;
            return Ok(Vec::new());
        }
        let item = self.items.get_mut(&index).ok_or_else(failure)?;
        if frame.item_id.as_deref() != Some(&item.id) || item.done {
            return Err(failure());
        }
        if frame.kind == "response.function_call_arguments.delta" {
            let (_, _, arguments) = item.call.as_mut().ok_or_else(failure)?;
            let delta = frame.delta.ok_or_else(failure)?;
            if item.arguments_done
                || arguments.len().saturating_add(delta.len())
                    > claw_provider_sdk::stream::MAX_TOOL_ARGUMENT_BYTES
            {
                return Err(failure());
            }
            self.retained_bytes = self.retained_bytes.saturating_add(delta.len());
            if self.retained_bytes > MAX_OUTPUT_BYTES {
                return Err(failure());
            }
            arguments.push_str(&delta);
            return Ok(Vec::new());
        }
        if frame.kind == "response.function_call_arguments.done" {
            let (_, _, arguments) = item.call.as_ref().ok_or_else(failure)?;
            if item.arguments_done || frame.arguments.as_deref() != Some(arguments) {
                return Err(failure());
            }
            item.arguments_done = true;
            return Ok(Vec::new());
        }
        let reasoning = frame.kind.starts_with("response.reasoning_summary_");
        if (reasoning && item.kind != "reasoning") || (!reasoning && item.kind != "message") {
            return Err(failure());
        }
        let part_index = if reasoning {
            frame.summary_index
        } else {
            frame.content_index
        }
        .filter(|index| *index < MAX_OUTPUT_ITEMS)
        .ok_or_else(failure)?;
        let refusal = frame.kind.starts_with("response.refusal.");
        match frame.kind.as_str() {
            "response.output_text.delta"
            | "response.reasoning_summary_text.delta"
            | "response.refusal.delta" => {
                let delta = frame.delta.ok_or_else(failure)?;
                self.retained_bytes = self.retained_bytes.saturating_add(delta.len());
                if self.retained_bytes > MAX_OUTPUT_BYTES {
                    return Err(failure());
                }
                let position = if reasoning {
                    &mut self.reasoning_position
                } else {
                    &mut self.text_position
                };
                if position.is_some_and(|previous| previous > (index, part_index)) {
                    return Err(failure());
                }
                *position = Some((index, part_index));
                if !item.parts.contains_key(&part_index) {
                    if self.part_count >= MAX_OUTPUT_ITEMS {
                        return Err(failure());
                    }
                    self.part_count += 1;
                }
                let part = item
                    .parts
                    .entry(part_index)
                    .or_insert_with(|| StreamPart::new(refusal));
                if part.refusal != refusal || part.finished {
                    return Err(failure());
                }
                part.text.push_str(&delta);
                Ok(vec![if reasoning {
                    StreamEvent::ReasoningDelta(delta)
                } else {
                    StreamEvent::TextDelta(delta)
                }])
            }
            "response.output_text.done"
            | "response.reasoning_summary_text.done"
            | "response.refusal.done" => {
                let text = if refusal { frame.refusal } else { frame.text }.ok_or_else(failure)?;
                if !item.parts.contains_key(&part_index) {
                    if !text.is_empty() || self.part_count >= MAX_OUTPUT_ITEMS {
                        return Err(failure());
                    }
                    self.part_count += 1;
                }
                let part = item
                    .parts
                    .entry(part_index)
                    .or_insert_with(|| StreamPart::new(refusal));
                if part.refusal != refusal || part.text != text || part.finished {
                    return Err(failure());
                }
                part.finished = true;
                Ok(Vec::new())
            }
            "response.content_part.added"
            | "response.content_part.done"
            | "response.reasoning_summary_part.added"
            | "response.reasoning_summary_part.done" => {
                let (refusal, text) = match (reasoning, frame.part.ok_or_else(failure)?) {
                    (false, StreamPartWire::Text { text })
                    | (true, StreamPartWire::Summary { text }) => (false, text),
                    (false, StreamPartWire::Refusal { refusal }) => (true, refusal),
                    _ => return Err(failure()),
                };
                if matches!(
                    frame.kind.as_str(),
                    "response.content_part.added" | "response.reasoning_summary_part.added"
                ) {
                    if !text.is_empty()
                        || item.parts.contains_key(&part_index)
                        || self.part_count >= MAX_OUTPUT_ITEMS
                    {
                        return Err(failure());
                    }
                    item.parts.insert(part_index, StreamPart::new(refusal));
                    self.part_count += 1;
                } else {
                    let part = item.parts.get_mut(&part_index).ok_or_else(failure)?;
                    if !part.finished || part.closed || part.refusal != refusal || part.text != text
                    {
                        return Err(failure());
                    }
                    part.closed = true;
                }
                Ok(Vec::new())
            }
            "response.output_text.annotation.added" => {
                if item
                    .parts
                    .get(&part_index)
                    .is_none_or(|part| part.refusal || part.closed)
                {
                    return Err(failure());
                }
                Ok(Vec::new())
            }
            _ => Err(failure()),
        }
    }

    fn matches_item(&self, index: usize, output: &OutputItem) -> bool {
        let Some(item) = self.items.get(&index) else {
            return false;
        };
        match output {
            OutputItem::Message {
                id, role, content, ..
            } => {
                item.kind == "message"
                    && *id == item.id
                    && role == "assistant"
                    && content.len() == item.parts.len()
                    && content.iter().enumerate().all(|(index, part)| {
                        item.parts.get(&index).is_some_and(|actual| match part {
                            OutputContent::Text { text } => !actual.refusal && *text == actual.text,
                            OutputContent::Refusal { refusal } => {
                                actual.refusal && *refusal == actual.text
                            }
                        })
                    })
            }
            OutputItem::Reasoning { id, summary } => {
                item.kind == "reasoning"
                    && *id == item.id
                    && summary.len() == item.parts.len()
                    && summary.iter().enumerate().all(|(index, part)| {
                        part.kind == "summary_text"
                            && item
                                .parts
                                .get(&index)
                                .is_some_and(|actual| !actual.refusal && actual.text == part.text)
                    })
            }
            OutputItem::Function {
                id,
                call_id,
                name,
                arguments,
                ..
            } => {
                item.kind == "function_call"
                    && *id == item.id
                    && item.arguments_done
                    && item.call.as_ref().is_some_and(|actual| {
                        actual.0 == *call_id && actual.1 == *name && actual.2 == *arguments
                    })
            }
        }
    }

    fn eof(&self, provider: &str) -> Result<(), ProviderError> {
        if self.completed {
            Ok(())
        } else {
            Err(invalid(
                provider,
                Operation::StreamCompletion,
                "Responses stream ended without a terminal response",
            ))
        }
    }
}

/// Decodes a recorded Responses SSE stream with terminal snapshot verification.
///
/// # Errors
/// Rejects malformed, reordered, inconsistent or unterminated streams.
pub fn decode_event_stream(provider: &str, body: &[u8]) -> Result<Vec<StreamEvent>, ProviderError> {
    let mut sse = SseDecoder::new();
    let mut decoder = ResponsesDecoder::default();
    let mut events = Vec::new();
    let framed = sse.push(body).map_err(|_| {
        invalid(
            provider,
            Operation::StreamCompletion,
            "Responses SSE framing failed",
        )
    })?;
    for event in framed {
        events.extend(decoder.accept(provider, &event)?);
    }
    for event in sse.finish().map_err(|_| {
        invalid(
            provider,
            Operation::StreamCompletion,
            "Responses SSE framing failed",
        )
    })? {
        events.extend(decoder.accept(provider, &event)?);
    }
    decoder.eof(provider)?;
    Ok(events)
}

pub(crate) fn event_stream(provider: String, chunks: ChunkStream) -> EventStream {
    let state = (
        chunks,
        SseDecoder::new(),
        ResponsesDecoder::default(),
        VecDeque::new(),
        false,
    );
    Box::pin(futures_util::stream::unfold(
        (state, provider),
        |((mut chunks, mut sse, mut decoder, mut pending, mut ended), provider)| async move {
            loop {
                if let Some(event) = pending.pop_front() {
                    return Some((event, ((chunks, sse, decoder, pending, ended), provider)));
                }
                if ended {
                    return None;
                }
                let framed = match chunks.next().await {
                    Some(Ok(bytes)) => sse.push(&bytes).map_err(|_| {
                        invalid(
                            &provider,
                            Operation::StreamCompletion,
                            "Responses SSE framing failed",
                        )
                    }),
                    Some(Err(error)) => {
                        ended = true;
                        Err(error)
                    }
                    None => {
                        ended = true;
                        sse.finish().map_err(|_| {
                            invalid(
                                &provider,
                                Operation::StreamCompletion,
                                "Responses SSE framing failed",
                            )
                        })
                    }
                };
                match framed {
                    Ok(events) => {
                        for event in events {
                            match decoder.accept(&provider, &event) {
                                Ok(events) => {
                                    pending.extend(events.into_iter().map(Ok));
                                    if decoder.completed {
                                        ended = true;
                                        break;
                                    }
                                }
                                Err(error) => {
                                    pending.push_back(Err(error));
                                    ended = true;
                                    break;
                                }
                            }
                        }
                        if ended
                            && !pending.iter().any(Result::is_err)
                            && let Err(error) = decoder.eof(&provider)
                        {
                            pending.push_back(Err(error));
                        }
                    }
                    Err(error) => {
                        pending.push_back(Err(error));
                        ended = true;
                    }
                }
            }
        },
    ))
}

/// Wraps raw Responses SSE chunks in the shared cancellation/accounting stream.
#[must_use]
pub fn events_from_chunks(
    provider: &str,
    cancel: CancelToken,
    chunks: ChunkStream,
) -> CompletionStream {
    CompletionStream::new(provider, cancel, event_stream(provider.to_owned(), chunks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_provider_sdk::model::{
        ImageMediaType, ImagePart, ToolDefinition, ToolParameters, ToolResultMessage,
    };

    fn response() -> Value {
        json!({"id":"resp-1","model":"gpt-4o","status":"completed","output":[{"type":"message","id":"msg-1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"owned answer"}]}],
            "usage":{"input_tokens":10,"output_tokens":8,"input_tokens_details":{"cached_tokens":2},"output_tokens_details":{"reasoning_tokens":3}}})
    }

    fn frames() -> Vec<Value> {
        vec![
            json!({"type":"response.created","response":{"id":"resp-1","model":"gpt-4o","status":"in_progress","output":[],"usage":null}}),
            json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg-1","role":"assistant","status":"in_progress","content":[]}}),
            json!({"type":"response.output_text.delta","output_index":0,"item_id":"msg-1","content_index":0,"delta":"owned "}),
            json!({"type":"response.output_text.delta","output_index":0,"item_id":"msg-1","content_index":0,"delta":"answer"}),
            json!({"type":"response.output_text.done","output_index":0,"item_id":"msg-1","content_index":0,"text":"owned answer"}),
            json!({"type":"response.output_item.done","output_index":0,"item":response()["output"][0]}),
            json!({"type":"response.completed","response":response()}),
        ]
    }

    fn sse(frames: &[Value]) -> Vec<u8> {
        use std::fmt::Write as _;

        let mut encoded = String::new();
        for (index, frame) in frames.iter().enumerate() {
            let mut frame = frame.clone();
            frame["sequence_number"] = json!(index);
            write!(
                encoded,
                "event: {}\ndata: {frame}\n\n",
                frame["type"].as_str().expect("type")
            )
            .expect("owned fixture string");
        }
        encoded.into_bytes()
    }

    #[test]
    fn responses_stream_requires_terminal_identity_content_and_sequence_consistency() {
        let original = frames();
        let events = decode_event_stream("openai", &sse(&original)).expect("complete stream");
        assert_eq!(events[1], StreamEvent::TextDelta("owned ".to_owned()));
        assert!(matches!(
            events.last(),
            Some(StreamEvent::Completed {
                finish_reason: FinishReason::Stop,
                ..
            })
        ));
        assert!(decode_event_stream("openai", &sse(&original[..original.len() - 1])).is_err());
        for (index, pointer, value) in [
            (3, "/item_id", json!("other")),
            (6, "/response/id", json!("other")),
            (6, "/response/model", json!("other-model")),
            (
                6,
                "/response/output/0/content/0/text",
                json!("different final answer"),
            ),
            (2, "/output_index", json!(99999)),
        ] {
            let mut changed = original.clone();
            *changed[index].pointer_mut(pointer).expect("field") = value;
            assert!(decode_event_stream("openai", &sse(&changed)).is_err());
        }
        let duplicated = String::from_utf8(sse(&original))
            .expect("UTF8")
            .replace("\"sequence_number\":3", "\"sequence_number\":2");
        assert!(decode_event_stream("openai", duplicated.as_bytes()).is_err());
    }

    #[test]
    fn responses_stream_parts_are_typed_ordered_bounded_and_finalized_once() {
        let mut original = frames();
        original.insert(2, json!({"type":"response.content_part.added","output_index":0,"item_id":"msg-1","content_index":0,"part":{"type":"output_text","text":""}}));
        original.insert(6, json!({"type":"response.content_part.done","output_index":0,"item_id":"msg-1","content_index":0,"part":{"type":"output_text","text":"owned answer"}}));
        assert!(decode_event_stream("openai", &sse(&original)).is_ok());
        let mut repeated = original.clone();
        repeated.insert(6, original[3].clone());
        assert!(decode_event_stream("openai", &sse(&repeated)).is_err());
        let mut wrong_part = original.clone();
        wrong_part[2]["part"]["type"] = json!("summary_text");
        assert!(decode_event_stream("openai", &sse(&wrong_part)).is_err());
        let mut reordered = original.clone();
        reordered[3]["content_index"] = json!(1);
        assert!(decode_event_stream("openai", &sse(&reordered)).is_err());
        let mut empty = original;
        empty[3]["delta"] = json!("");
        empty[4]["delta"] = json!("");
        empty[5]["text"] = json!("");
        empty[6]["part"]["text"] = json!("");
        empty[7]["item"]["content"][0]["text"] = json!("");
        empty[8]["response"]["output"][0]["content"][0]["text"] = json!("");
        assert!(decode_event_stream("openai", &sse(&empty)).is_ok());
        let mut decoder = ResponsesDecoder {
            identity: Some(("resp-1".to_owned(), "gpt-4o".to_owned())),
            part_count: MAX_OUTPUT_ITEMS,
            ..ResponsesDecoder::default()
        };
        let added = json!({"type":"response.output_item.added","sequence_number":0,"output_index":0,"item":{"type":"message","id":"msg-1","role":"assistant","status":"in_progress","content":[]}});
        assert!(
            decoder
                .accept(
                    "openai",
                    &SseEvent {
                        data: added.to_string(),
                        ..SseEvent::default()
                    }
                )
                .is_ok()
        );
        let mut part = empty[2].clone();
        part["sequence_number"] = json!(1);
        assert!(
            decoder
                .accept(
                    "openai",
                    &SseEvent {
                        data: part.to_string(),
                        ..SseEvent::default()
                    }
                )
                .is_err()
        );
    }

    fn function_frames() -> Vec<Value> {
        let mut frames = vec![frames()[0].clone()];
        let mut output = Vec::new();
        for index in 0..2 {
            let item = json!({"type":"function_call","id":format!("item-{index}"),"call_id":format!("call-{index}"),"name":"lookup","arguments":"","status":"in_progress"});
            frames.push(
                json!({"type":"response.output_item.added","output_index":index,"item":item}),
            );
            output.push(item);
        }
        for index in [1, 0] {
            for delta in ["{\"key\":", "\"one\"}"] {
                frames.push(json!({"type":"response.function_call_arguments.delta","output_index":index,"item_id":format!("item-{index}"),"delta":delta}));
            }
            output[index]["arguments"] = json!("{\"key\":\"one\"}");
            output[index]["status"] = json!("completed");
            frames.push(json!({"type":"response.function_call_arguments.done","output_index":index,"item_id":format!("item-{index}"),"arguments":output[index]["arguments"]}));
            frames.push(json!({"type":"response.output_item.done","output_index":index,"item":output[index]}));
        }
        let mut terminal = response();
        terminal["output"] = json!(output);
        frames.push(json!({"type":"response.completed","response":terminal}));
        frames
    }

    #[tokio::test]
    async fn responses_parallel_functions_publish_only_after_consistent_terminal_snapshot() {
        let frames = function_frames();
        let mut decoder = ResponsesDecoder::default();
        for (index, frame) in frames.iter().enumerate() {
            let mut frame = frame.clone();
            frame["sequence_number"] = json!(index);
            let events = decoder
                .accept(
                    "openai",
                    &SseEvent {
                        data: frame.to_string(),
                        ..SseEvent::default()
                    },
                )
                .expect("valid function event");
            if index + 1 < frames.len() {
                assert!(
                    events
                        .iter()
                        .all(|event| matches!(event, StreamEvent::Started { .. }))
                );
            } else {
                let calls: Vec<_> = events
                    .iter()
                    .filter_map(|event| {
                        if let StreamEvent::ToolCallCompleted { index, call } = event {
                            Some((*index, call.id.as_str()))
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(calls, [(0, "call-0"), (1, "call-1")]);
                assert!(matches!(
                    events.last(),
                    Some(StreamEvent::Completed {
                        finish_reason: FinishReason::ToolCalls,
                        ..
                    })
                ));
            }
        }
        for pointer in [
            "/response/output/1/call_id",
            "/response/output/1/name",
            "/response/output/1/arguments",
        ] {
            let mut changed = frames.clone();
            *changed
                .last_mut()
                .expect("terminal")
                .pointer_mut(pointer)
                .expect("field") = json!("changed-target-or-value");
            let mut stream = events_from_chunks(
                "openai",
                CancelToken::new(),
                Box::pin(futures_util::stream::iter([Ok(bytes::Bytes::from(sse(
                    &changed,
                )))])),
            );
            let mut failed = false;
            while let Some(event) = stream.next().await {
                match event {
                    Ok(StreamEvent::Started { .. }) => {}
                    Err(error) => {
                        assert_eq!(error.kind(), ErrorKind::Protocol);
                        failed = true;
                    }
                    _ => panic!("failed snapshot must not publish any function"),
                }
            }
            assert!(failed);
        }
    }

    #[tokio::test]
    async fn responses_every_chunk_split_preserves_deltas_and_unmarked_eof_is_an_error() {
        let body = sse(&frames());
        let expected = decode_event_stream("openai", &body).expect("reference events");
        for split in 1..body.len() {
            let chunks = [
                Ok(bytes::Bytes::copy_from_slice(&body[..split])),
                Ok(bytes::Bytes::copy_from_slice(&body[split..])),
            ];
            let mut stream = events_from_chunks(
                "openai",
                CancelToken::new(),
                Box::pin(futures_util::stream::iter(chunks)),
            );
            let mut events = Vec::new();
            while let Some(event) = stream.next().await {
                events.push(event.expect("valid fragment"));
            }
            assert_eq!(events, expected, "split {split}");
        }
        let frames = frames();
        let body = sse(&frames[..4]);
        let mut stream = events_from_chunks(
            "openai",
            CancelToken::new(),
            Box::pin(futures_util::stream::iter([Ok(bytes::Bytes::from(body))])),
        );
        let mut completed = false;
        let mut failed = false;
        while let Some(event) = stream.next().await {
            completed |= matches!(event, Ok(StreamEvent::Completed { .. }));
            failed |= event.is_err();
        }
        assert!(failed && !completed);
    }

    #[test]
    fn responses_request_encodes_stateless_text_image_functions_and_result_history() {
        let mut request = CompletionRequest::new(
            ModelId::new("gpt-4o").expect("model"),
            vec![
                ChatMessage::System("instructions".to_owned()),
                ChatMessage::User(vec![
                    ContentPart::text("hello"),
                    ContentPart::Image(ImagePart {
                        media_type: ImageMediaType::Png,
                        source: ImageSource::Base64("aW1hZ2U=".to_owned()),
                    }),
                ]),
                ChatMessage::Assistant(AssistantMessage {
                    tool_calls: vec![ToolCall {
                        id: "call-1".to_owned(),
                        name: "lookup".to_owned(),
                        arguments: ToolArguments::new(r#"{"key":"one"}"#).expect("args"),
                    }],
                    ..AssistantMessage::default()
                }),
                ChatMessage::ToolResult(ToolResultMessage {
                    tool_call_id: "call-1".to_owned(),
                    content: "owned result".to_owned(),
                    is_error: false,
                }),
            ],
        );
        request.tools.push(ToolDefinition {
            name: "lookup".to_owned(),
            description: "lookup one key".to_owned(),
            parameters: ToolParameters::new(
                json!({"type":"object","properties":{"key":{"type":"string"}}}),
            )
            .expect("schema"),
        });
        request.tool_choice = ToolChoice::Function("lookup".to_owned());
        request.max_output_tokens = Some(128);
        request.response_format = ResponseFormat::JsonObject;
        let document: Value =
            serde_json::from_str(&encode_completion("openai", &request, true).expect("request"))
                .expect("JSON");
        assert_eq!(document["store"], false);
        assert_eq!(document["stream"], true);
        assert_eq!(
            document["input"][1]["content"][1]["image_url"],
            "data:image/png;base64,aW1hZ2U="
        );
        assert_eq!(document["input"][2]["type"], "function_call");
        assert_eq!(
            document["input"][3],
            json!({"type":"function_call_output","call_id":"call-1","output":"owned result"})
        );
        assert_eq!(document["tools"][0]["type"], "function");
        assert_eq!(
            document["tool_choice"],
            json!({"type":"function","name":"lookup"})
        );
        assert_eq!(document["text"]["format"]["type"], "json_object");
        assert_eq!(document["max_output_tokens"], 128);
        assert!(document.get("previous_response_id").is_none());
        request.seed = Some(1);
        assert_eq!(
            encode_completion("openai", &request, false)
                .expect_err("unsupported seed")
                .kind(),
            ErrorKind::Unsupported
        );
        request.seed = None;
        request.messages.remove(2);
        assert!(encode_completion("openai", &request, false).is_err());
    }

    #[test]
    fn responses_plain_assistant_history_uses_input_message_content() {
        let request = CompletionRequest::new(
            ModelId::new("gpt-4o").expect("model"),
            vec![
                ChatMessage::user_text("first question"),
                ChatMessage::Assistant(AssistantMessage {
                    content: vec![ContentPart::text("prior answer")],
                    ..AssistantMessage::default()
                }),
                ChatMessage::user_text("follow-up question"),
            ],
        );
        let encoded: Value = serde_json::from_str(
            &encode_completion("openai", &request, false).expect("history request"),
        )
        .expect("JSON");
        assert_eq!(
            encoded["input"][1],
            json!({"role":"assistant","content":[{"type":"input_text","text":"prior answer"}]})
        );
        assert!(encoded["input"][1].get("id").is_none());
        assert!(encoded.get("previous_response_id").is_none());
    }

    #[test]
    fn responses_results_keep_reasoning_usage_and_complete_function_calls() {
        let mut source = response();
        source["output"].as_array_mut().expect("output").extend([
            json!({"type":"reasoning","id":"reason-1","summary":[{"type":"summary_text","text":"reasoning summary"}]}),
            json!({"type":"function_call","id":"item-1","call_id":"call-1","name":"lookup","arguments":"{\"key\":\"one\"}","status":"completed"})]);
        let decoded =
            decode_completion("openai", source.to_string().as_bytes()).expect("typed response");
        assert_eq!(decoded.message.text(), "owned answer");
        assert_eq!(
            decoded.message.reasoning.as_deref(),
            Some("reasoning summary")
        );
        assert_eq!(decoded.message.tool_calls[0].id, "call-1");
        assert_eq!(decoded.finish_reason, FinishReason::ToolCalls);
        assert_eq!(
            decoded.usage,
            Usage {
                input_tokens: 10,
                output_tokens: 8,
                cached_input_tokens: 2,
                reasoning_tokens: 3
            }
        );
        let mut incomplete = response();
        incomplete["status"] = json!("incomplete");
        incomplete["incomplete_details"] = json!({"reason":"max_output_tokens"});
        incomplete["output"][0]["status"] = json!("incomplete");
        assert_eq!(
            decode_completion("openai", incomplete.to_string().as_bytes())
                .expect("known partial terminal")
                .finish_reason,
            FinishReason::Length
        );
    }

    #[test]
    fn responses_invalid_or_unfinished_results_never_become_successful_tool_rounds() {
        for (pointer, value) in [
            ("/status", json!("in_progress")),
            ("/id", json!("")),
            ("/usage/input_tokens", json!(1)),
            ("/output/0/role", json!("system")),
            ("/output/0/status", json!("in_progress")),
            ("/output/0/type", json!("web_search_call")),
        ] {
            let mut source = response();
            *source.pointer_mut(pointer).expect("field") = value;
            assert!(decode_completion("openai", source.to_string().as_bytes()).is_err());
        }
        let mut duplicate = response();
        duplicate["output"] = json!([{"type":"function_call","id":"item-1","call_id":"call-1","name":"lookup","arguments":"{}"},
            {"type":"function_call","id":"item-2","call_id":"call-1","name":"lookup","arguments":"{}"}]);
        assert!(decode_completion("openai", duplicate.to_string().as_bytes()).is_err());
        duplicate["output"].as_array_mut().expect("output").pop();
        duplicate["output"][0]["arguments"] = json!("private-malformed-arguments");
        let error = decode_completion("openai", duplicate.to_string().as_bytes())
            .expect_err("bad function JSON");
        assert!(!error.detail().contains("private-malformed"));
    }
}

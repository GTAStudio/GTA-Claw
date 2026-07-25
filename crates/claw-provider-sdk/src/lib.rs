//! Typed provider abstraction for GTA Claw.
//!
//! This crate defines the model-provider contract used by the rest of GTA Claw:
//! typed request and response models, an incremental streaming decoder, a closed
//! error taxonomy, reliability policies (retry, circuit breaking, concurrency
//! limits) and a credential port with operating-system adapters.
//!
//! # Design rules
//!
//! * The public API never exposes untyped JSON documents. The only places where
//!   raw JSON is unavoidable — JSON-Schema tool parameter declarations and
//!   model-generated tool-call arguments — are wrapped in the validated
//!   [`ToolParameters`](model::ToolParameters) and
//!   [`ToolArguments`](model::ToolArguments) newtypes.
//! * Secret material is confined to [`secret::ApiKey`] and
//!   [`secret::SecretString`]. Neither type implements `serde::Serialize`, and
//!   both redact themselves in `Debug` and `Display`.
//! * Transport is pure Rust: `reqwest` over `rustls`. No OpenSSL, no Node.js.

pub mod cancel;
pub mod circuit;
pub mod clock;
pub mod error;
pub mod http;
pub mod limit;
pub mod model;
pub mod origin;
pub mod provider;
pub mod retry;
pub mod secret;
pub mod sse;
pub mod stream;

pub use cancel::CancelToken;
pub use error::{ErrorKind, Operation, ProviderError};
pub use model::{
    AssistantMessage, AuthMode, Capability, CapabilitySet, ChatMessage, CompletionRequest,
    CompletionResponse, Embedding, EmbeddingsRequest, EmbeddingsResponse, FinishReason,
    ModelDescriptor, ModelError, ModelId, ProviderId, ResponseFormat, ToolArguments, ToolCall,
    ToolChoice, ToolDefinition, ToolParameters, Usage,
};
pub use origin::{BoundApiKey, BoundSecret, Origin, OriginApproval, OriginError, TrustedOrigins};
pub use provider::{BoxFuture, Provider, RequestContext};
pub use secret::{ApiKey, CredentialKey, SecretStore, SecretStoreError, SecretString};
pub use stream::{CompletionStream, StreamEvent};

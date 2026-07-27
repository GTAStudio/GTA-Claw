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
//!   [`model::ToolParameters`] and [`model::ToolArguments`] newtypes.
//! * Secret material is confined to [`secret::ApiKey`] and
//!   [`secret::SecretString`]. Neither type implements `serde::Serialize`, and
//!   both redact themselves in `Debug` and `Display`.
//! * Transport is pure Rust: `hyper` over `rustls`. No OpenSSL, no Node.js.
//! * Outbound proxying is decided by one reviewed policy, [`http::proxy`],
//!   which owns environment precedence, `NO_PROXY` matching, redaction and the
//!   continue-without-proxy fallback. [`http::HttpTransport`] is currently its
//!   only consumer; the role, channel, skill and MCP transports still carry
//!   their own arrangements.

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
pub use error::{ErrorKind, FailureClass, Operation, ProviderError};
pub use model::{
    AssistantMessage, AuthMode, Capability, CapabilitySet, ChatMessage, CompletionRequest,
    CompletionResponse, Embedding, EmbeddingsRequest, EmbeddingsResponse, FinishReason,
    ModelDescriptor, ModelError, ModelId, ProviderId, ResponseFormat, ToolArguments, ToolCall,
    ToolChoice, ToolDefinition, ToolParameters, Usage,
};
pub use origin::{BoundApiKey, BoundSecret, Origin, OriginApproval, OriginError, TrustedOrigins};
pub use provider::{BoxFuture, Provider, ProviderPhase, ProviderStatus, RequestContext};
pub use secret::{ApiKey, CredentialKey, SecretStore, SecretStoreError, SecretString};
pub use stream::{CompletionStream, StreamEvent};

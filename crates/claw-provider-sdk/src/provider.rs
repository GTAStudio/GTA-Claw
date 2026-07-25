//! The [`Provider`] trait and its request context.

use std::future::Future;
use std::pin::Pin;

use crate::cancel::CancelToken;
use crate::error::{ErrorKind, Operation, ProviderError};
use crate::model::{
    CapabilitySet, CompletionRequest, CompletionResponse, EmbeddingsRequest, EmbeddingsResponse,
    ModelDescriptor, ProviderId,
};
use crate::stream::CompletionStream;

/// A boxed future returned by [`Provider`] methods.
///
/// The trait uses explicit boxing rather than `async fn` so it stays
/// dyn-compatible without pulling in a procedural-macro dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Per-call context threaded through every provider operation.
#[derive(Clone, Debug, Default)]
pub struct RequestContext {
    cancel: CancelToken,
    idempotency_key: Option<String>,
    correlation_id: Option<String>,
}

impl RequestContext {
    /// Creates a context with a fresh cancellation token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a context bound to an existing cancellation token.
    #[must_use]
    pub fn with_cancel(cancel: CancelToken) -> Self {
        Self {
            cancel,
            idempotency_key: None,
            correlation_id: None,
        }
    }

    /// Sets the idempotency key sent to providers that support one.
    #[must_use]
    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Sets a correlation identifier echoed in diagnostics.
    #[must_use]
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Returns the cancellation token.
    #[must_use]
    pub const fn cancel(&self) -> &CancelToken {
        &self.cancel
    }

    /// Returns the idempotency key, when one was set.
    #[must_use]
    pub fn idempotency_key_of(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    /// Returns the correlation identifier, when one was set.
    #[must_use]
    pub fn correlation_id_of(&self) -> Option<&str> {
        self.correlation_id.as_deref()
    }
}

/// A model provider.
///
/// Only [`Provider::id`] and [`Provider::capabilities`] must be implemented;
/// every operation defaults to [`ErrorKind::Unsupported`] so a provider that is
/// registered for metadata alone reports that honestly rather than panicking.
pub trait Provider: Send + Sync {
    /// Returns the frozen inventory identifier of this provider.
    fn id(&self) -> &ProviderId;

    /// Returns the operations this provider actually implements.
    fn capabilities(&self) -> CapabilitySet;

    /// Runs a non-streaming completion.
    fn complete<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionResponse, ProviderError>> {
        let _ = (request, context);
        Box::pin(async move { Err(self.unsupported(Operation::Complete)) })
    }

    /// Runs a streaming completion.
    fn stream<'a>(
        &'a self,
        request: &'a CompletionRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<CompletionStream, ProviderError>> {
        let _ = (request, context);
        Box::pin(async move { Err(self.unsupported(Operation::StreamCompletion)) })
    }

    /// Computes embeddings.
    fn embed<'a>(
        &'a self,
        request: &'a EmbeddingsRequest,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<EmbeddingsResponse, ProviderError>> {
        let _ = (request, context);
        Box::pin(async move { Err(self.unsupported(Operation::Embed)) })
    }

    /// Lists the models this provider currently serves.
    fn list_models<'a>(
        &'a self,
        context: &'a RequestContext,
    ) -> BoxFuture<'a, Result<Vec<ModelDescriptor>, ProviderError>> {
        let _ = context;
        Box::pin(async move { Err(self.unsupported(Operation::ListModels)) })
    }

    /// Builds the error returned for an operation this provider does not serve.
    fn unsupported(&self, operation: Operation) -> ProviderError {
        ProviderError::new(
            ErrorKind::Unsupported,
            self.id().as_str(),
            operation,
            "this provider is registered for metadata only",
        )
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;
    use crate::model::{Capability, ChatMessage, ModelId};

    #[derive(Debug)]
    struct MetadataOnly(ProviderId);

    impl Provider for MetadataOnly {
        fn id(&self) -> &ProviderId {
            &self.0
        }

        fn capabilities(&self) -> CapabilitySet {
            CapabilitySet::EMPTY
        }
    }

    fn request() -> CompletionRequest {
        CompletionRequest::new(
            ModelId::new("model-a").expect("valid"),
            vec![ChatMessage::user_text("hi")],
        )
    }

    #[tokio::test]
    async fn a_metadata_only_provider_reports_unsupported_for_every_operation() {
        let provider = MetadataOnly(ProviderId::new("venice").expect("valid"));
        let context = RequestContext::new();
        let request = request();

        let completion = provider
            .complete(&request, &context)
            .await
            .expect_err("unsupported");
        assert_eq!(completion.kind(), ErrorKind::Unsupported);
        assert_eq!(completion.provider(), "venice");
        assert_eq!(completion.operation(), Operation::Complete);
        assert_eq!(
            completion.detail(),
            "this provider is registered for metadata only"
        );
        assert!(!completion.is_retryable());

        let streaming = provider
            .stream(&request, &context)
            .await
            .expect_err("unsupported");
        assert_eq!(streaming.operation(), Operation::StreamCompletion);

        let embeddings = EmbeddingsRequest {
            model: ModelId::new("model-a").expect("valid"),
            inputs: vec!["a".to_owned()],
            dimensions: None,
        };
        let embedding = provider
            .embed(&embeddings, &context)
            .await
            .expect_err("unsupported");
        assert_eq!(embedding.operation(), Operation::Embed);

        let models = provider
            .list_models(&context)
            .await
            .expect_err("unsupported");
        assert_eq!(models.operation(), Operation::ListModels);
        assert_eq!(provider.capabilities(), CapabilitySet::EMPTY);
    }

    #[tokio::test]
    async fn a_provider_can_be_used_behind_a_trait_object() {
        let provider: Box<dyn Provider> =
            Box::new(MetadataOnly(ProviderId::new("codex").expect("valid")));
        let error = provider
            .complete(&request(), &RequestContext::new())
            .await
            .expect_err("unsupported");
        assert_eq!(error.provider(), "codex");
    }

    #[tokio::test]
    async fn overridden_operations_replace_the_default() {
        struct Streaming(ProviderId);

        impl Provider for Streaming {
            fn id(&self) -> &ProviderId {
                &self.0
            }

            fn capabilities(&self) -> CapabilitySet {
                CapabilitySet::from_slice(&[Capability::Streaming])
            }

            fn stream<'a>(
                &'a self,
                _request: &'a CompletionRequest,
                context: &'a RequestContext,
            ) -> BoxFuture<'a, Result<CompletionStream, ProviderError>> {
                let cancel = context.cancel().clone();
                Box::pin(async move {
                    Ok(CompletionStream::new(
                        "openai",
                        cancel,
                        Box::pin(futures_util::stream::iter(vec![Ok(
                            crate::stream::StreamEvent::TextDelta("ok".to_owned()),
                        )])),
                    ))
                })
            }
        }

        let provider = Streaming(ProviderId::new("openai").expect("valid"));
        assert!(provider.capabilities().contains(Capability::Streaming));
        let context = RequestContext::new();
        let mut stream = provider
            .stream(&request(), &context)
            .await
            .expect("stream starts");
        assert_eq!(
            stream.next().await,
            Some(Ok(crate::stream::StreamEvent::TextDelta("ok".to_owned())))
        );

        // The non-overridden operation still reports the honest default.
        assert_eq!(
            provider
                .complete(&request(), &context)
                .await
                .expect_err("unsupported")
                .kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn request_context_carries_optional_correlation_metadata() {
        let context = RequestContext::new();
        assert_eq!(context.idempotency_key_of(), None);
        assert_eq!(context.correlation_id_of(), None);
        assert!(!context.cancel().is_cancelled());

        let context = RequestContext::new()
            .idempotency_key("idem-1")
            .correlation_id("corr-1");
        assert_eq!(context.idempotency_key_of(), Some("idem-1"));
        assert_eq!(context.correlation_id_of(), Some("corr-1"));

        let token = CancelToken::new();
        let context = RequestContext::with_cancel(token.clone());
        token.cancel();
        assert!(context.cancel().is_cancelled());
    }
}

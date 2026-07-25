//! Typed metadata describing one registered provider.

use std::fmt::{self, Display, Formatter};

use claw_provider_sdk::model::{AuthMode, Capability, CapabilitySet};

/// The wire dialect a provider speaks.
///
/// This is GTA-Claw-owned metadata. The frozen upstream inventory records only
/// identifiers, so the dialect classification below is our own and is what
/// decides which client implementation a provider can use.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProviderFamily {
    /// `POST /chat/completions` in the OpenAI dialect.
    OpenAiChatCompletions,
    /// Anthropic `POST /v1/messages`.
    AnthropicMessages,
    /// GitHub Copilot's chat API, reached with an exchanged Copilot token.
    GitHubCopilot,
    /// OpenAI's Responses/Codex protocol, which is not the chat dialect.
    OpenAiResponses,
    /// Google Gemini `generateContent`.
    GoogleGemini,
    /// Amazon Bedrock `Converse` / `InvokeModelWithResponseStream`.
    AmazonBedrock,
    /// Cohere `POST /v2/chat`.
    CohereChat,
    /// Azure AI Foundry model inference.
    AzureFoundry,
    /// Image, video or audio generation rather than chat.
    MediaGeneration,
    /// The dialect is not classified by GTA-Claw.
    Unclassified,
}

impl ProviderFamily {
    /// Returns the stable identifier of this dialect.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiChatCompletions => "openai_chat_completions",
            Self::AnthropicMessages => "anthropic_messages",
            Self::GitHubCopilot => "github_copilot",
            Self::OpenAiResponses => "openai_responses",
            Self::GoogleGemini => "google_gemini",
            Self::AmazonBedrock => "amazon_bedrock",
            Self::CohereChat => "cohere_chat",
            Self::AzureFoundry => "azure_foundry",
            Self::MediaGeneration => "media_generation",
            Self::Unclassified => "unclassified",
        }
    }
}

impl Display for ProviderFamily {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How much real behavior GTA-Claw ships for a provider.
///
/// This value is deliberately blunt so that nothing can be silently
/// overclaimed: a caller can decide what to do purely from this field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ImplementationStatus {
    /// A working client ships **and** a default endpoint is configured, so the
    /// provider can be constructed from a credential alone.
    Implemented,
    /// A working client ships for this dialect, but GTA-Claw does not carry a
    /// verified default endpoint, so the caller must supply the base URL.
    EndpointRequired,
    /// Metadata only. No client ships; every operation returns
    /// [`ErrorKind::Unsupported`](claw_provider_sdk::ErrorKind::Unsupported).
    RegistrationOnly,
}

impl ImplementationStatus {
    /// Returns the stable identifier of this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::EndpointRequired => "endpoint_required",
            Self::RegistrationOnly => "registration_only",
        }
    }

    /// Returns `true` when a working client ships for this provider.
    #[must_use]
    pub const fn has_client(self) -> bool {
        matches!(self, Self::Implemented | Self::EndpointRequired)
    }
}

impl Display for ImplementationStatus {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Capabilities the OpenAI chat-completions client can drive.
pub const OPENAI_CAPABILITIES: CapabilitySet = CapabilitySet::from_slice(&[
    Capability::Completion,
    Capability::Streaming,
    Capability::ToolCalling,
    Capability::Embeddings,
    Capability::ModelListing,
    Capability::Vision,
    Capability::Reasoning,
    Capability::JsonMode,
    Capability::PromptCaching,
]);

/// Capabilities the Anthropic messages client can drive.
///
/// Anthropic serves no embeddings API and has no `response_format` switch, so
/// neither capability is claimed.
pub const ANTHROPIC_CAPABILITIES: CapabilitySet = CapabilitySet::from_slice(&[
    Capability::Completion,
    Capability::Streaming,
    Capability::ToolCalling,
    Capability::ModelListing,
    Capability::Vision,
    Capability::Reasoning,
    Capability::PromptCaching,
]);

/// Capabilities the GitHub Copilot client can drive.
///
/// Copilot exposes no embeddings endpoint to third-party clients.
pub const COPILOT_CAPABILITIES: CapabilitySet = CapabilitySet::from_slice(&[
    Capability::Completion,
    Capability::Streaming,
    Capability::ToolCalling,
    Capability::ModelListing,
    Capability::Vision,
    Capability::JsonMode,
]);

/// One registered provider.
///
/// The `record_id`, `id`, `plugin_id` and `source_path` fields reproduce the
/// frozen upstream inventory exactly. Everything else is GTA-Claw-owned
/// metadata: upstream publishes no display names, capabilities, auth modes or
/// endpoints in the frozen contract data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderDescriptor {
    /// Frozen inventory record identifier, always `provider:{id}`.
    pub record_id: &'static str,
    /// Frozen provider identifier.
    pub id: &'static str,
    /// Frozen upstream plugin identifier.
    pub plugin_id: &'static str,
    /// Frozen upstream plugin manifest path.
    pub source_path: &'static str,
    /// Human-readable name shown in GTA-Claw.
    pub display_name: &'static str,
    /// Wire dialect classification.
    pub family: ProviderFamily,
    /// How much behavior ships.
    pub status: ImplementationStatus,
    /// Accepted authentication modes, most preferred first.
    pub auth_modes: &'static [AuthMode],
    /// Default API base URL, when GTA-Claw ships a verified one.
    pub base_url: Option<&'static str>,
    /// Operations the shipped client can drive for this provider.
    pub capabilities: CapabilitySet,
}

impl ProviderDescriptor {
    /// Returns `true` when the provider needs no credential.
    #[must_use]
    pub fn is_credential_free(&self) -> bool {
        self.auth_modes == [AuthMode::None]
    }

    /// Returns `true` when the provider is registered for metadata only.
    #[must_use]
    pub const fn is_registration_only(&self) -> bool {
        matches!(self.status, ImplementationStatus::RegistrationOnly)
    }
}

impl Display for ProviderDescriptor {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.display_name, self.id)
    }
}

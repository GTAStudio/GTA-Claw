//! The frozen provider registry.
//!
//! Every identifier in `compat/upstream/inventories/providers.json` is
//! registered here with typed GTA-Claw metadata. The table is hand-written
//! rather than generated from the inventory, so
//! [`frozen_inventory`](../../tests/frozen_inventory.rs) can compare the two
//! independently.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use claw_provider_sdk::model::{AuthMode, CapabilitySet};

use crate::descriptor::{
    ANTHROPIC_CAPABILITIES, COPILOT_CAPABILITIES, ImplementationStatus, OPENAI_CAPABILITIES,
    ProviderDescriptor, ProviderFamily,
};

const fn capabilities_for(family: ProviderFamily, status: ImplementationStatus) -> CapabilitySet {
    if !status.has_client() {
        return CapabilitySet::EMPTY;
    }
    match family {
        ProviderFamily::OpenAiChatCompletions => OPENAI_CAPABILITIES,
        ProviderFamily::AnthropicMessages => ANTHROPIC_CAPABILITIES,
        ProviderFamily::GitHubCopilot => COPILOT_CAPABILITIES,
        _ => CapabilitySet::EMPTY,
    }
}

macro_rules! provider_table {
    ($(
        $id:literal, $plugin:literal, $dir:literal, $name:literal,
        $family:ident, $status:ident, [$($auth:ident),+ $(,)?], $base:expr
    );* $(;)?) => {
        /// Every provider in the frozen upstream inventory, in inventory order.
        pub static PROVIDERS: &[ProviderDescriptor] = &[
            $(ProviderDescriptor {
                record_id: concat!("provider:", $id),
                id: $id,
                plugin_id: $plugin,
                source_path: concat!("extensions/", $dir, "/openclaw.plugin.json"),
                display_name: $name,
                family: ProviderFamily::$family,
                status: ImplementationStatus::$status,
                auth_modes: &[$(AuthMode::$auth),+],
                base_url: $base,
                capabilities: capabilities_for(
                    ProviderFamily::$family,
                    ImplementationStatus::$status,
                ),
            }),*
        ];
    };
}

provider_table! {
    "qianfan", "qianfan", "qianfan", "Baidu AI Cloud Qianfan",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "qwen", "qwen", "qwen", "Alibaba Qwen",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "opencode-go", "opencode-go", "opencode-go", "OpenCode Go",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "openrouter", "openrouter", "openrouter", "OpenRouter",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://openrouter.ai/api/v1");
    "qwencloud", "qwen", "qwen", "Alibaba Qwen Cloud",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "qwen-oauth", "qwen", "qwen", "Alibaba Qwen (OAuth)",
        OpenAiChatCompletions, EndpointRequired, [OAuthAuthorizationCode], None;
    "qwen-portal", "qwen", "qwen", "Alibaba Qwen Portal",
        OpenAiChatCompletions, EndpointRequired, [OAuthAuthorizationCode], None;
    "modelstudio", "qwen", "qwen", "Alibaba Cloud Model Studio",
        OpenAiChatCompletions, Implemented, [BearerToken],
        Some("https://dashscope-intl.aliyuncs.com/compatible-mode/v1");
    "dashscope", "qwen", "qwen", "Alibaba Cloud DashScope",
        OpenAiChatCompletions, Implemented, [BearerToken],
        Some("https://dashscope.aliyuncs.com/compatible-mode/v1");
    "opencode", "opencode", "opencode", "OpenCode",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "novita", "novita", "novita", "Novita AI",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "novita-ai", "novita", "novita", "Novita AI (alias)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "mistral", "mistral", "mistral", "Mistral AI",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.mistral.ai/v1");
    "moonshot", "moonshot", "moonshot", "Moonshot AI",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.moonshot.ai/v1");
    "novitaai", "novita", "novita", "Novita AI (legacy alias)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "ollama-cloud", "ollama", "ollama", "Ollama Cloud",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "openai", "openai", "openai", "OpenAI",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.openai.com/v1");
    "nvidia", "nvidia", "nvidia", "NVIDIA NIM",
        OpenAiChatCompletions, Implemented, [BearerToken],
        Some("https://integrate.api.nvidia.com/v1");
    "ollama", "ollama", "ollama", "Ollama",
        OpenAiChatCompletions, Implemented, [None], Some("http://127.0.0.1:11434/v1");
    "qwen-cli", "qwen", "qwen", "Alibaba Qwen CLI",
        OpenAiChatCompletions, EndpointRequired, [OAuthAuthorizationCode], None;
    "volcengine", "volcengine", "volcengine", "Volcengine Ark",
        OpenAiChatCompletions, Implemented, [BearerToken],
        Some("https://ark.cn-beijing.volces.com/api/v3");
    "volcengine-plan", "volcengine", "volcengine", "Volcengine Ark (plan)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "vercel-ai-gateway", "vercel-ai-gateway", "vercel-ai-gateway", "Vercel AI Gateway",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://ai-gateway.vercel.sh/v1");
    "vllm", "vllm", "vllm", "vLLM",
        OpenAiChatCompletions, Implemented, [None], Some("http://127.0.0.1:8000/v1");
    "vydra", "vydra", "vydra", "Vydra",
        Unclassified, RegistrationOnly, [BearerToken], None;
    "xiaomi-token-plan", "xiaomi", "xiaomi", "Xiaomi MiMo (token plan)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "zai", "zai", "zai", "Z.ai",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "xai", "xai", "xai", "xAI",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.x.ai/v1");
    "xiaomi", "xiaomi", "xiaomi", "Xiaomi MiMo",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "venice", "venice", "venice", "Venice AI",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.venice.ai/api/v1");
    "sglang", "sglang", "sglang", "SGLang",
        OpenAiChatCompletions, Implemented, [None], Some("http://127.0.0.1:30000/v1");
    "stepfun", "stepfun", "stepfun", "StepFun",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "qwen-token-plan", "qwen", "qwen", "Alibaba Qwen (token plan)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "bailian-token-plan", "qwen", "qwen", "Alibaba Bailian (token plan)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "stepfun-plan", "stepfun", "stepfun", "StepFun (plan)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "tencent-tokenplan", "tencent", "tencent", "Tencent Cloud (token plan)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "together", "together", "together", "Together AI",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.together.xyz/v1");
    "synthetic", "synthetic", "synthetic", "Synthetic",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "tencent-tokenhub", "tencent", "tencent", "Tencent Cloud TokenHub",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "cohere", "cohere", "cohere", "Cohere",
        CohereChat, RegistrationOnly, [BearerToken], None;
    "comfy", "comfy", "comfy", "ComfyUI",
        MediaGeneration, RegistrationOnly, [None], None;
    "cloudflare-ai-gateway", "cloudflare-ai-gateway", "cloudflare-ai-gateway",
        "Cloudflare AI Gateway",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "codex", "codex", "codex", "OpenAI Codex",
        OpenAiResponses, RegistrationOnly, [OAuthAuthorizationCode, BearerToken], None;
    "copilot-proxy", "copilot-proxy", "copilot-proxy", "Copilot Proxy",
        OpenAiChatCompletions, EndpointRequired, [None], None;
    "fal", "fal", "fal", "fal.ai",
        MediaGeneration, RegistrationOnly, [ApiKey], None;
    "featherless", "featherless", "featherless", "Featherless AI",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.featherless.ai/v1");
    "deepinfra", "deepinfra", "deepinfra", "DeepInfra",
        OpenAiChatCompletions, Implemented, [BearerToken],
        Some("https://api.deepinfra.com/v1/openai");
    "deepseek", "deepseek", "deepseek", "DeepSeek",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.deepseek.com/v1");
    "clawrouter", "clawrouter", "clawrouter", "ClawRouter",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "anthropic", "anthropic", "anthropic", "Anthropic",
        AnthropicMessages, Implemented, [ApiKey, OAuthAuthorizationCode],
        Some("https://api.anthropic.com");
    "anthropic-vertex", "anthropic-vertex", "anthropic-vertex", "Anthropic on Vertex AI",
        AnthropicMessages, RegistrationOnly, [GoogleServiceAccount], None;
    "amazon-bedrock", "amazon-bedrock", "amazon-bedrock", "Amazon Bedrock",
        AmazonBedrock, RegistrationOnly, [AwsSigV4], None;
    "amazon-bedrock-mantle", "amazon-bedrock-mantle", "amazon-bedrock-mantle",
        "Amazon Bedrock (Mantle)",
        AmazonBedrock, RegistrationOnly, [AwsSigV4], None;
    "arcee", "arcee", "arcee", "Arcee AI",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://conductor.arcee.ai/v1");
    "cerebras", "cerebras", "cerebras", "Cerebras",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.cerebras.ai/v1");
    "chutes", "chutes", "chutes", "Chutes",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://llm.chutes.ai/v1");
    "byteplus", "byteplus", "byteplus", "BytePlus ModelArk",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "byteplus-plan", "byteplus", "byteplus", "BytePlus ModelArk (plan)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "fireworks", "fireworks", "fireworks", "Fireworks AI",
        OpenAiChatCompletions, Implemented, [BearerToken],
        Some("https://api.fireworks.ai/inference/v1");
    "litellm", "litellm", "litellm", "LiteLLM Proxy",
        OpenAiChatCompletions, Implemented, [BearerToken, None], Some("http://127.0.0.1:4000/v1");
    "lmstudio", "lmstudio", "lmstudio", "LM Studio",
        OpenAiChatCompletions, Implemented, [None], Some("http://127.0.0.1:1234/v1");
    "kimi", "kimi", "kimi-coding", "Kimi",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "kimi-coding", "kimi", "kimi-coding", "Kimi for Coding",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "longcat", "longcat", "longcat", "LongCat",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "minimax", "minimax", "minimax", "MiniMax",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "minimax-portal", "minimax", "minimax", "MiniMax Portal",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "meta", "meta", "meta", "Meta Llama API",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "microsoft-foundry", "microsoft-foundry", "microsoft-foundry", "Microsoft AI Foundry",
        AzureFoundry, RegistrationOnly, [AzureIdentity, ApiKey], None;
    "kilocode", "kilocode", "kilocode", "Kilo Code",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "gmi-cloud", "gmi", "gmi", "GMI Cloud",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "gmicloud", "gmi", "gmi", "GMI Cloud (legacy alias)",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "github-copilot", "github-copilot", "github-copilot", "GitHub Copilot",
        GitHubCopilot, Implemented, [OAuthDeviceCode], Some("https://api.githubcopilot.com");
    "gmi", "gmi", "gmi", "GMI",
        OpenAiChatCompletions, EndpointRequired, [BearerToken], None;
    "google", "google", "google", "Google Gemini",
        GoogleGemini, RegistrationOnly, [ApiKey], None;
    "groq", "groq", "groq", "Groq",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://api.groq.com/openai/v1");
    "huggingface", "huggingface", "huggingface", "Hugging Face Inference Providers",
        OpenAiChatCompletions, Implemented, [BearerToken], Some("https://router.huggingface.co/v1");
    "google-gemini-cli", "google", "google", "Google Gemini CLI",
        GoogleGemini, RegistrationOnly, [OAuthAuthorizationCode], None;
    "google-vertex", "google", "google", "Google Vertex AI",
        GoogleGemini, RegistrationOnly, [GoogleServiceAccount], None;
}

/// Immutable lookup over [`PROVIDERS`].
#[derive(Debug)]
pub struct ProviderRegistry {
    by_id: BTreeMap<&'static str, &'static ProviderDescriptor>,
}

impl ProviderRegistry {
    /// Returns the process-wide registry.
    #[must_use]
    pub fn global() -> &'static Self {
        static REGISTRY: OnceLock<ProviderRegistry> = OnceLock::new();
        REGISTRY.get_or_init(|| Self {
            by_id: PROVIDERS
                .iter()
                .map(|descriptor| (descriptor.id, descriptor))
                .collect(),
        })
    }

    /// Returns the number of registered providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Returns `true` when nothing is registered, which never happens.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Looks a provider up by its frozen identifier.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&'static ProviderDescriptor> {
        self.by_id.get(id).copied()
    }

    /// Iterates in frozen inventory order.
    pub fn iter(&self) -> impl Iterator<Item = &'static ProviderDescriptor> {
        PROVIDERS.iter()
    }

    /// Returns every provider whose identifiers sort ascending.
    #[must_use]
    pub fn ids(&self) -> Vec<&'static str> {
        self.by_id.keys().copied().collect()
    }

    /// Returns every provider with the given implementation status.
    #[must_use]
    pub fn with_status(&self, status: ImplementationStatus) -> Vec<&'static ProviderDescriptor> {
        let mut matches: Vec<_> = self
            .by_id
            .values()
            .copied()
            .filter(|descriptor| descriptor.status == status)
            .collect();
        matches.sort_unstable_by_key(|descriptor| descriptor.id);
        matches
    }

    /// Returns every provider in the given dialect family.
    #[must_use]
    pub fn with_family(&self, family: ProviderFamily) -> Vec<&'static ProviderDescriptor> {
        let mut matches: Vec<_> = self
            .by_id
            .values()
            .copied()
            .filter(|descriptor| descriptor.family == family)
            .collect();
        matches.sort_unstable_by_key(|descriptor| descriptor.id);
        matches
    }
}

/// Looks a provider up in the global registry.
#[must_use]
pub fn lookup(id: &str) -> Option<&'static ProviderDescriptor> {
    ProviderRegistry::global().get(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_holds_exactly_seventy_eight_unique_providers() {
        assert_eq!(PROVIDERS.len(), 78);
        let registry = ProviderRegistry::global();
        assert_eq!(registry.len(), 78);
        assert!(!registry.is_empty());
    }

    #[test]
    fn the_descriptor_macro_derives_record_ids_and_paths_from_the_provider_id() {
        // Scope, stated plainly: this pins the *macro template*, not the frozen
        // data. `record_id` and `source_path` are built by `provider_table!` from
        // `$id` and `$dir`, so no value of those inputs can make this fail — only
        // an edit to the template can. Conformance against the frozen inventory is
        // proved by `tests/frozen_inventory.rs`, which reads
        // `compat/upstream/inventories/providers.json` at run time; a provider id
        // that drifts from upstream is caught there and is invisible here.
        for descriptor in PROVIDERS {
            assert_eq!(
                descriptor.record_id,
                format!("provider:{}", descriptor.id),
                "{}",
                descriptor.id
            );
            assert!(
                descriptor.source_path.starts_with("extensions/"),
                "{}",
                descriptor.id
            );
            assert!(
                descriptor.source_path.ends_with("/openclaw.plugin.json"),
                "{}",
                descriptor.id
            );
        }
    }

    #[test]
    fn every_descriptor_has_a_distinct_display_name() {
        let mut names: Vec<&str> = PROVIDERS
            .iter()
            .map(|descriptor| descriptor.display_name)
            .collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(names.len(), total, "display names must be unique");
    }

    #[test]
    fn registration_only_providers_advertise_no_capabilities() {
        for descriptor in PROVIDERS {
            if descriptor.is_registration_only() {
                assert_eq!(
                    descriptor.capabilities,
                    CapabilitySet::EMPTY,
                    "{} must not advertise capabilities",
                    descriptor.id
                );
            } else {
                // The load-bearing assertion of this test: `capabilities_for`
                // falls through to `EMPTY` for any family outside the three that
                // ship a client, so this fails if a provider claims a client
                // status in a dialect nothing can drive.
                assert!(
                    !descriptor.capabilities.is_empty(),
                    "{} claims a client but advertises nothing",
                    descriptor.id
                );
            }
        }
    }

    #[test]
    fn implemented_providers_carry_a_default_https_or_loopback_endpoint() {
        for descriptor in PROVIDERS {
            match descriptor.status {
                ImplementationStatus::Implemented => {
                    let base = descriptor
                        .base_url
                        .unwrap_or_else(|| panic!("{} must ship a base URL", descriptor.id));
                    assert!(
                        base.starts_with("https://") || base.starts_with("http://127.0.0.1:"),
                        "{} has a non-TLS remote endpoint: {base}",
                        descriptor.id
                    );
                    assert!(
                        !base.ends_with('/'),
                        "{} base URL has a trailing slash",
                        descriptor.id
                    );
                }
                ImplementationStatus::EndpointRequired | ImplementationStatus::RegistrationOnly => {
                    assert_eq!(
                        descriptor.base_url, None,
                        "{} must not ship a base URL",
                        descriptor.id
                    );
                }
            }
        }
    }

    #[test]
    fn every_client_bearing_provider_is_dispatched_to_its_dialect_constant() {
        // Scope, stated plainly: this pins the *dispatch* performed by
        // `capabilities_for` — which family maps to which constant — and is blind
        // to the *content* of those constants, because both sides of the
        // comparison read the same three constants. Emptying `COPILOT_CAPABILITIES`
        // or adding a false capability to it leaves this test green. The content of
        // each constant is pinned in `descriptor.rs` against hand-written lists.
        for descriptor in PROVIDERS.iter().filter(|entry| entry.status.has_client()) {
            let expected = match descriptor.family {
                ProviderFamily::OpenAiChatCompletions => OPENAI_CAPABILITIES,
                ProviderFamily::AnthropicMessages => ANTHROPIC_CAPABILITIES,
                ProviderFamily::GitHubCopilot => COPILOT_CAPABILITIES,
                other => panic!("{} has no client for dialect {other}", descriptor.id),
            };
            assert_eq!(descriptor.capabilities, expected, "{}", descriptor.id);
        }
    }

    #[test]
    fn every_provider_declares_at_least_one_auth_mode() {
        for descriptor in PROVIDERS {
            assert!(
                !descriptor.auth_modes.is_empty(),
                "{} declares no auth mode",
                descriptor.id
            );
            let mut modes = descriptor.auth_modes.to_vec();
            modes.sort_unstable();
            let total = modes.len();
            modes.dedup();
            assert_eq!(modes.len(), total, "{} repeats an auth mode", descriptor.id);
        }
    }

    #[test]
    fn credential_free_providers_are_exactly_the_local_runtimes() {
        let mut free: Vec<&str> = PROVIDERS
            .iter()
            .filter(|descriptor| descriptor.is_credential_free())
            .map(|descriptor| descriptor.id)
            .collect();
        free.sort_unstable();
        assert_eq!(
            free,
            vec![
                "comfy",
                "copilot-proxy",
                "lmstudio",
                "ollama",
                "sglang",
                "vllm"
            ]
        );
    }

    #[test]
    fn lookup_finds_registered_providers_and_rejects_others() {
        let registry = ProviderRegistry::global();
        let openai = registry.get("openai").expect("openai is registered");
        assert_eq!(openai.display_name, "OpenAI");
        assert_eq!(openai.plugin_id, "openai");
        assert_eq!(openai.family, ProviderFamily::OpenAiChatCompletions);
        assert_eq!(openai.status, ImplementationStatus::Implemented);
        assert_eq!(openai.base_url, Some("https://api.openai.com/v1"));
        assert_eq!(lookup("openai"), Some(openai));

        assert_eq!(registry.get("OpenAI"), None);
        assert_eq!(registry.get("openai "), None);
        assert_eq!(registry.get("not-a-provider"), None);
        assert_eq!(lookup(""), None);
    }

    #[test]
    fn aliases_share_their_plugin_but_keep_distinct_identifiers() {
        let registry = ProviderRegistry::global();
        for id in [
            "qwen",
            "qwencloud",
            "qwen-oauth",
            "qwen-portal",
            "modelstudio",
            "dashscope",
            "qwen-cli",
            "qwen-token-plan",
            "bailian-token-plan",
        ] {
            let entry = registry.get(id).expect("registered");
            assert_eq!(entry.plugin_id, "qwen", "{id}");
            assert_eq!(entry.id, id);
        }
        assert_eq!(
            registry.get("kimi").expect("registered").source_path,
            "extensions/kimi-coding/openclaw.plugin.json",
            "kimi's manifest lives in the kimi-coding directory upstream"
        );
    }

    #[test]
    fn status_and_family_filters_partition_the_registry() {
        let registry = ProviderRegistry::global();
        let implemented = registry.with_status(ImplementationStatus::Implemented);
        let endpoint_required = registry.with_status(ImplementationStatus::EndpointRequired);
        let registration_only = registry.with_status(ImplementationStatus::RegistrationOnly);
        assert_eq!(
            implemented.len() + endpoint_required.len() + registration_only.len(),
            78
        );
        assert_eq!(implemented.len(), 28);
        assert_eq!(registration_only.len(), 12);
        assert_eq!(endpoint_required.len(), 38);

        let anthropic = registry.with_family(ProviderFamily::AnthropicMessages);
        assert_eq!(
            anthropic.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec!["anthropic", "anthropic-vertex"]
        );
        assert_eq!(
            registry
                .with_family(ProviderFamily::GitHubCopilot)
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            vec!["github-copilot"]
        );
    }

    #[test]
    fn the_implemented_set_is_exactly_the_documented_list() {
        let mut implemented: Vec<&str> = ProviderRegistry::global()
            .with_status(ImplementationStatus::Implemented)
            .iter()
            .map(|entry| entry.id)
            .collect();
        implemented.sort_unstable();
        assert_eq!(
            implemented,
            vec![
                "anthropic",
                "arcee",
                "cerebras",
                "chutes",
                "dashscope",
                "deepinfra",
                "deepseek",
                "featherless",
                "fireworks",
                "github-copilot",
                "groq",
                "huggingface",
                "litellm",
                "lmstudio",
                "mistral",
                "modelstudio",
                "moonshot",
                "nvidia",
                "ollama",
                "openai",
                "openrouter",
                "sglang",
                "together",
                "venice",
                "vercel-ai-gateway",
                "vllm",
                "volcengine",
                "xai",
            ]
        );
    }

    #[test]
    fn the_registration_only_set_is_exactly_the_documented_list() {
        let mut registration_only: Vec<&str> = ProviderRegistry::global()
            .with_status(ImplementationStatus::RegistrationOnly)
            .iter()
            .map(|entry| entry.id)
            .collect();
        registration_only.sort_unstable();
        assert_eq!(
            registration_only,
            vec![
                "amazon-bedrock",
                "amazon-bedrock-mantle",
                "anthropic-vertex",
                "codex",
                "cohere",
                "comfy",
                "fal",
                "google",
                "google-gemini-cli",
                "google-vertex",
                "microsoft-foundry",
                "vydra",
            ]
        );
    }

    #[test]
    fn iteration_preserves_frozen_inventory_order() {
        let ids: Vec<&str> = ProviderRegistry::global()
            .iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(ids.len(), 78);
        assert_eq!(ids[0], "qianfan");
        assert_eq!(ids[1], "qwen");
        assert_eq!(ids[77], "google-vertex");

        let sorted = ProviderRegistry::global().ids();
        assert_eq!(sorted.len(), 78);
        assert!(sorted.windows(2).all(|pair| pair[0] < pair[1]));
    }
}

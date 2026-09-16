//! Explicit native provider selection and independently enrolled credential origins.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use claw_config::SecretRef;
use claw_provider_sdk::clock::{PseudoRandomJitter, SystemClock};
use claw_provider_sdk::http::{HttpTransport, ProxyPolicy, TlsPolicy, TransportConfig};
use claw_provider_sdk::{ApiKey, Origin, OriginApproval, Provider, SecretString};
use claw_providers::anthropic::AnthropicConfig;
use claw_providers::openai_compatible::CompletionDialect;
use claw_providers::{Anthropic, OpenAiCompatible, ProviderRuntime, ReliabilityConfig};
use serde::Deserialize;
use url::Url;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ProviderKind {
    Openai,
    Anthropic,
}

impl ProviderKind {
    const fn id(self) -> &'static str {
        match self {
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
        }
    }

    const fn default_url(self) -> &'static str {
        match self {
            Self::Openai => "https://api.openai.com/v1/",
            Self::Anthropic => "https://api.anthropic.com/",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct NativeProviderPolicy {
    provider: ProviderKind,
    pub(super) model: String,
    api_key: String,
    base_url: Option<String>,
    request_timeout_ms: Option<u64>,
    completion_api: Option<CompletionDialect>,
    pub(super) max_observed_turn_tokens: Option<u64>,
}

impl NativeProviderPolicy {
    pub(super) fn from_configuration(
        config: Option<&claw_config::ProviderConfig>,
    ) -> Result<Option<Self>, String> {
        let environment = match std::env::var("GTA_CLAW_PROVIDER_POLICY") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("native provider policy must be UTF-8".to_owned()),
        };
        Self::select(config, environment.as_deref())
    }

    fn select(
        config: Option<&claw_config::ProviderConfig>,
        environment: Option<&str>,
    ) -> Result<Option<Self>, String> {
        if config.is_some() && environment.is_some() {
            return Err("core.provider and GTA_CLAW_PROVIDER_POLICY cannot be combined; choose one explicit configuration source".to_owned());
        }
        let Some(config) = config else {
            return environment.map(Self::parse).transpose();
        };
        let provider = match config.kind() {
            claw_config::ProviderKind::Openai => ProviderKind::Openai,
            claw_config::ProviderKind::Anthropic => ProviderKind::Anthropic,
            claw_config::ProviderKind::Copilot | claw_config::ProviderKind::Disabled => {
                return Ok(None);
            }
        };
        Ok(Some(Self {
            provider,
            model: config.model().expect("validated active model").to_owned(),
            api_key: config
                .api_key()
                .expect("validated native credential reference")
                .as_str()
                .to_owned(),
            base_url: config.base_url().map(str::to_owned),
            request_timeout_ms: config.request_timeout_ms(),
            completion_api: config.completion_api().map(|dialect| match dialect {
                claw_config::ProviderCompletionApi::ChatCompletions => {
                    CompletionDialect::ChatCompletions
                }
                claw_config::ProviderCompletionApi::Responses => CompletionDialect::Responses,
            }),
            max_observed_turn_tokens: config.max_observed_turn_tokens(),
        }))
    }

    pub(super) const fn provider_id(&self) -> &'static str {
        self.provider.id()
    }

    fn parse(value: &str) -> Result<Self, String> {
        if value.len() > 16 * 1024 {
            return Err("native provider policy exceeds its byte limit".to_owned());
        }
        let policy: Self = serde_json::from_str(value)
            .map_err(|_| "native provider policy does not match its closed schema".to_owned())?;
        if policy.model.is_empty()
            || policy.model.len() > 256
            || policy.model.trim() != policy.model
            || policy.model.chars().any(char::is_control)
            || policy
                .request_timeout_ms
                .is_some_and(|value| !(1_000..=120_000).contains(&value))
        {
            return Err("native provider model or timeout is invalid".to_owned());
        }
        SecretRef::parse(&policy.api_key).map_err(|_| {
            "native provider apiKey must be a SecretRef, never a literal credential".to_owned()
        })?;
        if matches!(policy.provider, ProviderKind::Anthropic) && policy.completion_api.is_some() {
            return Err(
                "native completionApi is only supported for the OpenAI provider".to_owned(),
            );
        }
        policy.endpoint()?;
        Ok(policy)
    }

    fn endpoint(&self) -> Result<Url, String> {
        let value = self
            .base_url
            .as_deref()
            .unwrap_or_else(|| self.provider.default_url());
        let endpoint =
            Url::parse(value).map_err(|_| "native provider endpoint is invalid".to_owned())?;
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
            || value.split('/').any(|part| matches!(part, "." | ".."))
        {
            return Err("native provider endpoint must not contain credentials, query, fragment or ambiguous paths".to_owned());
        }
        Origin::of(&endpoint).map_err(|_| {
            "native provider endpoint must be HTTPS or explicit loopback HTTP".to_owned()
        })?;
        Ok(endpoint)
    }

    pub(super) fn build(
        &self,
        proxy: ProxyPolicy,
        enrolled: &BTreeMap<String, Vec<String>>,
        resolve: impl FnOnce(&SecretRef) -> Result<SecretString, String>,
    ) -> Result<Arc<dyn Provider>, String> {
        let endpoint = self.endpoint()?;
        let origin =
            Origin::of(&endpoint).map_err(|_| "native provider origin is invalid".to_owned())?;
        let default = Url::parse(self.provider.default_url())
            .map_err(|_| "compiled provider endpoint is invalid".to_owned())?;
        let default_origin =
            Origin::of(&default).map_err(|_| "compiled provider origin is invalid".to_owned())?;
        let approval = if origin == default_origin {
            None
        } else {
            let trusted = enrolled.get(self.provider.id()).ok_or_else(|| {
                "custom provider credential origin has not been independently enrolled".to_owned()
            })?;
            let mut approval = None;
            for trusted in trusted {
                let candidate = Url::parse(trusted)
                    .map_err(|_| "enrolled provider origin is invalid".to_owned())?;
                let approved_origin = Origin::of(&candidate)
                    .map_err(|_| "enrolled provider origin is invalid".to_owned())?;
                if candidate.path() != "/"
                    || !candidate.username().is_empty()
                    || candidate.password().is_some()
                    || candidate.query().is_some()
                    || candidate.fragment().is_some()
                {
                    return Err(
                        "enrolled provider origin must contain only scheme, host and port"
                            .to_owned(),
                    );
                }
                if approved_origin == origin {
                    approval = Some(OriginApproval::enroll(approved_origin));
                }
            }
            Some(approval.ok_or_else(|| {
                "provider endpoint does not match the independently enrolled credential origin"
                    .to_owned()
            })?)
        };
        let reference = SecretRef::parse(&self.api_key)
            .map_err(|_| "native provider credential reference is invalid".to_owned())?;
        let secret = resolve(&reference)?;
        if secret.expose().is_empty()
            || secret.expose().len() > 4096
            || !secret.expose().bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(
                "native provider credential must be bounded non-whitespace ASCII".to_owned(),
            );
        }
        let key = ApiKey::from(secret);
        let reliability = ReliabilityConfig {
            retry: claw_provider_sdk::retry::RetryPolicy::never(),
            ..ReliabilityConfig::default()
        };
        let transport = HttpTransport::with_config(&TransportConfig {
            tls_policy: if endpoint.scheme() == "http" {
                TlsPolicy::AllowLoopbackPlaintext
            } else {
                TlsPolicy::RequireHttps
            },
            proxy_policy: proxy,
            request_timeout: Duration::from_millis(self.request_timeout_ms.unwrap_or(120_000)),
            ..TransportConfig::default()
        })
        .map_err(|_| "native provider transport could not be initialized".to_owned())?;
        let runtime = ProviderRuntime::with_parts(
            self.provider.id(),
            transport,
            reliability,
            Arc::new(SystemClock),
            Arc::new(PseudoRandomJitter::from_entropy()),
        );
        match self.provider {
            ProviderKind::Openai => {
                let provider = if let Some(approval) = &approval {
                    OpenAiCompatible::from_registry_with_enrolled_origin(
                        "openai",
                        Some(key),
                        endpoint,
                        approval,
                    )
                } else {
                    OpenAiCompatible::from_registry("openai", Some(key), Some(endpoint))
                }
                .map_err(|_| {
                    "native OpenAI-compatible provider configuration was refused".to_owned()
                })?;
                Ok(Arc::new(
                    provider
                        .with_completion_dialect(self.completion_api.unwrap_or_default())
                        .with_runtime(runtime),
                ))
            }
            ProviderKind::Anthropic => {
                let config = if let Some(approval) = &approval {
                    AnthropicConfig::for_enrolled_origin(key, endpoint, approval)
                } else {
                    AnthropicConfig::new(key).map(|mut config| {
                        config.base_url = endpoint;
                        config
                    })
                }
                .map_err(|_| "native Anthropic provider configuration was refused".to_owned())?;
                let provider = Anthropic::new(config)
                    .map_err(|_| "native Anthropic provider could not be initialized".to_owned())?;
                Ok(Arc::new(provider.with_runtime(runtime)))
            }
        }
    }
}

pub(super) fn enrolled_origins_from_environment() -> Result<BTreeMap<String, Vec<String>>, String> {
    match std::env::var("GTA_CLAW_PROVIDER_ORIGINS") {
        Ok(encoded) => {
            if encoded.len() > 8 * 1024 {
                return Err("provider origin enrollment exceeds its byte limit".to_owned());
            }
            let origins: BTreeMap<String, Vec<String>> =
                serde_json::from_str(&encoded).map_err(|_| {
                    "provider origin enrollment must be a provider-to-origins JSON object"
                        .to_owned()
                })?;
            if origins.len() > 2
                || origins.iter().any(|(provider, entries)| {
                    !matches!(provider.as_str(), "openai" | "anthropic") || entries.len() > 8
                })
            {
                return Err(
                    "provider origin enrollment contains unsupported or excessive entries"
                        .to_owned(),
                );
            }
            Ok(origins)
        }
        Err(std::env::VarError::NotPresent) => Ok(BTreeMap::new()),
        Err(_) => Err("provider origin enrollment must be UTF-8".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn typed_provider_selection_preserves_bindings_and_rejects_legacy_policy_conflicts() {
        for kind in ["openai", "anthropic", "copilot", "disabled"] {
            let mut selection = json!({"kind":kind});
            if kind != "disabled" {
                selection["model"] = json!("fixture-model");
                selection["request_timeout_ms"] = json!(5000);
                selection["max_observed_turn_tokens"] = json!(0);
            }
            if matches!(kind, "openai" | "anthropic") {
                selection["api_key"] = json!("env:NATIVE_TEST_KEY");
                selection["base_url"] = json!("http://127.0.0.1:23456/v1/");
                selection["credential_origin"] = json!("http://127.0.0.1:23456");
            }
            if kind == "openai" {
                selection["completion_api"] = json!("responses");
            }
            let snapshot = claw_config::ConfigLayers::new().with_workspace_json5(json!({"core":{
                "auth":{"github":{"pat":"env:GITHUB_TEST_KEY"}},"role":{"source_url":"http://127.0.0.1:23456/role"},
                "channels":{"teams":{"enabled":false}},"provider":selection}}).to_string()).resolve().expect("typed selection").config;
            for encoded in [
                "",
                "{}",
                "not-json",
                r#"{"provider":"openai","model":"other","apiKey":"env:OTHER"}"#,
            ] {
                assert!(
                    NativeProviderPolicy::select(snapshot.core().provider(), Some(encoded))
                        .is_err(),
                    "{kind}"
                );
            }
            let policy =
                NativeProviderPolicy::select(snapshot.core().provider(), None).expect("one source");
            if matches!(kind, "openai" | "anthropic") {
                let policy = policy.expect("native client selection");
                assert_eq!(policy.provider_id(), kind);
                assert_eq!(policy.model, "fixture-model");
                assert_eq!(policy.request_timeout_ms, Some(5000));
                assert_eq!(policy.max_observed_turn_tokens, Some(0));
                assert!(
                    policy
                        .build(ProxyPolicy::Disabled, &BTreeMap::new(), |_| panic!(
                            "declaration cannot authorize an origin"
                        ))
                        .is_err()
                );
                let enrolled =
                    BTreeMap::from([(kind.to_owned(), vec!["http://127.0.0.1:23456".to_owned()])]);
                let client = policy
                    .build(ProxyPolicy::Disabled, &enrolled, |reference| {
                        assert_eq!(reference.as_str(), "env:NATIVE_TEST_KEY");
                        Ok(SecretString::new("synthetic-native-key"))
                    })
                    .expect("independently enrolled client");
                assert_eq!(client.id().as_str(), kind);
            } else {
                assert!(policy.is_none());
            }
        }
        assert!(
            NativeProviderPolicy::select(None, None)
                .expect("legacy default")
                .is_none()
        );
        assert!(
            NativeProviderPolicy::select(
                None,
                Some(r#"{"provider":"openai","model":"legacy-model","apiKey":"env:LEGACY_KEY"}"#)
            )
            .expect("legacy policy")
            .is_some()
        );
    }

    #[test]
    fn native_provider_observed_budget_is_optional_typed_and_allows_explicit_zero() {
        for provider in ["openai", "anthropic"] {
            let base = json!({"provider":provider,"model":"model","apiKey":"env:TEST_KEY"});
            assert_eq!(
                NativeProviderPolicy::parse(&base.to_string())
                    .expect("default")
                    .max_observed_turn_tokens,
                None
            );
            for value in [0, 1, 10_000, u64::MAX] {
                let mut configured = base.clone();
                configured["maxObservedTurnTokens"] = json!(value);
                assert_eq!(
                    NativeProviderPolicy::parse(&configured.to_string())
                        .expect("budget")
                        .max_observed_turn_tokens,
                    Some(value)
                );
            }
            for invalid in [json!(-1), json!(0.5), json!("1000"), json!(true), json!({})] {
                let mut configured = base.clone();
                configured["maxObservedTurnTokens"] = invalid;
                assert!(NativeProviderPolicy::parse(&configured.to_string()).is_err());
            }
        }
    }

    #[test]
    fn native_provider_policy_rejects_literals_unknown_fields_and_unenrolled_destinations() {
        for value in [
            json!({"provider":"other","model":"model","apiKey":"env:TEST_KEY"}),
            json!({"provider":"openai","model":"model","apiKey":"literal-secret"}),
            json!({"provider":"openai","model":"model","apiKey":"env:TEST_KEY","fallback":true}),
            json!({"provider":"openai","model":"model","apiKey":"env:TEST_KEY","baseUrl":"https://user:secret@example.test/v1/"}),
        ] {
            assert!(NativeProviderPolicy::parse(&value.to_string()).is_err());
        }
        let policy = NativeProviderPolicy::parse(&json!({"provider":"openai","model":"model","apiKey":"env:TEST_KEY","baseUrl":"http://127.0.0.1:23456/v1/"}).to_string()).expect("typed policy");
        assert!(
            policy
                .build(ProxyPolicy::Disabled, &BTreeMap::new(), |_| panic!(
                    "unenrolled origin must not read a secret"
                ))
                .is_err()
        );
    }

    #[test]
    fn native_provider_policy_constructs_both_rust_clients_without_network() {
        for provider in ["openai", "anthropic"] {
            let policy = NativeProviderPolicy::parse(
                &json!({"provider":provider,"model":"model","apiKey":"env:TEST_KEY"}).to_string(),
            )
            .expect("native provider policy");
            let client = policy
                .build(ProxyPolicy::Disabled, &BTreeMap::new(), |_| {
                    Ok(SecretString::new("test-key"))
                })
                .expect("native client");
            assert_eq!(client.id().as_str(), provider);
        }
    }

    #[test]
    fn native_provider_responses_selection_is_explicit_and_openai_only() {
        for completion_api in [None, Some("chat_completions"), Some("responses")] {
            let mut value = json!({"provider":"openai","model":"model","apiKey":"env:TEST_KEY"});
            if let Some(completion_api) = completion_api {
                value["completionApi"] = json!(completion_api);
            }
            let policy = NativeProviderPolicy::parse(&value.to_string()).expect("explicit dialect");
            assert_eq!(
                policy.completion_api.unwrap_or_default(),
                if completion_api == Some("responses") {
                    CompletionDialect::Responses
                } else {
                    CompletionDialect::ChatCompletions
                }
            );
            assert!(
                policy
                    .build(ProxyPolicy::Disabled, &BTreeMap::new(), |_| {
                        Ok(SecretString::new("owned-fixture-key"))
                    })
                    .is_ok()
            );
        }
        for (provider, completion_api) in [
            ("openai", "auto"),
            ("anthropic", "responses"),
            ("anthropic", "chat_completions"),
        ] {
            let value = json!({"provider":provider,"model":"model","apiKey":"env:TEST_KEY","completionApi":completion_api});
            assert!(NativeProviderPolicy::parse(&value.to_string()).is_err());
        }
    }
}

//! Exhaustive contracts for the public legacy runtime disposition registry.

#[allow(dead_code)]
#[path = "../build_support.rs"]
mod build_support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use build_support::load_contract;
use claw_config::{
    AcceptedOnlyReason, LEGACY_RUNTIME_CONFIGS, LegacyRuntimeDisposition, LegacyRuntimeKey,
    LegacyRuntimeOwner, legacy_runtime_config,
};

#[test]
fn registry_exactly_matches_the_independent_frozen_runtime_oracle() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let frozen = load_contract(&manifest.join("../../compat/legacy/config/env-mapping.json"));
    let expected = frozen
        .mappings
        .iter()
        .filter(|mapping| mapping.scope == "runtime" && mapping.legacy_env != "COPILOT_CLI_PATH")
        .map(|mapping| {
            (
                mapping.legacy_env.as_str(),
                (
                    mapping.target_json5_key.as_str(),
                    mapping
                        .aliases
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let actual = LEGACY_RUNTIME_CONFIGS
        .iter()
        .map(|entry| {
            (
                entry.legacy_env(),
                (entry.target_json5_path(), entry.aliases().to_vec()),
            )
        })
        .collect::<BTreeMap<_, _>>();

    assert_eq!(actual, expected);
    assert_eq!(actual.len(), LEGACY_RUNTIME_CONFIGS.len());
    assert!(!actual.contains_key("COPILOT_CLI_PATH"));
}

#[test]
fn aliases_are_unique_names_for_one_semantic_leaf() {
    let mut all_environment_names = BTreeSet::new();
    let semantic_names = LEGACY_RUNTIME_CONFIGS
        .iter()
        .map(|entry| entry.legacy_env())
        .collect::<BTreeSet<_>>();

    for entry in LEGACY_RUNTIME_CONFIGS {
        assert!(all_environment_names.insert(entry.legacy_env()));
        for alias in entry.aliases() {
            assert!(all_environment_names.insert(alias));
            assert!(!semantic_names.contains(alias));
        }
    }

    let proxy = legacy_runtime_config(LegacyRuntimeKey::HttpsProxy);
    assert_eq!(
        proxy.aliases(),
        &[
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ]
    );
    assert_eq!(
        LEGACY_RUNTIME_CONFIGS
            .iter()
            .filter(|entry| entry.target_json5_path() == "network.proxy_url")
            .map(|entry| entry.key())
            .collect::<Vec<_>>(),
        vec![LegacyRuntimeKey::HttpsProxy]
    );
}

#[test]
fn accepted_only_is_a_typed_non_enforcement_disposition() {
    for entry in LEGACY_RUNTIME_CONFIGS {
        assert_eq!(
            entry.disposition(),
            LegacyRuntimeDisposition::AcceptedOnly(AcceptedOnlyReason::NoProductionConsumer),
            "{} must not imply consumer enforcement",
            entry.legacy_env()
        );
    }

    let domains = legacy_runtime_config(LegacyRuntimeKey::AllowedSkillDomains);
    assert_eq!(domains.intended_owner(), LegacyRuntimeOwner::SkillRuntime);
    assert_eq!(
        domains.semantic_note(),
        "Intended outbound skill HTTP domain policy; configuration alone does not enforce a security boundary."
    );

    let rate_limit = legacy_runtime_config(LegacyRuntimeKey::RateLimitPerMin);
    assert_eq!(rate_limit.intended_owner(), LegacyRuntimeOwner::GatewayHttp);
    assert_eq!(
        rate_limit.semantic_note(),
        "Intended per-IP /api/messages ingress rate limit; configuration alone does not enforce request throttling."
    );
}

#[test]
fn session_settings_are_only_ephemeral_provider_session_cache_policy() {
    let ttl = legacy_runtime_config(LegacyRuntimeKey::SessionTtlMs);
    assert_eq!(ttl.target_json5_path(), "sessions.ttl_ms");
    assert_eq!(
        ttl.intended_owner(),
        LegacyRuntimeOwner::ProviderSessionCache
    );
    assert_eq!(
        ttl.semantic_note(),
        "Controls the ephemeral provider-session cache TTL; it must never evict durable claw-memory data."
    );

    let capacity = legacy_runtime_config(LegacyRuntimeKey::MaxSessions);
    assert_eq!(capacity.target_json5_path(), "sessions.max_entries");
    assert_eq!(
        capacity.intended_owner(),
        LegacyRuntimeOwner::ProviderSessionCache
    );
    assert_eq!(
        capacity.semantic_note(),
        "Caps entries in the ephemeral provider-session cache; it must never evict durable claw-memory data."
    );
}

//! Build-time ownership boundary for the frozen GTA legacy mapping contract.

mod build_support;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use build_support::{Contract, Mapping};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let packaged_path = manifest_dir.join("data/env-mapping.json");
    println!("cargo:rerun-if-changed={}", packaged_path.display());
    let canonical = build_support::load_contract(&packaged_path);
    build_support::validate_contract(&canonical).expect("validate packaged mapping contract");

    verify_workspace_contract(&manifest_dir, &canonical);

    let generated = generate(&canonical);
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"))
        .join("legacy_mappings.rs");
    fs::write(output, generated).expect("write generated legacy mapping table");
}

fn verify_workspace_contract(manifest_dir: &Path, canonical: &Contract) {
    let workspace_root = manifest_dir.join("../..");
    let repository_marker = workspace_root.join("compat/legacy/contract.json");
    if !repository_marker.is_file() {
        return;
    }

    let workspace_path = workspace_root.join("compat/legacy/config/env-mapping.json");
    println!("cargo:rerun-if-changed={}", workspace_path.display());
    let workspace = build_support::load_contract(&workspace_path);
    build_support::validate_contract(&workspace).expect("validate workspace mapping contract");
    build_support::ensure_same_contract(canonical, &workspace)
        .expect("workspace mapping contract drifted from crates/claw-config/data/env-mapping.json");
}

fn generate(contract: &Contract) -> String {
    let mut output = String::from(
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub(crate) enum MappingId {\n",
    );
    for mapping in &contract.mappings {
        output.push_str("    ");
        output.push_str(&variant_name(&mapping.legacy_env));
        output.push_str(",\n");
    }
    output.push_str("}\n\n");
    generate_runtime_key_enum(&mut output, contract);
    output.push_str("pub(crate) static LEGACY_MAPPINGS: &[LegacyMappingContract] = &[\n");
    for mapping in &contract.mappings {
        generate_mapping(&mut output, mapping);
    }
    output.push_str("];\n\n");
    generate_runtime_registry(&mut output, contract);
    output
}

fn generate_runtime_key_enum(output: &mut String, contract: &Contract) {
    output.push_str(
        "/// Stable typed identities for automatically accepted legacy runtime settings.\n\
         #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]\n\
         pub enum LegacyRuntimeKey {\n",
    );
    for mapping in automatically_accepted_runtime_mappings(contract) {
        output.push_str("    /// Canonical `");
        output.push_str(&mapping.legacy_env);
        output.push_str("` legacy runtime setting.\n    ");
        output.push_str(&runtime_variant_name(&mapping.legacy_env));
        output.push_str(",\n");
    }
    output.push_str("}\n\n");
}

fn generate_runtime_registry(output: &mut String, contract: &Contract) {
    output.push_str(
        "/// Complete disposition registry for automatically accepted legacy runtime settings.\n\
         ///\n\
         /// Every entry is currently accepted-only: migration represents the value, but no\n\
         /// production crate outside `claw-config` has been established as its consumer.\n\
         pub static LEGACY_RUNTIME_CONFIGS: &[LegacyRuntimeConfig] = &[\n",
    );
    for mapping in automatically_accepted_runtime_mappings(contract) {
        let (owner, semantic_note) = runtime_metadata(&mapping.legacy_env);
        output.push_str("    LegacyRuntimeConfig::accepted_only(LegacyRuntimeKey::");
        output.push_str(&runtime_variant_name(&mapping.legacy_env));
        output.push_str(", ");
        output.push_str(&literal(&mapping.legacy_env));
        output.push_str(", &[");
        for alias in &mapping.aliases {
            output.push_str(&literal(alias));
            output.push(',');
        }
        output.push_str("], ");
        output.push_str(&literal(&mapping.target_json5_key));
        output.push_str(", LegacyRuntimeOwner::");
        output.push_str(owner);
        output.push_str(", ");
        output.push_str(&literal(semantic_note));
        output.push_str("),\n");
    }
    output.push_str("];\n");
}

fn automatically_accepted_runtime_mappings(contract: &Contract) -> impl Iterator<Item = &Mapping> {
    contract
        .mappings
        .iter()
        .filter(|mapping| mapping.scope == "runtime" && mapping.legacy_env != "COPILOT_CLI_PATH")
}

fn runtime_variant_name(value: &str) -> String {
    match value {
        "MicrosoftAppId" => "MicrosoftAppId".to_owned(),
        "MicrosoftAppPassword" => "MicrosoftAppPassword".to_owned(),
        _ => variant_name(value),
    }
}

fn runtime_metadata(legacy_env: &str) -> (&'static str, &'static str) {
    match legacy_env {
        "GITHUB_TOKEN" => (
            "Authentication",
            "Provider authentication credential; accepted migration does not bind a provider.",
        ),
        "DEVICE_FLOW_ENABLED" => (
            "Authentication",
            "GitHub device-flow policy; accepted migration does not start or govern device flow.",
        ),
        "GITHUB_CLIENT_ID" => (
            "Authentication",
            "GitHub device-flow client identity; accepted migration does not bind authentication.",
        ),
        "MicrosoftAppId" => (
            "ChannelAdapters",
            "Teams application identity; accepted migration does not configure a Teams adapter.",
        ),
        "MicrosoftAppPassword" => (
            "ChannelAdapters",
            "Teams application credential; accepted migration does not configure a Teams adapter.",
        ),
        "AGENT_ROLE_URL" => (
            "RoleLoading",
            "Remote role source; accepted migration does not fetch or load an agent role.",
        ),
        "ENABLED_SKILLS" => (
            "SkillRuntime",
            "Legacy skill source list; accepted migration does not discover or enable skills.",
        ),
        "ENABLE_TEAMS" => (
            "ChannelAdapters",
            "Teams channel enablement; accepted migration does not start a Teams adapter.",
        ),
        "ENABLE_TELEGRAM" => (
            "ChannelAdapters",
            "Telegram channel enablement; accepted migration does not start a Telegram adapter.",
        ),
        "TELEGRAM_BOT_TOKEN" => (
            "ChannelAdapters",
            "Telegram bot credential; accepted migration does not configure a Telegram adapter.",
        ),
        "TELEGRAM_POLL_INTERVAL_MS" => (
            "ChannelAdapters",
            "Telegram polling cadence; accepted migration does not schedule Telegram polling.",
        ),
        "ENABLE_DISCORD" => (
            "ChannelAdapters",
            "Discord channel enablement; accepted migration does not start a Discord adapter.",
        ),
        "DISCORD_BOT_TOKEN" => (
            "ChannelAdapters",
            "Discord bot credential; accepted migration does not configure a Discord adapter.",
        ),
        "DISCORD_GATEWAY_URL" => (
            "ChannelAdapters",
            "Discord gateway endpoint; accepted migration does not connect a Discord adapter.",
        ),
        "DISCORD_GATEWAY_INTENTS" => (
            "ChannelAdapters",
            "Discord gateway intents; accepted migration does not configure a Discord connection.",
        ),
        "ENABLE_WHATSAPP" => (
            "ChannelAdapters",
            "WhatsApp channel enablement; accepted migration does not start a WhatsApp adapter.",
        ),
        "WHATSAPP_VERIFY_TOKEN" => (
            "ChannelAdapters",
            "WhatsApp webhook verification credential; accepted migration does not bind a webhook.",
        ),
        "WHATSAPP_ACCESS_TOKEN" => (
            "ChannelAdapters",
            "WhatsApp API credential; accepted migration does not configure a WhatsApp adapter.",
        ),
        "WHATSAPP_PHONE_NUMBER_ID" => (
            "ChannelAdapters",
            "WhatsApp sender identity; accepted migration does not configure message delivery.",
        ),
        "WHATSAPP_WEBHOOK_PATH" => (
            "ChannelAdapters",
            "WhatsApp ingress path; accepted migration does not register an HTTP route.",
        ),
        "PORT" => (
            "GatewayHttp",
            "HTTP listen port; accepted migration does not bind a gateway listener.",
        ),
        "LOG_LEVEL" => (
            "Observability",
            "Logging threshold; accepted migration does not configure an observability subscriber.",
        ),
        "NODE_ENV" => (
            "Observability",
            "Development logging transport selector; accepted migration does not install a transport.",
        ),
        "SESSION_TTL_MS" => (
            "ProviderSessionCache",
            "Controls the ephemeral provider-session cache TTL; it must never evict durable claw-memory data.",
        ),
        "MAX_SESSIONS" => (
            "ProviderSessionCache",
            "Caps entries in the ephemeral provider-session cache; it must never evict durable claw-memory data.",
        ),
        "COPILOT_MODEL" => (
            "ProviderRuntime",
            "Default provider model; accepted migration does not select a runtime provider model.",
        ),
        "SKILL_EXEC_TIMEOUT_MS" => (
            "SkillRuntime",
            "Skill execution deadline; accepted migration does not time-limit skill execution.",
        ),
        "SDK_REQUEST_TIMEOUT_MS" => (
            "ProviderRuntime",
            "Provider request deadline; accepted migration does not configure provider transport.",
        ),
        "RATE_LIMIT_PER_MIN" => (
            "GatewayHttp",
            "Intended Teams HTTP ingress rate limit; configuration alone does not enforce request throttling.",
        ),
        "ALLOWED_SKILL_DOMAINS" => (
            "SkillRuntime",
            "Intended outbound skill HTTP domain policy; configuration alone does not enforce a security boundary.",
        ),
        "DOMAIN" => (
            "GatewayHttp",
            "Public gateway domain; accepted migration does not configure routing or TLS.",
        ),
        "AUTO_UPDATE" => (
            "UpdateRuntime",
            "Signed update policy; accepted migration does not schedule or execute updates.",
        ),
        "ADMIN_TOKEN" => (
            "Administration",
            "Administrative bearer credential; accepted migration does not register or protect admin routes.",
        ),
        "TRUST_PROXY" => (
            "GatewayHttp",
            "Forwarded-client trust policy; accepted migration does not change HTTP peer attribution.",
        ),
        "HTTPS_PROXY" => (
            "OutboundHttp",
            "Canonical outbound proxy setting and aliases; accepted migration does not configure HTTP clients.",
        ),
        _ => panic!("missing runtime disposition metadata for {legacy_env}"),
    }
}

fn generate_mapping(output: &mut String, mapping: &Mapping) {
    output.push_str("    LegacyMappingContract { id: MappingId::");
    output.push_str(&variant_name(&mapping.legacy_env));
    output.push_str(", legacy_env: ");
    output.push_str(&literal(&mapping.legacy_env));
    output.push_str(", aliases: &[");
    for alias in &mapping.aliases {
        output.push_str(&literal(alias));
        output.push(',');
    }
    output.push_str("], scope: ");
    output.push_str(&literal(&mapping.scope));
    output.push_str(", target: ");
    output.push_str(&literal(&mapping.target_json5_key));
    output.push_str(", secret: ");
    output.push_str(if mapping.secret { "true" } else { "false" });
    output.push_str(", _default_json: ");
    output.push_str(&literal(&mapping.default.to_string()));
    output.push_str(", _conversion: ");
    output.push_str(&literal(&mapping.conversion));
    output.push_str(", _validation: ");
    output.push_str(&literal(&mapping.validation));
    output.push_str(", _required_when: ");
    output.push_str(&literal(&mapping.required_when));
    output.push_str(", _known_legacy_quirk: ");
    match &mapping.known_legacy_quirk {
        Some(value) => {
            output.push_str("Some(");
            output.push_str(&literal(value));
            output.push(')');
        }
        None => output.push_str("None"),
    }
    output.push_str(" },\n");
}

fn variant_name(value: &str) -> String {
    value
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            let first = chars.next().expect("nonempty environment name segment");
            format!(
                "{}{}",
                first.to_ascii_uppercase(),
                chars.as_str().to_ascii_lowercase()
            )
        })
        .collect()
}

fn literal(value: &str) -> String {
    serde_json::to_string(value).expect("serialize generated string literal")
}

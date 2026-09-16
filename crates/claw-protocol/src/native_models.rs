//! Strict read-only native provider catalogue pages, separate from upstream model discovery.

use serde::Deserialize;
use serde_json::Value;

/// A malformed, unsupported or changed native catalogue page without remote content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogueError;

impl std::fmt::Display for CatalogueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Model catalogue page is invalid or changed")
    }
}

impl std::error::Error for CatalogueError {}

/// A local lifecycle fact explaining why no model catalogue has been published.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogueUnavailableReason {
    /// The provider was explicitly disabled by startup configuration.
    Disabled,
    /// The selected provider is waiting for its authentication flow.
    AuthenticationPending,
    /// No provider catalogue has been initialized in this slot.
    NotInitialized,
    /// The provider slot has been shut down.
    Retired,
}

impl std::fmt::Display for CatalogueUnavailableReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Disabled => "Provider is explicitly disabled",
            Self::AuthenticationPending => "Provider authentication is pending",
            Self::NotInitialized => "Provider catalogue is not initialized",
            Self::Retired => "Provider has been shut down",
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    schema_version: u64,
    available: bool,
    unavailable_reason: Option<CatalogueUnavailableReason>,
    selection_changed: bool,
    network_contacted: bool,
    offset: Option<usize>,
    end_offset: Option<usize>,
    next_offset: Option<usize>,
    total_models: Option<usize>,
    sha256: Option<String>,
    provider: Option<String>,
    provider_generation: Option<u64>,
    selected_model: Option<String>,
    selection_pinned: Option<bool>,
    observed_at_ms: Option<u64>,
    source: Option<String>,
    live_capabilities_verified: Option<bool>,
    models: Option<Vec<Model>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Model {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    display_name: Option<String>,
    context_window: Option<u32>,
    max_output_tokens: Option<u32>,
    advertised_capabilities: Vec<String>,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

/// Validates a content-free explicit catalogue refresh receipt, never a model invocation.
///
/// # Errors
/// Rejects unsupported fields, unsafe identities, invalid counts or a claimed selection change.
pub fn validate_refresh(encoded: &str, expected_sha256: &str) -> Result<(), CatalogueError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "Private closed wire receipt; every safety flag is required and checked"
    )]
    struct Receipt {
        schema_version: u64,
        refreshed: bool,
        provider: String,
        provider_generation: u64,
        requested_sha256: String,
        selected_model: String,
        total_models: usize,
        selection_changed: bool,
        network_contacted: bool,
        inference_invoked: bool,
    }
    if encoded.len() > 2048 {
        return Err(CatalogueError);
    }
    let receipt: Receipt = serde_json::from_str(encoded).map_err(|_| CatalogueError)?;
    if receipt.schema_version != 1
        || !receipt.refreshed
        || receipt.selection_changed
        || !receipt.network_contacted
        || receipt.inference_invoked
        || !valid_id(&receipt.provider)
        || !receipt
            .provider
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || receipt.provider_generation == 0
        || receipt.requested_sha256 != expected_sha256
        || expected_sha256.len() != 64
        || !expected_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !valid_id(&receipt.selected_model)
        || !(1..=1024).contains(&receipt.total_models)
    {
        return Err(CatalogueError);
    }
    Ok(())
}

/// Validates one page against its requested offset and optional pinned whole-catalogue digest.
///
/// A complete first page independently verifies the full ordered JSON digest.
/// A continuation only pins that digest and cannot prove omitted rows.
///
/// # Errors
/// Rejects unsupported shape, unsafe IDs, inconsistent limits, duplicates or a changed digest.
pub fn validate_page(
    encoded: &str,
    offset: usize,
    expected_sha256: Option<&str>,
) -> Result<(), CatalogueError> {
    validate_document(encoded, offset, expected_sha256, false)
}

/// Validates a complete, bounded catalogue snapshot against its observed digest.
///
/// # Errors
/// Rejects unavailable or incomplete catalogues, cross-page collisions and digest changes.
pub fn validate_snapshot(encoded: &str, expected_sha256: &str) -> Result<(), CatalogueError> {
    validate_document(encoded, 0, Some(expected_sha256), true)
}

fn validate_document(
    encoded: &str,
    offset: usize,
    expected_sha256: Option<&str>,
    complete: bool,
) -> Result<(), CatalogueError> {
    let max_bytes = if complete { 2 * 1024 * 1024 } else { 16 * 1024 };
    let max_models = if complete { 1024 } else { 8 };
    if encoded.len() > max_bytes || offset > 1024 || offset > 0 && expected_sha256.is_none() {
        return Err(CatalogueError);
    }
    let page: Page = serde_json::from_str(encoded).map_err(|_| CatalogueError)?;
    if page.schema_version != 1 || page.selection_changed || page.network_contacted {
        return Err(CatalogueError);
    }
    if !page.available {
        if complete
            || offset != 0
            || expected_sha256.is_some()
            || page.offset.is_some()
            || page.end_offset.is_some()
            || page.next_offset.is_some()
            || page.total_models.is_some()
            || page.sha256.is_some()
            || page.provider.is_some()
            || page.provider_generation.is_some()
            || page.selected_model.is_some()
            || page.selection_pinned.is_some()
            || page.observed_at_ms.is_some()
            || page.source.is_some()
            || page.live_capabilities_verified.is_some()
            || page.models.is_some()
        {
            return Err(CatalogueError);
        }
        return Ok(());
    }
    let end = page.end_offset.ok_or(CatalogueError)?;
    let total = page.total_models.ok_or(CatalogueError)?;
    let models = page.models.ok_or(CatalogueError)?;
    let selected = page.selected_model.ok_or(CatalogueError)?;
    let provider = page.provider.ok_or(CatalogueError)?;
    let digest = page.sha256.ok_or(CatalogueError)?;
    if page.unavailable_reason.is_some()
        || page.offset != Some(offset)
        || !(1..=1024).contains(&total)
        || models.is_empty()
        || models.len() > max_models
        || offset.checked_add(models.len()) != Some(end)
        || end > total
        || complete && (end != total || page.next_offset.is_some())
        || page
            .next_offset
            .map_or(end != total, |next| next != end || next >= total)
        || !valid_id(&provider)
        || !provider
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !valid_id(&selected)
        || page
            .provider_generation
            .is_none_or(|generation| generation == 0)
        || page.selection_pinned.is_none()
        || page.observed_at_ms == Some(0)
        || page.source.as_deref() != Some("provider_sdk_catalogue")
        || page.live_capabilities_verified != Some(false)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || expected_sha256.is_some_and(|expected| expected != digest)
    {
        return Err(CatalogueError);
    }
    let mut identities = std::collections::BTreeSet::new();
    let mut aliases = std::collections::BTreeSet::new();
    let mut alias_bytes = 0_usize;
    for model in &models {
        let mut capabilities = std::collections::BTreeSet::new();
        if !valid_id(&model.id)
            || !identities.insert(&model.id)
            || model.display_name.as_deref().is_some_and(|name| {
                name.trim().is_empty() || name.len() > 512 || name.chars().any(char::is_control)
            })
            || model.context_window == Some(0)
            || model.max_output_tokens == Some(0)
            || model
                .context_window
                .zip(model.max_output_tokens)
                .is_some_and(|(context, output)| output > context)
            || model.advertised_capabilities.len() > 9
            || model.advertised_capabilities.iter().any(|capability| {
                !matches!(
                    capability.as_str(),
                    "completion"
                        | "streaming"
                        | "tool_calling"
                        | "embeddings"
                        | "model_listing"
                        | "vision"
                        | "reasoning"
                        | "json_mode"
                        | "prompt_caching"
                ) || !capabilities.insert(capability)
            })
        {
            return Err(CatalogueError);
        }
        for alias in &model.aliases {
            alias_bytes = alias_bytes
                .saturating_add(alias.len())
                .saturating_add(model.id.len());
            if !valid_id(alias)
                || alias == "openclaw"
                || alias.starts_with("openclaw/")
                || alias == &selected
                || !aliases.insert(alias)
                || aliases.len() > 128
                || alias_bytes > 4096
            {
                return Err(CatalogueError);
            }
        }
    }
    if !identities.is_disjoint(&aliases) {
        return Err(CatalogueError);
    }
    if offset == 0 && end == total {
        use sha2::Digest as _;
        use std::fmt::Write as _;
        if !models.iter().any(|model| model.id == selected) {
            return Err(CatalogueError);
        }
        let raw: Value = serde_json::from_str(encoded).map_err(|_| CatalogueError)?;
        let snapshot = serde_json::json!({"provider":raw["provider"],"providerGeneration":raw["providerGeneration"],"selectedModel":raw["selectedModel"],"selectionPinned":raw["selectionPinned"],
            "observedAtMs":raw["observedAtMs"],"source":raw["source"],"liveCapabilitiesVerified":false,"models":raw["models"]});
        let mut actual = String::with_capacity(64);
        for byte in sha2::Sha256::digest(serde_json::to_vec(&snapshot).map_err(|_| CatalogueError)?)
        {
            write!(actual, "{byte:02x}").expect("bounded digest string");
        }
        if actual != digest {
            return Err(CatalogueError);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::Digest as _;
    use std::fmt::Write as _;

    fn seal(page: &mut Value) {
        let snapshot = json!({"provider":page["provider"],"providerGeneration":page["providerGeneration"],"selectedModel":page["selectedModel"],"selectionPinned":page["selectionPinned"],
            "observedAtMs":page["observedAtMs"],"source":page["source"],"liveCapabilitiesVerified":false,"models":page["models"]});
        let mut digest = String::with_capacity(64);
        for byte in sha2::Sha256::digest(serde_json::to_vec(&snapshot).expect("snapshot")) {
            write!(digest, "{byte:02x}").expect("bounded digest");
        }
        page["sha256"] = json!(digest);
    }

    #[test]
    fn unavailable_catalogue_reasons_are_closed_and_do_not_claim_live_readiness() {
        let original = json!({"schemaVersion":1,"available":false,"selectionChanged":false,"networkContacted":false});
        validate_page(&original.to_string(), 0, None).expect("legacy unavailable page");
        for reason in [
            CatalogueUnavailableReason::Disabled,
            CatalogueUnavailableReason::AuthenticationPending,
            CatalogueUnavailableReason::NotInitialized,
            CatalogueUnavailableReason::Retired,
        ] {
            let mut page = original.clone();
            page["unavailableReason"] = json!(reason);
            validate_page(&page.to_string(), 0, None).expect("typed local lifecycle reason");
            assert!(!reason.to_string().is_empty());
            assert!(validate_page(&page.to_string(), 1, Some(&"a".repeat(64))).is_err());
            assert!(validate_snapshot(&page.to_string(), &"a".repeat(64)).is_err());
            page["available"] = json!(true);
            assert!(validate_page(&page.to_string(), 0, None).is_err());
        }
        for reason in [
            json!("ready"),
            json!("upstream credential details"),
            json!(1),
            json!({"kind":"disabled"}),
        ] {
            let mut page = original.clone();
            page["unavailableReason"] = reason;
            assert!(validate_page(&page.to_string(), 0, None).is_err());
        }
    }

    #[test]
    fn complete_model_snapshots_verify_global_identity_aliases_and_digest() {
        let mut snapshot = json!({"schemaVersion":1,"available":true,"selectionChanged":false,"networkContacted":false,
            "offset":0,"endOffset":17,"nextOffset":null,"totalModels":17,"provider":"openai","providerGeneration":1,
            "selectedModel":"exact-0","selectionPinned":true,"observedAtMs":123,"source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,
            "models":(0..17).map(|ordinal| json!({"id":format!("exact-{ordinal}"),"displayName":null,"contextWindow":null,"maxOutputTokens":null,"advertisedCapabilities":[]})).collect::<Vec<_>>()});
        snapshot["models"][0]["aliases"] = json!(["work", "Work"]);
        seal(&mut snapshot);
        let digest = snapshot["sha256"].as_str().expect("digest").to_owned();
        validate_snapshot(&snapshot.to_string(), &digest).expect("complete 17-model snapshot");
        assert!(validate_page(&snapshot.to_string(), 0, None).is_err());

        let mut changed = snapshot.clone();
        changed["models"][16]["displayName"] = json!("changed");
        assert!(validate_snapshot(&changed.to_string(), &digest).is_err());
        for scenario in [
            "duplicate-id",
            "duplicate-alias",
            "alias-collision",
            "too-many-aliases",
            "selected-absent",
            "incomplete",
            "extra-field",
        ] {
            let mut invalid = snapshot.clone();
            match scenario {
                "duplicate-id" => invalid["models"][16]["id"] = json!("exact-0"),
                "duplicate-alias" => invalid["models"][16]["aliases"] = json!(["work"]),
                "alias-collision" => invalid["models"][0]["aliases"] = json!(["exact-16"]),
                "too-many-aliases" => {
                    for (ordinal, model) in invalid["models"]
                        .as_array_mut()
                        .expect("models")
                        .iter_mut()
                        .enumerate()
                    {
                        model["aliases"] = json!(
                            (0..8)
                                .map(|alias| format!("alias-{ordinal}-{alias}"))
                                .collect::<Vec<_>>()
                        );
                    }
                }
                "selected-absent" => invalid["selectedModel"] = json!("missing"),
                "incomplete" => invalid["nextOffset"] = json!(16),
                "extra-field" => invalid["models"][16]["credential"] = json!("untrusted"),
                _ => unreachable!(),
            }
            seal(&mut invalid);
            assert!(
                validate_snapshot(
                    &invalid.to_string(),
                    invalid["sha256"].as_str().expect("digest")
                )
                .is_err(),
                "{scenario}"
            );
        }
        assert!(validate_snapshot(&snapshot.to_string(), &"b".repeat(64)).is_err());
        assert!(validate_snapshot(r#"{"schemaVersion":1,"available":false,"selectionChanged":false,"networkContacted":false}"#, &digest).is_err());
        assert!(validate_snapshot(&" ".repeat(2 * 1024 * 1024 + 1), &digest).is_err());
    }

    #[test]
    fn model_alias_metadata_is_bounded_distinct_and_covered_by_the_catalogue_digest() {
        let mut page = json!({"schemaVersion":1,"available":true,"selectionChanged":false,"networkContacted":false,
            "offset":0,"endOffset":2,"nextOffset":null,"totalModels":2,"provider":"openai","providerGeneration":1,
            "selectedModel":"exact","selectionPinned":true,"observedAtMs":123,"source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,
            "models":[{"id":"exact","displayName":null,"contextWindow":null,"maxOutputTokens":null,"advertisedCapabilities":[]},
                {"id":"other","displayName":null,"contextWindow":null,"maxOutputTokens":null,"advertisedCapabilities":[]} ]});
        seal(&mut page);
        validate_page(&page.to_string(), 0, None).expect("old page without aliases");
        page["models"][0]["aliases"] = json!(["work", "WORK"]);
        seal(&mut page);
        validate_page(&page.to_string(), 0, None).expect("explicit case-sensitive aliases");
        for aliases in [
            json!(["work", "work"]),
            json!(["other"]),
            json!(["exact"]),
            json!(["openclaw/default"]),
            json!(["bad\nname"]),
            json!(null),
            json!(
                (0..129)
                    .map(|index| format!("alias-{index}"))
                    .collect::<Vec<_>>()
            ),
            json!(
                (0..20)
                    .map(|index| format!("{}{index}", "a".repeat(240)))
                    .collect::<Vec<_>>()
            ),
        ] {
            let mut invalid = page.clone();
            invalid["models"][0]["aliases"] = aliases;
            seal(&mut invalid);
            assert!(validate_page(&invalid.to_string(), 0, None).is_err());
        }
        let mut duplicated = page.clone();
        duplicated["models"][1]["aliases"] = json!(["work"]);
        seal(&mut duplicated);
        assert!(validate_page(&duplicated.to_string(), 0, None).is_err());
        page["models"][0]["aliases"] = json!(["changed"]);
        assert!(
            validate_page(&page.to_string(), 0, None).is_err(),
            "alias edits change the digest"
        );
    }
}

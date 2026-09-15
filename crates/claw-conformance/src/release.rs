//! Independently versioned release identity metadata, separate from parity claims.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::loader::{normalized_digest, parse_bytes, read_file};
use crate::{ConformanceError, ViolationCode};

/// Candidate upstream release tracked without replacing the frozen contract.
pub const CANDIDATE_RELEASE: &str = "v2026.9.4";

const REVIEWED_GATEWAY_SOURCES: &[u8] =
    include_bytes!("../../../compat/releases/v2026.9.4/gateway-sources.json");

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    repository: String,
    package_version: String,
    release_tag: String,
    tag_object_sha: String,
    commit_sha: String,
    tree_sha: String,
    gateway: GatewayVersions,
    evidence: SignatureEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayVersions {
    current: u32,
    minimum_general_client: u32,
    minimum_authenticated_node: u32,
    minimum_probe: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignatureEvidence {
    method: EvidenceMethod,
    commit_signature_verified: bool,
    tag_signature_verified: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceMethod {
    GithubApi,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewaySources {
    schema_version: u32,
    commit_sha: String,
    tree_sha: String,
    schema_constructor: String,
    sources: Vec<SourceWitness>,
    requests: Vec<RequestWitness>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceWitness {
    path: String,
    bytes: u64,
    git_blob_sha: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestWitness {
    method: String,
    source: String,
    symbol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parameters_schema: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
struct SchemaCoverage {
    request_schema_extraction_method: &'static str,
    complete_schema_extraction: bool,
    upstream_source_bytes_bundled: bool,
}

fn validate_sources(bytes: &[u8], metadata: &Manifest) -> Result<GatewaySources, ConformanceError> {
    if normalized_digest(bytes) != normalized_digest(REVIEWED_GATEWAY_SOURCES) {
        return Err(ConformanceError::new(
            ViolationCode::ManifestDrift,
            Some("gateway-sources.json".to_owned()),
            "candidate gateway source artifact differs from its compile-time reviewed bytes",
        ));
    }
    let sources: GatewaySources = parse_bytes("gateway-sources.json", bytes)?;
    let reviewed: GatewaySources = parse_bytes(
        "reviewed gateway source witnesses",
        REVIEWED_GATEWAY_SOURCES,
    )?;
    let paths = sources
        .sources
        .iter()
        .map(|source| source.path.as_str())
        .collect::<BTreeSet<_>>();
    let methods = sources
        .requests
        .iter()
        .map(|request| request.method.as_str())
        .collect::<BTreeSet<_>>();
    if sources != reviewed
        || sources.schema_version != 1
        || sources.commit_sha != metadata.commit_sha
        || sources.tree_sha != metadata.tree_sha
        || paths.len() != sources.sources.len()
        || methods.len() != sources.requests.len()
        || sources.sources.is_empty()
        || sources.requests.is_empty()
        || sources.sources.iter().any(|source| {
            !source
                .path
                .starts_with("packages/gateway-protocol/src/schema/")
                || source
                    .path
                    .split('/')
                    .any(|part| part == ".." || part.is_empty())
                || source.path.contains('\\')
                || !(1..=1_048_576).contains(&source.bytes)
                || !hex_digest(&source.git_blob_sha, 40)
                || !hex_digest(&source.sha256, 64)
        })
        || sources.requests.iter().any(|request| {
            !paths.contains(request.source.as_str())
                || request.method.is_empty()
                || request.method.len() > 128
                || !request
                    .method
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'.')
                || !request.symbol.ends_with("ParamsSchema")
                || request.symbol.len() > 128
                || !request
                    .symbol
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric())
        })
    {
        return Err(ConformanceError::new(
            ViolationCode::ManifestDrift,
            Some("gateway-sources.json".to_owned()),
            "candidate gateway source identity or request entrypoints differ from reviewed witnesses",
        ));
    }
    Ok(sources)
}

fn hex_digest(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validated candidate identity, not a complete contract or runtime attestation.
#[derive(Clone, Debug, Serialize)]
pub struct ReleaseBaseline {
    metadata: Manifest,
    normalized_artifact_sha256: String,
    gateway_sources: GatewaySources,
    normalized_gateway_sources_sha256: String,
    #[serde(flatten)]
    schema_extraction: SchemaCoverage,
    #[serde(skip)]
    request_validators: BTreeMap<String, Arc<jsonschema::Validator>>,
    complete_contract: bool,
    locally_verified_signatures: bool,
    runtime_verified: bool,
}

impl ReleaseBaseline {
    /// Reads bounded release metadata and checks its reviewed identity and wire versions.
    ///
    /// # Errors
    ///
    /// Rejects unreadable, malformed, oversized, unknown or drifted release metadata.
    pub fn load(root: impl AsRef<Path>) -> Result<Self, ConformanceError> {
        let bytes = read_file(root.as_ref(), "baseline.json")?;
        let metadata: Manifest = parse_bytes("baseline.json", &bytes)?;
        if metadata.schema_version != 1
            || metadata.repository != "openclaw/openclaw"
            || metadata.package_version != "2026.9.4"
            || metadata.release_tag != CANDIDATE_RELEASE
            || metadata.tag_object_sha != "8bec206f3c1f787e1e9c45cfd34d3de2a78c7b8e"
            || metadata.commit_sha != "3a9d69db306cd7f081e06254cb89c4bcc14a7107"
            || metadata.tree_sha != "e12ac49c56657a501b3eab13539bda4fa8aaee5f"
            || metadata.gateway
                != (GatewayVersions {
                    current: 4,
                    minimum_general_client: 4,
                    minimum_authenticated_node: 3,
                    minimum_probe: 3,
                })
            || !metadata.evidence.commit_signature_verified
            || !metadata.evidence.tag_signature_verified
        {
            return Err(ConformanceError::new(
                ViolationCode::ManifestDrift,
                Some("baseline.json".to_owned()),
                "candidate release identity or protocol metadata differs from its reviewed pin",
            ));
        }
        let source_bytes = read_file(root.as_ref(), "gateway-sources.json")?;
        let gateway_sources = validate_sources(&source_bytes, &metadata)?;
        let mut request_validators = BTreeMap::new();
        for request in &gateway_sources.requests {
            let Some(schema) = &request.parameters_schema else {
                continue;
            };
            let validator = jsonschema::options()
                .offline()
                .with_pattern_options(
                    jsonschema::PatternOptions::regex()
                        .size_limit(256 * 1024)
                        .dfa_size_limit(512 * 1024),
                )
                .build(schema)
                .map_err(|_| {
                    ConformanceError::new(
                        ViolationCode::JsonSchema,
                        Some(request.method.clone()),
                        "reviewed request schema cannot be compiled offline",
                    )
                })?;
            request_validators.insert(request.method.clone(), Arc::new(validator));
        }
        Ok(Self {
            metadata,
            normalized_artifact_sha256: normalized_digest(&bytes),
            gateway_sources,
            normalized_gateway_sources_sha256: normalized_digest(&source_bytes),
            schema_extraction: SchemaCoverage {
                request_schema_extraction_method: "manual_review_of_pinned_typebox_sources",
                complete_schema_extraction: false,
                upstream_source_bytes_bundled: false,
            },
            request_validators,
            complete_contract: false,
            locally_verified_signatures: false,
            runtime_verified: false,
        })
    }

    /// Returns the reviewed release tag.
    #[must_use]
    pub fn release_tag(&self) -> &str {
        &self.metadata.release_tag
    }

    /// Returns the source commit, distinct from the annotated tag object.
    #[must_use]
    pub fn commit_sha(&self) -> &str {
        &self.metadata.commit_sha
    }

    /// Returns the gateway wire version recorded in the fixed release.
    #[must_use]
    pub const fn gateway_version(&self) -> u32 {
        self.metadata.gateway.current
    }

    /// Returns the number of requests whose complete parameter schemas were extracted.
    #[must_use]
    pub fn request_schema_count(&self) -> usize {
        self.request_validators.len()
    }

    /// Checks a request against its reviewed upstream parameter schema only.
    ///
    /// This does not authorize execution or attest response or runtime compatibility.
    ///
    /// # Errors
    ///
    /// Rejects unknown or unextracted methods and parameters outside the pinned schema.
    pub fn validate_gateway_request(
        &self,
        method: &str,
        parameters: &serde_json::Value,
    ) -> Result<(), ConformanceError> {
        let validator = self.request_validators.get(method).ok_or_else(|| {
            ConformanceError::new(
                ViolationCode::JsonSchema,
                Some("candidate gateway request".to_owned()),
                "method has no reviewed parameter schema in this release slice",
            )
        })?;
        validator.validate(parameters).map_err(|error| {
            ConformanceError::at_json_path(
                method,
                error.instance_path().to_string(),
                "parameters do not satisfy the reviewed upstream request schema",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;

    use super::{
        GatewaySources, Manifest, REVIEWED_GATEWAY_SOURCES, ReleaseBaseline, validate_sources,
    };

    fn metadata() -> Manifest {
        serde_json::from_slice(include_bytes!(
            "../../../compat/releases/v2026.9.4/baseline.json"
        ))
        .expect("reviewed release")
    }

    fn sources() -> GatewaySources {
        serde_json::from_slice(include_bytes!(
            "../../../compat/releases/v2026.9.4/gateway-sources.json"
        ))
        .expect("reviewed source witnesses")
    }

    #[test]
    fn candidate_gateway_sources_are_pinned_separately_from_complete_contract() {
        let value = sources();
        assert_eq!(
            validate_sources(REVIEWED_GATEWAY_SOURCES, &metadata()).expect("valid"),
            value
        );
        assert_eq!(value.sources.len(), 8);
        assert_eq!(value.requests.len(), 6);
    }

    #[test]
    fn candidate_gateway_sources_refuse_tampering_duplicates_and_unrelated_paths() {
        for mutation in 0..6 {
            let mut value = sources();
            match mutation {
                0 => value.sources[0].sha256.replace_range(..1, "0"),
                1 => value.sources.push(value.sources[0].clone()),
                2 => value.requests.push(value.requests[0].clone()),
                3 => value.sources[0].path = "../upstream/gateway.json".to_owned(),
                4 => value.requests[0].source = "unreviewed.ts".to_owned(),
                _ => value.sources[0].bytes += 1,
            }
            let encoded = serde_json::to_vec(&value).expect("encode sources");
            assert!(validate_sources(&encoded, &metadata()).is_err());
        }
    }

    #[test]
    fn candidate_gateway_sources_reject_duplicate_schema_fields_and_external_references() {
        let source = std::str::from_utf8(REVIEWED_GATEWAY_SOURCES).expect("source utf8");
        for edited in [
            source.replacen("\"minLength\":1", "\"minLength\":1,\"minLength\":1", 1),
            source.replacen(
                "\"type\":\"object\"",
                "\"$ref\":\"https://unreviewed.invalid/schema\"",
                1,
            ),
        ] {
            assert!(validate_sources(edited.as_bytes(), &metadata()).is_err());
        }
    }

    #[test]
    fn candidate_gateway_request_schemas_enforce_reviewed_closed_shapes() {
        let baseline = ReleaseBaseline::load(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/releases/v2026.9.4"),
        )
        .expect("candidate baseline");
        assert_eq!(baseline.request_schema_count(), 6);
        for (method, parameters) in [
            ("agent.wait", json!({"runId":"run-one"})),
            ("agent.wait", json!({"runId":" ","timeoutMs":0})),
            ("chat.abort", json!({"sessionKey":"session-one"})),
            (
                "chat.abort",
                json!({"sessionKey":"session-one","agentId":"agent-one","runId":"run-one","preserveSideRuns":true}),
            ),
            ("sessions.describe", json!({"key":"session-one"})),
            (
                "sessions.describe",
                json!({"key":"session-one","agentId":"agent-one","includeDerivedTitles":true,"includeLastMessage":false}),
            ),
        ] {
            baseline
                .validate_gateway_request(method, &parameters)
                .expect(method);
        }
        for (method, parameters) in [
            ("agent.wait", json!({})),
            ("agent.wait", json!({"runId":""})),
            (
                "agent.wait",
                json!({"runId":"private-input","timeoutMs":-1}),
            ),
            (
                "agent.wait",
                json!({"runId":"private-input","timeoutMs":0.5}),
            ),
            (
                "agent.wait",
                json!({"runId":"private-input","timeoutMs":null}),
            ),
            (
                "agent.wait",
                json!({"runId":"private-input","acknowledge":true}),
            ),
            ("chat.abort", json!({"runId":"private-input"})),
            (
                "chat.abort",
                json!({"sessionKey":"private-input","preserveSideRuns":"true"}),
            ),
            (
                "chat.abort",
                json!({"sessionKey":"private-input","agentId":""}),
            ),
            (
                "chat.abort",
                json!({"sessionKey":"private-input","owner":true}),
            ),
            ("sessions.describe", json!({"sessionKey":"private-input"})),
            (
                "sessions.describe",
                json!({"key":"private-input","includeLastMessage":1}),
            ),
            (
                "sessions.describe",
                json!({"key":"private-input","unknown":true}),
            ),
            ("sessions.describe", json!([])),
            (
                "chat.inject",
                json!({"sessionKey":"private-input","message":"test"}),
            ),
            ("unreviewed.method", json!({})),
        ] {
            let error = baseline
                .validate_gateway_request(method, &parameters)
                .expect_err(method);
            assert!(!error.to_string().contains("private-input"));
        }
        let report = serde_json::to_value(baseline).expect("serialize candidate");
        for field in [
            "complete_schema_extraction",
            "complete_contract",
            "runtime_verified",
        ] {
            assert_eq!(report[field], false);
        }
        assert!(report.get("request_validators").is_none());
    }

    #[test]
    fn candidate_chat_history_contract_preserves_upstream_cursor_and_receipt_limits() {
        let baseline = ReleaseBaseline::load(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/releases/v2026.9.4"),
        )
        .expect("candidate baseline");
        let accepted = json!({
            "sessionKey":"session-one","agentId":"agent-one","cursor":"","limit":1000,
            "maxBytes":1024,"offset":0,"pendingBefore":1,"messageId":"message-one",
            "sessionId":"session-id","maxChars":500_000,
            "inputRunIds":(0..50).map(|index| format!("run-{index}")).collect::<Vec<_>>()
        });
        baseline
            .validate_gateway_request("chat.history", &accepted)
            .expect("all parameters");
        for (field, value) in [
            ("sessionKey", json!("")),
            ("agentId", json!("")),
            ("cursor", json!(1)),
            ("limit", json!(0)),
            ("limit", json!(1001)),
            ("maxBytes", json!(1023)),
            ("offset", json!(-1)),
            ("pendingBefore", json!(0)),
            ("maxChars", json!(500_001)),
            ("inputRunIds", json!([])),
            ("inputRunIds", json!(["repeated", "repeated"])),
            ("inputRunIds", json!(["overlong".repeat(37)])),
            (
                "inputRunIds",
                json!(
                    (0..51)
                        .map(|index| format!("run-{index}"))
                        .collect::<Vec<_>>()
                ),
            ),
            ("nativeRecovery", json!(true)),
        ] {
            let mut parameters = accepted.clone();
            parameters[field] = value;
            assert!(
                baseline
                    .validate_gateway_request("chat.history", &parameters)
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn candidate_session_send_contract_retains_attachment_and_mention_wire_semantics() {
        let baseline = ReleaseBaseline::load(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/releases/v2026.9.4"),
        )
        .expect("candidate baseline");
        for parameters in [
            json!({"key":"session-one","message":""}),
            json!({
                "key":"session-one","message":"content","timeoutMs":0,"thinking":"",
                "attachments":[{"content":{"opaque":true},"custom":true,"sizeBytes":-0.5}],
                "mentions":[{"profileId":"profile-one","start":9_007_199_254_740_991_u64,"end":1}]
            }),
        ] {
            baseline
                .validate_gateway_request("sessions.send", &parameters)
                .expect("wire parameters");
        }
        for parameters in [
            json!({"key":"session-one"}),
            json!({"key":"session-one","message":"content","idempotencyKey":""}),
            json!({"key":"session-one","message":"content","attachments":[{"sizeBytes":"1"}]}),
            json!({"key":"session-one","message":"content","mentions":[{"profileId":"profile-one","start":0,"end":1,"label":"extra"}]}),
            json!({"key":"session-one","message":"content","mentions":[{"profileId":"profile-one","start":0,"end":0}]}),
            json!({"key":"session-one","message":"content","mentions":[{"profileId":"profile-one","start":9_007_199_254_740_992_u64,"end":1}]}),
            json!({"key":"session-one","message":"content","mentions":vec![json!({"profileId":"profile-one","start":0,"end":1});11]}),
        ] {
            assert!(
                baseline
                    .validate_gateway_request("sessions.send", &parameters)
                    .is_err()
            );
        }
    }

    #[test]
    fn candidate_chat_send_contract_binds_wire_fields_without_inventing_record_key_constraints() {
        let baseline = ReleaseBaseline::load(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../compat/releases/v2026.9.4"),
        )
        .expect("candidate baseline");
        let minimal = json!({"sessionKey":"session-one","message":"","idempotencyKey":"input-one"});
        baseline
            .validate_gateway_request("chat.send", &minimal)
            .expect("minimal send");
        let mut accepted = json!({
            "sessionKey":"session-one","message":"message","idempotencyKey":"input-one",
            "agentId":"agent-one","sessionId":"session-id","thinking":"","fastMode":"auto",
            "fastAutoOnSeconds":1,"queueMode":"steer","deliver":false,
            "originatingChannel":"","originatingTo":"","originatingAccountId":"","originatingThreadId":"",
            "replyToId":"reply-one","timeoutMs":0,"systemProvenanceReceipt":"","suppressCommandInterpretation":false,
            "expectedLeafEntryId":null,"expectedSessionRoutingContract":"routing-one","expectedPermissionMode":null,
            "intent":{"kind":"session-goal-start","version":1,"issuedAtMs":0},
            "systemInputProvenance":{"kind":"external_user","originSessionId":"","sourceSessionKey":"","sourceChannel":"","sourceTool":""},
            "expectedToolOverrides":{"mcpServers":{"":true},"mcpToolsDeny":{"":[]},"skills":{"":false},"webSearch":false},
            "mentions":[{"profileId":"profile-one","start":0,"end":1}],
            "attachments":[{"mimeType":"text/plain","content":null,"custom":true}],
            "toolBindings":{"":null}
        });
        accepted["toolBindings"]["unbounded-key".repeat(20)] = json!(true);
        accepted["expectedToolOverrides"]["skills"]["unbounded-key".repeat(20)] = json!(true);
        baseline
            .validate_gateway_request("chat.send", &accepted)
            .expect("complete send shape");
        for (field, value) in [
            ("sessionKey", json!("k".repeat(513))),
            ("sessionId", json!("")),
            ("idempotencyKey", json!("")),
            ("queueMode", json!("retry")),
            ("fastMode", json!("on")),
            ("fastAutoOnSeconds", json!(0)),
            ("expectedLeafEntryId", json!("")),
            ("expectedPermissionMode", json!("owner")),
            ("expectedToolOverrides", json!({"skills":{"one":"yes"}})),
            (
                "expectedToolOverrides",
                json!({"mcpToolsDeny":{"one":[""]}}),
            ),
            ("expectedToolOverrides", json!({"allowAll":true})),
            ("systemInputProvenance", json!({"kind":"admin"})),
            (
                "intent",
                json!({"kind":"session-goal-start","version":2,"issuedAtMs":0}),
            ),
            ("intent", json!({"kind":"session-goal-start","version":1})),
            (
                "mentions",
                json!([{"profileId":"profile-one","start":0,"end":0}]),
            ),
            (
                "toolBindings",
                json!(
                    (0..17)
                        .map(|index| (format!("tool-{index}"), json!(null)))
                        .collect::<serde_json::Map<_, _>>()
                ),
            ),
            ("senderIsOwner", json!(true)),
        ] {
            let mut parameters = minimal.clone();
            parameters[field] = value;
            assert!(
                baseline
                    .validate_gateway_request("chat.send", &parameters)
                    .is_err(),
                "{field}"
            );
        }
        for field in ["sessionKey", "message", "idempotencyKey"] {
            let mut parameters = minimal.clone();
            parameters.as_object_mut().expect("object").remove(field);
            assert!(
                baseline
                    .validate_gateway_request("chat.send", &parameters)
                    .is_err(),
                "{field}"
            );
        }
    }
}

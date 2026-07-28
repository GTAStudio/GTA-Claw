//! Frozen remote-role interpretation, size bound, and fetch-port tests.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::{Path, PathBuf};

use claw_config::{
    ROLE_DOCUMENT_MAX_BYTES, ROLE_FETCH_ACCEPT, ROLE_FETCH_TIMEOUT_MS, RoleConfig, RoleDiagnostic,
    RoleDocumentOutcome, RoleFetchRequest, RoleJsonRejection, RoleLoadError, RoleParseError,
    RoleResponse, RoleSourceFetcher, load_role, parse_json5, parse_role_document,
};
use serde_json::Value;

const VALID: &str = r#"
{
  schema_version: 1,
  core: {
    auth: { github: { pat: "env:PRIVATE_GITHUB_TOKEN", device: { enabled: false } } },
    role: { source_url: "https://roles.example.test/default.json" },
    channels: { teams: { enabled: false } },
    server: {},
    logging: {},
    sessions: {},
    copilot: {},
    legacy: {},
    updates: {},
    admin: {},
    network: {},
  },
}
"#;

const JSON: &str = "application/json; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";

#[derive(Debug, Eq, PartialEq)]
struct TransportFailure;

impl Display for TransportFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("origin unreachable")
    }
}

impl Error for TransportFailure {}

#[derive(Default)]
struct RecordingFetcher {
    urls: Vec<String>,
    accepts: Vec<String>,
    timeouts: Vec<u64>,
    limits: Vec<usize>,
    response: Option<RoleResponse>,
}

impl RecordingFetcher {
    fn returning(response: RoleResponse) -> Self {
        Self {
            response: Some(response),
            ..Self::default()
        }
    }
}

impl RoleSourceFetcher for RecordingFetcher {
    type Error = TransportFailure;

    fn fetch(&mut self, request: RoleFetchRequest<'_>) -> Result<RoleResponse, Self::Error> {
        self.urls.push(request.url().to_owned());
        self.accepts.push(request.accept().to_owned());
        self.timeouts.push(request.timeout_ms());
        self.limits.push(request.max_bytes());
        self.response.clone().ok_or(TransportFailure)
    }
}

fn snapshot_role() -> RoleConfig {
    parse_json5(VALID, "role.json5")
        .expect("snapshot")
        .core()
        .role()
        .clone()
}

#[test]
fn string_content_is_used_with_its_optional_model() {
    let document = parse_role_document(
        Some(JSON),
        r#"{"content":"You are concise.","model":"gpt-4o"}"#,
    )
    .expect("json role");

    assert_eq!(document.content(), "You are concise.");
    assert_eq!(document.model(), Some("gpt-4o"));
    assert_eq!(document.outcome(), RoleDocumentOutcome::LoadedJson);
    assert!(document.diagnostics().is_empty());
}

#[test]
fn prompt_alias_is_used_when_content_is_absent() {
    let document =
        parse_role_document(Some(JSON), r#"{"prompt":"Alias wins."}"#).expect("prompt role");

    assert_eq!(document.content(), "Alias wins.");
    assert_eq!(document.model(), None);
    assert_eq!(document.diagnostics(), [RoleDiagnostic::PromptAliasUsed]);
}

#[test]
fn string_content_takes_precedence_over_prompt() {
    let document = parse_role_document(
        Some(JSON),
        r#"{"content":"Content wins.","prompt":"Ignored."}"#,
    )
    .expect("precedence role");

    assert_eq!(document.content(), "Content wins.");
    assert!(document.diagnostics().is_empty());
}

#[test]
fn non_string_content_falls_back_to_a_string_prompt() {
    let document = parse_role_document(
        Some(JSON),
        r#"{"content":7,"prompt":"Fallback.","model":"gpt-4o"}"#,
    )
    .expect("fallback role");

    assert_eq!(document.content(), "Fallback.");
    assert_eq!(document.model(), Some("gpt-4o"));
    assert_eq!(
        document.diagnostics(),
        [
            RoleDiagnostic::NonStringContentIgnored,
            RoleDiagnostic::PromptAliasUsed
        ]
    );
}

#[test]
fn null_content_is_treated_as_a_non_string_member() {
    let document = parse_role_document(Some(JSON), r#"{"content":null,"prompt":"Fallback."}"#)
        .expect("null content role");

    assert_eq!(document.content(), "Fallback.");
    assert_eq!(
        document.diagnostics(),
        [
            RoleDiagnostic::NonStringContentIgnored,
            RoleDiagnostic::PromptAliasUsed
        ]
    );
}

#[test]
fn neither_content_nor_prompt_is_rejected_for_a_json_content_type() {
    let error =
        parse_role_document(Some(JSON), r#"{"model":"gpt-4o"}"#).expect_err("missing content");

    assert_eq!(
        error,
        RoleParseError::Json(RoleJsonRejection::MissingContent)
    );
    assert!(error.to_string().contains("content"));
}

#[test]
fn empty_selected_content_never_falls_back_to_prompt() {
    let error = parse_role_document(Some(JSON), r#"{"content":"","prompt":"Not used."}"#)
        .expect_err("empty content");

    assert_eq!(error, RoleParseError::Json(RoleJsonRejection::EmptyContent));

    let empty_prompt =
        parse_role_document(Some(JSON), r#"{"prompt":""}"#).expect_err("empty alias");
    assert_eq!(
        empty_prompt,
        RoleParseError::Json(RoleJsonRejection::EmptyContent)
    );
}

#[test]
fn absent_and_non_string_models_both_resolve_to_no_override() {
    let absent = parse_role_document(Some(JSON), r#"{"content":"No model."}"#).expect("absent");
    assert_eq!(absent.model(), None);
    assert!(absent.diagnostics().is_empty());

    let non_string = parse_role_document(Some(JSON), r#"{"content":"No model.","model":42}"#)
        .expect("non-string model");
    assert_eq!(non_string.model(), None);
    assert_eq!(
        non_string.diagnostics(),
        [RoleDiagnostic::NonStringModelIgnored]
    );
}

#[test]
fn unknown_members_are_ignored() {
    let document = parse_role_document(
        Some(JSON),
        r#"{"content":"Kept.","extension_field":"ignored by the legacy loader"}"#,
    )
    .expect("extension role");

    assert_eq!(document.content(), "Kept.");
    assert!(document.diagnostics().is_empty());
}

#[test]
fn plain_text_bodies_are_used_verbatim_without_a_model() {
    let body = "Plain text is used verbatim as the system prompt.\n";
    let document = parse_role_document(Some(TEXT), body).expect("plain text role");

    assert_eq!(document.content(), body);
    assert_eq!(document.model(), None);
    assert_eq!(document.outcome(), RoleDocumentOutcome::LoadedPlainText);
    assert!(document.diagnostics().is_empty());
}

#[test]
fn a_missing_content_type_still_reads_a_non_json_body_as_plain_text() {
    let document = parse_role_document(None, "No header at all.").expect("plain text role");

    assert_eq!(document.content(), "No header at all.");
    assert_eq!(document.outcome(), RoleDocumentOutcome::LoadedPlainText);
}

#[test]
fn an_empty_plain_text_body_is_accepted_although_empty_json_content_is_not() {
    let document = parse_role_document(Some(TEXT), "").expect("empty plain text role");

    assert_eq!(document.content(), "");
    assert_eq!(document.outcome(), RoleDocumentOutcome::LoadedPlainText);
    assert!(document.diagnostics().is_empty());

    let rejected = parse_role_document(Some(JSON), r#"{"content":""}"#).expect_err("empty content");
    assert_eq!(
        rejected,
        RoleParseError::Json(RoleJsonRejection::EmptyContent)
    );
}

#[test]
fn a_json_content_type_rejects_a_body_that_is_not_valid_json() {
    let error = parse_role_document(Some(JSON), "{not json at all").expect_err("invalid json");

    match error {
        RoleParseError::Json(RoleJsonRejection::InvalidJson { path, message }) => {
            assert_eq!(path, "<root>");
            assert!(!message.is_empty());
        }
        other => panic!("expected an invalid JSON rejection, got {other:?}"),
    }
}

#[test]
fn a_json_content_type_rejects_trailing_content_after_a_valid_role() {
    let error = parse_role_document(Some(JSON), r#"{"content":"Kept."} trailing"#)
        .expect_err("trailing content");

    assert!(matches!(
        error,
        RoleParseError::Json(RoleJsonRejection::InvalidJson { .. })
    ));
}

#[test]
fn a_json_content_type_rejects_json_that_is_not_an_object() {
    let error = parse_role_document(Some(JSON), "[\"content\"]").expect_err("not an object");

    assert_eq!(error, RoleParseError::Json(RoleJsonRejection::NotAnObject));
}

#[test]
fn a_brace_body_that_is_not_valid_json_falls_back_to_plain_text_for_text_content_types() {
    let body = "{not json at all";
    let document = parse_role_document(Some(TEXT), body).expect("plain text fallback");

    assert_eq!(document.content(), body);
    assert_eq!(document.outcome(), RoleDocumentOutcome::LoadedPlainText);
    assert_eq!(document.model(), None);
    match document.diagnostics() {
        [RoleDiagnostic::PlainTextFallback(RoleJsonRejection::InvalidJson { .. })] => {}
        other => panic!("expected an invalid JSON fallback diagnostic, got {other:?}"),
    }
}

#[test]
fn a_valid_json_object_without_content_falls_back_to_plain_text_for_text_content_types() {
    let body = r#"{"model":"gpt-4o"}"#;
    let document = parse_role_document(Some(TEXT), body).expect("plain text fallback");

    assert_eq!(document.content(), body);
    assert_eq!(document.outcome(), RoleDocumentOutcome::LoadedPlainText);
    assert_eq!(
        document.diagnostics(),
        [RoleDiagnostic::PlainTextFallback(
            RoleJsonRejection::MissingContent
        )]
    );
}

#[test]
fn a_brace_body_is_parsed_as_json_even_without_a_json_content_type() {
    let document = parse_role_document(Some(TEXT), r#"  {"content":"Sniffed.","model":"gpt-4o"}"#)
        .expect("sniffed role");

    assert_eq!(document.content(), "Sniffed.");
    assert_eq!(document.model(), Some("gpt-4o"));
    assert_eq!(document.outcome(), RoleDocumentOutcome::LoadedJson);
}

#[test]
fn json_content_types_are_recognized_case_insensitively() {
    let error =
        parse_role_document(Some("Application/JSON"), r#"{"model":"gpt-4o"}"#).expect_err("fatal");

    assert_eq!(
        error,
        RoleParseError::Json(RoleJsonRejection::MissingContent)
    );
}

#[test]
fn a_body_over_the_size_bound_is_rejected_for_both_encodings() {
    let oversized = "a".repeat(ROLE_DOCUMENT_MAX_BYTES + 1);

    let text = parse_role_document(Some(TEXT), &oversized).expect_err("oversized text");
    assert_eq!(
        text,
        RoleParseError::TooLarge {
            bytes: ROLE_DOCUMENT_MAX_BYTES + 1,
            limit: ROLE_DOCUMENT_MAX_BYTES,
        }
    );

    let json = parse_role_document(Some(JSON), &oversized).expect_err("oversized json");
    assert_eq!(json, text);
    assert!(text.to_string().contains("1048576"));
}

#[test]
fn a_body_exactly_at_the_size_bound_is_accepted() {
    let body = "a".repeat(ROLE_DOCUMENT_MAX_BYTES);
    let document = parse_role_document(Some(TEXT), &body).expect("bounded body");

    assert_eq!(document.content().len(), ROLE_DOCUMENT_MAX_BYTES);
}

#[test]
fn the_fetch_request_carries_the_configured_url_and_every_frozen_limit() {
    let role = snapshot_role();
    let mut fetcher = RecordingFetcher::returning(
        RoleResponse::new(200, r#"{"content":"Loaded."}"#).with_content_type(JSON),
    );

    let document = load_role(&mut fetcher, &role).expect("loaded role");

    assert_eq!(document.content(), "Loaded.");
    assert_eq!(fetcher.urls, ["https://roles.example.test/default.json"]);
    assert_eq!(fetcher.accepts, [ROLE_FETCH_ACCEPT]);
    assert_eq!(fetcher.timeouts, [ROLE_FETCH_TIMEOUT_MS]);
    assert_eq!(fetcher.limits, [ROLE_DOCUMENT_MAX_BYTES]);
}

#[test]
fn a_transport_failure_is_reported_without_the_role_url() {
    let role = snapshot_role();
    let mut fetcher = RecordingFetcher::default();

    let error = load_role(&mut fetcher, &role).expect_err("transport failure");

    assert_eq!(error, RoleLoadError::Transport(TransportFailure));
    assert_eq!(error.to_string(), "role fetch failed: origin unreachable");
    assert!(!error.to_string().contains("roles.example.test"));
    assert!(error.source().is_some());
}

#[test]
fn a_non_success_status_is_rejected_before_the_body_is_read() {
    let role = snapshot_role();
    let mut fetcher = RecordingFetcher::returning(
        RoleResponse::new(404, r#"{"content":"Never read."}"#).with_content_type(JSON),
    );

    let error = load_role(&mut fetcher, &role).expect_err("status failure");

    assert_eq!(error, RoleLoadError::Status { status: 404 });
    assert_eq!(error.to_string(), "role fetch returned status 404");
}

#[test]
fn a_declared_length_over_the_bound_is_rejected_before_parsing() {
    let role = snapshot_role();
    let declared = u64::try_from(ROLE_DOCUMENT_MAX_BYTES).expect("limit fits in u64") + 1;
    let mut fetcher = RecordingFetcher::returning(
        RoleResponse::new(200, r#"{"content":"Short body, lying header."}"#)
            .with_content_type(JSON)
            .with_declared_length(declared),
    );

    let error = load_role(&mut fetcher, &role).expect_err("declared length failure");

    assert_eq!(
        error,
        RoleLoadError::DeclaredTooLarge {
            declared,
            limit: ROLE_DOCUMENT_MAX_BYTES,
        }
    );
}

#[test]
fn an_over_long_body_from_a_misbehaving_adapter_is_still_rejected() {
    let role = snapshot_role();
    let mut fetcher = RecordingFetcher::returning(
        RoleResponse::new(200, "a".repeat(ROLE_DOCUMENT_MAX_BYTES + 1)).with_content_type(TEXT),
    );

    let error = load_role(&mut fetcher, &role).expect_err("over-long body");

    assert_eq!(
        error,
        RoleLoadError::Parse(RoleParseError::TooLarge {
            bytes: ROLE_DOCUMENT_MAX_BYTES + 1,
            limit: ROLE_DOCUMENT_MAX_BYTES,
        })
    );
}

#[test]
fn a_body_that_is_not_utf8_is_rejected_rather_than_silently_substituted() {
    let role = snapshot_role();
    let mut fetcher = RecordingFetcher::returning(
        RoleResponse::new(200, vec![b'o', b'k', 0xFF]).with_content_type(TEXT),
    );

    let error = load_role(&mut fetcher, &role).expect_err("invalid utf-8");

    assert_eq!(error, RoleLoadError::NotUtf8 { valid_up_to: 2 });
}

#[test]
fn a_loaded_document_reports_its_json_rejection_through_the_error_chain() {
    let role = snapshot_role();
    let mut fetcher = RecordingFetcher::returning(
        RoleResponse::new(200, r#"{"model":"gpt-4o"}"#).with_content_type(JSON),
    );

    let error = load_role(&mut fetcher, &role).expect_err("missing content");

    assert_eq!(
        error,
        RoleLoadError::Parse(RoleParseError::Json(RoleJsonRejection::MissingContent))
    );
    let parse = error.source().expect("parse source");
    assert!(parse.source().is_some());
}

fn frozen_fixture_root() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let marker = manifest.join("../../compat/legacy/contract.json");
    marker
        .is_file()
        .then(|| manifest.join("../../compat/legacy/fixtures/role"))
}

fn read_fixture(root: &Path, relative: &str) -> String {
    std::fs::read_to_string(root.join(relative)).expect("read frozen role fixture")
}

#[test]
fn frozen_role_source_fixtures_produce_their_recorded_outcomes() {
    let Some(root) = frozen_fixture_root() else {
        return;
    };

    for name in [
        "json-content.json",
        "json-error.json",
        "non-string-model.json",
        "plain-text.json",
        "text-json-fallback.json",
    ] {
        let fixture: Value = serde_json::from_str(&read_fixture(&root, &format!("sources/{name}")))
            .expect("parse frozen role source fixture");
        let content_type = fixture["content_type"].as_str().expect("content_type");
        let body = match &fixture["body"] {
            Value::String(text) => text.clone(),
            object => serde_json::to_string(object).expect("serialize fixture body"),
        };
        let expected = &fixture["expected"];

        match expected["outcome"].as_str().expect("outcome") {
            "loaded_json" | "loaded_plain_text" => {
                let document =
                    parse_role_document(Some(content_type), &body).expect("frozen fixture loads");
                let expected_outcome = if expected["outcome"] == "loaded_json" {
                    RoleDocumentOutcome::LoadedJson
                } else {
                    RoleDocumentOutcome::LoadedPlainText
                };
                assert_eq!(document.outcome(), expected_outcome, "{name}");
                assert_eq!(
                    document.content(),
                    expected["content"].as_str().expect("expected content"),
                    "{name}"
                );
                assert_eq!(document.model(), expected["model"].as_str(), "{name}");
            }
            "error" => {
                let error =
                    parse_role_document(Some(content_type), &body).expect_err("frozen fixture");
                let fragment = expected["error_contains"].as_str().expect("error_contains");
                assert!(error.to_string().contains(fragment), "{name}: {error}");
            }
            other => panic!("{name}: unexpected frozen outcome {other}"),
        }
    }
}

#[test]
fn frozen_positive_role_documents_load_with_their_recorded_semantics() {
    let Some(root) = frozen_fixture_root() else {
        return;
    };

    let cases: [(&str, &str, Option<&str>, &[RoleDiagnostic]); 5] = [
        (
            "content.json",
            "You are a concise operational assistant.",
            Some("gpt-4o"),
            &[],
        ),
        (
            "prompt.json",
            "Use the prompt alias as the system message.",
            Some("claude-opus-4.6"),
            &[RoleDiagnostic::PromptAliasUsed],
        ),
        ("content-precedence.json", "This value wins.", None, &[]),
        (
            "non-string-content-fallback.json",
            "A non-string content field falls back to this prompt.",
            Some("gpt-4o"),
            &[
                RoleDiagnostic::NonStringContentIgnored,
                RoleDiagnostic::PromptAliasUsed,
            ],
        ),
        (
            "non-string-model.json",
            "Use the default model.",
            None,
            &[RoleDiagnostic::NonStringModelIgnored],
        ),
    ];

    for (name, content, model, diagnostics) in cases {
        let body = read_fixture(&root, &format!("positive/{name}"));
        let document = parse_role_document(Some(JSON), &body).expect("frozen positive fixture");

        assert_eq!(
            document.outcome(),
            RoleDocumentOutcome::LoadedJson,
            "{name}"
        );
        assert_eq!(document.content(), content, "{name}");
        assert_eq!(document.model(), model, "{name}");
        assert_eq!(document.diagnostics(), diagnostics, "{name}");
    }
}

#[test]
fn frozen_negative_role_documents_are_rejected_for_their_recorded_reasons() {
    let Some(root) = frozen_fixture_root() else {
        return;
    };

    for (name, rejection) in [
        ("missing-content.json", RoleJsonRejection::MissingContent),
        ("non-string-content.json", RoleJsonRejection::MissingContent),
        ("empty-content.json", RoleJsonRejection::EmptyContent),
    ] {
        let body = read_fixture(&root, &format!("negative/{name}"));
        let error = parse_role_document(Some(JSON), &body).expect_err("frozen negative fixture");

        assert_eq!(error, RoleParseError::Json(rejection), "{name}");
    }
}

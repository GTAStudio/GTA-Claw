//! Regression tests for the credential-handling audit of the provider layer.
//!
//! Each test names the finding it pins down. They are deliberately written
//! against the public API a caller actually has, because the audit's point was
//! that the previous design let ordinary configuration reach a bad outcome.

#![allow(clippy::literal_string_with_formatting_args)]

use claw_provider_sdk::error::ErrorKind;
use claw_provider_sdk::http::{Body, HttpRequest, HttpResponse, Method};
use claw_provider_sdk::origin::{
    BoundApiKey, BoundSecret, Origin, OriginApproval, credential_account,
};
use claw_provider_sdk::provider::Provider;
use claw_provider_sdk::secret::{ApiKey, SecretString};
use claw_providers::anthropic::{Anthropic, AnthropicConfig};
use claw_providers::github_copilot::{GitHubCopilot, GitHubCopilotConfig};
use claw_providers::openai_compatible::OpenAiCompatible;
use url::Url;

const ATTACKER: &str = "https://collector.attacker.test/v1";
const OPENAI_KEY: &str = "sk-openai-live-9f2c4b7e";
const ANTHROPIC_KEY: &str = "sk-ant-live-3d1a8f6b";
const GITHUB_TOKEN: &str = "gho_live_github_token_2f9c";

fn url(text: &str) -> Url {
    text.parse().expect("valid url")
}

// ---------------------------------------------------------------------------
// HIGH 1 / HIGH 2 — a credential cannot follow a redirected endpoint
// ---------------------------------------------------------------------------

/// The exact attack from HIGH 2: keep `provider = openai`, keep the stored
/// OpenAI key, swap only the base URL.
#[test]
fn an_openai_key_cannot_be_redirected_to_an_attacker_origin() {
    let error = OpenAiCompatible::from_registry(
        "openai",
        Some(ApiKey::new(OPENAI_KEY)),
        Some(url(ATTACKER)),
    )
    .expect_err("a swapped base URL must not silently reuse the stored key");
    assert_eq!(error.kind(), ErrorKind::Authentication);
    assert_eq!(error.provider(), "openai");
    assert!(
        !format!("{error:?}").contains(OPENAI_KEY),
        "the refusal must not echo the key"
    );
}

/// The same swap for a provider whose descriptor ships no default endpoint:
/// there is no registered origin to compare against, so the operator must
/// enroll one rather than the code defaulting to "anything goes".
#[test]
fn an_endpoint_required_provider_still_demands_an_enrolled_origin() {
    let error =
        OpenAiCompatible::from_registry("kimi", Some(ApiKey::new(OPENAI_KEY)), Some(url(ATTACKER)))
            .expect_err("an unenrolled origin must be refused");
    assert_eq!(error.kind(), ErrorKind::Authentication);

    let approval = OriginApproval::enroll(Origin::of(&url(ATTACKER)).expect("origin"));
    let client = OpenAiCompatible::from_registry_with_enrolled_origin(
        "kimi",
        Some(ApiKey::new(OPENAI_KEY)),
        url(ATTACKER),
        &approval,
    )
    .expect("an explicitly enrolled origin is allowed");
    assert_eq!(client.base_url().as_str(), ATTACKER);
}

/// Registry construction against the provider's own registered origin keeps
/// working, so the fix is not simply "refuse everything".
#[test]
fn the_registered_origin_still_works_without_enrollment() {
    let client = OpenAiCompatible::from_registry("openai", Some(ApiKey::new(OPENAI_KEY)), None)
        .expect("the registered default endpoint needs no enrollment");
    assert_eq!(client.base_url().as_str(), "https://api.openai.com/v1");

    let same_origin_subpath = OpenAiCompatible::from_registry(
        "openai",
        Some(ApiKey::new(OPENAI_KEY)),
        Some(url("https://api.openai.com/v1/beta")),
    )
    .expect("a different path on the registered origin is still the same origin");
    assert_eq!(
        same_origin_subpath.base_url().as_str(),
        "https://api.openai.com/v1/beta"
    );
}

#[test]
fn an_anthropic_key_cannot_be_redirected_to_an_attacker_origin() {
    let mut config = AnthropicConfig::new(ApiKey::new(ANTHROPIC_KEY)).expect("config");
    config.base_url = url(ATTACKER);
    let error = Anthropic::new(config)
        .expect_err("a swapped base URL must not silently reuse the stored key");
    assert_eq!(error.kind(), ErrorKind::Authentication);
    assert_eq!(error.provider(), "anthropic");
    assert!(!format!("{error:?}").contains(ANTHROPIC_KEY));
}

/// HIGH 1, the token-exchange leg: the long-lived GitHub OAuth token.
#[test]
fn the_github_oauth_token_cannot_be_sent_to_an_unpinned_exchange() {
    let mut config = GitHubCopilotConfig::new(SecretString::new(GITHUB_TOKEN)).expect("config");
    config.token_exchange_url = url("https://exchange.attacker.test/copilot_internal/v2/token");
    let error = GitHubCopilot::new(config).expect_err("an unpinned exchange must be refused");
    assert_eq!(error.kind(), ErrorKind::Authentication);
    assert!(!format!("{error:?}").contains(GITHUB_TOKEN));
}

/// HIGH 1, the spend leg: the exchanged Copilot token.
#[test]
fn the_copilot_api_origin_cannot_be_overridden_without_enrollment() {
    let mut config = GitHubCopilotConfig::new(SecretString::new(GITHUB_TOKEN)).expect("config");
    config.api_base_url = Some(url(ATTACKER));
    let error = GitHubCopilot::new(config).expect_err("an unpinned API base must be refused");
    assert_eq!(error.kind(), ErrorKind::Authentication);

    let mut enrolled = GitHubCopilotConfig::new(SecretString::new(GITHUB_TOKEN)).expect("config");
    enrolled.api_base_url = Some(url(ATTACKER));
    enrolled.approved_origins = vec![OriginApproval::enroll(
        Origin::of(&url(ATTACKER)).expect("origin"),
    )];
    GitHubCopilot::new(enrolled).expect("an explicitly enrolled origin is allowed");
}

/// The pinned defaults must still be reachable with no configuration at all.
#[test]
fn the_default_copilot_configuration_is_accepted() {
    let client =
        GitHubCopilot::with_github_token(SecretString::new(GITHUB_TOKEN)).expect("default config");
    assert_eq!(Provider::id(&client).as_str(), "github-copilot");
}

// ---------------------------------------------------------------------------
// The type-level guarantee behind the two SSRF findings
// ---------------------------------------------------------------------------

/// A bound credential is unreachable from the wrong origin even when a caller
/// bypasses the provider constructors entirely. This is the invariant that
/// stops a future provider from reintroducing the bug.
#[test]
fn a_bound_key_refuses_every_origin_but_its_own() {
    let bound =
        BoundApiKey::for_endpoint(&url("https://api.openai.com/v1"), ApiKey::new(OPENAI_KEY))
            .expect("bind");
    assert_eq!(
        bound
            .for_url(&url("https://api.openai.com/v1/chat/completions"))
            .expect("same origin")
            .expose(),
        OPENAI_KEY
    );
    // A different host, a different scheme and a different port are all
    // different origins.
    for wrong in [
        "https://collector.attacker.test/v1/chat/completions",
        "https://api.openai.com.attacker.test/v1",
        "https://api.openai.com:8443/v1",
    ] {
        bound
            .for_url(&url(wrong))
            .expect_err("a bound key must not be exposed to a foreign origin");
    }
}

/// The request builder is the only way a credential reaches the wire, and it
/// enforces the same binding, so no call site can forget to check.
#[test]
fn the_request_builder_refuses_to_authenticate_a_foreign_origin() {
    let bound = BoundSecret::new(
        Origin::parse("https://api.github.com").expect("origin"),
        SecretString::new(GITHUB_TOKEN),
    );
    HttpRequest::new(Method::Get, url("https://api.github.com/user"))
        .bound_secret_header("authorization", "token ", &bound)
        .expect("same origin");
    HttpRequest::new(Method::Get, url("https://exchange.attacker.test/user"))
        .bound_secret_header("authorization", "token ", &bound)
        .expect_err("a foreign origin must not be authenticated");
}

/// The secret-store account name carries the approved origin, so a redirected
/// endpoint looks up a credential that simply does not exist rather than
/// silently reusing the one stored for the real endpoint.
#[test]
fn the_credential_account_is_scoped_to_the_origin() {
    let real = credential_account(
        "openai",
        &Origin::parse("https://api.openai.com").expect("o"),
    );
    let redirected = credential_account(
        "openai",
        &Origin::parse("https://collector.attacker.test").expect("o"),
    );
    assert_ne!(real, redirected);
    assert_eq!(real, "openai@https://api.openai.com");
    assert_eq!(redirected, "openai@https://collector.attacker.test");
}

// ---------------------------------------------------------------------------
// HIGH 4 / HIGH 5 — nothing credential-bearing survives a Debug rendering
// ---------------------------------------------------------------------------

/// HIGH 4 named the exact bypass: a provider-chosen header name that is not on
/// any fixed allowlist.
#[test]
fn a_provider_chosen_secret_header_name_is_still_redacted() {
    let request = HttpRequest::new(Method::Post, url("https://api.example.test/v1/chat"))
        .secret_header("x-provider-secret", SecretString::new(OPENAI_KEY))
        .secret_header("x-goog-api-key", SecretString::new(ANTHROPIC_KEY));
    let rendered = format!("{request:?}");
    assert!(!rendered.contains(OPENAI_KEY), "{rendered}");
    assert!(!rendered.contains(ANTHROPIC_KEY), "{rendered}");
    assert!(rendered.contains("x-provider-secret"), "{rendered}");
    assert!(request.is_sensitive("x-provider-secret"));
    assert!(request.is_sensitive("X-Goog-Api-Key"));
}

/// HIGH 5's device-poll case: the device code is a bearer-equivalent secret and
/// it travels in a form body.
#[test]
fn a_form_body_never_renders_its_fields() {
    let body = Body::Form(format!(
        "client_id=Iv1.test&device_code={GITHUB_TOKEN}&grant_type=urn:ietf:params:oauth:grant-type:device_code"
    ));
    let rendered = format!("{body:?}");
    assert!(!rendered.contains(GITHUB_TOKEN), "{rendered}");
    assert!(!rendered.contains("client_id"), "{rendered}");
    assert!(rendered.contains("Form"), "{rendered}");
    assert!(rendered.contains("bytes: 113"), "{rendered}");
}

/// HIGH 5's main case: OAuth and Copilot token responses flow through
/// `HttpResponse`, whose derived `Debug` used to print the whole body.
#[test]
fn a_token_response_never_renders_its_body_or_header_values() {
    let response = HttpResponse::new(
        200,
        vec![
            ("content-type".to_owned(), "application/json".to_owned()),
            ("set-cookie".to_owned(), format!("session={GITHUB_TOKEN}")),
        ],
        format!(r#"{{"access_token":"{GITHUB_TOKEN}","token_type":"bearer"}}"#).into_bytes(),
    );
    let rendered = format!("{response:?}");
    assert!(!rendered.contains(GITHUB_TOKEN), "{rendered}");
    assert!(!rendered.contains("application/json"), "{rendered}");
    assert!(rendered.contains("set-cookie"), "{rendered}");
    assert!(rendered.contains("status: 200"), "{rendered}");
    assert!(rendered.contains("body_bytes: 67"), "{rendered}");
}

/// The provider objects themselves hold credentials for their whole lifetime,
/// so they are the most likely thing to end up in a `?provider` tracing field.
#[test]
fn provider_debug_output_holds_no_credential() {
    let openai = OpenAiCompatible::from_registry("openai", Some(ApiKey::new(OPENAI_KEY)), None)
        .expect("build");
    assert!(!format!("{openai:?}").contains(OPENAI_KEY));

    let anthropic =
        Anthropic::new(AnthropicConfig::new(ApiKey::new(ANTHROPIC_KEY)).expect("config"))
            .expect("build");
    assert!(!format!("{anthropic:?}").contains(ANTHROPIC_KEY));

    let copilot = GitHubCopilot::with_github_token(SecretString::new(GITHUB_TOKEN)).expect("build");
    assert!(!format!("{copilot:?}").contains(GITHUB_TOKEN));
}

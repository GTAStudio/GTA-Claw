//! Real SSRF policy assertions.
//!
//! Nothing in this file reaches the network. The transport is a recording stub
//! that fails the test if it is ever asked to contact a destination the policy
//! should have refused, and the deny-all transport proves the tool cannot fall
//! back to real I/O.

use std::collections::BTreeMap;
use std::net::IpAddr;

use claw_security::ssrf::{ResolutionError, TargetError};
use claw_tools::audit::InMemoryAuditSink;
use claw_tools::net::{
    DenyAllSearchProvider, DenyAllTransport, HttpRequest, HttpResponse, HttpTransport,
    NetFetchTool, NetworkError, PrivateOriginExceptions, SearchHit, SearchProvider, UrlPolicy,
    WebSearchTool,
};
use claw_tools::permission::{
    Approval, Capability, GrantLedger, GrantRequest, GrantScope, Resource,
};
use claw_tools::registry::ToolRegistry;
use claw_tools::sandbox::{Sandbox, SandboxLimits};
use claw_tools::tool::ToolContext;
use serde_json::json;

const NOW: u64 = 1_700_000_000_000;

/// Destinations an attacker classically tries to reach through a fetch tool.
const FORBIDDEN_TARGETS: [&str; 24] = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/admin",
    "https://127.16.0.1/",
    "http://localhost/",
    "http://LOCALHOST/",
    "http://localhost.localdomain/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "http://0x7f.0x0.0x0.0x1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[fe80::1]/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.goog/",
    "http://instance-data.ec2.internal/",
    "http://kubernetes.default.svc/api",
    "http://10.0.0.5/",
    "http://172.16.0.5/",
    "http://192.168.1.1/",
    "http://100.64.0.1/",
    "http://198.18.0.1/",
    "http://printer.local/",
    "http://db.internal/",
];

/// A transport that replays scripted responses and never performs I/O.
#[derive(Default)]
struct RecordingTransport {
    resolutions: BTreeMap<String, Vec<IpAddr>>,
    responses: Vec<HttpResponse>,
}

impl RecordingTransport {
    fn with_resolution(mut self, host: &str, addresses: &[&str]) -> Self {
        self.resolutions.insert(
            host.to_owned(),
            addresses
                .iter()
                .map(|address| address.parse().expect("test addresses are valid"))
                .collect(),
        );
        self
    }

    fn returning(mut self, responses: Vec<HttpResponse>) -> Self {
        self.responses = responses;
        self.responses.reverse();
        self
    }
}

impl HttpTransport for RecordingTransport {
    fn resolve(&mut self, host: &str) -> Result<Vec<IpAddr>, NetworkError> {
        self.resolutions
            .get(host)
            .cloned()
            .ok_or(NetworkError::TransportFailed)
    }

    fn fetch(&mut self, _request: &HttpRequest) -> Result<HttpResponse, NetworkError> {
        self.responses.pop().ok_or(NetworkError::TransportFailed)
    }
}

fn sandbox() -> Sandbox {
    let root = std::env::current_dir().expect("a working directory exists");
    Sandbox::new(&root, SandboxLimits::default()).expect("the crate directory is adoptable")
}

fn ledger() -> GrantLedger {
    let mut ledger = GrantLedger::new();
    ledger.grant(GrantRequest {
        capability: Capability::NetworkFetch,
        scope: GrantScope::Unrestricted,
        expires_unix_millis: None,
        max_uses: None,
        approval: Approval::Explicit,
    });
    ledger.grant(GrantRequest {
        capability: Capability::NetworkSearch,
        scope: GrantScope::Unrestricted,
        expires_unix_millis: None,
        max_uses: None,
        approval: Approval::Explicit,
    });
    ledger
}

#[test]
fn every_private_and_metadata_destination_is_refused_by_the_default_policy() {
    let policy = UrlPolicy::public_internet();
    for target in FORBIDDEN_TARGETS {
        let error = policy
            .validate(target)
            .expect_err("policy accepted a forbidden destination");
        assert!(
            matches!(
                error,
                NetworkError::Target(
                    TargetError::BlockedAddress
                        | TargetError::BlockedHost
                        | TargetError::AmbiguousIpLiteral
                        | TargetError::InvalidHost
                        | TargetError::InvalidUrl
                ) | NetworkError::HostDenied
                    | NetworkError::PortNotAllowed
            ),
            "unexpected refusal {error:?} for {target}"
        );
    }
}

#[test]
fn credentials_fragments_and_non_http_schemes_are_refused() {
    let policy = UrlPolicy::public_internet();
    assert_eq!(
        policy.validate("http://user:pass@example.com/"),
        Err(NetworkError::Target(TargetError::UserInfoForbidden))
    );
    assert_eq!(
        policy.validate("https://example.com/page#fragment"),
        Err(NetworkError::Target(TargetError::FragmentForbidden))
    );
    for scheme in [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
        "jar:http://example.com/!/",
    ] {
        assert_eq!(
            policy.validate(scheme),
            Err(NetworkError::Target(TargetError::UnsupportedScheme)),
            "scheme accepted for {scheme}"
        );
    }
    // Opaque schemes carry no authority at all and are refused earlier.
    assert_eq!(
        policy.validate("data:text/plain,hello"),
        Err(NetworkError::Target(TargetError::InvalidUrl))
    );
    assert_eq!(
        policy.validate("javascript:alert(1)"),
        Err(NetworkError::Target(TargetError::InvalidUrl))
    );
}

#[test]
fn only_allowlisted_ports_are_reachable() {
    let policy = UrlPolicy::public_internet();
    assert_eq!(
        policy.validate("http://example.com:22/"),
        Err(NetworkError::PortNotAllowed)
    );
    assert_eq!(
        policy.validate("http://example.com:6379/"),
        Err(NetworkError::PortNotAllowed)
    );
    assert_eq!(
        policy
            .validate("https://example.com/")
            .expect("443 is allowed")
            .host(),
        "example.com"
    );
    let narrowed = UrlPolicy::public_internet().with_allowed_ports([443]);
    assert_eq!(
        narrowed.validate("http://example.com/"),
        Err(NetworkError::PortNotAllowed)
    );
}

#[test]
fn an_exact_host_allowlist_refuses_everything_else() {
    let policy = UrlPolicy::exact_hosts(["api.example.com"]).expect("valid allowlist");
    assert_eq!(
        policy
            .validate("https://api.example.com/v1/models")
            .expect("the allowlisted host is reachable")
            .host(),
        "api.example.com"
    );
    for target in [
        "https://evil.example.com/",
        "https://api.example.com.evil.test/",
        "https://example.com/",
    ] {
        assert_eq!(
            policy.validate(target),
            Err(NetworkError::Target(TargetError::HostNotAllowlisted)),
            "allowlist accepted {target}"
        );
    }
}

#[test]
fn a_private_origin_exception_covers_exactly_one_origin() {
    let mut exceptions = PrivateOriginExceptions::none();
    exceptions
        .allow_origin("http://127.0.0.1:8080")
        .expect("a well-formed origin");
    let policy = UrlPolicy::public_internet().with_exceptions(exceptions);

    let permitted = policy
        .validate("http://127.0.0.1:8080/health")
        .expect("the excepted origin is reachable");
    assert_eq!(permitted.host(), "http://127.0.0.1:8080");
    assert_eq!(permitted.url(), "http://127.0.0.1:8080/health");
    policy
        .validate("http://127.0.0.1:8080")
        .expect("the bare origin is reachable");

    // Neighbouring ports, hosts, schemes and prefix-extension tricks must not
    // ride along on the exception.
    for target in [
        "http://127.0.0.1:8081/",
        "http://127.0.0.1:80800/",
        "https://127.0.0.1:8080/",
        "http://127.0.0.2:8080/",
        "http://127.0.0.1:8080.evil.test/",
        "http://127.0.0.1:8080@evil.test/",
    ] {
        assert!(
            policy.validate(target).is_err(),
            "the exception leaked to {target}"
        );
    }
}

#[test]
fn exception_origins_must_be_well_formed() {
    let mut exceptions = PrivateOriginExceptions::none();
    for candidate in [
        "127.0.0.1:8080",
        "http://127.0.0.1:8080/",
        "http://",
        "ftp://127.0.0.1",
        "http://127.0.0.1:8080#x",
        "http://user@127.0.0.1:8080",
        "http://127.0.0.1:0",
        "http://127.0.0.1:99999",
    ] {
        assert_eq!(
            exceptions.allow_origin(candidate),
            Err(NetworkError::InvalidExceptionOrigin),
            "malformed origin accepted: {candidate}"
        );
    }
    assert!(exceptions.origins().is_empty());
}

#[test]
fn the_tool_refuses_forbidden_urls_before_any_transport_call() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        unix_millis: NOW,
    };
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            DenyAllTransport,
        )))
        .expect("net_fetch registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    for target in FORBIDDEN_TARGETS {
        let error = registry
            .invoke(
                "net_fetch",
                &json!({ "url": target }),
                &context,
                &mut ledger,
                &mut audit,
            )
            .expect_err("the tool accepted a forbidden destination");
        assert!(
            error.network().is_some(),
            "unexpected error {error:?} for {target}"
        );
    }
    // Every refusal happened while deriving the resource, so no grant was
    // ever consulted and no authorization record exists.
    assert!(
        audit.records().iter().all(|record| record.grant.is_none()),
        "a forbidden destination reached the permission gate"
    );
}

#[test]
fn a_public_fetch_revalidates_dns_on_every_hop() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        unix_millis: NOW,
    };
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34"])
        .with_resolution("cdn.example.net", &["93.184.216.35"])
        .returning(vec![
            HttpResponse {
                status: 302,
                location: Some("https://cdn.example.net/asset".to_owned()),
                body: Vec::new(),
            },
            HttpResponse {
                status: 200,
                location: None,
                body: b"payload".to_vec(),
            },
        ]);
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            transport,
        )))
        .expect("net_fetch registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let output = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "https://example.com/start" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("a public fetch succeeds");
    assert_eq!(output.content, "payload");
    assert_eq!(output.structured["status"], 200);
    assert_eq!(output.structured["host"], "cdn.example.net");
    assert_eq!(
        output.structured["hops"],
        json!(["https://example.com/start", "https://cdn.example.net/asset"])
    );
    assert_eq!(
        audit.records()[0].resource,
        Some(Resource::Host("example.com".to_owned()))
    );
}

#[test]
fn a_redirect_into_private_space_is_refused_mid_flight() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        unix_millis: NOW,
    };
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34"])
        .returning(vec![HttpResponse {
            status: 302,
            location: Some("http://169.254.169.254/latest/meta-data/".to_owned()),
            body: Vec::new(),
        }]);
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            transport,
        )))
        .expect("net_fetch registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let error = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "https://example.com/start" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("the redirect must be refused");
    assert_eq!(
        error.network(),
        Some(&NetworkError::Target(TargetError::BlockedAddress))
    );
}

#[test]
fn a_rebinding_dns_answer_is_refused_before_the_request() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        unix_millis: NOW,
    };
    // The name resolves to a public address at first glance but the answer
    // contains a loopback address; the target must never be contacted.
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34", "127.0.0.1"])
        .returning(vec![HttpResponse {
            status: 200,
            location: None,
            body: b"should never be reached".to_vec(),
        }]);
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            transport,
        )))
        .expect("net_fetch registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let error = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "https://example.com/start" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("a rebinding answer must be refused");
    assert_eq!(
        error.network(),
        Some(&NetworkError::Resolution(ResolutionError::BlockedAddress))
    );
}

#[test]
fn the_redirect_budget_is_finite() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        unix_millis: NOW,
    };
    let looping = (0..8)
        .map(|index| HttpResponse {
            status: 302,
            location: Some(format!("https://example.com/hop{index}")),
            body: Vec::new(),
        })
        .collect();
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34"])
        .returning(looping);
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet().with_max_redirects(2),
            transport,
        )))
        .expect("net_fetch registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let error = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "https://example.com/start" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("the redirect budget is exhausted");
    assert_eq!(error.network(), Some(&NetworkError::TooManyRedirects));
}

#[test]
fn the_default_transport_reaches_nothing_at_all() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        unix_millis: NOW,
    };
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            DenyAllTransport,
        )))
        .expect("net_fetch registers");
    registry
        .register(Box::new(WebSearchTool::new(
            UrlPolicy::public_internet(),
            DenyAllSearchProvider,
        )))
        .expect("web_search registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let fetch = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "https://example.com/" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("no transport is configured");
    assert_eq!(fetch.network(), Some(&NetworkError::TransportRefused));

    let search = registry
        .invoke(
            "web_search",
            &json!({ "query": "anything" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("no provider is configured");
    assert_eq!(search.network(), Some(&NetworkError::TransportRefused));
}

#[test]
fn search_results_pointing_at_private_space_are_dropped() {
    struct StubProvider;

    impl SearchProvider for StubProvider {
        fn name(&self) -> &str {
            "stub"
        }

        fn search(
            &mut self,
            _query: &str,
            _max_results: usize,
        ) -> Result<Vec<SearchHit>, NetworkError> {
            Ok(vec![
                SearchHit {
                    title: "public".to_owned(),
                    url: "https://example.com/doc".to_owned(),
                    snippet: "fine".to_owned(),
                },
                SearchHit {
                    title: "metadata".to_owned(),
                    url: "http://169.254.169.254/latest/meta-data/".to_owned(),
                    snippet: "hostile".to_owned(),
                },
                SearchHit {
                    title: "loopback".to_owned(),
                    url: "http://127.0.0.1:8080/admin".to_owned(),
                    snippet: "hostile".to_owned(),
                },
            ])
        }
    }

    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        unix_millis: NOW,
    };
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(WebSearchTool::new(
            UrlPolicy::public_internet(),
            StubProvider,
        )))
        .expect("web_search registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let output = registry
        .invoke(
            "web_search",
            &json!({ "query": "gateway protocol" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("the search succeeds");
    assert_eq!(
        output.structured["results"],
        json!([{
            "title": "public",
            "url": "https://example.com/doc",
            "snippet": "fine",
        }])
    );
    assert_eq!(output.structured["rejected_results"], 2);
    assert!(output.truncated);
    assert!(
        !output.content.contains("169.254.169.254"),
        "a refused destination reached the model: {}",
        output.content
    );
}

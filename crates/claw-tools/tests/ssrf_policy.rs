//! Real SSRF policy assertions.
//!
//! Nothing in this file reaches the network. The transport is a recording stub
//! that fails the test if it is ever asked to contact a destination the policy
//! should have refused, and the deny-all transport proves the tool cannot fall
//! back to real I/O.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use claw_security::ssrf::{ResolutionError, TargetError};
use claw_tools::audit::{
    AuditError, AuditOutcome, AuditPhase, AuditReason, InMemoryAuditSink, ToolAuditRecord,
    ToolAuditSink,
};
use claw_tools::clock::{Clock, FixedClock};
use claw_tools::net::{
    DenyAllSearchProvider, DenyAllTransport, HttpRequest, HttpResponse, HttpTransport,
    NetFetchTool, NetworkError, PinnedHttpTransport, PrivateOriginExceptions, SearchHit,
    SearchProvider, UrlPolicy, WebSearchTool,
};
use claw_tools::permission::{
    Approval, Capability, DenialReason, GrantLedger, GrantRequest, GrantScope, PermissionError,
    Resource,
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

/// Shared record of every URL the transport was actually asked to fetch.
#[derive(Clone, Default)]
struct RequestLog(Rc<RefCell<Vec<String>>>);

impl RequestLog {
    fn urls(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

/// A response the stub transport should replay.
///
/// The peer is not scripted: an honest transport connects to one of the
/// addresses the caller pinned, so the stub reports `request.pinned` rather
/// than a value a test could quietly choose.
#[derive(Clone, Debug)]
struct ScriptedResponse {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

/// A transport that replays scripted responses and never performs I/O.
#[derive(Default)]
struct RecordingTransport {
    resolutions: BTreeMap<String, Vec<IpAddr>>,
    responses: Vec<ScriptedResponse>,
    log: RequestLog,
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

    fn returning(mut self, responses: Vec<ScriptedResponse>) -> Self {
        self.responses = responses;
        self.responses.reverse();
        self
    }

    fn logging(mut self, log: &RequestLog) -> Self {
        self.log = log.clone();
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

    fn fetch(&mut self, request: &HttpRequest) -> Result<HttpResponse, NetworkError> {
        self.log.0.borrow_mut().push(request.url.clone());
        let peer = *request
            .pinned
            .first()
            .ok_or(NetworkError::TransportFailed)?;
        let scripted = self.responses.pop().ok_or(NetworkError::TransportFailed)?;
        Ok(HttpResponse {
            status: scripted.status,
            location: scripted.location,
            body: scripted.body,
            peer,
        })
    }
}

/// A sink that refuses to record one specific host, proving an authorization
/// that cannot be committed is withdrawn instead of assumed.
struct SelectiveAuditSink {
    reject_host: &'static str,
    records: Vec<ToolAuditRecord>,
}

impl ToolAuditSink for SelectiveAuditSink {
    fn persist(&mut self, record: &ToolAuditRecord) -> Result<(), AuditError> {
        if record.resource == Some(Resource::Host(self.reject_host.to_owned())) {
            return Err(AuditError::new("sink refused the record"));
        }
        self.records.push(record.clone());
        Ok(())
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
        clock: &FixedClock::new(NOW),
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
        clock: &FixedClock::new(NOW),
    };
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34"])
        .with_resolution("cdn.example.net", &["93.184.216.35"])
        .returning(vec![
            ScriptedResponse {
                status: 302,
                location: Some("https://cdn.example.net/asset".to_owned()),
                body: Vec::new(),
            },
            ScriptedResponse {
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
    // The second host was reached, so it had to be authorized in its own right
    // and recorded before the request left the host.
    assert_eq!(audit.records().len(), 3);
    assert_eq!(audit.records()[1].phase, AuditPhase::Authorized);
    assert_eq!(audit.records()[1].outcome, AuditOutcome::Allowed);
    assert_eq!(
        audit.records()[1].resource,
        Some(Resource::Host("cdn.example.net".to_owned()))
    );
}

#[test]
fn a_host_scoped_grant_does_not_survive_a_cross_host_redirect() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let log = RequestLog::default();
    let transport = RecordingTransport::default()
        .logging(&log)
        .with_resolution("docs.example.com", &["93.184.216.34"])
        .with_resolution("attacker.test", &["93.184.216.36"])
        .returning(vec![
            ScriptedResponse {
                status: 302,
                location: Some("https://attacker.test/collect?d=context".to_owned()),
                body: Vec::new(),
            },
            ScriptedResponse {
                status: 200,
                location: None,
                body: b"exfiltrated".to_vec(),
            },
        ]);
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            transport,
        )))
        .expect("net_fetch registers");
    let mut ledger = GrantLedger::new();
    ledger.grant(GrantRequest {
        capability: Capability::NetworkFetch,
        scope: GrantScope::Host("docs.example.com".to_owned()),
        expires_unix_millis: None,
        max_uses: None,
        approval: Approval::Explicit,
    });
    let mut audit = InMemoryAuditSink::new();

    let error = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "https://docs.example.com/start" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("an open redirect widened a host-scoped grant");
    assert_eq!(
        error.permission(),
        Some(PermissionError {
            tool: "net_fetch",
            capability: Capability::NetworkFetch,
            reason: DenialReason::NoMatchingGrant,
        })
    );
    // The attacker host was never contacted: the refusal happened before the
    // redirect was followed, so nothing was exfiltrated.
    assert_eq!(
        log.urls(),
        vec!["https://docs.example.com/start".to_owned()]
    );
    assert_eq!(audit.records().len(), 3);
    assert_eq!(audit.records()[1].phase, AuditPhase::Authorized);
    assert_eq!(audit.records()[1].outcome, AuditOutcome::Denied);
    assert_eq!(audit.records()[1].reason, AuditReason::PolicyRejected);
    assert_eq!(
        audit.records()[1].denial,
        Some(DenialReason::NoMatchingGrant)
    );
    assert_eq!(
        audit.records()[1].resource,
        Some(Resource::Host("attacker.test".to_owned()))
    );
    assert_eq!(audit.records()[1].grant, None);
    assert_eq!(audit.records()[2].phase, AuditPhase::Completed);
    assert_eq!(audit.records()[2].outcome, AuditOutcome::Failed);
}

#[test]
fn a_same_host_redirect_spends_no_additional_grant_budget() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let log = RequestLog::default();
    let transport = RecordingTransport::default()
        .logging(&log)
        .with_resolution("docs.example.com", &["93.184.216.34"])
        .returning(vec![
            ScriptedResponse {
                status: 301,
                location: Some("https://docs.example.com/guide/v2".to_owned()),
                body: Vec::new(),
            },
            ScriptedResponse {
                status: 200,
                location: None,
                body: b"guide".to_vec(),
            },
        ]);
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            transport,
        )))
        .expect("net_fetch registers");
    let mut ledger = GrantLedger::new();
    // A single-use grant proves the same-host hop asked the broker no second
    // time: a second question would have found the grant exhausted.
    ledger.grant(GrantRequest {
        capability: Capability::NetworkFetch,
        scope: GrantScope::Host("docs.example.com".to_owned()),
        expires_unix_millis: None,
        max_uses: Some(1),
        approval: Approval::Explicit,
    });
    let mut audit = InMemoryAuditSink::new();

    let output = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "https://docs.example.com/guide" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("a same-host redirect stays inside the granted scope");
    assert_eq!(output.content, "guide");
    assert_eq!(
        log.urls(),
        vec![
            "https://docs.example.com/guide".to_owned(),
            "https://docs.example.com/guide/v2".to_owned(),
        ]
    );
    assert_eq!(audit.records().len(), 2);
    assert_eq!(audit.records()[0].phase, AuditPhase::Authorized);
    assert_eq!(audit.records()[1].phase, AuditPhase::Completed);
    assert_eq!(audit.records()[1].outcome, AuditOutcome::Allowed);
}

#[test]
fn every_cross_host_redirect_is_re_authorized_in_order() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let log = RequestLog::default();
    let transport = RecordingTransport::default()
        .logging(&log)
        .with_resolution("first.example.com", &["93.184.216.34"])
        .with_resolution("second.example.net", &["93.184.216.35"])
        .with_resolution("third.example.org", &["93.184.216.36"])
        .returning(vec![
            ScriptedResponse {
                status: 302,
                location: Some("https://second.example.net/b".to_owned()),
                body: Vec::new(),
            },
            ScriptedResponse {
                status: 302,
                location: Some("https://third.example.org/c".to_owned()),
                body: Vec::new(),
            },
            ScriptedResponse {
                status: 200,
                location: None,
                body: b"final".to_vec(),
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
            &json!({ "url": "https://first.example.com/a" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("an unrestricted grant covers every hop");
    assert_eq!(output.content, "final");
    assert_eq!(
        log.urls(),
        vec![
            "https://first.example.com/a".to_owned(),
            "https://second.example.net/b".to_owned(),
            "https://third.example.org/c".to_owned(),
        ]
    );
    let authorized: Vec<Option<Resource>> = audit
        .records()
        .iter()
        .filter(|record| record.phase == AuditPhase::Authorized)
        .map(|record| record.resource.clone())
        .collect();
    assert_eq!(
        authorized,
        vec![
            Some(Resource::Host("first.example.com".to_owned())),
            Some(Resource::Host("second.example.net".to_owned())),
            Some(Resource::Host("third.example.org".to_owned())),
        ]
    );
}

#[test]
fn an_unrecordable_redirect_authorization_is_withdrawn() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let log = RequestLog::default();
    let transport = RecordingTransport::default()
        .logging(&log)
        .with_resolution("docs.example.com", &["93.184.216.34"])
        .with_resolution("attacker.test", &["93.184.216.36"])
        .returning(vec![
            ScriptedResponse {
                status: 302,
                location: Some("https://attacker.test/collect".to_owned()),
                body: Vec::new(),
            },
            ScriptedResponse {
                status: 200,
                location: None,
                body: b"exfiltrated".to_vec(),
            },
        ]);
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            UrlPolicy::public_internet(),
            transport,
        )))
        .expect("net_fetch registers");
    // The grant itself is unrestricted, so only the audit failure can refuse
    // the hop.
    let mut ledger = ledger();
    let mut audit = SelectiveAuditSink {
        reject_host: "attacker.test",
        records: Vec::new(),
    };

    let error = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "https://docs.example.com/start" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("an unrecordable hop was allowed");
    assert_eq!(
        error.permission(),
        Some(PermissionError {
            tool: "net_fetch",
            capability: Capability::NetworkFetch,
            reason: DenialReason::AuditUnavailable,
        })
    );
    assert_eq!(
        log.urls(),
        vec!["https://docs.example.com/start".to_owned()]
    );
    assert_eq!(audit.records.len(), 2);
    assert_eq!(audit.records[1].phase, AuditPhase::Completed);
    assert_eq!(audit.records[1].outcome, AuditOutcome::Failed);
}

#[test]
fn a_redirect_into_private_space_is_refused_mid_flight() {
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34"])
        .returning(vec![ScriptedResponse {
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
        clock: &FixedClock::new(NOW),
    };
    // The name resolves to a public address at first glance but the answer
    // contains a loopback address; the target must never be contacted.
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34", "127.0.0.1"])
        .returning(vec![ScriptedResponse {
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
        clock: &FixedClock::new(NOW),
    };
    let looping = (0..8)
        .map(|index| ScriptedResponse {
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
        clock: &FixedClock::new(NOW),
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
        clock: &FixedClock::new(NOW),
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

/// A minimal, single-threaded HTTP server on loopback for transport tests.
///
/// It exists because a recording stub can only prove what the code under test
/// asked for, never where the bytes actually went. This one accepts real
/// connections, so pinning and redirect handling are observable.
struct LoopbackServer {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LoopbackServer {
    /// Starts a server that replies with `responses` in order, repeating the
    /// last reply once the script is exhausted.
    fn start(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind succeeds");
        let port = listener.local_addr().expect("bound address").port();
        listener
            .set_nonblocking(true)
            .expect("non-blocking listener");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut index = 0_usize;
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // Accepted sockets inherit the listener's non-blocking
                        // mode on Windows, which would make the first read
                        // fail instead of waiting for the request.
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                        let mut raw = Vec::new();
                        let mut chunk = [0_u8; 512];
                        while let Ok(read) = stream.read(&mut chunk) {
                            if read == 0 {
                                break;
                            }
                            raw.extend_from_slice(&chunk[..read]);
                            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        thread_requests
                            .lock()
                            .expect("request log is usable")
                            .push(String::from_utf8_lossy(&raw).into_owned());
                        let reply = responses
                            .get(index)
                            .or_else(|| responses.last())
                            .cloned()
                            .unwrap_or_default();
                        index += 1;
                        let _ = stream.write_all(reply.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("request log is usable").clone()
    }
}

impl Drop for LoopbackServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A transport that answers honestly but claims a different peer, standing in
/// for a client library that resolved the name again behind the caller's back.
struct RebindingTransport {
    answer: IpAddr,
    peer: IpAddr,
}

impl HttpTransport for RebindingTransport {
    fn resolve(&mut self, _host: &str) -> Result<Vec<IpAddr>, NetworkError> {
        Ok(vec![self.answer])
    }

    fn fetch(&mut self, _request: &HttpRequest) -> Result<HttpResponse, NetworkError> {
        Ok(HttpResponse {
            status: 200,
            location: None,
            body: b"metadata".to_vec(),
            peer: self.peer,
        })
    }
}

#[test]
fn a_transport_that_connects_off_the_validated_set_is_refused() {
    // DNS rebinding in its purest form: the answer that was validated is not
    // the address the connection reached.
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let transport = RebindingTransport {
        answer: "93.184.216.34".parse().expect("valid literal"),
        peer: "169.254.169.254".parse().expect("valid literal"),
    };
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
            &json!({ "url": "http://example.com/" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("a rebound connection must be refused");
    assert_eq!(
        error.network(),
        Some(&NetworkError::PeerNotPinned),
        "unexpected error {error:?}"
    );
}

#[test]
fn the_pinned_transport_connects_to_the_pinned_address_not_to_the_host_name() {
    // The host name here resolves nowhere. If the transport re-resolved the
    // URL, no connection could be made at all; the request arrives because the
    // caller's validated address is what gets dialled.
    let server = LoopbackServer::start(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_owned(),
    ]);
    let mut transport =
        PinnedHttpTransport::new().with_timeouts(Duration::from_secs(2), Duration::from_secs(2));
    let response = transport
        .fetch(&HttpRequest {
            url: format!("http://not-a-real-host.invalid:{}/thing", server.port),
            method: "GET".to_owned(),
            host: "not-a-real-host.invalid".to_owned(),
            port: server.port,
            pinned: vec!["127.0.0.1".parse().expect("valid literal")],
            max_body_bytes: 1024,
        })
        .expect("the pinned address answers");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hi");
    assert_eq!(
        response.peer,
        "127.0.0.1".parse::<IpAddr>().expect("valid literal"),
        "the transport reported a peer it did not connect to"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1, "expected exactly one request");
    assert!(
        requests[0].starts_with("GET /thing HTTP/1.1\r\n"),
        "unexpected request line: {:?}",
        requests[0]
    );
    assert!(
        requests[0].contains("Host: not-a-real-host.invalid\r\n"),
        "the Host header was rewritten: {:?}",
        requests[0]
    );
}

#[test]
fn the_pinned_transport_refuses_to_connect_when_no_address_is_pinned() {
    let server = LoopbackServer::start(vec!["HTTP/1.1 200 OK\r\n\r\n".to_owned()]);
    let mut transport = PinnedHttpTransport::new();
    let error = transport
        .fetch(&HttpRequest {
            url: format!("http://127.0.0.1:{}/", server.port),
            method: "GET".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: server.port,
            pinned: Vec::new(),
            max_body_bytes: 1024,
        })
        .expect_err("an unpinned request must not be sent");
    assert_eq!(error, NetworkError::TransportRefused);
    assert!(
        server.requests().is_empty(),
        "an unpinned request reached the socket"
    );
}

#[test]
fn the_pinned_transport_returns_redirects_instead_of_following_them() {
    // A client that follows redirects internally makes every hop invisible to
    // policy. This one hands the redirect back and stops.
    let server = LoopbackServer::start(vec![
        "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n"
            .to_owned(),
    ]);
    let mut transport = PinnedHttpTransport::new();
    let response = transport
        .fetch(&HttpRequest {
            url: format!("http://127.0.0.1:{}/start", server.port),
            method: "GET".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: server.port,
            pinned: vec!["127.0.0.1".parse().expect("valid literal")],
            max_body_bytes: 1024,
        })
        .expect("the server answers");

    assert_eq!(response.status, 302);
    assert_eq!(
        response.location.as_deref(),
        Some("http://169.254.169.254/latest/meta-data/")
    );
    assert_eq!(
        server.requests().len(),
        1,
        "the transport followed the redirect itself"
    );
}

#[test]
fn a_redirect_to_the_metadata_service_is_refused_over_a_real_socket() {
    // End to end over a real connection: an excepted loopback origin is
    // permitted, and its open redirect to the cloud metadata address is not.
    let server = LoopbackServer::start(vec![
        "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n"
            .to_owned(),
    ]);
    let mut exceptions = PrivateOriginExceptions::none();
    exceptions
        .allow_origin(&server.origin())
        .expect("a well-formed origin");
    let policy = UrlPolicy::public_internet().with_exceptions(exceptions);

    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            policy,
            PinnedHttpTransport::new(),
        )))
        .expect("net_fetch registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let error = registry
        .invoke(
            "net_fetch",
            &json!({ "url": format!("{}/start", server.origin()) }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("the metadata redirect must be refused");
    assert!(error.network().is_some(), "unexpected error {error:?}");
    assert_eq!(
        server.requests().len(),
        1,
        "the redirect was fetched despite being refused"
    );
}

#[test]
fn an_excepted_loopback_origin_is_fetched_over_a_real_socket() {
    // The positive control: without it the refusal tests above could pass for
    // the wrong reason.
    let server = LoopbackServer::start(vec![
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload".to_owned(),
    ]);
    let mut exceptions = PrivateOriginExceptions::none();
    exceptions
        .allow_origin(&server.origin())
        .expect("a well-formed origin");
    let policy = UrlPolicy::public_internet().with_exceptions(exceptions);

    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &FixedClock::new(NOW),
    };
    let mut registry = ToolRegistry::new();
    registry
        .register(Box::new(NetFetchTool::new(
            policy,
            PinnedHttpTransport::new(),
        )))
        .expect("net_fetch registers");
    let mut ledger = ledger();
    let mut audit = InMemoryAuditSink::new();

    let output = registry
        .invoke(
            "net_fetch",
            &json!({ "url": format!("{}/health", server.origin()) }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("an excepted origin is reachable");
    assert_eq!(output.structured["status"], 200);
    assert_eq!(output.structured["body"], "payload");
    assert_eq!(server.requests().len(), 1);
}

/// A clock that moves forward on every reading.
///
/// It models the only honest assumption available to a security check: time
/// passes between decisions. Code that samples time once per invocation and
/// reuses it cannot tell this clock apart from a frozen one.
#[derive(Debug)]
struct AdvancingClock {
    start: u64,
    step: u64,
    readings: AtomicU64,
}

impl AdvancingClock {
    fn new(start: u64, step: u64) -> Self {
        Self {
            start,
            step,
            readings: AtomicU64::new(0),
        }
    }

    fn readings(&self) -> u64 {
        self.readings.load(Ordering::Relaxed)
    }
}

impl Clock for AdvancingClock {
    fn unix_millis(&self) -> u64 {
        let reading = self.readings.fetch_add(1, Ordering::Relaxed);
        self.start + reading * self.step
    }
}

#[test]
fn a_grant_that_expires_mid_invocation_does_not_authorize_a_later_hop() {
    // The audited failure: one timestamp was captured per invocation and
    // reused for every later resource, so a grant that expired while the
    // request was in flight still authorized the host it was redirected to.
    // The second host's grant expires two seconds in; the clock passes that
    // point before the redirect is reached.
    let clock = AdvancingClock::new(NOW, 1_000);
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &clock,
    };
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34"])
        .with_resolution("cdn.example.net", &["93.184.216.35"])
        .returning(vec![
            ScriptedResponse {
                status: 302,
                location: Some("http://cdn.example.net/asset".to_owned()),
                body: Vec::new(),
            },
            ScriptedResponse {
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

    let mut ledger = GrantLedger::new();
    ledger.grant(GrantRequest {
        capability: Capability::NetworkFetch,
        scope: GrantScope::Host("example.com".to_owned()),
        expires_unix_millis: None,
        max_uses: None,
        approval: Approval::Explicit,
    });
    ledger.grant(GrantRequest {
        capability: Capability::NetworkFetch,
        scope: GrantScope::Host("cdn.example.net".to_owned()),
        expires_unix_millis: Some(NOW + 500),
        max_uses: None,
        approval: Approval::Explicit,
    });
    let mut audit = InMemoryAuditSink::new();

    let error = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "http://example.com/start" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect_err("an expired grant must not authorize the redirect target");
    assert!(error.permission().is_some(), "unexpected error {error:?}");
    assert!(
        clock.readings() > 1,
        "the clock was read once, so expiry was evaluated against a stale time"
    );
    // The refusal must be the second host, reached after the first was
    // legitimately authorized, not a blanket failure of the invocation.
    let records = audit.records();
    assert!(
        records.iter().any(|record| {
            record.resource == Some(Resource::Host("example.com".to_owned()))
                && record.outcome == AuditOutcome::Allowed
        }),
        "the first host was never authorized: {records:?}"
    );
    let refusal = records
        .iter()
        .find(|record| record.resource == Some(Resource::Host("cdn.example.net".to_owned())))
        .expect("the redirect target was evaluated");
    assert_eq!(refusal.outcome, AuditOutcome::Denied);
    assert_eq!(refusal.denial, Some(DenialReason::GrantExpired));
    assert!(
        refusal.unix_millis > NOW + 500,
        "the refusal was recorded against a time before the grant expired"
    );
}

#[test]
fn the_same_redirect_succeeds_while_the_second_grant_is_still_valid() {
    // Positive control for the test above: with a grant that outlives the
    // invocation, the identical redirect chain completes.
    let clock = AdvancingClock::new(NOW, 1_000);
    let sandbox = sandbox();
    let context = ToolContext {
        sandbox: &sandbox,
        clock: &clock,
    };
    let transport = RecordingTransport::default()
        .with_resolution("example.com", &["93.184.216.34"])
        .with_resolution("cdn.example.net", &["93.184.216.35"])
        .returning(vec![
            ScriptedResponse {
                status: 302,
                location: Some("http://cdn.example.net/asset".to_owned()),
                body: Vec::new(),
            },
            ScriptedResponse {
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

    let mut ledger = GrantLedger::new();
    for host in ["example.com", "cdn.example.net"] {
        ledger.grant(GrantRequest {
            capability: Capability::NetworkFetch,
            scope: GrantScope::Host(host.to_owned()),
            expires_unix_millis: Some(NOW + 600_000),
            max_uses: None,
            approval: Approval::Explicit,
        });
    }
    let mut audit = InMemoryAuditSink::new();

    let output = registry
        .invoke(
            "net_fetch",
            &json!({ "url": "http://example.com/start" }),
            &context,
            &mut ledger,
            &mut audit,
        )
        .expect("a live grant authorizes the redirect target");
    assert_eq!(output.structured["status"], 200);
    assert_eq!(output.structured["body"], "payload");
}

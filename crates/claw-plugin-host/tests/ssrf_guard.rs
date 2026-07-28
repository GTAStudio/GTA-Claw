//! Outbound HTTP is validated against the resolved address, not the name.
//!
//! Every request in this file originates from a real Component Model guest
//! calling `host-http.send` through Wasmtime; the fixture's `f` selector asks
//! for `https://example.invalid/probe`.

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use claw_plugin_api::capability::{Capability, CapabilityGrant, HttpGrant, HttpMethod};
use claw_plugin_host::PluginHost;
use claw_plugin_host::services::{
    DnsResolver, HostServices, HttpTransport, InboundResponse, OutboundRequest, StaticDns,
};
use support::{install_probe, probe_ceiling, unsigned_core_policy};

/// `permission-denied` is the second `error-code` case, so the guest sees `e1`.
const DENIED: &str = "e1";
const ALLOWED: &str = "o0";

/// Records every request it is handed and replies from a scripted queue.
#[derive(Default)]
struct ScriptedTransport {
    seen: Mutex<Vec<OutboundRequest>>,
    replies: Mutex<Vec<InboundResponse>>,
}

impl ScriptedTransport {
    fn new(replies: Vec<InboundResponse>) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            replies: Mutex::new(replies),
        })
    }

    fn seen(&self) -> Vec<OutboundRequest> {
        self.seen.lock().expect("transport lock").clone()
    }
}

impl HttpTransport for ScriptedTransport {
    fn send(&self, plugin_id: &str, request: OutboundRequest) -> Result<InboundResponse, String> {
        assert_eq!(
            plugin_id,
            support::PROBE_ID,
            "the transport must be told which plugin the request belongs to"
        );
        self.seen.lock().expect("transport lock").push(request);
        let mut replies = self.replies.lock().expect("reply lock");
        if replies.is_empty() {
            return Err("the script ran out of replies".to_owned());
        }
        Ok(replies.remove(0))
    }
}

/// Answers the first lookup with a public address and every later lookup with
/// loopback, which is exactly the DNS-rebinding shape.
struct RebindingDns {
    calls: Mutex<u32>,
}

impl DnsResolver for RebindingDns {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        let mut calls = self.calls.lock().expect("dns lock");
        *calls += 1;
        if *calls == 1 {
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        } else {
            Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
        }
    }
}

fn http_grant() -> Vec<CapabilityGrant> {
    vec![CapabilityGrant::Http(HttpGrant {
        hosts: vec!["example.invalid".to_owned()],
        methods: vec![HttpMethod::Get],
        allow_plaintext: true,
        max_response_bytes: 1 << 16,
    })]
}

fn ok_response() -> InboundResponse {
    InboundResponse {
        status: 200,
        headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
        body: b"ok".to_vec(),
    }
}

fn redirect_to(location: &str) -> InboundResponse {
    InboundResponse {
        status: 302,
        headers: vec![("location".to_owned(), location.to_owned())],
        body: Vec::new(),
    }
}

fn host_with(
    root: &std::path::Path,
    dns: Arc<dyn DnsResolver>,
    transport: Arc<dyn HttpTransport>,
) -> PluginHost {
    PluginHost::builder()
        .trust_policy(unsigned_core_policy(root))
        .operator_policy(probe_ceiling(http_grant()))
        .services(HostServices::deny_all().with_dns(dns).with_http(transport))
        .build()
        .expect("host")
}

#[test]
fn the_transport_is_handed_the_validated_address_not_just_a_url() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    let transport = ScriptedTransport::new(vec![ok_response()]);
    let dns = Arc::new(StaticDns::new().with(
        "example.invalid",
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    ));

    let mut host = host_with(root.path(), dns, transport.clone());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), ALLOWED);

    let seen = transport.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].url, "https://example.invalid/probe");
    assert_eq!(seen[0].host, "example.invalid");
    assert_eq!(seen[0].port, 443);
    assert_eq!(
        seen[0].addresses,
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        "the transport must connect to the address the validator inspected"
    );
}

#[test]
fn a_name_that_resolves_to_loopback_is_refused_before_any_connection() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    let transport = ScriptedTransport::new(vec![ok_response()]);
    let dns =
        Arc::new(StaticDns::new().with("example.invalid", vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]));

    let mut host = host_with(root.path(), dns, transport.clone());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), DENIED);

    assert!(
        transport.seen().is_empty(),
        "the transport must never see a request whose address failed validation"
    );
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1, "one refusal: {denials:?}");
    assert_eq!(denials[0].capability(), Capability::Http);
    assert_eq!(denials[0].operation(), "send");
    assert_eq!(
        denials[0].to_string(),
        "`send` is outside the granted `http` scope: `example.invalid` resolved to an address \
         that is not reachable: DNS resolution returned a blocked address"
    );
}

#[test]
fn the_metadata_service_is_refused_even_when_the_name_is_allowlisted() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    let transport = ScriptedTransport::new(vec![ok_response()]);
    let dns = Arc::new(StaticDns::new().with(
        "example.invalid",
        vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
    ));

    let mut host = host_with(root.path(), dns, transport.clone());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), DENIED);
    assert!(transport.seen().is_empty());
}

#[test]
fn a_redirect_to_a_private_address_is_refused_by_the_host() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    // The first hop looks perfectly normal; the redirect target is the cloud
    // metadata service.
    let transport = ScriptedTransport::new(vec![
        redirect_to("http://169.254.169.254/latest/meta-data/"),
        ok_response(),
    ]);
    let dns = Arc::new(
        StaticDns::new()
            .with(
                "example.invalid",
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            )
            .with(
                "169.254.169.254",
                vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
            ),
    );

    let mut host = host_with(root.path(), dns, transport.clone());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), DENIED);

    let seen = transport.seen();
    assert_eq!(
        seen.len(),
        1,
        "only the first hop may reach the transport: {seen:?}"
    );
    assert_eq!(seen[0].url, "https://example.invalid/probe");
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1, "one refusal: {denials:?}");
    assert_eq!(denials[0].capability(), Capability::Http);
}

#[test]
fn a_redirect_off_the_granted_host_is_refused_even_when_publicly_routable() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    let transport = ScriptedTransport::new(vec![
        redirect_to("https://exfiltration.invalid/collect"),
        ok_response(),
    ]);
    let dns = Arc::new(
        StaticDns::new()
            .with(
                "example.invalid",
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            )
            .with(
                "exfiltration.invalid",
                vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))],
            ),
    );

    let mut host = host_with(root.path(), dns, transport.clone());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), DENIED);
    assert_eq!(transport.seen().len(), 1, "the second hop never happened");
}

#[test]
fn a_rebinding_resolver_cannot_move_the_target_between_hops() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    // The redirect points back at the same allowlisted name, but the second
    // lookup answers with loopback.
    let transport = ScriptedTransport::new(vec![
        redirect_to("https://example.invalid/second"),
        ok_response(),
    ]);
    let dns = Arc::new(RebindingDns {
        calls: Mutex::new(0),
    });

    let mut host = host_with(root.path(), dns, transport.clone());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), DENIED);

    let seen = transport.seen();
    assert_eq!(seen.len(), 1, "the rebound hop must not be issued");
    assert_eq!(
        seen[0].addresses,
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
    );
}

#[test]
fn a_redirect_back_to_the_same_host_is_followed_once_it_revalidates() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    let transport = ScriptedTransport::new(vec![
        redirect_to("https://example.invalid/second"),
        ok_response(),
    ]);
    let dns = Arc::new(StaticDns::new().with(
        "example.invalid",
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    ));

    let mut host = host_with(root.path(), dns, transport.clone());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), ALLOWED);

    let urls: Vec<String> = transport
        .seen()
        .into_iter()
        .map(|request| request.url)
        .collect();
    assert_eq!(
        urls,
        vec![
            "https://example.invalid/probe".to_owned(),
            "https://example.invalid/second".to_owned(),
        ],
        "the host, not the transport, followed the redirect"
    );
    assert!(host.denials(&id).is_empty());
}

#[test]
fn a_redirect_loop_is_cut_off_by_the_hop_budget() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    let transport = ScriptedTransport::new(vec![
        redirect_to("https://example.invalid/1"),
        redirect_to("https://example.invalid/2"),
        redirect_to("https://example.invalid/3"),
        redirect_to("https://example.invalid/4"),
        redirect_to("https://example.invalid/5"),
    ]);
    let dns = Arc::new(StaticDns::new().with(
        "example.invalid",
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
    ));

    let mut host = host_with(root.path(), dns, transport.clone());
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), DENIED);

    // The original request plus three redirects, then the budget stops it.
    assert_eq!(transport.seen().len(), 4);
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1, "one refusal: {denials:?}");
    assert_eq!(
        denials[0].to_string(),
        "`send` exceeded the `http` quota: more than 3 redirects"
    );
}

#[test]
fn the_default_resolver_answers_nothing_at_all() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", http_grant());
    let transport = ScriptedTransport::new(vec![ok_response()]);

    // No `.with_dns(..)`: the deny-all default must not fall back to the
    // operating system resolver.
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(http_grant()))
        .services(HostServices::deny_all().with_http(transport.clone()))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("send"), DENIED);
    assert!(transport.seen().is_empty());
}

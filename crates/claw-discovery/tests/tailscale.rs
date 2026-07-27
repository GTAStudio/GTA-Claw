//! Tailscale Serve and Funnel authorisation oracles.
//!
//! Each denial below is a condition that a faithful `LocalAPI` client will happily
//! publish through if nothing checks it first, and each one has a distinct
//! failure mode in production: a Funnel on a port Tailscale does not terminate
//! looks published and silently never receives traffic; a Funnel without the
//! node attribute is rejected by the coordination server after the local serve
//! config has already been rewritten; a Funnel on a tailnet without HTTPS has no
//! certificate to present.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use claw_discovery::tailscale_policy::{
    DenialCause, ExposureMode, ExposureRequest, FUNNEL_NODE_ATTRIBUTE, FUNNEL_PUBLIC_PORTS,
    NodePolicy, TailnetPolicy,
};

const NODE: &str = "studio.tail.example";
const PLAIN_NODE: &str = "plain.tail.example";

const fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn policy() -> TailnetPolicy {
    let mut nodes = BTreeMap::new();
    nodes.insert(
        NODE.to_owned(),
        NodePolicy::with_attributes([FUNNEL_NODE_ATTRIBUTE]),
    );
    nodes.insert(PLAIN_NODE.to_owned(), NodePolicy::default());
    nodes.insert(
        "expired.tail.example".to_owned(),
        NodePolicy {
            key_expired: true,
            ..NodePolicy::with_attributes([FUNNEL_NODE_ATTRIBUTE])
        },
    );
    nodes.insert(
        "pending.tail.example".to_owned(),
        NodePolicy {
            awaiting_approval: true,
            ..NodePolicy::with_attributes([FUNNEL_NODE_ATTRIBUTE])
        },
    );
    TailnetPolicy {
        https_enabled: true,
        nodes,
    }
}

fn funnel(port: u16) -> ExposureRequest {
    ExposureRequest {
        node: NODE.to_owned(),
        mode: ExposureMode::Funnel,
        public_port: port,
        backend: loopback(4711),
        path: "/".to_owned(),
    }
}

#[test]
fn authorised_funnel_and_serve_exposures_produce_the_pinned_plan() {
    let policy = policy();

    let plan = policy.evaluate(&funnel(443)).expect("funnel on 443");
    assert_eq!(plan.host_port, "studio.tail.example:443");
    assert_eq!(plan.mode, ExposureMode::Funnel);
    assert_eq!(plan.backend, loopback(4711));
    assert_eq!(plan.path, "/");
    assert!(
        plan.allow_funnel,
        "a funnel exposure must set AllowFunnel for its host:port"
    );

    // Serve is tailnet-internal, so it is not bound to the Funnel port list and
    // must not set AllowFunnel.
    let serve = ExposureRequest {
        mode: ExposureMode::Serve,
        public_port: 9443,
        path: "/gateway".to_owned(),
        ..funnel(443)
    };
    let plan = policy.evaluate(&serve).expect("serve on 9443");
    assert_eq!(plan.host_port, "studio.tail.example:9443");
    assert_eq!(plan.path, "/gateway");
    assert!(
        !plan.allow_funnel,
        "a serve exposure must never set AllowFunnel"
    );

    // A node with no attributes at all may still serve inside the tailnet.
    let plain_serve = ExposureRequest {
        node: PLAIN_NODE.to_owned(),
        ..serve
    };
    assert_eq!(
        policy
            .evaluate(&plain_serve)
            .expect("plain serve")
            .host_port,
        "plain.tail.example:9443"
    );
}

#[test]
fn funnel_public_port_outside_the_terminated_set_is_refused() {
    let policy = policy();

    for port in FUNNEL_PUBLIC_PORTS {
        assert!(
            policy.evaluate(&funnel(port)).is_ok(),
            "port {port} is terminated by Funnel and must be allowed"
        );
    }
    // 9443 is the trap: it is a perfectly ordinary HTTPS-alternative port, it is
    // accepted by Serve, and Funnel does not terminate it.
    for port in [80, 8080, 8444, 9443, 10001, 65535] {
        let denial = policy
            .evaluate(&funnel(port))
            .expect_err("funnel must refuse a port it cannot terminate");
        assert_eq!(denial.cause, DenialCause::PublicPortNotAllowed);
        assert!(
            denial.detail.contains(&port.to_string()),
            "the refusal must name the offending port, got {}",
            denial.detail
        );
    }
    // Port zero is refused for both modes, because it is not routable.
    let serve_zero = ExposureRequest {
        mode: ExposureMode::Serve,
        public_port: 0,
        ..funnel(443)
    };
    assert_eq!(
        policy.evaluate(&serve_zero).expect_err("port 0").cause,
        DenialCause::PublicPortNotAllowed
    );
}

#[test]
fn funnel_without_the_node_attribute_is_refused() {
    let policy = policy();
    let request = ExposureRequest {
        node: PLAIN_NODE.to_owned(),
        ..funnel(443)
    };

    let denial = policy
        .evaluate(&request)
        .expect_err("a node without the funnel attribute must be refused");
    assert_eq!(denial.cause, DenialCause::MissingFunnelAttribute);
    assert!(
        denial.detail.contains(FUNNEL_NODE_ATTRIBUTE),
        "the refusal must name the missing attribute, got {}",
        denial.detail
    );

    // Granting some unrelated attribute must not satisfy the check.
    let mut widened = policy;
    widened.nodes.insert(
        PLAIN_NODE.to_owned(),
        NodePolicy::with_attributes(["nextdns", "funnel-ish"]),
    );
    assert_eq!(
        widened
            .evaluate(&request)
            .expect_err("near-miss attribute")
            .cause,
        DenialCause::MissingFunnelAttribute
    );
}

#[test]
fn funnel_on_a_tailnet_without_https_is_refused() {
    let mut policy = policy();
    policy.https_enabled = false;

    let denial = policy
        .evaluate(&funnel(443))
        .expect_err("funnel is HTTPS only");
    assert_eq!(denial.cause, DenialCause::HttpsDisabled);
    assert!(denial.detail.contains("HTTPS"), "got {}", denial.detail);

    // Serve is unaffected, so disabling HTTPS must not break tailnet-internal
    // exposure.
    let serve = ExposureRequest {
        mode: ExposureMode::Serve,
        ..funnel(443)
    };
    assert!(policy.evaluate(&serve).is_ok());
}

#[test]
fn unauthorised_nodes_are_refused_before_any_exposure_is_planned() {
    let policy = policy();

    let unknown = ExposureRequest {
        node: "ghost.tail.example".to_owned(),
        ..funnel(443)
    };
    assert_eq!(
        policy.evaluate(&unknown).expect_err("unknown node").cause,
        DenialCause::UnknownNode
    );

    let expired = ExposureRequest {
        node: "expired.tail.example".to_owned(),
        ..funnel(443)
    };
    assert_eq!(
        policy.evaluate(&expired).expect_err("expired key").cause,
        DenialCause::NodeKeyExpired
    );

    let pending = ExposureRequest {
        node: "pending.tail.example".to_owned(),
        ..funnel(443)
    };
    assert_eq!(
        policy.evaluate(&pending).expect_err("pending auth").cause,
        DenialCause::MachineAuthPending
    );

    // Node authorisation is checked before the port and attribute rules, so an
    // expired node is refused for expiry even when its request is also invalid
    // in other ways.
    let doubly_bad = ExposureRequest {
        node: "expired.tail.example".to_owned(),
        ..funnel(9443)
    };
    assert_eq!(
        policy.evaluate(&doubly_bad).expect_err("expired").cause,
        DenialCause::NodeKeyExpired
    );
}

#[test]
fn a_non_loopback_backend_is_refused_for_serve_and_funnel_alike() {
    let policy = policy();

    for backend in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 4711),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 4711),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4711),
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            4711,
        ),
    ] {
        for mode in [ExposureMode::Serve, ExposureMode::Funnel] {
            let request = ExposureRequest {
                mode,
                backend,
                ..funnel(443)
            };
            let denial = policy
                .evaluate(&request)
                .expect_err("republishing a third party must be refused");
            assert_eq!(denial.cause, DenialCause::BackendNotLoopback);
            assert!(
                denial.detail.contains(&backend.to_string()),
                "got {}",
                denial.detail
            );
        }
    }

    // IPv6 loopback is loopback.
    let v6 = ExposureRequest {
        backend: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4711),
        ..funnel(443)
    };
    assert!(policy.evaluate(&v6).is_ok());
}

#[test]
fn exposure_paths_must_be_absolute_and_non_traversing() {
    let policy = policy();

    for path in ["", "gateway", "./gateway", "../etc"] {
        let request = ExposureRequest {
            path: path.to_owned(),
            ..funnel(443)
        };
        assert_eq!(
            policy.evaluate(&request).expect_err("relative path").cause,
            DenialCause::InvalidPath,
            "path {path:?} must be refused"
        );
    }
    let traversing = ExposureRequest {
        path: "/gateway/../../secret".to_owned(),
        ..funnel(443)
    };
    assert_eq!(
        policy
            .evaluate(&traversing)
            .expect_err("traversing path")
            .cause,
        DenialCause::InvalidPath
    );

    assert!(
        policy
            .evaluate(&ExposureRequest {
                path: "/gateway/v1".to_owned(),
                ..funnel(443)
            })
            .is_ok()
    );
}

#[test]
fn every_denial_names_its_cause_in_the_operator_message() {
    let policy = policy();
    let denial = policy.evaluate(&funnel(9443)).expect_err("bad port");

    // The Display form is what reaches a log, so it must carry both halves.
    let rendered = denial.to_string();
    assert!(
        rendered.starts_with("public-port-not-allowed:"),
        "got {rendered}"
    );
    assert!(rendered.contains("9443"), "got {rendered}");
    assert_eq!(DenialCause::HttpsDisabled.to_string(), "https-disabled");
    assert_eq!(ExposureMode::Funnel.to_string(), "funnel");
    assert_eq!(ExposureMode::Serve.to_string(), "serve");
}

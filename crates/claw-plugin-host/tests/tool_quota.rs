//! Tool registrations are quota-bounded and are withdrawn with the instance.
//!
//! Every registration here comes from a real Component Model guest calling
//! `host-tools.register` through Wasmtime, so the ledger the host keeps is the
//! same one the guest actually populated.

mod support;

use std::sync::Arc;

use claw_plugin_api::capability::{CapabilityGrant, EventKind, EventsGrant, ToolsGrant};
use claw_plugin_host::services::{HostServices, RecordingSink};
use claw_plugin_host::{LifecycleState, PluginHost, TerminationCause};
use support::{install_variant, probe_ceiling, unsigned_core_policy};

/// `permission-denied` is the second `error-code` case, so the guest sees `e1`.
const DENIED: &str = "e1";
const ALLOWED: &str = "o0";

fn tools_grant(max_tools: u32) -> Vec<CapabilityGrant> {
    vec![CapabilityGrant::Tools(ToolsGrant {
        max_tools,
        max_schema_bytes: 4096,
    })]
}

#[test]
fn a_plugin_cannot_register_more_tools_than_it_was_granted() {
    let root = support::tempdir();
    let component = support::probe_component_registering_tools(3);
    let grants = tools_grant(2);
    let dir = install_variant(root.path(), "probe", &component, grants.clone());

    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(grants))
        .services(HostServices::deny_all().with_tools(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    // The guest registers `ta`, `tb`, `tc`; the third exceeds the quota, and
    // the answer carries the code of the last call it made.
    assert_eq!(
        host.invoke_tool(&id, "z", "{}").expect("register"),
        DENIED,
        "the third distinct tool must be refused"
    );
    assert_eq!(
        host.registered_tools(&id),
        Some(vec!["ta".to_owned(), "tb".to_owned()]),
        "only the tools inside the quota were kept"
    );
    let names: Vec<String> = recorder
        .tools()
        .into_iter()
        .map(|registration| registration.name)
        .collect();
    assert_eq!(names, vec!["ta".to_owned(), "tb".to_owned()]);

    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1, "one refusal: {denials:?}");
    assert_eq!(denials[0].operation(), "register");
    assert_eq!(
        denials[0].to_string(),
        "`register` exceeded the `tools` quota: this plugin already holds 2 of its 2 granted tools"
    );
}

#[test]
fn re_registering_the_same_name_does_not_consume_more_quota() {
    let root = support::tempdir();
    // The stock probe registers the single name `probe` on every `k` call.
    let grants = tools_grant(1);
    let dir = support::install_probe(root.path(), "probe", grants.clone());

    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(grants))
        .services(HostServices::deny_all().with_tools(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    for _ in 0..4 {
        assert_eq!(host.invoke_tool(&id, "k", "{}").expect("register"), ALLOWED);
    }
    assert_eq!(host.registered_tools(&id), Some(vec!["probe".to_owned()]));
    assert_eq!(
        recorder.tools().len(),
        1,
        "the sink holds one entry per distinct name, not one per call"
    );
    assert!(host.denials(&id).is_empty());
}

#[test]
fn deactivating_withdraws_every_tool_the_plugin_advertised() {
    let root = support::tempdir();
    let grants = tools_grant(4);
    let dir = support::install_probe(root.path(), "probe", grants.clone());

    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(grants))
        .services(HostServices::deny_all().with_tools(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "k", "{}").expect("register"), ALLOWED);
    assert_eq!(recorder.tools().len(), 1);

    host.deactivate(&id).expect("deactivate");
    assert_eq!(host.state(&id), Some(LifecycleState::Inactive));
    assert!(
        recorder.tools().is_empty(),
        "a deactivated plugin must not stay advertised"
    );
    assert_eq!(host.registered_tools(&id), Some(Vec::new()));

    // Reactivating starts from an empty ledger, so the quota is not leaked.
    host.activate(&id).expect("reactivate");
    assert_eq!(host.registered_tools(&id), Some(Vec::new()));
    assert_eq!(host.invoke_tool(&id, "k", "{}").expect("register"), ALLOWED);
    assert_eq!(recorder.tools().len(), 1);
}

#[test]
fn a_trapping_plugin_loses_its_tools_immediately() {
    let root = support::tempdir();
    let mut grants = tools_grant(4);
    grants.push(CapabilityGrant::Events(EventsGrant {
        emit_kinds: std::iter::once(EventKind::Heartbeat).collect(),
        max_payload_bytes: 1024,
    }));
    let dir = support::install_probe(root.path(), "probe", grants.clone());

    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(grants))
        .services(
            HostServices::deny_all()
                .with_tools(Arc::new(recorder.clone()))
                .with_events(Arc::new(recorder.clone())),
        )
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "k", "{}").expect("register"), ALLOWED);
    assert_eq!(recorder.tools().len(), 1);

    // `t` makes the guest trap.
    host.invoke_tool(&id, "t", "{}")
        .expect_err("the guest must trap");
    assert_eq!(
        host.state(&id),
        Some(LifecycleState::Faulted(TerminationCause::Trap))
    );
    assert!(
        recorder.tools().is_empty(),
        "a faulted plugin must not stay advertised"
    );
    assert_eq!(
        host.registered_tools(&id),
        None,
        "the faulted instance is gone, so it holds no ledger at all"
    );
}

#[test]
fn unloading_withdraws_every_tool_the_plugin_advertised() {
    let root = support::tempdir();
    let grants = tools_grant(4);
    let dir = support::install_probe(root.path(), "probe", grants.clone());

    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(grants))
        .services(HostServices::deny_all().with_tools(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "k", "{}").expect("register"), ALLOWED);
    assert_eq!(recorder.tools().len(), 1);

    host.unload(&id).expect("unload");
    assert_eq!(host.state(&id), None);
    assert!(
        recorder.tools().is_empty(),
        "an unloaded plugin must not stay advertised"
    );
    assert_eq!(host.registered_tools(&id), None);
}

#[test]
fn dropping_a_host_withdraws_tools_without_running_guest_code() {
    let root = support::tempdir();
    let grants = tools_grant(4);
    let dir = support::install_probe(root.path(), "probe", grants.clone());
    let recorder = RecordingSink::new();

    {
        let mut host = PluginHost::builder()
            .trust_policy(unsigned_core_policy(root.path()))
            .operator_policy(probe_ceiling(grants))
            .services(HostServices::deny_all().with_tools(Arc::new(recorder.clone())))
            .build()
            .expect("host");
        let id = host.load(&dir).expect("load");
        host.activate(&id).expect("activate");
        assert_eq!(host.invoke_tool(&id, "k", "{}").expect("register"), ALLOWED);
        assert_eq!(recorder.tools().len(), 1);
    }

    assert!(
        recorder.tools().is_empty(),
        "Drop must not leave externally registered plugin tools behind"
    );
}

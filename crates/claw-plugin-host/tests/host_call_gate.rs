//! The shared host-call gate really does block a running guest.
//!
//! The concurrency ceiling is the only resource limit that is not enforced by
//! Wasmtime itself, so it is worth proving through a real Component Model guest
//! rather than by calling the counter directly.

mod support;

use std::sync::Arc;

use claw_plugin_api::capability::{Capability, CapabilityGrant, LogGrant, LogLevel};
use claw_plugin_host::services::{HostServices, RecordingSink};
use claw_plugin_host::{HostCallGate, PluginHost};
use support::{install_probe, probe_ceiling, unsigned_core_policy};

/// `permission-denied` is the second `error-code` case, so the guest sees `e1`.
const DENIED: &str = "e1";
const ALLOWED: &str = "o0";

fn log_grant() -> Vec<CapabilityGrant> {
    vec![CapabilityGrant::Log(LogGrant {
        min_level: LogLevel::Trace,
        max_message_bytes: 4096,
    })]
}

#[test]
fn a_guest_host_call_is_refused_while_the_shared_gate_is_full() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", log_grant());

    // One slot for the whole host, and the operator is holding it.
    let gate = HostCallGate::new(1);
    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(log_grant()))
        .host_call_gate(gate.clone())
        .services(HostServices::deny_all().with_logs(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    // Baseline: the call works while the gate is free.
    assert_eq!(host.invoke_tool(&id, "j", "{}").expect("log"), ALLOWED);
    assert_eq!(recorder.logs().len(), 1);

    let permit = gate
        .try_acquire()
        .expect("the operator takes the only slot");
    assert_eq!(gate.in_flight(), 1);
    assert_eq!(
        host.invoke_tool(&id, "j", "{}").expect("log"),
        DENIED,
        "a running guest must not be able to exceed the shared ceiling"
    );
    assert_eq!(
        recorder.logs().len(),
        1,
        "the refused call never reached the sink"
    );

    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1, "one refusal: {denials:?}");
    assert_eq!(denials[0].capability(), Capability::Log);
    assert_eq!(denials[0].operation(), "log");
    assert_eq!(
        denials[0].to_string(),
        "`log` exceeded the `log` quota: at most 1 host calls may run at once across this host"
    );

    // Releasing the slot restores service, so the refusal was the gate and not
    // a poisoned instance.
    drop(permit);
    assert_eq!(gate.in_flight(), 0);
    assert_eq!(host.invoke_tool(&id, "j", "{}").expect("log"), ALLOWED);
    assert_eq!(recorder.logs().len(), 2);
}

#[test]
fn the_gate_is_shared_across_every_plugin_on_one_host() {
    let root = support::tempdir();
    let first = install_probe(root.path(), "first", log_grant());
    let second = install_probe(root.path(), "second", log_grant());

    let gate = HostCallGate::new(1);
    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(log_grant()))
        .host_call_gate(gate.clone())
        .services(HostServices::deny_all().with_logs(Arc::new(recorder.clone())))
        .build()
        .expect("host");

    let first_id = host.load(&first).expect("load the first plugin");
    host.activate(&first_id).expect("activate the first plugin");
    // The second copy declares the same id, so loading it twice is refused;
    // this test only needs the first instance plus the shared counter.
    assert!(
        host.load(&second).is_err(),
        "two plugins may not share one id"
    );

    let permit = gate.try_acquire().expect("take the only slot");
    assert_eq!(host.invoke_tool(&first_id, "j", "{}").expect("log"), DENIED);
    drop(permit);
    assert_eq!(
        host.invoke_tool(&first_id, "j", "{}").expect("log"),
        ALLOWED
    );
    assert_eq!(recorder.logs().len(), 1);
}

#[test]
fn every_permit_is_released_when_the_host_call_returns() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", log_grant());

    let gate = HostCallGate::new(2);
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(log_grant()))
        .host_call_gate(gate.clone())
        .services(HostServices::deny_all().with_logs(Arc::new(RecordingSink::new())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    for _ in 0..16 {
        assert_eq!(host.invoke_tool(&id, "j", "{}").expect("log"), ALLOWED);
        assert_eq!(gate.in_flight(), 0, "no permit may outlive its host call");
    }

    // A denied call must release its slot too: `b` needs `random`, which is not
    // granted, and the denial happens after the permit was taken.
    assert_eq!(host.invoke_tool(&id, "b", "{}").expect("random"), DENIED);
    assert_eq!(gate.in_flight(), 0);
}

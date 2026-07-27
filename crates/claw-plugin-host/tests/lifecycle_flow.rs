//! The full lifecycle, driven against a real component.

mod support;

use claw_plugin_api::capability::EventKind;
use claw_plugin_host::services::HostEvent;
use claw_plugin_host::{
    EventOutcome, GuestFailure, HostError, LifecycleState, PluginHost, TerminationCause,
};
use support::{PROBE_ID, PROBE_VERSION, install_probe, install_probe_named, unsigned_core_policy};

fn event(kind: EventKind, sequence: u64) -> HostEvent {
    HostEvent {
        kind,
        sequence,
        source: "test".to_owned(),
        payload: "{}".to_owned(),
    }
}

#[test]
fn the_states_follow_discover_load_activate_deactivate_unload() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from(&dir))
        .build()
        .expect("host");

    let found = host.discover();
    assert_eq!(found.len(), 1);
    let directory = found[0].directory.clone();
    let discovered = found[0].manifest.as_ref().expect("a valid manifest");
    assert_eq!(discovered.id, PROBE_ID);
    assert_eq!(discovered.version, PROBE_VERSION);
    assert_eq!(host.state(PROBE_ID), None, "discovery must not load");

    let id = host.load(&directory).expect("load");
    assert_eq!(host.state(&id), Some(LifecycleState::Loaded));
    assert_eq!(
        host.component_path(&id).expect("path"),
        std::fs::canonicalize(directory.join("component.wasm")).expect("canonicalize")
    );
    assert_eq!(
        host.component_digest(&id).expect("digest"),
        host.manifest(&id).expect("manifest").component.sha256
    );

    host.activate(&id).expect("activate");
    assert_eq!(host.state(&id), Some(LifecycleState::Active));

    host.deactivate(&id).expect("deactivate");
    assert_eq!(host.state(&id), Some(LifecycleState::Inactive));

    host.activate(&id).expect("reactivate");
    assert_eq!(host.state(&id), Some(LifecycleState::Active));

    host.unload(&id).expect("unload");
    assert_eq!(host.state(&id), None);
    assert!(host.loaded_ids().is_empty());
}

#[test]
fn operations_are_refused_in_the_wrong_state() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from(&dir))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");

    // Loaded, not active.
    match host
        .invoke_tool(&id, "x", "{}")
        .expect_err("a loaded plugin is not runnable yet")
    {
        HostError::WrongState {
            id: reported,
            actual,
            expected,
        } => {
            assert_eq!(reported, PROBE_ID);
            assert_eq!(actual, "loaded");
            assert_eq!(expected, "invoke-tool");
        }
        other => panic!("expected a wrong-state error, got {other}"),
    }

    match host
        .deactivate(&id)
        .expect_err("a loaded plugin cannot be deactivated")
    {
        HostError::WrongState {
            actual, expected, ..
        } => {
            assert_eq!(actual, "loaded");
            assert_eq!(expected, "deactivate");
        }
        other => panic!("expected a wrong-state error, got {other}"),
    }

    host.activate(&id).expect("activate");
    match host
        .activate(&id)
        .expect_err("an active plugin cannot be activated again")
    {
        HostError::WrongState {
            actual, expected, ..
        } => {
            assert_eq!(actual, "active");
            assert_eq!(expected, "activate");
        }
        other => panic!("expected a wrong-state error, got {other}"),
    }
}

#[test]
fn an_unknown_plugin_is_reported_by_name() {
    let mut host = PluginHost::builder().build().expect("host");
    for error in [
        host.activate("nobody").expect_err("activate"),
        host.deactivate("nobody").expect_err("deactivate"),
        host.unload("nobody").expect_err("unload"),
        host.reload("nobody").expect_err("reload"),
        host.invoke_tool("nobody", "x", "{}").expect_err("invoke"),
    ] {
        match error {
            HostError::UnknownPlugin(id) => assert_eq!(id, "nobody"),
            other => panic!("expected an unknown plugin, got {other}"),
        }
    }
    assert_eq!(host.state("nobody"), None);
    assert!(host.manifest("nobody").is_none());
    assert!(host.component_digest("nobody").is_none());
    assert!(host.component_path("nobody").is_none());
    assert!(host.resource_usage("nobody").is_none());
    assert!(host.denials("nobody").is_empty());
}

#[test]
fn events_reach_the_guest_and_its_answer_comes_back() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from(&dir))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    // The fixture only claims heartbeats.
    assert_eq!(
        host.handle_event(&id, &event(EventKind::Heartbeat, 7))
            .expect("heartbeat"),
        EventOutcome {
            handled: true,
            note: Some("ok".to_owned()),
        }
    );
    for kind in [
        EventKind::SessionStarted,
        EventKind::SessionEnded,
        EventKind::Message,
        EventKind::ToolResult,
        EventKind::ConfigChanged,
        EventKind::Shutdown,
    ] {
        assert_eq!(
            host.handle_event(&id, &event(kind, 1)).expect("event"),
            EventOutcome {
                handled: false,
                note: None,
            },
            "{kind:?} is not one the fixture handles"
        );
    }
}

#[test]
fn a_guest_error_is_surfaced_without_faulting_the_plugin() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from(&dir))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    match host
        .invoke_tool(&id, "zzz", "{}")
        .expect_err("the fixture does not know this tool")
    {
        HostError::Guest(GuestFailure { code, message }) => {
            assert_eq!(code, "invalid-input");
            assert_eq!(message, "unknown probe");
        }
        other => panic!("expected a guest error, got {other}"),
    }

    assert_eq!(
        host.state(&id),
        Some(LifecycleState::Active),
        "a well-behaved error must not fault the plugin"
    );
    assert_eq!(
        host.invoke_tool(&id, "x", "{}").expect("still usable"),
        "ok"
    );
}

#[test]
fn reload_picks_up_new_bytes_from_disk() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from(&dir))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    let first_digest = host.component_digest(&id).expect("digest").to_owned();

    // Fault it, then reload from the same directory.
    let error = host.invoke_tool(&id, "t", "{}").expect_err("trap");
    assert_eq!(error.termination(), Some(TerminationCause::Trap));

    let reloaded = host.reload(&id).expect("reload");
    assert_eq!(reloaded, PROBE_ID);
    assert_eq!(host.state(&id), Some(LifecycleState::Loaded));
    assert_eq!(
        host.component_digest(&id).expect("digest"),
        first_digest,
        "the bytes on disk did not change, so neither did the digest"
    );

    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "x", "{}").expect("call"), "ok");
    assert!(
        host.denials(&id).is_empty(),
        "a reload clears the previous instance's audit log"
    );
}

#[test]
fn unloading_forgets_everything_about_a_plugin() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from(&dir))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "a", "{}").expect("clock"), "e1");
    assert_eq!(host.denials(&id).len(), 1);

    host.unload(&id).expect("unload");
    assert!(host.denials(&id).is_empty());
    assert!(host.manifest(&id).is_none());
    assert_eq!(host.state(&id), None);

    // And the same id can be loaded again from scratch.
    let again = host.load(&dir).expect("load again");
    assert_eq!(again, PROBE_ID);
    assert_eq!(host.state(&again), Some(LifecycleState::Loaded));
}

#[test]
fn shutdown_disposes_every_plugin_in_reverse_activation_order() {
    let root = support::tempdir();
    let first = install_probe(root.path(), "first", Vec::new());
    let other_id = "gta-claw-fixture-other";
    let second = install_probe_named(root.path(), "second", other_id, Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(support::ceiling_from_all(&[&first, &second]))
        .build()
        .expect("host");
    let first_id = host.load(&first).expect("load first");
    let second_id = host.load(&second).expect("load second");
    host.activate(&first_id).expect("activate first");
    host.activate(&second_id).expect("activate second");

    let report = host.shutdown();
    assert!(report.is_clean());
    let disposed: Vec<&str> = report
        .outcomes()
        .iter()
        .map(|outcome| outcome.plugin_id.as_str())
        .collect();
    assert_eq!(disposed, [other_id, PROBE_ID]);
    assert!(host.loaded_ids().is_empty());
}

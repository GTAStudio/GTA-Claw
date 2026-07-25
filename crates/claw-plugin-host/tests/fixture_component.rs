//! The fixture component must really assemble, load, describe itself and run.

mod support;

use claw_plugin_host::{LifecycleState, PluginHost};
use support::{PROBE_ID, PROBE_VERSION, install_probe, probe_component, unsigned_core_policy};

#[test]
fn the_probe_fixture_assembles_into_a_component() {
    let bytes = probe_component();
    assert_eq!(
        &bytes[..8],
        &[0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00],
        "the fixture must be a component binary, not a core module"
    );
}

#[test]
fn the_probe_fixture_loads_activates_and_answers() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .build()
        .expect("host");

    let id = host.load(&dir).expect("load the probe");
    assert_eq!(id, PROBE_ID);
    assert_eq!(host.state(&id), Some(LifecycleState::Loaded));
    assert_eq!(host.manifest(&id).expect("manifest").version, PROBE_VERSION);

    host.activate(&id).expect("activate");
    assert_eq!(host.state(&id), Some(LifecycleState::Active));

    let answer = host.invoke_tool(&id, "x", "{}").expect("invoke");
    assert_eq!(answer, "ok");

    host.deactivate(&id).expect("deactivate");
    assert_eq!(host.state(&id), Some(LifecycleState::Inactive));

    host.unload(&id).expect("unload");
    assert_eq!(host.state(&id), None);
}

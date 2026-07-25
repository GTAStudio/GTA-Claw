//! Capabilities exist only inside the activation window.
//!
//! Both tests drive a real Component Model guest that calls a host import from
//! outside that window: once from `describe` (before the host has confirmed the
//! component's identity) and once from `deactivate` (after the plugin has been
//! told to stop).

mod support;

use std::sync::Arc;

use claw_plugin_api::capability::{
    Capability, CapabilityGrant, DenialReason, EventKind, EventsGrant, FilesystemGrant, LogGrant,
    LogLevel,
};
use claw_plugin_host::services::{HostServices, RecordingSink};
use claw_plugin_host::state::LifecyclePhase;
use claw_plugin_host::{LifecycleState, PluginHost};
use support::{install_variant, probe_ceiling, unsigned_core_policy};

#[test]
fn a_host_call_from_describe_is_refused_even_though_the_grant_exists() {
    let root = support::tempdir();
    let secret = root.path().join("probe.txt");
    std::fs::write(&secret, b"exfiltrate me").expect("write the secret");

    let grants = vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
        roots: vec![root.path().to_path_buf()],
        max_file_bytes: 1 << 16,
    })];
    let component = support::probe_component_reading_during_describe();
    let dir = install_variant(root.path(), "probe", &component, grants.clone());

    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(grants))
        .build()
        .expect("host");

    // The load itself still succeeds: the guest ignores the error code.
    let id = host.load(&dir).expect("load");
    assert_eq!(host.state(&id), Some(LifecycleState::Loaded));

    let denials = host.denials(&id);
    assert_eq!(
        denials.len(),
        1,
        "exactly the one describe-time call was audited: {denials:?}"
    );
    assert_eq!(denials[0].capability(), Capability::FilesystemRead);
    assert_eq!(denials[0].operation(), "read-file");
    assert_eq!(
        denials[0].reason(),
        &DenialReason::WrongPhase(
            "capability `filesystem-read` is not reachable while this plugin is `starting`"
                .to_owned()
        ),
        "the refusal must be the lifecycle phase, not a missing grant"
    );

    // The same call from inside the window succeeds, so the refusal above was
    // the phase and not a missing grant.
    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "c", "{}").expect("read"), "o0");
}

#[test]
fn deactivate_keeps_cleanup_logging_and_loses_everything_else() {
    let root = support::tempdir();
    let grants = vec![
        CapabilityGrant::Log(LogGrant {
            min_level: LogLevel::Trace,
            max_message_bytes: 4096,
        }),
        CapabilityGrant::Events(EventsGrant {
            emit_kinds: [EventKind::Heartbeat].into_iter().collect(),
            max_payload_bytes: 4096,
        }),
    ];
    let component = support::probe_component_calling_during_deactivate();
    let dir = install_variant(root.path(), "probe", &component, grants.clone());

    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(probe_ceiling(grants))
        .services(
            HostServices::deny_all()
                .with_logs(Arc::new(recorder.clone()))
                .with_events(Arc::new(recorder.clone())),
        )
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    // Both work while the plugin is active.
    assert_eq!(host.invoke_tool(&id, "j", "{}").expect("log"), "o0");
    assert_eq!(host.invoke_tool(&id, "l", "{}").expect("emit"), "o0");
    assert_eq!(recorder.events().len(), 1);
    let logs_before = recorder.logs().len();

    host.deactivate(&id).expect("deactivate");

    // The cleanup log landed; the event did not.
    assert_eq!(
        recorder.logs().len(),
        logs_before + 1,
        "logging is in the cleanup set"
    );
    assert_eq!(
        recorder.events().len(),
        1,
        "emitting an event during deactivation must be refused"
    );

    let denials = host.denials(&id);
    let events_denials: Vec<_> = denials
        .iter()
        .filter(|denial| denial.capability() == Capability::Events)
        .collect();
    assert_eq!(events_denials.len(), 1, "one refusal: {denials:?}");
    assert_eq!(events_denials[0].operation(), "emit");
    assert_eq!(
        events_denials[0].reason(),
        &DenialReason::WrongPhase(
            "capability `events` is not reachable while this plugin is `deactivating`".to_owned()
        )
    );
}

#[test]
fn the_cleanup_set_is_exactly_logging_and_the_private_store() {
    // A change to the cleanup set is a security decision and must be a
    // deliberate edit here, not a silent widening.
    assert_eq!(
        LifecyclePhase::CLEANUP,
        [Capability::Log, Capability::Store]
    );
    for capability in Capability::ALL {
        assert!(
            LifecyclePhase::Active.permits(capability),
            "the active window permits everything that was granted"
        );
        assert!(
            !LifecyclePhase::Starting.permits(capability),
            "nothing is reachable before activation"
        );
        assert!(
            !LifecyclePhase::Loaded.permits(capability),
            "nothing is reachable between load and activate"
        );
        assert!(
            !LifecyclePhase::Inactive.permits(capability),
            "nothing is reachable after deactivation"
        );
        assert_eq!(
            LifecyclePhase::Deactivating.permits(capability),
            LifecyclePhase::CLEANUP.contains(&capability),
            "{capability:?} disagrees with the cleanup set"
        );
    }
}

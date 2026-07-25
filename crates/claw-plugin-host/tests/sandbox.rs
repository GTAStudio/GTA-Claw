//! Capability enforcement, exercised by a real WebAssembly guest.
//!
//! Every test here loads the probe component, activates it and asks it to make
//! a host call. The guest reports what the host answered: `o0` when the call
//! returned successfully and `e<n>` when the host returned an error whose code
//! discriminant is `n` (`permission-denied` is `1`). Nothing is mocked; the
//! bytes really run inside Wasmtime.

mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use claw_plugin_api::capability::{
    Capability, CapabilityGrant, ClockGrant, ConfigGrant, ConfigScope, DenialReason, EventKind,
    EventsGrant, FilesystemGrant, HttpGrant, HttpMethod, LogGrant, LogLevel, RandomGrant,
    StoreGrant, ToolsGrant,
};
use claw_plugin_host::services::{
    HostServices, InMemoryConfig, InMemoryStore, RecordingSink, StoreBackend,
};
use claw_plugin_host::{HostError, PluginHost, TerminationCause, ViolationPolicy};
use support::{PROBE_ID, install_probe, install_probe_named, unsigned_core_policy};

/// `permission-denied` is the second `error-code` case, so the guest sees `e1`.
const DENIED: &str = "e1";
/// The host call returned `ok`.
const ALLOWED: &str = "o0";

/// Every probe letter, with the capability and operation the host must demand.
const PROBES: &[(&str, Capability, &str)] = &[
    ("a", Capability::Clock, "now-ms"),
    ("b", Capability::Random, "get-bytes"),
    ("c", Capability::FilesystemRead, "read-file"),
    ("d", Capability::FilesystemWrite, "write-file"),
    ("e", Capability::FilesystemRead, "list-dir"),
    ("f", Capability::Http, "send"),
    ("g", Capability::Store, "get"),
    ("h", Capability::Store, "set"),
    ("i", Capability::Config, "get"),
    ("j", Capability::Log, "log"),
    ("k", Capability::Tools, "register"),
    ("l", Capability::Events, "emit"),
];

fn recording_services(recorder: &RecordingSink) -> HostServices {
    HostServices::deny_all()
        .with_logs(Arc::new(recorder.clone()))
        .with_tools(Arc::new(recorder.clone()))
        .with_events(Arc::new(recorder.clone()))
        .with_config(Arc::new(InMemoryConfig::new()))
        .with_store(Arc::new(InMemoryStore::new()))
}

#[test]
fn a_plugin_with_no_grants_is_refused_every_single_host_call() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .services(recording_services(&recorder))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    for (probe, capability, operation) in PROBES {
        let answer = host
            .invoke_tool(&id, probe, "{}")
            .unwrap_or_else(|error| panic!("probe {probe} must return, got {error}"));
        assert_eq!(
            answer, DENIED,
            "probe {probe} needs {capability}.{operation} and must be refused"
        );
    }

    let audited: BTreeSet<(Capability, &str)> = host
        .denials(&id)
        .iter()
        .map(|denial| (denial.capability(), denial.operation()))
        .collect();
    let expected: BTreeSet<(Capability, &str)> = PROBES
        .iter()
        .map(|(_, capability, operation)| (*capability, *operation))
        .collect();
    assert_eq!(
        audited, expected,
        "every probe must appear in the audit log exactly once"
    );

    for denial in host.denials(&id) {
        assert_eq!(
            *denial.reason(),
            DenialReason::NotGranted,
            "{} was refused for the wrong reason",
            denial.capability()
        );
    }

    assert!(
        recorder.logs().is_empty(),
        "an ungranted plugin must not reach the log sink"
    );
    assert!(
        recorder.tools().is_empty(),
        "an ungranted plugin must not register tools"
    );
    assert!(
        recorder.events().is_empty(),
        "an ungranted plugin must not publish events"
    );
}

#[test]
fn granting_one_capability_does_not_open_any_other() {
    let root = support::tempdir();
    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::Clock(ClockGrant { resolution_ms: 1 })],
    );
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(
        host.invoke_tool(&id, "a", "{}").expect("clock probe"),
        ALLOWED,
        "the granted clock must work"
    );
    for (probe, capability, operation) in PROBES {
        if *capability == Capability::Clock {
            continue;
        }
        assert_eq!(
            host.invoke_tool(&id, probe, "{}").expect("probe"),
            DENIED,
            "{capability}.{operation} was never granted, so probe {probe} must fail"
        );
    }
}

#[test]
fn filesystem_reads_are_confined_to_the_granted_root() {
    let root = support::tempdir();
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).expect("create the data dir");
    std::fs::write(data.join("probe.txt"), b"hello").expect("seed the file");
    std::fs::create_dir_all(data.join("probe")).expect("create the listable dir");

    let inside = install_probe(
        root.path(),
        "inside",
        vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![data.clone()],
            max_file_bytes: 4096,
        })],
    );
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .build()
        .expect("host");
    let id = host.load(&inside).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(
        host.invoke_tool(&id, "c", "{}").expect("read probe"),
        ALLOWED,
        "a file inside the granted root must be readable"
    );
    assert_eq!(
        host.invoke_tool(&id, "e", "{}").expect("list probe"),
        ALLOWED,
        "a directory inside the granted root must be listable"
    );
    assert_eq!(
        host.invoke_tool(&id, "d", "{}").expect("write probe"),
        DENIED,
        "a read grant must never imply a write grant"
    );

    let write_denials: Vec<_> = host
        .denials(&id)
        .into_iter()
        .filter(|denial| denial.capability() == Capability::FilesystemWrite)
        .collect();
    assert_eq!(write_denials.len(), 1, "exactly one write denial");
    assert_eq!(*write_denials[0].reason(), DenialReason::NotGranted);
    assert_eq!(
        std::fs::read(data.join("probe.txt")).expect("read back"),
        b"hello",
        "the refused write must not have touched the file"
    );
}

#[test]
fn a_guest_cannot_climb_out_of_its_granted_root() {
    let root = support::tempdir();
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).expect("create the data dir");
    std::fs::write(root.path().join("escape.txt"), b"secret").expect("seed the secret");

    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![data],
            max_file_bytes: 4096,
        })],
    );
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    // `..` traversal, an absolute path and a `.` segment are all refused before
    // the host ever touches the filesystem.
    assert_eq!(
        host.invoke_tool(&id, "p", "{}").expect("traversal probe"),
        DENIED,
        "`../escape.txt` must never resolve"
    );
    assert_eq!(
        host.invoke_tool(&id, "q", "{}").expect("absolute probe"),
        DENIED,
        "an absolute path must never resolve"
    );
    assert_eq!(
        host.invoke_tool(&id, "n", "{}").expect("dot probe"),
        DENIED,
        "a `.` segment must never resolve"
    );

    let reasons: Vec<DenialReason> = host
        .denials(&id)
        .iter()
        .map(|denial| denial.reason().clone())
        .collect();
    assert_eq!(
        reasons,
        vec![
            DenialReason::InvalidArgument("path must not contain `.` or `..` segments".to_owned()),
            DenialReason::InvalidArgument("path must be relative".to_owned()),
            DenialReason::InvalidArgument("path must not contain `.` or `..` segments".to_owned()),
        ],
        "each attempt must be refused as a malformed path"
    );
}

#[test]
fn a_filesystem_grant_for_the_wrong_root_is_out_of_scope() {
    let root = support::tempdir();
    let elsewhere = root.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("create the other dir");

    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![elsewhere],
            max_file_bytes: 4096,
        })],
    );
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(
        host.invoke_tool(&id, "c", "{}").expect("read probe"),
        DENIED,
        "`probe.txt` resolves outside the granted root"
    );
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1, "one denial");
    assert_eq!(denials[0].capability(), Capability::FilesystemRead);
    assert_eq!(denials[0].operation(), "read-file");
    assert_eq!(
        *denials[0].reason(),
        DenialReason::OutOfScope(
            "`probe.txt` does not resolve inside a granted read root".to_owned()
        ),
        "the denial must name the containment failure"
    );
}

#[test]
fn http_grants_are_scoped_to_host_and_method() {
    let root = support::tempdir();
    let wrong_host = install_probe(
        root.path(),
        "wrong-host",
        vec![CapabilityGrant::Http(HttpGrant {
            hosts: vec!["other.invalid".to_owned()],
            methods: vec![HttpMethod::Get],
            allow_plaintext: false,
            max_response_bytes: 4096,
        })],
    );
    let wrong_method = install_probe_named(
        root.path(),
        "wrong-method",
        "gta-claw-fixture-postr",
        vec![CapabilityGrant::Http(HttpGrant {
            hosts: vec!["example.invalid".to_owned()],
            methods: vec![HttpMethod::Post],
            allow_plaintext: false,
            max_response_bytes: 4096,
        })],
    );

    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .build()
        .expect("host");

    let host_id = host.load(&wrong_host).expect("load wrong host");
    let method_id = host.load(&wrong_method).expect("load wrong method");
    host.activate(&host_id).expect("activate");
    host.activate(&method_id).expect("activate");

    assert_eq!(
        host.invoke_tool(&host_id, "f", "{}").expect("http probe"),
        DENIED,
        "example.invalid was not on the allow list"
    );
    let denials = host.denials(&host_id);
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].capability(), Capability::Http);
    assert_eq!(
        *denials[0].reason(),
        DenialReason::OutOfScope(
            "host `example.invalid` is not in the granted host list".to_owned()
        )
    );

    assert_eq!(
        host.invoke_tool(&method_id, "f", "{}").expect("http probe"),
        DENIED,
        "GET was not among the granted methods"
    );
    let denials = host.denials(&method_id);
    assert_eq!(denials.len(), 1);
    assert_eq!(
        *denials[0].reason(),
        DenialReason::OutOfScope("method `GET` is not in the granted method list".to_owned())
    );
}

#[test]
fn config_reads_are_scoped_to_the_granted_keys() {
    let root = support::tempdir();
    let config = InMemoryConfig::new();
    config.set(PROBE_ID, "k", "v");

    let other_key: BTreeSet<String> = ["other".to_owned()].into_iter().collect();
    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::Config(ConfigGrant {
            scope: ConfigScope::Keys(other_key),
        })],
    );
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .services(HostServices::deny_all().with_config(Arc::new(config)))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(
        host.invoke_tool(&id, "i", "{}").expect("config probe"),
        DENIED,
        "key `k` is not in the granted key set"
    );
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1);
    assert_eq!(
        *denials[0].reason(),
        DenialReason::OutOfScope("key `k` is not in the granted key list".to_owned())
    );
}

#[test]
fn a_store_grant_with_no_room_refuses_writes_but_still_allows_reads() {
    let root = support::tempdir();
    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::Store(StoreGrant {
            max_total_bytes: 1,
            max_value_bytes: 1,
            max_keys: 1,
        })],
    );
    let store = InMemoryStore::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .services(HostServices::deny_all().with_store(Arc::new(store.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(
        host.invoke_tool(&id, "g", "{}").expect("store get"),
        ALLOWED,
        "reading a missing key is allowed and answers none"
    );
    assert_eq!(
        host.invoke_tool(&id, "h", "{}").expect("store set"),
        DENIED,
        "the two byte value does not fit in a one byte quota"
    );
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].capability(), Capability::Store);
    assert_eq!(denials[0].operation(), "set");
    assert_eq!(
        *denials[0].reason(),
        DenialReason::QuotaExceeded("value is 2 bytes, the grant allows 1".to_owned())
    );
    assert_eq!(
        StoreBackend::key_count(&store, PROBE_ID),
        0,
        "a refused write must not have reached the backend"
    );
}

#[test]
fn log_grants_filter_by_level() {
    let root = support::tempdir();
    let recorder = RecordingSink::new();
    // The probe logs at `info`; a grant that starts at `warn` must refuse it.
    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::Log(LogGrant {
            min_level: LogLevel::Warn,
            max_message_bytes: 256,
        })],
    );
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .services(HostServices::deny_all().with_logs(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(
        host.invoke_tool(&id, "j", "{}").expect("log probe"),
        DENIED,
        "info is below the granted minimum level"
    );
    assert!(
        recorder.logs().is_empty(),
        "a refused log must never reach the sink"
    );
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1);
    assert_eq!(
        *denials[0].reason(),
        DenialReason::OutOfScope("severity Info is below the granted floor Warn".to_owned())
    );
}

#[test]
fn event_grants_are_scoped_to_the_granted_kinds() {
    let root = support::tempdir();
    let recorder = RecordingSink::new();
    // The probe emits `heartbeat`; grant only `message`.
    let kinds: BTreeSet<EventKind> = [EventKind::Message].into_iter().collect();
    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::Events(EventsGrant {
            emit_kinds: kinds,
            max_payload_bytes: 256,
        })],
    );
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .services(HostServices::deny_all().with_events(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(
        host.invoke_tool(&id, "l", "{}").expect("event probe"),
        DENIED,
        "heartbeat is not among the granted kinds"
    );
    assert!(
        recorder.events().is_empty(),
        "a refused event must never reach the sink"
    );
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1);
    assert_eq!(
        *denials[0].reason(),
        DenialReason::OutOfScope(
            "event kind `Heartbeat` is not in the granted emit list".to_owned()
        )
    );
}

#[test]
fn granted_calls_actually_reach_the_host_services() {
    let root = support::tempdir();
    let recorder = RecordingSink::new();
    let kinds: BTreeSet<EventKind> = [EventKind::Heartbeat].into_iter().collect();
    let dir = install_probe(
        root.path(),
        "probe",
        vec![
            CapabilityGrant::Log(LogGrant {
                min_level: LogLevel::Trace,
                max_message_bytes: 256,
            }),
            CapabilityGrant::Tools(ToolsGrant {
                max_tools: 4,
                max_schema_bytes: 256,
            }),
            CapabilityGrant::Events(EventsGrant {
                emit_kinds: kinds,
                max_payload_bytes: 256,
            }),
            CapabilityGrant::Random(RandomGrant {
                max_bytes_per_call: 32,
            }),
        ],
    );
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .services(recording_services(&recorder))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    assert_eq!(host.invoke_tool(&id, "j", "{}").expect("log"), ALLOWED);
    assert_eq!(host.invoke_tool(&id, "k", "{}").expect("tools"), ALLOWED);
    assert_eq!(host.invoke_tool(&id, "l", "{}").expect("events"), ALLOWED);
    assert_eq!(host.invoke_tool(&id, "b", "{}").expect("random"), ALLOWED);

    let logs = recorder.logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].plugin_id, PROBE_ID);
    assert_eq!(logs[0].level, LogLevel::Info);
    assert_eq!(logs[0].message, "probe");

    let tools = recorder.tools();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].plugin_id, PROBE_ID);
    assert_eq!(tools[0].name, "probe");
    assert_eq!(tools[0].summary, "probe tool");
    assert_eq!(tools[0].input_schema, "{}");

    let events = recorder.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, PROBE_ID);
    assert_eq!(events[0].1.kind, EventKind::Heartbeat);
    assert_eq!(events[0].1.source, "probe");
    assert_eq!(events[0].1.payload, "{}");

    assert!(
        host.denials(&id).is_empty(),
        "nothing was refused in this test"
    );
}

#[test]
fn the_trap_violation_policy_kills_the_call_instead_of_returning_an_error() {
    let root = support::tempdir();
    let dir = install_probe(root.path(), "probe", Vec::new());
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .violation_policy(ViolationPolicy::Trap)
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    host.activate(&id).expect("activate");

    let error = host
        .invoke_tool(&id, "a", "{}")
        .expect_err("a trapping policy must not return a value");
    assert_eq!(
        error.termination(),
        Some(TerminationCause::Trap),
        "the refused call must unwind the guest, not return to it"
    );

    // The refusal is still audited, with the same reason the returning policy
    // would have produced.
    let denials = host.denials(&id);
    assert_eq!(denials.len(), 1);
    assert_eq!(denials[0].capability(), Capability::Clock);
    assert_eq!(denials[0].operation(), "now-ms");
    assert_eq!(*denials[0].reason(), DenialReason::NotGranted);

    let error = host
        .invoke_tool(&id, "x", "{}")
        .expect_err("the plugin must now be faulted");
    match error {
        HostError::Faulted { id: faulted, cause } => {
            assert_eq!(faulted, PROBE_ID);
            assert_eq!(cause, TerminationCause::Trap);
        }
        other => panic!("expected a faulted plugin, got {other}"),
    }
}

#[test]
fn two_plugins_never_share_a_grant() {
    let root = support::tempdir();
    let privileged = install_probe(
        root.path(),
        "privileged",
        vec![CapabilityGrant::Clock(ClockGrant { resolution_ms: 1 })],
    );
    let plain = install_probe_named(root.path(), "plain", "gta-claw-fixture-plain", Vec::new());

    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .build()
        .expect("host");
    let privileged_id = host.load(&privileged).expect("load privileged");
    let plain_id = host.load(&plain).expect("load plain");
    assert_ne!(privileged_id, plain_id);
    host.activate(&privileged_id).expect("activate privileged");
    host.activate(&plain_id).expect("activate plain");

    assert_eq!(
        host.invoke_tool(&privileged_id, "a", "{}").expect("clock"),
        ALLOWED
    );
    assert_eq!(
        host.invoke_tool(&plain_id, "a", "{}").expect("clock"),
        DENIED,
        "the second plugin has no clock grant of its own"
    );
    assert!(host.denials(&privileged_id).is_empty());
    assert_eq!(host.denials(&plain_id).len(), 1);
}

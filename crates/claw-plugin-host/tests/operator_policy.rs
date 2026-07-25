//! A manifest may only ever narrow the operator's grant, never widen it.
//!
//! Every test here installs a manifest that asks for more than the operator
//! allows and then drives the real probe component through Wasmtime to prove
//! that the extra reach is not there at the host-function boundary either.

mod support;

use std::sync::Arc;

use claw_plugin_api::capability::{
    Capability, CapabilityGrant, CapabilitySet, ConfigGrant, ConfigScope, FilesystemGrant,
    HttpGrant, HttpMethod, LogGrant, LogLevel, StoreGrant,
};
use claw_plugin_api::policy::{OperatorPolicy, WithheldReason};
use claw_plugin_host::PluginHost;
use claw_plugin_host::services::{HostServices, InMemoryConfig, InMemoryStore, RecordingSink};
use support::{PROBE_ID, install_probe, unsigned_core_policy};

/// `permission-denied` is the second `error-code` case, so the guest sees `e1`.
const DENIED: &str = "e1";
/// The host call returned `ok`.
const ALLOWED: &str = "o0";

#[test]
fn a_manifest_that_asks_for_the_whole_disk_gets_only_the_operator_root() {
    let root = support::tempdir();
    let sandbox = root.path().join("sandbox");
    std::fs::create_dir_all(sandbox.join("probe")).expect("create the granted directory");
    std::fs::write(sandbox.join("probe.txt"), b"in scope").expect("write the in-scope file");
    std::fs::write(root.path().join("escape.txt"), b"out of scope").expect("write the secret");

    // The hostile manifest asks for the whole temporary tree, which contains
    // `escape.txt`. The operator only ever allowed the `sandbox` subtree.
    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![root.path().to_path_buf()],
            max_file_bytes: 1 << 20,
        })],
    );
    let ceiling = CapabilitySet::new([CapabilityGrant::FilesystemRead(FilesystemGrant {
        roots: vec![sandbox.clone()],
        max_file_bytes: 4096,
    })])
    .expect("valid ceiling");

    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(OperatorPolicy::deny_all().allow(PROBE_ID, ceiling))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");

    let effective = host
        .effective_capabilities(&id)
        .expect("the instance is live")
        .filesystem_read()
        .cloned()
        .expect("read survives");
    assert_eq!(
        effective.roots,
        vec![sandbox.clone()],
        "the manifest's wider root must have been dropped"
    );
    assert_eq!(effective.max_file_bytes, 4096, "the tighter quota wins");
    assert_eq!(
        host.narrowed_capabilities(&id),
        Some([Capability::FilesystemRead].as_slice())
    );

    host.activate(&id).expect("activate");
    // `c` reads `probe.txt`, which exists only under the operator's root, and
    // `p` tries to climb out with `../escape.txt`.
    assert_eq!(
        host.invoke_tool(&id, "c", "{}").expect("read in scope"),
        ALLOWED
    );
    assert_eq!(
        host.invoke_tool(&id, "p", "{}").expect("read out of scope"),
        DENIED,
        "the manifest's own wider root must not be reachable"
    );
    assert_eq!(
        host.invoke_tool(&id, "q", "{}").expect("absolute read"),
        DENIED
    );
}

#[test]
fn a_capability_absent_from_the_ceiling_is_withheld_entirely() {
    let root = support::tempdir();
    let dir = install_probe(
        root.path(),
        "probe",
        vec![
            CapabilityGrant::Log(LogGrant {
                min_level: LogLevel::Trace,
                max_message_bytes: 4096,
            }),
            CapabilityGrant::Http(HttpGrant {
                hosts: vec!["example.invalid".to_owned()],
                methods: vec![HttpMethod::Get],
                allow_plaintext: true,
                max_response_bytes: 1 << 20,
            }),
        ],
    );
    // The operator allows logging and nothing else. Exfiltration was requested
    // by a perfectly valid manifest and is simply not on offer.
    let ceiling = CapabilitySet::new([CapabilityGrant::Log(LogGrant {
        min_level: LogLevel::Warn,
        max_message_bytes: 64,
    })])
    .expect("valid ceiling");

    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(OperatorPolicy::deny_all().allow(PROBE_ID, ceiling))
        .services(HostServices::deny_all().with_logs(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");

    let withheld = host
        .withheld_capabilities(&id)
        .expect("the instance is live");
    assert_eq!(withheld.len(), 1);
    assert_eq!(withheld[0].capability(), Capability::Http);
    assert_eq!(withheld[0].reason(), WithheldReason::NotInCeiling);
    assert!(
        host.effective_capabilities(&id)
            .expect("live")
            .http()
            .is_none()
    );

    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "f", "{}").expect("http"), DENIED);
    // The probe logs at `info`, which is below the operator's `warn` floor, so
    // even the surviving capability is the operator's version of it.
    assert_eq!(host.invoke_tool(&id, "j", "{}").expect("log"), DENIED);
    assert!(
        recorder.logs().is_empty(),
        "nothing reached the log sink at all"
    );
}

#[test]
fn config_keys_and_store_quotas_are_intersected_not_replaced() {
    let root = support::tempdir();
    let dir = install_probe(
        root.path(),
        "probe",
        vec![
            CapabilityGrant::Config(ConfigGrant {
                scope: ConfigScope::Keys(["probe".to_owned(), "secret".to_owned()].into()),
            }),
            CapabilityGrant::Store(StoreGrant {
                max_total_bytes: 1 << 20,
                max_value_bytes: 1 << 20,
                max_keys: 1024,
            }),
        ],
    );
    let ceiling = CapabilitySet::new([
        CapabilityGrant::Config(ConfigGrant {
            scope: ConfigScope::Keys(["probe".to_owned(), "other".to_owned()].into()),
        }),
        CapabilityGrant::Store(StoreGrant {
            max_total_bytes: 1024,
            max_value_bytes: 256,
            max_keys: 2,
        }),
    ])
    .expect("valid ceiling");

    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(OperatorPolicy::deny_all().allow(PROBE_ID, ceiling))
        .services(
            HostServices::deny_all()
                .with_config(Arc::new(InMemoryConfig::new()))
                .with_store(Arc::new(InMemoryStore::new())),
        )
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");

    let effective = host.effective_capabilities(&id).expect("live").clone();
    match effective.config().expect("config survives").scope.clone() {
        ConfigScope::Keys(keys) => {
            assert_eq!(
                keys.into_iter().collect::<Vec<_>>(),
                vec!["probe".to_owned()],
                "only the key both sides agreed on survives"
            );
        }
        ConfigScope::OwnNamespace => {
            panic!("a keyed ceiling must never widen to the whole namespace")
        }
    }
    let store = effective.store().expect("store survives");
    assert_eq!(store.max_total_bytes, 1024, "the tighter total wins");
    assert_eq!(store.max_keys, 2, "the tighter key count wins");
    assert_eq!(store.max_value_bytes, 256, "the tighter value size wins");
}

#[test]
fn a_plugin_the_operator_never_named_gets_nothing_at_all() {
    let root = support::tempdir();
    let dir = install_probe(
        root.path(),
        "probe",
        vec![CapabilityGrant::Log(LogGrant {
            min_level: LogLevel::Trace,
            max_message_bytes: 4096,
        })],
    );
    // The ceiling names a *different* plugin, so this one falls through to the
    // deny-all default.
    let ceiling = CapabilitySet::new([CapabilityGrant::Log(LogGrant {
        min_level: LogLevel::Trace,
        max_message_bytes: 4096,
    })])
    .expect("valid ceiling");

    let recorder = RecordingSink::new();
    let mut host = PluginHost::builder()
        .trust_policy(unsigned_core_policy(root.path()))
        .operator_policy(OperatorPolicy::deny_all().allow("some-other-plugin", ceiling))
        .services(HostServices::deny_all().with_logs(Arc::new(recorder.clone())))
        .build()
        .expect("host");
    let id = host.load(&dir).expect("load");
    assert!(
        host.effective_capabilities(&id).expect("live").is_empty(),
        "a plugin outside the policy holds nothing"
    );

    host.activate(&id).expect("activate");
    assert_eq!(host.invoke_tool(&id, "j", "{}").expect("log"), DENIED);
    assert!(recorder.logs().is_empty());
}

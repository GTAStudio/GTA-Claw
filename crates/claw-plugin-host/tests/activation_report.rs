//! Signed batch activation keeps deterministic ordering and partial success.

mod support;

use std::sync::Arc;

use claw_plugin_api::registry::DeliveryClass;
use claw_plugin_api::trust::{Ed25519Verifier, TrustPolicy, VerificationError};
use claw_plugin_host::{
    ActivationOutcome, ActivationStage, DiscoveryRecord, DiscoveryStage, HostError, LifecycleState,
    PluginHost,
};
use ed25519_dalek::SigningKey;
use support::{
    PROBE_ID, install, manifest_for, probe_component, probe_component_named, sign_manifest,
};

#[test]
fn signed_activation_reports_failures_in_order_and_keeps_later_successes() {
    let root = support::tempdir();
    let key = SigningKey::from_bytes(&[42_u8; 32]);

    let malformed = root.path().join("aaa-malformed");
    std::fs::create_dir_all(&malformed).expect("create malformed fixture");
    std::fs::write(malformed.join("plugin.json"), b"{not-json").expect("write malformed manifest");

    let good_component = probe_component();
    let good_manifest = sign_manifest(&manifest_for(&good_component), &key, "release");
    install(root.path(), "bbb-good", &good_component, &good_manifest);

    let other_id = "gta-claw-fixture-other";
    let other_component = probe_component_named(other_id);
    let mut other_manifest = manifest_for(&other_component);
    other_manifest.id = other_id.to_owned();
    let mut tampered = sign_manifest(&other_manifest, &key, "release");
    tampered.description.push_str(" after signing");
    install(root.path(), "ccc-tampered", &other_component, &tampered);

    let policy = TrustPolicy::deny_all()
        .with_root(root.path().to_path_buf())
        .require_signature(true)
        .require_identity_binding(false)
        .with_trusted_key_id("release")
        .allow_delivery_class(DeliveryClass::Core);
    let mut host = PluginHost::builder()
        .trust_policy(policy)
        .verifier(Arc::new(
            Ed25519Verifier::new().with_key("release", key.verifying_key().to_bytes()),
        ))
        .build()
        .expect("host");

    let report = host.activate_discovered();
    assert_eq!(report.activated_count(), 1);
    assert_eq!(report.failure_count(), 2);
    assert_eq!(report.outcomes().len(), 3);

    let paths: Vec<&str> = report
        .outcomes()
        .iter()
        .map(|outcome| {
            let path = match outcome {
                ActivationOutcome::Activated(plugin) => &plugin.directory,
                ActivationOutcome::Failed(failure) => &failure.path,
            };
            path.file_name()
                .and_then(|name| name.to_str())
                .expect("fixture directory name")
        })
        .collect();
    assert_eq!(paths, ["aaa-malformed", "bbb-good", "ccc-tampered"]);

    let ActivationOutcome::Failed(malformed) = &report.outcomes()[0] else {
        panic!("the malformed manifest should fail");
    };
    assert_eq!(malformed.stage, ActivationStage::Manifest);
    assert!(malformed.plugin_id.is_none());
    assert!(malformed.error.to_string().contains("manifest JSON"));

    let ActivationOutcome::Activated(good) = &report.outcomes()[1] else {
        panic!("the signed fixture should activate");
    };
    assert_eq!(good.id, PROBE_ID);
    assert_eq!(good.signing_key_id.as_deref(), Some("release"));
    assert_eq!(host.state(PROBE_ID), Some(LifecycleState::Active));
    assert_eq!(host.signing_key_id(PROBE_ID), Some("release"));

    let ActivationOutcome::Failed(tampered) = &report.outcomes()[2] else {
        panic!("the tampered signature should fail");
    };
    assert_eq!(tampered.plugin_id.as_deref(), Some(other_id));
    assert_eq!(tampered.stage, ActivationStage::Load);
    assert!(matches!(
        tampered.error,
        HostError::Verification(VerificationError::BadSignature { .. })
    ));
    assert!(tampered.cleanup_error.is_none());
    assert_eq!(host.loaded_ids(), [PROBE_ID]);
}

#[test]
fn detailed_discovery_surfaces_an_unreadable_root() {
    let base = support::tempdir();
    let missing = base.path().join("missing");
    let host = PluginHost::builder()
        .trust_policy(TrustPolicy::deny_all().with_root(missing.clone()))
        .build()
        .expect("host");

    let records = host.discover_detailed();
    assert_eq!(records.len(), 1);
    let DiscoveryRecord::Failed { path, stage, error } = &records[0] else {
        panic!("a missing root must be a diagnostic");
    };
    assert_eq!(path, &missing);
    assert_eq!(*stage, DiscoveryStage::Root);
    assert!(error.to_string().contains("i/o error"));
}

#[cfg(unix)]
#[test]
fn detailed_discovery_surfaces_child_metadata_failures() {
    use std::os::unix::fs::symlink;

    let root = support::tempdir();
    let broken = root.path().join("broken-plugin");
    symlink(root.path().join("missing-target"), &broken).expect("create broken child symlink");
    let host = PluginHost::builder()
        .trust_policy(TrustPolicy::deny_all().with_root(root.path().to_path_buf()))
        .build()
        .expect("host");

    let records = host.discover_detailed();
    assert_eq!(records.len(), 1);
    let DiscoveryRecord::Failed { path, stage, .. } = &records[0] else {
        panic!("broken child metadata must be a diagnostic");
    };
    assert_eq!(path, &broken);
    assert_eq!(*stage, DiscoveryStage::Manifest);
}

#[cfg(unix)]
#[test]
fn detailed_discovery_surfaces_a_dangling_manifest_symlink() {
    use std::os::unix::fs::symlink;

    let root = support::tempdir();
    let plugin = root.path().join("broken-plugin");
    std::fs::create_dir_all(&plugin).expect("create plugin directory");
    symlink(plugin.join("missing-manifest"), plugin.join("plugin.json"))
        .expect("create dangling manifest symlink");
    let host = PluginHost::builder()
        .trust_policy(TrustPolicy::deny_all().with_root(root.path().to_path_buf()))
        .build()
        .expect("host");

    let records = host.discover_detailed();
    assert_eq!(records.len(), 1);
    let DiscoveryRecord::Failed { path, stage, .. } = &records[0] else {
        panic!("dangling manifest symlink must be a diagnostic");
    };
    assert_eq!(path, &plugin);
    assert_eq!(*stage, DiscoveryStage::Manifest);
}

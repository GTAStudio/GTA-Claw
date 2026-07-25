//! Everything the host checks before a component is allowed to run.
//!
//! These tests all use the same real component and change exactly one thing at
//! a time, so a rejection can only be caused by the thing that was changed.

mod support;

use claw_plugin_api::abi::AbiIncompatibility;
use claw_plugin_api::manifest::{
    ComponentRef, ManifestError, ManifestSignature, PluginManifest, SignatureAlgorithm,
};
use claw_plugin_api::registry::DeliveryClass;
use claw_plugin_api::trust::{
    Ed25519Verifier, TrustError, TrustPolicy, VerificationError, component_sha256, signing_payload,
};
use claw_plugin_host::{HostError, PluginHost};
use ed25519_dalek::{Signer, SigningKey};
use support::{
    PROBE_ID, install, manifest_for, probe_component, probe_component_importing_wasi,
    probe_component_named, probe_component_without_guest_export, unsigned_core_policy,
};

fn host(policy: TrustPolicy) -> PluginHost {
    PluginHost::builder()
        .trust_policy(policy)
        .build()
        .expect("host")
}

#[test]
fn a_component_that_imports_wasi_is_refused_before_it_is_instantiated() {
    // Every interface below is a real WASI interface a plugin might reach for.
    let attempts = [
        "wasi:filesystem/preopens@0.2.0",
        "wasi:cli/environment@0.2.0",
        "wasi:sockets/instance-network@0.2.0",
        "wasi:clocks/wall-clock@0.2.0",
        "wasi:random/random@0.2.0",
    ];
    for interface in attempts {
        let root = support::tempdir();
        let component = probe_component_importing_wasi(interface);
        let manifest = manifest_for(&component);
        let dir = install(root.path(), "probe", &component, &manifest);
        let mut host = host(unsigned_core_policy(root.path()));

        let error = host
            .load(&dir)
            .expect_err("an ambient import must be refused");
        match error {
            HostError::UnsatisfiedImport(name) => {
                assert_eq!(name, interface, "the host must name the import it refused")
            }
            other => panic!("expected an unsatisfied import for {interface}, got {other}"),
        }
        assert!(
            host.loaded_ids().is_empty(),
            "a refused component must not be registered"
        );
    }
}

#[test]
fn the_unmodified_component_still_loads() {
    // The counterweight to the test above: the only difference between the two
    // fixtures is the extra import, so the rejection cannot be incidental.
    let root = support::tempdir();
    let component = probe_component();
    let manifest = manifest_for(&component);
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    assert_eq!(host.load(&dir).expect("load"), PROBE_ID);
    assert_eq!(host.loaded_ids(), vec![PROBE_ID]);
}

#[test]
fn a_component_without_the_guest_export_is_refused() {
    let root = support::tempdir();
    let component = probe_component_without_guest_export();
    let manifest = manifest_for(&component);
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("the guest export is mandatory");
    assert!(
        matches!(error, HostError::Instantiate(_)),
        "expected an instantiation failure, got {error}"
    );
}

#[test]
fn bytes_that_do_not_match_the_pinned_digest_are_refused() {
    let root = support::tempdir();
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    let honest = manifest.component.sha256.clone();
    manifest.component.sha256 = component_sha256(b"something else entirely");
    let claimed = manifest.component.sha256.clone();
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("the digest must be checked");
    match error {
        HostError::DigestMismatch { expected, actual } => {
            assert_eq!(expected, claimed);
            assert_eq!(actual, honest);
        }
        other => panic!("expected a digest mismatch, got {other}"),
    }
}

#[test]
fn a_component_whose_size_was_misdeclared_is_refused() {
    let root = support::tempdir();
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.component.size_bytes = component.len() as u64 + 1;
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("the size must be checked");
    match error {
        HostError::DigestMismatch { expected, actual } => {
            assert_eq!(expected, format!("{} bytes", component.len() + 1));
            assert_eq!(actual, format!("{} bytes", component.len()));
        }
        other => panic!("expected a size mismatch, got {other}"),
    }
}

#[test]
fn a_manifest_that_declares_a_component_above_its_own_ceiling_is_refused() {
    let root = support::tempdir();
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.limits.max_component_bytes = (component.len() - 1) as u64;
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("the ceiling must be enforced");
    match error {
        HostError::Manifest(ManifestError::ComponentTooLarge {
            size_bytes,
            max_component_bytes,
        }) => {
            assert_eq!(size_bytes, component.len() as u64);
            assert_eq!(max_component_bytes, (component.len() - 1) as u64);
        }
        other => panic!("expected a schema-level rejection, got {other}"),
    }
}

#[test]
fn a_component_file_larger_than_the_ceiling_is_refused_before_it_is_read() {
    let root = support::tempdir();
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    // The manifest under-declares the size so it passes its own schema check;
    // the host still measures the file on disk.
    manifest.component.size_bytes = (component.len() - 1) as u64;
    manifest.limits.max_component_bytes = (component.len() - 1) as u64;
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("the ceiling must be enforced");
    match error {
        HostError::ComponentTooLarge { actual, limit } => {
            assert_eq!(actual, component.len() as u64);
            assert_eq!(limit, (component.len() - 1) as u64);
        }
        other => panic!("expected an oversized component, got {other}"),
    }
}

#[test]
fn a_manifest_declaring_a_future_abi_is_refused() {
    let root = support::tempdir();
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.abi_version = "2.0.0".to_owned();
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("a major bump is incompatible");
    match error {
        HostError::Manifest(ManifestError::AbiIncompatible(
            AbiIncompatibility::MajorMismatch { host, guest },
        )) => {
            assert_eq!(host, 1);
            assert_eq!(guest, 2);
        }
        other => panic!("expected an ABI rejection, got {other}"),
    }
}

#[test]
fn a_manifest_declaring_a_newer_minor_abi_is_refused() {
    let root = support::tempdir();
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.abi_version = "1.1.0".to_owned();
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host
        .load(&dir)
        .expect_err("the host cannot supply an interface it does not implement");
    match error {
        HostError::Manifest(ManifestError::AbiIncompatible(AbiIncompatibility::MinorTooNew {
            host,
            guest,
        })) => {
            assert_eq!(host, 0);
            assert_eq!(guest, 1);
        }
        other => panic!("expected a minor ABI rejection, got {other}"),
    }
}

#[test]
fn a_manifest_that_lies_about_the_component_identity_is_refused() {
    let root = support::tempdir();
    // The bytes really report `gta-claw-fixture-probe`; the manifest claims a
    // different, same-length id.
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.id = "gta-claw-fixture-other0".to_owned();
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("identity must agree");
    match error {
        HostError::IdentityMismatch {
            field,
            manifest: claimed,
            component: reported,
        } => {
            assert_eq!(field, "id");
            assert_eq!(claimed, "gta-claw-fixture-other0");
            assert_eq!(reported, PROBE_ID);
        }
        other => panic!("expected an identity mismatch, got {other}"),
    }
}

#[test]
fn a_manifest_that_lies_about_the_component_version_is_refused() {
    let root = support::tempdir();
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.version = "9.9.9".to_owned();
    let dir = install(root.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("the version must agree");
    match error {
        HostError::IdentityMismatch {
            field,
            manifest: claimed,
            component: reported,
        } => {
            assert_eq!(field, "version");
            assert_eq!(claimed, "9.9.9");
            assert_eq!(reported, "0.1.0");
        }
        other => panic!("expected a version mismatch, got {other}"),
    }
}

#[test]
fn a_plugin_outside_every_trusted_root_is_refused() {
    let trusted = support::tempdir();
    let elsewhere = support::tempdir();
    let component = probe_component();
    let manifest = manifest_for(&component);
    let dir = install(elsewhere.path(), "probe", &component, &manifest);
    let mut host = host(unsigned_core_policy(trusted.path()));

    let error = host.load(&dir).expect_err("only trusted roots may load");
    match error {
        HostError::Trust(TrustError::OutsideTrustedRoots { path }) => {
            let canonical = std::fs::canonicalize(&dir).expect("canonicalize");
            assert_eq!(path, canonical);
        }
        other => panic!("expected a trust rejection, got {other}"),
    }
}

#[test]
fn a_delivery_class_that_was_not_enabled_is_refused() {
    let root = support::tempdir();
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.delivery_class = DeliveryClass::OfficialExternal;
    let dir = install(root.path(), "probe", &component, &manifest);
    // `unsigned_core_policy` only enables `Core`.
    let mut host = host(unsigned_core_policy(root.path()));

    let error = host.load(&dir).expect_err("the class was never enabled");
    match error {
        HostError::Trust(TrustError::DeliveryClassNotAllowed { class }) => {
            assert_eq!(class, DeliveryClass::OfficialExternal);
        }
        other => panic!("expected a delivery-class rejection, got {other}"),
    }
}

#[test]
fn an_unsigned_plugin_is_refused_when_the_policy_demands_a_signature() {
    let root = support::tempdir();
    let component = probe_component();
    let manifest = manifest_for(&component);
    let dir = install(root.path(), "probe", &component, &manifest);
    let policy = TrustPolicy::deny_all()
        .with_root(root.path().to_path_buf())
        .require_signature(true)
        .require_identity_binding(false)
        .allow_delivery_class(DeliveryClass::Core);
    let mut host = host(policy);

    let error = host.load(&dir).expect_err("a signature is required");
    assert!(
        matches!(error, HostError::Trust(TrustError::SignatureRequired)),
        "expected a signature requirement, got {error}"
    );
}

#[test]
fn a_signed_plugin_loads_and_a_tampered_one_does_not() {
    let key = SigningKey::from_bytes(&[42_u8; 32]);
    let public = key.verifying_key().to_bytes();

    let sign = |manifest: &PluginManifest| -> PluginManifest {
        let payload = signing_payload(manifest).expect("payload");
        let signature = key.sign(&payload);
        let mut hex = String::new();
        for byte in signature.to_bytes() {
            hex.push_str(&format!("{byte:02x}"));
        }
        PluginManifest {
            signature: Some(ManifestSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                key_id: "release".to_owned(),
                value: hex,
            }),
            ..manifest.clone()
        }
    };

    let root = support::tempdir();
    let component = probe_component();
    let signed = sign(&manifest_for(&component));
    let good = install(root.path(), "good", &component, &signed);

    // Same signature, but the manifest now asks for a bigger memory budget.
    let mut escalated = signed.clone();
    escalated.limits.max_memory_bytes *= 2;
    let bad = install(root.path(), "bad", &component, &escalated);

    let policy = TrustPolicy::deny_all()
        .with_root(root.path().to_path_buf())
        .require_signature(true)
        .require_identity_binding(false)
        .with_trusted_key_id("release")
        .allow_delivery_class(DeliveryClass::Core);
    let mut host = PluginHost::builder()
        .trust_policy(policy)
        .verifier(std::sync::Arc::new(
            Ed25519Verifier::new().with_key("release", public),
        ))
        .build()
        .expect("host");

    assert_eq!(host.load(&good).expect("the signed plugin loads"), PROBE_ID);
    host.unload(PROBE_ID).expect("unload");

    let error = host
        .load(&bad)
        .expect_err("a transplanted signature must not verify");
    match error {
        HostError::Verification(VerificationError::BadSignature { key_id }) => {
            assert_eq!(key_id, "release");
        }
        other => panic!("expected a bad signature, got {other}"),
    }
}

#[test]
fn the_same_plugin_cannot_be_loaded_twice() {
    let root = support::tempdir();
    let component = probe_component();
    let manifest = manifest_for(&component);
    let first = install(root.path(), "first", &component, &manifest);
    let second = install(root.path(), "second", &component, &manifest);
    let mut host = host(unsigned_core_policy(root.path()));

    assert_eq!(host.load(&first).expect("load"), PROBE_ID);
    let error = host.load(&second).expect_err("ids must be unique");
    match error {
        HostError::DuplicatePlugin(id) => assert_eq!(id, PROBE_ID),
        other => panic!("expected a duplicate, got {other}"),
    }
}

#[test]
fn discovery_reports_every_directory_including_the_broken_ones() {
    let root = support::tempdir();
    let component = probe_component();

    let good = manifest_for(&component);
    install(root.path(), "aaa-good", &component, &good);

    let other = probe_component_named("gta-claw-fixture-other");
    let mut other_manifest = manifest_for(&other);
    other_manifest.id = "gta-claw-fixture-other".to_owned();
    other_manifest.component = ComponentRef {
        path: "component.wasm".to_owned(),
        sha256: component_sha256(&other),
        size_bytes: other.len() as u64,
    };
    install(root.path(), "bbb-other", &other, &other_manifest);

    let broken = root.path().join("ccc-broken");
    std::fs::create_dir_all(&broken).expect("create");
    std::fs::write(broken.join("plugin.json"), b"{ not json").expect("write");

    let host = host(unsigned_core_policy(root.path()));
    let found = host.discover();
    assert_eq!(
        found.len(),
        3,
        "every directory with a manifest is reported"
    );

    let ids: Vec<Option<String>> = found
        .iter()
        .map(|entry| {
            entry
                .manifest
                .as_ref()
                .ok()
                .map(|manifest| manifest.id.clone())
        })
        .collect();
    assert_eq!(
        ids,
        vec![
            Some(PROBE_ID.to_owned()),
            Some("gta-claw-fixture-other".to_owned()),
            None,
        ],
        "results are ordered by directory and the broken one is reported as an error"
    );

    match found[2].manifest.as_ref() {
        Err(HostError::Manifest(_)) => {}
        other => panic!("expected a manifest error, got {other:?}"),
    }
}

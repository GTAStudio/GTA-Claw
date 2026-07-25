//! Trust policy and signature verification against a real filesystem.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use claw_plugin_api::manifest::{ManifestSignature, PluginManifest, SignatureAlgorithm};
use claw_plugin_api::registry::DeliveryClass;
use claw_plugin_api::trust::{
    Ed25519Verifier, SignatureVerifier, TrustError, TrustPolicy, VerificationError,
    VerificationRequest, component_sha256, signing_payload,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

const COMPONENT_BYTES: &[u8] = b"\0asm\x0d\x00\x01\x00 not a real component, only bytes to hash";

fn manifest_value(delivery_class: &str) -> Value {
    json!({
        "manifest_version": 1,
        "id": "trust-fixture",
        "display_name": "Trust fixture",
        "description": "Plugin manifest used by the trust policy integration tests.",
        "version": "1.4.2",
        "abi_version": "1.0.0",
        "delivery_class": delivery_class,
        "component": {
            "path": "component/trust.wasm",
            "sha256": component_sha256(COMPONENT_BYTES),
            "size_bytes": COMPONENT_BYTES.len()
        },
        "capabilities": [
            { "capability": "log", "min_level": "info", "max_message_bytes": 1024 }
        ]
    })
}

fn parse(value: &Value) -> PluginManifest {
    PluginManifest::parse(&serde_json::to_vec(value).expect("encode")).expect("valid manifest")
}

/// Lays out `<dir>/component/trust.wasm` and returns the plugin directory.
fn write_plugin(dir: &Path) -> PathBuf {
    fs::create_dir_all(dir.join("component")).expect("create component dir");
    fs::write(dir.join("component").join("trust.wasm"), COMPONENT_BYTES).expect("write component");
    dir.to_path_buf()
}

fn permissive_policy(root: &Path) -> TrustPolicy {
    TrustPolicy::deny_all()
        .with_root(root)
        .require_signature(false)
        .allow_delivery_class(DeliveryClass::Core)
}

#[test]
fn the_default_policy_denies_everything() {
    let temp = support::tempdir();
    let plugin_dir = write_plugin(&temp.path().join("plugin"));
    let manifest = parse(&manifest_value("core"));

    let policy = TrustPolicy::default();
    assert!(policy.signature_required());
    assert!(policy.roots().is_empty());
    assert_eq!(
        policy.authorize(&plugin_dir, &manifest),
        Err(TrustError::DeliveryClassNotAllowed {
            class: DeliveryClass::Core
        })
    );
}

#[test]
fn a_policy_with_no_roots_refuses_even_an_allowed_delivery_class() {
    let temp = support::tempdir();
    let plugin_dir = write_plugin(&temp.path().join("plugin"));
    let manifest = parse(&manifest_value("core"));

    let policy = TrustPolicy::deny_all()
        .require_signature(false)
        .allow_delivery_class(DeliveryClass::Core);
    assert_eq!(
        policy.authorize(&plugin_dir, &manifest),
        Err(TrustError::NoTrustedRoots)
    );
}

#[test]
fn an_unsigned_plugin_under_a_trusted_root_is_authorised() {
    let temp = support::tempdir();
    let root = temp.path().join("plugins");
    let plugin_dir = write_plugin(&root.join("trust-fixture"));
    let manifest = parse(&manifest_value("core"));

    let decision = permissive_policy(&root)
        .authorize(&plugin_dir, &manifest)
        .expect("authorised");
    assert_eq!(
        decision.root(),
        fs::canonicalize(&root).expect("canonical root")
    );
    assert_eq!(
        decision.component_path(),
        fs::canonicalize(plugin_dir.join("component").join("trust.wasm")).expect("canonical")
    );
    assert_eq!(decision.signing_key_id(), None);
    assert!(decision.component_path().starts_with(decision.root()));
}

#[test]
fn a_plugin_directory_outside_every_root_is_refused() {
    let temp = support::tempdir();
    let root = temp.path().join("plugins");
    fs::create_dir_all(&root).expect("create root");
    let outside = write_plugin(&temp.path().join("elsewhere"));
    let manifest = parse(&manifest_value("core"));

    let error = permissive_policy(&root)
        .authorize(&outside, &manifest)
        .unwrap_err();
    match error {
        TrustError::OutsideTrustedRoots { path } => {
            assert_eq!(path, fs::canonicalize(&outside).expect("canonical"));
        }
        other => panic!("expected an outside-root error, got {other}"),
    }
}

#[test]
fn a_parent_traversal_into_a_sibling_directory_is_resolved_and_refused() {
    let temp = support::tempdir();
    let root = temp.path().join("plugins");
    fs::create_dir_all(&root).expect("create root");
    let sibling = write_plugin(&temp.path().join("sibling"));
    let manifest = parse(&manifest_value("core"));

    // Lexically this path is "inside" the root; canonicalisation must undo that.
    let traversal = root.join("..").join("sibling");
    let error = permissive_policy(&root)
        .authorize(&traversal, &manifest)
        .unwrap_err();
    match error {
        TrustError::OutsideTrustedRoots { path } => {
            assert_eq!(path, fs::canonicalize(&sibling).expect("canonical"));
        }
        other => panic!("expected an outside-root error, got {other}"),
    }
}

#[test]
fn a_missing_component_file_is_refused_before_any_read() {
    let temp = support::tempdir();
    let root = temp.path().join("plugins");
    let plugin_dir = root.join("trust-fixture");
    fs::create_dir_all(&plugin_dir).expect("create plugin dir");
    let manifest = parse(&manifest_value("core"));

    let error = permissive_policy(&root)
        .authorize(&plugin_dir, &manifest)
        .unwrap_err();
    match error {
        TrustError::UnresolvablePath { path, .. } => {
            assert!(
                path.ends_with(Path::new("component").join("trust.wasm")),
                "unexpected path {}",
                path.display()
            );
        }
        other => panic!("expected an unresolvable path error, got {other}"),
    }
}

#[test]
fn each_delivery_class_must_be_enabled_explicitly() {
    let temp = support::tempdir();
    let root = temp.path().join("plugins");
    let plugin_dir = write_plugin(&root.join("trust-fixture"));

    let policy = TrustPolicy::deny_all()
        .with_root(&root)
        .require_signature(false)
        .allow_delivery_class(DeliveryClass::Core);

    for (wire, class) in [
        ("official_external", DeliveryClass::OfficialExternal),
        ("source_only_qa", DeliveryClass::SourceOnlyQa),
    ] {
        let manifest = parse(&manifest_value(wire));
        assert_eq!(
            policy.authorize(&plugin_dir, &manifest),
            Err(TrustError::DeliveryClassNotAllowed { class })
        );
    }

    let core = parse(&manifest_value("core"));
    assert!(policy.authorize(&plugin_dir, &core).is_ok());
}

#[test]
fn an_unsigned_plugin_is_refused_when_signatures_are_required() {
    let temp = support::tempdir();
    let root = temp.path().join("plugins");
    let plugin_dir = write_plugin(&root.join("trust-fixture"));
    let manifest = parse(&manifest_value("core"));

    let policy = TrustPolicy::deny_all()
        .with_root(&root)
        .allow_delivery_class(DeliveryClass::Core);
    assert_eq!(
        policy.authorize(&plugin_dir, &manifest),
        Err(TrustError::SignatureRequired)
    );
}

#[test]
fn a_signature_from_an_untrusted_key_id_is_refused() {
    let temp = support::tempdir();
    let root = temp.path().join("plugins");
    let plugin_dir = write_plugin(&root.join("trust-fixture"));

    let mut manifest = parse(&manifest_value("core"));
    manifest.signature = Some(ManifestSignature {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: "attacker".to_owned(),
        value: "ab".repeat(64),
    });

    let policy = TrustPolicy::deny_all()
        .with_root(&root)
        .allow_delivery_class(DeliveryClass::Core)
        .with_trusted_key_id("release-2026");
    assert_eq!(
        policy.authorize(&plugin_dir, &manifest),
        Err(TrustError::UntrustedKeyId {
            key_id: "attacker".to_owned()
        })
    );
}

fn sign(manifest: &PluginManifest, key: &SigningKey, key_id: &str) -> PluginManifest {
    let mut unsigned = manifest.clone();
    unsigned.signature = None;
    let payload = signing_payload(&unsigned).expect("payload");
    let signature = key.sign(&payload);
    let mut hex = String::with_capacity(128);
    for byte in signature.to_bytes() {
        hex.push_str(&format!("{byte:02x}"));
    }
    let mut signed = unsigned;
    signed.signature = Some(ManifestSignature {
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: key_id.to_owned(),
        value: hex,
    });
    signed
}

#[test]
fn a_genuine_ed25519_signature_verifies() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let manifest = parse(&manifest_value("core"));
    let signed = sign(&manifest, &key, "release-2026");

    let verifier = Ed25519Verifier::new().with_key("release-2026", key.verifying_key().to_bytes());
    assert_eq!(
        verifier.verify(&VerificationRequest {
            manifest: &signed,
            component_sha256: &signed.component.sha256,
        }),
        Ok(())
    );
}

#[test]
fn a_signature_does_not_survive_a_capability_escalation() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let manifest = parse(&manifest_value("core"));
    let signed = sign(&manifest, &key, "release-2026");

    let mut escalated = signed.clone();
    escalated.capabilities.push(
        serde_json::from_value(json!({
            "capability": "filesystem-read",
            "roots": [if cfg!(windows) { "C:\\" } else { "/" }],
            "max_file_bytes": 1_048_576
        }))
        .expect("grant"),
    );

    let verifier = Ed25519Verifier::new().with_key("release-2026", key.verifying_key().to_bytes());
    assert_eq!(
        verifier.verify(&VerificationRequest {
            manifest: &escalated,
            component_sha256: &escalated.component.sha256,
        }),
        Err(VerificationError::BadSignature {
            key_id: "release-2026".to_owned()
        })
    );
}

#[test]
fn a_signature_does_not_survive_a_component_repin() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let manifest = parse(&manifest_value("core"));
    let signed = sign(&manifest, &key, "release-2026");

    let mut repinned = signed.clone();
    repinned.component.sha256 = component_sha256(b"a different component");

    let verifier = Ed25519Verifier::new().with_key("release-2026", key.verifying_key().to_bytes());
    assert_eq!(
        verifier.verify(&VerificationRequest {
            manifest: &repinned,
            component_sha256: &repinned.component.sha256,
        }),
        Err(VerificationError::BadSignature {
            key_id: "release-2026".to_owned()
        })
    );
}

#[test]
fn bytes_that_do_not_match_the_pinned_digest_are_refused() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let manifest = parse(&manifest_value("core"));
    let signed = sign(&manifest, &key, "release-2026");
    let swapped = component_sha256(b"swapped component bytes");

    let verifier = Ed25519Verifier::new().with_key("release-2026", key.verifying_key().to_bytes());
    assert_eq!(
        verifier.verify(&VerificationRequest {
            manifest: &signed,
            component_sha256: &swapped,
        }),
        Err(VerificationError::DigestMismatch {
            expected: signed.component.sha256.clone(),
            found: swapped,
        })
    );
}

#[test]
fn a_signature_from_another_key_is_refused() {
    let signer = SigningKey::from_bytes(&[7_u8; 32]);
    let other = SigningKey::from_bytes(&[9_u8; 32]);
    let manifest = parse(&manifest_value("core"));
    let signed = sign(&manifest, &signer, "release-2026");

    let verifier =
        Ed25519Verifier::new().with_key("release-2026", other.verifying_key().to_bytes());
    assert_eq!(
        verifier.verify(&VerificationRequest {
            manifest: &signed,
            component_sha256: &signed.component.sha256,
        }),
        Err(VerificationError::BadSignature {
            key_id: "release-2026".to_owned()
        })
    );
}

#[test]
fn an_unregistered_key_id_is_refused_before_any_crypto_runs() {
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let manifest = parse(&manifest_value("core"));
    let signed = sign(&manifest, &key, "unregistered");

    let verifier = Ed25519Verifier::new().with_key("release-2026", key.verifying_key().to_bytes());
    assert_eq!(
        verifier.verify(&VerificationRequest {
            manifest: &signed,
            component_sha256: &signed.component.sha256,
        }),
        Err(VerificationError::UnknownKey {
            key_id: "unregistered".to_owned()
        })
    );
}

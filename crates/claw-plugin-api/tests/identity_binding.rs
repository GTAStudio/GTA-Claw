//! A trusted signing key does not let a component claim any identity it likes.
//!
//! Each test builds a policy that trusts the attacker's key host-wide and then
//! shows that the per-identity binding still refuses the impersonation.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use claw_plugin_api::manifest::{ManifestSignature, PluginManifest, SignatureAlgorithm};
use claw_plugin_api::registry::{DeliveryClass, PluginRegistry};
use claw_plugin_api::trust::{IdentityBinding, TrustError, TrustPolicy, component_sha256};
use serde_json::{Value, json};

const COMPONENT_BYTES: &[u8] = b"\0asm\x0d\x00\x01\x00 identity binding fixture bytes";

fn manifest_value(id: &str, delivery_class: &str) -> Value {
    json!({
        "manifest_version": 1,
        "id": id,
        "display_name": "Identity fixture",
        "description": "Plugin manifest used by the identity binding integration tests.",
        "version": "1.4.2",
        "abi_version": "1.0.0",
        "delivery_class": delivery_class,
        "component": {
            "path": "component/identity.wasm",
            "sha256": component_sha256(COMPONENT_BYTES),
            "size_bytes": COMPONENT_BYTES.len()
        },
        "capabilities": []
    })
}

fn parse(value: &Value) -> PluginManifest {
    PluginManifest::parse(&serde_json::to_vec(value).expect("encode")).expect("valid manifest")
}

/// Attaches a syntactically valid signature. `authorize` inspects only the key
/// id, so no real key material is needed to exercise the binding checks.
fn signed(mut manifest: PluginManifest, key_id: &str) -> PluginManifest {
    manifest.signature = Some(ManifestSignature {
        key_id: key_id.to_owned(),
        algorithm: SignatureAlgorithm::Ed25519,
        value: "A".repeat(86),
    });
    manifest
}

fn write_plugin(dir: &Path) -> PathBuf {
    fs::create_dir_all(dir.join("component")).expect("create component dir");
    fs::write(dir.join("component").join("identity.wasm"), COMPONENT_BYTES)
        .expect("write component");
    dir.to_path_buf()
}

fn policy_trusting_both_keys(root: &Path, binding: IdentityBinding) -> TrustPolicy {
    TrustPolicy::deny_all()
        .with_root(root)
        .require_signature(false)
        .allow_delivery_class(DeliveryClass::Core)
        .allow_delivery_class(DeliveryClass::OfficialExternal)
        .with_trusted_key_id("official-key")
        .with_trusted_key_id("community-key")
        .with_identity_binding(binding)
}

#[test]
fn a_trusted_key_cannot_sign_an_identity_it_is_not_bound_to() {
    let temp = support::tempdir();
    let dir = write_plugin(&temp.path().join("victim"));
    let policy = policy_trusting_both_keys(
        temp.path(),
        IdentityBinding::new("victim-plugin", DeliveryClass::Core, &dir)
            .with_key_id("official-key"),
    );

    // `community-key` is trusted host-wide but is not bound to this identity.
    let hostile = signed(
        parse(&manifest_value("victim-plugin", "core")),
        "community-key",
    );
    assert_eq!(
        policy.authorize(&dir, &hostile),
        Err(TrustError::BindingKeyMismatch {
            plugin_id: "victim-plugin".to_owned(),
            key_id: Some("community-key".to_owned()),
        })
    );

    // The bound key still works, so the refusal above was the binding and not
    // host-wide key trust.
    let honest = signed(
        parse(&manifest_value("victim-plugin", "core")),
        "official-key",
    );
    let decision = policy
        .authorize(&dir, &honest)
        .expect("the bound key must pass");
    assert_eq!(decision.signing_key_id(), Some("official-key"));
}

#[test]
fn a_bound_identity_cannot_upgrade_its_own_delivery_class() {
    let temp = support::tempdir();
    let dir = write_plugin(&temp.path().join("external"));
    let policy = policy_trusting_both_keys(
        temp.path(),
        IdentityBinding::new("external-plugin", DeliveryClass::OfficialExternal, &dir)
            .with_key_id("official-key"),
    );

    let escalated = signed(
        parse(&manifest_value("external-plugin", "core")),
        "official-key",
    );
    assert_eq!(
        policy.authorize(&dir, &escalated),
        Err(TrustError::BindingClassMismatch {
            plugin_id: "external-plugin".to_owned(),
            bound: DeliveryClass::OfficialExternal,
            declared: DeliveryClass::Core,
        })
    );

    let honest = signed(
        parse(&manifest_value("external-plugin", "official_external")),
        "official-key",
    );
    policy
        .authorize(&dir, &honest)
        .expect("the bound class must pass");
}

#[test]
fn a_bound_identity_cannot_be_loaded_from_a_different_directory() {
    let temp = support::tempdir();
    let dir = write_plugin(&temp.path().join("expected"));
    let decoy = write_plugin(&temp.path().join("decoy"));
    let policy = policy_trusting_both_keys(
        temp.path(),
        IdentityBinding::new("pinned-plugin", DeliveryClass::Core, &dir)
            .with_key_id("official-key"),
    );

    let manifest = signed(
        parse(&manifest_value("pinned-plugin", "core")),
        "official-key",
    );
    policy
        .authorize(&dir, &manifest)
        .expect("the bound location must pass");

    assert_eq!(
        policy.authorize(&decoy, &manifest),
        Err(TrustError::BindingLocationMismatch {
            plugin_id: "pinned-plugin".to_owned(),
            bound: fs::canonicalize(&dir).expect("canonicalize the bound directory"),
            found: fs::canonicalize(&decoy).expect("canonicalize the decoy"),
        })
    );
}

#[test]
fn an_identity_binding_with_no_keys_accepts_only_an_unsigned_manifest() {
    let temp = support::tempdir();
    let dir = write_plugin(&temp.path().join("unsigned"));
    let policy = policy_trusting_both_keys(
        temp.path(),
        IdentityBinding::new("unsigned-plugin", DeliveryClass::Core, &dir),
    );

    let plain = parse(&manifest_value("unsigned-plugin", "core"));
    let decision = policy
        .authorize(&dir, &plain)
        .expect("an unsigned manifest must pass");
    assert_eq!(decision.signing_key_id(), None);

    assert_eq!(
        policy.authorize(&dir, &signed(plain, "official-key")),
        Err(TrustError::BindingKeyMismatch {
            plugin_id: "unsigned-plugin".to_owned(),
            key_id: Some("official-key".to_owned()),
        })
    );
}

#[test]
fn a_frozen_registry_id_always_needs_a_binding_even_when_bindings_are_optional() {
    let temp = support::tempdir();
    let dir = write_plugin(&temp.path().join("registry"));
    // A real id taken from the frozen inventory at run time, so this test
    // cannot drift away from the registry it is protecting.
    let reserved = PluginRegistry::all()
        .find(|descriptor| descriptor.delivery_class() == DeliveryClass::Core)
        .expect("the frozen inventory has core plugins");

    let policy = TrustPolicy::deny_all()
        .with_root(temp.path())
        .require_signature(false)
        .require_identity_binding(false)
        .allow_delivery_class(DeliveryClass::Core);

    assert_eq!(
        policy.authorize(&dir, &parse(&manifest_value(reserved.id(), "core"))),
        Err(TrustError::UnboundIdentity {
            plugin_id: reserved.id().to_owned(),
            reserved: true,
        })
    );

    // An id the frozen inventory does not reserve passes while bindings are
    // optional, so the refusal above came from the registry check.
    policy
        .authorize(&dir, &parse(&manifest_value("not-a-frozen-id", "core")))
        .expect("an unreserved id may be unbound when bindings are optional");
}

#[test]
fn a_frozen_registry_id_cannot_declare_the_wrong_delivery_class() {
    let temp = support::tempdir();
    let dir = write_plugin(&temp.path().join("class"));
    let reserved = PluginRegistry::all()
        .find(|descriptor| descriptor.delivery_class() == DeliveryClass::Core)
        .expect("the frozen inventory has core plugins");

    let policy = TrustPolicy::deny_all()
        .with_root(temp.path())
        .require_signature(false)
        .require_identity_binding(false)
        .allow_delivery_class(DeliveryClass::Core)
        .allow_delivery_class(DeliveryClass::OfficialExternal)
        .with_identity_binding(IdentityBinding::new(
            reserved.id(),
            DeliveryClass::OfficialExternal,
            &dir,
        ));

    assert_eq!(
        policy.authorize(
            &dir,
            &parse(&manifest_value(reserved.id(), "official_external"))
        ),
        Err(TrustError::RegistryClassMismatch {
            plugin_id: reserved.id().to_owned(),
            registry: DeliveryClass::Core,
            declared: DeliveryClass::OfficialExternal,
        })
    );
}

#[test]
fn requiring_bindings_is_the_default_and_refuses_an_unknown_id() {
    let temp = support::tempdir();
    let dir = write_plugin(&temp.path().join("stranger"));
    let policy = TrustPolicy::deny_all()
        .with_root(temp.path())
        .require_signature(false)
        .allow_delivery_class(DeliveryClass::Core);
    assert!(policy.identity_binding_required());

    assert_eq!(
        policy.authorize(&dir, &parse(&manifest_value("stranger-plugin", "core"))),
        Err(TrustError::UnboundIdentity {
            plugin_id: "stranger-plugin".to_owned(),
            reserved: false,
        })
    );
    assert!(policy.identity_binding("stranger-plugin").is_none());
}

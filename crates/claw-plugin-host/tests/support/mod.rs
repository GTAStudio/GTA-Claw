//! Shared helpers for the host integration tests.
//!
//! Every fixture here is a real WebAssembly component: the text in
//! `tests/fixtures/probe-guest.wat` is assembled by `wat` at test time and
//! handed to Wasmtime unchanged.

#![expect(
    dead_code,
    unreachable_pub,
    reason = "this module is compiled separately into every integration test binary, so each \
              binary sees the helpers the other binaries use as unused `pub` items; splitting it \
              per binary would duplicate the fixtures the tests are meant to share"
)]

pub mod qa;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use claw_plugin_api::capability::{CapabilityGrant, CapabilitySet};
use claw_plugin_api::limits::ResourceLimits;
use claw_plugin_api::manifest::{
    ComponentRef, MANIFEST_VERSION, ManifestSignature, PluginManifest, SignatureAlgorithm,
};
use claw_plugin_api::policy::OperatorPolicy;
use claw_plugin_api::registry::DeliveryClass;
use claw_plugin_api::trust::{IdentityBinding, TrustPolicy, component_sha256, signing_payload};
use ed25519_dalek::{Signer, SigningKey};

/// The component text every fixture is derived from.
pub const PROBE_WAT: &str = include_str!("../fixtures/probe-guest.wat");

/// The identity the probe component reports from `describe`.
pub const PROBE_ID: &str = "gta-claw-fixture-probe";
/// The version the probe component reports from `describe`.
pub const PROBE_VERSION: &str = "0.1.0";

/// Assembles the unmodified probe component.
#[must_use]
pub fn probe_component() -> Vec<u8> {
    wat::parse_str(PROBE_WAT).expect("the probe fixture must assemble")
}

/// Assembles a probe whose no-op tool returns an empty JSON object.
#[must_use]
pub fn probe_component_returning_json() -> Vec<u8> {
    let source = probe_wat_lf();
    let text = source.replacen(
        "(data (i32.const 1048) \"ok\")",
        "(data (i32.const 1048) \"{}\")",
        1,
    );
    assert_ne!(text, source, "the JSON response must have been inserted");
    wat::parse_str(&text).expect("the JSON probe fixture must assemble")
}

/// Assembles a probe whose unknown-tool error exceeds the fixture id length.
#[must_use]
pub fn probe_component_with_oversized_error() -> Vec<u8> {
    let source = probe_wat_lf();
    let text = source.replacen(
        "(i32.store (i32.const 268) (i32.const 13))",
        "(i32.store (i32.const 268) (i32.const 30))",
        1,
    );
    assert_ne!(text, source, "the oversized error must have been inserted");
    wat::parse_str(&text).expect("the oversized-error probe fixture must assemble")
}

/// A self-deleting directory beneath the system temporary directory.
///
/// This replaces the `tempfile` crate. `tempfile` seeds its name generator from
/// a newer `getrandom` line than the one `ring` already resolves in the root
/// dependency graph, and the root `deny.toml` - a frozen trust-root file that
/// cannot be edited - denies duplicate crate versions.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a fresh directory that no other test can collide with.
    ///
    /// Uniqueness comes from the process id (distinct per test binary), the
    /// creation timestamp and a per-process counter, so no randomness is
    /// required.
    pub fn new() -> std::io::Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "claw-plugin-test-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// The directory itself.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Creates a self-deleting temporary directory, panicking on failure.
#[must_use]
pub fn tempdir() -> TempDir {
    TempDir::new().expect("the system temporary directory must be writable")
}

/// A trust policy that accepts unsigned core plugins below `root`.
///
/// Everything else stays closed: no other root, no other delivery class.
/// Identity bindings are relaxed for ids outside the frozen registry, because
/// the fixture id is not a real plugin; `tests/identity_binding.rs` exercises
/// the binding rules directly, including the ones that cannot be relaxed.
#[must_use]
pub fn unsigned_core_policy(root: &Path) -> TrustPolicy {
    TrustPolicy::deny_all()
        .with_root(root.to_path_buf())
        .require_signature(false)
        .require_identity_binding(false)
        .allow_delivery_class(DeliveryClass::Core)
}

/// A trust policy that additionally binds `id` to `directory`.
#[must_use]
pub fn bound_core_policy(root: &Path, directory: &Path, id: &str) -> TrustPolicy {
    unsigned_core_policy(root)
        .require_identity_binding(true)
        .with_identity_binding(IdentityBinding::new(
            id,
            DeliveryClass::Core,
            directory.to_path_buf(),
        ))
}

/// An operator ceiling that allows `plugin_id` exactly `grants`.
///
/// Tests that are about the *runtime* capability boundary use this so the
/// intersection is the identity function and the grant under test survives it
/// unchanged. Tests that are about the ceiling itself build their own.
#[must_use]
pub fn ceiling_for(plugin_id: &str, grants: Vec<CapabilityGrant>) -> OperatorPolicy {
    let set = CapabilitySet::new(grants).expect("the ceiling must be a valid capability set");
    OperatorPolicy::deny_all().allow(plugin_id, set)
}

/// An operator ceiling for the probe fixture allowing exactly `grants`.
#[must_use]
pub fn probe_ceiling(grants: Vec<CapabilityGrant>) -> OperatorPolicy {
    ceiling_for(PROBE_ID, grants)
}

/// An operator ceiling matching whatever the manifest in `directory` requests.
///
/// This deliberately makes the intersection an identity function, because the
/// tests that use it are about what the *runtime* boundary does with a granted
/// capability. The ceiling's own narrowing and withholding behaviour is proved
/// separately, in `tests/operator_policy.rs` and in the `claw-plugin-api` unit
/// tests, where the ceiling and the request differ.
#[must_use]
pub fn ceiling_from(directory: &Path) -> OperatorPolicy {
    ceiling_from_all(&[directory])
}

/// The union of [`ceiling_from`] over several plugin directories.
///
/// Panics when two directories claim the same plugin id, since that would
/// silently drop one of the ceilings.
#[must_use]
pub fn ceiling_from_all(directories: &[&Path]) -> OperatorPolicy {
    let mut policy = OperatorPolicy::deny_all();
    let mut seen = std::collections::BTreeSet::new();
    for directory in directories {
        let bytes = std::fs::read(directory.join("plugin.json")).expect("read the manifest back");
        let manifest: PluginManifest =
            serde_json::from_slice(&bytes).expect("the manifest must parse");
        assert!(
            seen.insert(manifest.id.clone()),
            "two fixtures claim the plugin id `{}`",
            manifest.id
        );
        let set = CapabilitySet::new(manifest.capabilities)
            .expect("the ceiling must be a valid capability set");
        policy = policy.allow(manifest.id, set);
    }
    policy
}

/// Assembles a probe component that also imports a WASI interface.
///
/// Nothing else changes, so a rejection can only be caused by the extra
/// import rather than by a malformed or incomplete component.
#[must_use]
pub fn probe_component_importing_wasi(interface: &str) -> Vec<u8> {
    let anchor = "  ;; ---------------------------------------------------------------- imports";
    assert!(
        PROBE_WAT.contains(anchor),
        "the fixture must still carry its host-imports anchor"
    );
    let text = PROBE_WAT.replacen(
        anchor,
        &format!("  (import \"{interface}\" (instance))\n{anchor}"),
        1,
    );
    assert_ne!(text, PROBE_WAT, "the wasi import must have been inserted");
    wat::parse_str(&text).expect("the wasi fixture must assemble")
}

/// Assembles a probe component that exports the wrong interface name.
#[must_use]
pub fn probe_component_without_guest_export() -> Vec<u8> {
    let text = PROBE_WAT.replacen(
        "(export \"gta-claw:plugin/guest@1.0.0\" (instance $guest-exports))",
        "(export \"gta-claw:plugin/not-guest@1.0.0\" (instance $guest-exports))",
        1,
    );
    assert_ne!(text, PROBE_WAT, "the export rename must have been applied");
    wat::parse_str(&text).expect("the renamed fixture must assemble")
}

/// Assembles a probe component that reports a different plugin id.
///
/// The id lives in a data segment whose length is baked into `describe`, so
/// only same-length ids are accepted here. That keeps the fixture honest: the
/// component really does report the id the manifest claims.
#[must_use]
pub fn probe_component_named(id: &str) -> Vec<u8> {
    assert_eq!(
        id.len(),
        PROBE_ID.len(),
        "a renamed probe id must be exactly {} bytes",
        PROBE_ID.len()
    );
    let text = PROBE_WAT.replacen(
        &format!("(data (i32.const 1024) \"{PROBE_ID}\")"),
        &format!("(data (i32.const 1024) \"{id}\")"),
        1,
    );
    assert_ne!(text, PROBE_WAT, "the id replacement must have been applied");
    wat::parse_str(&text).expect("the renamed fixture must assemble")
}

/// The fixture source with line endings normalised.
///
/// The `.wat` may be checked out with CRLF on Windows, so every anchor-based
/// helper below works against this normalised copy rather than `PROBE_WAT`.
fn probe_wat_lf() -> String {
    PROBE_WAT.replace("\r\n", "\n")
}

/// Assembles a probe component that reads a file from inside `describe`.
///
/// `describe` runs before the host has established that the component really is
/// the plugin its manifest names, so a host call there must be refused no
/// matter what the manifest was granted.
#[must_use]
pub fn probe_component_reading_during_describe() -> Vec<u8> {
    let source = probe_wat_lf();
    let anchor = "    (func (export \"describe\") (result i32)\n";
    assert!(source.contains(anchor), "the describe anchor must exist");
    let text = source.replacen(
        anchor,
        &format!(
            "{anchor}      (call $h-fs-read (i32.const 1064) (i32.const 9) (i32.const 288))\n"
        ),
        1,
    );
    assert_ne!(text, source, "the describe host call must be inserted");
    wat::parse_str(&text).expect("the describe fixture must assemble")
}

/// Assembles a probe component that logs and emits an event from `deactivate`.
///
/// `log` is in the cleanup set and must still work; `events` is not and must be
/// refused, even though both were granted for the active window.
#[must_use]
pub fn probe_component_calling_during_deactivate() -> Vec<u8> {
    let source = probe_wat_lf();
    let anchor = "    (func (export \"deactivate\") (result i32)\n";
    assert!(source.contains(anchor), "the deactivate anchor must exist");
    let injected = concat!(
        "      (call $h-log (i32.const 2) (i32.const 1048) (i32.const 2) (i32.const 288))\n",
        "      (call $h-events\n",
        "        (i32.const 5) (i64.const 0)\n",
        "        (i32.const 1052) (i32.const 5)\n",
        "        (i32.const 1120) (i32.const 2)\n",
        "        (i32.const 288))\n",
    );
    let text = source.replacen(anchor, &format!("{anchor}{injected}"), 1);
    assert_ne!(text, source, "the deactivate host calls must be inserted");
    wat::parse_str(&text).expect("the deactivate fixture must assemble")
}

/// Assembles a probe whose `deactivate` export returns an ABI error.
#[must_use]
pub fn probe_component_failing_deactivate() -> Vec<u8> {
    let source = probe_wat_lf();
    let original = concat!(
        "    (func (export \"deactivate\") (result i32)\n",
        "      (i32.store8 (i32.const 192) (i32.const 0))\n",
        "      (i32.const 192))\n",
    );
    let replacement = concat!(
        "    (func (export \"deactivate\") (result i32)\n",
        "      (i32.store8 (i32.const 192) (i32.const 1))\n",
        "      (i32.store8 (i32.const 196) (i32.const 0))\n",
        "      (i32.store (i32.const 200) (i32.const 1136))\n",
        "      (i32.store (i32.const 204) (i32.const 13))\n",
        "      (i32.const 192))\n",
    );
    let text = source.replacen(original, replacement, 1);
    assert_ne!(text, source, "the deactivation error must be inserted");
    wat::parse_str(&text).expect("the deactivation-error fixture must assemble")
}

/// Assembles a probe whose `deactivate` export never returns on its own.
#[must_use]
pub fn probe_component_spinning_on_deactivate() -> Vec<u8> {
    let source = probe_wat_lf();
    let original = concat!(
        "    (func (export \"deactivate\") (result i32)\n",
        "      (i32.store8 (i32.const 192) (i32.const 0))\n",
        "      (i32.const 192))\n",
    );
    let replacement = concat!(
        "    (func (export \"deactivate\") (result i32)\n",
        "      (loop $deactivate-spin (br $deactivate-spin))\n",
        "      (i32.const 192))\n",
    );
    let text = source.replacen(original, replacement, 1);
    assert_ne!(text, source, "the deactivation loop must be inserted");
    wat::parse_str(&text).expect("the spinning-deactivation fixture must assemble")
}

/// Assembles a probe component that registers `count` distinct tools.
///
/// Names are `ta`, `tb`, ... so a quota of *n* can be tested by asking for more
/// than *n*. The answer is the two-byte code of the *last* registration that
/// was attempted, so a refusal in the middle is visible.
#[must_use]
pub fn probe_component_registering_tools(count: u32) -> Vec<u8> {
    assert!(
        (1..=26).contains(&count),
        "the fixture supports 1..=26 tools"
    );
    let source = probe_wat_lf();
    let anchor = "      ;; l: host-events.emit";
    assert!(source.contains(anchor), "the emit anchor must exist");
    let mut body = String::from("      ;; z: register several distinct tools\n");
    body.push_str("      (if (i32.eq (local.get $selector) (i32.const 122))\n        (then\n");
    for index in 0..count {
        // Each name is two bytes: `t` followed by a distinct letter, written
        // into scratch memory (between the answer buffer and the literals, so
        // it cannot collide with a `cabi_realloc` allocation) before the call.
        write!(
            body,
            "          (i32.store8 (i32.const 640) (i32.const 116))\n          (i32.store8 (i32.const 641) (i32.const {}))\n          (call $h-tools\n            (i32.const 640) (i32.const 2)\n            (i32.const 1108) (i32.const 10)\n            (i32.const 1120) (i32.const 2)\n            (i32.const 288))\n",
            97 + index
        )
        .expect("writing to a `String` cannot fail");
    }
    body.push_str("          (return (call $answer (i32.const 288) (i32.const 4)))))\n");
    let text = source.replacen(anchor, &format!("{body}{anchor}"), 1);
    assert_ne!(text, source, "the tool loop must be inserted");
    wat::parse_str(&text).expect("the tool-quota fixture must assemble")
}

/// Assembles a probe whose `y` tool replaces the stock registration with invalid JSON.
#[must_use]
pub fn probe_component_registering_invalid_replacement() -> Vec<u8> {
    let source = probe_wat_lf();
    let anchor = "      ;; l: host-events.emit";
    assert!(source.contains(anchor), "the emit anchor must exist");
    let body = concat!(
        "      ;; y: replace `probe` with an invalid schema\n",
        "      (if (i32.eq (local.get $selector) (i32.const 121))\n",
        "        (then\n",
        "          (i32.store8 (i32.const 640) (i32.const 123))\n",
        "          (call $h-tools\n",
        "            (i32.const 1052) (i32.const 5)\n",
        "            (i32.const 1108) (i32.const 10)\n",
        "            (i32.const 640) (i32.const 1)\n",
        "            (i32.const 288))\n",
        "          (return (call $answer (i32.const 288) (i32.const 4)))))\n",
    );
    let text = source.replacen(anchor, &format!("{body}{anchor}"), 1);
    assert_ne!(text, source, "the invalid replacement must be inserted");
    wat::parse_str(&text).expect("the invalid-replacement fixture must assemble")
}

/// Assembles a probe that registers one tool and then spins during activation.
#[must_use]
pub fn probe_component_registering_tool_then_spinning_on_activate() -> Vec<u8> {
    let source = probe_wat_lf();
    let original = concat!(
        "    (func (export \"activate\") (result i32)\n",
        "      (i32.store8 (i32.const 192) (i32.const 0))\n",
        "      (i32.const 192))\n",
    );
    let replacement = concat!(
        "    (func (export \"activate\") (result i32)\n",
        "      (call $h-tools\n",
        "        (i32.const 1052) (i32.const 5)\n",
        "        (i32.const 1108) (i32.const 10)\n",
        "        (i32.const 1120) (i32.const 2)\n",
        "        (i32.const 288))\n",
        "      (loop $activate-spin (br $activate-spin))\n",
        "      (i32.const 192))\n",
    );
    let text = source.replacen(original, replacement, 1);
    assert_ne!(text, source, "the activation loop must be inserted");
    wat::parse_str(&text).expect("the activation-loop fixture must assemble")
}

/// Assembles a probe that registers during activation and logs from deactivate.
#[must_use]
pub fn probe_component_registering_tool_on_activate_and_logging_on_deactivate() -> Vec<u8> {
    let source = probe_wat_lf();
    let activate = concat!(
        "    (func (export \"activate\") (result i32)\n",
        "      (i32.store8 (i32.const 192) (i32.const 0))\n",
        "      (i32.const 192))\n",
    );
    let replacement = concat!(
        "    (func (export \"activate\") (result i32)\n",
        "      (call $h-tools\n",
        "        (i32.const 1052) (i32.const 5)\n",
        "        (i32.const 1108) (i32.const 10)\n",
        "        (i32.const 1120) (i32.const 2)\n",
        "        (i32.const 288))\n",
        "      (i32.store8 (i32.const 192) (i32.const 0))\n",
        "      (i32.const 192))\n",
    );
    let text = source.replacen(activate, replacement, 1);
    let deactivate = "    (func (export \"deactivate\") (result i32)\n";
    let text = text.replacen(
        deactivate,
        &format!(
            "{deactivate}      (call $h-log (i32.const 2) (i32.const 1048) (i32.const 2) (i32.const 288))\n"
        ),
        1,
    );
    assert_ne!(text, source, "the lifecycle hooks must be inserted");
    wat::parse_str(&text).expect("the activation-rollback fixture must assemble")
}

/// Assembles a probe that registers during activation and never finishes deactivation.
#[must_use]
pub fn probe_component_registering_tool_on_activate_then_spinning_on_deactivate() -> Vec<u8> {
    let source = probe_wat_lf();
    let activate = concat!(
        "    (func (export \"activate\") (result i32)\n",
        "      (i32.store8 (i32.const 192) (i32.const 0))\n",
        "      (i32.const 192))\n",
    );
    let active = concat!(
        "    (func (export \"activate\") (result i32)\n",
        "      (call $h-tools\n",
        "        (i32.const 1052) (i32.const 5)\n",
        "        (i32.const 1108) (i32.const 10)\n",
        "        (i32.const 1120) (i32.const 2)\n",
        "        (i32.const 288))\n",
        "      (i32.store8 (i32.const 192) (i32.const 0))\n",
        "      (i32.const 192))\n",
    );
    let deactivate = concat!(
        "    (func (export \"deactivate\") (result i32)\n",
        "      (i32.store8 (i32.const 192) (i32.const 0))\n",
        "      (i32.const 192))\n",
    );
    let spinning = concat!(
        "    (func (export \"deactivate\") (result i32)\n",
        "      (loop $deactivate-spin (br $deactivate-spin))\n",
        "      (i32.const 192))\n",
    );
    let text = source
        .replacen(activate, active, 1)
        .replacen(deactivate, spinning, 1);
    assert_ne!(text, source, "the lifecycle hooks must be inserted");
    wat::parse_str(&text).expect("the bounded-rollback fixture must assemble")
}

/// A manifest describing `component` with no capabilities and default limits.
#[must_use]
pub fn manifest_for(component: &[u8]) -> PluginManifest {
    PluginManifest {
        manifest_version: MANIFEST_VERSION,
        id: PROBE_ID.to_owned(),
        display_name: "Probe fixture".to_owned(),
        description: "A component fixture used by the host integration tests.".to_owned(),
        version: PROBE_VERSION.to_owned(),
        abi_version: "1.0.0".to_owned(),
        delivery_class: DeliveryClass::Core,
        component: ComponentRef {
            path: "component.wasm".to_owned(),
            sha256: component_sha256(component),
            size_bytes: component.len() as u64,
        },
        capabilities: Vec::new(),
        limits: ResourceLimits::default(),
        signature: None,
    }
}

/// Signs a manifest with the host contract's canonical Ed25519 payload.
#[must_use]
pub fn sign_manifest(manifest: &PluginManifest, key: &SigningKey, key_id: &str) -> PluginManifest {
    let payload = signing_payload(manifest).expect("the fixture manifest must serialize");
    let signature = key.sign(&payload);
    let mut value = String::with_capacity(128);
    for byte in signature.to_bytes() {
        write!(value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    PluginManifest {
        signature: Some(ManifestSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: key_id.to_owned(),
            value,
        }),
        ..manifest.clone()
    }
}

/// Writes `component` and `manifest` into a fresh directory below `root`.
///
/// The manifest is written verbatim, so a test can deliberately desynchronise
/// it from the bytes on disk.
pub fn install(
    root: &Path,
    directory: &str,
    component: &[u8],
    manifest: &PluginManifest,
) -> PathBuf {
    let dir = root.join(directory);
    std::fs::create_dir_all(&dir).expect("create the plugin directory");
    std::fs::write(dir.join(&manifest.component.path), component).expect("write the component");
    let json = serde_json::to_vec_pretty(manifest).expect("serialise the manifest");
    std::fs::write(dir.join("plugin.json"), json).expect("write the manifest");
    dir
}

/// Installs the unmodified probe with the given capability grants.
pub fn install_probe(root: &Path, directory: &str, grants: Vec<CapabilityGrant>) -> PathBuf {
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.capabilities = grants;
    install(root, directory, &component, &manifest)
}

/// Installs the probe with grants and adjusted limits.
pub fn install_probe_with(
    root: &Path,
    directory: &str,
    grants: Vec<CapabilityGrant>,
    limits: ResourceLimits,
) -> PathBuf {
    let component = probe_component();
    let mut manifest = manifest_for(&component);
    manifest.capabilities = grants;
    manifest.limits = limits;
    install(root, directory, &component, &manifest)
}

/// Installs a probe that reports (and claims) a different plugin id.
pub fn install_probe_named(
    root: &Path,
    directory: &str,
    id: &str,
    grants: Vec<CapabilityGrant>,
) -> PathBuf {
    let component = probe_component_named(id);
    let mut manifest = manifest_for(&component);
    id.clone_into(&mut manifest.id);
    manifest.capabilities = grants;
    install(root, directory, &component, &manifest)
}

/// Installs an arbitrary probe variant with the given grants.
pub fn install_variant(
    root: &Path,
    directory: &str,
    component: &[u8],
    grants: Vec<CapabilityGrant>,
) -> PathBuf {
    let mut manifest = manifest_for(component);
    manifest.capabilities = grants;
    install(root, directory, component, &manifest)
}

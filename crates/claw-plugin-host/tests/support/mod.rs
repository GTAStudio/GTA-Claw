//! Shared helpers for the host integration tests.
//!
//! Every fixture here is a real WebAssembly component: the text in
//! `tests/fixtures/probe-guest.wat` is assembled by `wat` at test time and
//! handed to Wasmtime unchanged.

#![allow(dead_code, unreachable_pub)]

use std::path::{Path, PathBuf};

use claw_plugin_api::capability::CapabilityGrant;
use claw_plugin_api::limits::ResourceLimits;
use claw_plugin_api::manifest::{ComponentRef, MANIFEST_VERSION, PluginManifest};
use claw_plugin_api::registry::DeliveryClass;
use claw_plugin_api::trust::{TrustPolicy, component_sha256};

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

/// A trust policy that accepts unsigned core plugins below `root`.
///
/// Everything else stays closed: no other root, no other delivery class.
#[must_use]
pub fn unsigned_core_policy(root: &Path) -> TrustPolicy {
    TrustPolicy::deny_all()
        .with_root(root.to_path_buf())
        .require_signature(false)
        .allow_delivery_class(DeliveryClass::Core)
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
    manifest.id = id.to_owned();
    manifest.capabilities = grants;
    install(root, directory, &component, &manifest)
}

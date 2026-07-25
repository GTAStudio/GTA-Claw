//! The GTA-Claw WebAssembly plugin contract.
//!
//! GTA-Claw plugins are sandboxed WebAssembly components. They are never
//! JavaScript, and this crate contains no script engine, no package manager
//! integration and no network client. It defines the parts of the plugin system
//! that both the host and out-of-process tooling need to agree on:
//!
//! * [`abi`] - the ABI version carried by the WIT world and the host/guest
//!   compatibility policy.
//! * [`capability`] - the deny-by-default capability model and the scope types
//!   the host enforces at its import boundary.
//! * [`limits`] - the per-plugin resource envelope.
//! * [`manifest`] - the strict plugin manifest schema and its validation.
//! * [`policy`] - the operator-owned capability ceiling a manifest's requests
//!   are intersected with, so a manifest can only ever narrow what the operator
//!   allowed.
//! * [`trust`] - where components may be loaded from, which key may sign for
//!   which plugin identity, plus manifest signature verification.
//! * [`registry`] - all 137 descriptors from the frozen upstream inventory,
//!   with an explicit and deliberately conservative implementation status.
//!
//! The WIT world itself lives in `wit/gta-claw-plugin/world.wit` and is
//! re-exported here as [`WIT_WORLD`] so tools can embed it without guessing a
//! path. `claw-plugin-host` generates its bindings from the same file, so the
//! string below and the compiled ABI cannot drift apart.

pub mod abi;
pub mod capability;
pub mod limits;
pub mod manifest;
pub mod policy;
pub mod registry;
mod registry_data;
pub mod trust;

pub use registry_data::BASELINE_SHA;

/// The full text of the WIT world this ABI generation defines.
pub const WIT_WORLD: &str = include_str!("../../../wit/gta-claw-plugin/world.wit");

/// Path of the WIT package directory relative to the workspace root.
pub const WIT_PACKAGE_DIR: &str = "wit/gta-claw-plugin";

#[cfg(test)]
mod tests {
    use super::{BASELINE_SHA, WIT_WORLD};

    #[test]
    fn the_embedded_wit_declares_the_versioned_package_and_world() {
        assert!(
            WIT_WORLD.contains("package gta-claw:plugin@1.0.0;"),
            "the WIT package version is the ABI version"
        );
        assert!(WIT_WORLD.contains("world plugin {"));
        assert!(WIT_WORLD.contains("export guest;"));
    }

    #[test]
    fn the_wit_world_imports_no_wasi_interface() {
        let code_only: String = WIT_WORLD
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code_only.contains("wasi:"),
            "the plugin world must never reference a wasi interface"
        );
        assert!(
            code_only.contains("interface guest {"),
            "comment stripping must not have removed the world body"
        );
    }

    #[test]
    fn every_capability_has_a_host_interface_in_the_wit_world() {
        for interface in [
            "interface host-log",
            "interface host-config",
            "interface host-store",
            "interface host-fs",
            "interface host-http",
            "interface host-clock",
            "interface host-random",
            "interface host-tools",
            "interface host-events",
        ] {
            assert!(WIT_WORLD.contains(interface), "missing `{interface}`");
        }
    }

    #[test]
    fn the_baseline_sha_matches_the_frozen_upstream_commit() {
        assert_eq!(BASELINE_SHA, "b43e832fcc8000ed7287c7accc54e381db607f85");
    }
}

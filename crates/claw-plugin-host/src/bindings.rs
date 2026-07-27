//! Generated bindings for the `gta-claw:plugin@1.0.0` world.
//!
//! Nothing here is checked in: `bindgen!` re-expands `wit/gta-claw-plugin` on
//! every build, so the items below have no source file to annotate and must
//! never be hand-edited. The macro is still expanded in its own private module
//! so that any future need to relax a lint for the expansion stays contained
//! to this file. It needs no relaxation today: the expansion is an external
//! macro, and this module is `pub(crate)`, so neither the workspace
//! documentation lints (`missing_docs`, `unreachable_pub`) nor the Clippy
//! groups fire inside it. A blanket `allow` here would only be able to hide a
//! future problem.

wasmtime::component::bindgen!({
    path: "../../wit/gta-claw-plugin",
    world: "plugin",
    imports: { default: trappable },
});

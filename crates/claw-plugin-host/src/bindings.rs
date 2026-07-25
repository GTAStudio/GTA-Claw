//! Generated bindings for the `gta-claw:plugin@1.0.0` world.
//!
//! The macro is expanded in its own module so the generated items can opt out
//! of the workspace documentation lints without loosening them anywhere else.

#![allow(missing_docs, unreachable_pub, clippy::all, clippy::pedantic)]

wasmtime::component::bindgen!({
    path: "../../wit/gta-claw-plugin",
    world: "plugin",
    imports: { default: trappable },
});

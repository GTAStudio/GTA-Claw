//! Slint iOS shell for GTA Claw.
//!
//! This binary is what the Xcode run script builds with
//! `cargo build --target aarch64-apple-ios --bin gta-claw-ios-shell`. All of the
//! client behaviour lives in the root-workspace `gta-claw-ios` crate; this
//! package is the Slint front end and nothing else.

mod shell;

#[allow(missing_docs, unreachable_pub)]
mod generated_ui {
    slint::include_modules!();
}

fn main() -> Result<(), slint::PlatformError> {
    shell::run()
}

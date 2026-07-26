//! Native Slint Android client for GTA Claw.
//!
//! The crate is split so that only the thinnest possible layer is Android-only:
//!
//! * [`onboarding`] — connection state machine, input policy and redaction.
//! * [`session`] — attempt ownership and Gateway client configuration.
//! * [`controller`] — Tokio ownership of one [`claw_gateway_client::GatewayClient`].
//! * `ui_adapter` — Slint event loop, compiled only for `target_os = "android"`.
//!
//! The first three compile and are tested on the development host, so the
//! behaviour that matters is verified without a device in the loop.

pub mod controller;
pub mod onboarding;
pub mod session;

#[cfg(target_os = "android")]
mod ui_adapter;

#[cfg(target_os = "android")]
#[allow(missing_docs, unreachable_pub)]
mod generated_ui {
    slint::include_modules!();
}

/// Android entry point.
///
/// `android-activity`'s `NativeActivity` glue resolves this symbol by name, so
/// it cannot be mangled. This attribute is the only `unsafe` item in the crate;
/// the function body performs no unsafe operation. The crate lint is `deny`
/// rather than `forbid` for exactly this declaration — every crate under
/// `crates/` and `apps/gta-claw-{cli,daemon}` keeps `forbid`.
///
/// `expect` rather than `allow`: the lint has been verified to fire here, so if
/// a future Slint release stops requiring the unmangled symbol the unfulfilled
/// expectation turns into a warning and `-D warnings` removes this exemption
/// for us.
#[cfg(target_os = "android")]
#[expect(
    unsafe_code,
    reason = "android-activity resolves the unmangled `android_main` symbol by name"
)]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    ui_adapter::run(app);
}

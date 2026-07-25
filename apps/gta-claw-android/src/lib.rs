//! UI-independent Android client core for GTA Claw.
//!
//! This crate holds the parts of the Android client that do not know what draws
//! them:
//!
//! * [`onboarding`] — connection state machine, input policy and redaction.
//! * [`session`] — attempt ownership and Gateway client configuration.
//! * [`identity`] — session device identity from the platform CSPRNG.
//! * [`controller`] — Tokio ownership of one [`claw_gateway_client::GatewayClient`].
//!
//! Nothing here links a toolkit, so the same core serves a native Android shell,
//! headless use and test harnesses, and every behaviour that matters is verified
//! on the development host without a device in the loop.
//!
//! # What this crate is not
//!
//! There is **no Android user interface in this repository**, and this crate
//! does not render, does not own an activity and exports no `android_main`. The
//! repository's supply-chain policy forbids GUI dependencies in workspace
//! members and requires members to inherit `unsafe_code = "forbid"`, which rules
//! out both the toolkit and the unmangled entry-point symbol an Android
//! `cdylib` needs. A shell would have to live outside this workspace and depend
//! on this crate.

pub mod controller;
pub mod identity;
pub mod onboarding;
pub mod session;

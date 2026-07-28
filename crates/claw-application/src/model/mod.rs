//! Value types shared by application ports and their adapters.
//!
//! Nothing here derives serde. The application layer is deliberately free of any serialization
//! framework: adapters that need a wire form own the mapping, exactly as they already must for
//! [`claw_domain::SessionId`], which is defined without serde derives.
//!
//! # Feature gate
//!
//! Gated behind the `runtime-ports` feature so that front-ends linking this
//! crate only for [`Application`](crate::Application) and
//! [`SystemProbe`](crate::SystemProbe) do not inherit `claw-domain`. `test` is
//! in the gate as well so `cargo test -p claw-application` still compiles and
//! runs the suite rather than reporting success over skipped tests.

pub mod approval;
pub mod goal;
pub mod ids;
pub mod message;
pub mod session;
pub mod time;

//! Transport- and storage-independent security primitives for GTA Claw.
//!
//! This crate deliberately contains no network client, TLS terminator, database,
//! operating-system keyring, or private-key persistence implementation. Platform
//! crates provide those adapters through the ports exposed here.

pub mod audit;
pub mod authorization;
pub mod gateway_authz;
pub mod identity;
pub mod pairing;
pub mod secret;
pub mod ssrf;

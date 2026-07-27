//! Authenticated node identity, discovery, and connectivity boundaries.

/// Bonjour and DNS-SD advertisement and browsing.
pub mod dns_sd;
/// Node identity and Gateway protocol compatibility policy.
pub mod identity;
/// Pure-Rust SSH configuration, verification, and forwarding.
pub mod ssh;
/// Tailscale LocalAPI discovery, identity, and exposure policy.
pub mod tailscale;

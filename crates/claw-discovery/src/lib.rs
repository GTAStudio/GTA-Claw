//! Wire-format and fail-closed policy oracles for GTA Claw discovery and fleet.
//!
//! This crate deliberately contains no network runtime, no process spawning and
//! no container client. Every behaviour it covers is a pure function of bytes or
//! of a pinned fixture, so the whole surface is executable on a CI runner that
//! has no multicast interface, no SSH daemon, no tailnet and no Docker socket.
//!
//! It complements the runtime-side discovery and fleet implementation by proving
//! the layers a runtime normally delegates to a third-party crate or to an
//! external CLI:
//!
//! * [`dnssd`] — the RFC 1035 / RFC 6762 / RFC 6763 wire codec, the TXT
//!   key/value contract, and the DNS-SD resolution chain with bailiwick
//!   enforcement.
//! * [`known_hosts`] — the OpenSSH `known_hosts` grammar and its fail-closed
//!   host-key verdicts, including `@revoked` and `@cert-authority` markers and
//!   hashed host entries.
//! * [`tailscale_policy`] — the Tailscale Serve/Funnel authorisation gate that
//!   decides whether an exposure may be created at all.
//! * [`fleet_cli`] — the argument vector planner for local container cells,
//!   covering create, status, logs, backup, doctor and remove.

pub mod dnssd;
pub mod fleet_cli;
pub mod known_hosts;
pub mod tailscale_policy;

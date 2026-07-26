//! The GTA Claw daemon.
//!
//! This crate is the composition root of the product. It owns no domain logic
//! of its own: it decides which implementation satisfies which port, in what
//! order the subsystems come up, and how they go down.
//!
//! # What is real here and what is standing in
//!
//! The composition, the lifecycle, the authorization flow, the task tracking
//! and the shutdown path are real and are what will ship. The subsystem
//! implementations in [`adapters`] are deterministic stand-ins for crates that
//! are still on unmerged branches. Each one implements exactly the port its
//! real counterpart will implement, so swapping them is a one-line change in
//! [`compose`].
//!
//! # The two rules the composition enforces
//!
//! Audits of sibling crates found the same two defects repeatedly, so the
//! composition is built so they cannot occur:
//!
//! 1. A security decision is never reused. Every action that needs authority
//!    asks for it at the moment of the action, and receives a capability that
//!    dies when the run drains or when its lifetime elapses, measured against
//!    the clock read at redemption.
//! 2. Validated objects cross boundaries, never re-resolvable names. A
//!    destination is a set of checked addresses, a tool is a resolved binding,
//!    and a route is a matched route — never a string that a later stage looks
//!    up again.

pub mod adapters;
pub mod compose;
pub mod control;
pub mod ingress;
pub mod runtime;
pub mod services;
pub mod settings;

pub use compose::{Daemon, DaemonBuilder, StopSummary};
pub use ingress::{HttpIngress, http_ingress_id};
pub use runtime::{RuntimeHost, TaskLedger, TokenShutdown, TrackedSpawner};

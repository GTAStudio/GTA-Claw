//! The context-engine service provider interface.
//!
//! Upstream `OpenClaw` describes the context engine as the component between raw session history
//! and the prompt a provider is handed, with a fixed five-phase lifecycle: `bootstrap` opens a
//! session, `ingest` offers items, `assemble` produces a prompt per provider round, `maintain`
//! performs between-round upkeep, and `compact` sheds context under budget pressure. The port
//! itself lives in [`claw_application::ports::context`]; this module is what makes it a *service
//! provider interface* rather than five function signatures.
//!
//! Three pieces:
//!
//! - [`contract`] names each obligation the lifecycle imposes as an [`SpiRequirement`]. The list
//!   is closed, so "conformant" has a definition rather than a vibe.
//! - [`suite`] is the reusable conformance harness. Any implementer — in this repository or in a
//!   plug-in — calls [`verify_spi_conformance`] and gets back an [`SpiReport`] naming exactly
//!   which requirements it failed and what the harness observed.
//! - [`mod@reference`] is a real engine that passes the suite, so the SPI has a working implementer
//!   and the suite has a subject that is meant to succeed.
//!
//! A conformance suite whose only subject passes is worthless, because it cannot distinguish an
//! engine that honours the contract from one that returns plausible numbers. The suite is
//! therefore pinned from the failing side too: `tests/context_engine_spi.rs` runs a mutation
//! matrix of deliberately broken engines, one defect per requirement, and asserts both that each
//! defect is caught and that between them every requirement in the contract is trippable.

pub mod contract;
pub mod reference;
pub mod suite;

pub use contract::{LifecyclePhase, SpiReport, SpiRequirement, SpiViolation};
pub use reference::{ReferenceContextEngine, is_pinned};
pub use suite::{
    CONFORMANCE_TOKEN_BUDGET, PINNED_PROBE_ITEM_COUNT, PROBE_ITEM_COUNT, pinned_markers,
    probe_items, probe_markers, verify_spi_conformance,
};

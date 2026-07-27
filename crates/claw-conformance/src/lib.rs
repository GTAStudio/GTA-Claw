//! Data-driven conformance harness for the frozen `OpenClaw` compatibility data.
//!
//! The harness never changes the authoritative `compat/upstream` artifacts. It
//! loads and validates them, accepts evidence-backed implementation claims, and
//! produces deterministic parity reports.
//!
//! Evidence verification proves that a cited Rust test is literally declared in
//! a standard-libtest Cargo target root in a package admitted by the repository's
//! workspace topology, or a source file reachable through explicit `mod`
//! declarations from one. The resolver follows nested inline modules and exact
//! string-literal `#[path]` overrides within the owning Cargo package while
//! rejecting unreadable overrides without falling back to a same-named module.
//! It also rejects orphan files, unlisted and excluded packages, implicit
//! path-dependency members, cross-package paths, test-disabled targets, and
//! targets with `harness = false`, while retaining standalone build roots outside
//! any declared workspace. Parent-module `cfg` predicates are deliberately not
//! evaluated. This cannot prove that the test ran or is semantically sufficient
//! for the claim.
//! Automated citation integrity therefore composes with independent review:
//! the harness rejects fabricated evidence, while reviewers judge sufficiency.
//! The verifier recognizes literal test declarations only; macro-generated
//! tests are conservatively rejected because their expanded items are unavailable.
//!
//! # Runtime attestation follow-up
//!
//! Closing the remaining execution-provenance gap requires a coordinated,
//! base-owned two-phase CI change. The runner must invoke each citation through
//! one exact standard-libtest Cargo target and require exactly one passing,
//! non-ignored test, then emit a canonical attestation bound to the commit SHA,
//! toolchain, target triple, package, target, command, and result. Both the Rust
//! and PowerShell validators must consume those same attestation bytes. The
//! current frozen workflow runs this conformance check inside the workspace test
//! command, so it cannot consume that command's completed output.

mod claims;
mod error;
mod loader;
mod model;
mod report;

pub use claims::{
    ClaimLevel, ClaimsFile, Evidence, FeatureClaim, ImplementationPointer, InventoryClaim,
    Registry, discover_claim_files,
};
pub use error::{ConformanceError, ViolationCode};
pub use loader::Contract;
pub use model::{Classification, Feature, FeatureLedger, InventoryRecord};
pub use report::{
    FeatureReport, InventoryCoverage, LedgerReport, ParityReport, ParityStatus, ParityTotals,
    generate_report,
};

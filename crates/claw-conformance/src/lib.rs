//! Data-driven conformance harness for the frozen OpenClaw compatibility data.
//!
//! The harness never changes the authoritative `compat/upstream` artifacts. It
//! loads and validates them, accepts evidence-backed implementation claims, and
//! produces deterministic parity reports.
//!
//! Evidence verification proves that a cited Rust test exists and is enabled;
//! it cannot prove that the test is semantically sufficient for the claim.
//! Automated citation integrity therefore composes with independent review:
//! the harness rejects fabricated evidence, while reviewers judge sufficiency.

mod claims;
mod error;
mod loader;
mod model;
mod report;

pub use claims::{
    ClaimLevel, ClaimsFile, Evidence, FeatureClaim, InventoryClaim, Registry, discover_claim_files,
};
pub use error::{ConformanceError, ViolationCode};
pub use loader::Contract;
pub use model::{Classification, Feature, FeatureLedger, InventoryRecord};
pub use report::{
    FeatureReport, InventoryCoverage, LedgerReport, ParityReport, ParityStatus, ParityTotals,
    generate_report,
};

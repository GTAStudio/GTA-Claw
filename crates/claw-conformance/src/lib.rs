//! Data-driven conformance harness for the frozen OpenClaw compatibility data.
//!
//! The harness never changes the authoritative `compat/upstream` artifacts. It
//! loads and validates them, accepts evidence-backed implementation claims, and
//! produces deterministic parity reports.

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

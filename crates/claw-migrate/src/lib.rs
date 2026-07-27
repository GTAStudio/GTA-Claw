//! Transactional, npm-free migration providers for supported agent clients.
//!
//! Plans are side-effect free and serialize as the frozen legacy migration
//! result contract. [`MigrationPlan::report`] adds a diagnostics-oriented
//! operation summary without changing that frozen shape. Apply creates and
//! verifies backups before writing, while rollback restores files and
//! secret-store entries and reports every independent restoration failure.

mod contract;
mod engine;
mod platform;
mod providers;

pub use contract::{
    Artifact, ArtifactKind, ArtifactSignature, Bridge, ContractViolation, Diagnostic,
    DiagnosticSeverity, InputKind, LegacySkill, LegacySkillError, LoadedRole, MigrationInput,
    MigrationResult, MigrationStatus, RemainingJavascript, RoleError, RoleLoadOutcome,
    load_role_json, load_role_source, parse_legacy_skill, recognize_bridges,
};
pub use engine::{
    ApplyContext, ApplyReceipt, ArtifactSigner, Detection, DetectionConfidence,
    Ed25519ArtifactSigner, MigrationError, MigrationPlan, MigrationProvider, MigrationReport,
    PlanContext, SecretStore, SecretStoreError, SecretValue,
};
pub use platform::{HostPlatform, PlatformPaths, SystemPlatformPaths};
pub use providers::{ClaudeMigrationProvider, CodexMigrationProvider, HermesMigrationProvider};

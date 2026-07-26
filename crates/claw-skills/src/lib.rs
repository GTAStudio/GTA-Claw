//! Safe Rust-native skill loading and execution.
//!
//! Modern skills can dispatch to native handlers, a declarative HTTP port, or
//! the separately owned Wasm host. Legacy JavaScript is intentionally absent
//! from the executable model and can only be classified for manual migration.

mod legacy;
mod manifest;
mod registry;
mod runtime;
mod schema;

pub use legacy::{
    LegacyBridge, LegacyParameterShape, LegacySkillDisposition, LegacySkillError,
    MigrationEvidenceError, MigrationInputKind, MigrationStatus, PortArtifactEvidence,
    ValidatedMigrationEvidence, inspect_legacy_manifest, validate_migration_evidence,
};
pub use manifest::{
    HttpMethod, HttpParameterEncoding, HttpResponseMode, HttpSkillDefinition, ManifestError,
    SkillExecution, SkillManifest, load_manifest,
};
pub use registry::{SkillDescriptor, SkillImplementation, descriptor, registry};
pub use runtime::{
    HttpBridge, HttpBridgeError, HttpRequest, HttpResponse, NativeRegistryError,
    NativeSkillHandler, NativeSkillRegistry, SkillExecutionError, SkillRuntime, WasmHostError,
    WasmSkillHost,
};
pub use schema::{
    ParameterValidationError, ParameterViolation, ParameterViolationKind, SchemaError,
    SchemaErrorKind, validate_parameters, validate_schema,
};

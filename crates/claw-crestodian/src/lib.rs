//! Backup-first setup, deterministic remote rescue, and configuration recovery.
//!
//! Every API accepts explicit paths and time values. The crate never discovers
//! or writes real user configuration directories on its own.
//!
//! The privileged surface is deliberately narrow. A Crestodian session runs the
//! ordinary agent loop restricted to exactly one ring-zero authority tool
//! ([`RING_ZERO_TOOL`]) that wraps a closed set of typed operations; a backend
//! that cannot prove that restriction never starts. Configuration writes are
//! typed values of a closed field table, never ad-hoc edits, and paths that own
//! the inference route or credential resolution are refused outright. Remote
//! rescue speaks a closed grammar with no model in the loop, runs only for an
//! explicitly identified owner, and applies a mutation only after an unexpired
//! approval from the same message identity, with mandatory metadata-only audit.

mod audit;
mod error;
mod mutation;
mod recovery;
mod rescue;
mod ring;
mod runtime;
mod setup;
mod state;

pub use audit::JsonlRescueAudit;
pub use error::{CrestodianError, RestoreFailure};
pub use mutation::{
    CRESTODIAN_SETTINGS_SCHEMA_VERSION, ConfigDigest, ConfigDigestChange, CrestodianSettings,
    DEFAULT_GATEWAY_PORT, MutationField, MutationRejection, TypedMutation, ValueType,
};
pub use recovery::{
    ConfigCondition, Crestodian, RecoveryAction, RecoveryAssessment, RecoveryReport, StateCondition,
};
pub use rescue::{
    PendingOperation, RescueAuditEvent, RescueAuditKind, RescueAuditSink, RescueAuthorizationError,
    RescueCommand, RescueContext, RescueControlPlane, RescueError, RescueParseError,
    RescueParseReason, RescueResponse, RescueSession, RescueStatus, authorize_rescue,
    parse_rescue_command,
};
pub use ring::{
    BackendToolContract, CODEX_PLANNER_TOOL, CrestodianOperation, OperationRejection,
    RING_ZERO_TOOL, RingZeroDenial, RingZeroSession, RingZeroToolDescriptor, SessionKind,
    parse_operation, ring_zero_tool_descriptor, ring_zero_tool_schema,
};
pub use runtime::CrestodianRuntime;
pub use setup::{GuidedSetup, SetupAnswers, SetupField, SetupQuestion, SetupReport};
pub use state::{CRESTODIAN_STATE_SCHEMA_VERSION, CrestodianState};

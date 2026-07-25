//! Backup-first setup, deterministic remote rescue, and configuration recovery.
//!
//! Every API accepts explicit paths and time values. The crate never discovers
//! or writes real user configuration directories on its own.

mod error;
mod recovery;
mod rescue;
mod setup;
mod state;

pub use error::{CrestodianError, RestoreFailure};
pub use recovery::{
    ConfigCondition, Crestodian, RecoveryAction, RecoveryAssessment, RecoveryReport, StateCondition,
};
pub use rescue::{
    RescueAuditEvent, RescueAuditKind, RescueAuditSink, RescueAuthorizationError, RescueCommand,
    RescueContext, RescueControlPlane, RescueError, RescueParseError, RescueResponse,
    RescueSession, RescueStatus, authorize_rescue, parse_rescue_command,
};
pub use setup::{GuidedSetup, SetupAnswers, SetupField, SetupQuestion, SetupReport};
pub use state::{CRESTODIAN_STATE_SCHEMA_VERSION, CrestodianState};

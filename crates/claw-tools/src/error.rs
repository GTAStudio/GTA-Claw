//! The single error type crossing the tool boundary.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::audit::{AuditError, AuditReason};
use crate::exec::ExecutionError;
use crate::fs::PatchError;
use crate::net::NetworkError;
use crate::permission::PermissionError;
use crate::sandbox::SandboxError;
use crate::schema::SchemaError;

/// Any refusal or failure of a tool invocation.
#[derive(Debug)]
pub enum ToolError {
    /// The requested tool is not registered.
    UnknownTool,
    /// A tool with the same name is already registered.
    DuplicateTool,
    /// Argument validation refused the payload.
    Schema(SchemaError),
    /// A permission gate refused the invocation.
    Permission(PermissionError),
    /// The workspace sandbox refused the path.
    Sandbox(SandboxError),
    /// A unified diff could not be parsed or did not apply cleanly.
    Patch(PatchError),
    /// Process execution failed or was refused.
    Execution(ExecutionError),
    /// A network operation failed or was refused.
    Network(NetworkError),
    /// A mandatory audit write failed, so the invocation was abandoned.
    Audit(AuditError),
}

impl ToolError {
    /// Returns the sandbox refusal, when the failure came from the sandbox.
    #[must_use]
    pub const fn sandbox(&self) -> Option<SandboxError> {
        match self {
            Self::Sandbox(error) => Some(*error),
            _ => None,
        }
    }

    /// Returns the permission refusal, when a gate refused the invocation.
    #[must_use]
    pub const fn permission(&self) -> Option<PermissionError> {
        match self {
            Self::Permission(error) => Some(*error),
            _ => None,
        }
    }

    /// Returns the schema refusal, when validation refused the payload.
    #[must_use]
    pub const fn schema(&self) -> Option<&SchemaError> {
        match self {
            Self::Schema(error) => Some(error),
            _ => None,
        }
    }

    /// Returns the patch refusal, when a unified diff was rejected.
    #[must_use]
    pub const fn patch(&self) -> Option<PatchError> {
        match self {
            Self::Patch(error) => Some(*error),
            _ => None,
        }
    }

    /// Returns the execution failure, when a process failed or was refused.
    #[must_use]
    pub const fn execution(&self) -> Option<&ExecutionError> {
        match self {
            Self::Execution(error) => Some(error),
            _ => None,
        }
    }

    /// Returns the network failure, when a request failed or was refused.
    #[must_use]
    pub const fn network(&self) -> Option<&NetworkError> {
        match self {
            Self::Network(error) => Some(error),
            _ => None,
        }
    }

    /// Returns the stable audit reason recorded for this failure.
    #[must_use]
    pub const fn audit_reason(&self) -> AuditReason {
        match self {
            Self::UnknownTool | Self::DuplicateTool => AuditReason::UnknownTool,
            Self::Schema(_) => AuditReason::ValidationRejected,
            Self::Permission(_) => AuditReason::PolicyRejected,
            Self::Sandbox(SandboxError::FileTooLarge | SandboxError::DirectoryTooLarge) => {
                AuditReason::LimitExceeded
            }
            Self::Sandbox(_) => AuditReason::SandboxRejected,
            Self::Patch(_) => AuditReason::ValidationRejected,
            Self::Execution(_) | Self::Network(_) | Self::Audit(_) => AuditReason::ExecutionFailed,
        }
    }
}

impl Display for ToolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTool => formatter.write_str("unknown tool"),
            Self::DuplicateTool => formatter.write_str("tool name is already registered"),
            Self::Schema(error) => Display::fmt(error, formatter),
            Self::Permission(error) => Display::fmt(error, formatter),
            Self::Sandbox(error) => Display::fmt(error, formatter),
            Self::Patch(error) => Display::fmt(error, formatter),
            Self::Execution(error) => Display::fmt(error, formatter),
            Self::Network(error) => Display::fmt(error, formatter),
            Self::Audit(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for ToolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnknownTool | Self::DuplicateTool => None,
            Self::Schema(error) => Some(error),
            Self::Permission(error) => Some(error),
            Self::Sandbox(error) => Some(error),
            Self::Patch(error) => Some(error),
            Self::Execution(error) => Some(error),
            Self::Network(error) => Some(error),
            Self::Audit(error) => Some(error),
        }
    }
}

impl From<SchemaError> for ToolError {
    fn from(error: SchemaError) -> Self {
        Self::Schema(error)
    }
}

impl From<PermissionError> for ToolError {
    fn from(error: PermissionError) -> Self {
        Self::Permission(error)
    }
}

impl From<SandboxError> for ToolError {
    fn from(error: SandboxError) -> Self {
        Self::Sandbox(error)
    }
}

impl From<PatchError> for ToolError {
    fn from(error: PatchError) -> Self {
        Self::Patch(error)
    }
}

impl From<ExecutionError> for ToolError {
    fn from(error: ExecutionError) -> Self {
        Self::Execution(error)
    }
}

impl From<NetworkError> for ToolError {
    fn from(error: NetworkError) -> Self {
        Self::Network(error)
    }
}

impl From<AuditError> for ToolError {
    fn from(error: AuditError) -> Self {
        Self::Audit(error)
    }
}

//! ACP interoperability errors.

use std::time::Duration;

/// Failure returned by ACP bridges, debug clients, and harness runtimes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AcpInteropError {
    /// An ACP protocol operation failed.
    #[error("ACP protocol failed: {0}")]
    Protocol(#[from] agent_client_protocol::Error),
    /// An operating-system operation failed.
    #[error("ACP I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A bounded operation exceeded its deadline.
    #[error("ACP operation timed out after {0:?}")]
    Timeout(Duration),
    /// A requested harness alias is not configured.
    #[error("ACP harness alias is not configured: {0}")]
    UnknownHarness(String),
    /// A lifecycle operation conflicts with the current state.
    #[error("ACP lifecycle conflict: {0}")]
    Lifecycle(String),
    /// Harness configuration is invalid.
    #[error("ACP configuration is invalid: {0}")]
    Configuration(String),
}

/// Result alias for ACP interoperability.
pub type Result<T> = std::result::Result<T, AcpInteropError>;

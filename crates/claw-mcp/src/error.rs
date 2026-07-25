//! Shared MCP interoperability errors.

use std::time::Duration;

/// Failure returned by MCP transport and lifecycle operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum McpError {
    /// An operating-system operation failed.
    #[error("MCP I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization or parsing failed.
    #[error("MCP JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// An HTTP request failed.
    #[error("MCP HTTP failed: {0}")]
    Http(#[from] reqwest::Error),
    /// A URL was invalid.
    #[error("MCP URL failed: {0}")]
    Url(#[from] url::ParseError),
    /// The protocol peer returned an error.
    #[error("MCP service failed: {0}")]
    Service(#[from] rmcp::service::ServiceError),
    /// Client initialization failed.
    #[error("MCP client initialization failed: {0}")]
    ClientInitialize(#[source] Box<rmcp::service::ClientInitializeError>),
    /// Server initialization failed.
    #[error("MCP server initialization failed: {0}")]
    ServerInitialize(#[source] Box<rmcp::service::ServerInitializeError>),
    /// A task used by the protocol service failed.
    #[error("MCP task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// A bounded operation exceeded its deadline.
    #[error("MCP operation timed out after {0:?}")]
    Timeout(Duration),
    /// A peer sent malformed or unsupported protocol data.
    #[error("MCP protocol violation: {0}")]
    Protocol(String),
    /// A configured server was not found.
    #[error("MCP server is not configured: {0}")]
    UnknownServer(String),
    /// A configured server already exists.
    #[error("MCP server is already configured: {0}")]
    DuplicateServer(String),
    /// An operation is invalid for the server's current lifecycle state.
    #[error("MCP lifecycle conflict: {0}")]
    Lifecycle(String),
    /// Secure credential persistence failed without exposing credential bytes.
    #[error("MCP credential store failed: {0}")]
    CredentialStore(String),
}

/// Convenient result alias for MCP interoperability operations.
pub type Result<T> = std::result::Result<T, McpError>;

impl From<rmcp::service::ClientInitializeError> for McpError {
    fn from(error: rmcp::service::ClientInitializeError) -> Self {
        Self::ClientInitialize(Box::new(error))
    }
}

impl From<rmcp::service::ServerInitializeError> for McpError {
    fn from(error: rmcp::service::ServerInitializeError) -> Self {
        Self::ServerInitialize(Box::new(error))
    }
}

//! Agent Client Protocol interoperability for GTA-Claw.

pub mod acpx;
pub mod bridge;
pub mod debug_client;
pub mod error;
mod protocol;

pub use agent_client_protocol_schema as schema;
pub use error::{AcpInteropError, Result};
pub use protocol::ProtocolError as Error;

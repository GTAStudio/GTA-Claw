//! Agent Client Protocol interoperability for GTA-Claw.

pub mod acpx;
pub mod bridge;
pub mod debug_client;
pub mod error;

pub use agent_client_protocol::schema;
pub use error::{AcpInteropError, Result};

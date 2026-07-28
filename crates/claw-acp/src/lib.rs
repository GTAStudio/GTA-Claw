//! Agent Client Protocol interoperability for GTA-Claw.

pub mod acpx;
pub mod bridge;
pub mod debug_client;
pub mod error;
mod protocol;

pub use agent_client_protocol_schema as schema;
/// Wire types for the one ACP protocol version this bridge speaks.
///
/// The upstream schema namespaces its wire format per protocol version. Every
/// request, response, and notification handled here is a
/// [`schema::ProtocolVersion::V1`] type, and the bridge rejects any peer that
/// negotiates another version, so importing through this alias keeps that
/// single supported version visible at each use site.
pub use agent_client_protocol_schema::v1 as schema_v1;
pub use error::{AcpInteropError, Result};
pub use protocol::ProtocolError as Error;

//! Value types shared by application ports and their adapters.
//!
//! Nothing here derives serde. The application layer is deliberately free of any serialization
//! framework: adapters that need a wire form own the mapping, exactly as they already must for
//! [`claw_domain::SessionId`], which is defined without serde derives.

pub mod approval;
pub mod goal;
pub mod ids;
pub mod message;
pub mod session;
pub mod time;

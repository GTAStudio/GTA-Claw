//! Fleet, ClawHub, and authenticated webhook automation boundaries.

/// Trusted ClawHub package lifecycle.
pub mod clawhub;
/// Fleet cell coordination and lifecycle.
pub mod fleet;
/// Authenticated TaskFlow webhook ingress and delivery.
pub mod webhooks;

//! Deterministic stand-ins for the subsystems that have not landed yet.
//!
//! Every crate named in the composition — `claw-config`, `claw-observability`,
//! `claw-state`, `claw-provider-sdk`, `claw-providers`, `claw-tools`,
//! `claw-memory`, `claw-runtime`, `claw-gateway`, `claw-http-api`,
//! `claw-plugin-host` — is represented here by an in-crate adapter that
//! implements the same port the real crate will implement.
//!
//! These are stand-ins, not mocks. They do the work: the persistence adapter
//! really is transactional, the tool surface really can change its catalogue
//! between turns, the plugin host really does scope capabilities to an
//! instance, and the egress-backed provider registry really refuses a
//! destination the policy forbids. That is what makes the end-to-end test a
//! test of the composition rather than a test of a mock.
//!
//! When a real crate lands, its adapter is deleted and the port is bound to the
//! real implementation. Nothing in [`crate::compose`] changes.

pub mod engine;
pub mod ingress;
pub mod model;
pub mod plugins;
pub mod state;
pub mod support;

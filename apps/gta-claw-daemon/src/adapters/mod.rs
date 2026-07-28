//! Process adapters and deterministic composition fixtures.
//!
//! The adapters in [`http_api`] bridge the shipped production crates. The
//! remaining modules support the deterministic composition harness: every crate
//! named in that harness — `claw-config`, `claw-observability`,
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
//! They remain intentionally separate so production cannot accidentally claim a
//! loopback fixture as a live dependency.

pub mod agent_runtime;
pub mod channels;
pub mod engine;
pub mod http_api;
pub mod ingress;
pub mod legacy;
pub mod model;
pub mod plugins;
pub mod signed_plugins;
pub mod state;
pub mod support;
pub mod updater;

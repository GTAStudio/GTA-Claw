//! Provider registry and provider clients for GTA-Claw.
//!
//! This crate registers every provider in the frozen upstream inventory
//! (`compat/upstream/inventories/providers.json`) with typed GTA-Claw metadata,
//! and ships real clients for three wire dialects:
//!
//! * [`openai_compatible`] — the `OpenAI` `chat/completions` dialect.
//! * [`anthropic`] — Anthropic `POST /v1/messages`.
//! * [`github_copilot`] — GitHub Copilot, reached through a pure-Rust
//!   RFC 8628 device authorization flow.
//!
//! Providers that speak another dialect are registered with exact identifiers
//! and typed metadata, and report
//! [`RegistrationOnly`](descriptor::ImplementationStatus::RegistrationOnly).
//! Nothing in this crate claims behavior it does not implement: see
//! [`ProviderDescriptor::status`].
//!
//! Around the registry sit the four rules that make an identifier usable:
//!
//! * [`alias`] — resolving a human-written name to a frozen identifier, and
//!   refusing an alias table that could send a caller to the wrong provider.
//! * [`config`] — strict deserialisation of an operator's provider
//!   configuration, plus endpoint and header validation.
//! * [`auth`] — credential shapes and the check that a provider accepts the
//!   offered mode and was actually given the secret.
//! * [`routing`] — choosing a configured provider from the capabilities a
//!   request needs.

pub mod alias;
pub mod anthropic;
pub mod auth;
pub mod config;
pub mod descriptor;
pub mod github_copilot;
pub mod openai_compatible;
pub mod registry;
pub mod routing;
pub mod runtime;

pub use alias::{AliasConflict, AliasTable, Resolution, UnknownProvider};
pub use anthropic::Anthropic;
pub use auth::{AuthConfig, AuthError, Authorization, SecretField, authorize};
pub use config::{ConfigError, ProviderConfig, ResolvedProvider};
pub use descriptor::{ImplementationStatus, ProviderDescriptor, ProviderFamily};
pub use github_copilot::{DeviceFlow, GitHubCopilot};
pub use openai_compatible::OpenAiCompatible;
pub use registry::{PROVIDERS, ProviderRegistry, lookup};
pub use routing::{Route, RouteError, RouteRequest, RoutingTable};
pub use runtime::{ProviderRuntime, ReliabilityConfig};

/// Number of provider descriptors in the frozen inventory.
pub const FROZEN_PROVIDER_COUNT: usize = 78;

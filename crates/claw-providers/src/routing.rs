//! Capability routing over configured providers.
//!
//! Routing answers one question: given a set of capabilities a request needs,
//! which configured provider should serve it? The rules are deliberately
//! boring, because a surprising router is a router that sends a prompt to the
//! wrong vendor.
//!
//! * Only providers the operator configured and left enabled are eligible.
//! * A provider is a candidate only if it advertises **every** required
//!   capability.
//! * Explicit preferences are honoured in the order written, and a preference
//!   that cannot be honoured is an **error**, never a silent fallback: an
//!   operator who named a provider meant it.
//! * With no preference, the first eligible candidate in frozen inventory order
//!   wins, so the choice is deterministic across runs and platforms.
//! * When nothing qualifies, routing fails with
//!   [`RouteError::NoProviderAvailable`] rather than picking anything.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_provider_sdk::model::{Capability, CapabilitySet};

use crate::alias::AliasTable;
use crate::config::ResolvedProvider;
use crate::descriptor::ProviderDescriptor;
use crate::registry::{self, PROVIDERS};

/// What a caller needs from a provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteRequest<'a> {
    /// Capabilities the chosen provider must advertise. Must not be empty.
    pub required: CapabilitySet,
    /// Provider names to try first, in order. Frozen identifiers or aliases.
    pub preferred: &'a [&'a str],
}

impl<'a> RouteRequest<'a> {
    /// Builds a request for a single capability and no preference.
    #[must_use]
    pub const fn for_capability(capability: Capability) -> Self {
        Self {
            required: CapabilitySet::from_slice(&[capability]),
            preferred: &[],
        }
    }

    /// Returns the request with the given preferences applied.
    #[must_use]
    pub const fn preferring(mut self, preferred: &'a [&'a str]) -> Self {
        self.preferred = preferred;
        self
    }
}

/// The provider a request was routed to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route<'a> {
    /// The chosen provider's configuration.
    pub provider: &'a ResolvedProvider,
    /// The preference that selected it, when one did.
    pub honoured_preference: Option<String>,
}

impl Route<'_> {
    /// Returns the frozen identifier of the chosen provider.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.provider.descriptor.id
    }
}

/// Why routing failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteError {
    /// The request asked for nothing, which would match every provider.
    EmptyRequirement,
    /// A preference names nothing that exists.
    UnknownPreference {
        /// The name as written.
        name: String,
    },
    /// A preference names a real provider that is not configured, or is
    /// configured but disabled.
    PreferenceNotConfigured {
        /// Frozen provider identifier.
        provider: &'static str,
    },
    /// A preference names a configured provider that cannot do the work.
    PreferenceLacksCapability {
        /// Frozen provider identifier.
        provider: &'static str,
        /// The capabilities it does not advertise, in declaration order.
        missing: Vec<Capability>,
    },
    /// Nothing configured advertises the required capabilities.
    NoProviderAvailable {
        /// The capabilities that went unserved, in declaration order.
        required: Vec<Capability>,
        /// How many enabled providers were considered.
        considered: usize,
    },
}

impl RouteError {
    /// Returns a stable machine-readable code for this failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyRequirement => "empty_requirement",
            Self::UnknownPreference { .. } => "unknown_preference",
            Self::PreferenceNotConfigured { .. } => "preference_not_configured",
            Self::PreferenceLacksCapability { .. } => "preference_lacks_capability",
            Self::NoProviderAvailable { .. } => "no_provider_available",
        }
    }
}

impl Display for RouteError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRequirement => {
                formatter.write_str("a routing request must require at least one capability")
            }
            Self::UnknownPreference { name } => write!(
                formatter,
                "preferred provider '{name}' is neither a registered provider nor a known alias"
            ),
            Self::PreferenceNotConfigured { provider } => write!(
                formatter,
                "preferred provider '{provider}' is not configured, or is disabled"
            ),
            Self::PreferenceLacksCapability { provider, missing } => {
                let missing: Vec<&str> = missing.iter().map(|entry| entry.as_str()).collect();
                write!(
                    formatter,
                    "preferred provider '{provider}' does not support {}",
                    missing.join(", ")
                )
            }
            Self::NoProviderAvailable {
                required,
                considered,
            } => {
                let required: Vec<&str> = required.iter().map(|entry| entry.as_str()).collect();
                write!(
                    formatter,
                    "none of the {considered} enabled provider(s) supports {}",
                    required.join(", ")
                )
            }
        }
    }
}

impl Error for RouteError {}

/// A provider configured twice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateProvider {
    /// Frozen identifier of the repeated provider.
    pub provider: &'static str,
}

impl Display for DuplicateProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "provider '{}' is configured more than once",
            self.provider
        )
    }
}

impl Error for DuplicateProvider {}

/// The configured providers a request may be routed to.
#[derive(Clone, Debug)]
pub struct RoutingTable {
    entries: Vec<ResolvedProvider>,
}

impl RoutingTable {
    /// Builds a routing table from validated configurations.
    ///
    /// Entries are stored in frozen inventory order, so routing never depends
    /// on the order of a configuration file or on hash iteration.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateProvider`] when two configurations resolve to the
    /// same frozen identifier — which includes one written as an alias and one
    /// written canonically, the case an operator is least likely to spot.
    pub fn new(providers: Vec<ResolvedProvider>) -> Result<Self, DuplicateProvider> {
        let mut seen: BTreeSet<&'static str> = BTreeSet::new();
        for provider in &providers {
            if !seen.insert(provider.descriptor.id) {
                return Err(DuplicateProvider {
                    provider: provider.descriptor.id,
                });
            }
        }
        let mut entries = providers;
        // Unregistered rows cannot occur — a `ResolvedProvider` is only built
        // from a registry descriptor — but ordering them last is a defined
        // outcome, where indexing a lookup table would be a panic.
        entries.sort_by_key(|provider| {
            registry::inventory_index(provider.descriptor.id).unwrap_or(usize::MAX)
        });
        Ok(Self { entries })
    }

    /// Returns the number of configured providers, enabled or not.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when nothing is configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the configured providers in frozen inventory order.
    #[must_use]
    pub fn providers(&self) -> &[ResolvedProvider] {
        &self.entries
    }

    /// Returns every enabled provider that advertises `required`, in frozen
    /// inventory order.
    #[must_use]
    pub fn candidates(&self, required: CapabilitySet) -> Vec<&ResolvedProvider> {
        self.entries
            .iter()
            .filter(|provider| {
                provider.enabled && provider.descriptor.capabilities.contains_all(required)
            })
            .collect()
    }

    /// Routes a request through the built-in alias table.
    ///
    /// # Errors
    ///
    /// * [`RouteError::EmptyRequirement`] — the request requires no capability,
    ///   which would match every configured provider.
    /// * [`RouteError::UnknownPreference`] — a preferred name is neither a
    ///   frozen identifier nor a known alias.
    /// * [`RouteError::PreferenceNotConfigured`] — every stated preference
    ///   failed and the first failure was a provider that is absent from this
    ///   table or configured but disabled.
    /// * [`RouteError::PreferenceLacksCapability`] — every stated preference
    ///   failed and the first failure was a configured, enabled provider that
    ///   does not advertise all the required capabilities.
    /// * [`RouteError::NoProviderAvailable`] — no preference was stated and no
    ///   enabled provider advertises all the required capabilities.
    pub fn route(&self, request: &RouteRequest<'_>) -> Result<Route<'_>, RouteError> {
        self.route_with(request, AliasTable::builtin())
    }

    /// Routes a request, resolving preferences through an explicit alias table.
    ///
    /// # Errors
    ///
    /// The same failures as [`RoutingTable::route`], except that
    /// [`RouteError::UnknownPreference`] is decided against `aliases` rather
    /// than the built-in table.
    pub fn route_with(
        &self,
        request: &RouteRequest<'_>,
        aliases: &AliasTable,
    ) -> Result<Route<'_>, RouteError> {
        if request.required.is_empty() {
            return Err(RouteError::EmptyRequirement);
        }

        // Preferences are tried in order. A name that resolves to nothing is a
        // typo and fails immediately; a name that resolves but cannot serve
        // this request lets the next preference have a turn. If every stated
        // preference fails, the first failure is returned rather than some
        // unrelated provider: a caller who named providers did so on purpose,
        // and silently ignoring that is how a prompt reaches the wrong vendor.
        let mut first_failure: Option<RouteError> = None;
        for name in request.preferred {
            let descriptor = aliases
                .resolve(name)
                .map_err(|error| RouteError::UnknownPreference { name: error.name })?
                .descriptor;
            let Some(provider) = self
                .entries
                .iter()
                .find(|entry| entry.descriptor.id == descriptor.id && entry.enabled)
            else {
                first_failure.get_or_insert(RouteError::PreferenceNotConfigured {
                    provider: descriptor.id,
                });
                continue;
            };
            let missing = provider
                .descriptor
                .capabilities
                .missing_from(request.required);
            if !missing.is_empty() {
                first_failure.get_or_insert(RouteError::PreferenceLacksCapability {
                    provider: descriptor.id,
                    missing,
                });
                continue;
            }
            return Ok(Route {
                provider,
                honoured_preference: Some((*name).to_owned()),
            });
        }
        if let Some(failure) = first_failure {
            return Err(failure);
        }

        self.candidates(request.required)
            .first()
            .map(|provider| Route {
                provider,
                honoured_preference: None,
            })
            .ok_or_else(|| RouteError::NoProviderAvailable {
                required: CapabilitySet::EMPTY.missing_from(request.required),
                considered: self
                    .entries
                    .iter()
                    .filter(|provider| provider.enabled)
                    .count(),
            })
    }
}

/// Returns every registered provider that advertises `required`, regardless of
/// configuration, in frozen inventory order.
///
/// This is the catalogue view an interactive picker needs. It is deliberately
/// separate from [`RoutingTable::candidates`], which answers what can be called
/// *now*; conflating the two is how a picker ends up offering a provider that
/// no credential exists for.
#[must_use]
pub fn registered_for(required: CapabilitySet) -> Vec<&'static ProviderDescriptor> {
    PROVIDERS
        .iter()
        .filter(|descriptor| descriptor.capabilities.contains_all(required))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProviderConfig;

    fn resolved(json: &str) -> ResolvedProvider {
        ProviderConfig::from_json(json)
            .expect("valid configuration")
            .resolve()
            .expect("resolves")
    }

    fn openai() -> ResolvedProvider {
        resolved(r#"{"id":"openai","auth":{"mode":"bearer_token","token":"t"}}"#)
    }

    fn anthropic() -> ResolvedProvider {
        resolved(r#"{"id":"anthropic","auth":{"mode":"api_key","key":"k"}}"#)
    }

    fn ollama() -> ResolvedProvider {
        resolved(r#"{"id":"ollama","auth":{"mode":"none"}}"#)
    }

    #[test]
    fn an_empty_table_routes_nothing_and_says_how_many_it_looked_at() {
        let table = RoutingTable::new(Vec::new()).expect("no duplicates");
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        let error = table
            .route(&RouteRequest::for_capability(Capability::Completion))
            .expect_err("nothing is configured");
        assert_eq!(error.code(), "no_provider_available");
        assert_eq!(
            error,
            RouteError::NoProviderAvailable {
                required: vec![Capability::Completion],
                considered: 0,
            }
        );
        assert!(error.to_string().contains("completion"));
    }

    #[test]
    fn routing_prefers_frozen_inventory_order_over_configuration_order() {
        // `openai` precedes `anthropic` in the frozen inventory, so it wins
        // whichever way round the configurations were listed.
        let forwards = RoutingTable::new(vec![openai(), anthropic()]).expect("distinct");
        let backwards = RoutingTable::new(vec![anthropic(), openai()]).expect("distinct");
        for table in [&forwards, &backwards] {
            let route = table
                .route(&RouteRequest::for_capability(Capability::Completion))
                .expect("routes");
            assert_eq!(route.id(), "openai");
            assert_eq!(route.honoured_preference, None);
        }
        assert_eq!(
            forwards
                .providers()
                .iter()
                .map(ResolvedProvider::id)
                .collect::<Vec<_>>(),
            backwards
                .providers()
                .iter()
                .map(ResolvedProvider::id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_required_capability_no_one_serves_routes_nowhere() {
        // Anthropic serves no embeddings API, so a table holding only Anthropic
        // cannot serve an embeddings request even though it is configured.
        let table = RoutingTable::new(vec![anthropic()]).expect("distinct");
        assert_eq!(table.candidates(CapabilitySet::EMPTY).len(), 1);
        let error = table
            .route(&RouteRequest::for_capability(Capability::Embeddings))
            .expect_err("anthropic has no embeddings endpoint");
        assert_eq!(
            error,
            RouteError::NoProviderAvailable {
                required: vec![Capability::Embeddings],
                considered: 1,
            }
        );

        let with_openai = RoutingTable::new(vec![anthropic(), openai()]).expect("distinct");
        assert_eq!(
            with_openai
                .route(&RouteRequest::for_capability(Capability::Embeddings))
                .expect("openai serves embeddings")
                .id(),
            "openai"
        );
    }

    #[test]
    fn a_disabled_provider_is_never_routed_to() {
        let disabled = resolved(
            r#"{"id":"openai","auth":{"mode":"bearer_token","token":"t"},"enabled":false}"#,
        );
        let table = RoutingTable::new(vec![disabled, anthropic()]).expect("distinct");
        assert_eq!(table.len(), 2);
        assert_eq!(
            table
                .route(&RouteRequest::for_capability(Capability::Completion))
                .expect("anthropic is still enabled")
                .id(),
            "anthropic"
        );
        assert_eq!(
            table
                .route(&RouteRequest::for_capability(Capability::Embeddings))
                .expect_err("the only embeddings provider is disabled")
                .code(),
            "no_provider_available"
        );
    }

    #[test]
    fn preferences_are_honoured_in_order_and_may_be_written_as_aliases() {
        let table = RoutingTable::new(vec![openai(), anthropic()]).expect("distinct");
        let route = table
            .route(&RouteRequest::for_capability(Capability::Completion).preferring(&["claude"]))
            .expect("routes");
        assert_eq!(route.id(), "anthropic");
        assert_eq!(route.honoured_preference.as_deref(), Some("claude"));

        assert_eq!(
            table
                .route(
                    &RouteRequest::for_capability(Capability::Completion).preferring(&["openai"])
                )
                .expect("routes")
                .id(),
            "openai"
        );
    }

    #[test]
    fn an_unhonourable_preference_is_an_error_rather_than_a_silent_fallback() {
        let table = RoutingTable::new(vec![openai(), anthropic()]).expect("distinct");

        assert_eq!(
            table
                .route(&RouteRequest::for_capability(Capability::Completion).preferring(&["gpt-9"]))
                .expect_err("no such provider"),
            RouteError::UnknownPreference {
                name: "gpt-9".to_owned()
            }
        );
        assert_eq!(
            table
                .route(&RouteRequest::for_capability(Capability::Completion).preferring(&["groq"]))
                .expect_err("groq is registered but not configured"),
            RouteError::PreferenceNotConfigured { provider: "groq" }
        );
        assert_eq!(
            table
                .route(
                    &RouteRequest::for_capability(Capability::Embeddings)
                        .preferring(&["anthropic"])
                )
                .expect_err("anthropic serves no embeddings"),
            RouteError::PreferenceLacksCapability {
                provider: "anthropic",
                missing: vec![Capability::Embeddings],
            }
        );
        // Even though `openai` would have served it.
        assert_eq!(
            table
                .route(&RouteRequest::for_capability(Capability::Embeddings))
                .expect("without a preference openai wins")
                .id(),
            "openai"
        );
    }

    #[test]
    fn a_request_that_requires_nothing_is_refused() {
        let table = RoutingTable::new(vec![openai()]).expect("distinct");
        let error = table
            .route(&RouteRequest {
                required: CapabilitySet::EMPTY,
                preferred: &[],
            })
            .expect_err("an empty requirement matches everything");
        assert_eq!(error, RouteError::EmptyRequirement);
        assert_eq!(error.code(), "empty_requirement");
    }

    #[test]
    fn a_provider_configured_twice_is_refused_even_through_an_alias() {
        assert_eq!(
            RoutingTable::new(vec![openai(), openai()]).expect_err("same id twice"),
            DuplicateProvider { provider: "openai" }
        );
        let aliased = resolved(r#"{"id":"claude","auth":{"mode":"api_key","key":"k"}}"#);
        assert_eq!(
            RoutingTable::new(vec![anthropic(), aliased]).expect_err("alias and canonical"),
            DuplicateProvider {
                provider: "anthropic"
            }
        );
    }

    #[test]
    fn a_compound_requirement_needs_every_capability_at_once() {
        let table = RoutingTable::new(vec![anthropic(), ollama()]).expect("distinct");
        let vision_and_embeddings = CapabilitySet::from_slice(&[
            Capability::Vision,
            Capability::Embeddings,
            Capability::Reasoning,
        ]);
        // Anthropic has vision and reasoning but no embeddings; Ollama, through
        // the OpenAI dialect, has all three.
        assert_eq!(
            table
                .route(&RouteRequest {
                    required: vision_and_embeddings,
                    preferred: &[],
                })
                .expect("ollama serves all three")
                .id(),
            "ollama"
        );
        assert_eq!(
            table
                .route(&RouteRequest {
                    required: vision_and_embeddings,
                    preferred: &["anthropic"],
                })
                .expect_err("anthropic is short one"),
            RouteError::PreferenceLacksCapability {
                provider: "anthropic",
                missing: vec![Capability::Embeddings],
            }
        );
    }

    #[test]
    fn the_catalogue_view_is_wider_than_the_configured_view() {
        let configured = RoutingTable::new(vec![openai()]).expect("distinct");
        let completion = CapabilitySet::from_slice(&[Capability::Completion]);
        let catalogue = registered_for(completion);
        assert_eq!(configured.candidates(completion).len(), 1);
        assert!(catalogue.len() > 1);
        // Every registration-only row is absent from both.
        assert!(
            catalogue
                .iter()
                .all(|descriptor| !descriptor.is_registration_only())
        );
        assert!(registered_for(CapabilitySet::EMPTY).len() > catalogue.len());
    }
}

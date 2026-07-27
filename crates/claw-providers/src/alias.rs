//! Alias resolution for provider identifiers.
//!
//! An identifier reaching this crate comes from a human: a configuration file,
//! a command line, an environment variable. Resolution therefore accepts a
//! little surface variation, and refuses everything else.
//!
//! # Why folding stops at case
//!
//! Normalisation trims surrounding whitespace and lowercases ASCII. It
//! deliberately does **not** fold separators, because the frozen inventory
//! itself makes that ambiguous: `novita-ai` and `novitaai` are two distinct
//! rows, as are `gmi-cloud` and `gmicloud`. Stripping `-` would map each pair
//! onto one string and silently route a caller to whichever row won. That is
//! not a hypothetical — it is pinned by a test that reads the frozen inventory
//! and asserts both pairs are present and distinct.
//!
//! Every frozen identifier is already lowercase ASCII, so lowercasing is
//! injective over the inventory and cannot merge two rows.
//!
//! # Why an alias table is validated rather than trusted
//!
//! An alias is a second name for a provider, so a bad table silently sends
//! credentials and prompts to the wrong service. [`AliasTable::new`] therefore
//! refuses four shapes outright — an alias that shadows a frozen identifier, a
//! duplicated alias, an alias pointing at nothing, and an alias that is not in
//! normalised form and so could never be reached.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::OnceLock;

use crate::descriptor::ProviderDescriptor;
use crate::registry::ProviderRegistry;

/// GTA-Claw-owned convenience aliases.
///
/// These are **not** upstream data: the frozen inventory publishes identifiers
/// only. Each entry is a spelling a human plausibly types for a provider whose
/// frozen identifier is written differently — a brand name, or the same name
/// hyphenated the other way. None of them may collide with a frozen identifier;
/// `AliasTable::builtin` would panic if one did, and a test proves it does not.
///
/// The list is kept sorted so that a duplicate is visible on review rather than
/// only at run time.
pub const BUILTIN_ALIASES: &[(&str, &str)] = &[
    ("azure-ai-foundry", "microsoft-foundry"),
    ("azure-foundry", "microsoft-foundry"),
    ("bedrock", "amazon-bedrock"),
    ("bedrock-mantle", "amazon-bedrock-mantle"),
    ("byte-plus", "byteplus"),
    ("claude", "anthropic"),
    ("cloudflare", "cloudflare-ai-gateway"),
    ("comfyui", "comfy"),
    ("dash-scope", "dashscope"),
    ("deep-infra", "deepinfra"),
    ("deep-seek", "deepseek"),
    ("fal-ai", "fal"),
    ("fireworks-ai", "fireworks"),
    ("gemini", "google"),
    ("gemini-cli", "google-gemini-cli"),
    ("hugging-face", "huggingface"),
    ("kilo-code", "kilocode"),
    ("litellm-proxy", "litellm"),
    ("lm-studio", "lmstudio"),
    ("long-cat", "longcat"),
    ("mini-max", "minimax"),
    ("mistral-ai", "mistral"),
    ("model-studio", "modelstudio"),
    ("moonshot-ai", "moonshot"),
    ("open-code", "opencode"),
    ("open-code-go", "opencode-go"),
    ("open-router", "openrouter"),
    ("step-fun", "stepfun"),
    ("together-ai", "together"),
    ("venice-ai", "venice"),
    ("vertex", "google-vertex"),
    ("vertex-ai", "google-vertex"),
    ("volc-engine", "volcengine"),
    ("x-ai", "xai"),
    ("z-ai", "zai"),
];

/// Normalises a user-supplied provider name.
///
/// Trims ASCII whitespace and lowercases ASCII characters. Non-ASCII characters
/// are left untouched, so no locale-dependent case mapping can turn one
/// identifier into another.
#[must_use]
pub fn normalize(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

/// How a name matched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MatchKind {
    /// The name is a frozen inventory identifier.
    Canonical,
    /// The name is an alias; the payload is the normalised alias that matched.
    Alias(String),
}

/// A successful resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    /// The provider the name resolves to.
    pub descriptor: &'static ProviderDescriptor,
    /// Whether the name was a frozen identifier or an alias.
    pub matched: MatchKind,
}

impl Resolution {
    /// Returns the frozen identifier of the resolved provider.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.descriptor.id
    }

    /// Returns `true` when the name was an alias rather than a frozen id.
    #[must_use]
    pub fn is_alias(&self) -> bool {
        matches!(self.matched, MatchKind::Alias(_))
    }
}

/// A name that resolves to nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownProvider {
    /// The name as supplied by the caller.
    pub name: String,
}

impl Display for UnknownProvider {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "'{}' is neither a registered provider nor a known alias",
            self.name
        )
    }
}

impl Error for UnknownProvider {}

/// Why an alias table was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AliasConflict {
    /// The alias is itself a frozen provider identifier.
    ShadowsProvider {
        /// The offending alias.
        alias: String,
    },
    /// The alias was declared more than once.
    Duplicate {
        /// The offending alias.
        alias: String,
        /// The target of the first declaration.
        first: String,
        /// The target of the second declaration.
        second: String,
    },
    /// The alias points at an identifier that is not registered.
    DanglingTarget {
        /// The offending alias.
        alias: String,
        /// The unregistered target.
        target: String,
    },
    /// The alias is not in normalised form, so nothing could ever match it.
    NotNormalized {
        /// The offending alias.
        alias: String,
    },
}

impl AliasConflict {
    /// Returns a stable machine-readable code for this refusal.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ShadowsProvider { .. } => "alias_shadows_provider",
            Self::Duplicate { .. } => "duplicate_alias",
            Self::DanglingTarget { .. } => "dangling_alias_target",
            Self::NotNormalized { .. } => "alias_not_normalized",
        }
    }
}

impl Display for AliasConflict {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShadowsProvider { alias } => write!(
                formatter,
                "alias '{alias}' is already a registered provider identifier"
            ),
            Self::Duplicate {
                alias,
                first,
                second,
            } => write!(
                formatter,
                "alias '{alias}' is declared twice, for '{first}' and for '{second}'"
            ),
            Self::DanglingTarget { alias, target } => write!(
                formatter,
                "alias '{alias}' points at unregistered provider '{target}'"
            ),
            Self::NotNormalized { alias } => write!(
                formatter,
                "alias '{alias}' is not in normalised form and could never be matched"
            ),
        }
    }
}

impl Error for AliasConflict {}

/// A validated set of provider aliases.
#[derive(Clone, Debug)]
pub struct AliasTable {
    entries: BTreeMap<String, &'static ProviderDescriptor>,
}

impl AliasTable {
    /// Builds a table with no aliases, so only frozen identifiers resolve.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Validates and builds an alias table.
    ///
    /// # Errors
    ///
    /// Returns the first [`AliasConflict`] found, checked in entry order:
    /// an alias that is not normalised, one that shadows a frozen provider
    /// identifier, one that repeats an earlier alias, or one whose target is
    /// not registered.
    pub fn new(entries: &[(&str, &str)]) -> Result<Self, AliasConflict> {
        let registry = ProviderRegistry::global();
        let mut table: BTreeMap<String, &'static ProviderDescriptor> = BTreeMap::new();
        for &(alias, target) in entries {
            let alias = alias.to_owned();
            if alias != normalize(&alias) || alias.is_empty() {
                return Err(AliasConflict::NotNormalized { alias });
            }
            if registry.get(&alias).is_some() {
                return Err(AliasConflict::ShadowsProvider { alias });
            }
            if let Some(existing) = table.get(&alias) {
                return Err(AliasConflict::Duplicate {
                    alias,
                    first: existing.id.to_owned(),
                    second: target.to_owned(),
                });
            }
            let descriptor = registry
                .get(target)
                .ok_or_else(|| AliasConflict::DanglingTarget {
                    alias: alias.clone(),
                    target: target.to_owned(),
                })?;
            table.insert(alias, descriptor);
        }
        Ok(Self { entries: table })
    }

    /// Returns the process-wide table built from [`BUILTIN_ALIASES`].
    ///
    /// # Panics
    ///
    /// Panics when [`BUILTIN_ALIASES`] is invalid. That is a defect in this
    /// crate rather than a runtime condition a caller can cause, and
    /// `the_builtin_alias_table_is_valid_against_the_frozen_inventory` fails
    /// first if one is ever introduced.
    #[must_use]
    pub fn builtin() -> &'static Self {
        static BUILTIN: OnceLock<AliasTable> = OnceLock::new();
        BUILTIN.get_or_init(|| {
            Self::new(BUILTIN_ALIASES).expect("the built-in alias table must be valid")
        })
    }

    /// Returns the number of aliases in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the table declares no aliases.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the aliases of one frozen identifier, sorted.
    #[must_use]
    pub fn aliases_for(&self, id: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(_, descriptor)| descriptor.id == id)
            .map(|(alias, _)| alias.as_str())
            .collect()
    }

    /// Resolves a user-supplied name.
    ///
    /// A frozen identifier always wins over an alias, which cannot happen
    /// anyway because [`AliasTable::new`] refuses a shadowing alias.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownProvider`] when the normalised name is neither a frozen
    /// identifier nor an alias in this table.
    pub fn resolve(&self, name: &str) -> Result<Resolution, UnknownProvider> {
        let normalized = normalize(name);
        if let Some(descriptor) = ProviderRegistry::global().get(&normalized) {
            return Ok(Resolution {
                descriptor,
                matched: MatchKind::Canonical,
            });
        }
        if let Some(descriptor) = self.entries.get(&normalized) {
            return Ok(Resolution {
                descriptor,
                matched: MatchKind::Alias(normalized),
            });
        }
        Err(UnknownProvider {
            name: name.to_owned(),
        })
    }
}

/// Resolves a name through the built-in alias table.
///
/// # Errors
///
/// Returns [`UnknownProvider`] when the name resolves to nothing.
pub fn resolve(name: &str) -> Result<Resolution, UnknownProvider> {
    AliasTable::builtin().resolve(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_trims_and_lowercases_ascii_only() {
        assert_eq!(normalize("  OpenAI \t"), "openai");
        assert_eq!(normalize("GITHUB-COPILOT"), "github-copilot");
        assert_eq!(normalize("openai"), "openai");
        // Separators survive: folding them would merge distinct frozen rows.
        assert_eq!(normalize("novita-ai"), "novita-ai");
        assert_eq!(normalize("gmi_cloud"), "gmi_cloud");
        // Inner whitespace is not an accident to be forgiven.
        assert_eq!(normalize("open ai"), "open ai");
    }

    #[test]
    fn separator_folding_would_merge_two_pairs_of_distinct_providers() {
        let registry = ProviderRegistry::global();
        for (dashed, joined) in [("novita-ai", "novitaai"), ("gmi-cloud", "gmicloud")] {
            let dashed = registry.get(dashed).expect("registered");
            let joined = registry.get(joined).expect("registered");
            assert_ne!(dashed.id, joined.id);
            assert_eq!(dashed.id.replace('-', ""), joined.id);
        }
        // And the fold is not performed, so both still resolve to themselves.
        assert_eq!(resolve("novita-ai").expect("resolves").id(), "novita-ai");
        assert_eq!(resolve("novitaai").expect("resolves").id(), "novitaai");
        assert_eq!(resolve("gmi-cloud").expect("resolves").id(), "gmi-cloud");
        assert_eq!(resolve("gmicloud").expect("resolves").id(), "gmicloud");
    }

    #[test]
    fn a_frozen_identifier_resolves_canonically_and_an_alias_resolves_to_it() {
        let canonical = resolve("anthropic").expect("registered");
        assert_eq!(canonical.matched, MatchKind::Canonical);
        assert!(!canonical.is_alias());

        let aliased = resolve("  CLAUDE ").expect("aliased");
        assert_eq!(aliased.id(), "anthropic");
        assert_eq!(aliased.matched, MatchKind::Alias("claude".to_owned()));
        assert!(aliased.is_alias());
        assert_eq!(aliased.descriptor, canonical.descriptor);
    }

    #[test]
    fn an_unknown_name_resolves_to_nothing_and_says_so() {
        let error = resolve("not-a-provider").expect_err("unknown");
        assert_eq!(error.name, "not-a-provider");
        assert!(error.to_string().contains("not-a-provider"));
        assert!(resolve("").is_err());
        assert!(resolve("   ").is_err());
        assert!(resolve("open ai").is_err());
        // A frozen identifier with anything appended is a different name.
        assert!(resolve("openai-").is_err());
        assert!(resolve("openai/").is_err());
    }

    #[test]
    fn the_builtin_alias_table_is_valid_against_the_frozen_inventory() {
        let table = AliasTable::builtin();
        assert_eq!(table.len(), BUILTIN_ALIASES.len());
        assert!(!table.is_empty());
        assert_eq!(
            table.aliases_for("microsoft-foundry"),
            vec!["azure-ai-foundry", "azure-foundry"]
        );
        assert_eq!(table.aliases_for("openai"), Vec::<&str>::new());

        let mut aliases: Vec<&str> = BUILTIN_ALIASES.iter().map(|(alias, _)| *alias).collect();
        assert!(
            aliases.windows(2).all(|pair| pair[0] < pair[1]),
            "the built-in table is kept sorted so a duplicate is visible on review"
        );
        aliases.sort_unstable();
        let total = aliases.len();
        aliases.dedup();
        assert_eq!(aliases.len(), total);
    }

    #[test]
    fn an_alias_table_refuses_shadowing_duplicate_dangling_and_unnormalised_entries() {
        assert_eq!(
            AliasTable::new(&[("openai", "anthropic")]).expect_err("shadowing"),
            AliasConflict::ShadowsProvider {
                alias: "openai".to_owned()
            }
        );
        assert_eq!(
            AliasTable::new(&[("gpt", "openai"), ("gpt", "anthropic")]).expect_err("duplicate"),
            AliasConflict::Duplicate {
                alias: "gpt".to_owned(),
                first: "openai".to_owned(),
                second: "anthropic".to_owned(),
            }
        );
        // A duplicate is refused even when both entries agree, because the
        // second declaration is dead weight that hides a later disagreement.
        assert_eq!(
            AliasTable::new(&[("gpt", "openai"), ("gpt", "openai")])
                .expect_err("duplicate")
                .code(),
            "duplicate_alias"
        );
        assert_eq!(
            AliasTable::new(&[("gpt", "openai-next")]).expect_err("dangling"),
            AliasConflict::DanglingTarget {
                alias: "gpt".to_owned(),
                target: "openai-next".to_owned(),
            }
        );
        for unnormalised in ["GPT", " gpt", "gpt ", ""] {
            assert_eq!(
                AliasTable::new(&[(unnormalised, "openai")])
                    .expect_err("unnormalised")
                    .code(),
                "alias_not_normalized",
                "{unnormalised:?}"
            );
        }
    }

    #[test]
    fn an_empty_table_still_resolves_every_frozen_identifier() {
        let table = AliasTable::empty();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(
            table.resolve("openai").expect("canonical").matched,
            MatchKind::Canonical
        );
        assert!(table.resolve("claude").is_err());
    }

    #[test]
    fn alias_conflict_codes_are_distinct() {
        let codes = [
            AliasConflict::ShadowsProvider {
                alias: String::new(),
            }
            .code(),
            AliasConflict::Duplicate {
                alias: String::new(),
                first: String::new(),
                second: String::new(),
            }
            .code(),
            AliasConflict::DanglingTarget {
                alias: String::new(),
                target: String::new(),
            }
            .code(),
            AliasConflict::NotNormalized {
                alias: String::new(),
            }
            .code(),
        ];
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }
}

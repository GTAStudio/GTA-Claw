//! The operator-owned capability ceiling a manifest is intersected with.
//!
//! A plugin manifest is written by whoever wrote the plugin. It is therefore a
//! *request*, never a grant. If the manifest's capability list became the
//! runtime grant set directly, a validly signed hostile plugin could ask for
//! `filesystem-write` over the whole disk and every later boundary check would
//! pass, because the attacker's request would be the grant.
//!
//! [`OperatorPolicy`] is the other half. It is owned by whoever runs the host,
//! it denies everything by default, and it is the only source of authority.
//! What an instance actually receives is
//!
//! ```text
//! effective = requested ∩ ceiling
//! ```
//!
//! computed per capability *and per scope field*, so a manifest can only ever
//! narrow what the operator allowed. Anything the operator did not allow is
//! withheld outright and recorded, so the refusal is visible rather than
//! silent.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::capability::{
    Capability, CapabilityGrant, CapabilitySet, ClockGrant, ConfigGrant, ConfigScope, EventsGrant,
    FilesystemGrant, HttpGrant, HttpMethod, LogGrant, RandomGrant, StoreGrant, ToolsGrant,
    host_matches,
};

/// Why a requested capability did not survive the intersection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WithheldReason {
    /// The operator's ceiling for this plugin does not mention the capability.
    NotInCeiling,
    /// The capability is in the ceiling, but the requested scope and the
    /// granted scope have nothing in common - every root, host, key or event
    /// kind the manifest asked for is outside what the operator allowed.
    ScopesDisjoint,
}

impl WithheldReason {
    /// Stable, machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInCeiling => "not-in-ceiling",
            Self::ScopesDisjoint => "scopes-disjoint",
        }
    }
}

/// One capability the manifest asked for and did not get.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Withheld {
    capability: Capability,
    reason: WithheldReason,
}

impl Withheld {
    /// The capability that was refused.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Why it was refused.
    #[must_use]
    pub const fn reason(&self) -> WithheldReason {
        self.reason
    }
}

impl fmt::Display for Withheld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            WithheldReason::NotInCeiling => write!(
                f,
                "capability `{}` is not in the operator's ceiling for this plugin",
                self.capability
            ),
            WithheldReason::ScopesDisjoint => write!(
                f,
                "capability `{}` was requested with a scope that lies entirely outside the operator's ceiling",
                self.capability
            ),
        }
    }
}

/// The outcome of intersecting one manifest with one ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveCapabilities {
    granted: CapabilitySet,
    withheld: Vec<Withheld>,
    narrowed: Vec<Capability>,
}

impl EffectiveCapabilities {
    /// What the instance actually receives.
    #[must_use]
    pub const fn granted(&self) -> &CapabilitySet {
        &self.granted
    }

    /// Requested capabilities that were refused outright, sorted.
    #[must_use]
    pub fn withheld(&self) -> &[Withheld] {
        &self.withheld
    }

    /// Requested capabilities that survived but with a reduced scope, sorted.
    #[must_use]
    pub fn narrowed(&self) -> &[Capability] {
        &self.narrowed
    }

    /// Whether the manifest got exactly what it asked for.
    #[must_use]
    pub const fn is_unrestricted(&self) -> bool {
        self.withheld.is_empty() && self.narrowed.is_empty()
    }

    /// Consumes the outcome and returns the grant set.
    #[must_use]
    pub fn into_granted(self) -> CapabilitySet {
        self.granted
    }
}

/// The operator's per-plugin capability ceilings.
///
/// [`OperatorPolicy::deny_all`] is the starting point and the [`Default`]: a
/// plugin with no entry receives nothing at all, no matter what its manifest
/// declares or who signed it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperatorPolicy {
    ceilings: BTreeMap<String, CapabilitySet>,
}

impl OperatorPolicy {
    /// A policy that grants nothing to anybody.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Sets the ceiling for one plugin id, replacing any previous entry.
    #[must_use]
    pub fn allow(mut self, plugin_id: impl Into<String>, ceiling: CapabilitySet) -> Self {
        self.ceilings.insert(plugin_id.into(), ceiling);
        self
    }

    /// The ceiling configured for `plugin_id`, if any.
    #[must_use]
    pub fn ceiling(&self, plugin_id: &str) -> Option<&CapabilitySet> {
        self.ceilings.get(plugin_id)
    }

    /// The plugin ids this policy grants anything to, sorted.
    pub fn plugin_ids(&self) -> impl Iterator<Item = &str> {
        self.ceilings.keys().map(String::as_str)
    }

    /// Intersects a manifest's requested capabilities with this policy.
    ///
    /// A plugin with no configured ceiling receives an empty grant set and
    /// every requested capability is reported as withheld.
    #[must_use]
    pub fn effective(&self, plugin_id: &str, requested: &CapabilitySet) -> EffectiveCapabilities {
        let mut granted = Vec::new();
        let mut withheld = Vec::new();
        let mut narrowed = Vec::new();
        let ceiling = self.ceilings.get(plugin_id);

        for request in requested.grants() {
            let capability = request.capability();
            let Some(allowed) = ceiling.and_then(|set| set.grant(capability)) else {
                withheld.push(Withheld {
                    capability,
                    reason: WithheldReason::NotInCeiling,
                });
                continue;
            };
            match narrow(request, allowed) {
                Some(effective) => {
                    if &effective != request {
                        narrowed.push(capability);
                    }
                    granted.push(effective);
                }
                None => withheld.push(Withheld {
                    capability,
                    reason: WithheldReason::ScopesDisjoint,
                }),
            }
        }

        withheld.sort_unstable();
        narrowed.sort_unstable();
        EffectiveCapabilities {
            // Every grant here is an intersection of two grants that were
            // already validated, so the set cannot fail to build. Falling back
            // to the empty set keeps the failure closed rather than open.
            granted: CapabilitySet::new(granted).unwrap_or_else(|_| CapabilitySet::empty()),
            withheld,
            narrowed,
        }
    }
}

/// Intersects one requested grant with the matching ceiling grant.
///
/// Returns `None` when nothing survives, which the caller records as a
/// withheld capability rather than an empty grant, because an empty scope is
/// not a valid grant.
fn narrow(requested: &CapabilityGrant, ceiling: &CapabilityGrant) -> Option<CapabilityGrant> {
    match (requested, ceiling) {
        (CapabilityGrant::Log(request), CapabilityGrant::Log(limit)) => {
            let max_message_bytes = request.max_message_bytes.min(limit.max_message_bytes);
            (max_message_bytes > 0).then_some(CapabilityGrant::Log(LogGrant {
                // A higher floor is the narrower one.
                min_level: request.min_level.max(limit.min_level),
                max_message_bytes,
            }))
        }
        (CapabilityGrant::Config(request), CapabilityGrant::Config(limit)) => {
            narrow_config_scope(&request.scope, &limit.scope)
                .map(|scope| CapabilityGrant::Config(ConfigGrant { scope }))
        }
        (CapabilityGrant::Store(request), CapabilityGrant::Store(limit)) => {
            let max_total_bytes = request.max_total_bytes.min(limit.max_total_bytes);
            let max_value_bytes = request.max_value_bytes.min(limit.max_value_bytes);
            let max_keys = request.max_keys.min(limit.max_keys);
            if max_total_bytes == 0 || max_value_bytes == 0 || max_keys == 0 {
                return None;
            }
            Some(CapabilityGrant::Store(StoreGrant {
                max_total_bytes,
                // `CapabilityGrant::validate` requires the per-value ceiling to
                // stay under the total, and two independent minima can cross
                // that line, so clamp it back.
                max_value_bytes: u32::try_from(u64::from(max_value_bytes).min(max_total_bytes))
                    .unwrap_or(max_value_bytes),
                max_keys,
            }))
        }
        (CapabilityGrant::FilesystemRead(request), CapabilityGrant::FilesystemRead(limit)) => {
            narrow_filesystem(request, limit).map(CapabilityGrant::FilesystemRead)
        }
        (CapabilityGrant::FilesystemWrite(request), CapabilityGrant::FilesystemWrite(limit)) => {
            narrow_filesystem(request, limit).map(CapabilityGrant::FilesystemWrite)
        }
        (CapabilityGrant::Http(request), CapabilityGrant::Http(limit)) => {
            narrow_http(request, limit).map(CapabilityGrant::Http)
        }
        (CapabilityGrant::Clock(request), CapabilityGrant::Clock(limit)) => {
            Some(CapabilityGrant::Clock(ClockGrant {
                // A coarser reading is the narrower one.
                resolution_ms: request.resolution_ms.max(limit.resolution_ms).max(1),
            }))
        }
        (CapabilityGrant::Random(request), CapabilityGrant::Random(limit)) => {
            let max_bytes_per_call = request.max_bytes_per_call.min(limit.max_bytes_per_call);
            (max_bytes_per_call > 0)
                .then_some(CapabilityGrant::Random(RandomGrant { max_bytes_per_call }))
        }
        (CapabilityGrant::Tools(request), CapabilityGrant::Tools(limit)) => {
            let max_tools = request.max_tools.min(limit.max_tools);
            let max_schema_bytes = request.max_schema_bytes.min(limit.max_schema_bytes);
            (max_tools > 0 && max_schema_bytes > 0).then_some(CapabilityGrant::Tools(ToolsGrant {
                max_tools,
                max_schema_bytes,
            }))
        }
        (CapabilityGrant::Events(request), CapabilityGrant::Events(limit)) => {
            let emit_kinds: BTreeSet<_> = request
                .emit_kinds
                .intersection(&limit.emit_kinds)
                .copied()
                .collect();
            let max_payload_bytes = request.max_payload_bytes.min(limit.max_payload_bytes);
            (!emit_kinds.is_empty() && max_payload_bytes > 0).then_some(CapabilityGrant::Events(
                EventsGrant {
                    emit_kinds,
                    max_payload_bytes,
                },
            ))
        }
        // `CapabilitySet` is keyed by capability, so the caller only ever pairs
        // two grants of the same variant. A mismatch would mean the key and the
        // payload disagreed, which is refused rather than guessed at.
        _ => None,
    }
}

fn narrow_config_scope(requested: &ConfigScope, ceiling: &ConfigScope) -> Option<ConfigScope> {
    match (requested, ceiling) {
        (ConfigScope::OwnNamespace, ConfigScope::OwnNamespace) => Some(ConfigScope::OwnNamespace),
        (ConfigScope::Keys(keys), ConfigScope::OwnNamespace) => {
            (!keys.is_empty()).then(|| ConfigScope::Keys(keys.clone()))
        }
        (ConfigScope::OwnNamespace, ConfigScope::Keys(keys)) => {
            (!keys.is_empty()).then(|| ConfigScope::Keys(keys.clone()))
        }
        (ConfigScope::Keys(requested), ConfigScope::Keys(allowed)) => {
            let keys: BTreeSet<String> = requested.intersection(allowed).cloned().collect();
            (!keys.is_empty()).then_some(ConfigScope::Keys(keys))
        }
    }
}

fn narrow_filesystem(
    requested: &FilesystemGrant,
    ceiling: &FilesystemGrant,
) -> Option<FilesystemGrant> {
    // The surviving set is the intersection of two collections of directory
    // trees. Two trees intersect only when one contains the other, and the
    // intersection is then the deeper of the two - which is inside the ceiling
    // and inside the request, so neither side can be widened.
    let mut roots: Vec<PathBuf> = Vec::new();
    for root in &requested.roots {
        for allowed in &ceiling.roots {
            let overlap = if under(root, allowed) {
                root
            } else if under(allowed, root) {
                allowed
            } else {
                continue;
            };
            if !roots.iter().any(|kept| kept == overlap) {
                roots.push(overlap.clone());
            }
        }
    }
    let max_file_bytes = requested.max_file_bytes.min(ceiling.max_file_bytes);
    (!roots.is_empty() && max_file_bytes > 0).then_some(FilesystemGrant {
        roots,
        max_file_bytes,
    })
}

/// Whether `candidate` is `allowed` itself or lies below it.
///
/// Both sides come from a validated [`FilesystemGrant`], so both are absolute
/// and free of `..`. The host canonicalises the surviving roots afterwards and
/// re-checks this containment, so a root that only *looks* contained cannot
/// widen the grant.
fn under(candidate: &Path, allowed: &Path) -> bool {
    candidate.starts_with(allowed)
}

fn narrow_http(requested: &HttpGrant, ceiling: &HttpGrant) -> Option<HttpGrant> {
    let hosts: Vec<String> = requested
        .hosts
        .iter()
        .filter(|pattern| {
            ceiling
                .hosts
                .iter()
                .any(|allowed| pattern_within(pattern, allowed))
        })
        .cloned()
        .collect();
    let methods: Vec<HttpMethod> = requested
        .methods
        .iter()
        .filter(|method| ceiling.methods.contains(method))
        .copied()
        .collect();
    let max_response_bytes = requested.max_response_bytes.min(ceiling.max_response_bytes);
    (!hosts.is_empty() && !methods.is_empty() && max_response_bytes > 0).then_some(HttpGrant {
        hosts,
        methods,
        // Plaintext needs both sides to agree.
        allow_plaintext: requested.allow_plaintext && ceiling.allow_plaintext,
        max_response_bytes,
    })
}

/// Whether every host `pattern` can reach is also reachable through `allowed`.
///
/// A literal is covered when the ceiling pattern matches it. A wildcard is
/// only covered by an identical wildcard, because `*.a.example.com` and
/// `*.example.com` cover different name sets and a lexical suffix test would
/// let `*.evil-example.com` slip through.
fn pattern_within(pattern: &str, allowed: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    let allowed = allowed.trim_end_matches('.').to_ascii_lowercase();
    if pattern == allowed {
        return true;
    }
    if pattern.starts_with("*.") {
        // Only an identical wildcard covers a wildcard, and that case is the
        // equality above.
        return false;
    }
    host_matches(&allowed, &pattern)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::{OperatorPolicy, WithheldReason};
    use crate::capability::{
        Capability, CapabilityGrant, CapabilitySet, ClockGrant, ConfigGrant, ConfigScope,
        EventKind, EventsGrant, FilesystemGrant, HttpGrant, HttpMethod, LogGrant, LogLevel,
        RandomGrant, StoreGrant, ToolsGrant,
    };

    fn set(grants: Vec<CapabilityGrant>) -> CapabilitySet {
        CapabilitySet::new(grants).expect("valid grants")
    }

    /// Builds an absolute path that is absolute on this platform.
    ///
    /// `/srv/...` is not absolute on Windows, and grant validation rightly
    /// rejects a relative root, so the fixtures cannot hard-code POSIX paths.
    fn abs(relative: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:\\{}", relative.replace('/', "\\")))
        } else {
            PathBuf::from(format!("/{relative}"))
        }
    }

    #[test]
    fn a_plugin_with_no_ceiling_receives_nothing_it_asked_for() {
        let requested = set(vec![
            CapabilityGrant::Log(LogGrant {
                min_level: LogLevel::Trace,
                max_message_bytes: 4096,
            }),
            CapabilityGrant::FilesystemWrite(FilesystemGrant {
                roots: vec![abs("")],
                max_file_bytes: 1 << 30,
            }),
        ]);
        let effective = OperatorPolicy::deny_all().effective("hostile", &requested);
        assert_eq!(effective.granted().len(), 0);
        assert_eq!(effective.withheld().len(), 2);
        assert_eq!(effective.withheld()[0].capability(), Capability::Log);
        assert_eq!(
            effective.withheld()[0].reason(),
            WithheldReason::NotInCeiling
        );
        assert_eq!(
            effective.withheld()[1].capability(),
            Capability::FilesystemWrite
        );
        assert_eq!(
            effective.withheld()[1].reason(),
            WithheldReason::NotInCeiling
        );
    }

    #[test]
    fn a_ceiling_for_one_plugin_does_not_reach_another() {
        let ceiling = set(vec![CapabilityGrant::Clock(ClockGrant {
            resolution_ms: 1000,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::Clock(ClockGrant {
            resolution_ms: 1,
        })]);
        assert_eq!(policy.effective("alpha", &requested).granted().len(), 1);
        assert_eq!(policy.effective("beta", &requested).granted().len(), 0);
    }

    #[test]
    fn a_manifest_cannot_widen_a_filesystem_root() {
        let ceiling = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![abs("srv/plugins/alpha")],
            max_file_bytes: 4096,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![
                abs("srv/plugins/alpha/data"),
                abs("etc"),
                abs("srv/plugins/alpha-evil"),
            ],
            max_file_bytes: 1 << 30,
        })]);
        let effective = policy.effective("alpha", &requested);
        let grant = effective
            .granted()
            .filesystem_read()
            .expect("the in-scope root survives");
        assert_eq!(grant.roots, vec![abs("srv/plugins/alpha/data")]);
        assert_eq!(grant.max_file_bytes, 4096);
        assert_eq!(effective.narrowed(), [Capability::FilesystemRead]);
        assert!(effective.withheld().is_empty());
    }

    #[test]
    fn a_request_that_contains_the_ceiling_is_cut_back_to_the_ceiling() {
        // The manifest asks for the whole drive; the operator only ever offered
        // one subtree, so the intersection is that subtree.
        let ceiling = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![abs("srv/plugins/alpha")],
            max_file_bytes: 4096,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![abs("")],
            max_file_bytes: 1 << 30,
        })]);
        let effective = policy.effective("alpha", &requested);
        let grant = effective
            .granted()
            .filesystem_read()
            .expect("the overlap survives");
        assert_eq!(
            grant.roots,
            vec![abs("srv/plugins/alpha")],
            "the operator's root, not the manifest's, is what is granted"
        );
        assert_eq!(grant.max_file_bytes, 4096);
        assert_eq!(effective.narrowed(), [Capability::FilesystemRead]);
    }

    #[test]
    fn overlapping_roots_are_deduplicated_to_the_deeper_tree() {
        let ceiling = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![abs("srv/plugins/alpha"), abs("srv/plugins/alpha/data")],
            max_file_bytes: 4096,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![abs("srv/plugins/alpha/data")],
            max_file_bytes: 4096,
        })]);
        let effective = policy.effective("alpha", &requested);
        let grant = effective
            .granted()
            .filesystem_read()
            .expect("the overlap survives");
        assert_eq!(
            grant.roots,
            vec![abs("srv/plugins/alpha/data")],
            "the same tree must not be listed twice"
        );
    }

    #[test]
    fn a_filesystem_request_with_no_root_in_the_ceiling_is_withheld_entirely() {
        let ceiling = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![abs("srv/plugins/alpha")],
            max_file_bytes: 4096,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![abs("etc"), abs("var")],
            max_file_bytes: 4096,
        })]);
        let effective = policy.effective("alpha", &requested);
        assert!(effective.granted().filesystem_read().is_none());
        assert_eq!(
            effective.withheld()[0].reason(),
            WithheldReason::ScopesDisjoint
        );
    }

    #[test]
    fn asking_for_write_when_only_read_was_allowed_gets_nothing() {
        let ceiling = set(vec![CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![abs("srv/plugins/alpha")],
            max_file_bytes: 4096,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::FilesystemWrite(FilesystemGrant {
            roots: vec![abs("srv/plugins/alpha")],
            max_file_bytes: 4096,
        })]);
        let effective = policy.effective("alpha", &requested);
        assert!(effective.granted().is_empty());
        assert_eq!(
            effective.withheld()[0].capability(),
            Capability::FilesystemWrite
        );
        assert_eq!(
            effective.withheld()[0].reason(),
            WithheldReason::NotInCeiling
        );
    }

    #[test]
    fn http_hosts_methods_and_plaintext_are_all_intersected() {
        let ceiling = set(vec![CapabilityGrant::Http(HttpGrant {
            hosts: vec!["api.example.com".to_owned(), "*.cdn.example.com".to_owned()],
            methods: vec![HttpMethod::Get, HttpMethod::Head],
            allow_plaintext: false,
            max_response_bytes: 4096,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::Http(HttpGrant {
            hosts: vec![
                "api.example.com".to_owned(),
                "evil.example.com".to_owned(),
                "one.cdn.example.com".to_owned(),
                "*.example.com".to_owned(),
            ],
            methods: vec![HttpMethod::Get, HttpMethod::Post, HttpMethod::Delete],
            allow_plaintext: true,
            max_response_bytes: 1 << 30,
        })]);
        let grant = policy
            .effective("alpha", &requested)
            .into_granted()
            .http()
            .cloned()
            .expect("http survives");
        assert_eq!(
            grant.hosts,
            vec![
                "api.example.com".to_owned(),
                "one.cdn.example.com".to_owned()
            ]
        );
        assert_eq!(grant.methods, vec![HttpMethod::Get]);
        assert!(!grant.allow_plaintext);
        assert_eq!(grant.max_response_bytes, 4096);
    }

    #[test]
    fn a_wildcard_request_is_never_covered_by_a_different_wildcard() {
        let ceiling = set(vec![CapabilityGrant::Http(HttpGrant {
            hosts: vec!["*.example.com".to_owned()],
            methods: vec![HttpMethod::Get],
            allow_plaintext: false,
            max_response_bytes: 4096,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        for hostile in ["*.evil-example.com", "*.other.com", "*.a.example.com"] {
            let requested = set(vec![CapabilityGrant::Http(HttpGrant {
                hosts: vec![hostile.to_owned()],
                methods: vec![HttpMethod::Get],
                allow_plaintext: false,
                max_response_bytes: 4096,
            })]);
            let effective = policy.effective("alpha", &requested);
            assert!(
                effective.granted().http().is_none(),
                "`{hostile}` must not be covered by `*.example.com`"
            );
        }
        let requested = set(vec![CapabilityGrant::Http(HttpGrant {
            hosts: vec!["*.example.com".to_owned()],
            methods: vec![HttpMethod::Get],
            allow_plaintext: false,
            max_response_bytes: 4096,
        })]);
        assert!(
            policy
                .effective("alpha", &requested)
                .granted()
                .http()
                .is_some(),
            "the identical wildcard is covered"
        );
    }

    #[test]
    fn quotas_always_take_the_tighter_of_the_two_sides() {
        let ceiling = set(vec![
            CapabilityGrant::Log(LogGrant {
                min_level: LogLevel::Warn,
                max_message_bytes: 128,
            }),
            CapabilityGrant::Store(StoreGrant {
                max_total_bytes: 1024,
                max_value_bytes: 512,
                max_keys: 4,
            }),
            CapabilityGrant::Random(RandomGrant {
                max_bytes_per_call: 32,
            }),
            CapabilityGrant::Tools(ToolsGrant {
                max_tools: 2,
                max_schema_bytes: 256,
            }),
            CapabilityGrant::Clock(ClockGrant {
                resolution_ms: 1000,
            }),
        ]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![
            CapabilityGrant::Log(LogGrant {
                min_level: LogLevel::Trace,
                max_message_bytes: 65536,
            }),
            CapabilityGrant::Store(StoreGrant {
                max_total_bytes: 1 << 30,
                max_value_bytes: 1 << 20,
                max_keys: 4096,
            }),
            CapabilityGrant::Random(RandomGrant {
                max_bytes_per_call: 1 << 20,
            }),
            CapabilityGrant::Tools(ToolsGrant {
                max_tools: 200,
                max_schema_bytes: 65536,
            }),
            CapabilityGrant::Clock(ClockGrant { resolution_ms: 1 }),
        ]);
        let granted = policy.effective("alpha", &requested).into_granted();
        let log = granted.log().expect("log");
        assert_eq!(log.min_level, LogLevel::Warn);
        assert_eq!(log.max_message_bytes, 128);
        let store = granted.store().expect("store");
        assert_eq!(store.max_total_bytes, 1024);
        assert_eq!(store.max_value_bytes, 512);
        assert_eq!(store.max_keys, 4);
        assert_eq!(granted.random().expect("random").max_bytes_per_call, 32);
        let tools = granted.tools().expect("tools");
        assert_eq!(tools.max_tools, 2);
        assert_eq!(tools.max_schema_bytes, 256);
        assert_eq!(granted.clock().expect("clock").resolution_ms, 1000);
    }

    #[test]
    fn a_manifest_asking_for_less_than_the_ceiling_keeps_its_own_smaller_numbers() {
        let ceiling = set(vec![CapabilityGrant::Random(RandomGrant {
            max_bytes_per_call: 4096,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::Random(RandomGrant {
            max_bytes_per_call: 16,
        })]);
        let effective = policy.effective("alpha", &requested);
        assert_eq!(
            effective
                .granted()
                .random()
                .expect("random")
                .max_bytes_per_call,
            16
        );
        assert!(effective.is_unrestricted(), "nothing had to be reduced");
    }

    #[test]
    fn config_keys_and_event_kinds_are_set_intersections() {
        let ceiling = set(vec![
            CapabilityGrant::Config(ConfigGrant {
                scope: ConfigScope::Keys(BTreeSet::from(["alpha".to_owned(), "beta".to_owned()])),
            }),
            CapabilityGrant::Events(EventsGrant {
                emit_kinds: BTreeSet::from([EventKind::Heartbeat, EventKind::Message]),
                max_payload_bytes: 256,
            }),
        ]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![
            CapabilityGrant::Config(ConfigGrant {
                scope: ConfigScope::OwnNamespace,
            }),
            CapabilityGrant::Events(EventsGrant {
                emit_kinds: BTreeSet::from([
                    EventKind::Heartbeat,
                    EventKind::Shutdown,
                    EventKind::ToolResult,
                ]),
                max_payload_bytes: 4096,
            }),
        ]);
        let granted = policy.effective("alpha", &requested).into_granted();
        assert_eq!(
            granted.config().expect("config").scope,
            ConfigScope::Keys(BTreeSet::from(["alpha".to_owned(), "beta".to_owned()])),
            "asking for the whole namespace collapses onto the allowed keys"
        );
        let events = granted.events().expect("events");
        assert_eq!(events.emit_kinds, BTreeSet::from([EventKind::Heartbeat]));
        assert_eq!(events.max_payload_bytes, 256);
    }

    #[test]
    fn disjoint_config_keys_withhold_the_capability() {
        let ceiling = set(vec![CapabilityGrant::Config(ConfigGrant {
            scope: ConfigScope::Keys(BTreeSet::from(["alpha".to_owned()])),
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        let requested = set(vec![CapabilityGrant::Config(ConfigGrant {
            scope: ConfigScope::Keys(BTreeSet::from(["secret".to_owned()])),
        })]);
        let effective = policy.effective("alpha", &requested);
        assert!(effective.granted().config().is_none());
        assert_eq!(
            effective.withheld()[0].reason(),
            WithheldReason::ScopesDisjoint
        );
    }

    #[test]
    fn every_produced_grant_still_passes_its_own_validation() {
        let ceiling = set(vec![CapabilityGrant::Store(StoreGrant {
            max_total_bytes: 64,
            max_value_bytes: 64,
            max_keys: 1,
        })]);
        let policy = OperatorPolicy::deny_all().allow("alpha", ceiling);
        // The requested per-value ceiling is larger than the allowed total, so
        // a naive per-field minimum would produce an invalid grant.
        let requested = set(vec![CapabilityGrant::Store(StoreGrant {
            max_total_bytes: 1 << 20,
            max_value_bytes: 4096,
            max_keys: 16,
        })]);
        let granted = policy.effective("alpha", &requested).into_granted();
        let store = granted.store().expect("store survives");
        assert_eq!(store.max_total_bytes, 64);
        assert_eq!(store.max_value_bytes, 64);
        for grant in granted.grants() {
            grant.validate().expect("the narrowed grant is still valid");
        }
    }
}

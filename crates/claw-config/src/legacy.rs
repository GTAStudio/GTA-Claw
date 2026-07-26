//! Audited disposition inventory for automatically migrated legacy runtime settings.
//!
//! Migration into a [`ConfigSnapshot`](crate::ConfigSnapshot) proves only that a
//! value was accepted and represented. It does not prove that another crate
//! consumes or enforces that value. [`LEGACY_RUNTIME_CONFIGS`] records that
//! distinction explicitly.

/// Why an automatically migrated runtime setting remains inert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptedOnlyReason {
    /// No production consumer outside `claw-config` currently binds the value.
    NoProductionConsumer,
}

/// The intended subsystem owner for a legacy runtime setting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRuntimeOwner {
    /// Provider credentials and authentication policy.
    Authentication,
    /// Agent role acquisition and loading.
    RoleLoading,
    /// Teams, Telegram, Discord, and WhatsApp adapters.
    ChannelAdapters,
    /// Gateway and HTTP ingress behavior.
    GatewayHttp,
    /// Logging and diagnostic behavior.
    Observability,
    /// Ephemeral provider-session caching.
    ProviderSessionCache,
    /// Provider selection and request behavior.
    ProviderRuntime,
    /// Skill discovery, execution, and outbound policy.
    SkillRuntime,
    /// Signed runtime update behavior.
    UpdateRuntime,
    /// Administrative HTTP behavior.
    Administration,
    /// Outbound HTTP client behavior.
    OutboundHttp,
}

/// Independent consumer evidence for an enforced setting.
///
/// This value has no public constructor. A future `claw-config` change may
/// construct it only after reviewing an actual production consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerEnforcement {
    consumer: LegacyRuntimeOwner,
    evidence: &'static str,
}

impl ConsumerEnforcement {
    /// Creates evidence that a production subsystem enforces the setting.
    ///
    /// `evidence` must name the reviewed implementation surface precisely.
    #[must_use]
    pub const fn new(consumer: LegacyRuntimeOwner, evidence: &'static str) -> Self {
        assert!(
            !evidence.is_empty(),
            "consumer enforcement evidence must not be empty"
        );
        Self { consumer, evidence }
    }

    /// Returns the subsystem that enforces the setting.
    #[must_use]
    pub const fn consumer(self) -> LegacyRuntimeOwner {
        self.consumer
    }

    /// Returns the implementation evidence recorded during consumer review.
    #[must_use]
    pub const fn evidence(self) -> &'static str {
        self.evidence
    }
}

/// Whether an accepted legacy runtime value has a production consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRuntimeDisposition {
    /// Migration accepts the value, but no production consumer binds it.
    AcceptedOnly(AcceptedOnlyReason),
    /// Independent consumer evidence establishes behavioral enforcement.
    Enforced(ConsumerEnforcement),
}

/// One semantic legacy runtime setting and its current routing disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyRuntimeConfig {
    key: LegacyRuntimeKey,
    legacy_env: &'static str,
    aliases: &'static [&'static str],
    target_json5_path: &'static str,
    intended_owner: LegacyRuntimeOwner,
    disposition: LegacyRuntimeDisposition,
    semantic_note: &'static str,
}

impl LegacyRuntimeConfig {
    const fn accepted_only(
        key: LegacyRuntimeKey,
        legacy_env: &'static str,
        aliases: &'static [&'static str],
        target_json5_path: &'static str,
        intended_owner: LegacyRuntimeOwner,
        semantic_note: &'static str,
    ) -> Self {
        Self {
            key,
            legacy_env,
            aliases,
            target_json5_path,
            intended_owner,
            disposition: LegacyRuntimeDisposition::AcceptedOnly(
                AcceptedOnlyReason::NoProductionConsumer,
            ),
            semantic_note,
        }
    }

    /// Returns the stable typed identity of this semantic setting.
    #[must_use]
    pub const fn key(self) -> LegacyRuntimeKey {
        self.key
    }

    /// Returns the canonical audited legacy environment variable.
    #[must_use]
    pub const fn legacy_env(self) -> &'static str {
        self.legacy_env
    }

    /// Returns alternative environment spellings for the same semantic setting.
    #[must_use]
    pub const fn aliases(self) -> &'static [&'static str] {
        self.aliases
    }

    /// Returns the canonical destination path in the legacy JSON5 envelope.
    #[must_use]
    pub const fn target_json5_path(self) -> &'static str {
        self.target_json5_path
    }

    /// Returns the subsystem intended to consume this setting.
    #[must_use]
    pub const fn intended_owner(self) -> LegacyRuntimeOwner {
        self.intended_owner
    }

    /// Returns whether production behavior currently enforces the setting.
    #[must_use]
    pub const fn disposition(self) -> LegacyRuntimeDisposition {
        self.disposition
    }

    /// Returns a concise semantic and routing note.
    #[must_use]
    pub const fn semantic_note(self) -> &'static str {
        self.semantic_note
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LegacyMappingContract {
    pub(crate) id: MappingId,
    pub(crate) legacy_env: &'static str,
    pub(crate) aliases: &'static [&'static str],
    pub(crate) scope: &'static str,
    pub(crate) target: &'static str,
    pub(crate) secret: bool,
    pub(crate) _default_json: &'static str,
    pub(crate) _conversion: &'static str,
    pub(crate) _validation: &'static str,
    pub(crate) _required_when: &'static str,
    pub(crate) _known_legacy_quirk: Option<&'static str>,
}

include!(concat!(env!("OUT_DIR"), "/legacy_mappings.rs"));

/// Returns the registry entry for a typed semantic key.
#[must_use]
pub fn legacy_runtime_config(key: LegacyRuntimeKey) -> &'static LegacyRuntimeConfig {
    LEGACY_RUNTIME_CONFIGS
        .iter()
        .find(|entry| entry.key() == key)
        .expect("generated legacy runtime key must have exactly one registry entry")
}

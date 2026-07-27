use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use super::ValidationPolicy;

/// A closed Gateway role from the validator-owned inventory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Ordinary control-plane RPC client.
    Operator,
    /// Capability-host RPC client.
    Node,
    /// Closed worker protocol role, not admitted to ordinary Gateway RPC.
    Worker,
}

impl Role {
    /// Returns the exact wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Node => "node",
            Self::Worker => "worker",
        }
    }

    /// Parses an exact, case-sensitive role identity.
    #[must_use]
    pub fn from_identity(identity: &str) -> Option<Self> {
        roles()
            .iter()
            .copied()
            .find(|role| role.as_str() == identity)
    }
}

/// A closed operator scope from the validator-owned inventory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum OperatorScope {
    /// Full operator authority.
    #[serde(rename = "operator.admin")]
    Admin,
    /// Read-only operator authority.
    #[serde(rename = "operator.read")]
    Read,
    /// Mutating operator authority; also implies read.
    #[serde(rename = "operator.write")]
    Write,
    /// Approval workflow authority.
    #[serde(rename = "operator.approvals")]
    Approvals,
    /// Device/node pairing authority.
    #[serde(rename = "operator.pairing")]
    Pairing,
    /// Authority to read Talk secrets.
    #[serde(rename = "operator.talk.secrets")]
    TalkSecrets,
}

impl OperatorScope {
    /// Returns the exact wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "operator.admin",
            Self::Read => "operator.read",
            Self::Write => "operator.write",
            Self::Approvals => "operator.approvals",
            Self::Pairing => "operator.pairing",
            Self::TalkSecrets => "operator.talk.secrets",
        }
    }

    /// Parses an exact, case-sensitive scope identity.
    #[must_use]
    pub fn from_identity(identity: &str) -> Option<Self> {
        operator_scopes()
            .iter()
            .copied()
            .find(|scope| scope.as_str() == identity)
    }
}

/// Authorization classification frozen for a core method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MethodScope {
    /// A statically scoped operator method.
    Operator(OperatorScope),
    /// A node-role-only method.
    Node,
    /// A method whose operator scope must be supplied by its caller/runtime resolver.
    Dynamic,
}

/// Frozen descriptor for one callable core Gateway method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreMethod {
    name: &'static str,
    scope: MethodScope,
    advertised: bool,
}

impl CoreMethod {
    pub(crate) const fn new(name: &'static str, scope: MethodScope, advertised: bool) -> Self {
        Self {
            name,
            scope,
            advertised,
        }
    }

    /// Returns the exact, case-sensitive method identity.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the frozen authorization classification.
    #[must_use]
    pub const fn scope(self) -> MethodScope {
        self.scope
    }

    /// Reports whether this method appears in the conservative hello feature list.
    #[must_use]
    pub const fn advertised(self) -> bool {
        self.advertised
    }
}

/// Frozen descriptor for one core Gateway event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreEvent {
    name: &'static str,
}

impl CoreEvent {
    pub(crate) const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Returns the exact, case-sensitive event identity.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }
}

include!(concat!(env!("OUT_DIR"), "/gateway_registry.rs"));

/// Returns the pinned upstream baseline used to generate this registry.
#[must_use]
pub const fn baseline_sha() -> &'static str {
    GENERATED_BASELINE_SHA
}

/// Returns all 278 frozen core method descriptors in canonical inventory order.
#[must_use]
pub const fn core_methods() -> &'static [CoreMethod] {
    &GENERATED_CORE_METHODS
}

/// Returns all 33 frozen core events in canonical inventory order.
#[must_use]
pub const fn core_events() -> &'static [CoreEvent] {
    &GENERATED_CORE_EVENTS
}

/// Returns all three roles, including the closed worker role.
#[must_use]
pub const fn roles() -> &'static [Role] {
    &GENERATED_ROLES
}

/// Returns all six closed operator scopes.
#[must_use]
pub const fn operator_scopes() -> &'static [OperatorScope] {
    &GENERATED_SCOPES
}

/// Resolves a core method by exact ordinal UTF-8 identity.
#[must_use]
pub fn resolve_core_method(name: &str) -> Option<&'static CoreMethod> {
    core_methods().iter().find(|method| method.name == name)
}

/// Resolves a core event by exact ordinal UTF-8 identity.
#[must_use]
pub fn resolve_core_event(name: &str) -> Option<&'static CoreEvent> {
    core_events().iter().find(|event| event.name == name)
}

/// A validated runtime plugin method that remains distinct from the core registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicPluginMethod {
    name: String,
    scope: OperatorScope,
}

impl DynamicPluginMethod {
    /// Constructs a plugin method after enforcing name and operator-scope policy.
    ///
    /// Missing legacy metadata defaults to admin. Reserved upstream namespaces
    /// are always coerced to admin and can never be weakened by a plugin.
    ///
    /// # Errors
    ///
    /// - [`RegistryError::EmptyPluginMethod`] — `raw_name` is empty after
    ///   trimming surrounding whitespace.
    /// - [`RegistryError::PluginMethodTooLong`] — the trimmed name exceeds
    ///   `policy.max_name_bytes`.
    /// - [`RegistryError::CoreMethodShadow`] — the trimmed name is byte-for-byte
    ///   one of the frozen core methods, which a plugin must never take over.
    pub fn new(
        raw_name: impl Into<String>,
        scope: Option<OperatorScope>,
        policy: &ValidationPolicy,
    ) -> Result<Self, RegistryError> {
        let raw_name = raw_name.into();
        let name = raw_name.trim();
        if name.is_empty() {
            return Err(RegistryError::EmptyPluginMethod);
        }
        if name.len() > policy.max_name_bytes {
            return Err(RegistryError::PluginMethodTooLong {
                actual: name.len(),
                limit: policy.max_name_bytes,
            });
        }
        if resolve_core_method(name).is_some() {
            return Err(RegistryError::CoreMethodShadow(name.to_owned()));
        }
        let scope = if is_reserved_admin_plugin_method(name) {
            OperatorScope::Admin
        } else {
            scope.unwrap_or(OperatorScope::Admin)
        };
        Ok(Self {
            name: name.to_owned(),
            scope,
        })
    }

    /// Returns the exact normalized method identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns this plugin method's explicit authorization classification.
    #[must_use]
    pub const fn scope(&self) -> OperatorScope {
        self.scope
    }
}

fn is_reserved_admin_plugin_method(name: &str) -> bool {
    ["exec.approvals.", "config.", "wizard.", "update."]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// An exact-identity registry for explicitly opted-in runtime plugin methods.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DynamicPluginRegistry {
    methods: BTreeMap<String, DynamicPluginMethod>,
}

impl DynamicPluginRegistry {
    /// Creates an empty plugin registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            methods: BTreeMap::new(),
        }
    }

    /// Validates and registers one method, rejecting duplicates and core shadows.
    ///
    /// # Errors
    ///
    /// Returns every rejection listed for [`DynamicPluginMethod::new`], plus
    /// [`RegistryError::DuplicatePluginMethod`] when a method with this exact
    /// normalized identity is already registered. Registration is all-or-
    /// nothing: a rejected method leaves the registry unchanged.
    pub fn register(
        &mut self,
        raw_name: impl Into<String>,
        scope: Option<OperatorScope>,
        policy: &ValidationPolicy,
    ) -> Result<&DynamicPluginMethod, RegistryError> {
        let method = DynamicPluginMethod::new(raw_name, scope, policy)?;
        match self.methods.entry(method.name.clone()) {
            Entry::Occupied(_) => Err(RegistryError::DuplicatePluginMethod(method.name)),
            Entry::Vacant(slot) => Ok(slot.insert(method)),
        }
    }

    /// Parses untrusted plugin scope metadata through the closed operator set.
    ///
    /// Omitted legacy metadata defaults to admin. Empty, node, dynamic, unknown,
    /// or incorrectly cased scope strings are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::InvalidPluginScope`] when `declared_scope` is
    /// `Some` but is not one of the six closed operator scope identities, and
    /// otherwise every rejection listed for [`DynamicPluginRegistry::register`].
    pub fn register_declared(
        &mut self,
        raw_name: impl Into<String>,
        declared_scope: Option<&str>,
        policy: &ValidationPolicy,
    ) -> Result<&DynamicPluginMethod, RegistryError> {
        let scope = match declared_scope {
            None => None,
            Some(scope) => Some(
                OperatorScope::from_identity(scope)
                    .ok_or_else(|| RegistryError::InvalidPluginScope(scope.to_owned()))?,
            ),
        };
        self.register(raw_name, scope, policy)
    }

    /// Resolves a registered plugin method using exact ordinal UTF-8 comparison.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&DynamicPluginMethod> {
        self.methods.get(name)
    }

    /// Returns the number of registered runtime methods.
    #[must_use]
    pub fn len(&self) -> usize {
        self.methods.len()
    }

    /// Reports whether no runtime methods are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }

    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.methods.keys().map(String::as_str)
    }
}

/// A resolved Gateway method whose core/plugin provenance is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayMethod<'a> {
    /// A frozen core method.
    Core(&'static CoreMethod),
    /// An explicitly registered runtime plugin method.
    DynamicPlugin(&'a DynamicPluginMethod),
}

impl<'a> GatewayMethod<'a> {
    /// Returns the authorization classification.
    #[must_use]
    pub const fn scope(self) -> MethodScope {
        match self {
            Self::Core(method) => method.scope(),
            Self::DynamicPlugin(method) => MethodScope::Operator(method.scope()),
        }
    }

    /// Returns the exact method identity without imposing a static lifetime.
    #[must_use]
    pub fn identity(self) -> &'a str {
        match self {
            Self::Core(method) => method.name(),
            Self::DynamicPlugin(method) => method.name(),
        }
    }
}

/// Explicit policy controlling whether runtime plugin lookup is permitted.
#[derive(Clone, Copy, Debug)]
pub enum PluginLookup<'a> {
    /// Resolve only the frozen core registry.
    Deny,
    /// Resolve against this caller-supplied runtime plugin registry after core lookup.
    Allow(&'a DynamicPluginRegistry),
}

/// Resolves a method without ever collapsing a dynamic plugin into the core variant.
///
/// # Errors
///
/// Returns [`RegistryError::UnknownMethod`] when `name` is not byte-for-byte a
/// frozen core method and either `plugin_lookup` is [`PluginLookup::Deny`] or
/// the supplied registry holds no method with that exact identity. Lookup is
/// ordinal and case-sensitive, so a differently cased spelling fails closed.
pub fn resolve_gateway_method<'a>(
    name: &str,
    plugin_lookup: PluginLookup<'a>,
) -> Result<GatewayMethod<'a>, RegistryError> {
    if let Some(method) = resolve_core_method(name) {
        return Ok(GatewayMethod::Core(method));
    }
    if let PluginLookup::Allow(registry) = plugin_lookup
        && let Some(method) = registry.resolve(name)
    {
        return Ok(GatewayMethod::DynamicPlugin(method));
    }
    Err(RegistryError::UnknownMethod(name.to_owned()))
}

/// A registry construction or lookup failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    /// A plugin method is empty after trimming.
    EmptyPluginMethod,
    /// A plugin method exceeds the caller's explicit UTF-8 byte limit.
    PluginMethodTooLong {
        /// Actual UTF-8 byte length.
        actual: usize,
        /// Configured limit.
        limit: usize,
    },
    /// A plugin method attempted to shadow a frozen core method.
    CoreMethodShadow(String),
    /// A plugin method duplicates another runtime registration.
    DuplicatePluginMethod(String),
    /// Plugin metadata named a non-operator, empty, unknown, or incorrectly cased scope.
    InvalidPluginScope(String),
    /// No core or explicitly opted-in plugin method has this exact identity.
    UnknownMethod(String),
}

impl Display for RegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPluginMethod => formatter.write_str("plugin method name is empty"),
            Self::PluginMethodTooLong { actual, limit } => {
                write!(
                    formatter,
                    "plugin method is {actual} bytes; limit is {limit}"
                )
            }
            Self::CoreMethodShadow(name) => {
                write!(formatter, "plugin shadows core method `{name}`")
            }
            Self::DuplicatePluginMethod(name) => {
                write!(formatter, "duplicate plugin method `{name}`")
            }
            Self::InvalidPluginScope(scope) => {
                write!(formatter, "invalid plugin operator scope `{scope}`")
            }
            Self::UnknownMethod(name) => write!(formatter, "unknown gateway method `{name}`"),
        }
    }
}

impl Error for RegistryError {}

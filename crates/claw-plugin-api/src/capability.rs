//! The capability model: what a plugin is allowed to ask the host to do.
//!
//! The host denies every side effect by default. A plugin only reaches a host
//! function when its manifest declares the matching [`Capability`] *and* the
//! operator's grant set contains a [`CapabilityGrant`] whose scope covers the
//! concrete call. Both checks happen inside the host function itself, so an
//! unlinked, mis-linked or forged import cannot bypass them.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Longest accepted plugin-facing key (configuration and store).
pub const MAX_KEY_LEN: usize = 128;
/// Upper bound the host will accept for a single random draw.
pub const MAX_RANDOM_BYTES: u32 = 1 << 20;
/// Upper bound the host will accept for a clock quantisation step.
pub const MAX_CLOCK_RESOLUTION_MS: u64 = 3_600_000;
/// Upper bound the host will accept for registered tools per plugin.
pub const MAX_TOOLS: u32 = 256;

/// One host-mediated side effect class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Structured logging.
    Log,
    /// Reading plugin-scoped configuration.
    Config,
    /// Plugin-scoped key/value persistence.
    Store,
    /// Reading files below granted roots.
    FilesystemRead,
    /// Writing files below granted roots.
    FilesystemWrite,
    /// Outbound HTTP over a host-owned transport.
    Http,
    /// Coarse wall-clock reads.
    Clock,
    /// Host-provided randomness.
    Random,
    /// Tool registration.
    Tools,
    /// Publishing events back to the host.
    Events,
}

impl Capability {
    /// Every capability defined by this ABI generation.
    pub const ALL: [Self; 10] = [
        Self::Log,
        Self::Config,
        Self::Store,
        Self::FilesystemRead,
        Self::FilesystemWrite,
        Self::Http,
        Self::Clock,
        Self::Random,
        Self::Tools,
        Self::Events,
    ];

    /// Stable wire name, matching the manifest encoding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Config => "config",
            Self::Store => "store",
            Self::FilesystemRead => "filesystem-read",
            Self::FilesystemWrite => "filesystem-write",
            Self::Http => "http",
            Self::Clock => "clock",
            Self::Random => "random",
            Self::Tools => "tools",
            Self::Events => "events",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Severity ceiling for the `log` capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogLevel {
    /// Very fine-grained tracing.
    Trace,
    /// Developer diagnostics.
    Debug,
    /// Normal operational information.
    Info,
    /// Recoverable anomaly.
    Warn,
    /// Failure the operator should see.
    Error,
}

/// Event classes a plugin may observe or publish.
///
/// Mirrors `gta-claw:plugin/types.event-kind`. `claw-plugin-host` proves the
/// mapping is total in both directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventKind {
    /// A conversation session was created.
    SessionStarted,
    /// A conversation session was closed.
    SessionEnded,
    /// A chat message was observed.
    Message,
    /// A tool invocation produced a result.
    ToolResult,
    /// The plugin-scoped configuration changed.
    ConfigChanged,
    /// Periodic liveness tick.
    Heartbeat,
    /// The host is shutting the plugin down.
    Shutdown,
}

impl EventKind {
    /// Every event kind defined by this ABI generation.
    pub const ALL: [Self; 7] = [
        Self::SessionStarted,
        Self::SessionEnded,
        Self::Message,
        Self::ToolResult,
        Self::ConfigChanged,
        Self::Heartbeat,
        Self::Shutdown,
    ];
}

/// HTTP methods a plugin may be allowed to issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
}

impl HttpMethod {
    /// Uppercase wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// Which configuration keys a plugin may read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConfigScope {
    /// Every key in the plugin's own namespace.
    OwnNamespace,
    /// Only the listed keys.
    Keys(BTreeSet<String>),
}

/// Scope of the `log` capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogGrant {
    /// Lowest severity the host will accept from this plugin.
    pub min_level: LogLevel,
    /// Longest log message the host will accept, in bytes.
    pub max_message_bytes: u32,
}

/// Scope of the `config` capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigGrant {
    /// Readable keys.
    pub scope: ConfigScope,
}

/// Scope of the `store` capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreGrant {
    /// Total bytes the plugin may keep stored.
    pub max_total_bytes: u64,
    /// Longest single value, in bytes.
    pub max_value_bytes: u32,
    /// Maximum number of distinct keys.
    pub max_keys: u32,
}

/// Scope of `filesystem-read` or `filesystem-write`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemGrant {
    /// Absolute host directories the plugin may reach. Plugin-supplied paths
    /// are always relative and are resolved below one of these.
    pub roots: Vec<PathBuf>,
    /// Longest file the host will read or write for this plugin, in bytes.
    pub max_file_bytes: u64,
}

/// Scope of the `http` capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpGrant {
    /// Hosts the plugin may contact. An entry may be a bare host name or a
    /// single-label wildcard such as `*.example.com`.
    pub hosts: Vec<String>,
    /// Methods the plugin may issue.
    pub methods: Vec<HttpMethod>,
    /// Whether plaintext `http://` targets are allowed at all.
    pub allow_plaintext: bool,
    /// Longest response body the host will hand back, in bytes.
    pub max_response_bytes: u64,
}

/// Scope of the `clock` capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockGrant {
    /// Quantisation step applied to every reading, in milliseconds.
    pub resolution_ms: u64,
}

/// Scope of the `random` capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RandomGrant {
    /// Longest single draw, in bytes.
    pub max_bytes_per_call: u32,
}

/// Scope of the `tools` capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolsGrant {
    /// Maximum number of tools this plugin may have registered at once.
    pub max_tools: u32,
    /// Longest JSON Schema string accepted per tool, in bytes.
    pub max_schema_bytes: u32,
}

/// Scope of the `events` capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsGrant {
    /// Event kinds the plugin may publish.
    pub emit_kinds: BTreeSet<EventKind>,
    /// Longest event payload, in bytes.
    pub max_payload_bytes: u32,
}

/// One granted capability together with its scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "capability", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CapabilityGrant {
    /// Structured logging.
    Log(LogGrant),
    /// Reading plugin-scoped configuration.
    Config(ConfigGrant),
    /// Plugin-scoped key/value persistence.
    Store(StoreGrant),
    /// Reading files below granted roots.
    FilesystemRead(FilesystemGrant),
    /// Writing files below granted roots.
    FilesystemWrite(FilesystemGrant),
    /// Outbound HTTP.
    Http(HttpGrant),
    /// Coarse wall-clock reads.
    Clock(ClockGrant),
    /// Host-provided randomness.
    Random(RandomGrant),
    /// Tool registration.
    Tools(ToolsGrant),
    /// Publishing events back to the host.
    Events(EventsGrant),
}

impl CapabilityGrant {
    /// The capability this grant scopes.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        match self {
            Self::Log(_) => Capability::Log,
            Self::Config(_) => Capability::Config,
            Self::Store(_) => Capability::Store,
            Self::FilesystemRead(_) => Capability::FilesystemRead,
            Self::FilesystemWrite(_) => Capability::FilesystemWrite,
            Self::Http(_) => Capability::Http,
            Self::Clock(_) => Capability::Clock,
            Self::Random(_) => Capability::Random,
            Self::Tools(_) => Capability::Tools,
            Self::Events(_) => Capability::Events,
        }
    }

    /// Checks the internal consistency of the grant's scope.
    ///
    /// # Errors
    ///
    /// Returns [`GrantError`] describing the first violated rule.
    pub fn validate(&self) -> Result<(), GrantError> {
        match self {
            Self::Log(grant) => require(
                grant.max_message_bytes > 0,
                self.capability(),
                "max_message_bytes must be positive",
            ),
            Self::Config(grant) => match &grant.scope {
                ConfigScope::OwnNamespace => Ok(()),
                ConfigScope::Keys(keys) => {
                    require(
                        !keys.is_empty(),
                        self.capability(),
                        "keys must not be empty",
                    )?;
                    for key in keys {
                        validate_key(key).map_err(|reason| GrantError {
                            capability: self.capability(),
                            reason,
                        })?;
                    }
                    Ok(())
                }
            },
            Self::Store(grant) => {
                require(
                    grant.max_total_bytes > 0,
                    self.capability(),
                    "max_total_bytes must be positive",
                )?;
                require(
                    grant.max_value_bytes > 0,
                    self.capability(),
                    "max_value_bytes must be positive",
                )?;
                require(
                    grant.max_keys > 0,
                    self.capability(),
                    "max_keys must be positive",
                )?;
                require(
                    u64::from(grant.max_value_bytes) <= grant.max_total_bytes,
                    self.capability(),
                    "max_value_bytes must not exceed max_total_bytes",
                )
            }
            Self::FilesystemRead(grant) | Self::FilesystemWrite(grant) => {
                require(
                    !grant.roots.is_empty(),
                    self.capability(),
                    "roots must not be empty",
                )?;
                require(
                    grant.max_file_bytes > 0,
                    self.capability(),
                    "max_file_bytes must be positive",
                )?;
                for root in &grant.roots {
                    require(
                        root.is_absolute(),
                        self.capability(),
                        "every root must be absolute",
                    )?;
                    require(
                        !root.components().any(|c| matches!(c, Component::ParentDir)),
                        self.capability(),
                        "roots must not contain `..`",
                    )?;
                }
                Ok(())
            }
            Self::Http(grant) => {
                require(
                    !grant.hosts.is_empty(),
                    self.capability(),
                    "hosts must not be empty",
                )?;
                require(
                    !grant.methods.is_empty(),
                    self.capability(),
                    "methods must not be empty",
                )?;
                require(
                    grant.max_response_bytes > 0,
                    self.capability(),
                    "max_response_bytes must be positive",
                )?;
                for host in &grant.hosts {
                    validate_host_pattern(host).map_err(|reason| GrantError {
                        capability: self.capability(),
                        reason,
                    })?;
                }
                Ok(())
            }
            Self::Clock(grant) => {
                require(
                    grant.resolution_ms > 0,
                    self.capability(),
                    "resolution_ms must be positive",
                )?;
                require(
                    grant.resolution_ms <= MAX_CLOCK_RESOLUTION_MS,
                    self.capability(),
                    "resolution_ms is above the host ceiling",
                )
            }
            Self::Random(grant) => {
                require(
                    grant.max_bytes_per_call > 0,
                    self.capability(),
                    "max_bytes_per_call must be positive",
                )?;
                require(
                    grant.max_bytes_per_call <= MAX_RANDOM_BYTES,
                    self.capability(),
                    "max_bytes_per_call is above the host ceiling",
                )
            }
            Self::Tools(grant) => {
                require(
                    grant.max_tools > 0,
                    self.capability(),
                    "max_tools must be positive",
                )?;
                require(
                    grant.max_tools <= MAX_TOOLS,
                    self.capability(),
                    "max_tools is above the host ceiling",
                )?;
                require(
                    grant.max_schema_bytes > 0,
                    self.capability(),
                    "max_schema_bytes must be positive",
                )
            }
            Self::Events(grant) => {
                require(
                    !grant.emit_kinds.is_empty(),
                    self.capability(),
                    "emit_kinds must not be empty",
                )?;
                require(
                    grant.max_payload_bytes > 0,
                    self.capability(),
                    "max_payload_bytes must be positive",
                )
            }
        }
    }
}

fn require(
    condition: bool,
    capability: Capability,
    reason: &'static str,
) -> Result<(), GrantError> {
    if condition {
        Ok(())
    } else {
        Err(GrantError {
            capability,
            reason: reason.to_owned(),
        })
    }
}

/// A capability grant violated one of the scope rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantError {
    capability: Capability,
    reason: String,
}

impl GrantError {
    /// The capability whose grant was rejected.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// Why the grant was rejected.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "capability `{}` grant is invalid: {}",
            self.capability, self.reason
        )
    }
}

impl core::error::Error for GrantError {}

/// The complete, deduplicated grant set handed to one plugin instance.
///
/// An empty set is the default and denies every host import.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    grants: BTreeMap<Capability, CapabilityGrant>,
}

impl CapabilitySet {
    /// The empty, fully denied grant set.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a grant set, rejecting duplicates and invalid scopes.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilitySetError`] when a capability appears twice or a
    /// grant fails [`CapabilityGrant::validate`].
    pub fn new<I>(grants: I) -> Result<Self, CapabilitySetError>
    where
        I: IntoIterator<Item = CapabilityGrant>,
    {
        let mut map = BTreeMap::new();
        for grant in grants {
            grant.validate().map_err(CapabilitySetError::Grant)?;
            let capability = grant.capability();
            if map.insert(capability, grant).is_some() {
                return Err(CapabilitySetError::Duplicate(capability));
            }
        }
        Ok(Self { grants: map })
    }

    /// Whether `capability` was granted at all.
    #[must_use]
    pub fn contains(&self, capability: Capability) -> bool {
        self.grants.contains_key(&capability)
    }

    /// The granted capabilities, in a stable order.
    pub fn capabilities(&self) -> impl Iterator<Item = Capability> + '_ {
        self.grants.keys().copied()
    }

    /// The grants, in a stable order.
    pub fn grants(&self) -> impl Iterator<Item = &CapabilityGrant> + '_ {
        self.grants.values()
    }

    /// Number of granted capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether nothing at all is granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// The `log` grant, if any.
    #[must_use]
    pub fn log(&self) -> Option<&LogGrant> {
        match self.grants.get(&Capability::Log) {
            Some(CapabilityGrant::Log(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `config` grant, if any.
    #[must_use]
    pub fn config(&self) -> Option<&ConfigGrant> {
        match self.grants.get(&Capability::Config) {
            Some(CapabilityGrant::Config(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `store` grant, if any.
    #[must_use]
    pub fn store(&self) -> Option<&StoreGrant> {
        match self.grants.get(&Capability::Store) {
            Some(CapabilityGrant::Store(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `filesystem-read` grant, if any.
    #[must_use]
    pub fn filesystem_read(&self) -> Option<&FilesystemGrant> {
        match self.grants.get(&Capability::FilesystemRead) {
            Some(CapabilityGrant::FilesystemRead(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `filesystem-write` grant, if any.
    #[must_use]
    pub fn filesystem_write(&self) -> Option<&FilesystemGrant> {
        match self.grants.get(&Capability::FilesystemWrite) {
            Some(CapabilityGrant::FilesystemWrite(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `http` grant, if any.
    #[must_use]
    pub fn http(&self) -> Option<&HttpGrant> {
        match self.grants.get(&Capability::Http) {
            Some(CapabilityGrant::Http(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `clock` grant, if any.
    #[must_use]
    pub fn clock(&self) -> Option<&ClockGrant> {
        match self.grants.get(&Capability::Clock) {
            Some(CapabilityGrant::Clock(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `random` grant, if any.
    #[must_use]
    pub fn random(&self) -> Option<&RandomGrant> {
        match self.grants.get(&Capability::Random) {
            Some(CapabilityGrant::Random(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `tools` grant, if any.
    #[must_use]
    pub fn tools(&self) -> Option<&ToolsGrant> {
        match self.grants.get(&Capability::Tools) {
            Some(CapabilityGrant::Tools(grant)) => Some(grant),
            _ => None,
        }
    }

    /// The `events` grant, if any.
    #[must_use]
    pub fn events(&self) -> Option<&EventsGrant> {
        match self.grants.get(&Capability::Events) {
            Some(CapabilityGrant::Events(grant)) => Some(grant),
            _ => None,
        }
    }
}

/// A grant set could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilitySetError {
    /// The same capability was granted twice.
    Duplicate(Capability),
    /// A grant scope was invalid.
    Grant(GrantError),
}

impl fmt::Display for CapabilitySetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(capability) => {
                write!(f, "capability `{capability}` is granted more than once")
            }
            Self::Grant(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for CapabilitySetError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Duplicate(_) => None,
            Self::Grant(error) => Some(error),
        }
    }
}

/// Why a concrete host call was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DenialReason {
    /// The capability was never granted.
    NotGranted,
    /// The capability was granted but this call fell outside its scope.
    OutOfScope(String),
    /// The call was in scope but exceeded a quota.
    QuotaExceeded(String),
    /// The argument was malformed before scope could even be evaluated.
    InvalidArgument(String),
}

/// A refused host call, recorded in the host audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityDenial {
    capability: Capability,
    operation: &'static str,
    reason: DenialReason,
}

impl CapabilityDenial {
    /// Records a denial for an ungranted capability.
    #[must_use]
    pub const fn not_granted(capability: Capability, operation: &'static str) -> Self {
        Self {
            capability,
            operation,
            reason: DenialReason::NotGranted,
        }
    }

    /// Records a denial for an in-grant call that left the granted scope.
    #[must_use]
    pub fn out_of_scope(
        capability: Capability,
        operation: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            capability,
            operation,
            reason: DenialReason::OutOfScope(detail.into()),
        }
    }

    /// Records a denial for an exceeded quota.
    #[must_use]
    pub fn quota_exceeded(
        capability: Capability,
        operation: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            capability,
            operation,
            reason: DenialReason::QuotaExceeded(detail.into()),
        }
    }

    /// Records a denial for a malformed argument.
    #[must_use]
    pub fn invalid_argument(
        capability: Capability,
        operation: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            capability,
            operation,
            reason: DenialReason::InvalidArgument(detail.into()),
        }
    }

    /// The capability the refused call belongs to.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// The host operation that refused the call.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Why the call was refused.
    #[must_use]
    pub const fn reason(&self) -> &DenialReason {
        &self.reason
    }
}

impl fmt::Display for CapabilityDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.reason {
            DenialReason::NotGranted => write!(
                f,
                "`{}` requires capability `{}`, which is not granted",
                self.operation, self.capability
            ),
            DenialReason::OutOfScope(detail) => write!(
                f,
                "`{}` is outside the granted `{}` scope: {detail}",
                self.operation, self.capability
            ),
            DenialReason::QuotaExceeded(detail) => write!(
                f,
                "`{}` exceeded the `{}` quota: {detail}",
                self.operation, self.capability
            ),
            DenialReason::InvalidArgument(detail) => write!(
                f,
                "`{}` received an invalid argument for `{}`: {detail}",
                self.operation, self.capability
            ),
        }
    }
}

impl core::error::Error for CapabilityDenial {}

/// Rejects a plugin-supplied key that the host would otherwise use as a
/// namespace component.
///
/// # Errors
///
/// Returns a human-readable reason when the key is unusable.
pub fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("key must not be empty".to_owned());
    }
    if key.len() > MAX_KEY_LEN {
        return Err(format!("key is longer than {MAX_KEY_LEN} bytes"));
    }
    if !key.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_'
    }) {
        return Err(
            "key may only contain lowercase ASCII letters, digits, `.`, `-` and `_`".to_owned(),
        );
    }
    Ok(())
}

/// Rejects a plugin-supplied path before it ever reaches the host filesystem.
///
/// The check is purely lexical and deliberately strict: only forward-slash
/// separated relative paths built from plain names are accepted. The host still
/// canonicalises the joined path and re-checks root containment afterwards,
/// so this function is the first of two independent gates.
///
/// # Errors
///
/// Returns a human-readable reason when the path is unusable.
pub fn validate_relative_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("path must not be empty".to_owned());
    }
    if path.len() > 1024 {
        return Err("path is longer than 1024 bytes".to_owned());
    }
    if path.contains('\0') {
        return Err("path must not contain NUL".to_owned());
    }
    if path.chars().any(|c| c.is_control()) {
        return Err("path must not contain control characters".to_owned());
    }
    if path.contains('\\') {
        return Err("path must use `/` as its separator".to_owned());
    }
    if path.contains(':') {
        return Err("path must not contain `:`".to_owned());
    }
    if path.starts_with('/') {
        return Err("path must be relative".to_owned());
    }
    let mut resolved = PathBuf::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err("path must not contain an empty segment".to_owned());
        }
        if segment == "." || segment == ".." {
            return Err("path must not contain `.` or `..` segments".to_owned());
        }
        if segment.ends_with(' ') || segment.ends_with('.') {
            return Err("path segments must not end with a space or a dot".to_owned());
        }
        resolved.push(segment);
    }
    // Belt and braces: the parsed form must still be a plain relative path.
    if resolved.is_absolute()
        || resolved
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("path must be a plain relative path".to_owned());
    }
    Ok(resolved)
}

/// Whether `host` matches an allowlist `pattern`.
///
/// A pattern is either a literal host name or a single-label wildcard such as
/// `*.example.com`, which matches exactly one additional label.
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let Some(label) = host.strip_suffix(suffix) else {
            return false;
        };
        let Some(label) = label.strip_suffix('.') else {
            return false;
        };
        return !label.is_empty() && !label.contains('.');
    }
    pattern == host
}

/// Rejects an unusable HTTP allowlist entry.
///
/// # Errors
///
/// Returns a human-readable reason when the pattern is unusable.
pub fn validate_host_pattern(pattern: &str) -> Result<(), String> {
    let body = pattern.strip_prefix("*.").unwrap_or(pattern);
    if body.is_empty() {
        return Err("host pattern must not be empty".to_owned());
    }
    if body.len() > 253 {
        return Err("host pattern is longer than 253 bytes".to_owned());
    }
    if pattern.starts_with("*.") && !body.contains('.') {
        return Err("wildcard host patterns need at least two labels".to_owned());
    }
    if body != body.to_ascii_lowercase() {
        return Err("host pattern must be lowercase".to_owned());
    }
    if body.contains('/') || body.contains('@') || body.contains(':') {
        return Err("host pattern must not contain a scheme, userinfo or port".to_owned());
    }
    if body.contains('*') {
        return Err("only a single leading `*.` wildcard is supported".to_owned());
    }
    for label in body.split('.') {
        if label.is_empty() {
            return Err("host pattern must not contain an empty label".to_owned());
        }
        if label.len() > 63 {
            return Err("host pattern labels must be at most 63 bytes".to_owned());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("host pattern labels must not start or end with `-`".to_owned());
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("host pattern labels must be ASCII letters, digits or `-`".to_owned());
        }
    }
    Ok(())
}

/// Joins a validated relative path onto `root` without leaving it lexically.
///
/// This does not touch the filesystem; the host must still canonicalise the
/// result and confirm containment before opening anything.
#[must_use]
pub fn join_under_root(root: &Path, relative: &Path) -> PathBuf {
    let mut joined = root.to_path_buf();
    for component in relative.components() {
        if let Component::Normal(segment) = component {
            joined.push(segment);
        }
    }
    joined
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use super::{
        Capability, CapabilityGrant, CapabilitySet, CapabilitySetError, ClockGrant, ConfigGrant,
        ConfigScope, EventKind, EventsGrant, FilesystemGrant, HttpGrant, HttpMethod, LogGrant,
        LogLevel, RandomGrant, StoreGrant, ToolsGrant, host_matches, join_under_root,
        validate_host_pattern, validate_key, validate_relative_path,
    };

    fn log_grant() -> CapabilityGrant {
        CapabilityGrant::Log(LogGrant {
            min_level: LogLevel::Info,
            max_message_bytes: 4096,
        })
    }

    fn fs_grant(root: &str) -> FilesystemGrant {
        FilesystemGrant {
            roots: vec![PathBuf::from(root)],
            max_file_bytes: 1024,
        }
    }

    /// An absolute path for the platform the tests are running on.
    fn absolute(relative: &str) -> String {
        if cfg!(windows) {
            format!("C:\\{}", relative.replace('/', "\\"))
        } else {
            format!("/{relative}")
        }
    }

    #[test]
    fn capability_wire_names_are_stable_and_unique() {
        let names: Vec<&str> = Capability::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "log",
                "config",
                "store",
                "filesystem-read",
                "filesystem-write",
                "http",
                "clock",
                "random",
                "tools",
                "events",
            ]
        );
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(unique.len(), names.len());
    }

    #[test]
    fn capability_json_encoding_is_kebab_case() {
        let encoded = serde_json::to_string(&Capability::FilesystemWrite).expect("serialize");
        assert_eq!(encoded, "\"filesystem-write\"");
        let decoded: Capability = serde_json::from_str("\"filesystem-read\"").expect("deserialize");
        assert_eq!(decoded, Capability::FilesystemRead);
    }

    #[test]
    fn empty_capability_set_denies_everything() {
        let set = CapabilitySet::empty();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        for capability in Capability::ALL {
            assert!(
                !set.contains(capability),
                "{capability} must not be granted"
            );
        }
        assert!(set.log().is_none());
        assert!(set.filesystem_read().is_none());
        assert!(set.http().is_none());
    }

    #[test]
    fn duplicate_capabilities_are_rejected() {
        let error = CapabilitySet::new([log_grant(), log_grant()]).unwrap_err();
        assert_eq!(error, CapabilitySetError::Duplicate(Capability::Log));
    }

    #[test]
    fn distinct_read_and_write_filesystem_grants_coexist() {
        let read_root = absolute("srv/in");
        let write_root = absolute("srv/out");
        let set = CapabilitySet::new([
            CapabilityGrant::FilesystemRead(fs_grant(&read_root)),
            CapabilityGrant::FilesystemWrite(fs_grant(&write_root)),
        ])
        .expect("valid set");
        assert_eq!(
            set.filesystem_read().expect("read grant").roots,
            vec![PathBuf::from(&read_root)]
        );
        assert_eq!(
            set.filesystem_write().expect("write grant").roots,
            vec![PathBuf::from(&write_root)]
        );
        assert_eq!(
            set.capabilities().collect::<Vec<_>>(),
            vec![Capability::FilesystemRead, Capability::FilesystemWrite]
        );
    }

    #[test]
    fn filesystem_grant_requires_absolute_roots_without_parent_segments() {
        let relative = CapabilityGrant::FilesystemRead(FilesystemGrant {
            roots: vec![PathBuf::from("relative/dir")],
            max_file_bytes: 16,
        });
        let error = relative.validate().unwrap_err();
        assert_eq!(error.capability(), Capability::FilesystemRead);
        assert_eq!(error.reason(), "every root must be absolute");

        let empty = CapabilityGrant::FilesystemWrite(FilesystemGrant {
            roots: Vec::new(),
            max_file_bytes: 16,
        });
        assert_eq!(
            empty.validate().unwrap_err().reason(),
            "roots must not be empty"
        );
    }

    #[test]
    fn store_grant_rejects_value_larger_than_total() {
        let grant = CapabilityGrant::Store(StoreGrant {
            max_total_bytes: 16,
            max_value_bytes: 32,
            max_keys: 4,
        });
        assert_eq!(
            grant.validate().unwrap_err().reason(),
            "max_value_bytes must not exceed max_total_bytes"
        );
    }

    #[test]
    fn clock_and_random_grants_have_ceilings() {
        let clock = CapabilityGrant::Clock(ClockGrant {
            resolution_ms: 3_600_001,
        });
        assert_eq!(
            clock.validate().unwrap_err().reason(),
            "resolution_ms is above the host ceiling"
        );
        let random = CapabilityGrant::Random(RandomGrant {
            max_bytes_per_call: (1 << 20) + 1,
        });
        assert_eq!(
            random.validate().unwrap_err().reason(),
            "max_bytes_per_call is above the host ceiling"
        );
    }

    #[test]
    fn empty_scopes_are_rejected() {
        let config = CapabilityGrant::Config(ConfigGrant {
            scope: ConfigScope::Keys(BTreeSet::new()),
        });
        assert_eq!(
            config.validate().unwrap_err().reason(),
            "keys must not be empty"
        );

        let events = CapabilityGrant::Events(EventsGrant {
            emit_kinds: BTreeSet::new(),
            max_payload_bytes: 32,
        });
        assert_eq!(
            events.validate().unwrap_err().reason(),
            "emit_kinds must not be empty"
        );

        let http = CapabilityGrant::Http(HttpGrant {
            hosts: Vec::new(),
            methods: vec![HttpMethod::Get],
            allow_plaintext: false,
            max_response_bytes: 1024,
        });
        assert_eq!(
            http.validate().unwrap_err().reason(),
            "hosts must not be empty"
        );
    }

    #[test]
    fn grant_json_is_internally_tagged() {
        let grant = CapabilityGrant::Clock(ClockGrant { resolution_ms: 250 });
        let encoded = serde_json::to_value(&grant).expect("serialize");
        assert_eq!(
            encoded,
            serde_json::json!({ "capability": "clock", "resolution_ms": 250 })
        );
        let decoded: CapabilityGrant = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(decoded, grant);
    }

    #[test]
    fn tools_grant_json_rejects_unknown_fields() {
        let error = serde_json::from_value::<CapabilityGrant>(serde_json::json!({
            "capability": "tools",
            "max_tools": 4,
            "max_schema_bytes": 512,
            "max_widgets": 3
        }))
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown field `max_widgets`, expected `max_tools` or `max_schema_bytes`"
        );
    }

    #[test]
    fn tools_grant_accepts_its_documented_shape() {
        let grant: CapabilityGrant = serde_json::from_value(serde_json::json!({
            "capability": "tools",
            "max_tools": 4,
            "max_schema_bytes": 512
        }))
        .expect("deserialize");
        assert_eq!(
            grant,
            CapabilityGrant::Tools(ToolsGrant {
                max_tools: 4,
                max_schema_bytes: 512,
            })
        );
    }

    #[test]
    fn event_kind_wire_names_are_kebab_case() {
        let encoded = serde_json::to_string(&EventKind::ALL.to_vec()).expect("serialize");
        assert_eq!(
            encoded,
            "[\"session-started\",\"session-ended\",\"message\",\"tool-result\",\"config-changed\",\"heartbeat\",\"shutdown\"]"
        );
    }

    #[test]
    fn keys_must_be_lowercase_and_bounded() {
        assert_eq!(validate_key("model.default"), Ok(()));
        assert_eq!(validate_key(""), Err("key must not be empty".to_owned()));
        assert_eq!(
            validate_key("Model"),
            Err(
                "key may only contain lowercase ASCII letters, digits, `.`, `-` and `_`".to_owned()
            )
        );
        assert_eq!(
            validate_key(&"a".repeat(129)),
            Err("key is longer than 128 bytes".to_owned())
        );
    }

    #[test]
    fn relative_path_validation_rejects_escapes() {
        assert_eq!(
            validate_relative_path("data/report.json"),
            Ok(PathBuf::from("data").join("report.json"))
        );
        for (input, expected) in [
            ("", "path must not be empty"),
            ("/etc/passwd", "path must be relative"),
            ("..", "path must not contain `.` or `..` segments"),
            ("a/../../b", "path must not contain `.` or `..` segments"),
            ("./a", "path must not contain `.` or `..` segments"),
            ("a//b", "path must not contain an empty segment"),
            ("a\\b", "path must use `/` as its separator"),
            ("C:/Windows", "path must not contain `:`"),
            ("a/b:stream", "path must not contain `:`"),
            ("a/b ", "path segments must not end with a space or a dot"),
            ("a/b.", "path segments must not end with a space or a dot"),
            ("a/\0b", "path must not contain NUL"),
            ("a/\nb", "path must not contain control characters"),
            ("a/\tb", "path must not contain control characters"),
        ] {
            assert_eq!(
                validate_relative_path(input),
                Err(expected.to_owned()),
                "input `{input}`"
            );
        }
    }

    #[test]
    fn join_under_root_keeps_the_root_prefix() {
        let relative = validate_relative_path("nested/file.txt").expect("valid");
        let joined = join_under_root(Path::new("/srv/data"), &relative);
        assert_eq!(
            joined,
            Path::new("/srv/data").join("nested").join("file.txt")
        );
    }

    #[test]
    fn host_patterns_match_exactly_one_wildcard_label() {
        assert!(host_matches("api.example.com", "api.example.com"));
        assert!(host_matches("api.example.com", "API.EXAMPLE.COM"));
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
        assert!(!host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("api.example.com", "evil-api.example.com"));
        assert!(!host_matches(
            "api.example.com",
            "api.example.com.evil.test"
        ));
    }

    #[test]
    fn host_pattern_validation_rejects_urls_and_ports() {
        assert_eq!(validate_host_pattern("api.example.com"), Ok(()));
        assert_eq!(validate_host_pattern("*.example.com"), Ok(()));
        assert_eq!(
            validate_host_pattern("https://api.example.com"),
            Err("host pattern must not contain a scheme, userinfo or port".to_owned())
        );
        assert_eq!(
            validate_host_pattern("api.example.com:8443"),
            Err("host pattern must not contain a scheme, userinfo or port".to_owned())
        );
        assert_eq!(
            validate_host_pattern("API.example.com"),
            Err("host pattern must be lowercase".to_owned())
        );
        assert_eq!(
            validate_host_pattern("*.com"),
            Err("wildcard host patterns need at least two labels".to_owned())
        );
        assert_eq!(
            validate_host_pattern("a.*.example.com"),
            Err("only a single leading `*.` wildcard is supported".to_owned())
        );
    }
}

//! The host-side services a granted capability is allowed to reach.
//!
//! The plugin host owns *enforcement*; the embedder owns *effects*. Every
//! trait here is only ever consulted after the capability check for the call
//! has already passed, so an implementation never has to repeat the sandbox
//! rules. All defaults deny.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use claw_plugin_api::capability::{EventKind, LogLevel};

/// One structured log record emitted by a plugin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    /// The plugin that emitted the record.
    pub plugin_id: String,
    /// Severity, already checked against the grant's floor.
    pub level: LogLevel,
    /// Message, already truncated to the grant's byte ceiling.
    pub message: String,
}

/// A typed event crossing the host boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEvent {
    /// Discriminant of `payload`.
    pub kind: EventKind,
    /// Host-assigned monotonic sequence number.
    pub sequence: u64,
    /// Opaque origin identifier.
    pub source: String,
    /// JSON-encoded payload.
    pub payload: String,
}

/// A tool a plugin has registered with the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolRegistration {
    /// The plugin that registered the tool.
    pub plugin_id: String,
    /// Tool name, unique within the plugin.
    pub name: String,
    /// One-line description.
    pub summary: String,
    /// JSON Schema for the tool input.
    pub input_schema: String,
}

/// An outbound HTTP request that already passed every host-side check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundRequest {
    /// Uppercase method, already checked against the grant's allowlist.
    pub method: String,
    /// Canonical URL produced by `claw-security`'s SSRF validator.
    pub url: String,
    /// Headers, already filtered.
    pub headers: Vec<(String, String)>,
    /// Optional body.
    pub body: Option<Vec<u8>>,
}

/// The response an [`HttpTransport`] produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

/// Sink for plugin log records.
pub trait LogSink: Send + Sync {
    /// Records one log line.
    fn record(&self, record: LogRecord);
}

/// Read-only plugin configuration.
pub trait ConfigProvider: Send + Sync {
    /// Reads one key from the plugin's own namespace.
    fn get(&self, plugin_id: &str, key: &str) -> Option<String>;

    /// Lists the keys in the plugin's own namespace, sorted.
    fn keys(&self, plugin_id: &str) -> Vec<String>;
}

/// Plugin-scoped key/value persistence.
pub trait StoreBackend: Send + Sync {
    /// Reads a value.
    fn get(&self, plugin_id: &str, key: &str) -> Option<Vec<u8>>;

    /// Writes a value.
    fn set(&self, plugin_id: &str, key: &str, value: Vec<u8>);

    /// Deletes a value, reporting whether one was present.
    fn delete(&self, plugin_id: &str, key: &str) -> bool;

    /// Total bytes currently stored for this plugin.
    fn total_bytes(&self, plugin_id: &str) -> u64;

    /// Number of keys currently stored for this plugin.
    fn key_count(&self, plugin_id: &str) -> u32;
}

/// Outbound HTTP transport.
pub trait HttpTransport: Send + Sync {
    /// Performs one already-validated request.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message when the transport itself failed. The
    /// message is surfaced to the guest as an `internal` error.
    fn send(&self, plugin_id: &str, request: OutboundRequest) -> Result<InboundResponse, String>;
}

/// Coarse wall clock.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch, before host quantisation.
    fn now_ms(&self) -> u64;
}

/// Randomness source.
pub trait RandomSource: Send + Sync {
    /// Fills `buffer` with random bytes.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message when entropy is unavailable.
    fn fill(&self, buffer: &mut [u8]) -> Result<(), String>;
}

/// Sink for tool registrations.
pub trait ToolSink: Send + Sync {
    /// Registers or replaces a tool.
    fn register(&self, registration: ToolRegistration);

    /// Removes a tool, reporting whether one was registered.
    fn unregister(&self, plugin_id: &str, name: &str) -> bool;
}

/// Sink for events a plugin publishes.
pub trait EventSink: Send + Sync {
    /// Publishes one event.
    fn publish(&self, plugin_id: &str, event: HostEvent);
}

/// Drops every log record.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardLogs;

impl LogSink for DiscardLogs {
    fn record(&self, _record: LogRecord) {}
}

/// A configuration provider with no keys at all.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyConfig;

impl ConfigProvider for EmptyConfig {
    fn get(&self, _plugin_id: &str, _key: &str) -> Option<String> {
        None
    }

    fn keys(&self, _plugin_id: &str) -> Vec<String> {
        Vec::new()
    }
}

/// A transport that performs no I/O and fails every request.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllHttp;

impl HttpTransport for DenyAllHttp {
    fn send(&self, _plugin_id: &str, _request: OutboundRequest) -> Result<InboundResponse, String> {
        Err("this host has no HTTP transport installed".to_owned())
    }
}

/// The operating-system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// The operating-system entropy source.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), String> {
        getrandom::fill(buffer).map_err(|error| error.to_string())
    }
}

/// Drops every event.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardEvents;

impl EventSink for DiscardEvents {
    fn publish(&self, _plugin_id: &str, _event: HostEvent) {}
}

/// A thread-safe, process-local configuration provider.
#[derive(Clone, Debug, Default)]
pub struct InMemoryConfig {
    values: Arc<Mutex<BTreeMap<(String, String), String>>>,
}

impl InMemoryConfig {
    /// An empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets one key for one plugin.
    pub fn set(
        &self,
        plugin_id: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        let mut guard = self
            .values
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        guard.insert((plugin_id.into(), key.into()), value.into());
    }
}

impl ConfigProvider for InMemoryConfig {
    fn get(&self, plugin_id: &str, key: &str) -> Option<String> {
        let guard = self
            .values
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        guard.get(&(plugin_id.to_owned(), key.to_owned())).cloned()
    }

    fn keys(&self, plugin_id: &str) -> Vec<String> {
        let guard = self
            .values
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        guard
            .keys()
            .filter(|(owner, _)| owner == plugin_id)
            .map(|(_, key)| key.clone())
            .collect()
    }
}

/// Keys are (plugin id, key) so two plugins can never read each other's rows.
type StoreMap = BTreeMap<(String, String), Vec<u8>>;

/// A thread-safe, process-local key/value store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryStore {
    values: Arc<Mutex<StoreMap>>,
}

impl InMemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut StoreMap) -> R) -> R {
        let mut guard = self
            .values
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        f(&mut guard)
    }
}

impl StoreBackend for InMemoryStore {
    fn get(&self, plugin_id: &str, key: &str) -> Option<Vec<u8>> {
        self.with(|values| values.get(&(plugin_id.to_owned(), key.to_owned())).cloned())
    }

    fn set(&self, plugin_id: &str, key: &str, value: Vec<u8>) {
        self.with(|values| values.insert((plugin_id.to_owned(), key.to_owned()), value));
    }

    fn delete(&self, plugin_id: &str, key: &str) -> bool {
        self.with(|values| {
            values
                .remove(&(plugin_id.to_owned(), key.to_owned()))
                .is_some()
        })
    }

    fn total_bytes(&self, plugin_id: &str) -> u64 {
        self.with(|values| {
            values
                .iter()
                .filter(|((owner, _), _)| owner == plugin_id)
                .map(|(_, value)| value.len() as u64)
                .sum()
        })
    }

    fn key_count(&self, plugin_id: &str) -> u32 {
        self.with(|values| {
            u32::try_from(
                values
                    .keys()
                    .filter(|(owner, _)| owner == plugin_id)
                    .count(),
            )
            .unwrap_or(u32::MAX)
        })
    }
}

/// A store backend that has nothing and keeps nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullStore;

impl StoreBackend for NullStore {
    fn get(&self, _plugin_id: &str, _key: &str) -> Option<Vec<u8>> {
        None
    }

    fn set(&self, _plugin_id: &str, _key: &str, _value: Vec<u8>) {}

    fn delete(&self, _plugin_id: &str, _key: &str) -> bool {
        false
    }

    fn total_bytes(&self, _plugin_id: &str) -> u64 {
        0
    }

    fn key_count(&self, _plugin_id: &str) -> u32 {
        0
    }
}

/// Collects log records, tool registrations and events for inspection.
#[derive(Clone, Debug, Default)]
pub struct RecordingSink {
    logs: Arc<Mutex<Vec<LogRecord>>>,
    tools: Arc<Mutex<Vec<ToolRegistration>>>,
    events: Arc<Mutex<Vec<(String, HostEvent)>>>,
}

impl RecordingSink {
    /// An empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every log record captured so far.
    #[must_use]
    pub fn logs(&self) -> Vec<LogRecord> {
        self.logs.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Every tool registration captured so far.
    #[must_use]
    pub fn tools(&self) -> Vec<ToolRegistration> {
        self.tools.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Every published event captured so far, with its plugin id.
    #[must_use]
    pub fn events(&self) -> Vec<(String, HostEvent)> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl LogSink for RecordingSink {
    fn record(&self, record: LogRecord) {
        self.logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record);
    }
}

impl ToolSink for RecordingSink {
    fn register(&self, registration: ToolRegistration) {
        let mut guard = self.tools.lock().unwrap_or_else(|e| e.into_inner());
        guard.retain(|existing| {
            existing.plugin_id != registration.plugin_id || existing.name != registration.name
        });
        guard.push(registration);
    }

    fn unregister(&self, plugin_id: &str, name: &str) -> bool {
        let mut guard = self.tools.lock().unwrap_or_else(|e| e.into_inner());
        let before = guard.len();
        guard.retain(|existing| existing.plugin_id != plugin_id || existing.name != name);
        guard.len() != before
    }
}

impl EventSink for RecordingSink {
    fn publish(&self, plugin_id: &str, event: HostEvent) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((plugin_id.to_owned(), event));
    }
}

/// A tool sink that keeps nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardTools;

impl ToolSink for DiscardTools {
    fn register(&self, _registration: ToolRegistration) {}

    fn unregister(&self, _plugin_id: &str, _name: &str) -> bool {
        false
    }
}

/// The complete set of services a host instance offers to granted capabilities.
///
/// [`HostServices::deny_all`] wires every slot to an implementation that has
/// nothing to give, so a misconfigured embedder cannot accidentally hand a
/// plugin more reach than it asked for.
#[derive(Clone)]
pub struct HostServices {
    pub(crate) logs: Arc<dyn LogSink>,
    pub(crate) config: Arc<dyn ConfigProvider>,
    pub(crate) store: Arc<dyn StoreBackend>,
    pub(crate) http: Arc<dyn HttpTransport>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) random: Arc<dyn RandomSource>,
    pub(crate) tools: Arc<dyn ToolSink>,
    pub(crate) events: Arc<dyn EventSink>,
}

impl core::fmt::Debug for HostServices {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HostServices").finish_non_exhaustive()
    }
}

impl Default for HostServices {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl HostServices {
    /// Services that hold nothing and perform no I/O.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            logs: Arc::new(DiscardLogs),
            config: Arc::new(EmptyConfig),
            store: Arc::new(NullStore),
            http: Arc::new(DenyAllHttp),
            clock: Arc::new(SystemClock),
            random: Arc::new(OsRandom),
            tools: Arc::new(DiscardTools),
            events: Arc::new(DiscardEvents),
        }
    }

    /// Installs a log sink.
    #[must_use]
    pub fn with_logs(mut self, sink: Arc<dyn LogSink>) -> Self {
        self.logs = sink;
        self
    }

    /// Installs a configuration provider.
    #[must_use]
    pub fn with_config(mut self, provider: Arc<dyn ConfigProvider>) -> Self {
        self.config = provider;
        self
    }

    /// Installs a key/value store.
    #[must_use]
    pub fn with_store(mut self, backend: Arc<dyn StoreBackend>) -> Self {
        self.store = backend;
        self
    }

    /// Installs an HTTP transport.
    #[must_use]
    pub fn with_http(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.http = transport;
        self
    }

    /// Installs a clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Installs a randomness source.
    #[must_use]
    pub fn with_random(mut self, random: Arc<dyn RandomSource>) -> Self {
        self.random = random;
        self
    }

    /// Installs a tool sink.
    #[must_use]
    pub fn with_tools(mut self, tools: Arc<dyn ToolSink>) -> Self {
        self.tools = tools;
        self
    }

    /// Installs an event sink.
    #[must_use]
    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }
}

/// A clock that always answers the same millisecond, for deterministic tests.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

/// A randomness source that refuses to produce bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableRandom;

impl RandomSource for UnavailableRandom {
    fn fill(&self, _buffer: &mut [u8]) -> Result<(), String> {
        Err("no entropy source is installed".to_owned())
    }
}

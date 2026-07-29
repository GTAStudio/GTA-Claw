//! The host-side services a granted capability is allowed to reach.
//!
//! The plugin host owns *enforcement*; the embedder owns *effects*. Every
//! trait here is only ever consulted after the capability check for the call
//! has already passed, so an implementation never has to repeat the sandbox
//! rules. All defaults deny.

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use claw_plugin_api::cancellation::CancellationToken;
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

/// A tool registration the embedding surface refused to publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolRegistrationError {
    reason: String,
}

impl ToolRegistrationError {
    /// Creates an explicit publication rejection.
    #[must_use]
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Stable operator-facing rejection reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl core::fmt::Display for ToolRegistrationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl core::error::Error for ToolRegistrationError {}

/// An outbound HTTP request that already passed every host-side check.
///
/// The transport must connect to one of [`OutboundRequest::addresses`]. Those
/// addresses were resolved by the host and revalidated immediately before this
/// value was constructed, so re-resolving [`OutboundRequest::host`] inside the
/// transport would reopen the DNS-rebinding window the host just closed.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    /// Uppercase method, already checked against the grant's allowlist.
    pub method: String,
    /// Canonical URL produced by `claw-security`'s SSRF validator.
    pub url: String,
    /// Canonical target host. Use it for the `Host` header and for TLS SNI,
    /// never for a fresh name lookup.
    pub host: String,
    /// Explicit or scheme-default port.
    pub port: u16,
    /// The addresses the host resolved and validated for this attempt. Connect
    /// to one of these and to nothing else.
    pub addresses: Vec<IpAddr>,
    /// Headers, already filtered.
    pub headers: Vec<(String, String)>,
    /// Optional body.
    pub body: Option<Vec<u8>>,
}

impl core::fmt::Debug for OutboundRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OutboundRequest")
            .field("method", &self.method)
            .field("url", &redact_url_query(&self.url))
            .field("host", &self.host)
            .field("port", &self.port)
            .field("addresses", &self.addresses)
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("body_bytes", &self.body.as_ref().map_or(0, Vec::len))
            .finish()
    }
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

/// Deadline and cancellation state for one host-side operation.
///
/// The value is cloned out of a plugin's store before a blocking adapter runs,
/// so the adapter can observe the same absolute deadline and cancellation flag
/// that Wasmtime's epoch callback enforces for guest code.
#[derive(Clone, Debug)]
pub struct HostCallControl {
    deadline: Instant,
    cancellation: Option<CancellationToken>,
}

impl HostCallControl {
    /// Creates a control with an absolute deadline and optional cancellation.
    #[must_use]
    pub const fn new(deadline: Instant, cancellation: Option<CancellationToken>) -> Self {
        Self {
            deadline,
            cancellation,
        }
    }

    /// Absolute deadline for the complete host call.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Cancellation signal, when the caller supplied one.
    #[must_use]
    pub const fn cancellation(&self) -> Option<&CancellationToken> {
        self.cancellation.as_ref()
    }

    /// Time remaining before the absolute deadline.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Checks whether the operation must stop.
    ///
    /// An expired deadline wins when cancellation is also pending, matching the
    /// store's deterministic interruption classification.
    ///
    /// # Errors
    ///
    /// Returns [`HostCallStop::DeadlineExceeded`] once the deadline is reached,
    /// or [`HostCallStop::Cancelled`] when cancellation was requested first.
    pub fn check(&self) -> Result<(), HostCallStop> {
        if Instant::now() >= self.deadline {
            Err(HostCallStop::DeadlineExceeded)
        } else if self
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            Err(HostCallStop::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Why a controlled host-side operation stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCallStop {
    /// The caller requested cancellation.
    Cancelled,
    /// The absolute host-call deadline was reached.
    DeadlineExceeded,
}

impl core::fmt::Display for HostCallStop {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("operation cancelled"),
            Self::DeadlineExceeded => formatter.write_str("operation deadline exceeded"),
        }
    }
}

impl core::error::Error for HostCallStop {}

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

/// Name resolution for outbound HTTP.
///
/// The host resolves names itself, immediately before it hands a request to a
/// transport, so that the addresses the SSRF validator inspected are the same
/// addresses the connection uses. Leaving resolution to the transport would
/// mean the validator's verdict and the connection's target are two separate
/// lookups, which is precisely the DNS-rebinding hole.
pub trait DnsResolver: Send + Sync {
    /// Resolves `host` to every address a connection might use.
    ///
    /// Implementations must return *all* candidate addresses; returning only
    /// the first would let a hostile authoritative server hide a loopback
    /// answer behind a public one.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message when the name cannot be resolved.
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String>;

    /// Resolves with the guest call's absolute control.
    ///
    /// Existing resolvers remain source-compatible through this default. A
    /// resolver with an interruptible backend should override it.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`DnsResolver::resolve`], or a stable
    /// cancellation/deadline message when the control stops the call.
    fn resolve_with_control(
        &self,
        host: &str,
        port: u16,
        control: &HostCallControl,
    ) -> Result<Vec<IpAddr>, String> {
        control
            .check()
            .map_err(|stop| format!("DNS resolution {stop}"))?;
        let addresses = self.resolve(host, port);
        control
            .check()
            .map_err(|stop| format!("DNS resolution {stop}"))?;
        addresses
    }
}

/// Outbound HTTP transport.
pub trait HttpTransport: Send + Sync {
    /// Performs one already-validated request.
    ///
    /// Implementations must connect to one of [`OutboundRequest::addresses`],
    /// must send [`OutboundRequest::host`] as the `Host` header and TLS SNI,
    /// and must **not** follow redirects: the host re-runs the full SSRF check
    /// on every hop itself and will issue the next hop as a fresh request.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message when the transport itself failed. The
    /// message is surfaced to the guest as an `internal` error.
    fn send(&self, plugin_id: &str, request: OutboundRequest) -> Result<InboundResponse, String>;

    /// Performs one request with the guest call's deadline and cancellation.
    ///
    /// Existing transports remain source-compatible through this default. A
    /// transport that can interrupt blocking I/O should override it.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`HttpTransport::send`], or a stable
    /// cancellation/deadline message when the control stops the call.
    fn send_with_control(
        &self,
        plugin_id: &str,
        request: OutboundRequest,
        control: &HostCallControl,
    ) -> Result<InboundResponse, String> {
        control
            .check()
            .map_err(|stop| format!("HTTP request {stop}"))?;
        let response = self.send(plugin_id, request);
        control
            .check()
            .map_err(|stop| format!("HTTP request {stop}"))?;
        response
    }
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
    /// Atomically registers or replaces a tool.
    ///
    /// A rejection must leave no public entry for this plugin-local name,
    /// including an older registration being replaced.
    ///
    /// # Errors
    ///
    /// Returns [`ToolRegistrationError`] when the embedding surface rejects the
    /// registration under its own publication policy.
    fn register(&self, registration: ToolRegistration) -> Result<(), ToolRegistrationError>;

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

/// A resolver that resolves nothing.
///
/// This is the default, so a host that installs a transport but forgets to
/// install a resolver cannot reach the network at all rather than silently
/// falling back to ambient name resolution.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllDns;

impl DnsResolver for DenyAllDns {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        Err("this host has no DNS resolver installed".to_owned())
    }
}

/// The operating-system resolver.
///
/// Opt in explicitly. Every address it returns is still checked against the
/// SSRF policy before a connection is attempted.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        let addresses: Vec<IpAddr> = (host, port)
            .to_socket_addrs()
            .map_err(|error| error.to_string())?
            .map(|address| address.ip())
            .collect();
        if addresses.is_empty() {
            return Err(format!("`{host}` resolved to no addresses"));
        }
        Ok(addresses)
    }
}

/// A resolver with a fixed answer table, for deterministic tests.
#[derive(Clone, Debug, Default)]
pub struct StaticDns {
    answers: BTreeMap<String, Vec<IpAddr>>,
}

impl StaticDns {
    /// A resolver that knows no names.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one answer, replacing any previous answer for the same host.
    #[must_use]
    pub fn with(mut self, host: impl Into<String>, addresses: Vec<IpAddr>) -> Self {
        self.answers.insert(host.into(), addresses);
        self
    }
}

impl DnsResolver for StaticDns {
    fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        self.answers
            .get(host)
            .cloned()
            .ok_or_else(|| format!("`{host}` is not in the static answer table"))
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
        getrandom::getrandom(buffer).map_err(|error| error.to_string())
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
        let mut guard = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        guard.insert((plugin_id.into(), key.into()), value.into());
    }
}

impl ConfigProvider for InMemoryConfig {
    fn get(&self, plugin_id: &str, key: &str) -> Option<String> {
        let guard = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        guard.get(&(plugin_id.to_owned(), key.to_owned())).cloned()
    }

    fn keys(&self, plugin_id: &str) -> Vec<String> {
        let guard = self.values.lock().unwrap_or_else(PoisonError::into_inner);
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
        let mut guard = self.values.lock().unwrap_or_else(PoisonError::into_inner);
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
        self.logs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every tool registration captured so far.
    #[must_use]
    pub fn tools(&self) -> Vec<ToolRegistration> {
        self.tools
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Every published event captured so far, with its plugin id.
    #[must_use]
    pub fn events(&self) -> Vec<(String, HostEvent)> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl LogSink for RecordingSink {
    fn record(&self, record: LogRecord) {
        self.logs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(record);
    }
}

impl ToolSink for RecordingSink {
    fn register(&self, registration: ToolRegistration) -> Result<(), ToolRegistrationError> {
        let mut guard = self.tools.lock().unwrap_or_else(PoisonError::into_inner);
        guard.retain(|existing| {
            existing.plugin_id != registration.plugin_id || existing.name != registration.name
        });
        guard.push(registration);
        drop(guard);
        Ok(())
    }

    fn unregister(&self, plugin_id: &str, name: &str) -> bool {
        let mut guard = self.tools.lock().unwrap_or_else(PoisonError::into_inner);
        let before = guard.len();
        guard.retain(|existing| existing.plugin_id != plugin_id || existing.name != name);
        guard.len() != before
    }
}

impl EventSink for RecordingSink {
    fn publish(&self, plugin_id: &str, event: HostEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((plugin_id.to_owned(), event));
    }
}

/// A tool sink that keeps nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardTools;

impl ToolSink for DiscardTools {
    fn register(&self, _registration: ToolRegistration) -> Result<(), ToolRegistrationError> {
        Ok(())
    }

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
    pub(crate) dns: Arc<dyn DnsResolver>,
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
            dns: Arc::new(DenyAllDns),
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

    /// Installs a DNS resolver.
    ///
    /// Without one, outbound HTTP fails at the resolution step even when the
    /// capability is granted and a transport is installed.
    #[must_use]
    pub fn with_dns(mut self, resolver: Arc<dyn DnsResolver>) -> Self {
        self.dns = resolver;
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

fn redact_url_query(url: &str) -> String {
    url.split_once('?')
        .map_or_else(|| url.to_owned(), |(base, _)| format!("{base}?[REDACTED]"))
}

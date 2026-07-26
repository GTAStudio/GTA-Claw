//! The port traits every subsystem crate implements.
//!
//! These are the integration contract. Each trait belongs to exactly one crate
//! in the workspace, named in its documentation, and the daemon composes the
//! product from trait objects alone. Nothing here mentions a concrete subsystem.
//!
//! Two shapes recur and both are deliberate.
//!
//! **Privileged calls take a [`Grant<T>`].** [`ProviderTransportPort::send`],
//! [`ToolSurfacePort::invoke`], [`SecretStorePort::lease`] and
//! [`PluginHostPort::activate`] cannot be called without one, and a grant is
//! minted by the composition at the moment of the call. An implementation
//! cannot cache a grant for later use because redeeming it consumes it.
//!
//! **Lookups return validated objects.** [`ProviderRegistryPort::resolve`]
//! returns a [`ProviderBinding`] carrying a [`ResolvedEndpoint`], not a URL
//! string; [`ToolSurfacePort::catalogue`] returns [`ToolBinding`] values, not
//! tool names. Callers act on the returned object, so the check that produced it
//! cannot be bypassed by re-resolving the name.

use std::net::SocketAddr;

use claw_domain::SessionId;
use secrecy::SecretString;

use super::BoxFuture;
use super::authority::Grant;
use super::egress::ResolvedEndpoint;
use super::error::SubsystemError;
use super::session::{
    AssembledContext, CredentialLease, CredentialName, GatewayRequest, GatewayResponse, ModelName,
    ObservedEvent, PluginActivation, PluginInstance, ProviderBinding, ProviderCall, ProviderName,
    ProviderReply, ResolvedSession, RuntimeSettings, SessionRecord, ToolBinding, ToolCall,
    ToolOutcome, TurnEvent, TurnRecord, TurnRequest, TurnSummary,
};
use super::subsystem::Subsystem;

/// Supplies the settings the daemon runs under.
///
/// Implemented by `claw-config` (with `claw-crestodian` supplying policy
/// overlays).
///
/// [`Self::settings`] is called every time settings are needed, never once at
/// start-up. That is what makes a configuration change take effect on the next
/// action rather than the next restart, and it is the same rule the
/// [`AuthorityPort`](super::authority::AuthorityPort) follows.
pub trait ConfigPort: Send + Sync + 'static {
    /// Returns the settings in force right now.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the configuration cannot be read or
    /// fails validation.
    fn settings(&self) -> BoxFuture<'_, Result<RuntimeSettings, SubsystemError>>;

    /// Returns how many times the configuration has been replaced since the
    /// process started, so callers can detect that a value they are holding is
    /// stale.
    fn generation(&self) -> u64;
}

/// Receives structured events from every subsystem.
///
/// Implemented by `claw-observability`.
///
/// [`Self::record`] is synchronous and must not block: it is called from
/// request paths and from drop glue. Implementations should hand the event to a
/// bounded queue and drop on overflow rather than apply back-pressure to the
/// caller.
pub trait ObservabilityPort: Send + Sync + 'static {
    /// Records one event.
    fn record(&self, event: ObservedEvent);

    /// Returns how many events were dropped because the queue was full.
    fn dropped(&self) -> u64;
}

/// Durable storage for sessions and turns.
///
/// Implemented by `claw-state`, which owns the schema and the SQLite file
/// control. The composition treats persistence strictly as a port and never
/// reaches for a file path.
pub trait PersistencePort: Send + Sync + 'static {
    /// Loads a session, returning `None` when it has never been recorded.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the store cannot be read.
    fn load_session(
        &self,
        id: &SessionId,
    ) -> BoxFuture<'_, Result<Option<SessionRecord>, SubsystemError>>;

    /// Begins a transaction.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when a transaction cannot be started.
    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn PersistenceTransaction>, SubsystemError>>;
}

/// A unit of durable work that either lands completely or not at all.
///
/// Dropping a transaction without calling [`Self::commit`] must roll it back.
/// The composition relies on that: a turn that fails part way through leaves no
/// half-written session.
pub trait PersistenceTransaction: Send + 'static {
    /// Stages a session insert or update.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the record is rejected, for instance
    /// because its revision is stale.
    fn upsert_session(&mut self, record: SessionRecord) -> Result<(), SubsystemError>;

    /// Stages a turn append.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the record is rejected.
    fn append_turn(&mut self, record: TurnRecord) -> Result<(), SubsystemError>;

    /// Commits everything staged.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the commit fails, in which case nothing
    /// staged has been applied.
    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), SubsystemError>>;

    /// Discards everything staged.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the rollback itself fails.
    fn rollback(self: Box<Self>) -> BoxFuture<'static, Result<(), SubsystemError>>;
}

/// A credential named together with the origin it may be presented to.
///
/// This pairing is the whole point. A credential is never looked up by name
/// alone, because a name says nothing about where the bytes will be sent. The
/// origin is a [`ResolvedEndpoint`], so it is the destination that was actually
/// checked rather than a hostname that could resolve elsewhere.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRequest {
    name: CredentialName,
    origin: ResolvedEndpoint,
}

impl CredentialRequest {
    /// Asks for `name` in order to authenticate to `origin`.
    #[must_use]
    pub const fn new(name: CredentialName, origin: ResolvedEndpoint) -> Self {
        Self { name, origin }
    }

    /// Returns the credential name.
    #[must_use]
    pub const fn name(&self) -> &CredentialName {
        &self.name
    }

    /// Returns the origin the credential will be presented to.
    #[must_use]
    pub const fn origin(&self) -> &ResolvedEndpoint {
        &self.origin
    }
}

/// Origin-bound credential storage.
///
/// Implemented by `claw-provider-sdk` / `claw-providers`.
///
/// Implementations must refuse to release a credential whose stored origin does
/// not match the requested one; [`CredentialLease::is_bound_to`] is the exact
/// comparison the composition expects, and the returned lease carries the origin
/// so a caller cannot present it elsewhere without being caught.
pub trait SecretStorePort: Send + Sync + 'static {
    /// Releases a credential for one use against one origin.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the grant cannot be redeemed, the
    /// credential is unknown, or it is filed against a different origin.
    fn lease(
        &self,
        request: Grant<CredentialRequest>,
    ) -> BoxFuture<'_, Result<CredentialLease, SubsystemError>>;

    /// Begins a transaction over the store.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when a transaction cannot be started.
    fn begin(&self) -> BoxFuture<'_, Result<Box<dyn SecretTransaction>, SubsystemError>>;
}

/// A transactional edit of the secret store.
///
/// As with [`PersistenceTransaction`], dropping without committing must discard
/// the staged changes. A partially applied credential rotation is worse than a
/// failed one.
pub trait SecretTransaction: Send + 'static {
    /// Stages a credential, bound to the origin it may be presented to.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the credential is rejected.
    fn put(
        &mut self,
        name: CredentialName,
        origin: ResolvedEndpoint,
        secret: SecretString,
    ) -> Result<(), SubsystemError>;

    /// Stages a credential removal.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the removal is rejected.
    fn remove(&mut self, name: &CredentialName) -> Result<(), SubsystemError>;

    /// Commits everything staged.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the commit fails.
    fn commit(self: Box<Self>) -> BoxFuture<'static, Result<(), SubsystemError>>;

    /// Discards everything staged.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the rollback itself fails.
    fn rollback(self: Box<Self>) -> BoxFuture<'static, Result<(), SubsystemError>>;
}

/// Knows which providers exist and where they live.
///
/// Implemented by `claw-providers` on top of `claw-provider-sdk`.
///
/// [`Self::resolve`] must build its [`ProviderBinding`] by passing the
/// configured URL through an [`EgressGuard`](super::egress::EgressGuard). A
/// binding assembled from an unchecked string defeats the guard for every caller
/// downstream, because the binding is what the transport connects to.
pub trait ProviderRegistryPort: Send + Sync + 'static {
    /// Returns every configured provider.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the registry cannot be read.
    fn bindings(&self) -> BoxFuture<'_, Result<Vec<ProviderBinding>, SubsystemError>>;

    /// Resolves one provider and model to the binding that serves it.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the provider is unknown, does not offer
    /// the model, or resolves to a destination egress policy forbids.
    fn resolve(
        &self,
        provider: &ProviderName,
        model: &ModelName,
    ) -> BoxFuture<'_, Result<ProviderBinding, SubsystemError>>;
}

/// Carries one request to a model provider.
///
/// Implemented by `claw-providers`.
///
/// The transport must connect to
/// [`ResolvedEndpoint::addresses`](super::egress::ResolvedEndpoint::addresses)
/// on the call's binding and must not resolve
/// [`ResolvedEndpoint::host`](super::egress::ResolvedEndpoint::host) again. The
/// host is present only for TLS server-name indication and the `Host` header.
pub trait ProviderTransportPort: Send + Sync + 'static {
    /// Sends the call and waits for the reply.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the grant cannot be redeemed or the
    /// provider call fails.
    fn send(
        &self,
        call: Grant<ProviderCall>,
    ) -> BoxFuture<'_, Result<ProviderReply, SubsystemError>>;
}

/// The sandboxed tool surface.
///
/// Implemented by `claw-tools`.
///
/// The catalogue is per-session and is re-read for each turn. A tool that was
/// available last turn may not be available this turn, and the composition
/// depends on that being observable rather than cached.
pub trait ToolSurfacePort: Send + Sync + 'static {
    /// Returns the tools available to this session right now.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the catalogue cannot be built.
    fn catalogue(
        &self,
        session: &ResolvedSession,
    ) -> BoxFuture<'_, Result<Vec<ToolBinding>, SubsystemError>>;

    /// Runs one tool.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the grant cannot be redeemed or the
    /// tool could not be run at all. A tool that ran and failed is reported as a
    /// failed [`ToolOutcome`], not as an error.
    fn invoke(&self, call: Grant<ToolCall>) -> BoxFuture<'_, Result<ToolOutcome, SubsystemError>>;
}

/// Builds the context a turn is given.
///
/// Implemented by `claw-memory`.
///
/// `budget` is a byte budget the assembler must respect; exceeding it is a
/// failure, not a truncation the caller has to detect.
pub trait ContextAssemblyPort: Send + Sync + 'static {
    /// Assembles context for one prompt.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when context cannot be assembled.
    fn assemble(
        &self,
        session: &ResolvedSession,
        prompt: &str,
        budget: usize,
    ) -> BoxFuture<'_, Result<AssembledContext, SubsystemError>>;
}

/// Receives turn events as they happen.
///
/// Implemented by whatever is streaming the turn to a client: the gateway, the
/// HTTP API's server-sent-event endpoints, or a channel adapter.
///
/// Events arrive with strictly increasing [`TurnEvent::sequence`] values, and
/// exactly one terminal event ends the sequence. Implementations must not block.
pub trait TurnEventSink: Send + Sync {
    /// Emits one event.
    fn emit(&self, event: TurnEvent);
}

/// Runs a turn.
///
/// Implemented by `claw-runtime`.
///
/// The engine is given a [`Grant<TurnRequest>`] and a
/// [`TurnCapabilities`](super::service::TurnCapabilities). It holds no
/// capability of its own: every provider call and every tool call it makes goes
/// back through the capabilities object, which re-authorizes at that moment.
pub trait SessionEnginePort: Send + Sync + 'static {
    /// Runs one turn to completion.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the turn cannot be completed.
    fn run_turn<'a>(
        &'a self,
        request: Grant<TurnRequest>,
        capabilities: &'a super::service::TurnCapabilities,
        events: &'a dyn TurnEventSink,
    ) -> BoxFuture<'a, Result<TurnSummary, SubsystemError>>;
}

/// Serves requests that arrive from outside the process.
///
/// Implemented by the composition itself
/// ([`SessionService`](super::service::SessionService)) and consumed by every
/// ingress subsystem. Ingress crates are handed one of these and never build
/// their own session handling.
pub trait GatewayDispatch: Send + Sync + 'static {
    /// Handles one request.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] describing why the request could not be
    /// served, including authorization denials.
    fn dispatch(
        &self,
        request: GatewayRequest,
    ) -> BoxFuture<'_, Result<GatewayResponse, SubsystemError>>;

    /// Returns the method names this dispatcher accepts, sorted.
    fn methods(&self) -> Vec<String>;
}

/// The Gateway protocol v4 server.
///
/// Implemented by `claw-gateway`, which must also implement [`Subsystem`].
///
/// The owner is expected to register all 278 methods from
/// `compat/upstream/inventories/gateway-protocol.json` and to authorize each
/// one through the composition's [`GatewayDispatch`] rather than by consulting a
/// decision taken at handshake time.
pub trait GatewayPort: Subsystem {
    /// Returns how many protocol methods are registered.
    fn registered_methods(&self) -> usize;

    /// Returns the addresses the server is actually bound to, which is empty
    /// before it has started.
    fn bound(&self) -> Vec<SocketAddr>;
}

/// One route exposed by the HTTP surface.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HttpRoute {
    method: String,
    path: String,
    streaming: bool,
}

impl HttpRoute {
    /// Declares a request/response route.
    #[must_use]
    pub fn unary(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            streaming: false,
        }
    }

    /// Declares a server-sent-event route.
    #[must_use]
    pub fn streaming(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            streaming: true,
        }
    }

    /// Returns the HTTP method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns whether the route streams.
    #[must_use]
    pub const fn is_streaming(&self) -> bool {
        self.streaming
    }
}

/// The HTTP and server-sent-event surface.
///
/// Implemented by `claw-http-api`, which must also implement [`Subsystem`].
pub trait HttpApiPort: Subsystem {
    /// Returns every route the surface serves.
    fn routes(&self) -> Vec<HttpRoute>;

    /// Returns the addresses the surface is bound to.
    fn bound(&self) -> Vec<SocketAddr>;
}

/// The WebAssembly component host.
///
/// Implemented by `claw-plugin-host`.
///
/// Capabilities must be installed on the instance during
/// [`Self::activate`], from the grant being redeemed at that moment, and must be
/// removed by [`Self::teardown`]. Installing them on the store before
/// instantiation and leaving them live is the exact defect this contract exists
/// to prevent.
pub trait PluginHostPort: Send + Sync + 'static {
    /// Instantiates a component with exactly the capabilities the grant carries.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the grant cannot be redeemed or the
    /// component cannot be instantiated.
    fn activate(
        &self,
        activation: Grant<PluginActivation>,
    ) -> BoxFuture<'_, Result<PluginInstance, SubsystemError>>;

    /// Destroys an instance and everything installed on it.
    ///
    /// # Errors
    ///
    /// Returns a [`SubsystemError`] when the instance could not be destroyed.
    fn teardown(&self, instance: PluginInstance) -> BoxFuture<'_, Result<(), SubsystemError>>;
}

/// An adapter that carries conversations to and from an external service.
///
/// Implemented by `claw-channels` (with `claw-skills` supplying behaviour), and
/// by `claw-nodes` for node-hosted conversations. Must also implement
/// [`Subsystem`].
pub trait ChannelPort: Subsystem {
    /// Returns the channels this adapter serves, sorted.
    fn channels(&self) -> Vec<String>;
}

/// A bridge to another agent protocol.
///
/// Implemented by `claw-mcp` and `claw-acp`. Must also implement [`Subsystem`].
pub trait BridgePort: Subsystem {
    /// Returns the protocol name, for instance `mcp` or `acp`.
    fn protocol(&self) -> &str;

    /// Returns how many peers are currently connected.
    fn connected_peers(&self) -> usize;
}

/// Scheduled and event-driven work.
///
/// Implemented by `claw-automation`. Must also implement [`Subsystem`].
pub trait AutomationPort: Subsystem {
    /// Returns how many triggers are currently armed.
    fn armed_triggers(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use super::{CredentialRequest, HttpRoute};
    use crate::composition::BoxFuture;
    use crate::composition::clock::ProcessClock;
    use crate::composition::egress::{
        DnsPort, EgressGuard, EgressPolicy, HostPattern, ResolvedEndpoint,
    };
    use crate::composition::error::SubsystemError;
    use crate::composition::session::CredentialName;

    /// Answers every lookup with one fixed address.
    #[derive(Debug)]
    struct FixedDns(IpAddr);

    impl DnsPort for FixedDns {
        fn lookup<'a>(
            &'a self,
            _host: &'a str,
        ) -> BoxFuture<'a, Result<Vec<IpAddr>, SubsystemError>> {
            Box::pin(async move { Ok(vec![self.0]) })
        }
    }

    async fn endpoint() -> ResolvedEndpoint {
        let guard = EgressGuard::new(
            EgressPolicy::deny_all().allow_host(HostPattern::parse("api.example.com")),
            Arc::new(FixedDns(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))),
            Arc::new(ProcessClock),
        );

        guard
            .resolve_url("https://api.example.com/v1")
            .await
            .expect("the host is allowed and resolves to a routable address")
    }

    #[tokio::test]
    async fn a_credential_request_keeps_the_origin_it_was_checked_against() {
        let origin = endpoint().await;
        let request = CredentialRequest::new(
            CredentialName::new("openai-key").expect("valid"),
            origin.clone(),
        );

        assert_eq!(request.name().as_str(), "openai-key");
        assert_eq!(request.origin().host(), "api.example.com");
        assert_eq!(request.origin().port(), 443);
        assert_eq!(
            request.origin().addresses(),
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    #[test]
    fn routes_distinguish_streaming_from_unary() {
        let unary = HttpRoute::unary("POST", "/v1/chat/completions");
        let stream = HttpRoute::streaming("GET", "/v1/sessions/events");

        assert_eq!(unary.method(), "POST");
        assert_eq!(unary.path(), "/v1/chat/completions");
        assert!(!unary.is_streaming());

        assert_eq!(stream.method(), "GET");
        assert_eq!(stream.path(), "/v1/sessions/events");
        assert!(stream.is_streaming());
        assert_ne!(unary, stream);
    }
}

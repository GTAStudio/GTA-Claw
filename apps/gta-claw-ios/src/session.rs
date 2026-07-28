//! Connection lifecycle presented as a snapshot a user interface can bind to.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use claw_gateway_client::{ConnectionInfo, ConnectionState};
use claw_protocol::gateway::ProtocolVersion;
use claw_security::authorization::{Role, Scope, ScopeSet};

use crate::endpoint::{EndpointSummary, GatewayEndpoint};
use crate::host_app::AppRunState;

/// Severity a front end may render for the current connection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IosStatusKind {
    /// Nothing is happening and nothing has failed.
    Neutral,
    /// A connection attempt is under way.
    Progress,
    /// The connection is authenticated.
    Ready,
    /// The connection is degraded but may recover.
    Warning,
    /// The connection stopped and will not recover without the user.
    Failed,
}

/// The interface carrying the current iOS network path.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IosNetworkInterface {
    /// A Wi-Fi path.
    Wifi,
    /// A cellular path.
    Cellular,
    /// A wired Ethernet path, including adapter-backed iPad connections.
    WiredEthernet,
    /// A loopback-only path.
    Loopback,
    /// A path whose interface type is not represented by this build.
    Other,
}

impl IosNetworkInterface {
    /// Returns text safe to render in connection diagnostics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Wifi => "Wi-Fi",
            Self::Cellular => "cellular",
            Self::WiredEthernet => "wired Ethernet",
            Self::Loopback => "loopback",
            Self::Other => "another interface",
        }
    }
}

impl Display for IosNetworkInterface {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// One usable path reported by the host application's network monitor.
///
/// `id` is an opaque, process-local route generation. The host app keeps it
/// stable when only cost flags change and advances it when the usable route
/// changes, including Wi-Fi-to-Wi-Fi transitions. This lets the core restart a
/// stale socket without treating duplicate path callbacks as route changes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IosNetworkRoute {
    id: u64,
    interface: IosNetworkInterface,
    expensive: bool,
    constrained: bool,
    local_network_available: bool,
}

impl IosNetworkRoute {
    /// Creates a route with ordinary cost and no asserted local-network path.
    #[must_use]
    pub const fn new(id: u64, interface: IosNetworkInterface) -> Self {
        Self {
            id,
            interface,
            expensive: false,
            constrained: false,
            local_network_available: false,
        }
    }

    /// Records the host monitor's `isExpensive` value.
    #[must_use]
    pub const fn with_expensive(mut self, expensive: bool) -> Self {
        self.expensive = expensive;
        self
    }

    /// Records the host monitor's `isConstrained` value.
    #[must_use]
    pub const fn with_constrained(mut self, constrained: bool) -> Self {
        self.constrained = constrained;
        self
    }

    /// Records whether the path can reach the local link.
    ///
    /// The host supplies this rather than the core inferring it from the
    /// interface type. VPNs and multi-interface paths make that inference
    /// unreliable.
    #[must_use]
    pub const fn with_local_network_available(mut self, available: bool) -> Self {
        self.local_network_available = available;
        self
    }

    /// Returns the opaque route generation.
    #[must_use]
    pub const fn id(self) -> u64 {
        self.id
    }

    /// Returns the interface carrying the route.
    #[must_use]
    pub const fn interface(self) -> IosNetworkInterface {
        self.interface
    }

    /// Returns whether iOS classifies the route as expensive.
    #[must_use]
    pub const fn is_expensive(self) -> bool {
        self.expensive
    }

    /// Returns whether Low Data Mode or an equivalent constraint applies.
    #[must_use]
    pub const fn is_constrained(self) -> bool {
        self.constrained
    }

    /// Returns whether the host confirmed a local-link path is available.
    #[must_use]
    pub const fn local_network_available(self) -> bool {
        self.local_network_available
    }

    const fn notice(self) -> Option<&'static str> {
        match (self.constrained, self.expensive) {
            (true, true) => Some(
                "Low Data Mode is active on an expensive path; background reconnects remain paused \
                 and foreground retries are bounded.",
            ),
            (true, false) => Some(
                "Low Data Mode is active; background reconnects remain paused and foreground \
                 retries are bounded.",
            ),
            (false, true) => Some(
                "This is an expensive network path; reconnect attempts are bounded to limit data \
                 and battery use.",
            ),
            (false, false) => None,
        }
    }
}

/// Availability reported by the host application's `NWPathMonitor` adapter.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IosNetworkPath {
    /// The host has not delivered an initial path yet.
    #[default]
    Unknown,
    /// No route is currently usable.
    Unsatisfied,
    /// iOS may establish a route after user or system action.
    RequiresConnection,
    /// A route is usable now.
    Satisfied(IosNetworkRoute),
}

impl IosNetworkPath {
    /// Returns whether a Gateway socket may be started now.
    #[must_use]
    pub const fn is_satisfied(self) -> bool {
        matches!(self, Self::Satisfied(_))
    }

    /// Returns the usable route, if one exists.
    #[must_use]
    pub const fn route(self) -> Option<IosNetworkRoute> {
        match self {
            Self::Satisfied(route) => Some(route),
            Self::Unknown | Self::Unsatisfied | Self::RequiresConnection => None,
        }
    }

    /// Returns whether the path can be used for local discovery.
    #[must_use]
    pub const fn local_network_available(self) -> bool {
        match self {
            Self::Satisfied(route) => route.local_network_available(),
            Self::Unknown | Self::Unsatisfied | Self::RequiresConnection => false,
        }
    }

    /// Returns text safe to render beside network state.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "checking network",
            Self::Unsatisfied => "offline",
            Self::RequiresConnection => "network requires connection",
            Self::Satisfied(route) => route.interface().label(),
        }
    }
}

impl Display for IosNetworkPath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// An operation a user interface may offer to a person.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IosAction {
    /// Read sessions and history.
    ReadSessions,
    /// Send a message into a session.
    SendMessage,
    /// Resolve a pending approval.
    ResolveApproval,
    /// Change Gateway configuration.
    Administer,
}

impl IosAction {
    /// Every action a user interface may offer, in a stable order.
    pub const ALL: [Self; 4] = [
        Self::ReadSessions,
        Self::SendMessage,
        Self::ResolveApproval,
        Self::Administer,
    ];

    /// Returns the single Gateway scope this action requires.
    #[must_use]
    pub const fn required_scope(self) -> Scope {
        match self {
            Self::ReadSessions => Scope::OperatorRead,
            Self::SendMessage => Scope::OperatorWrite,
            Self::ResolveApproval => Scope::OperatorApprovals,
            Self::Administer => Scope::OperatorAdmin,
        }
    }

    /// Returns text safe to render on a control.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadSessions => "read sessions",
            Self::SendMessage => "send a message",
            Self::ResolveApproval => "resolve an approval",
            Self::Administer => "administer the Gateway",
        }
    }
}

impl Display for IosAction {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// The authorization a Gateway actually confirmed for the live connection.
///
/// This is built only from a validated server hello. It is never built from the
/// role and scopes the client *requested*, because a request is not a grant, and
/// an interface that renders a requested scope as though it were held is a
/// fabricated permission summary.
///
/// Scope implication is deliberately not modelled: `operator.admin` does not
/// imply `operator.read` here.
///
/// Implication rules *do* exist in this workspace, on the server side —
/// `claw_protocol::gateway::authorization` allows any method when the granted
/// set contains `operator.admin`, and treats `operator.write` as satisfying
/// `operator.read`. This client deliberately does not mirror them. Mirroring
/// would make the interface *more* permissive by inference, and an interface
/// that infers a grant it was never told about is the fabricated permission
/// summary this type exists to prevent.
///
/// The cost is accepted and is in the safe direction: this client may withhold
/// an action the server would in fact have allowed, which a person discovers by
/// the action being absent. The reverse — offering an action the server refuses
/// — would be discovered by a failure after the person had been told they could.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedAuthorization {
    role: Option<Role>,
    role_text: String,
    scopes: ScopeSet,
    unrecognized_scopes: Vec<String>,
}

impl ObservedAuthorization {
    /// Reads the confirmed authorization out of a validated server hello.
    #[must_use]
    pub fn from_connection(info: &ConnectionInfo) -> Self {
        let mut recognized = Vec::new();
        let mut unrecognized_scopes = Vec::new();
        for scope in info.scopes.iter() {
            match Scope::parse(scope) {
                Ok(scope) => recognized.push(scope),
                Err(_) => unrecognized_scopes.push(scope.clone()),
            }
        }
        Self {
            role: Role::parse(&info.role).ok(),
            role_text: info.role.clone(),
            scopes: ScopeSet::from_scopes(recognized),
            unrecognized_scopes,
        }
    }

    /// Returns the confirmed role when it is one this build understands.
    #[must_use]
    pub const fn role(&self) -> Option<Role> {
        self.role
    }

    /// Returns the exact role identity the server sent, understood or not.
    #[must_use]
    pub fn role_text(&self) -> &str {
        &self.role_text
    }

    /// Returns the confirmed scopes this build understands.
    #[must_use]
    pub const fn scopes(&self) -> ScopeSet {
        self.scopes
    }

    /// Returns confirmed scope identities this build does not understand.
    ///
    /// These are surfaced rather than discarded so that a person is not told
    /// their access is narrower than the server actually granted. They never
    /// grant an action, because this build cannot enforce a scope it cannot
    /// name.
    #[must_use]
    pub fn unrecognized_scopes(&self) -> &[String] {
        &self.unrecognized_scopes
    }

    /// Returns whether the confirmed scopes permit an action.
    #[must_use]
    pub const fn grants(&self, action: IosAction) -> bool {
        self.scopes.contains(action.required_scope())
    }

    /// Returns text describing the confirmed authorization.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut names = self
            .scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect::<Vec<_>>();
        names.extend(
            self.unrecognized_scopes
                .iter()
                .map(|scope| format!("{scope} (not enforced by this build)")),
        );
        if names.is_empty() {
            format!("{} with no scopes", self.role_text)
        } else {
            format!("{} with {}", self.role_text, names.join(", "))
        }
    }
}

/// A witness that an action was checked against the confirmed authorization.
///
/// The only way to obtain one is [`IosSessionModel::authorize`], so acting code
/// cannot proceed on a permission without consulting the same record the
/// interface rendered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedAction {
    action: IosAction,
}

impl AuthorizedAction {
    /// Returns the authorized action.
    #[must_use]
    pub const fn action(self) -> IosAction {
        self.action
    }
}

/// An action the live connection does not permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDenied {
    action: IosAction,
    observed: Option<ObservedAuthorization>,
}

impl AuthorizationDenied {
    /// Returns the refused action.
    #[must_use]
    pub const fn action(&self) -> IosAction {
        self.action
    }

    /// Returns the scope the action would have required.
    #[must_use]
    pub const fn required_scope(&self) -> Scope {
        self.action.required_scope()
    }

    /// Returns the confirmed authorization, when a connection was established.
    #[must_use]
    pub const fn observed(&self) -> Option<&ObservedAuthorization> {
        self.observed.as_ref()
    }
}

impl Display for AuthorizationDenied {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match &self.observed {
            Some(observed) => write!(
                formatter,
                "cannot {}: this connection is {}, and the action requires {}",
                self.action,
                observed.summary(),
                self.required_scope().as_str()
            ),
            None => write!(
                formatter,
                "cannot {}: no authenticated connection has confirmed any authorization",
                self.action
            ),
        }
    }
}

impl Error for AuthorizationDenied {}

/// A connection attempt was refused before it started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptRejected {
    /// Another transport task still owns the session.
    AlreadyInFlight,
    /// The app is not active in the foreground.
    AppNotForeground {
        /// The state the host most recently reported.
        state: AppRunState,
    },
    /// The host has not reported a usable network path.
    NetworkUnavailable {
        /// The path state that blocked the attempt.
        path: IosNetworkPath,
    },
}

impl Display for AttemptRejected {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInFlight => {
                formatter.write_str("a connection attempt is already in flight")
            }
            Self::AppNotForeground { state } => write!(
                formatter,
                "connection is paused while the app is {}; return to the foreground to connect",
                state.label()
            ),
            Self::NetworkUnavailable { path } => write!(
                formatter,
                "connection is paused because the network is {path}; wait for a usable path"
            ),
        }
    }
}

impl Error for AttemptRejected {}

/// Why the core asks the host to stop its current transport task.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransportStopReason {
    /// The application entered the background.
    EnteredBackground,
    /// The current network path became unusable.
    NetworkUnavailable,
    /// A different usable route replaced the one carrying the socket.
    NetworkChanged,
    /// The person explicitly cancelled or disconnected.
    UserRequested,
}

/// Why a previously interrupted connection is ready to resume.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransportResumeReason {
    /// The application became active in the foreground.
    ReturnedToForeground,
    /// A usable network path became available.
    NetworkRestored,
    /// A changed route requires a fresh socket.
    NetworkChanged,
}

/// Work the host app should perform after a lifecycle or network transition.
///
/// This core never owns the async runtime or the `GatewayClient`. The host
/// processes a `Stop` by cancelling or shutting down the matching task, then
/// drops its [`ConnectionAttempt`] and calls [`IosSessionModel::reconcile`].
/// It processes `Resume` by starting a new attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransportDirective {
    /// No transport work is needed.
    #[default]
    None,
    /// Stop the current generation-scoped task.
    Stop {
        /// The task generation to stop.
        attempt_id: u64,
        /// Why continuing it would be incorrect.
        reason: TransportStopReason,
    },
    /// Start a fresh transport when the host is ready.
    Resume {
        /// Why the previous connection was interrupted.
        reason: TransportResumeReason,
    },
}

/// Whether a generation-scoped transport observation changed the model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationResult {
    /// The observation changed the cached snapshot.
    Applied {
        /// Revision of the resulting snapshot.
        revision: u64,
    },
    /// The transport repeated the state already rendered.
    Unchanged {
        /// Current snapshot revision.
        revision: u64,
    },
    /// The observation belongs to a task the core has already invalidated.
    Stale,
}

/// What this crate has actually observed about the connection.
///
/// [`ConnectionState::Ready`] carries a [`claw_gateway_client::ConnectionEpoch`]
/// that only the transport client may allocate, so the authenticated case is
/// reduced here to the validated hello summary the interface needs.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Observed {
    Lifecycle(ConnectionState),
    Authenticated(ConnectionInfo),
    Abandoned,
    Suspended(TransportStopReason),
}

fn classify(state: ConnectionState) -> Observed {
    match state {
        ConnectionState::Ready(ready) => Observed::Authenticated(ready.info),
        other => Observed::Lifecycle(other),
    }
}

const fn is_in_progress(observed: Option<&Observed>) -> bool {
    matches!(
        observed,
        Some(Observed::Lifecycle(
            ConnectionState::Starting
                | ConnectionState::Connecting
                | ConnectionState::Authenticating
                | ConnectionState::Reconnecting { .. }
        ))
    )
}

#[derive(Debug)]
struct SessionState {
    observed: Option<Observed>,
    attempt: Option<u64>,
    stopping_attempt: Option<u64>,
    next_attempt: u64,
    run_state: AppRunState,
    network_path: IosNetworkPath,
    resume_reason: Option<TransportResumeReason>,
    revision: u64,
    snapshot: Arc<IosViewSnapshot>,
}

#[derive(Debug)]
struct Shared {
    endpoint: EndpointSummary,
    state: Mutex<SessionState>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn refresh(&self, state: &mut SessionState) {
        state.revision = state.revision.wrapping_add(1);
        state.snapshot = Arc::new(IosViewSnapshot::build(
            state.revision,
            self.endpoint.clone(),
            SnapshotInputs {
                observed: state.observed.as_ref(),
                attempt_in_flight: state.attempt.is_some(),
                transport_stopping: state.stopping_attempt.is_some(),
                run_state: state.run_state,
                network_path: state.network_path,
                resume_reason: state.resume_reason,
            },
        ));
    }
}

/// The iOS connection lifecycle, rendered for a user interface.
///
/// Cheap to clone; every clone observes the same state.
#[derive(Clone, Debug)]
pub struct IosSessionModel {
    shared: Arc<Shared>,
}

impl IosSessionModel {
    /// Creates a model for one endpoint with no attempt in flight.
    ///
    /// The model starts fail-closed as [`AppRunState::Inactive`] with
    /// [`IosNetworkPath::Unknown`]. A host must report
    /// [`AppRunState::Foreground`] and a satisfied path before
    /// [`IosSessionModel::begin_attempt`] can succeed.
    #[must_use]
    pub fn new(endpoint: &GatewayEndpoint) -> Self {
        let endpoint = endpoint.summary();
        let run_state = AppRunState::default();
        let network_path = IosNetworkPath::default();
        let snapshot = Arc::new(IosViewSnapshot::build(
            0,
            endpoint.clone(),
            SnapshotInputs {
                observed: None,
                attempt_in_flight: false,
                transport_stopping: false,
                run_state,
                network_path,
                resume_reason: None,
            },
        ));
        Self {
            shared: Arc::new(Shared {
                endpoint,
                state: Mutex::new(SessionState {
                    observed: None,
                    attempt: None,
                    stopping_attempt: None,
                    next_attempt: 1,
                    run_state,
                    network_path,
                    resume_reason: None,
                    revision: 0,
                    snapshot,
                }),
            }),
        }
    }

    /// Records the host application's current lifecycle state.
    ///
    /// Entering the background immediately invalidates the active generation
    /// and removes its authorization from the snapshot. A late `Ready`
    /// observation from that task is then rejected as stale. The transient
    /// [`AppRunState::Inactive`] state does not tear down an established socket:
    /// permission alerts and interruptions pass through it, and reconnect churn
    /// there would waste battery and can suppress the alert that caused it.
    #[must_use]
    pub fn set_run_state(&self, run_state: AppRunState) -> TransportDirective {
        let mut state = self.shared.lock();
        if state.run_state == run_state {
            let directive = reconcile_state(&state);
            drop(state);
            return directive;
        }
        state.run_state = run_state;
        let directive = if run_state == AppRunState::Background {
            suspend_transport(
                &mut state,
                TransportStopReason::EnteredBackground,
                TransportResumeReason::ReturnedToForeground,
            )
        } else {
            TransportDirective::None
        };
        self.shared.refresh(&mut state);
        let directive = if directive == TransportDirective::None {
            reconcile_state(&state)
        } else {
            directive
        };
        drop(state);
        directive
    }

    /// Records a semantic network-path update from the host application.
    ///
    /// Duplicate values are coalesced without advancing the snapshot revision.
    /// A path becoming unavailable stops retries immediately. A changed route
    /// generation also stops the old task even when both paths are satisfied,
    /// because a socket tied to the old route should not spend its retry budget
    /// before the new path is used.
    #[must_use]
    pub fn set_network_path(&self, network_path: IosNetworkPath) -> TransportDirective {
        let mut state = self.shared.lock();
        if state.network_path == network_path {
            let directive = reconcile_state(&state);
            drop(state);
            return directive;
        }
        let route_changed = matches!(
            (state.network_path.route(), network_path.route()),
            (Some(previous), Some(current)) if previous.id() != current.id()
        );
        state.network_path = network_path;
        let directive = if !network_path.is_satisfied() {
            suspend_transport(
                &mut state,
                TransportStopReason::NetworkUnavailable,
                TransportResumeReason::NetworkRestored,
            )
        } else if route_changed {
            suspend_transport(
                &mut state,
                TransportStopReason::NetworkChanged,
                TransportResumeReason::NetworkChanged,
            )
        } else {
            TransportDirective::None
        };
        self.shared.refresh(&mut state);
        let directive = if directive == TransportDirective::None {
            reconcile_state(&state)
        } else {
            directive
        };
        drop(state);
        directive
    }

    /// Returns transport work made possible by the current host state.
    ///
    /// Call this after the host has stopped and dropped an invalidated transport
    /// task. It is side-effect free; [`IosSessionModel::begin_attempt`] consumes
    /// the pending resume only after a replacement task is actually reserved.
    #[must_use]
    pub fn reconcile(&self) -> TransportDirective {
        reconcile_state(&self.shared.lock())
    }

    /// Marks one connection attempt as in flight.
    ///
    /// The returned guard releases the marker when it is dropped, which includes
    /// the case where the caller's future is dropped rather than run to
    /// completion. On iOS that is the ordinary case rather than an edge case:
    /// the system suspends an application whenever it leaves the foreground, so
    /// a model that only released its marker on a completion path would strand
    /// the interface on "connecting" for the rest of the process lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptRejected`] when an attempt is already in flight, the app
    /// is not active in the foreground, or no usable network path exists.
    pub fn begin_attempt(&self) -> Result<ConnectionAttempt, AttemptRejected> {
        let mut state = self.shared.lock();
        if state.attempt.is_some() || state.stopping_attempt.is_some() {
            return Err(AttemptRejected::AlreadyInFlight);
        }
        if state.run_state != AppRunState::Foreground {
            return Err(AttemptRejected::AppNotForeground {
                state: state.run_state,
            });
        }
        if !state.network_path.is_satisfied() {
            return Err(AttemptRejected::NetworkUnavailable {
                path: state.network_path,
            });
        }
        let id = state.next_attempt;
        state.next_attempt = state.next_attempt.wrapping_add(1);
        state.attempt = Some(id);
        state.resume_reason = None;
        state.observed = Some(Observed::Lifecycle(ConnectionState::Starting));
        self.shared.refresh(&mut state);
        drop(state);
        Ok(ConnectionAttempt {
            shared: Arc::clone(&self.shared),
            id,
        })
    }

    /// Stops the active transport in response to a user action.
    ///
    /// The generation is invalidated before this returns, so callbacks racing
    /// with cancellation cannot restore authorization.
    #[must_use]
    pub fn request_disconnect(&self) -> TransportDirective {
        let mut state = self.shared.lock();
        let attempt_id = state.attempt.take();
        if let Some(attempt_id) = attempt_id {
            state.stopping_attempt = Some(attempt_id);
        }
        let had_pending_resume = state.resume_reason.take().is_some();
        if attempt_id.is_none() && state.stopping_attempt.is_none() {
            if had_pending_resume {
                state.observed = Some(Observed::Lifecycle(ConnectionState::Stopped));
                self.shared.refresh(&mut state);
            }
            drop(state);
            return TransportDirective::None;
        }
        let already_stopped = matches!(
            state.observed,
            Some(Observed::Lifecycle(ConnectionState::Stopped))
        );
        if !already_stopped {
            state.observed = Some(Observed::Lifecycle(ConnectionState::Stopped));
            self.shared.refresh(&mut state);
        } else if attempt_id.is_some() {
            self.shared.refresh(&mut state);
        }
        let directive = attempt_id.map_or(TransportDirective::None, |attempt_id| {
            TransportDirective::Stop {
                attempt_id,
                reason: TransportStopReason::UserRequested,
            }
        });
        drop(state);
        directive
    }

    /// Returns whether an attempt guard is currently held.
    #[must_use]
    pub fn attempt_in_flight(&self) -> bool {
        let state = self.shared.lock();
        state.attempt.is_some() || state.stopping_attempt.is_some()
    }

    /// Returns the current view of the connection.
    #[must_use]
    pub fn snapshot(&self) -> Arc<IosViewSnapshot> {
        Arc::clone(&self.shared.lock().snapshot)
    }

    /// Returns the cached snapshot only when its revision differs from `known`.
    ///
    /// Comparison uses inequality rather than ordering so it remains correct if
    /// the process survives enough updates for the counter to wrap.
    #[must_use]
    pub fn snapshot_if_changed(&self, known: u64) -> Option<Arc<IosViewSnapshot>> {
        let snapshot = self.snapshot();
        (snapshot.revision() != known).then_some(snapshot)
    }

    /// Checks an action against the authorization the server confirmed.
    ///
    /// This consults exactly the record [`IosViewSnapshot::permits`] renders, so
    /// an interface cannot offer a control the acting code would refuse.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationDenied`] when no connection is authenticated or
    /// the confirmed scopes do not include the action's required scope.
    pub fn authorize(&self, action: IosAction) -> Result<AuthorizedAction, AuthorizationDenied> {
        let snapshot = self.snapshot();
        if snapshot.permits(action) {
            Ok(AuthorizedAction { action })
        } else {
            Err(AuthorizationDenied {
                action,
                observed: snapshot.authorization().cloned(),
            })
        }
    }
}

fn reconcile_state(state: &SessionState) -> TransportDirective {
    if let Some(reason) = state.resume_reason
        && state.attempt.is_none()
        && state.stopping_attempt.is_none()
        && state.run_state == AppRunState::Foreground
        && state.network_path.is_satisfied()
    {
        TransportDirective::Resume { reason }
    } else {
        TransportDirective::None
    }
}

fn suspend_transport(
    state: &mut SessionState,
    stop_reason: TransportStopReason,
    resume_reason: TransportResumeReason,
) -> TransportDirective {
    // Resync and terminal transport states require an explicit new user
    // attempt; lifecycle changes must not turn them into automatic resumes.
    let resumable = state.resume_reason.is_some()
        || matches!(
            state.observed,
            Some(
                Observed::Authenticated(_)
                    | Observed::Lifecycle(
                        ConnectionState::Starting
                            | ConnectionState::Connecting
                            | ConnectionState::Authenticating
                            | ConnectionState::Reconnecting { .. }
                    )
            )
        );
    let attempt_id = state.attempt.take();
    if let Some(attempt_id) = attempt_id {
        state.stopping_attempt = Some(attempt_id);
    }
    if !resumable {
        return attempt_id.map_or(TransportDirective::None, |attempt_id| {
            TransportDirective::Stop {
                attempt_id,
                reason: stop_reason,
            }
        });
    }
    if attempt_id.is_none() && state.stopping_attempt.is_none() {
        return TransportDirective::None;
    }
    state.observed = Some(Observed::Suspended(stop_reason));
    state.resume_reason = Some(resume_reason);
    attempt_id.map_or(TransportDirective::None, |attempt_id| {
        TransportDirective::Stop {
            attempt_id,
            reason: stop_reason,
        }
    })
}

/// An in-flight connection attempt.
///
/// Dropping this releases the model's in-flight marker, and moves an incomplete
/// attempt to an abandoned state so the interface becomes usable again.
#[derive(Debug)]
#[must_use = "the attempt is only in flight while this guard is held"]
pub struct ConnectionAttempt {
    shared: Arc<Shared>,
    id: u64,
}

impl ConnectionAttempt {
    /// Returns the process-local attempt identity.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Records a state from this exact transport generation.
    ///
    /// Observations are ignored after lifecycle, network, or user actions have
    /// invalidated the generation. This is the path host integration must use;
    /// accepting unscoped callbacks would let a late `Ready` resurrect a
    /// backgrounded or offline session.
    #[must_use]
    pub fn observe(&self, connection: ConnectionState) -> ObservationResult {
        self.observe_value(classify(connection))
    }

    fn observe_value(&self, observed: Observed) -> ObservationResult {
        let mut state = self.shared.lock();
        if state.attempt != Some(self.id) {
            drop(state);
            return ObservationResult::Stale;
        }
        debug_assert!(
            state.resume_reason.is_none(),
            "resume reason must be consumed before an attempt becomes active"
        );
        if state.observed.as_ref() == Some(&observed) {
            let revision = state.revision;
            drop(state);
            return ObservationResult::Unchanged { revision };
        }
        state.observed = Some(observed);
        self.shared.refresh(&mut state);
        let revision = state.revision;
        drop(state);
        ObservationResult::Applied { revision }
    }

    #[cfg(test)]
    fn observe_authenticated(&self, info: ConnectionInfo) -> ObservationResult {
        self.observe_value(Observed::Authenticated(info))
    }
}

impl Drop for ConnectionAttempt {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        if state.stopping_attempt == Some(self.id) {
            state.stopping_attempt = None;
            self.shared.refresh(&mut state);
            drop(state);
            return;
        }
        if state.attempt != Some(self.id) {
            drop(state);
            return;
        }
        debug_assert!(
            state.resume_reason.is_none(),
            "resume reason must be consumed before an attempt becomes active"
        );
        state.attempt = None;
        if state.observed.is_none()
            || is_in_progress(state.observed.as_ref())
            || matches!(state.observed, Some(Observed::Authenticated(_)))
        {
            state.observed = Some(Observed::Abandoned);
        }
        self.shared.refresh(&mut state);
        drop(state);
    }
}

/// A complete, redaction-safe view of the connection for one render pass.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these booleans are independent control and scheduling facts a front end binds \
              directly, not a state that could be one enum: progress, cancellation, connection, \
              pending resume, and transport ownership overlap in different combinations"
)]
pub struct IosViewSnapshot {
    revision: u64,
    endpoint: EndpointSummary,
    run_state: AppRunState,
    network_path: IosNetworkPath,
    status: IosStatusKind,
    title: String,
    detail: String,
    protocol: Option<ProtocolVersion>,
    server_version: Option<String>,
    authorization: Option<ObservedAuthorization>,
    busy: bool,
    can_connect: bool,
    can_cancel: bool,
    can_disconnect: bool,
    should_resume: bool,
    transport_active: bool,
}

#[derive(Clone, Copy)]
struct SnapshotInputs<'a> {
    observed: Option<&'a Observed>,
    attempt_in_flight: bool,
    transport_stopping: bool,
    run_state: AppRunState,
    network_path: IosNetworkPath,
    resume_reason: Option<TransportResumeReason>,
}

impl IosViewSnapshot {
    fn build(revision: u64, endpoint: EndpointSummary, inputs: SnapshotInputs<'_>) -> Self {
        let SnapshotInputs {
            observed,
            attempt_in_flight,
            transport_stopping,
            run_state,
            network_path,
            resume_reason,
        } = inputs;
        let (mut status, mut title, mut detail) = describe(observed, run_state, network_path);
        let info = match observed {
            Some(Observed::Authenticated(info)) => Some(info),
            _ => None,
        };
        let busy = attempt_in_flight && status == IosStatusKind::Progress;
        let transport_active = attempt_in_flight || transport_stopping;
        let can_connect = !transport_active
            && info.is_none()
            && run_state == AppRunState::Foreground
            && network_path.is_satisfied();
        let should_resume = resume_reason.is_some() && can_connect;
        if let Some(reason) = resume_reason.filter(|_| should_resume) {
            status = IosStatusKind::Warning;
            "Ready to reconnect".clone_into(&mut title);
            Self::resume_detail(reason).clone_into(&mut detail);
        }
        if let Some(notice) = network_path.route().and_then(IosNetworkRoute::notice)
            && (info.is_some() || status == IosStatusKind::Progress)
        {
            detail.push(' ');
            detail.push_str(notice);
        }
        Self {
            revision,
            endpoint,
            run_state,
            network_path,
            status,
            title,
            detail,
            protocol: info.map(|info| info.protocol),
            server_version: info.map(|info| info.server_version.clone()),
            authorization: info.map(ObservedAuthorization::from_connection),
            busy,
            can_connect,
            can_cancel: busy,
            can_disconnect: info.is_some(),
            should_resume,
            transport_active,
        }
    }

    const fn resume_detail(reason: TransportResumeReason) -> &'static str {
        match reason {
            TransportResumeReason::ReturnedToForeground => {
                "The app is active again and can start a fresh Gateway connection."
            }
            TransportResumeReason::NetworkRestored => {
                "A usable network is available again and can carry a fresh Gateway connection."
            }
            TransportResumeReason::NetworkChanged => {
                "The route changed; reconnect to bind the Gateway socket to the current path."
            }
        }
    }

    /// Returns the model revision that produced this snapshot.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns display text for the endpoint that cannot carry a credential.
    #[must_use]
    pub const fn endpoint(&self) -> &EndpointSummary {
        &self.endpoint
    }

    /// Returns the host lifecycle state used for this render.
    #[must_use]
    pub const fn run_state(&self) -> AppRunState {
        self.run_state
    }

    /// Returns the host network path used for this render.
    #[must_use]
    pub const fn network_path(&self) -> IosNetworkPath {
        self.network_path
    }

    /// Returns the severity to render.
    #[must_use]
    pub const fn status(&self) -> IosStatusKind {
        self.status
    }

    /// Returns the headline text.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the supporting text.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Returns the negotiated protocol version, once authenticated.
    #[must_use]
    pub const fn protocol(&self) -> Option<ProtocolVersion> {
        self.protocol
    }

    /// Returns the server version text, once authenticated.
    #[must_use]
    pub fn server_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    /// Returns the authorization the server confirmed, once authenticated.
    ///
    /// This is [`None`] at every other point in the lifecycle, including while
    /// an attempt is in flight. There is no partial or optimistic value.
    #[must_use]
    pub const fn authorization(&self) -> Option<&ObservedAuthorization> {
        self.authorization.as_ref()
    }

    /// Returns whether the live connection permits an action.
    ///
    /// Always `false` without an authenticated connection.
    #[must_use]
    pub fn permits(&self, action: IosAction) -> bool {
        self.authorization
            .as_ref()
            .is_some_and(|observed| observed.grants(action))
    }

    /// Returns whether work is in progress.
    #[must_use]
    pub const fn busy(&self) -> bool {
        self.busy
    }

    /// Returns whether a connect control should be enabled.
    #[must_use]
    pub const fn can_connect(&self) -> bool {
        self.can_connect
    }

    /// Returns whether a cancel control should be enabled.
    #[must_use]
    pub const fn can_cancel(&self) -> bool {
        self.can_cancel
    }

    /// Returns whether a disconnect control should be enabled.
    #[must_use]
    pub const fn can_disconnect(&self) -> bool {
        self.can_disconnect
    }

    /// Returns whether a lifecycle- or network-interrupted session is ready to resume.
    #[must_use]
    pub const fn should_resume(&self) -> bool {
        self.should_resume
    }

    /// Returns whether a generation-scoped transport task still owns the model.
    #[must_use]
    pub const fn transport_active(&self) -> bool {
        self.transport_active
    }
}

fn describe(
    observed: Option<&Observed>,
    run_state: AppRunState,
    network_path: IosNetworkPath,
) -> (IosStatusKind, String, String) {
    let Some(observed) = observed else {
        if run_state == AppRunState::Background {
            return (
                IosStatusKind::Neutral,
                "Paused in background".to_owned(),
                "Connections and retries resume only after the app returns to the foreground."
                    .to_owned(),
            );
        }
        if run_state == AppRunState::Inactive {
            return (
                IosStatusKind::Neutral,
                "App inactive".to_owned(),
                "Waiting for the app to become active before starting network work.".to_owned(),
            );
        }
        if !network_path.is_satisfied() {
            return describe_unavailable_network(network_path);
        }
        return (
            IosStatusKind::Neutral,
            "Not connected".to_owned(),
            "No connection has been attempted.".to_owned(),
        );
    };
    match observed {
        Observed::Abandoned => (
            IosStatusKind::Neutral,
            "Not connected".to_owned(),
            "The connection attempt was abandoned before it finished.".to_owned(),
        ),
        Observed::Authenticated(info) => (
            IosStatusKind::Ready,
            "Connected".to_owned(),
            format!(
                "Authenticated as {}.",
                ObservedAuthorization::from_connection(info).summary()
            ),
        ),
        Observed::Suspended(reason) => describe_suspension(*reason, network_path),
        Observed::Lifecycle(state) => describe_lifecycle(state),
    }
}

fn describe_unavailable_network(network_path: IosNetworkPath) -> (IosStatusKind, String, String) {
    match network_path {
        IosNetworkPath::Unknown => (
            IosStatusKind::Neutral,
            "Checking the network".to_owned(),
            "Waiting for the host app's first network-path update.".to_owned(),
        ),
        IosNetworkPath::Unsatisfied => (
            IosStatusKind::Warning,
            "No network connection".to_owned(),
            "Reconnect attempts are paused until iOS reports a usable path.".to_owned(),
        ),
        IosNetworkPath::RequiresConnection => (
            IosStatusKind::Warning,
            "Network needs attention".to_owned(),
            "iOS says the route requires a connection first; retries are paused meanwhile."
                .to_owned(),
        ),
        IosNetworkPath::Satisfied(_) => (
            IosStatusKind::Neutral,
            "Not connected".to_owned(),
            "No connection has been attempted.".to_owned(),
        ),
    }
}

fn describe_suspension(
    reason: TransportStopReason,
    network_path: IosNetworkPath,
) -> (IosStatusKind, String, String) {
    match reason {
        TransportStopReason::EnteredBackground => (
            IosStatusKind::Neutral,
            "Paused in background".to_owned(),
            "The connection was stopped to avoid background retries and will be eligible to \
             resume when the app becomes active."
                .to_owned(),
        ),
        TransportStopReason::NetworkUnavailable => describe_unavailable_network(network_path),
        TransportStopReason::NetworkChanged => (
            IosStatusKind::Warning,
            "Network changed".to_owned(),
            "The old socket was stopped before reconnecting on the new route.".to_owned(),
        ),
        TransportStopReason::UserRequested => (
            IosStatusKind::Neutral,
            "Disconnected".to_owned(),
            "The connection was closed.".to_owned(),
        ),
    }
}

fn describe_lifecycle(state: &ConnectionState) -> (IosStatusKind, String, String) {
    match state {
        ConnectionState::Starting => (
            IosStatusKind::Progress,
            "Starting".to_owned(),
            "Preparing the connection.".to_owned(),
        ),
        ConnectionState::Connecting => (
            IosStatusKind::Progress,
            "Connecting".to_owned(),
            "Opening the Gateway socket.".to_owned(),
        ),
        ConnectionState::Authenticating => (
            IosStatusKind::Progress,
            "Authenticating".to_owned(),
            "Proving this device to the Gateway.".to_owned(),
        ),
        ConnectionState::Reconnecting { attempt, delay } => (
            IosStatusKind::Progress,
            "Reconnecting".to_owned(),
            format!("Attempt {attempt} starts in {} ms.", delay.as_millis()),
        ),
        ConnectionState::ResyncRequired(reason) => (
            IosStatusKind::Warning,
            "Out of sync".to_owned(),
            format!("{reason}."),
        ),
        ConnectionState::AuthenticationFailed(failure) => (
            IosStatusKind::Failed,
            "Sign-in failed".to_owned(),
            format!("{failure}."),
        ),
        ConnectionState::ProtocolFailed { category } => (
            IosStatusKind::Failed,
            "Protocol failure".to_owned(),
            format!("The Gateway sent something this build rejects ({category})."),
        ),
        ConnectionState::ReconnectExhausted => (
            IosStatusKind::Failed,
            "Gave up reconnecting".to_owned(),
            "The retry budget for this endpoint is spent.".to_owned(),
        ),
        ConnectionState::Stopped => (
            IosStatusKind::Neutral,
            "Disconnected".to_owned(),
            "The connection was closed.".to_owned(),
        ),
        // `classify` turns Ready into Observed::Authenticated before it reaches
        // this function; this arm exists so the match stays exhaustive.
        ConnectionState::Ready(ready) => (
            IosStatusKind::Ready,
            "Connected".to_owned(),
            format!(
                "Authenticated as {}.",
                ObservedAuthorization::from_connection(&ready.info).summary()
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use claw_gateway_client::{ConnectionInfo, ConnectionState, ResyncRequired};
    use claw_protocol::gateway::GATEWAY_PROTOCOL_VERSION;
    use claw_security::authorization::{Role, Scope};

    use super::{
        AttemptRejected, IosAction, IosNetworkInterface, IosNetworkPath, IosNetworkRoute,
        IosSessionModel, IosStatusKind, ObservationResult, ObservedAuthorization,
        TransportDirective, TransportResumeReason, TransportStopReason,
    };
    use crate::endpoint::GatewayEndpoint;
    use crate::host_app::AppRunState;

    fn new_model() -> IosSessionModel {
        let endpoint = GatewayEndpoint::parse("wss://gateway.example:4443")
            .expect("the fixture endpoint is valid");
        IosSessionModel::new(&endpoint)
    }

    fn path(id: u64) -> IosNetworkPath {
        IosNetworkPath::Satisfied(IosNetworkRoute::new(id, IosNetworkInterface::Wifi))
    }

    fn model() -> IosSessionModel {
        let model = new_model();
        assert_eq!(
            model.set_run_state(AppRunState::Foreground),
            TransportDirective::None
        );
        assert_eq!(model.set_network_path(path(1)), TransportDirective::None);
        model
    }

    fn hello(role: &str, scopes: &[&str]) -> ConnectionInfo {
        ConnectionInfo {
            protocol: GATEWAY_PROTOCOL_VERSION,
            server_version: "2026.7.2".to_owned(),
            connection_id: "connection-1".to_owned(),
            role: role.to_owned(),
            scopes: scopes
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>()
                .into(),
            advertised_method_count: 3,
            advertised_event_count: 4,
            max_payload_bytes: 1024,
        }
    }

    #[test]
    fn a_new_model_waits_for_active_lifecycle_and_network_observations() {
        let model = new_model();
        let initial = model.snapshot();

        assert_eq!(initial.run_state(), AppRunState::Inactive);
        assert_eq!(initial.network_path(), IosNetworkPath::Unknown);
        assert_eq!(initial.title(), "App inactive");
        assert!(!initial.can_connect());
        assert!(matches!(
            model.begin_attempt(),
            Err(AttemptRejected::AppNotForeground {
                state: AppRunState::Inactive
            })
        ));

        assert_eq!(
            model.set_run_state(AppRunState::Foreground),
            TransportDirective::None
        );
        assert!(matches!(
            model.begin_attempt(),
            Err(AttemptRejected::NetworkUnavailable {
                path: IosNetworkPath::Unknown
            })
        ));
        assert_eq!(model.snapshot().title(), "Checking the network");
    }

    #[test]
    fn a_fresh_model_reports_no_connection_and_no_authorization() {
        let snapshot = model().snapshot();

        assert_eq!(snapshot.status(), IosStatusKind::Neutral);
        assert_eq!(snapshot.title(), "Not connected");
        assert!(
            snapshot.authorization().is_none(),
            "a fresh model must not report authorization: {snapshot:?}"
        );
        assert!(
            snapshot.can_connect(),
            "a fresh model must offer connect: {snapshot:?}"
        );
        assert!(
            !snapshot.busy(),
            "a fresh model must not be busy: {snapshot:?}"
        );
    }

    #[test]
    fn no_action_is_permitted_without_a_confirmed_authorization() {
        let model = model();
        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe(ConnectionState::Authenticating),
            ObservationResult::Applied { .. }
        ));
        let snapshot = model.snapshot();

        for action in IosAction::ALL {
            assert!(
                !snapshot.permits(action),
                "{action:?} must not be permitted while authenticating: {snapshot:?}"
            );
            let denied = model
                .authorize(action)
                .expect_err("authorize must refuse without a confirmed authorization");

            assert_eq!(denied.action(), action);
            assert_eq!(denied.required_scope(), action.required_scope());
            assert!(
                denied.observed().is_none(),
                "denial must report no observed authorization, got {denied:?}"
            );
        }
    }

    #[test]
    fn the_interface_view_and_the_acting_code_agree_for_every_action_and_state() {
        let cases = [
            (None, "no observation"),
            (Some(hello("operator", &[])), "operator with no scopes"),
            (
                Some(hello("operator", &["operator.read"])),
                "operator with read",
            ),
            (
                Some(hello("operator", &["operator.read", "operator.admin"])),
                "operator with read and admin",
            ),
            (
                Some(hello("operator", &["operator.telepathy"])),
                "operator with an unenforceable scope",
            ),
        ];

        for (info, description) in cases {
            let model = model();
            let attempt = info.map(|info| {
                let attempt = model.begin_attempt().expect("the attempt is admitted");
                assert!(matches!(
                    attempt.observe_authenticated(info),
                    ObservationResult::Applied { .. }
                ));
                attempt
            });
            let snapshot = model.snapshot();

            for action in IosAction::ALL {
                let rendered = snapshot.permits(action);
                let acted = model.authorize(action).is_ok();

                assert_eq!(
                    rendered, acted,
                    "{description}, {action:?}: the interface rendered permits={rendered} while the acting code decided permits={acted}; snapshot was {snapshot:?}"
                );
            }
            drop(attempt);
        }
    }

    #[test]
    fn observed_authorization_grants_only_the_exact_confirmed_scopes() {
        let observed = ObservedAuthorization::from_connection(&hello(
            "operator",
            &["operator.read", "operator.write"],
        ));

        assert_eq!(observed.role(), Some(Role::Operator));
        assert!(
            observed.grants(IosAction::ReadSessions),
            "operator.read must grant reading: {observed:?}"
        );
        assert!(
            observed.grants(IosAction::SendMessage),
            "operator.write must grant sending: {observed:?}"
        );
        assert!(
            !observed.grants(IosAction::Administer),
            "an unheld scope must not grant administration: {observed:?}"
        );
        assert_eq!(
            observed.unrecognized_scopes(),
            &[] as &[String],
            "all fixture scopes are understood: {observed:?}"
        );
    }

    #[test]
    fn an_admin_scope_does_not_silently_imply_narrower_scopes() {
        let observed =
            ObservedAuthorization::from_connection(&hello("operator", &["operator.admin"]));

        assert!(
            observed.grants(IosAction::Administer),
            "operator.admin must grant administration: {observed:?}"
        );
        assert!(
            !observed.grants(IosAction::ReadSessions),
            "operator.admin must not be treated as implying operator.read: {observed:?}"
        );
        assert!(
            observed.scopes().contains(Scope::OperatorAdmin),
            "the confirmed scope set is wrong: {observed:?}"
        );
    }

    #[test]
    fn an_unenforceable_scope_is_surfaced_but_never_grants_anything() {
        let observed =
            ObservedAuthorization::from_connection(&hello("operator", &["operator.telepathy"]));

        assert_eq!(
            observed.unrecognized_scopes(),
            ["operator.telepathy".to_owned()],
            "the unknown scope must be surfaced: {observed:?}"
        );
        for action in IosAction::ALL {
            assert!(
                !observed.grants(action),
                "{action:?} must not be granted by an unenforceable scope: {observed:?}"
            );
        }
        assert!(
            observed.summary().contains("not enforced by this build"),
            "the summary must say the scope is not enforced here, got {:?}",
            observed.summary()
        );
    }

    #[test]
    fn an_unrecognised_role_is_reported_verbatim_rather_than_coerced() {
        let observed = ObservedAuthorization::from_connection(&hello("superuser", &[]));

        assert_eq!(
            observed.role(),
            None,
            "an unknown role must not be coerced: {observed:?}"
        );
        assert_eq!(observed.role_text(), "superuser");
        assert!(
            observed.summary().contains("superuser"),
            "the summary must name the role the server actually sent, got {:?}",
            observed.summary()
        );
    }

    #[test]
    fn an_authenticated_snapshot_reports_the_negotiated_protocol_and_controls() {
        let model = model();
        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe_authenticated(hello("operator", &["operator.read"])),
            ObservationResult::Applied { .. }
        ));
        let snapshot = model.snapshot();

        assert_eq!(snapshot.status(), IosStatusKind::Ready);
        assert_eq!(snapshot.protocol(), Some(GATEWAY_PROTOCOL_VERSION));
        assert_eq!(snapshot.server_version(), Some("2026.7.2"));
        assert!(
            snapshot.can_disconnect() && !snapshot.can_connect(),
            "an authenticated snapshot must offer disconnect only: {snapshot:?}"
        );
        assert!(
            snapshot.permits(IosAction::ReadSessions),
            "the confirmed operator.read scope must permit reading: {snapshot:?}"
        );
    }

    #[test]
    fn a_second_attempt_is_refused_while_the_first_guard_is_held() {
        let model = model();
        let first = model
            .begin_attempt()
            .expect("the first attempt is admitted");
        let second = model.begin_attempt();

        assert!(
            second.is_err(),
            "a second attempt must be refused while attempt {} is in flight",
            first.id()
        );
        drop(first);
        assert!(
            model.begin_attempt().is_ok(),
            "an attempt must be admitted once the previous guard is dropped"
        );
    }

    #[test]
    fn dropping_the_attempt_future_releases_the_guard_and_clears_the_interface() {
        let model = model();
        let owned = model.clone();
        let mut attempt = Box::pin(async move {
            let guard = owned
                .begin_attempt()
                .expect("the first attempt is admitted");
            assert!(matches!(
                guard.observe(ConnectionState::Connecting),
                ObservationResult::Applied { .. }
            ));
            std::future::pending::<()>().await;
        });
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        assert_eq!(
            attempt.as_mut().poll(&mut context),
            Poll::Pending,
            "the fixture future must suspend while holding the guard"
        );

        let during = model.snapshot();
        assert!(
            model.attempt_in_flight(),
            "the guard must still be held while the future is suspended: {during:?}"
        );
        assert!(
            during.busy() && during.can_cancel() && !during.can_connect(),
            "a suspended attempt must render as busy and cancellable: {during:?}"
        );

        // The future is dropped, not driven to completion. On iOS this is what
        // happens when the system suspends the application mid-connect.
        drop(attempt);

        let after = model.snapshot();
        assert!(
            !model.attempt_in_flight(),
            "dropping the future must release the guard: {after:?}"
        );
        assert!(
            !after.busy() && after.can_connect(),
            "dropping the future must return the interface to a connectable state: {after:?}"
        );
        assert_eq!(after.status(), IosStatusKind::Neutral);
        assert!(
            after.detail().contains("abandoned"),
            "an abandoned attempt must say so rather than claim a clean close, got {:?}",
            after.detail()
        );
    }

    #[test]
    fn dropping_an_attempt_does_not_overwrite_a_terminal_observation() {
        let model = model();
        let attempt = model
            .begin_attempt()
            .expect("the first attempt is admitted");
        assert!(matches!(
            attempt.observe(ConnectionState::ReconnectExhausted),
            ObservationResult::Applied { .. }
        ));
        drop(attempt);
        let snapshot = model.snapshot();

        assert_eq!(snapshot.status(), IosStatusKind::Failed);
        assert_eq!(
            snapshot.title(),
            "Gave up reconnecting",
            "a terminal failure must survive the guard drop: {snapshot:?}"
        );
    }

    #[test]
    fn a_stale_guard_does_not_clear_a_newer_attempt() {
        let model = model();
        let first = model
            .begin_attempt()
            .expect("the first attempt is admitted");
        let first_id = first.id();
        drop(first);
        let second = model.begin_attempt().expect("a second attempt is admitted");

        assert_ne!(
            second.id(),
            first_id,
            "each attempt must have its own identity"
        );
        assert!(
            model.attempt_in_flight(),
            "attempt {} must still be in flight",
            second.id()
        );
    }

    #[test]
    fn duplicate_host_and_transport_updates_reuse_the_cached_snapshot() {
        let model = model();
        let first = model.snapshot();

        assert_eq!(model.set_network_path(path(1)), TransportDirective::None);
        let duplicate_path = model.snapshot();
        assert!(
            Arc::ptr_eq(&first, &duplicate_path),
            "a duplicate path update rebuilt revision {} as {}",
            first.revision(),
            duplicate_path.revision()
        );
        assert!(model.snapshot_if_changed(first.revision()).is_none());

        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe(ConnectionState::Connecting),
            ObservationResult::Applied { .. }
        ));
        let connecting = model.snapshot();
        assert_eq!(
            attempt.observe(ConnectionState::Connecting),
            ObservationResult::Unchanged {
                revision: connecting.revision()
            }
        );
        assert!(Arc::ptr_eq(&connecting, &model.snapshot()));
    }

    #[test]
    fn backgrounding_invalidates_callbacks_and_waits_for_shutdown_before_resuming() {
        let model = model();
        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe_authenticated(hello("operator", &["operator.read"])),
            ObservationResult::Applied { .. }
        ));

        assert_eq!(
            model.set_run_state(AppRunState::Background),
            TransportDirective::Stop {
                attempt_id: attempt.id(),
                reason: TransportStopReason::EnteredBackground,
            }
        );
        let background = model.snapshot();
        assert!(background.authorization().is_none());
        assert!(background.transport_active());
        assert_eq!(background.title(), "Paused in background");

        assert_eq!(
            model.set_run_state(AppRunState::Foreground),
            TransportDirective::None,
            "a replacement must wait until the old task has actually stopped"
        );
        let before_stale = model.snapshot();
        assert_eq!(
            attempt.observe_authenticated(hello("operator", &["operator.admin"])),
            ObservationResult::Stale
        );
        assert!(Arc::ptr_eq(&before_stale, &model.snapshot()));

        drop(attempt);
        assert_eq!(
            model.reconcile(),
            TransportDirective::Resume {
                reason: TransportResumeReason::ReturnedToForeground,
            }
        );
        let ready = model.snapshot();
        assert!(ready.should_resume());
        assert_eq!(ready.title(), "Ready to reconnect");
        assert!(!ready.transport_active());

        assert_eq!(model.request_disconnect(), TransportDirective::None);
        assert_eq!(model.reconcile(), TransportDirective::None);
        assert_eq!(model.snapshot().title(), "Disconnected");
    }

    #[test]
    fn transient_inactive_state_keeps_an_authenticated_transport() {
        let model = model();
        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe_authenticated(hello("operator", &["operator.read"])),
            ObservationResult::Applied { .. }
        ));

        assert_eq!(
            model.set_run_state(AppRunState::Inactive),
            TransportDirective::None
        );
        let inactive = model.snapshot();
        assert!(inactive.authorization().is_some());
        assert!(inactive.transport_active());
        assert_eq!(inactive.status(), IosStatusKind::Ready);

        assert_eq!(
            model.set_run_state(AppRunState::Foreground),
            TransportDirective::None
        );
    }

    #[test]
    fn a_changed_route_retires_the_old_socket_before_reconnect() {
        let model = model();
        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe_authenticated(hello("operator", &["operator.read"])),
            ObservationResult::Applied { .. }
        ));
        let cellular = IosNetworkPath::Satisfied(
            IosNetworkRoute::new(2, IosNetworkInterface::Cellular).with_expensive(true),
        );

        assert_eq!(
            model.set_network_path(cellular),
            TransportDirective::Stop {
                attempt_id: attempt.id(),
                reason: TransportStopReason::NetworkChanged,
            }
        );
        let wired = IosNetworkPath::Satisfied(
            IosNetworkRoute::new(3, IosNetworkInterface::WiredEthernet)
                .with_local_network_available(true),
        );
        assert_eq!(
            model.set_network_path(wired),
            TransportDirective::None,
            "a second route change while the first stop drains must not issue a duplicate stop"
        );
        let changed = model.snapshot();
        assert!(changed.authorization().is_none());
        assert_eq!(changed.title(), "Network changed");
        assert_eq!(changed.network_path(), wired);
        assert!(!changed.should_resume());

        drop(attempt);
        assert_eq!(
            model.reconcile(),
            TransportDirective::Resume {
                reason: TransportResumeReason::NetworkChanged,
            }
        );
        assert!(model.snapshot().should_resume());
    }

    #[test]
    fn a_cost_change_on_the_same_route_updates_ui_without_restarting() {
        let model = model();
        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe(ConnectionState::Connecting),
            ObservationResult::Applied { .. }
        ));
        let before = model.snapshot();
        let expensive = IosNetworkPath::Satisfied(
            IosNetworkRoute::new(1, IosNetworkInterface::Wifi).with_expensive(true),
        );

        assert_eq!(model.set_network_path(expensive), TransportDirective::None);
        let after = model.snapshot();
        assert_ne!(after.revision(), before.revision());
        assert!(after.detail().contains("expensive network path"));
        assert!(after.transport_active());
    }

    #[test]
    fn dropping_an_authenticated_task_removes_its_authorization() {
        let model = model();
        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe_authenticated(hello("operator", &["operator.read"])),
            ObservationResult::Applied { .. }
        ));
        assert!(model.snapshot().authorization().is_some());

        drop(attempt);

        let after = model.snapshot();
        assert!(after.authorization().is_none());
        assert_eq!(after.title(), "Not connected");
        assert!(after.can_connect());
    }

    #[test]
    fn user_disconnect_does_not_schedule_an_automatic_resume() {
        let model = model();
        let attempt = model.begin_attempt().expect("the attempt is admitted");
        assert!(matches!(
            attempt.observe_authenticated(hello("operator", &["operator.read"])),
            ObservationResult::Applied { .. }
        ));

        assert_eq!(
            model.request_disconnect(),
            TransportDirective::Stop {
                attempt_id: attempt.id(),
                reason: TransportStopReason::UserRequested,
            }
        );
        assert_eq!(
            attempt.observe(ConnectionState::Connecting),
            ObservationResult::Stale
        );
        assert_eq!(
            model.set_run_state(AppRunState::Background),
            TransportDirective::None,
            "backgrounding while a user-requested stop drains must not turn it into a resumable stop"
        );
        assert_eq!(
            model.set_run_state(AppRunState::Foreground),
            TransportDirective::None
        );
        drop(attempt);

        assert_eq!(model.reconcile(), TransportDirective::None);
        let snapshot = model.snapshot();
        assert_eq!(snapshot.title(), "Disconnected");
        assert!(!snapshot.should_resume());
        assert!(snapshot.can_connect());
    }

    #[test]
    fn a_terminal_failure_is_not_made_resumable_by_a_lifecycle_race() {
        let terminal_states = [
            (ConnectionState::ReconnectExhausted, "Gave up reconnecting"),
            (
                ConnectionState::ResyncRequired(ResyncRequired::EventQueueSaturated),
                "Out of sync",
            ),
            (
                ConnectionState::ProtocolFailed { category: "codec" },
                "Protocol failure",
            ),
        ];

        for (terminal, title) in terminal_states {
            let model = model();
            let attempt = model.begin_attempt().expect("the attempt is admitted");
            assert!(matches!(
                attempt.observe(terminal),
                ObservationResult::Applied { .. }
            ));

            assert_eq!(
                model.set_run_state(AppRunState::Background),
                TransportDirective::Stop {
                    attempt_id: attempt.id(),
                    reason: TransportStopReason::EnteredBackground,
                }
            );
            drop(attempt);
            assert_eq!(
                model.set_run_state(AppRunState::Foreground),
                TransportDirective::None
            );
            assert_eq!(model.reconcile(), TransportDirective::None);

            let snapshot = model.snapshot();
            assert_eq!(snapshot.title(), title);
            assert!(!snapshot.should_resume());
        }
    }

    #[test]
    fn every_constructible_lifecycle_state_renders_text_and_never_a_permission() {
        // AuthenticationFailure has no public or test constructor in
        // claw-gateway-client, so its ConnectionState variant cannot be built
        // from this crate. The match in describe_lifecycle remains exhaustive.
        let states = [
            (ConnectionState::Starting, IosStatusKind::Progress),
            (ConnectionState::Connecting, IosStatusKind::Progress),
            (ConnectionState::Authenticating, IosStatusKind::Progress),
            (
                ConnectionState::Reconnecting {
                    attempt: 1,
                    delay: Duration::from_millis(250),
                },
                IosStatusKind::Progress,
            ),
            (
                ConnectionState::ResyncRequired(ResyncRequired::EventQueueSaturated),
                IosStatusKind::Warning,
            ),
            (ConnectionState::ReconnectExhausted, IosStatusKind::Failed),
            (
                ConnectionState::ProtocolFailed { category: "codec" },
                IosStatusKind::Failed,
            ),
            (ConnectionState::Stopped, IosStatusKind::Neutral),
        ];

        for (state, expected) in states {
            let model = model();
            let attempt = model.begin_attempt().expect("the attempt is admitted");
            let _observation = attempt.observe(state.clone());
            let snapshot = model.snapshot();

            assert_eq!(
                snapshot.status(),
                expected,
                "wrong status for {state:?}: {snapshot:?}"
            );
            assert!(
                !snapshot.title().is_empty() && !snapshot.detail().is_empty(),
                "every state needs renderable text, {state:?} produced {snapshot:?}"
            );
            assert!(
                snapshot.authorization().is_none(),
                "{state:?} is not an authenticated connection and must report no authorization: {snapshot:?}"
            );
            for action in IosAction::ALL {
                assert!(
                    !snapshot.permits(action),
                    "{state:?} must not permit {action:?}: {snapshot:?}"
                );
            }
        }
    }
}

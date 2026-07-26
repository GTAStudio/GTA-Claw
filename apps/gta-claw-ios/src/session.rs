//! Connection lifecycle presented as a snapshot a user interface can bind to.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use claw_gateway_client::{ConnectionInfo, ConnectionState};
use claw_protocol::gateway::ProtocolVersion;
use claw_security::authorization::{Role, Scope, ScopeSet};

use crate::endpoint::{EndpointSummary, GatewayEndpoint};

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

/// An operation a user interface may offer to a person.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IosAction {
    /// Read sessions and history.
    ReadSessions,
    /// Send a message into a session.
    SendMessage,
    /// Resolve a pending approval.
    ResolveApproval,
    /// Approve or revoke a device pairing.
    ManagePairing,
    /// Change Gateway configuration.
    Administer,
}

impl IosAction {
    /// Every action a user interface may offer, in a stable order.
    pub const ALL: [Self; 5] = [
        Self::ReadSessions,
        Self::SendMessage,
        Self::ResolveApproval,
        Self::ManagePairing,
        Self::Administer,
    ];

    /// Returns the single Gateway scope this action requires.
    #[must_use]
    pub const fn required_scope(self) -> Scope {
        match self {
            Self::ReadSessions => Scope::OperatorRead,
            Self::SendMessage => Scope::OperatorWrite,
            Self::ResolveApproval => Scope::OperatorApprovals,
            Self::ManagePairing => Scope::OperatorPairing,
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
            Self::ManagePairing => "manage pairing",
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
/// Scope implication is deliberately not modelled. `operator.admin` does not
/// imply `operator.read` here, because no implication rule exists anywhere in
/// this workspace and inventing one would let the interface promise access the
/// server may refuse.
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
    pub fn grants(&self, action: IosAction) -> bool {
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
pub struct AttemptRejected;

impl Display for AttemptRejected {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("a connection attempt is already in flight")
    }
}

impl Error for AttemptRejected {}

/// What this crate has actually observed about the connection.
///
/// [`ConnectionState::Ready`] carries a [`claw_gateway_client::ConnectionEpoch`]
/// that only the transport client may allocate, so the authenticated case is
/// reduced here to the validated hello summary the interface needs.
#[derive(Clone, Debug)]
enum Observed {
    Lifecycle(ConnectionState),
    Authenticated(ConnectionInfo),
    Abandoned,
}

fn classify(state: ConnectionState) -> Observed {
    match state {
        ConnectionState::Ready(ready) => Observed::Authenticated(ready.info),
        other => Observed::Lifecycle(other),
    }
}

fn is_in_progress(observed: Option<&Observed>) -> bool {
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
    next_attempt: u64,
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
    #[must_use]
    pub fn new(endpoint: &GatewayEndpoint) -> Self {
        Self {
            shared: Arc::new(Shared {
                endpoint: endpoint.summary(),
                state: Mutex::new(SessionState {
                    observed: None,
                    attempt: None,
                    next_attempt: 1,
                }),
            }),
        }
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
    /// Returns [`AttemptRejected`] when an attempt is already in flight.
    pub fn begin_attempt(&self) -> Result<ConnectionAttempt, AttemptRejected> {
        let mut state = self.shared.lock();
        if state.attempt.is_some() {
            return Err(AttemptRejected);
        }
        let id = state.next_attempt;
        state.next_attempt = state.next_attempt.saturating_add(1);
        state.attempt = Some(id);
        drop(state);
        Ok(ConnectionAttempt {
            shared: Arc::clone(&self.shared),
            id,
        })
    }

    /// Records a lifecycle state observed from the transport client.
    pub fn observe(&self, connection: ConnectionState) {
        self.shared.lock().observed = Some(classify(connection));
    }

    /// Returns whether an attempt guard is currently held.
    #[must_use]
    pub fn attempt_in_flight(&self) -> bool {
        self.shared.lock().attempt.is_some()
    }

    /// Returns the current view of the connection.
    #[must_use]
    pub fn snapshot(&self) -> IosViewSnapshot {
        let state = self.shared.lock();
        let attempt_in_flight = state.attempt.is_some();
        let observed = state.observed.clone();
        drop(state);
        IosViewSnapshot::build(
            self.shared.endpoint.clone(),
            observed.as_ref(),
            attempt_in_flight,
        )
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

    #[cfg(test)]
    fn observe_authenticated(&self, info: ConnectionInfo) {
        self.shared.lock().observed = Some(Observed::Authenticated(info));
    }
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
}

impl Drop for ConnectionAttempt {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        if state.attempt != Some(self.id) {
            return;
        }
        state.attempt = None;
        if state.observed.is_none() || is_in_progress(state.observed.as_ref()) {
            state.observed = Some(Observed::Abandoned);
        }
    }
}

/// A complete, redaction-safe view of the connection for one render pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IosViewSnapshot {
    endpoint: EndpointSummary,
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
}

impl IosViewSnapshot {
    fn build(
        endpoint: EndpointSummary,
        observed: Option<&Observed>,
        attempt_in_flight: bool,
    ) -> Self {
        let (status, title, detail) = describe(observed);
        let info = match observed {
            Some(Observed::Authenticated(info)) => Some(info),
            _ => None,
        };
        let busy = attempt_in_flight || status == IosStatusKind::Progress;
        Self {
            endpoint,
            status,
            title,
            detail,
            protocol: info.map(|info| info.protocol),
            server_version: info.map(|info| info.server_version.clone()),
            authorization: info.map(ObservedAuthorization::from_connection),
            busy,
            can_connect: !busy && info.is_none(),
            can_cancel: busy,
            can_disconnect: info.is_some(),
        }
    }

    /// Returns display text for the endpoint that cannot carry a credential.
    #[must_use]
    pub const fn endpoint(&self) -> &EndpointSummary {
        &self.endpoint
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
}

fn describe(observed: Option<&Observed>) -> (IosStatusKind, String, String) {
    let Some(observed) = observed else {
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
        Observed::Lifecycle(state) => describe_lifecycle(state),
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
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use claw_gateway_client::{ConnectionInfo, ConnectionState, ResyncRequired};
    use claw_protocol::gateway::GATEWAY_PROTOCOL_VERSION;
    use claw_security::authorization::{Role, Scope};

    use super::{IosAction, IosSessionModel, IosStatusKind, ObservedAuthorization};
    use crate::endpoint::GatewayEndpoint;

    fn model() -> IosSessionModel {
        let endpoint = GatewayEndpoint::parse("wss://gateway.example:4443")
            .expect("the fixture endpoint is valid");
        IosSessionModel::new(&endpoint)
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
        model.observe(ConnectionState::Authenticating);
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
            if let Some(info) = info {
                model.observe_authenticated(info);
            }
            let snapshot = model.snapshot();

            for action in IosAction::ALL {
                let rendered = snapshot.permits(action);
                let acted = model.authorize(action).is_ok();

                assert_eq!(
                    rendered, acted,
                    "{description}, {action:?}: the interface rendered permits={rendered} while the acting code decided permits={acted}; snapshot was {snapshot:?}"
                );
            }
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
        model.observe_authenticated(hello("operator", &["operator.read"]));
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
            let _guard = owned
                .begin_attempt()
                .expect("the first attempt is admitted");
            owned.observe(ConnectionState::Connecting);
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
        model.observe(ConnectionState::ReconnectExhausted);
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
    fn every_lifecycle_state_renders_text_and_never_a_permission() {
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
            model.observe(state.clone());
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

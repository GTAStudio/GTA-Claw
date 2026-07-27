//! Authorization that is taken once per action and cannot outlive the run.
//!
//! The rule this module enforces is narrow and absolute: **a decision that
//! authorizes a new action must be taken at the moment of that action, against
//! the state that holds at that moment.**
//!
//! It is enforced by three properties working together.
//!
//! - A privileged port takes a [`Grant<T>`] *by value* and the payload can only
//!   be reached through [`Grant::redeem`], which also consumes it. One grant,
//!   one action.
//! - Only [`GrantIssuer::issue`] can build a `Grant`, and it calls
//!   [`AuthorityPort::authorize`] every single time. The port hands back an
//!   [`Authorization`], never a `Grant`, so no implementation of the port can
//!   manufacture a capability that outlives the decision it came from.
//! - Every grant is stamped with the [`RunEpoch`] it was minted in and carries
//!   an [`EpochGate`]. The gate closes the instant the daemon stops running, so
//!   a capability cannot be redeemed during or after teardown even if its
//!   expiry has not been reached.
//!
//! The expiry check reads the clock *at redemption*. This is the specific defect
//! the audits kept finding: comparing an expiry against the timestamp captured
//! when the decision was made always says the decision is fresh.

use std::fmt::{self, Debug, Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use claw_domain::SessionId;

use super::BoxFuture;
use super::clock::{Clock, MonotonicInstant};
use super::id::SubsystemId;
use super::lifecycle::{EpochGate, RunEpoch};
use super::session::{
    Capability, CapabilitySet, CredentialName, ModelName, ProviderName, ToolName,
};

/// Who is asking.
///
/// A principal carries the capabilities it holds *right now*. Ingress
/// subsystems must rebuild it per request rather than caching the one they
/// built at handshake, because the whole point of re-authorizing every action
/// is lost if the inputs are stale.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Principal {
    id: String,
    capabilities: CapabilitySet,
}

impl Principal {
    /// Creates a principal holding `capabilities`.
    #[must_use]
    pub fn new(id: impl Into<String>, capabilities: CapabilitySet) -> Self {
        Self {
            id: id.into(),
            capabilities,
        }
    }

    /// Returns the principal identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the capabilities held at the moment this principal was built.
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }
}

impl Display for Principal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.id)
    }
}

/// The closed set of things the composition will authorize.
///
/// It is closed on purpose. A policy that can be asked about an open-ended
/// string cannot be reviewed, and a new privileged operation should require a
/// deliberate change here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    /// Address an existing session, or create it.
    OpenSession,
    /// Run one turn in an already resolved session.
    SubmitTurn,
    /// Send a request to a model provider.
    CallProvider {
        /// Which provider.
        provider: ProviderName,
        /// Which model.
        model: ModelName,
    },
    /// Run a tool.
    InvokeTool {
        /// Which tool.
        tool: ToolName,
        /// What the tool needs to be allowed to do.
        required: CapabilitySet,
    },
    /// Release a credential from the secret store.
    ReadCredential {
        /// Which credential.
        credential: CredentialName,
    },
    /// Instantiate a plugin component.
    ActivatePlugin {
        /// Which component.
        component: String,
    },
    /// Commit a turn to durable storage.
    RecordTurn,
}

impl Action {
    /// Returns the stable label for this kind of action.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::OpenSession => "open-session",
            Self::SubmitTurn => "submit-turn",
            Self::CallProvider { .. } => "call-provider",
            Self::InvokeTool { .. } => "invoke-tool",
            Self::ReadCredential { .. } => "read-credential",
            Self::ActivatePlugin { .. } => "activate-plugin",
            Self::RecordTurn => "record-turn",
        }
    }

    /// Returns the capabilities this action needs, which is empty for actions
    /// that are not capability-gated.
    #[must_use]
    pub fn required_capabilities(&self) -> CapabilitySet {
        match self {
            Self::InvokeTool { required, .. } => required.clone(),
            Self::CallProvider { .. } => CapabilitySet::from_capabilities([Capability::Network]),
            _ => CapabilitySet::empty(),
        }
    }
}

impl Display for Action {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::CallProvider { provider, model } => {
                write!(formatter, "call-provider {provider}/{model}")
            }
            Self::InvokeTool { tool, .. } => write!(formatter, "invoke-tool {tool}"),
            Self::ReadCredential { credential } => {
                write!(formatter, "read-credential {credential}")
            }
            Self::ActivatePlugin { component } => write!(formatter, "activate-plugin {component}"),
            other => formatter.write_str(other.label()),
        }
    }
}

/// One question put to the authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionRequest {
    subsystem: SubsystemId,
    principal: Principal,
    action: Action,
    session: Option<SessionId>,
}

impl ActionRequest {
    /// Asks whether `principal` may perform `action` inside `subsystem`.
    #[must_use]
    pub const fn new(subsystem: SubsystemId, principal: Principal, action: Action) -> Self {
        Self {
            subsystem,
            principal,
            action,
            session: None,
        }
    }

    /// Names the session the action belongs to.
    #[must_use]
    pub fn in_session(mut self, session: SessionId) -> Self {
        self.session = Some(session);
        self
    }

    /// Returns the subsystem that will perform the action.
    #[must_use]
    pub const fn subsystem(&self) -> &SubsystemId {
        &self.subsystem
    }

    /// Returns the asking principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the action.
    #[must_use]
    pub const fn action(&self) -> &Action {
        &self.action
    }

    /// Returns the session, when the action belongs to one.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionId> {
        self.session.as_ref()
    }
}

/// A policy decision to allow an action.
///
/// This is what an [`AuthorityPort`] returns. It is not itself a capability: the
/// issuer turns it into a [`Grant`], applying its own upper bound on the
/// lifetime so a permissive policy cannot mint something long-lived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authorization {
    ttl: Duration,
    note: Option<String>,
}

impl Authorization {
    /// Allows the action for at most `ttl`.
    #[must_use]
    pub const fn for_duration(ttl: Duration) -> Self {
        Self { ttl, note: None }
    }

    /// Attaches an explanation for audit output.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Returns the requested lifetime.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns the explanation, when one was given.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// Why an action was refused, or why a capability could not be redeemed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Denial {
    /// Policy refused.
    Policy {
        /// What was refused.
        action: String,
        /// The policy's explanation.
        reason: String,
    },
    /// The principal lacks capabilities the action needs.
    MissingCapabilities {
        /// What was refused.
        action: String,
        /// The capabilities that were absent.
        missing: Vec<Capability>,
    },
    /// The capability was redeemed after it expired.
    Expired {
        /// Which capability.
        serial: GrantSerial,
        /// How old it was when redeemed.
        age: Duration,
        /// How long it was valid for.
        ttl: Duration,
    },
    /// The daemon is not running, so nothing can be authorized.
    NotRunning,
    /// The daemon left the run the capability was minted in.
    EpochClosed,
}

impl Display for Denial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy { action, reason } => {
                write!(formatter, "policy refused {action}: {reason}")
            }
            Self::MissingCapabilities { action, missing } => {
                let rendered: Vec<&str> = missing.iter().map(|held| held.label()).collect();
                write!(
                    formatter,
                    "{action} needs capabilities the principal does not hold: {}",
                    rendered.join(",")
                )
            }
            Self::Expired { serial, age, ttl } => write!(
                formatter,
                "{serial} expired: redeemed {}ms after it was minted, {}ms past its lifetime",
                age.as_millis(),
                age.saturating_sub(*ttl).as_millis()
            ),
            Self::NotRunning => {
                formatter.write_str("the daemon is not running, so nothing can be authorized")
            }
            Self::EpochClosed => {
                formatter.write_str("the daemon left the run epoch the grant was minted in")
            }
        }
    }
}

impl std::error::Error for Denial {}

/// The serial number of one capability, unique within one issuer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GrantSerial(u64);

impl GrantSerial {
    /// Returns the serial as a number, counting from one.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Display for GrantSerial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "grant {}", self.0)
    }
}

/// What a capability can safely say about itself in a log line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantReceipt {
    serial: GrantSerial,
    action: String,
    epoch: RunEpoch,
    expires_at: MonotonicInstant,
}

impl GrantReceipt {
    /// Returns the capability's serial.
    #[must_use]
    pub const fn serial(&self) -> GrantSerial {
        self.serial
    }

    /// Returns the rendered action.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Returns the run the capability belongs to.
    #[must_use]
    pub const fn epoch(&self) -> RunEpoch {
        self.epoch
    }

    /// Returns when the capability stops being redeemable.
    #[must_use]
    pub const fn expires_at(&self) -> MonotonicInstant {
        self.expires_at
    }
}

impl Display for GrantReceipt {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} for {} in {} until {}",
            self.serial, self.action, self.epoch, self.expires_at
        )
    }
}

/// Permission to perform exactly one action, carrying what that action needs.
///
/// A grant is deliberately hostile to reuse:
///
/// - it is neither `Clone` nor `Copy`;
/// - the payload is unreachable except through [`Self::redeem`], which takes
///   `self` by value;
/// - redemption re-reads the clock and re-checks the epoch gate.
///
/// A port that accepts a `Grant<T>` therefore cannot be handed the same
/// permission twice, and cannot act on a permission after the daemon has begun
/// shutting down.
#[must_use = "a grant that is never redeemed authorizes nothing"]
pub struct Grant<T> {
    subject: T,
    serial: GrantSerial,
    epoch: RunEpoch,
    action: String,
    ttl: Duration,
    minted_at: MonotonicInstant,
    expires_at: MonotonicInstant,
    gate: EpochGate,
    clock: Arc<dyn Clock>,
}

impl<T> Grant<T> {
    /// Returns what can safely be logged about this capability.
    #[must_use]
    pub fn receipt(&self) -> GrantReceipt {
        GrantReceipt {
            serial: self.serial,
            action: self.action.clone(),
            epoch: self.epoch,
            expires_at: self.expires_at,
        }
    }

    /// Returns the capability's serial.
    #[must_use]
    pub const fn serial(&self) -> GrantSerial {
        self.serial
    }

    /// Consumes the capability and yields what it authorizes.
    ///
    /// The clock is read here, not when the grant was minted, so a capability
    /// that has been sitting in a queue is refused rather than honoured.
    ///
    /// # Errors
    ///
    /// - [`Denial::EpochClosed`] when the daemon has left the run this
    ///   capability belongs to. This is checked first, because a capability from
    ///   a finished run must be refused whether or not it has expired.
    /// - [`Denial::Expired`] when the capability's lifetime has elapsed.
    pub fn redeem(self) -> Result<T, Denial> {
        let now = self.clock.now();

        if self.gate.current() != Some(self.epoch) {
            return Err(Denial::EpochClosed);
        }

        if now > self.expires_at {
            return Err(Denial::Expired {
                serial: self.serial,
                age: now.saturating_since(self.minted_at),
                ttl: self.ttl,
            });
        }

        Ok(self.subject)
    }
}

impl<T> Debug for Grant<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Grant")
            .field("serial", &self.serial)
            .field("action", &self.action)
            .field("epoch", &self.epoch)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Turns policy decisions into single-use capabilities.
///
/// One issuer serves the whole composition, so serials are unique across it and
/// every capability is tied to the same epoch gate.
pub struct GrantIssuer {
    authority: Arc<dyn AuthorityPort>,
    clock: Arc<dyn Clock>,
    gate: EpochGate,
    max_ttl: Duration,
    next_serial: AtomicU64,
}

impl GrantIssuer {
    /// Creates an issuer that will never mint a capability living longer than
    /// `max_ttl`, whatever the authority asks for.
    #[must_use]
    pub fn new(
        authority: Arc<dyn AuthorityPort>,
        clock: Arc<dyn Clock>,
        gate: EpochGate,
        max_ttl: Duration,
    ) -> Self {
        Self {
            authority,
            clock,
            gate,
            max_ttl,
            next_serial: AtomicU64::new(1),
        }
    }

    /// Returns the ceiling applied to every capability's lifetime.
    #[must_use]
    pub const fn max_ttl(&self) -> Duration {
        self.max_ttl
    }

    /// Asks the authority about `request` and, if allowed, mints a capability
    /// carrying `subject`.
    ///
    /// The epoch is captured before the authority is consulted and re-checked
    /// afterwards. Without the second check, a drain that began while the policy
    /// was being evaluated would still produce a live capability.
    ///
    /// # Errors
    ///
    /// - [`Denial::NotRunning`] when the daemon is not serving.
    /// - Whatever the authority returned, unchanged.
    /// - [`Denial::EpochClosed`] when the daemon stopped serving while the
    ///   authority was deciding.
    pub async fn issue<T>(&self, request: &ActionRequest, subject: T) -> Result<Grant<T>, Denial> {
        let epoch = self.gate.current().ok_or(Denial::NotRunning)?;
        let minted_at = self.clock.now();
        let authorization = self.authority.authorize(request, minted_at).await?;

        if self.gate.current() != Some(epoch) {
            return Err(Denial::EpochClosed);
        }

        let ttl = authorization.ttl().min(self.max_ttl);
        let expires_at = minted_at
            .checked_add(ttl)
            .unwrap_or(MonotonicInstant::from_origin(Duration::MAX));

        Ok(Grant {
            subject,
            serial: GrantSerial(self.next_serial.fetch_add(1, Ordering::SeqCst)),
            epoch,
            action: request.action().to_string(),
            ttl,
            minted_at,
            expires_at,
            gate: self.gate.clone(),
            clock: Arc::clone(&self.clock),
        })
    }
}

impl Debug for GrantIssuer {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrantIssuer")
            .field("max_ttl", &self.max_ttl)
            .field("epoch", &self.gate.current())
            .finish_non_exhaustive()
    }
}

/// Decides whether an action may proceed.
///
/// Implementations must evaluate against current state on every call. They must
/// not memoise a decision for a principal, a session or a connection: the
/// composition calls this once per action precisely so that a change of policy
/// takes effect on the very next action.
pub trait AuthorityPort: Send + Sync + 'static {
    /// Decides `request` as of `now`.
    ///
    /// # Errors
    ///
    /// Returns the [`Denial`] describing why the action is refused.
    fn authorize<'a>(
        &'a self,
        request: &'a ActionRequest,
        now: MonotonicInstant,
    ) -> BoxFuture<'a, Result<Authorization, Denial>>;
}

/// An authority that allows anything the principal already holds the
/// capabilities for.
///
/// This is the reference implementation of the capability half of the rule, and
/// the one the daemon uses unless a richer policy is supplied. It is stateless,
/// so it cannot go stale.
#[derive(Clone, Copy, Debug)]
pub struct CapabilityAuthority {
    ttl: Duration,
}

impl CapabilityAuthority {
    /// Creates an authority that grants `ttl` to every allowed action.
    #[must_use]
    pub const fn new(ttl: Duration) -> Self {
        Self { ttl }
    }
}

impl AuthorityPort for CapabilityAuthority {
    fn authorize<'a>(
        &'a self,
        request: &'a ActionRequest,
        _now: MonotonicInstant,
    ) -> BoxFuture<'a, Result<Authorization, Denial>> {
        Box::pin(async move {
            let required = request.action().required_capabilities();
            let missing = required.missing_from(request.principal().capabilities());

            if missing.is_empty() {
                Ok(Authorization::for_duration(self.ttl))
            } else {
                Err(Denial::MissingCapabilities {
                    action: request.action().to_string(),
                    missing,
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{
        Action, ActionRequest, AuthorityPort, Authorization, BoxFuture, CapabilityAuthority,
        Denial, GrantIssuer, GrantSerial, MonotonicInstant, Principal,
    };
    use crate::composition::clock::Clock;
    use crate::composition::id::SubsystemId;
    use crate::composition::lifecycle::{EpochGate, Lifecycle, LifecyclePhase};
    use crate::composition::session::{
        Capability, CapabilitySet, ModelName, ProviderName, ToolName,
    };

    /// A clock whose reading is set by the test, one millisecond at a time.
    #[derive(Debug, Default)]
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn set(&self, millis: u64) {
            self.0.store(millis, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> MonotonicInstant {
            MonotonicInstant::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    /// Records how many decisions it was asked for, and answers from a switch
    /// the test can flip between actions.
    #[derive(Debug)]
    struct SwitchableAuthority {
        allow: Mutex<bool>,
        ttl: Duration,
        calls: AtomicU64,
    }

    impl SwitchableAuthority {
        fn new(ttl: Duration) -> Self {
            Self {
                allow: Mutex::new(true),
                ttl,
                calls: AtomicU64::new(0),
            }
        }

        fn deny_from_now_on(&self) {
            *self.allow.lock().expect("uncontended") = false;
        }

        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl AuthorityPort for SwitchableAuthority {
        fn authorize<'a>(
            &'a self,
            request: &'a ActionRequest,
            _now: MonotonicInstant,
        ) -> BoxFuture<'a, Result<Authorization, Denial>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let allowed = *self.allow.lock().expect("uncontended");

            Box::pin(async move {
                if allowed {
                    Ok(Authorization::for_duration(self.ttl).with_note("switch is on"))
                } else {
                    Err(Denial::Policy {
                        action: request.action().to_string(),
                        reason: "the switch was turned off".to_owned(),
                    })
                }
            })
        }
    }

    /// Drains the daemon from inside the decision, modelling a shutdown that
    /// begins while a policy evaluation is in flight.
    struct DrainingAuthority {
        lifecycle: Arc<Mutex<Lifecycle>>,
    }

    impl AuthorityPort for DrainingAuthority {
        fn authorize<'a>(
            &'a self,
            _request: &'a ActionRequest,
            _now: MonotonicInstant,
        ) -> BoxFuture<'a, Result<Authorization, Denial>> {
            Box::pin(async move {
                self.lifecycle
                    .lock()
                    .expect("uncontended")
                    .transition_to(LifecyclePhase::Draining)
                    .expect("running may drain");

                Ok(Authorization::for_duration(Duration::from_mins(1)))
            })
        }
    }

    fn running_lifecycle() -> Lifecycle {
        let mut lifecycle = Lifecycle::new();

        for phase in [
            LifecyclePhase::Initializing,
            LifecyclePhase::Initialized,
            LifecyclePhase::Starting,
            LifecyclePhase::Running,
        ] {
            lifecycle.transition_to(phase).expect("legal transition");
        }

        lifecycle
    }

    fn principal(capabilities: CapabilitySet) -> Principal {
        Principal::new("operator-1", capabilities)
    }

    fn request(action: Action, capabilities: CapabilitySet) -> ActionRequest {
        ActionRequest::new(
            SubsystemId::new("engine").expect("valid"),
            principal(capabilities),
            action,
        )
    }

    fn submit_turn() -> ActionRequest {
        request(Action::SubmitTurn, CapabilitySet::all())
    }

    #[tokio::test]
    async fn every_action_costs_one_fresh_decision() {
        let lifecycle = running_lifecycle();
        let authority = Arc::new(SwitchableAuthority::new(Duration::from_secs(10)));
        let issuer = GrantIssuer::new(
            Arc::clone(&authority) as Arc<dyn AuthorityPort>,
            Arc::new(ManualClock::default()),
            lifecycle.epoch_gate(),
            Duration::from_secs(30),
        );

        for expected in 1..=3 {
            let grant = issuer
                .issue(&submit_turn(), expected)
                .await
                .expect("allowed");
            assert_eq!(grant.redeem().expect("valid"), expected);
            assert_eq!(authority.calls(), expected);
        }
    }

    #[tokio::test]
    async fn a_policy_change_takes_effect_on_the_very_next_action() {
        let lifecycle = running_lifecycle();
        let authority = Arc::new(SwitchableAuthority::new(Duration::from_secs(10)));
        let issuer = GrantIssuer::new(
            Arc::clone(&authority) as Arc<dyn AuthorityPort>,
            Arc::new(ManualClock::default()),
            lifecycle.epoch_gate(),
            Duration::from_secs(30),
        );

        let first = issuer
            .issue(&submit_turn(), "first")
            .await
            .expect("allowed");
        assert_eq!(first.redeem().expect("still valid"), "first");

        authority.deny_from_now_on();

        let denial = issuer
            .issue(&submit_turn(), "second")
            .await
            .expect_err("the same principal is now refused");

        assert_eq!(
            denial,
            Denial::Policy {
                action: "submit-turn".to_owned(),
                reason: "the switch was turned off".to_owned(),
            }
        );
        assert_eq!(authority.calls(), 2);
    }

    #[tokio::test]
    async fn a_capability_expires_against_the_clock_read_when_it_is_redeemed() {
        let lifecycle = running_lifecycle();
        let clock = Arc::new(ManualClock::default());
        let issuer = GrantIssuer::new(
            Arc::new(SwitchableAuthority::new(Duration::from_millis(500))),
            Arc::clone(&clock) as Arc<dyn Clock>,
            lifecycle.epoch_gate(),
            Duration::from_secs(30),
        );

        let grant = issuer
            .issue(&submit_turn(), "payload")
            .await
            .expect("allowed");
        assert_eq!(
            grant.receipt().expires_at(),
            MonotonicInstant::from_millis(500)
        );

        clock.set(500);
        let still_valid = issuer
            .issue(&submit_turn(), "other")
            .await
            .expect("allowed");
        assert_eq!(
            still_valid.redeem().expect("exactly at expiry is valid"),
            "other"
        );

        clock.set(501);
        let denial = grant.redeem().expect_err("one millisecond late is refused");

        assert_eq!(
            denial,
            Denial::Expired {
                serial: GrantSerial(1),
                age: Duration::from_millis(501),
                ttl: Duration::from_millis(500),
            }
        );
    }

    #[tokio::test]
    async fn the_issuer_caps_a_lifetime_the_policy_asked_to_exceed() {
        let lifecycle = running_lifecycle();
        let clock = Arc::new(ManualClock::default());
        let issuer = GrantIssuer::new(
            Arc::new(SwitchableAuthority::new(Duration::from_hours(1))),
            Arc::clone(&clock) as Arc<dyn Clock>,
            lifecycle.epoch_gate(),
            Duration::from_millis(250),
        );

        let grant = issuer.issue(&submit_turn(), ()).await.expect("allowed");

        assert_eq!(issuer.max_ttl(), Duration::from_millis(250));
        assert_eq!(
            grant.receipt().expires_at(),
            MonotonicInstant::from_millis(250)
        );

        clock.set(251);
        assert!(matches!(
            grant.redeem().expect_err("capped lifetime is enforced"),
            Denial::Expired { .. }
        ));
    }

    #[tokio::test]
    async fn a_capability_dies_the_moment_the_daemon_starts_draining() {
        let mut lifecycle = running_lifecycle();
        let clock = Arc::new(ManualClock::default());
        let issuer = GrantIssuer::new(
            Arc::new(SwitchableAuthority::new(Duration::from_hours(1))),
            Arc::clone(&clock) as Arc<dyn Clock>,
            lifecycle.epoch_gate(),
            Duration::from_hours(1),
        );

        let grant = issuer
            .issue(&submit_turn(), "installed early")
            .await
            .expect("allowed");
        assert_eq!(
            grant.receipt().epoch(),
            lifecycle.active_epoch().expect("the daemon is running")
        );

        lifecycle
            .transition_to(LifecyclePhase::Draining)
            .expect("running may drain");

        assert_eq!(
            grant
                .redeem()
                .expect_err("teardown invalidates capabilities"),
            Denial::EpochClosed
        );
    }

    #[tokio::test]
    async fn nothing_can_be_authorized_before_the_daemon_is_running() {
        let issuer = GrantIssuer::new(
            Arc::new(SwitchableAuthority::new(Duration::from_secs(10))),
            Arc::new(ManualClock::default()),
            EpochGate::closed(),
            Duration::from_secs(30),
        );

        assert_eq!(
            issuer
                .issue(&submit_turn(), ())
                .await
                .expect_err("the gate is shut"),
            Denial::NotRunning
        );
    }

    #[tokio::test]
    async fn a_drain_that_begins_during_a_decision_invalidates_that_decision() {
        let lifecycle = Arc::new(Mutex::new(running_lifecycle()));
        let gate = lifecycle.lock().expect("uncontended").epoch_gate();
        let issuer = GrantIssuer::new(
            Arc::new(DrainingAuthority {
                lifecycle: Arc::clone(&lifecycle),
            }),
            Arc::new(ManualClock::default()),
            gate,
            Duration::from_secs(30),
        );

        let denial = issuer
            .issue(&submit_turn(), ())
            .await
            .expect_err("a decision taken across a drain is void");

        assert_eq!(denial, Denial::EpochClosed);
    }

    #[tokio::test]
    async fn serials_are_unique_and_increase() {
        let lifecycle = running_lifecycle();
        let issuer = GrantIssuer::new(
            Arc::new(SwitchableAuthority::new(Duration::from_secs(10))),
            Arc::new(ManualClock::default()),
            lifecycle.epoch_gate(),
            Duration::from_secs(30),
        );

        let first = issuer.issue(&submit_turn(), ()).await.expect("allowed");
        let second = issuer.issue(&submit_turn(), ()).await.expect("allowed");

        assert_eq!(first.serial().get(), 1);
        assert_eq!(second.serial().get(), 2);
        assert_eq!(first.receipt().serial(), first.serial());
        assert_eq!(
            second.receipt().to_string(),
            "grant 2 for submit-turn in epoch 1 until +10000ms"
        );
    }

    #[tokio::test]
    async fn the_capability_authority_refuses_a_tool_the_principal_cannot_run() {
        let lifecycle = running_lifecycle();
        let issuer = GrantIssuer::new(
            Arc::new(CapabilityAuthority::new(Duration::from_secs(10))),
            Arc::new(ManualClock::default()),
            lifecycle.epoch_gate(),
            Duration::from_secs(30),
        );
        let action = Action::InvokeTool {
            tool: ToolName::new("write-file").expect("valid"),
            required: CapabilitySet::from_capabilities([
                Capability::WriteWorkspace,
                Capability::SpawnProcess,
            ]),
        };

        let denial = issuer
            .issue(
                &request(
                    action,
                    CapabilitySet::from_capabilities([Capability::ReadWorkspace]),
                ),
                (),
            )
            .await
            .expect_err("missing capabilities are refused");

        assert_eq!(
            denial,
            Denial::MissingCapabilities {
                action: "invoke-tool write-file".to_owned(),
                missing: vec![Capability::WriteWorkspace, Capability::SpawnProcess],
            }
        );
        assert_eq!(
            denial.to_string(),
            "invoke-tool write-file needs capabilities the principal does not hold: write-workspace,spawn-process"
        );
    }

    #[tokio::test]
    async fn the_capability_authority_allows_a_tool_the_principal_can_run() {
        let lifecycle = running_lifecycle();
        let issuer = GrantIssuer::new(
            Arc::new(CapabilityAuthority::new(Duration::from_secs(10))),
            Arc::new(ManualClock::default()),
            lifecycle.epoch_gate(),
            Duration::from_secs(30),
        );
        let action = Action::InvokeTool {
            tool: ToolName::new("read-file").expect("valid"),
            required: CapabilitySet::from_capabilities([Capability::ReadWorkspace]),
        };

        let grant = issuer
            .issue(
                &request(
                    action,
                    CapabilitySet::from_capabilities([
                        Capability::ReadWorkspace,
                        Capability::Network,
                    ]),
                ),
                "allowed",
            )
            .await
            .expect("held capabilities permit the tool");

        assert_eq!(grant.redeem().expect("valid"), "allowed");
    }

    #[tokio::test]
    async fn calling_a_provider_requires_the_network_capability() {
        let lifecycle = running_lifecycle();
        let issuer = GrantIssuer::new(
            Arc::new(CapabilityAuthority::new(Duration::from_secs(10))),
            Arc::new(ManualClock::default()),
            lifecycle.epoch_gate(),
            Duration::from_secs(30),
        );
        let action = Action::CallProvider {
            provider: ProviderName::new("openai").expect("valid"),
            model: ModelName::new("gpt-5").expect("valid"),
        };

        let denial = issuer
            .issue(
                &request(
                    action,
                    CapabilitySet::from_capabilities([Capability::ReadWorkspace]),
                ),
                (),
            )
            .await
            .expect_err("network is required");

        assert_eq!(
            denial,
            Denial::MissingCapabilities {
                action: "call-provider openai/gpt-5".to_owned(),
                missing: vec![Capability::Network],
            }
        );
    }

    #[test]
    fn action_labels_and_rendered_forms_are_pinned() {
        let tool = ToolName::new("read-file").expect("valid");
        let actions = [
            (Action::OpenSession, "open-session", "open-session"),
            (Action::SubmitTurn, "submit-turn", "submit-turn"),
            (Action::RecordTurn, "record-turn", "record-turn"),
            (
                Action::InvokeTool {
                    tool,
                    required: CapabilitySet::empty(),
                },
                "invoke-tool",
                "invoke-tool read-file",
            ),
            (
                Action::ActivatePlugin {
                    component: "formatter".to_owned(),
                },
                "activate-plugin",
                "activate-plugin formatter",
            ),
        ];

        for (action, label, rendered) in actions {
            assert_eq!(action.label(), label);
            assert_eq!(action.to_string(), rendered);
        }
    }

    #[test]
    fn a_request_carries_the_session_it_was_scoped_to() {
        let session = claw_domain::SessionId::new("session-9").expect("valid");
        let scoped = submit_turn().in_session(session.clone());

        assert_eq!(scoped.session(), Some(&session));
        assert_eq!(submit_turn().session(), None);
        assert_eq!(scoped.subsystem().as_str(), "engine");
        assert_eq!(scoped.principal().id(), "operator-1");
    }

    #[test]
    fn an_authorization_carries_its_lifetime_and_note() {
        let authorization =
            Authorization::for_duration(Duration::from_secs(2)).with_note("operator override");

        assert_eq!(authorization.ttl(), Duration::from_secs(2));
        assert_eq!(authorization.note(), Some("operator override"));
        assert_eq!(
            Authorization::for_duration(Duration::from_secs(2)).note(),
            None
        );
    }

    #[test]
    fn denial_text_is_pinned() {
        assert_eq!(
            Denial::NotRunning.to_string(),
            "the daemon is not running, so nothing can be authorized"
        );
        assert_eq!(
            Denial::EpochClosed.to_string(),
            "the daemon left the run epoch the grant was minted in"
        );
        assert_eq!(
            Denial::Policy {
                action: "submit-turn".to_owned(),
                reason: "quota exhausted".to_owned(),
            }
            .to_string(),
            "policy refused submit-turn: quota exhausted"
        );
    }
}

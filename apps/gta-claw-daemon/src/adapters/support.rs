//! Clock, DNS, configuration, observability and policy stand-ins.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use claw_application::composition::{
    ActionRequest, AuthorityPort, Authorization, BoxFuture, Clock, ConfigPort, Denial, DnsPort,
    MonotonicInstant, ObservabilityPort, ObservedEvent, RuntimeSettings, Severity, SubsystemError,
    SubsystemId, well_known,
};

/// A clock the test drives by hand, in whole milliseconds.
///
/// Every expiry check in the composition reads the clock at the moment of the
/// check, so moving this forward is enough to make a capability expire without
/// any sleeping.
#[derive(Debug, Default)]
pub struct SteppedClock(AtomicU64);

impl SteppedClock {
    /// Creates a clock reading zero.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Moves the clock forward by `millis`.
    pub fn advance(&self, millis: u64) {
        self.0.fetch_add(millis, Ordering::SeqCst);
    }

    /// Returns the current reading in milliseconds.
    #[must_use]
    pub fn millis(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl Clock for SteppedClock {
    fn now(&self) -> MonotonicInstant {
        MonotonicInstant::from_millis(self.0.load(Ordering::SeqCst))
    }
}

/// A resolver backed by a fixed table.
///
/// The answers can be replaced, which is what the rebinding regression test
/// needs: it changes the table between two lookups and shows that a destination
/// already resolved does not move.
#[derive(Debug, Default)]
pub struct TableDns(RwLock<BTreeMap<String, Vec<IpAddr>>>);

impl TableDns {
    /// Creates a resolver with the given entries.
    #[must_use]
    pub fn new(entries: impl IntoIterator<Item = (String, Vec<IpAddr>)>) -> Self {
        Self(RwLock::new(entries.into_iter().collect()))
    }

    /// Replaces the answer for `host`.
    pub fn set(&self, host: &str, addresses: Vec<IpAddr>) {
        self.0
            .write()
            .expect("uncontended")
            .insert(host.to_owned(), addresses);
    }
}

impl DnsPort for TableDns {
    fn lookup<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, SubsystemError>> {
        Box::pin(async move {
            self.0
                .read()
                .expect("uncontended")
                .get(host)
                .cloned()
                .ok_or_else(|| {
                    SubsystemError::not_found(well_known::egress(), format!("no answer for {host}"))
                })
        })
    }
}

/// Settings that can be replaced while the daemon runs.
///
/// [`ConfigPort::settings`] is read once per turn, so replacing the settings
/// here changes the very next turn rather than requiring a restart. The
/// generation counter lets a caller notice that a value it captured is stale.
#[derive(Debug)]
pub struct MutableConfig {
    settings: RwLock<RuntimeSettings>,
    generation: AtomicU64,
}

impl MutableConfig {
    /// Creates a configuration port serving `settings`.
    #[must_use]
    pub fn new(settings: RuntimeSettings) -> Self {
        Self {
            settings: RwLock::new(settings),
            generation: AtomicU64::new(0),
        }
    }

    /// Replaces the settings and bumps the generation.
    pub fn replace(&self, settings: RuntimeSettings) {
        *self.settings.write().expect("uncontended") = settings;
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

impl ConfigPort for MutableConfig {
    fn settings(&self) -> BoxFuture<'_, Result<RuntimeSettings, SubsystemError>> {
        Box::pin(async move { Ok(self.settings.read().expect("uncontended").clone()) })
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
}

/// Keeps the most recent events in memory and counts the ones it had to drop.
#[derive(Debug)]
pub struct MemoryObservability {
    capacity: usize,
    events: Mutex<VecDeque<ObservedEvent>>,
    dropped: AtomicU64,
}

impl MemoryObservability {
    /// Creates a sink holding at most `capacity` events.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            events: Mutex::new(VecDeque::with_capacity(capacity)),
            dropped: AtomicU64::new(0),
        }
    }

    /// Returns every event still held, oldest first.
    #[must_use]
    pub fn events(&self) -> Vec<ObservedEvent> {
        self.events
            .lock()
            .expect("uncontended")
            .iter()
            .cloned()
            .collect()
    }

    /// Returns how many events of `severity` are held.
    #[must_use]
    pub fn count_at(&self, severity: Severity) -> usize {
        self.events
            .lock()
            .expect("uncontended")
            .iter()
            .filter(|event| event.severity() == severity)
            .count()
    }
}

impl Default for MemoryObservability {
    fn default() -> Self {
        Self::new(1_024)
    }
}

impl ObservabilityPort for MemoryObservability {
    fn record(&self, event: ObservedEvent) {
        let mut events = self.events.lock().expect("uncontended");

        if events.len() == self.capacity {
            events.pop_front();
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }

        events.push_back(event);
    }

    fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }
}

/// What the policy currently says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyStance {
    /// Every action the principal holds capabilities for is allowed.
    Permit,
    /// Every action is refused.
    RefuseEverything,
    /// Tool invocations are refused; everything else is allowed.
    RefuseTools,
}

/// An authority whose answer can be changed at any moment.
///
/// This exists to make the composition's central rule observable: the
/// composition consults the authority once per action, so flipping the stance
/// between two actions of the same turn changes the second one. An
/// implementation that cached its first answer would pass every other test and
/// fail this one.
#[derive(Debug)]
pub struct LivePolicy {
    stance: RwLock<PolicyStance>,
    ttl: RwLock<Duration>,
    decisions: AtomicU64,
    pending: RwLock<Option<(u64, PolicyStance)>>,
}

impl LivePolicy {
    /// Creates a permissive policy granting `ttl` per action.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            stance: RwLock::new(PolicyStance::Permit),
            ttl: RwLock::new(ttl),
            decisions: AtomicU64::new(0),
            pending: RwLock::new(None),
        }
    }

    /// Changes what the policy says from the next decision onwards.
    pub fn set_stance(&self, stance: PolicyStance) {
        *self.stance.write().expect("uncontended") = stance;
    }

    /// Arranges for the stance to change once `decision` decisions have been
    /// taken, so a test can place the change at an exact point in a turn
    /// without racing it.
    ///
    /// The change takes effect *after* the numbered decision, which is what
    /// makes the assertion meaningful: the decision before it succeeds and the
    /// one after it is refused.
    pub fn change_stance_after(&self, decision: u64, stance: PolicyStance) {
        *self.pending.write().expect("uncontended") = Some((decision, stance));
    }

    /// Changes the lifetime granted from the next decision onwards.
    pub fn set_ttl(&self, ttl: Duration) {
        *self.ttl.write().expect("uncontended") = ttl;
    }

    /// Returns how many decisions have been asked for.
    #[must_use]
    pub fn decisions(&self) -> u64 {
        self.decisions.load(Ordering::SeqCst)
    }
}

impl AuthorityPort for LivePolicy {
    fn authorize<'a>(
        &'a self,
        request: &'a ActionRequest,
        _now: MonotonicInstant,
    ) -> BoxFuture<'a, Result<Authorization, Denial>> {
        self.decisions.fetch_add(1, Ordering::SeqCst);

        let stance = *self.stance.read().expect("uncontended");
        let ttl = *self.ttl.read().expect("uncontended");

        // Applied after this decision has already read the stance, so the
        // numbered decision succeeds and the following one sees the change.
        let taken = self.decisions.load(Ordering::SeqCst);
        let mut pending = self.pending.write().expect("uncontended");
        if let Some((at, next)) = *pending
            && taken >= at
        {
            *self.stance.write().expect("uncontended") = next;
            *pending = None;
        }
        drop(pending);

        Box::pin(async move {
            let action = request.action();
            let missing = action
                .required_capabilities()
                .missing_from(request.principal().capabilities());

            if !missing.is_empty() {
                return Err(Denial::MissingCapabilities {
                    action: action.to_string(),
                    missing,
                });
            }

            let refused = match stance {
                PolicyStance::Permit => false,
                PolicyStance::RefuseEverything => true,
                PolicyStance::RefuseTools => {
                    matches!(
                        action,
                        claw_application::composition::Action::InvokeTool { .. }
                    )
                }
            };

            if refused {
                return Err(Denial::Policy {
                    action: action.to_string(),
                    reason: "the operator withdrew this permission".to_owned(),
                });
            }

            Ok(Authorization::for_duration(ttl))
        })
    }
}

/// Builds an observed event for the daemon's own reporting.
#[must_use]
pub fn note(
    subsystem: SubsystemId,
    severity: Severity,
    message: String,
    at: MonotonicInstant,
) -> ObservedEvent {
    ObservedEvent::new(subsystem, severity, message, at)
}

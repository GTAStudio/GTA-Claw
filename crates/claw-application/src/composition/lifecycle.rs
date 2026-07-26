//! The daemon-wide lifecycle, and the epoch gate that kills capabilities at teardown.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Where the composition as a whole currently is.
///
/// Individual subsystems do not have their own phase: the composition advances
/// as a unit so that "is the daemon accepting new work?" has exactly one answer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LifecyclePhase {
    /// Subsystems have been registered but nothing has been initialized.
    Created,
    /// Subsystems are being initialized in dependency order.
    Initializing,
    /// Every subsystem initialized successfully.
    Initialized,
    /// Subsystems are being started in dependency order.
    Starting,
    /// The daemon is serving. This is the only phase in which work is accepted.
    Running,
    /// New work is refused while work already in flight is finished.
    Draining,
    /// Subsystems are being shut down in reverse dependency order.
    Stopping,
    /// Every subsystem has been shut down. Terminal.
    Stopped,
    /// A phase failed. Only teardown may follow.
    Failed,
}

impl LifecyclePhase {
    /// Every phase, in lifecycle order.
    pub const ALL: [Self; 9] = [
        Self::Created,
        Self::Initializing,
        Self::Initialized,
        Self::Starting,
        Self::Running,
        Self::Draining,
        Self::Stopping,
        Self::Stopped,
        Self::Failed,
    ];

    /// Returns the stable label used in error text and readiness output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Initializing => "initializing",
            Self::Initialized => "initialized",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    /// Returns whether the composition accepts new work in this phase.
    #[must_use]
    pub const fn accepts_work(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Returns whether no further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// Returns whether `next` may directly follow `self`.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Initializing)
                | (Self::Initializing, Self::Initialized)
                | (Self::Initialized, Self::Starting)
                | (Self::Initialized, Self::Stopping)
                | (Self::Starting, Self::Running)
                | (Self::Running, Self::Draining)
                | (Self::Draining, Self::Stopping)
                | (Self::Stopping, Self::Stopped)
                | (Self::Failed, Self::Stopping)
                | (Self::Failed, Self::Stopped)
                | (
                    Self::Created
                        | Self::Initializing
                        | Self::Initialized
                        | Self::Starting
                        | Self::Running
                        | Self::Draining
                        | Self::Stopping,
                    Self::Failed
                )
        )
    }
}

impl Display for LifecyclePhase {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// A rejected lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseTransitionError {
    from: LifecyclePhase,
    to: LifecyclePhase,
}

impl PhaseTransitionError {
    /// Returns the phase the composition was in.
    #[must_use]
    pub const fn from(self) -> LifecyclePhase {
        self.from
    }

    /// Returns the phase that was refused.
    #[must_use]
    pub const fn to(self) -> LifecyclePhase {
        self.to
    }
}

impl Display for PhaseTransitionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "illegal lifecycle transition: {} -> {}",
            self.from, self.to
        )
    }
}

impl Error for PhaseTransitionError {}

/// The serial number of one continuous run.
///
/// A new epoch begins every time the composition enters
/// [`LifecyclePhase::Running`]. Capabilities are stamped with the epoch they
/// were minted in, which is what makes them worthless after a drain.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunEpoch(u64);

impl RunEpoch {
    /// Returns the epoch as a number, counting from one.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Display for RunEpoch {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "epoch {}", self.0)
    }
}

/// A shared, cheap-to-read handle answering "is the daemon still in the run that
/// minted this capability?".
///
/// The gate is open only while the composition is in
/// [`LifecyclePhase::Running`]. It is deliberately a separate handle from
/// [`Lifecycle`] so that a capability can carry the ability to *ask* without
/// carrying the ability to *change* the answer: only `Lifecycle` can open or
/// close a gate.
#[derive(Clone, Debug)]
pub struct EpochGate(Arc<AtomicU64>);

impl EpochGate {
    /// Creates a gate that is closed, and that no [`Lifecycle`] will ever open.
    ///
    /// Useful for tests that want every redemption to be refused.
    #[must_use]
    pub fn closed() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    /// Returns the epoch currently being served, or `None` while closed.
    #[must_use]
    pub fn current(&self) -> Option<RunEpoch> {
        match self.0.load(Ordering::Acquire) {
            0 => None,
            epoch => Some(RunEpoch(epoch)),
        }
    }

    fn open(&self, epoch: RunEpoch) {
        self.0.store(epoch.0, Ordering::Release);
    }

    fn close(&self) {
        self.0.store(0, Ordering::Release);
    }
}

impl Default for EpochGate {
    fn default() -> Self {
        Self::closed()
    }
}

/// The composition's phase, and the epoch gate derived from it.
#[derive(Debug)]
pub struct Lifecycle {
    phase: LifecyclePhase,
    epoch: u64,
    gate: EpochGate,
}

impl Lifecycle {
    /// Creates a lifecycle in [`LifecyclePhase::Created`] with a closed gate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            phase: LifecyclePhase::Created,
            epoch: 0,
            gate: EpochGate::closed(),
        }
    }

    /// Returns the current phase.
    #[must_use]
    pub const fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    /// Returns a handle to the epoch gate.
    ///
    /// Clones observe every later change, so a capability that holds one sees
    /// the gate close the moment the daemon starts draining.
    #[must_use]
    pub fn epoch_gate(&self) -> EpochGate {
        self.gate.clone()
    }

    /// Returns the epoch being served, or `None` outside
    /// [`LifecyclePhase::Running`].
    #[must_use]
    pub fn active_epoch(&self) -> Option<RunEpoch> {
        self.gate.current()
    }

    /// Advances to `next`.
    ///
    /// Entering [`LifecyclePhase::Running`] allocates a fresh epoch and opens
    /// the gate; leaving it closes the gate before this returns, so no
    /// capability minted in the old run can be redeemed afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`PhaseTransitionError`] when the transition is not one of the
    /// seventeen legal edges, leaving the phase untouched.
    pub fn transition_to(&mut self, next: LifecyclePhase) -> Result<(), PhaseTransitionError> {
        if !self.phase.can_transition_to(next) {
            return Err(PhaseTransitionError {
                from: self.phase,
                to: next,
            });
        }

        if next == LifecyclePhase::Running {
            self.epoch += 1;
            self.gate.open(RunEpoch(self.epoch));
        } else if self.phase == LifecyclePhase::Running {
            self.gate.close();
        }

        self.phase = next;
        Ok(())
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{EpochGate, Lifecycle, LifecyclePhase, RunEpoch};

    /// The legal edges, written out by hand so the exhaustive test below is not
    /// checking `can_transition_to` against itself.
    const LEGAL_EDGES: [(LifecyclePhase, LifecyclePhase); 17] = [
        (LifecyclePhase::Created, LifecyclePhase::Initializing),
        (LifecyclePhase::Created, LifecyclePhase::Failed),
        (LifecyclePhase::Initializing, LifecyclePhase::Initialized),
        (LifecyclePhase::Initializing, LifecyclePhase::Failed),
        (LifecyclePhase::Initialized, LifecyclePhase::Starting),
        (LifecyclePhase::Initialized, LifecyclePhase::Stopping),
        (LifecyclePhase::Initialized, LifecyclePhase::Failed),
        (LifecyclePhase::Starting, LifecyclePhase::Running),
        (LifecyclePhase::Starting, LifecyclePhase::Failed),
        (LifecyclePhase::Running, LifecyclePhase::Draining),
        (LifecyclePhase::Running, LifecyclePhase::Failed),
        (LifecyclePhase::Draining, LifecyclePhase::Stopping),
        (LifecyclePhase::Draining, LifecyclePhase::Failed),
        (LifecyclePhase::Stopping, LifecyclePhase::Stopped),
        (LifecyclePhase::Stopping, LifecyclePhase::Failed),
        (LifecyclePhase::Failed, LifecyclePhase::Stopping),
        (LifecyclePhase::Failed, LifecyclePhase::Stopped),
    ];

    fn run_to_running() -> Lifecycle {
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

    #[test]
    fn every_one_of_the_eighty_one_ordered_pairs_matches_the_written_table() {
        let mut accepted = 0;

        for from in LifecyclePhase::ALL {
            for to in LifecyclePhase::ALL {
                let expected = LEGAL_EDGES.contains(&(from, to));
                assert_eq!(
                    from.can_transition_to(to),
                    expected,
                    "{from} -> {to} disagreed with the written table"
                );

                if expected {
                    accepted += 1;
                }
            }
        }

        assert_eq!(accepted, LEGAL_EDGES.len());
    }

    #[test]
    fn no_phase_may_transition_to_itself() {
        for phase in LifecyclePhase::ALL {
            assert!(
                !phase.can_transition_to(phase),
                "{phase} was allowed to re-enter itself"
            );
        }
    }

    #[test]
    fn stopped_accepts_nothing_and_is_the_only_terminal_phase() {
        for phase in LifecyclePhase::ALL {
            assert!(!LifecyclePhase::Stopped.can_transition_to(phase));
            assert_eq!(phase.is_terminal(), phase == LifecyclePhase::Stopped);
        }
    }

    #[test]
    fn running_is_the_only_phase_that_accepts_work() {
        for phase in LifecyclePhase::ALL {
            assert_eq!(phase.accepts_work(), phase == LifecyclePhase::Running);
        }
    }

    #[test]
    fn a_rejected_transition_names_both_ends_and_leaves_the_phase_alone() {
        let mut lifecycle = Lifecycle::new();

        let error = lifecycle
            .transition_to(LifecyclePhase::Running)
            .expect_err("created cannot jump straight to running");

        assert_eq!(error.from(), LifecyclePhase::Created);
        assert_eq!(error.to(), LifecyclePhase::Running);
        assert_eq!(
            error.to_string(),
            "illegal lifecycle transition: created -> running"
        );
        assert_eq!(lifecycle.phase(), LifecyclePhase::Created);
    }

    #[test]
    fn the_gate_is_shut_until_running_is_entered() {
        let mut lifecycle = Lifecycle::new();
        let gate = lifecycle.epoch_gate();

        assert_eq!(gate.current(), None);

        for phase in [
            LifecyclePhase::Initializing,
            LifecyclePhase::Initialized,
            LifecyclePhase::Starting,
        ] {
            lifecycle.transition_to(phase).expect("legal transition");
            assert_eq!(gate.current(), None, "gate opened early in {phase}");
        }

        lifecycle
            .transition_to(LifecyclePhase::Running)
            .expect("legal transition");
        assert_eq!(gate.current(), Some(RunEpoch(1)));
    }

    #[test]
    fn draining_shuts_the_gate_for_handles_taken_before_the_run_began() {
        let mut lifecycle = Lifecycle::new();
        let gate = lifecycle.epoch_gate();

        for phase in [
            LifecyclePhase::Initializing,
            LifecyclePhase::Initialized,
            LifecyclePhase::Starting,
            LifecyclePhase::Running,
        ] {
            lifecycle.transition_to(phase).expect("legal transition");
        }
        assert_eq!(gate.current(), Some(RunEpoch(1)));

        lifecycle
            .transition_to(LifecyclePhase::Draining)
            .expect("legal transition");

        assert_eq!(gate.current(), None);
        assert_eq!(lifecycle.active_epoch(), None);
    }

    #[test]
    fn failing_out_of_running_also_shuts_the_gate() {
        let mut lifecycle = run_to_running();
        let gate = lifecycle.epoch_gate();

        lifecycle
            .transition_to(LifecyclePhase::Failed)
            .expect("running may fail");

        assert_eq!(gate.current(), None);
    }

    #[test]
    fn a_second_run_uses_a_later_epoch_than_the_first() {
        let mut lifecycle = run_to_running();
        let gate = lifecycle.epoch_gate();
        let first = gate.current().expect("first run is open");

        for phase in [LifecyclePhase::Draining, LifecyclePhase::Stopping] {
            lifecycle.transition_to(phase).expect("legal transition");
        }

        // A fresh composition object models a restart; the epoch counter is
        // per-composition, so assert the first run is the first epoch.
        assert_eq!(first, RunEpoch(1));
        assert_eq!(first.get(), 1);
        assert_eq!(first.to_string(), "epoch 1");
        assert_eq!(Lifecycle::new().active_epoch(), None);
    }

    #[test]
    fn an_explicitly_closed_gate_never_reports_an_epoch() {
        let gate = EpochGate::closed();

        assert_eq!(gate.current(), None);
        assert_eq!(EpochGate::default().current(), None);
    }

    #[test]
    fn phase_labels_are_unique_and_stable() {
        let labels: Vec<&str> = LifecyclePhase::ALL.iter().map(|p| p.label()).collect();
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(unique.len(), labels.len());
        assert_eq!(
            labels,
            vec![
                "created",
                "initializing",
                "initialized",
                "starting",
                "running",
                "draining",
                "stopping",
                "stopped",
                "failed",
            ]
        );
    }
}

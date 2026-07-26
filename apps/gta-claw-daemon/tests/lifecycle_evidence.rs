//! Evidence for one property the composition depends on but does not witness.
//!
//! # What this file is
//!
//! `StopSummary::is_clean()` is the conjunction of a clean shutdown report, a
//! settled task ledger, and the phase reaching `Stopped`. The task ledger's
//! `is_settled()` compares spawned against terminated **over the tasks that
//! went through `TrackedSpawner`**. A task started with a bare `tokio::spawn`
//! is in neither total, so it can outlive a stop the summary calls clean.
//!
//! Nothing in the repository states that. The three existing ledger tests
//! (`runtime.rs`) all spawn *through* the tracker, so they measure the ledger
//! against itself and cannot see the boundary of its denominator.
//!
//! The test below asserts the blind spot **exists**. That is deliberate: it
//! turns an assumption into a property, and it fails the day someone widens the
//! ledger — which is exactly when a reader wants to be told.
//!
//! # What this file deliberately does not contain
//!
//! A second candidate — that the order of `quiesce`, `drain` and `shutdown` is
//! unobserved — was investigated and **withdrawn**. It is already covered, and
//! covered better, by `composition::host::tests::
//! every_ingress_is_quiesced_before_any_subsystem_is_drained`, which uses *two*
//! ingress subsystems and so separates "every ingress quiesces before any
//! subsystem drains" from the weaker "each ingress quiesces before its own
//! drain". A single-subsystem recorder cannot tell those apart, so a test here
//! would have been strictly weaker than the one that already exists.
//!
//! Inverting the two loops in `SubsystemHost::quiesce_and_drain` was caught by
//! seven tests across `claw-application` and this crate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use claw_application::composition::{
    BoxFuture, Clock, ServiceHandle, StartContext, Subsystem, SubsystemDescriptor, SubsystemError,
    SubsystemId, SubsystemKind, well_known,
};
use gta_claw_daemon::adapters::support::SteppedClock;
use gta_claw_daemon::compose::Daemon;

/// The control: an added subsystem that starts no tasks at all.
///
/// Exists so the escaping subsystem below is the *only* difference between the
/// two runs, which is what makes comparing their ledgers meaningful.
#[derive(Debug, Default)]
struct QuietSubsystem;

impl QuietSubsystem {
    fn id() -> SubsystemId {
        SubsystemId::new("quiet-subsystem").expect("the literal satisfies the grammar")
    }
}

impl Subsystem for QuietSubsystem {
    fn descriptor(&self) -> SubsystemDescriptor {
        SubsystemDescriptor::new(Self::id(), SubsystemKind::Ingress)
            .depends_on(well_known::engine())
    }

    fn initialize<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move { Ok(()) })
    }

    fn start<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move { Ok(ServiceHandle::inert(Self::id())) })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move { Ok(()) })
    }
}

/// A subsystem that starts a task the daemon's spawner never sees.
///
/// The task parks forever, so it cannot terminate on its own; if the ledger
/// counted it, the ledger could not settle.
#[derive(Debug, Default)]
struct EscapingSubsystem {
    running: Arc<AtomicBool>,
    escaped: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl EscapingSubsystem {
    fn id() -> SubsystemId {
        SubsystemId::new("escaping-subsystem").expect("the literal satisfies the grammar")
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn escaped_task_is_still_alive(&self) -> bool {
        self.escaped
            .lock()
            .expect("the handle is usable")
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    fn abort_escaped_task(&self) {
        if let Some(handle) = self.escaped.lock().expect("the handle is usable").take() {
            handle.abort();
        }
    }
}

impl Subsystem for EscapingSubsystem {
    fn descriptor(&self) -> SubsystemDescriptor {
        SubsystemDescriptor::new(Self::id(), SubsystemKind::Ingress)
            .depends_on(well_known::engine())
    }

    fn initialize<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move { Ok(()) })
    }

    fn start<'a>(
        &'a self,
        _context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>> {
        Box::pin(async move {
            let running = Arc::clone(&self.running);

            // Deliberately not `context.spawner()`. This is the shape the
            // ledger cannot see, and the point of the test.
            let escaped = tokio::spawn(async move {
                running.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
            });

            *self.escaped.lock().expect("the handle is usable") = Some(escaped);
            Ok(ServiceHandle::inert(Self::id()))
        })
    }

    fn shutdown<'a>(&'a self) -> BoxFuture<'a, Result<(), SubsystemError>> {
        Box::pin(async move { Ok(()) })
    }
}

/// Waits for the escaped task to reach its parked state.
async fn wait_until_running(subsystem: &EscapingSubsystem) {
    for _ in 0..400 {
        if subsystem.is_running() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the escaped task never started, so the rest of this test would prove nothing");
}

/// Builds a daemon carrying one extra subsystem, with everything else fixed.
fn daemon_with(extra: Arc<dyn Subsystem>) -> Daemon {
    Daemon::builder()
        .clock(Arc::new(SteppedClock::new()) as Arc<dyn Clock>)
        .with_subsystem(extra)
        .build()
        .expect("the composition builds with an added subsystem")
}

/// The task ledger counts what it spawned, not what is running.
///
/// Two daemons are run so the escapee is the only difference between them: one
/// with a subsystem that spawns nothing, one with a subsystem that escapes.
/// Equal ledgers across the pair is the finding — the escaped task moved
/// neither total, so `is_clean()` reads exactly as it would have had the task
/// never existed.
///
/// Asserting only "still clean" would be compatible with the escapee never
/// having started, so the test also proves the task reached its parked state
/// and was still alive after the stop returned.
#[tokio::test]
async fn a_task_spawned_outside_the_tracked_spawner_never_reaches_the_ledger() {
    let mut quiet = daemon_with(Arc::new(QuietSubsystem) as Arc<dyn Subsystem>);
    quiet.start().await.expect("the control comes up");
    let control_summary = quiet.stop().await.expect("the control stops");
    assert!(
        control_summary.is_clean(),
        "the control run must be a clean stop for the comparison to mean anything"
    );

    let escapee = Arc::new(EscapingSubsystem::default());
    let mut leaky = daemon_with(Arc::clone(&escapee) as Arc<dyn Subsystem>);
    leaky.start().await.expect("the escaping daemon comes up");
    wait_until_running(&escapee).await;

    let escaping_summary = leaky.stop().await.expect("the escaping daemon stops");

    assert!(
        escapee.escaped_task_is_still_alive(),
        "the escaped task ended by itself, so this run proves nothing about a leak"
    );
    assert!(
        escaping_summary.is_clean(),
        "a task the ledger cannot see is still running, and the summary is expected to \
         call the stop clean anyway; if this now fails, the blind spot has closed and \
         this test should be replaced by one asserting the leak is caught"
    );
    assert_eq!(
        escaping_summary.tasks().spawned(),
        control_summary.tasks().spawned(),
        "the escaped task moved the spawn count, so the ledger has grown visibility it \
         did not have and this evidence is stale"
    );
    assert_eq!(
        escaping_summary.tasks().terminated(),
        control_summary.tasks().terminated(),
        "the escaped task moved the termination count while it was still running"
    );
    assert!(
        escaping_summary.tasks().is_settled(),
        "the ledger settled over its own tasks, which is the narrower claim it makes"
    );

    escapee.abort_escaped_task();
}

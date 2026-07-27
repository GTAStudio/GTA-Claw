//! Cooperative host suspension.
//!
//! A host that is about to be put to sleep — a laptop closing its lid, a
//! container about to be checkpointed, a supervisor about to snapshot a VM —
//! needs a way to ask the process to stop *starting* things, confirm that
//! nothing is still running, and hold that state briefly. It must never
//! cancel work that is already in flight, and it must never wedge the process
//! if the asker disappears. That is what this module implements.
//!
//! The protocol is upstream's `gateway.suspend.prepare` / `.status` /
//! `.resume` triple, taken from the frozen baseline
//! `openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`
//! (`packages/gateway-protocol/src/schema/gateway-suspend.ts`,
//! `src/gateway/server-methods.ts`).
//!
//! # The pieces
//!
//! - [`WorkAdmission`] is the process-wide fence. It has three phases and
//!   refuses — never queues — new root work while closed.
//! - [`ActiveWorkSnapshot`] is one reading of the thirteen counters that
//!   decide whether the host is idle, plus the blockers to report when it is
//!   not.
//! - [`SuspendCoordinator`] owns at most one lease and drives the fence, the
//!   [`Scheduler`] and the [`Clock`].
//!
//! # Wiring this into a host
//!
//! This crate deliberately owns no transport. A gateway or daemon wires it in
//! four places:
//!
//! 1. Share one `Arc<WorkAdmission>` and one [`SuspendCoordinator`] per
//!    process.
//! 2. In the request dispatcher, take a [`RootWorkLease`] per inbound root
//!    request. When [`WorkAdmission::try_begin_root_work`] refuses, answer with
//!    a retryable unavailable error carrying the refusal's reason, phase and
//!    `retry_after_ms` — unless
//!    [`is_method_allowed_during_suspension`] says the method is one of the
//!    three suspend control methods, which must stay callable so the
//!    controller can poll and resume.
//! 3. Route the three control methods to [`SuspendCoordinator::prepare`],
//!    [`SuspendCoordinator::status`] and [`SuspendCoordinator::resume`],
//!    rejecting parameters that [`is_valid_suspension_token`] refuses.
//! 4. Implement [`Scheduler`] over the host's own timers, and
//!    [`ActiveWorkInspector`] over its activity registries. The inspector's
//!    `root_requests` should exclude the request running the preparation; see
//!    [`WorkAdmission::active_root_work_excluding`].
//!
//! # Differences from upstream
//!
//! - Nesting is explicit. Upstream detects a nested request through an
//!   `AsyncLocalStorage`; Rust has no ambient async context, so a host passes
//!   its [`RootWorkLease`] down instead.
//! - Invalidation is polled, not pushed. Upstream hands the coordinator an
//!   invalidation callback; here [`SuspendLease::is_active`] is checked at
//!   every entry point, which observes the same transitions and cannot
//!   deadlock against the coordinator's own lock.
//! - Expiry and scheduler recovery are driven by the caller. Upstream arms an
//!   `unref`'d timer; here every entry point normalises first, and
//!   [`SuspendCoordinator::poll`] lets a host drive both from its own timer
//!   without adding an async runtime dependency to this crate.

mod active_work;
mod admission;
mod clock;
mod coordinator;

pub use active_work::{
    ActiveWorkCounts, ActiveWorkInspector, ActiveWorkSnapshot, Blocker, BlockerKind, IdleInspector,
    MAX_REPORTED_TASK_BLOCKERS, MAX_REPORTED_TASK_TITLE_UTF16, TaskBlocker, TaskRuntime,
};
pub use admission::{
    AdmissionPhase, AdmissionRefusal, ROOT_WORK_RETRY_AFTER_MS, RefusalReason, RootWorkLease,
    SUSPEND_CONTROL_METHODS, SuspendLease, WorkAdmission, is_method_allowed_during_suspension,
};
pub use clock::{Clock, ManualClock, SystemClock};
pub use coordinator::{
    BusyReason, MAX_SUSPENSION_TOKEN_LEN, NoopScheduler, PrepareOutcome, ProcessSuspensionIds,
    ResumeOutcome, SCHEDULER_RECOVERY_RETRY_MS, SUSPEND_RETRY_AFTER_MS, SUSPEND_TTL_MS, Scheduler,
    SchedulerError, StatusOutcome, SuspendCoordinator, SuspensionIds, is_valid_suspension_token,
};

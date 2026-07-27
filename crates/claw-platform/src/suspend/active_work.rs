//! The activity snapshot a suspension decision is made from.
//!
//! A host is suspendable only when it is completely idle. "Idle" is not a
//! boolean the host guesses at: it is the sum of thirteen independently
//! inspected counters, and every non-zero counter becomes a *blocker* the
//! caller can read back. Refusing to suspend without saying what is running
//! turns a cooperative protocol into a coin flip.
//!
//! The counter set, the blocker vocabulary and the blocker messages mirror
//! `src/infra/gateway-active-work.ts` at the frozen upstream baseline, so a
//! client written against the upstream `gateway.suspend.*` schema reads the
//! same diagnostics from this host.

use std::fmt::Debug;

/// The number of task blockers reported individually before they are folded
/// into a single "additional" row.
pub const MAX_REPORTED_TASK_BLOCKERS: usize = 8;

/// The number of UTF-16 code units of a task title that is reported.
pub const MAX_REPORTED_TASK_TITLE_UTF16: usize = 80;

/// The runtime a background task is executing under.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TaskRuntime {
    /// A sub-agent run.
    Subagent,
    /// An Agent Client Protocol session.
    Acp,
    /// A command-line run.
    Cli,
    /// A scheduled run.
    Cron,
}

impl TaskRuntime {
    /// Returns the upstream wire literal for this runtime.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subagent => "subagent",
            Self::Acp => "acp",
            Self::Cli => "cli",
            Self::Cron => "cron",
        }
    }
}

/// A single running background task that blocks suspension.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskBlocker {
    task_id: String,
    runtime: TaskRuntime,
    run_id: Option<String>,
    label: Option<String>,
    title: Option<String>,
}

impl TaskBlocker {
    /// Describes a running task.
    #[must_use]
    pub fn new(task_id: impl Into<String>, runtime: TaskRuntime) -> Self {
        Self {
            task_id: task_id.into(),
            runtime,
            run_id: None,
            label: None,
            title: None,
        }
    }

    /// Attaches the identity of the current run.
    #[must_use]
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    /// Attaches the operator-visible label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Attaches the task title, which is truncated when reported.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Returns the task identity.
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// Returns the runtime executing the task.
    #[must_use]
    pub const fn runtime(&self) -> TaskRuntime {
        self.runtime
    }

    /// Returns the identity of the current run, when known.
    #[must_use]
    pub fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    /// Returns the operator-visible label, when set.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Returns the untruncated task title, when set.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// Renders the diagnostic line reported to the suspension caller.
    ///
    /// The task status is always `running`, because a task that is not running
    /// does not block a suspension and is never reported here.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = vec![format!("taskId={}", self.task_id)];
        if let Some(run_id) = self.run_id.as_deref().filter(|value| !value.is_empty()) {
            parts.push(format!("runId={run_id}"));
        }
        parts.push("status=running".to_owned());
        parts.push(format!("runtime={}", self.runtime.as_str()));
        if let Some(label) = self.label.as_deref().filter(|value| !value.is_empty()) {
            parts.push(format!("label={label}"));
        }
        if let Some(title) = self.title.as_deref().filter(|value| !value.is_empty()) {
            parts.push(format!(
                "title={}",
                truncate_utf16(title, MAX_REPORTED_TASK_TITLE_UTF16)
            ));
        }
        parts.join(" ")
    }
}

/// Truncates to at most `limit` UTF-16 code units without splitting a
/// surrogate pair, matching `truncateUtf16Safe` upstream.
fn truncate_utf16(input: &str, limit: usize) -> &str {
    let mut units = 0usize;
    for (index, character) in input.char_indices() {
        let next = units + character.len_utf16();
        if next > limit {
            return &input[..index];
        }
        units = next;
    }
    input
}

/// The category of work that blocks a suspension.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BlockerKind {
    /// Queued or executing command-queue operations.
    Queue,
    /// Pending auto-reply deliveries.
    Reply,
    /// Active embedded agent runs.
    EmbeddedRun,
    /// Active background exec sessions.
    BackgroundExec,
    /// Active scheduled runs.
    CronRun,
    /// A running background task.
    Task,
    /// Admitted root requests other than the preparing one.
    RootRequest,
    /// Admitted session turns.
    SessionAdmission,
    /// Session lifecycle mutations in flight.
    SessionMutation,
    /// Active chat runs.
    ChatRun,
    /// Queued chat turns.
    QueuedTurn,
    /// Pending terminal session writes.
    TerminalPersistence,
    /// Open terminal sessions.
    TerminalSession,
}

impl BlockerKind {
    /// Returns the upstream wire literal for this blocker kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::Reply => "reply",
            Self::EmbeddedRun => "embedded-run",
            Self::BackgroundExec => "background-exec",
            Self::CronRun => "cron-run",
            Self::Task => "task",
            Self::RootRequest => "root-request",
            Self::SessionAdmission => "session-admission",
            Self::SessionMutation => "session-mutation",
            Self::ChatRun => "chat-run",
            Self::QueuedTurn => "queued-turn",
            Self::TerminalPersistence => "terminal-persistence",
            Self::TerminalSession => "terminal-session",
        }
    }
}

/// One reason a host is not idle.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Blocker {
    kind: BlockerKind,
    count: u64,
    message: String,
    task: Option<TaskBlocker>,
}

impl Blocker {
    /// Returns the category of blocking work.
    #[must_use]
    pub const fn kind(&self) -> BlockerKind {
        self.kind
    }

    /// Returns how many units of work this blocker represents.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Returns the operator-facing description.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the task detail, for [`BlockerKind::Task`] blockers that carry one.
    #[must_use]
    pub const fn task(&self) -> Option<&TaskBlocker> {
        self.task.as_ref()
    }
}

/// The thirteen counters that decide whether a host is idle.
///
/// The categories deliberately overlap — one embedded run can also be a queue
/// entry — so [`ActiveWorkCounts::total_active`] is a compatibility aggregate
/// for the wire `activeCount`, never a count of distinct operations.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActiveWorkCounts {
    /// Queued or executing command-queue operations.
    pub queue_size: u64,
    /// Pending auto-reply deliveries.
    pub pending_replies: u64,
    /// Active embedded agent runs.
    pub embedded_runs: u64,
    /// Active background exec sessions.
    pub background_exec_sessions: u64,
    /// Active scheduled runs.
    pub cron_runs: u64,
    /// Running background tasks.
    pub active_tasks: u64,
    /// Admitted root requests other than the preparing one.
    pub root_requests: u64,
    /// Admitted session turns.
    pub session_admissions: u64,
    /// Session lifecycle mutations in flight.
    pub session_mutations: u64,
    /// Active chat runs.
    pub chat_runs: u64,
    /// Queued chat turns.
    pub queued_turns: u64,
    /// Pending terminal session writes.
    pub terminal_persistence: u64,
    /// Open terminal sessions.
    pub terminal_sessions: u64,
}

impl ActiveWorkCounts {
    /// Returns the compatibility aggregate reported as `activeCount`.
    #[must_use]
    pub const fn total_active(&self) -> u64 {
        self.queue_size
            .saturating_add(self.pending_replies)
            .saturating_add(self.embedded_runs)
            .saturating_add(self.background_exec_sessions)
            .saturating_add(self.cron_runs)
            .saturating_add(self.active_tasks)
            .saturating_add(self.root_requests)
            .saturating_add(self.session_admissions)
            .saturating_add(self.session_mutations)
            .saturating_add(self.chat_runs)
            .saturating_add(self.queued_turns)
            .saturating_add(self.terminal_persistence)
            .saturating_add(self.terminal_sessions)
    }

    /// Returns whether every counter is zero.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.total_active() == 0
    }
}

/// Reads the host counters a suspension decision depends on.
///
/// Implementations are called while the scheduler is paused and while the
/// coordinator holds its own lock, so they must not block and must not call
/// back into `SuspendCoordinator`: a slow inspector holds the whole host
/// still, and a re-entrant one deadlocks.
pub trait ActiveWorkInspector: Debug + Send + Sync {
    /// Returns the current counters.
    fn counts(&self) -> ActiveWorkCounts;

    /// Returns detail for the running background tasks, when available.
    fn task_blockers(&self) -> Vec<TaskBlocker> {
        Vec::new()
    }
}

/// A host that never has work of its own.
///
/// Useful for hosts whose only work is gateway requests, and as a starting
/// point for tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdleInspector;

impl ActiveWorkInspector for IdleInspector {
    fn counts(&self) -> ActiveWorkCounts {
        ActiveWorkCounts::default()
    }
}

/// One reading of everything that could block a suspension.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActiveWorkSnapshot {
    counts: ActiveWorkCounts,
    blockers: Vec<Blocker>,
}

impl ActiveWorkSnapshot {
    /// Reads every counter once and renders the blocker list.
    #[must_use]
    pub fn capture(inspector: &dyn ActiveWorkInspector) -> Self {
        let counts = inspector.counts();
        let mut blockers = Vec::new();
        let mut push = |count: u64, kind: BlockerKind, message: String| {
            if count > 0 {
                blockers.push(Blocker {
                    kind,
                    count,
                    message,
                    task: None,
                });
            }
        };

        push(
            counts.queue_size,
            BlockerKind::Queue,
            format!("{} queued or active operation(s)", counts.queue_size),
        );
        push(
            counts.pending_replies,
            BlockerKind::Reply,
            format!(
                "{} pending reply delivery operation(s)",
                counts.pending_replies
            ),
        );
        push(
            counts.embedded_runs,
            BlockerKind::EmbeddedRun,
            format!("{} active embedded run(s)", counts.embedded_runs),
        );
        push(
            counts.background_exec_sessions,
            BlockerKind::BackgroundExec,
            format!(
                "{} active background exec session(s)",
                counts.background_exec_sessions
            ),
        );
        push(
            counts.cron_runs,
            BlockerKind::CronRun,
            format!("{} active cron run(s)", counts.cron_runs),
        );
        push(
            counts.root_requests,
            BlockerKind::RootRequest,
            format!("{} active gateway request(s)", counts.root_requests),
        );
        push(
            counts.session_admissions,
            BlockerKind::SessionAdmission,
            format!("{} admitted session turn(s)", counts.session_admissions),
        );
        push(
            counts.session_mutations,
            BlockerKind::SessionMutation,
            format!(
                "{} active session lifecycle mutation(s)",
                counts.session_mutations
            ),
        );
        push(
            counts.chat_runs,
            BlockerKind::ChatRun,
            format!("{} active chat run(s)", counts.chat_runs),
        );
        push(
            counts.queued_turns,
            BlockerKind::QueuedTurn,
            format!("{} queued chat turn(s)", counts.queued_turns),
        );
        push(
            counts.terminal_persistence,
            BlockerKind::TerminalPersistence,
            format!(
                "{} pending terminal session write(s)",
                counts.terminal_persistence
            ),
        );
        push(
            counts.terminal_sessions,
            BlockerKind::TerminalSession,
            format!("{} open terminal session(s)", counts.terminal_sessions),
        );

        if counts.active_tasks > 0 {
            append_task_blockers(&mut blockers, counts.active_tasks, inspector);
        }

        Self { counts, blockers }
    }

    /// Returns the counters this snapshot was built from.
    #[must_use]
    pub const fn counts(&self) -> &ActiveWorkCounts {
        &self.counts
    }

    /// Returns every blocker, in upstream reporting order.
    #[must_use]
    pub fn blockers(&self) -> &[Blocker] {
        &self.blockers
    }

    /// Consumes the snapshot and returns its blockers.
    #[must_use]
    pub fn into_blockers(self) -> Vec<Blocker> {
        self.blockers
    }

    /// Returns the aggregate reported as `activeCount`.
    #[must_use]
    pub const fn active_count(&self) -> u64 {
        self.counts.total_active()
    }

    /// Returns whether the host may be suspended.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.counts.is_idle()
    }
}

fn append_task_blockers(
    blockers: &mut Vec<Blocker>,
    active_tasks: u64,
    inspector: &dyn ActiveWorkInspector,
) {
    let tasks = inspector.task_blockers();
    if tasks.is_empty() {
        blockers.push(Blocker {
            kind: BlockerKind::Task,
            count: active_tasks,
            message: format!("{active_tasks} active background task run(s)"),
            task: None,
        });
        return;
    }

    let shown = tasks.len().min(MAX_REPORTED_TASK_BLOCKERS);
    for task in tasks.into_iter().take(shown) {
        blockers.push(Blocker {
            kind: BlockerKind::Task,
            count: 1,
            message: task.describe(),
            task: Some(task),
        });
    }

    let omitted = active_tasks.saturating_sub(u64::try_from(shown).unwrap_or(u64::MAX));
    if omitted > 0 {
        blockers.push(Blocker {
            kind: BlockerKind::Task,
            count: omitted,
            message: format!("{omitted} additional active background task run(s)"),
            task: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActiveWorkCounts, ActiveWorkInspector, ActiveWorkSnapshot, BlockerKind, IdleInspector,
        MAX_REPORTED_TASK_BLOCKERS, TaskBlocker, TaskRuntime, truncate_utf16,
    };

    #[derive(Debug, Default)]
    struct StubInspector {
        counts: ActiveWorkCounts,
        tasks: Vec<TaskBlocker>,
    }

    impl ActiveWorkInspector for StubInspector {
        fn counts(&self) -> ActiveWorkCounts {
            self.counts
        }

        fn task_blockers(&self) -> Vec<TaskBlocker> {
            self.tasks.clone()
        }
    }

    #[test]
    fn an_idle_host_reports_no_blockers() {
        let snapshot = ActiveWorkSnapshot::capture(&IdleInspector);

        assert!(snapshot.is_idle());
        assert_eq!(snapshot.active_count(), 0);
        assert!(snapshot.blockers().is_empty());
    }

    #[test]
    fn every_counter_contributes_to_the_aggregate() {
        let counts = ActiveWorkCounts {
            queue_size: 1,
            pending_replies: 2,
            embedded_runs: 3,
            background_exec_sessions: 4,
            cron_runs: 5,
            active_tasks: 6,
            root_requests: 7,
            session_admissions: 8,
            session_mutations: 9,
            chat_runs: 10,
            queued_turns: 11,
            terminal_persistence: 12,
            terminal_sessions: 13,
        };

        assert_eq!(counts.total_active(), 91);
        assert!(!counts.is_idle());
    }

    #[test]
    fn blockers_are_reported_in_the_upstream_vocabulary_and_order() {
        let inspector = StubInspector {
            counts: ActiveWorkCounts {
                queue_size: 2,
                pending_replies: 1,
                embedded_runs: 1,
                background_exec_sessions: 1,
                cron_runs: 1,
                active_tasks: 1,
                root_requests: 1,
                session_admissions: 1,
                session_mutations: 1,
                chat_runs: 1,
                queued_turns: 1,
                terminal_persistence: 1,
                terminal_sessions: 1,
            },
            tasks: Vec::new(),
        };

        let snapshot = ActiveWorkSnapshot::capture(&inspector);
        let kinds: Vec<&str> = snapshot
            .blockers()
            .iter()
            .map(|blocker| blocker.kind().as_str())
            .collect();

        assert_eq!(
            kinds,
            vec![
                "queue",
                "reply",
                "embedded-run",
                "background-exec",
                "cron-run",
                "root-request",
                "session-admission",
                "session-mutation",
                "chat-run",
                "queued-turn",
                "terminal-persistence",
                "terminal-session",
                "task",
            ]
        );
        assert_eq!(
            snapshot.blockers()[0].message(),
            "2 queued or active operation(s)"
        );
        assert_eq!(
            snapshot.blockers()[12].message(),
            "1 active background task run(s)"
        );
    }

    #[test]
    fn task_blockers_are_capped_and_the_remainder_is_folded_into_one_row() {
        let tasks: Vec<TaskBlocker> = (0..10)
            .map(|index| TaskBlocker::new(format!("task-{index}"), TaskRuntime::Subagent))
            .collect();
        let inspector = StubInspector {
            counts: ActiveWorkCounts {
                active_tasks: 10,
                ..ActiveWorkCounts::default()
            },
            tasks,
        };

        let snapshot = ActiveWorkSnapshot::capture(&inspector);

        assert_eq!(snapshot.blockers().len(), MAX_REPORTED_TASK_BLOCKERS + 1);
        let last = snapshot.blockers().last().expect("a folded row");
        assert_eq!(last.kind(), BlockerKind::Task);
        assert_eq!(last.count(), 2);
        assert_eq!(last.message(), "2 additional active background task run(s)");
        assert!(last.task().is_none());
    }

    #[test]
    fn a_task_blocker_renders_the_upstream_diagnostic_line() {
        let task = TaskBlocker::new("task-1", TaskRuntime::Cron)
            .with_run_id("run-9")
            .with_label("nightly")
            .with_title("compact the archive");

        assert_eq!(
            task.describe(),
            "taskId=task-1 runId=run-9 status=running runtime=cron label=nightly title=compact the archive"
        );

        let minimal = TaskBlocker::new("task-2", TaskRuntime::Acp);

        assert_eq!(
            minimal.describe(),
            "taskId=task-2 status=running runtime=acp"
        );
    }

    #[test]
    fn a_reported_title_is_truncated_without_splitting_a_surrogate_pair() {
        let title = "x".repeat(79) + "🙂";
        let task = TaskBlocker::new("task-3", TaskRuntime::Cli).with_title(title);

        let described = task.describe();
        let title = described
            .strip_prefix("taskId=task-3 status=running runtime=cli title=")
            .expect("a described title");

        assert_eq!(title.chars().count(), 79);
        assert!(!title.contains('🙂'));
    }

    #[test]
    fn truncation_keeps_whole_characters_within_the_utf16_budget() {
        assert_eq!(truncate_utf16("abc", 80), "abc");
        assert_eq!(truncate_utf16("abc", 2), "ab");
        assert_eq!(truncate_utf16("🙂🙂", 3), "🙂");
        assert_eq!(truncate_utf16("🙂", 1), "");
    }
}

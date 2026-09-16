use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// Every lifecycle state presented by the GTA Claw run monitor.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// The run has not been submitted.
    #[default]
    Draft,
    /// The run is waiting for capacity.
    Queued,
    /// Runtime startup is in progress.
    Starting,
    /// The agent is actively working.
    Running,
    /// A human approval is required.
    WaitingForApproval,
    /// The agent asked a question.
    WaitingForAnswer,
    /// The user paused the run.
    Paused,
    /// Progress is blocked by an external condition.
    Blocked,
    /// An effect may have occurred; its result must be reconciled, not automatically repeated.
    OutcomeUnknown,
    /// The run failed.
    Failed,
    /// The run was cancelled.
    Cancelled,
    /// The run completed without workspace changes.
    Completed,
    /// The run completed and changed the workspace.
    CompletedWithChanges,
}

impl RunState {
    /// All states in stable display order.
    pub const ALL: [Self; 13] = [
        Self::Draft,
        Self::Queued,
        Self::Starting,
        Self::Running,
        Self::WaitingForApproval,
        Self::WaitingForAnswer,
        Self::Paused,
        Self::Blocked,
        Self::OutcomeUnknown,
        Self::Failed,
        Self::Cancelled,
        Self::Completed,
        Self::CompletedWithChanges,
    ];

    /// Human-readable state text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Draft => "Draft",
            Self::Queued => "Queued",
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::WaitingForApproval => "Waiting for approval",
            Self::WaitingForAnswer => "Waiting for answer",
            Self::Paused => "Paused",
            Self::Blocked => "Blocked",
            Self::OutcomeUnknown => "Outcome unknown",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
            Self::Completed => "Completed",
            Self::CompletedWithChanges => "Completed with changes",
        }
    }

    /// A unique monochrome marker, retained when color is disabled.
    #[must_use]
    pub const fn marker(self) -> char {
        match self {
            Self::Draft => 'D',
            Self::Queued => 'Q',
            Self::Starting => 'S',
            Self::Running => 'R',
            Self::WaitingForApproval => 'A',
            Self::WaitingForAnswer => '?',
            Self::Paused => 'P',
            Self::Blocked => 'B',
            Self::OutcomeUnknown => '!',
            Self::Failed => 'F',
            Self::Cancelled => 'X',
            Self::Completed => 'C',
            Self::CompletedWithChanges => '+',
        }
    }

    pub(crate) const fn color(self) -> u8 {
        match self {
            Self::Draft => 245,
            Self::Queued => 33,
            Self::Starting => 39,
            Self::Running => 42,
            Self::WaitingForApproval => 214,
            Self::WaitingForAnswer => 220,
            Self::Paused => 141,
            Self::Blocked => 208,
            Self::OutcomeUnknown => 202,
            Self::Failed => 196,
            Self::Cancelled => 160,
            Self::Completed => 35,
            Self::CompletedWithChanges => 48,
        }
    }
}

impl RunState {
    /// Fail-safe state for a run state this build does not know about: an
    /// unknown state must never look like progress or success.
    const UNKNOWN: Self = Self::Blocked;

    pub(crate) fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().replace([' ', '-'], "_").as_str() {
            "draft" => Self::Draft,
            "queued" => Self::Queued,
            "starting" => Self::Starting,
            "running" => Self::Running,
            "waiting_for_approval" | "waitingapproval" => Self::WaitingForApproval,
            "waiting_for_answer" | "waitinganswer" => Self::WaitingForAnswer,
            "paused" => Self::Paused,
            "blocked" => Self::Blocked,
            "outcome_unknown" => Self::OutcomeUnknown,
            "failed" => Self::Failed,
            "cancelled" | "canceled" => Self::Cancelled,
            "completed_with_changes" | "completedwithchanges" => Self::CompletedWithChanges,
            "completed" => Self::Completed,
            _ => Self::UNKNOWN,
        }
    }
}

/// One session shown in the navigation and monitor screens.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionSummary {
    /// Stable Gateway session identifier.
    pub id: String,
    /// User-facing title.
    pub title: String,
    /// Workspace path or description.
    pub workspace: String,
    /// Current run state.
    pub state: RunState,
    /// Optional progress percentage.
    pub progress: Option<u8>,
}

/// A transcript entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptEntry {
    /// Speaker or source.
    pub role: String,
    /// Sanitized text.
    pub text: String,
}

/// One tool execution timeline entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolActivity {
    /// Tool name.
    pub name: String,
    /// Current tool status.
    pub status: String,
    /// Redacted activity summary.
    pub summary: String,
}

/// A pending interactive request from an agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Prompt {
    /// An execution approval.
    Approval {
        /// Gateway request identifier.
        id: String,
        /// Human-readable request.
        text: String,
        /// Fingerprint of the complete authenticated preview; absent previews cannot be approved.
        preview_fingerprint: Option<String>,
    },
    /// A question requiring text input.
    Question {
        /// Gateway question identifier.
        id: String,
        /// Human-readable question.
        text: String,
    },
}

/// Top-level terminal screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Screen {
    /// Session navigation.
    Sessions,
    /// Selected session transcript and tools.
    Workspace,
    /// Cross-session run state monitor.
    Runs,
    /// Workspace diff viewer.
    Diff,
    /// Session artifact viewer.
    Artifacts,
    /// Keyboard reference.
    Help,
    /// Bounded cached provider model catalogue.
    Models,
}

impl Screen {
    pub(crate) const ALL: [Self; 7] = [
        Self::Sessions,
        Self::Workspace,
        Self::Runs,
        Self::Diff,
        Self::Artifacts,
        Self::Help,
        Self::Models,
    ];

    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::Sessions => "Sessions",
            Self::Workspace => "Workspace",
            Self::Runs => "Runs",
            Self::Diff => "Diff",
            Self::Artifacts => "Artifacts",
            Self::Help => "Help",
            Self::Models => "Models",
        }
    }
}

/// Complete state consumed synchronously by the render thread.
#[derive(Clone, Debug)]
pub struct PendingMessage {
    /// Session selected for this exact input.
    pub session_id: String,
    /// Original text retained until a definitive receipt.
    pub text: String,
    /// Original random idempotency identity, reused only on explicit retry.
    pub idempotency_key: String,
    /// A previous attempt has no definitive receipt.
    pub unconfirmed: bool,
    /// At least one attempt might have reached the server, retained across refused retries.
    pub may_have_been_sent: bool,
    /// Structured operation retained without converting its content into a chat message.
    pub memory: Option<crate::gateway::MemoryCommand>,
}

impl PendingMessage {
    pub(crate) fn command(&self) -> crate::gateway::UiCommand {
        self.memory.as_ref().map_or_else(
            || crate::gateway::UiCommand::SendMessage {
                session_id: self.session_id.clone(),
                text: self.text.clone(),
                idempotency_key: self.idempotency_key.clone(),
            },
            |command| crate::gateway::UiCommand::InvokeMemory {
                session_id: self.session_id.clone(),
                command: command.clone(),
                idempotency_key: self.idempotency_key.clone(),
            },
        )
    }
}

/// Complete state consumed synchronously by the render thread.
#[derive(Debug)]
pub struct AppModel {
    /// Visible screen.
    pub screen: Screen,
    /// Gateway connection summary.
    pub connection: String,
    /// Ready worker connection observed by the render loop; cleared on disconnect.
    pub connection_id: Option<u64>,
    /// Known sessions.
    pub sessions: Vec<SessionSummary>,
    /// Selected session index.
    pub selected: usize,
    /// Streaming transcript.
    pub transcript: VecDeque<TranscriptEntry>,
    /// Tool activity timeline.
    pub tools: VecDeque<ToolActivity>,
    /// Pending approval or question.
    pub prompt: Option<Prompt>,
    /// Current unified diff.
    pub diff: Vec<String>,
    /// Artifact names.
    pub artifacts: Vec<String>,
    /// Preview lines for the selected artifact.
    pub artifact_content: Vec<String>,
    /// Whether the command palette is open.
    pub palette_open: bool,
    /// Command palette input.
    pub palette: String,
    /// Text input for a pending question.
    pub answer: String,
    /// Current status or error notice.
    pub notice: Option<String>,
    /// Vertical scroll offset.
    pub scroll: usize,
    /// Independent scroll position for the fixed approval preview.
    pub approval_scroll: usize,
    /// Last rendered terminal dimensions used to refuse unseen approval content.
    pub viewport: (u16, u16),
    /// Observed native run for the selected session.
    pub active_run: Option<(String, String)>,
    /// Monotonic turn and revision of the currently displayed native run.
    pub active_run_version: Option<(Option<u64>, u64)>,
    /// Last explicitly viewed partial page, never eligible for acknowledgement.
    pub partial_page: Option<crate::gateway::PartialPage>,
    /// Explicitly viewed provider rounds, never eligible for acknowledgement.
    pub accounting_page: Option<crate::gateway::AccountingPage>,
    /// Observed usage for the selected native run; absence is not zero cost.
    pub provider_accounting: Option<claw_protocol::native_accounting::ProviderAccounting>,
    /// One validated provider catalogue page for the current connection.
    pub model_catalogue: Option<serde_json::Value>,
    /// Single in-flight catalogue request, independent of chat submission.
    pub pending_catalogue: Option<crate::gateway::ModelCatalogueRequest>,
    /// Monotonic catalogue request identity, never reset on reconnect.
    pub catalogue_sequence: u64,
    /// Explicit local file work, retained independently of Gateway connection/session resets.
    pub local_configuration: crate::local_configuration::LocalConfiguration,
    /// Complete results eligible for acknowledgement only after workspace rendering.
    pub pending_acks: VecDeque<(String, u64)>,
    /// Bounded identities of terminal results already added to this session view.
    pub received_results: VecDeque<(String, u64)>,
    /// Session with another recovery page, advanced only after rendering the current page.
    pub pending_recovery: Option<String>,
    /// Whether message input currently owns ordinary character keys.
    pub composer_open: bool,
    /// Bounded unsent message text.
    pub composer: String,
    /// Explicit memory input bound to the session selected when editing began.
    pub memory_draft: Option<(String, crate::gateway::MemoryDraft)>,
    /// A queued or unconfirmed message that cannot be replaced by another send.
    pub pending_message: Option<PendingMessage>,
}

impl Default for AppModel {
    fn default() -> Self {
        Self {
            screen: Screen::Sessions,
            connection: "Gateway: starting".to_owned(),
            connection_id: None,
            sessions: Vec::new(),
            selected: 0,
            transcript: VecDeque::new(),
            tools: VecDeque::new(),
            prompt: None,
            diff: Vec::new(),
            artifacts: Vec::new(),
            artifact_content: Vec::new(),
            palette_open: false,
            palette: String::new(),
            answer: String::new(),
            notice: None,
            scroll: 0,
            approval_scroll: 0,
            viewport: (0, 0),
            active_run: None,
            active_run_version: None,
            partial_page: None,
            accounting_page: None,
            provider_accounting: None,
            model_catalogue: None,
            pending_catalogue: None,
            catalogue_sequence: 0,
            local_configuration: crate::local_configuration::LocalConfiguration::default(),
            pending_acks: VecDeque::new(),
            received_results: VecDeque::new(),
            pending_recovery: None,
            composer_open: false,
            composer: String::new(),
            memory_draft: None,
            pending_message: None,
        }
    }
}

impl AppModel {
    /// Returns the selected session.
    #[must_use]
    pub fn selected_session(&self) -> Option<&SessionSummary> {
        self.sessions.get(self.selected)
    }

    pub(crate) fn next_screen(&mut self) {
        let index = Screen::ALL
            .iter()
            .position(|screen| *screen == self.screen)
            .unwrap_or(0);
        self.screen = Screen::ALL[(index + 1) % Screen::ALL.len()];
        self.scroll = 0;
    }

    pub(crate) fn select_next(&mut self) {
        if !self.sessions.is_empty() {
            let next = (self.selected + 1).min(self.sessions.len() - 1);
            if self.selected != next {
                self.selected = next;
                self.clear_session_view();
            }
        }
    }

    pub(crate) fn select_previous(&mut self) {
        let previous = self.selected.saturating_sub(1);
        if self.selected != previous {
            self.selected = previous;
            self.clear_session_view();
        }
    }

    pub(crate) fn clear_session_view(&mut self) {
        if self.memory_draft.is_some() {
            self.composer_open = false;
        }
        self.transcript.clear();
        self.tools.clear();
        self.prompt = None;
        self.answer.clear();
        self.diff.clear();
        self.artifacts.clear();
        self.artifact_content.clear();
        self.active_run = None;
        self.active_run_version = None;
        self.partial_page = None;
        self.accounting_page = None;
        self.provider_accounting = None;
        self.pending_acks.clear();
        self.received_results.clear();
        self.pending_recovery = None;
        self.scroll = 0;
        self.approval_scroll = 0;
    }

    /// Rows the active screen can scroll through.
    fn scrollable_rows(&self) -> usize {
        match self.screen {
            Screen::Sessions | Screen::Runs => self.sessions.len(),
            Screen::Workspace => crate::render::transcript_row_count(self),
            Screen::Diff => self.diff.len(),
            Screen::Artifacts => self.artifacts.len().max(self.artifact_content.len()),
            Screen::Help => 0,
            Screen::Models => crate::render::model_catalogue_row_count(self),
        }
    }

    /// Moves the viewport toward the end of the content.
    ///
    /// The transcript is anchored to its newest line, so there `scroll` counts
    /// rows of scrollback and moving forward means scrolling *less* far back.
    /// Every other screen indexes from the top. Scrolling is clamped so the
    /// viewport can never run past the content into a blank screen.
    pub(crate) fn scroll_forward(&mut self) {
        self.scroll = if self.screen == Screen::Workspace {
            self.scroll.saturating_sub(1)
        } else {
            self.scroll
                .saturating_add(1)
                .min(self.scrollable_rows().saturating_sub(1))
        };
    }

    /// Moves the viewport toward the start of the content.
    pub(crate) fn scroll_back(&mut self) {
        self.scroll = if self.screen == Screen::Workspace {
            self.scroll
                .saturating_add(1)
                .min(self.scrollable_rows().saturating_sub(1))
        } else {
            self.scroll.saturating_sub(1)
        };
    }
}

#[cfg(test)]
mod tests {
    use super::{AppModel, Screen, TranscriptEntry};

    fn model_with(screen: Screen, rows: usize) -> AppModel {
        let mut model = AppModel {
            screen,
            ..AppModel::default()
        };
        model.diff = (0..rows).map(|row| format!("line {row}")).collect();
        for row in 0..rows {
            model.transcript.push_back(TranscriptEntry {
                role: "agent".to_owned(),
                text: format!("line {row}"),
            });
        }
        model
    }

    #[test]
    fn scrolling_stops_at_the_end_of_the_content() {
        let mut model = model_with(Screen::Diff, 3);
        for _ in 0..100 {
            model.scroll_forward();
        }
        assert_eq!(model.scroll, 2);
        for _ in 0..100 {
            model.scroll_back();
        }
        assert_eq!(model.scroll, 0);
    }

    #[test]
    fn an_empty_screen_never_scrolls_into_blank_space() {
        let mut model = model_with(Screen::Diff, 0);
        model.scroll_forward();
        assert_eq!(model.scroll, 0);

        let mut help = model_with(Screen::Help, 5);
        help.scroll_forward();
        assert_eq!(help.scroll, 0);
    }

    #[test]
    fn the_transcript_scrolls_back_into_history_and_forward_to_the_newest_line() {
        let mut model = model_with(Screen::Workspace, 4);
        model.scroll_back();
        model.scroll_back();
        assert_eq!(model.scroll, 2, "scrolling back moves into older output");
        model.scroll_forward();
        assert_eq!(
            model.scroll, 1,
            "scrolling forward returns toward the newest"
        );
        for _ in 0..10 {
            model.scroll_back();
        }
        assert_eq!(model.scroll, 3, "scrollback stops at the oldest line");
    }

    #[test]
    fn an_unknown_run_state_is_never_reported_as_progress() {
        assert_eq!(
            super::RunState::parse("nonsense-from-a-newer-gateway"),
            super::RunState::UNKNOWN
        );
    }
}

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
    pub const ALL: [Self; 12] = [
        Self::Draft,
        Self::Queued,
        Self::Starting,
        Self::Running,
        Self::WaitingForApproval,
        Self::WaitingForAnswer,
        Self::Paused,
        Self::Blocked,
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
}

impl Screen {
    pub(crate) const ALL: [Self; 6] = [
        Self::Sessions,
        Self::Workspace,
        Self::Runs,
        Self::Diff,
        Self::Artifacts,
        Self::Help,
    ];

    pub(crate) const fn title(self) -> &'static str {
        match self {
            Self::Sessions => "Sessions",
            Self::Workspace => "Workspace",
            Self::Runs => "Runs",
            Self::Diff => "Diff",
            Self::Artifacts => "Artifacts",
            Self::Help => "Help",
        }
    }
}

/// Complete state consumed synchronously by the render thread.
#[derive(Debug)]
pub struct AppModel {
    /// Visible screen.
    pub screen: Screen,
    /// Gateway connection summary.
    pub connection: String,
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
}

impl Default for AppModel {
    fn default() -> Self {
        Self {
            screen: Screen::Sessions,
            connection: "Gateway: starting".to_owned(),
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
            self.selected = (self.selected + 1).min(self.sessions.len() - 1);
        }
    }

    pub(crate) const fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Rows the active screen can scroll through.
    fn scrollable_rows(&self) -> usize {
        match self.screen {
            Screen::Sessions | Screen::Runs => self.sessions.len(),
            Screen::Workspace => self.transcript.len(),
            Screen::Diff => self.diff.len(),
            Screen::Artifacts => self.artifacts.len().max(self.artifact_content.len()),
            Screen::Help => 0,
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

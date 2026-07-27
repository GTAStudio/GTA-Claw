use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

/// Upper bound on the per-run history a session keeps in memory and renders.
const MAX_SESSION_HISTORY: usize = 200;

pub(crate) const PRIMARY_DESTINATIONS: [PrimaryDestination; 7] = [
    PrimaryDestination::Focus,
    PrimaryDestination::Workspaces,
    PrimaryDestination::Runs,
    PrimaryDestination::Schedules,
    PrimaryDestination::Deliverables,
    PrimaryDestination::Extensions,
    PrimaryDestination::Settings,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OnboardingStage {
    Welcome,
    DeviceAuthorization,
    WorkspaceTrust,
    GatewayConnection,
}

impl OnboardingStage {
    pub(crate) const fn index(self) -> i32 {
        match self {
            Self::Welcome => 0,
            Self::DeviceAuthorization => 1,
            Self::WorkspaceTrust => 2,
            Self::GatewayConnection => 3,
        }
    }

    pub(crate) const fn from_index(index: i32) -> Option<Self> {
        match index {
            0 => Some(Self::Welcome),
            1 => Some(Self::DeviceAuthorization),
            2 => Some(Self::WorkspaceTrust),
            3 => Some(Self::GatewayConnection),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimaryDestination {
    Focus,
    Workspaces,
    Runs,
    Schedules,
    Deliverables,
    Extensions,
    Settings,
}

impl PrimaryDestination {
    pub(crate) const fn index(self) -> i32 {
        match self {
            Self::Focus => 0,
            Self::Workspaces => 1,
            Self::Runs => 2,
            Self::Schedules => 3,
            Self::Deliverables => 4,
            Self::Extensions => 5,
            Self::Settings => 6,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Focus => "Focus",
            Self::Workspaces => "Workspaces",
            Self::Runs => "Runs",
            Self::Schedules => "Schedules",
            Self::Deliverables => "Deliverables",
            Self::Extensions => "Extensions",
            Self::Settings => "Settings",
        }
    }

    pub(crate) const fn from_index(index: i32) -> Option<Self> {
        match index {
            0 => Some(Self::Focus),
            1 => Some(Self::Workspaces),
            2 => Some(Self::Runs),
            3 => Some(Self::Schedules),
            4 => Some(Self::Deliverables),
            5 => Some(Self::Extensions),
            6 => Some(Self::Settings),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductSurface {
    Primary(PrimaryDestination),
    Session,
    Update,
    Diagnostics,
}

impl ProductSurface {
    pub(crate) const fn screen_index(self) -> i32 {
        match self {
            Self::Primary(destination) => destination.index(),
            Self::Session => 7,
            Self::Update => 8,
            Self::Diagnostics => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunState {
    Draft,
    Queued,
    Starting,
    Running,
    WaitingForApproval,
    WaitingForAnswer,
    Paused,
    Blocked,
    Failed,
    Cancelled,
    Completed,
    CompletedWithChanges,
}

impl RunState {
    pub(crate) const ALL: [Self; 12] = [
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

    pub(crate) const fn label(self) -> &'static str {
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

    pub(crate) const fn tone(self) -> SemanticTone {
        match self {
            Self::Draft | Self::Queued | Self::Paused | Self::Cancelled => SemanticTone::Neutral,
            Self::Starting | Self::Running | Self::WaitingForAnswer => SemanticTone::Info,
            Self::WaitingForApproval | Self::Blocked => SemanticTone::Warning,
            Self::Failed => SemanticTone::Danger,
            Self::Completed | Self::CompletedWithChanges => SemanticTone::Success,
        }
    }

    pub(crate) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Cancelled | Self::Completed | Self::CompletedWithChanges
        )
    }
}

impl Display for RunState {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SemanticTone {
    Neutral,
    Info,
    Warning,
    Danger,
    Success,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunLifecycle {
    state: RunState,
}

impl RunLifecycle {
    pub(crate) const fn new(state: RunState) -> Self {
        Self { state }
    }

    pub(crate) const fn state(&self) -> RunState {
        self.state
    }

    pub(crate) const fn transition(&mut self, next: RunState) -> Result<(), InvalidRunTransition> {
        if is_valid_transition(self.state, next) {
            self.state = next;
            Ok(())
        } else {
            Err(InvalidRunTransition {
                from: self.state,
                to: next,
            })
        }
    }
}

const fn is_valid_transition(from: RunState, to: RunState) -> bool {
    use RunState::{
        Blocked, Cancelled, Completed, CompletedWithChanges, Draft, Failed, Paused, Queued,
        Running, Starting, WaitingForAnswer, WaitingForApproval,
    };

    matches!(
        (from, to),
        (Draft, Queued | Cancelled)
            | (Queued, Starting | Paused | Cancelled)
            | (Starting, Running | Blocked | Failed | Cancelled)
            | (
                Running,
                WaitingForApproval
                    | WaitingForAnswer
                    | Paused
                    | Blocked
                    | Failed
                    | Cancelled
                    | Completed
                    | CompletedWithChanges
            )
            | (
                WaitingForApproval | WaitingForAnswer,
                Running | Paused | Failed | Cancelled
            )
            | (Paused, Queued | Running | Cancelled)
            | (Blocked, Queued | Failed | Cancelled)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidRunTransition {
    from: RunState,
    to: RunState,
}

impl Display for InvalidRunTransition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot transition a run from {} to {}",
            self.from, self.to
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunSummary {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) workspace: String,
    pub(crate) state: RunState,
    pub(crate) detail: String,
    pub(crate) updated: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkspaceSummary {
    pub(crate) name: String,
    pub(crate) location: String,
    pub(crate) kind: String,
    pub(crate) branch: String,
    pub(crate) active_runs: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScheduleSummary {
    pub(crate) name: String,
    pub(crate) cadence: String,
    pub(crate) next_run: String,
    pub(crate) enabled: bool,
    pub(crate) workspace: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeliverableSummary {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) source: String,
    pub(crate) size: String,
    pub(crate) pinned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExtensionSummary {
    pub(crate) name: String,
    pub(crate) category: String,
    pub(crate) detail: String,
    pub(crate) permission: String,
    pub(crate) enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TranscriptRole {
    User,
    Assistant,
    Activity,
    System,
}

impl TranscriptRole {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::User => "You",
            Self::Assistant => "GTA Claw",
            Self::Activity => "Tool activity",
            Self::System => "System",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TranscriptEntry {
    pub(crate) role: TranscriptRole,
    pub(crate) text: String,
    pub(crate) detail: String,
    pub(crate) timestamp: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActivityEntry {
    pub(crate) title: String,
    pub(crate) detail: String,
    pub(crate) state: RunState,
    pub(crate) duration: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiffMode {
    Unified,
    SideBySide,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChangeKind {
    Context,
    Added,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiffLine {
    pub(crate) old_line: Option<u32>,
    pub(crate) new_line: Option<u32>,
    pub(crate) kind: ChangeKind,
    pub(crate) text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionFile {
    pub(crate) name: String,
    pub(crate) status: String,
    diff: Vec<DiffLine>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunSessionData {
    transcript: Vec<TranscriptEntry>,
    activity: Vec<ActivityEntry>,
    files: Vec<SessionFile>,
    selected_file: usize,
    approval_prompt: String,
    approval_scope: String,
    question: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SideBySideLine {
    pub(crate) old_line: Option<u32>,
    pub(crate) old_text: String,
    pub(crate) new_line: Option<u32>,
    pub(crate) new_text: String,
    pub(crate) kind: ChangeKind,
}

pub(crate) fn render_unified(lines: &[DiffLine]) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            let marker = match line.kind {
                ChangeKind::Context => ' ',
                ChangeKind::Added => '+',
                ChangeKind::Removed => '-',
            };
            format!("{marker}{}", line.text)
        })
        .collect()
}

pub(crate) fn render_side_by_side(lines: &[DiffLine]) -> Vec<SideBySideLine> {
    let mut rendered = Vec::with_capacity(lines.len());
    let mut index = 0;
    while index < lines.len() {
        let line = &lines[index];
        if line.kind == ChangeKind::Removed {
            let removed_start = index;
            while index < lines.len() && lines[index].kind == ChangeKind::Removed {
                index += 1;
            }
            let added_start = index;
            while index < lines.len() && lines[index].kind == ChangeKind::Added {
                index += 1;
            }
            let removed = &lines[removed_start..added_start];
            let added = &lines[added_start..index];
            let row_count = usize::max(removed.len(), added.len());
            for offset in 0..row_count {
                let old = removed.get(offset);
                let new = added.get(offset);
                rendered.push(SideBySideLine {
                    old_line: old.and_then(|entry| entry.old_line),
                    old_text: old.map_or_else(String::new, |entry| entry.text.clone()),
                    new_line: new.and_then(|entry| entry.new_line),
                    new_text: new.map_or_else(String::new, |entry| entry.text.clone()),
                    kind: if new.is_some() {
                        ChangeKind::Added
                    } else {
                        ChangeKind::Removed
                    },
                });
            }
            continue;
        }

        let (old_line, old_text, new_line, new_text) = match line.kind {
            ChangeKind::Context => (
                line.old_line,
                line.text.clone(),
                line.new_line,
                line.text.clone(),
            ),
            ChangeKind::Added => (None, String::new(), line.new_line, line.text.clone()),
            ChangeKind::Removed => (line.old_line, line.text.clone(), None, String::new()),
        };
        rendered.push(SideBySideLine {
            old_line,
            old_text,
            new_line,
            new_text,
            kind: line.kind,
        });
        index += 1;
    }
    rendered
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PagedModel<T> {
    rows: Vec<T>,
    page_size: usize,
    page: usize,
}

impl<T> PagedModel<T> {
    pub(crate) fn new(rows: Vec<T>, page_size: usize) -> Self {
        assert!(page_size > 0, "page size must be positive");
        Self {
            rows,
            page_size,
            page: 0,
        }
    }

    pub(crate) const fn page(&self) -> usize {
        self.page
    }

    pub(crate) const fn page_size(&self) -> usize {
        self.page_size
    }

    pub(crate) const fn page_count(&self) -> usize {
        self.rows.len().div_ceil(self.page_size)
    }

    pub(crate) fn visible(&self) -> &[T] {
        let start = self.page.saturating_mul(self.page_size);
        let end = usize::min(start + self.page_size, self.rows.len());
        &self.rows[start..end]
    }

    pub(crate) const fn next_page(&mut self) -> bool {
        if self.page + 1 < self.page_count() {
            self.page += 1;
            true
        } else {
            false
        }
    }

    pub(crate) const fn previous_page(&mut self) -> bool {
        if self.page > 0 {
            self.page -= 1;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccessibilityNode {
    pub(crate) role: String,
    pub(crate) label: String,
    pub(crate) description: String,
    pub(crate) live: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductState {
    onboarding_stage: OnboardingStage,
    surface: ProductSurface,
    focused_run: RunLifecycle,
    selected_run: RunSummary,
    selected_deliverable: usize,
    palette_open: bool,
    diff_mode: DiffMode,
    selected_settings_section: usize,
    runs: PagedModel<RunSummary>,
    workspaces: Vec<WorkspaceSummary>,
    schedules: Vec<ScheduleSummary>,
    deliverables: Vec<DeliverableSummary>,
    extensions: Vec<ExtensionSummary>,
    sessions: BTreeMap<String, RunSessionData>,
}

impl Default for ProductState {
    fn default() -> Self {
        let runs = demo_runs();
        let selected_run = runs
            .iter()
            .find(|run| run.state == RunState::WaitingForApproval)
            .cloned()
            .expect("demo runs include an approval request");
        let sessions = runs
            .iter()
            .map(|run| (run.id.clone(), demo_session(run)))
            .collect();
        Self {
            onboarding_stage: OnboardingStage::Welcome,
            surface: ProductSurface::Primary(PrimaryDestination::Focus),
            focused_run: RunLifecycle::new(selected_run.state),
            selected_run,
            selected_deliverable: 0,
            palette_open: false,
            diff_mode: DiffMode::Unified,
            selected_settings_section: 0,
            runs: PagedModel::new(runs, 24),
            workspaces: demo_workspaces(),
            schedules: demo_schedules(),
            deliverables: demo_deliverables(),
            extensions: demo_extensions(),
            sessions,
        }
    }
}

impl ProductState {
    pub(crate) const fn onboarding_stage(&self) -> OnboardingStage {
        self.onboarding_stage
    }

    pub(crate) const fn surface(&self) -> ProductSurface {
        self.surface
    }

    pub(crate) const fn palette_open(&self) -> bool {
        self.palette_open
    }

    pub(crate) const fn diff_mode(&self) -> DiffMode {
        self.diff_mode
    }

    pub(crate) const fn selected_settings_section(&self) -> usize {
        self.selected_settings_section
    }

    pub(crate) const fn runs(&self) -> &PagedModel<RunSummary> {
        &self.runs
    }

    pub(crate) const fn selected_run(&self) -> &RunSummary {
        &self.selected_run
    }

    pub(crate) fn workspaces(&self) -> &[WorkspaceSummary] {
        &self.workspaces
    }

    pub(crate) fn schedules(&self) -> &[ScheduleSummary] {
        &self.schedules
    }

    pub(crate) fn deliverables(&self) -> &[DeliverableSummary] {
        &self.deliverables
    }

    pub(crate) fn selected_deliverable(&self) -> &DeliverableSummary {
        &self.deliverables[self.selected_deliverable]
    }

    pub(crate) const fn selected_deliverable_index(&self) -> usize {
        self.selected_deliverable
    }

    pub(crate) const fn selected_deliverable_content(&self) -> &'static str {
        match self.selected_deliverable {
            0 => {
                "Native desktop architecture\n\n• Rust owns application state\n• Slint provides typed presentation adapters\n• Tokio runs Gateway work off the UI thread\n• Approval and diff review remain explicit"
            }
            1 => {
                "Image preview\n\nSettings screen at 1080 × 720 logical pixels.\nTheme: light · Density: 100% · Accessibility labels: active"
            }
            _ => {
                "{\n  \"gateway\": \"healthy\",\n  \"renderer\": \"software-fallback-ready\",\n  \"accessibility\": \"active\"\n}"
            }
        }
    }

    pub(crate) fn extensions(&self) -> &[ExtensionSummary] {
        &self.extensions
    }

    pub(crate) fn transcript(&self) -> &[TranscriptEntry] {
        &self.selected_session().transcript
    }

    pub(crate) fn activity(&self) -> &[ActivityEntry] {
        &self.selected_session().activity
    }

    pub(crate) fn session_files(&self) -> &[SessionFile] {
        &self.selected_session().files
    }

    pub(crate) fn selected_file_index(&self) -> usize {
        self.sessions
            .get(&self.selected_run.id)
            .expect("every run has session data")
            .selected_file
    }

    pub(crate) fn selected_file_name(&self) -> &str {
        let session = self.selected_session();
        &session.files[session.selected_file].name
    }

    pub(crate) fn diff(&self) -> &[DiffLine] {
        let session = self.selected_session();
        &session.files[session.selected_file].diff
    }

    pub(crate) fn approval_prompt(&self) -> &str {
        &self.selected_session().approval_prompt
    }

    pub(crate) fn approval_scope(&self) -> &str {
        &self.selected_session().approval_scope
    }

    pub(crate) fn question(&self) -> &str {
        &self.selected_session().question
    }

    pub(crate) const fn select_destination(&mut self, destination: PrimaryDestination) {
        self.surface = ProductSurface::Primary(destination);
    }

    pub(crate) const fn select_onboarding_stage(&mut self, stage: OnboardingStage) {
        self.onboarding_stage = stage;
    }

    pub(crate) fn open_session(&mut self, visible_index: usize) {
        if let Some(run) = self.runs.visible().get(visible_index).cloned() {
            self.focused_run = RunLifecycle::new(run.state);
            self.selected_run = run;
        }
        self.surface = ProductSurface::Session;
    }

    pub(crate) fn open_workspace(&mut self, workspace_index: usize) -> bool {
        let Some(workspace) = self.workspaces.get(workspace_index) else {
            return false;
        };
        let Some(run) = self
            .runs
            .rows
            .iter()
            .find(|run| run.workspace == workspace.name)
            .cloned()
        else {
            return false;
        };
        self.focused_run = RunLifecycle::new(run.state);
        self.selected_run = run;
        self.surface = ProductSurface::Session;
        true
    }

    pub(crate) const fn open_update(&mut self) {
        self.surface = ProductSurface::Update;
    }

    pub(crate) const fn open_diagnostics(&mut self) {
        self.surface = ProductSurface::Diagnostics;
    }

    pub(crate) const fn return_from_auxiliary(&mut self) {
        self.surface = match self.surface {
            ProductSurface::Session => ProductSurface::Primary(PrimaryDestination::Runs),
            ProductSurface::Update | ProductSurface::Diagnostics => {
                ProductSurface::Primary(PrimaryDestination::Settings)
            }
            ProductSurface::Primary(destination) => ProductSurface::Primary(destination),
        };
    }

    pub(crate) const fn toggle_palette(&mut self) {
        self.palette_open = !self.palette_open;
    }

    pub(crate) const fn close_palette(&mut self) {
        self.palette_open = false;
    }

    pub(crate) const fn set_diff_mode(&mut self, mode: DiffMode) {
        self.diff_mode = mode;
    }

    pub(crate) fn select_settings_section(&mut self, index: usize) {
        self.selected_settings_section = index.min(7);
    }

    pub(crate) fn toggle_schedule(&mut self, index: usize) {
        if let Some(schedule) = self.schedules.get_mut(index) {
            if !schedule.enabled && schedule.next_run == "Not scheduled" {
                return;
            }
            schedule.enabled = !schedule.enabled;
        }
    }

    pub(crate) fn create_schedule(&mut self) {
        let number = self.schedules.len() + 1;
        self.schedules.push(ScheduleSummary {
            name: format!("New schedule {number}"),
            cadence: "Choose a cadence".to_owned(),
            next_run: "Not scheduled".to_owned(),
            enabled: false,
            workspace: self.workspaces[0].name.clone(),
        });
    }

    pub(crate) fn toggle_extension(&mut self, index: usize) {
        if let Some(extension) = self.extensions.get_mut(index) {
            extension.enabled = !extension.enabled;
        }
    }

    pub(crate) const fn select_deliverable(&mut self, index: usize) {
        if index < self.deliverables.len() {
            self.selected_deliverable = index;
        }
    }

    pub(crate) fn toggle_selected_deliverable_pin(&mut self) {
        self.deliverables[self.selected_deliverable].pinned =
            !self.deliverables[self.selected_deliverable].pinned;
    }

    pub(crate) fn select_session_file(&mut self, index: usize) {
        let session = self.selected_session_mut();
        if index < session.files.len() {
            session.selected_file = index;
        }
    }

    pub(crate) fn record_message(
        &mut self,
        role: TranscriptRole,
        text: impl Into<String>,
        detail: impl Into<String>,
    ) {
        let transcript = &mut self.selected_session_mut().transcript;
        transcript.push(TranscriptEntry {
            role,
            text: text.into(),
            detail: detail.into(),
            timestamp: "Now".to_owned(),
        });
        if transcript.len() > MAX_SESSION_HISTORY {
            transcript.remove(0);
        }
    }

    pub(crate) fn resolve_approval(
        &mut self,
        approved: bool,
    ) -> Result<RunState, InvalidRunTransition> {
        if self.focused_run.state().is_terminal() {
            return Err(InvalidRunTransition {
                from: self.focused_run.state(),
                to: if approved {
                    RunState::Running
                } else {
                    RunState::Cancelled
                },
            });
        }
        let next = if approved {
            RunState::Running
        } else {
            RunState::Cancelled
        };
        self.focused_run.transition(next)?;
        self.selected_run.state = next;
        self.selected_run.detail = if approved {
            "Approval recorded; execution resumed".to_owned()
        } else {
            "Approval denied; execution cancelled".to_owned()
        };
        "Now".clone_into(&mut self.selected_run.updated);
        self.persist_selected_run();
        self.record_transition_activity(if approved {
            "Approval granted"
        } else {
            "Approval denied"
        });
        Ok(next)
    }

    pub(crate) fn answer_question(
        &mut self,
        answer: &str,
    ) -> Result<RunState, InvalidRunTransition> {
        let next = if answer == "Pause run" {
            RunState::Paused
        } else {
            RunState::Running
        };
        self.focused_run.transition(next)?;
        self.selected_run.state = next;
        self.selected_run.detail = if next == RunState::Paused {
            "Answer recorded; execution paused".to_owned()
        } else {
            "Answer recorded; execution resumed".to_owned()
        };
        "Now".clone_into(&mut self.selected_run.updated);
        self.persist_selected_run();
        self.record_transition_activity(if next == RunState::Paused {
            "Run paused by answer"
        } else {
            "Answer received"
        });
        Ok(next)
    }

    fn persist_selected_run(&mut self) {
        if let Some(run) = self
            .runs
            .rows
            .iter_mut()
            .find(|run| run.id == self.selected_run.id)
        {
            run.clone_from(&self.selected_run);
        }
    }

    fn selected_session(&self) -> &RunSessionData {
        self.sessions
            .get(&self.selected_run.id)
            .expect("every run has session data")
    }

    fn selected_session_mut(&mut self) -> &mut RunSessionData {
        self.sessions
            .get_mut(&self.selected_run.id)
            .expect("every run has session data")
    }

    fn record_transition_activity(&mut self, title: &str) {
        let state = self.selected_run.state;
        let detail = self.selected_run.detail.clone();
        let activity = &mut self.selected_session_mut().activity;
        activity.push(ActivityEntry {
            title: title.to_owned(),
            detail,
            state,
            duration: "Now".to_owned(),
        });
        if activity.len() > MAX_SESSION_HISTORY {
            activity.remove(0);
        }
    }

    pub(crate) const fn next_run_page(&mut self) -> bool {
        self.runs.next_page()
    }

    pub(crate) const fn previous_run_page(&mut self) -> bool {
        self.runs.previous_page()
    }

    pub(crate) fn keyboard_order() -> Vec<String> {
        let mut order = PRIMARY_DESTINATIONS
            .iter()
            .map(|destination| destination.label().to_owned())
            .collect::<Vec<_>>();
        order.extend([
            "Command palette".to_owned(),
            "Primary content".to_owned(),
            "Context inspector".to_owned(),
        ]);
        order
    }

    pub(crate) fn accessibility_nodes() -> Vec<AccessibilityNode> {
        vec![
            AccessibilityNode {
                role: "navigation".to_owned(),
                label: "Primary navigation".to_owned(),
                description: "Seven application destinations".to_owned(),
                live: "off".to_owned(),
            },
            AccessibilityNode {
                role: "main".to_owned(),
                label: "Primary content".to_owned(),
                description: "Selected GTA Claw workspace surface".to_owned(),
                live: "off".to_owned(),
            },
            AccessibilityNode {
                role: "status".to_owned(),
                label: "Run status".to_owned(),
                description: "Auditable run lifecycle updates".to_owned(),
                live: "polite".to_owned(),
            },
            AccessibilityNode {
                role: "alert".to_owned(),
                label: "Approval request".to_owned(),
                description: "Explicit permission required before execution".to_owned(),
                live: "assertive".to_owned(),
            },
        ]
    }
}

fn demo_runs() -> Vec<RunSummary> {
    (0..10)
        .flat_map(|copy| {
            RunState::ALL
                .into_iter()
                .enumerate()
                .map(move |(state_index, state)| RunSummary {
                    id: format!("run-{:02}-{:02}", state_index + 1, copy + 1),
                    title: format!("{} workflow {}", state.label(), copy + 1),
                    workspace: match copy % 3 {
                        0 => "GTA-Claw",
                        1 => "Gateway lab",
                        _ => "Release workspace",
                    }
                    .to_owned(),
                    state,
                    detail: match state {
                        RunState::WaitingForApproval => {
                            "Review requested command and affected files".to_owned()
                        }
                        RunState::WaitingForAnswer => "Agent needs a workspace decision".to_owned(),
                        RunState::CompletedWithChanges => {
                            "Generated a reviewed change set".to_owned()
                        }
                        _ => format!(
                            "Auditable {} lifecycle summary",
                            state.label().to_lowercase()
                        ),
                    },
                    updated: format!("{}m ago", state_index * 3 + copy + 1),
                })
        })
        .collect()
}

fn demo_workspaces() -> Vec<WorkspaceSummary> {
    vec![
        WorkspaceSummary {
            name: "GTA-Claw".to_owned(),
            location: r"C:\work\GTA-Claw".to_owned(),
            kind: "Git repository".to_owned(),
            branch: "desktop-slint-application".to_owned(),
            active_runs: 3,
        },
        WorkspaceSummary {
            name: "Gateway lab".to_owned(),
            location: r"D:\labs\gateway-double".to_owned(),
            kind: "Local directory".to_owned(),
            branch: "Not versioned".to_owned(),
            active_runs: 1,
        },
        WorkspaceSummary {
            name: "Release workspace".to_owned(),
            location: "ssh://builder/release".to_owned(),
            kind: "Remote workspace".to_owned(),
            branch: "main".to_owned(),
            active_runs: 0,
        },
    ]
}

fn demo_schedules() -> Vec<ScheduleSummary> {
    vec![
        ScheduleSummary {
            name: "Dependency health".to_owned(),
            cadence: "Weekdays at 09:00".to_owned(),
            next_run: "Monday, 09:00".to_owned(),
            enabled: true,
            workspace: "GTA-Claw".to_owned(),
        },
        ScheduleSummary {
            name: "Nightly diagnostics".to_owned(),
            cadence: "Daily at 01:30".to_owned(),
            next_run: "Tomorrow, 01:30".to_owned(),
            enabled: true,
            workspace: "Gateway lab".to_owned(),
        },
        ScheduleSummary {
            name: "Release notes".to_owned(),
            cadence: "Every Friday".to_owned(),
            next_run: "Friday, 16:00".to_owned(),
            enabled: false,
            workspace: "Release workspace".to_owned(),
        },
    ]
}

fn demo_deliverables() -> Vec<DeliverableSummary> {
    vec![
        DeliverableSummary {
            name: "desktop-architecture.md".to_owned(),
            kind: "Document".to_owned(),
            source: "Run run-12-01".to_owned(),
            size: "18 KB".to_owned(),
            pinned: true,
        },
        DeliverableSummary {
            name: "settings-screen.png".to_owned(),
            kind: "Image".to_owned(),
            source: "Run run-11-02".to_owned(),
            size: "412 KB".to_owned(),
            pinned: true,
        },
        DeliverableSummary {
            name: "diagnostics.json".to_owned(),
            kind: "Structured data".to_owned(),
            source: "Gateway lab".to_owned(),
            size: "7 KB".to_owned(),
            pinned: false,
        },
    ]
}

fn demo_extensions() -> Vec<ExtensionSummary> {
    vec![
        ExtensionSummary {
            name: "Desktop engineer".to_owned(),
            category: "Role".to_owned(),
            detail: "Rust, Slint, testing, and release workflow".to_owned(),
            permission: "Workspace read/write".to_owned(),
            enabled: true,
        },
        ExtensionSummary {
            name: "Accessibility audit".to_owned(),
            category: "Skill".to_owned(),
            detail: "Keyboard, contrast, labels, and live-region checks".to_owned(),
            permission: "Workspace read".to_owned(),
            enabled: true,
        },
        ExtensionSummary {
            name: "GitHub".to_owned(),
            category: "Connector".to_owned(),
            detail: "Issues, pull requests, and repository metadata".to_owned(),
            permission: "Ask before write".to_owned(),
            enabled: true,
        },
        ExtensionSummary {
            name: "Local shell".to_owned(),
            category: "Permission".to_owned(),
            detail: "Bounded commands in trusted workspaces".to_owned(),
            permission: "Per-command approval".to_owned(),
            enabled: false,
        },
    ]
}

fn demo_session(run: &RunSummary) -> RunSessionData {
    RunSessionData {
        transcript: demo_transcript(run),
        activity: demo_activity(run),
        files: demo_files(run),
        selected_file: 0,
        approval_prompt: format!("Allow '{}' to continue in {}?", run.title, run.workspace),
        approval_scope: format!("Run {} · bounded workspace action", run.id),
        question: format!(
            "{} needs a decision. Continue execution or pause the run?",
            run.title
        ),
    }
}

fn demo_transcript(run: &RunSummary) -> Vec<TranscriptEntry> {
    vec![
        TranscriptEntry {
            role: TranscriptRole::User,
            text: format!("Start {}.", run.title),
            detail: format!("Workspace: {} · Run: {}", run.workspace, run.id),
            timestamp: "13:01".to_owned(),
        },
        TranscriptEntry {
            role: TranscriptRole::Assistant,
            text: format!("I prepared an auditable plan for {}.", run.workspace),
            detail: "Only auditable decisions and activity summaries are shown.".to_owned(),
            timestamp: "13:02".to_owned(),
        },
        TranscriptEntry {
            role: TranscriptRole::Activity,
            text: format!("Inspected inputs for {}.", run.title),
            detail: format!("Current lifecycle state: {}", run.state),
            timestamp: "13:03".to_owned(),
        },
        TranscriptEntry {
            role: TranscriptRole::System,
            text: format!("Run status: {}.", run.state),
            detail: run.detail.clone(),
            timestamp: "13:04".to_owned(),
        },
    ]
}

fn demo_activity(run: &RunSummary) -> Vec<ActivityEntry> {
    vec![
        ActivityEntry {
            title: format!("Inspect {}", run.workspace),
            detail: format!("Loaded inputs for {}", run.id),
            state: RunState::Completed,
            duration: "2s".to_owned(),
        },
        ActivityEntry {
            title: run.title.clone(),
            detail: run.detail.clone(),
            state: run.state,
            duration: if run.state.is_terminal() {
                "Complete".to_owned()
            } else {
                "Active".to_owned()
            },
        },
    ]
}

fn demo_files(run: &RunSummary) -> Vec<SessionFile> {
    let names = match run.workspace.as_str() {
        "Gateway lab" => ["gateway-session.rs", "health-check.rs", "protocol.rs"],
        "Release workspace" => ["release-plan.toml", "notes.md", "signing.rs"],
        _ => ["product-shell.slint", "product_state.rs", "main.rs"],
    };
    names
        .into_iter()
        .enumerate()
        .map(|(index, name)| SessionFile {
            name: name.to_owned(),
            status: if index == 0 {
                "Modified".to_owned()
            } else {
                "Reviewed".to_owned()
            },
            diff: demo_diff(run, name, index),
        })
        .collect()
}

fn demo_diff(run: &RunSummary, file_name: &str, offset: usize) -> Vec<DiffLine> {
    let line = u32::try_from(42 + offset).expect("demo diff line fits in u32");
    vec![
        DiffLine {
            old_line: Some(line),
            new_line: Some(line),
            kind: ChangeKind::Context,
            text: format!("// {} · {}", run.workspace, file_name),
        },
        DiffLine {
            old_line: Some(line + 1),
            new_line: None,
            kind: ChangeKind::Removed,
            text: "let run = \"pending\";".to_owned(),
        },
        DiffLine {
            old_line: None,
            new_line: Some(line + 1),
            kind: ChangeKind::Added,
            text: format!("let run = \"{}\";", run.id),
        },
        DiffLine {
            old_line: Some(line + 2),
            new_line: Some(line + 2),
            kind: ChangeKind::Context,
            text: "apply_reviewed_changes();".to_owned(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_twelve_run_states_have_stable_labels_and_tones() {
        let actual = RunState::ALL
            .into_iter()
            .map(|state| (state.label(), state.tone(), state.is_terminal()))
            .collect::<Vec<_>>();
        let expected = vec![
            ("Draft", SemanticTone::Neutral, false),
            ("Queued", SemanticTone::Neutral, false),
            ("Starting", SemanticTone::Info, false),
            ("Running", SemanticTone::Info, false),
            ("Waiting for approval", SemanticTone::Warning, false),
            ("Waiting for answer", SemanticTone::Info, false),
            ("Paused", SemanticTone::Neutral, false),
            ("Blocked", SemanticTone::Warning, false),
            ("Failed", SemanticTone::Danger, true),
            ("Cancelled", SemanticTone::Neutral, true),
            ("Completed", SemanticTone::Success, true),
            ("Completed with changes", SemanticTone::Success, true),
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn run_lifecycle_accepts_review_round_trip_and_rejects_terminal_mutation() {
        let mut lifecycle = RunLifecycle::new(RunState::Draft);
        assert_eq!(lifecycle.transition(RunState::Queued), Ok(()));
        assert_eq!(lifecycle.transition(RunState::Starting), Ok(()));
        assert_eq!(lifecycle.transition(RunState::Running), Ok(()));
        assert_eq!(lifecycle.transition(RunState::WaitingForApproval), Ok(()));
        assert_eq!(lifecycle.transition(RunState::Running), Ok(()));
        assert_eq!(lifecycle.transition(RunState::CompletedWithChanges), Ok(()));
        assert_eq!(lifecycle.state(), RunState::CompletedWithChanges);
        assert_eq!(
            lifecycle.transition(RunState::Running),
            Err(InvalidRunTransition {
                from: RunState::CompletedWithChanges,
                to: RunState::Running,
            })
        );
    }

    #[test]
    fn pagination_exposes_bounded_exact_pages() {
        let mut model = PagedModel::new((0..7).collect::<Vec<_>>(), 3);
        assert_eq!(model.page(), 0);
        assert_eq!(model.page_size(), 3);
        assert_eq!(model.page_count(), 3);
        assert_eq!(model.visible(), &[0, 1, 2]);
        assert!(model.next_page());
        assert_eq!(model.visible(), &[3, 4, 5]);
        assert!(model.next_page());
        assert_eq!(model.visible(), &[6]);
        assert!(!model.next_page());
        assert!(model.previous_page());
        assert_eq!(model.visible(), &[3, 4, 5]);
    }

    #[test]
    fn diff_renderers_preserve_exact_unified_and_paired_content() {
        let state = ProductState::default();
        assert_eq!(
            render_unified(state.diff()),
            vec![
                " // GTA-Claw · product-shell.slint",
                "-let run = \"pending\";",
                "+let run = \"run-05-01\";",
                " apply_reviewed_changes();",
            ]
        );
        assert_eq!(
            render_side_by_side(state.diff()),
            vec![
                SideBySideLine {
                    old_line: Some(42),
                    old_text: "// GTA-Claw · product-shell.slint".to_owned(),
                    new_line: Some(42),
                    new_text: "// GTA-Claw · product-shell.slint".to_owned(),
                    kind: ChangeKind::Context,
                },
                SideBySideLine {
                    old_line: Some(43),
                    old_text: "let run = \"pending\";".to_owned(),
                    new_line: Some(43),
                    new_text: "let run = \"run-05-01\";".to_owned(),
                    kind: ChangeKind::Added,
                },
                SideBySideLine {
                    old_line: Some(44),
                    old_text: "apply_reviewed_changes();".to_owned(),
                    new_line: Some(44),
                    new_text: "apply_reviewed_changes();".to_owned(),
                    kind: ChangeKind::Context,
                },
            ]
        );
    }

    #[test]
    fn side_by_side_diff_pairs_contiguous_replacement_blocks_by_position() {
        let lines = vec![
            DiffLine {
                old_line: Some(1),
                new_line: None,
                kind: ChangeKind::Removed,
                text: "old one".to_owned(),
            },
            DiffLine {
                old_line: Some(2),
                new_line: None,
                kind: ChangeKind::Removed,
                text: "old two".to_owned(),
            },
            DiffLine {
                old_line: None,
                new_line: Some(1),
                kind: ChangeKind::Added,
                text: "new one".to_owned(),
            },
            DiffLine {
                old_line: None,
                new_line: Some(2),
                kind: ChangeKind::Added,
                text: "new two".to_owned(),
            },
        ];
        assert_eq!(
            render_side_by_side(&lines),
            vec![
                SideBySideLine {
                    old_line: Some(1),
                    old_text: "old one".to_owned(),
                    new_line: Some(1),
                    new_text: "new one".to_owned(),
                    kind: ChangeKind::Added,
                },
                SideBySideLine {
                    old_line: Some(2),
                    old_text: "old two".to_owned(),
                    new_line: Some(2),
                    new_text: "new two".to_owned(),
                    kind: ChangeKind::Added,
                },
            ]
        );
    }

    #[test]
    fn run_activity_history_is_bounded_like_the_transcript() {
        let mut state = ProductState::default();
        assert!(!state.activity().is_empty());
        for index in 0..MAX_SESSION_HISTORY + 5 {
            let answer = if index % 2 == 0 { "" } else { "Pause run" };
            state
                .answer_question(answer)
                .expect("alternating answers stay inside the run lifecycle");
        }
        assert_eq!(state.activity().len(), MAX_SESSION_HISTORY);
        assert_eq!(
            state.activity()[MAX_SESSION_HISTORY - 1].title,
            "Answer received"
        );
    }

    #[test]
    fn keyboard_navigation_order_is_stable_and_complete() {
        assert_eq!(
            ProductState::keyboard_order(),
            vec![
                "Focus",
                "Workspaces",
                "Runs",
                "Schedules",
                "Deliverables",
                "Extensions",
                "Settings",
                "Command palette",
                "Primary content",
                "Context inspector",
            ]
        );
    }

    #[test]
    fn accessibility_metadata_identifies_landmarks_and_live_regions() {
        assert_eq!(
            ProductState::accessibility_nodes(),
            vec![
                AccessibilityNode {
                    role: "navigation".to_owned(),
                    label: "Primary navigation".to_owned(),
                    description: "Seven application destinations".to_owned(),
                    live: "off".to_owned(),
                },
                AccessibilityNode {
                    role: "main".to_owned(),
                    label: "Primary content".to_owned(),
                    description: "Selected GTA Claw workspace surface".to_owned(),
                    live: "off".to_owned(),
                },
                AccessibilityNode {
                    role: "status".to_owned(),
                    label: "Run status".to_owned(),
                    description: "Auditable run lifecycle updates".to_owned(),
                    live: "polite".to_owned(),
                },
                AccessibilityNode {
                    role: "alert".to_owned(),
                    label: "Approval request".to_owned(),
                    description: "Explicit permission required before execution".to_owned(),
                    live: "assertive".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn product_navigation_retains_primary_selection_across_auxiliary_surfaces() {
        let mut state = ProductState::default();
        state.select_destination(PrimaryDestination::Settings);
        assert_eq!(
            state.surface(),
            ProductSurface::Primary(PrimaryDestination::Settings)
        );
        state.open_diagnostics();
        assert_eq!(state.surface(), ProductSurface::Diagnostics);
        state.select_destination(PrimaryDestination::Runs);
        state.open_session(0);
        assert_eq!(state.surface(), ProductSurface::Session);
        state.set_diff_mode(DiffMode::SideBySide);
        assert_eq!(state.diff_mode(), DiffMode::SideBySide);
    }

    #[test]
    fn onboarding_wizard_uses_explicit_forward_and_backward_stages() {
        let mut state = ProductState::default();
        assert_eq!(state.onboarding_stage(), OnboardingStage::Welcome);
        state.select_onboarding_stage(OnboardingStage::DeviceAuthorization);
        assert_eq!(
            state.onboarding_stage(),
            OnboardingStage::DeviceAuthorization
        );
        state.select_onboarding_stage(OnboardingStage::WorkspaceTrust);
        assert_eq!(state.onboarding_stage(), OnboardingStage::WorkspaceTrust);
        state.select_onboarding_stage(OnboardingStage::GatewayConnection);
        assert_eq!(state.onboarding_stage(), OnboardingStage::GatewayConnection);
        state.select_onboarding_stage(OnboardingStage::Welcome);
        assert_eq!(state.onboarding_stage(), OnboardingStage::Welcome);
    }

    #[test]
    fn mutable_controls_update_rust_owned_models_and_bound_transcript_history() {
        let mut state = ProductState::default();
        assert_eq!(state.schedules().len(), 3);
        state.create_schedule();
        assert_eq!(
            state.schedules()[3],
            ScheduleSummary {
                name: "New schedule 4".to_owned(),
                cadence: "Choose a cadence".to_owned(),
                next_run: "Not scheduled".to_owned(),
                enabled: false,
                workspace: "GTA-Claw".to_owned(),
            }
        );
        state.toggle_schedule(3);
        assert!(!state.schedules()[3].enabled);
        assert!(state.schedules()[0].enabled);
        state.toggle_schedule(0);
        assert!(!state.schedules()[0].enabled);
        assert!(state.extensions()[0].enabled);
        state.toggle_extension(0);
        assert!(!state.extensions()[0].enabled);
        assert_eq!(state.selected_deliverable().name, "desktop-architecture.md");
        state.select_deliverable(2);
        assert_eq!(state.selected_deliverable().name, "diagnostics.json");
        assert!(!state.selected_deliverable().pinned);
        state.toggle_selected_deliverable_pin();
        assert!(state.selected_deliverable().pinned);

        for index in 0..205 {
            state.record_message(
                TranscriptRole::User,
                format!("message-{index}"),
                "keyboard submission",
            );
        }
        assert_eq!(state.transcript().len(), 200);
        assert_eq!(state.transcript()[0].text, "message-5");
        assert_eq!(state.transcript()[199].text, "message-204");
    }

    #[test]
    fn opening_and_approving_a_run_preserves_identity_and_updates_lifecycle() {
        let mut state = ProductState::default();
        assert_eq!(state.selected_run().id, "run-05-01");
        assert_eq!(state.resolve_approval(true), Ok(RunState::Running));
        assert_eq!(state.selected_run().id, "run-05-01");
        assert_eq!(state.selected_run().state, RunState::Running);
        assert_eq!(state.runs().visible()[4].state, RunState::Running);
        assert_eq!(
            state.activity().last(),
            Some(&ActivityEntry {
                title: "Approval granted".to_owned(),
                detail: "Approval recorded; execution resumed".to_owned(),
                state: RunState::Running,
                duration: "Now".to_owned(),
            })
        );
        assert_eq!(
            state.selected_run().detail,
            "Approval recorded; execution resumed"
        );
        state.open_session(4);
        assert_eq!(state.selected_run().id, "run-05-01");
        assert_eq!(state.selected_run().state, RunState::Running);
        assert_eq!(
            state.resolve_approval(true),
            Err(InvalidRunTransition {
                from: RunState::Running,
                to: RunState::Running,
            })
        );
    }

    #[test]
    fn workspace_opening_and_answers_use_canonical_run_records() {
        let mut state = ProductState::default();
        assert_eq!(
            state.transcript()[0].detail,
            "Workspace: GTA-Claw · Run: run-05-01"
        );
        let first_diff = state.diff().to_vec();
        state.select_session_file(1);
        assert_eq!(state.selected_file_index(), 1);
        assert_ne!(state.diff(), first_diff);
        assert!(state.open_workspace(1));
        assert_eq!(state.selected_run().workspace, "Gateway lab");
        assert_eq!(
            state.transcript()[0].detail,
            "Workspace: Gateway lab · Run: run-01-02"
        );
        assert_eq!(state.session_files()[0].name, "gateway-session.rs");
        state.record_message(TranscriptRole::User, "Gateway-only note", "isolated");
        assert_eq!(state.surface(), ProductSurface::Session);
        assert!(state.open_workspace(2));
        assert_eq!(state.selected_run().workspace, "Release workspace");
        assert!(
            state
                .transcript()
                .iter()
                .all(|entry| entry.text != "Gateway-only note")
        );
        assert_eq!(state.session_files()[0].name, "release-plan.toml");
        assert!(!state.open_workspace(3));

        state.open_session(5);
        assert_eq!(state.selected_run().state, RunState::WaitingForAnswer);
        assert_eq!(state.answer_question("Continue"), Ok(RunState::Running));
        assert_eq!(state.selected_run().state, RunState::Running);
        assert_eq!(state.runs().visible()[5].state, RunState::Running);
        assert_eq!(
            state.activity().last().map(|entry| entry.state),
            Some(RunState::Running)
        );
        state.open_session(5);
        assert_eq!(
            state.selected_run().detail,
            "Answer recorded; execution resumed"
        );

        let mut paused = ProductState::default();
        paused.open_session(5);
        assert_eq!(paused.answer_question("Pause run"), Ok(RunState::Paused));
        assert_eq!(paused.selected_run().state, RunState::Paused);
        assert_eq!(paused.runs().visible()[5].state, RunState::Paused);
        assert_eq!(
            paused.activity().last().map(|entry| entry.state),
            Some(RunState::Paused)
        );
    }

    #[test]
    fn demo_run_collection_covers_every_state_on_every_page_group() {
        let state = ProductState::default();
        assert_eq!(state.runs().page_count(), 5);
        let rows = demo_runs();
        assert_eq!(rows.len(), 120);
        let state_counts = RunState::ALL
            .into_iter()
            .map(|run_state| {
                rows.iter()
                    .filter(|summary| summary.state == run_state)
                    .count()
            })
            .collect::<Vec<_>>();
        assert_eq!(state_counts, vec![10; 12]);
        assert!(rows.chunks_exact(24).all(|page| {
            RunState::ALL
                .into_iter()
                .all(|run_state| page.iter().filter(|run| run.state == run_state).count() == 2)
        }));
    }
}

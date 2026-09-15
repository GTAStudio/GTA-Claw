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
    OutcomeUnknown,
    Failed,
    Cancelled,
    Completed,
    CompletedWithChanges,
}

impl RunState {
    pub(crate) const ALL: [Self; 13] = [
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
            Self::OutcomeUnknown => "Outcome unknown",
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
            Self::WaitingForApproval | Self::Blocked | Self::OutcomeUnknown => {
                SemanticTone::Warning
            }
            Self::Failed => SemanticTone::Danger,
            Self::Completed | Self::CompletedWithChanges => SemanticTone::Success,
        }
    }

    pub(crate) const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Failed
                | Self::Cancelled
                | Self::Completed
                | Self::CompletedWithChanges
                | Self::OutcomeUnknown
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
    native: Option<NativeProjection>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NativeProjection {
    generation: u64,
    connection: Option<crate::controller::ProductConnection>,
    ready: bool,
    content_versions: BTreeMap<String, u64>,
    history_requests: BTreeMap<u64, (String, u64)>,
    pending_submissions: BTreeMap<String, serde_json::Value>,
    uncertain_submissions: std::collections::BTreeSet<String>,
    retryable_submissions: std::collections::BTreeSet<String>,
    memory_results: BTreeMap<String, String>,
    memory_runs: BTreeMap<String, String>,
    latest_turns: BTreeMap<String, u64>,
    active_runs: BTreeMap<String, String>,
    approvals: BTreeMap<String, NativeApproval>,
    dismissed_approvals: std::collections::BTreeSet<String>,
    queries: std::collections::VecDeque<(&'static str, serde_json::Value)>,
    completed_runs: BTreeMap<String, String>,
}

static EMPTY_DELIVERABLE: DeliverableSummary = DeliverableSummary {
    name: String::new(),
    kind: String::new(),
    source: String::new(),
    size: String::new(),
    pinned: false,
};

#[derive(Clone, Eq, PartialEq)]
struct NativeApproval {
    id: String,
    binding_token: Option<String>,
}

impl std::fmt::Debug for NativeApproval {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeApproval")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

const fn empty_session() -> RunSessionData {
    RunSessionData {
        transcript: Vec::new(),
        activity: Vec::new(),
        files: Vec::new(),
        selected_file: 0,
        approval_prompt: String::new(),
        approval_scope: String::new(),
        question: String::new(),
    }
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
            native: None,
        }
    }
}

impl ProductState {
    pub(crate) fn native() -> Self {
        let selected_run = RunSummary {
            id: "native-session".to_owned(),
            title: "Conversation".to_owned(),
            workspace: String::new(),
            state: RunState::Draft,
            detail: "Not connected".to_owned(),
            updated: String::new(),
        };
        Self {
            onboarding_stage: OnboardingStage::Welcome,
            surface: ProductSurface::Session,
            focused_run: RunLifecycle::new(RunState::Draft),
            runs: PagedModel::new(vec![selected_run.clone()], 24),
            sessions: BTreeMap::from([(selected_run.id.clone(), empty_session())]),
            selected_run,
            selected_deliverable: 0,
            palette_open: false,
            diff_mode: DiffMode::Unified,
            selected_settings_section: 0,
            workspaces: Vec::new(),
            schedules: Vec::new(),
            deliverables: Vec::new(),
            extensions: Vec::new(),
            native: Some(NativeProjection::default()),
        }
    }

    pub(crate) fn apply_native(&mut self, update: crate::controller::ProductUpdate) {
        use crate::controller::ProductUpdate;
        let Some(native) = &mut self.native else {
            return;
        };
        let generation = match &update {
            ProductUpdate::Reset { generation } | ProductUpdate::Unavailable { generation } => {
                *generation
            }
            ProductUpdate::Ready { connection }
            | ProductUpdate::HistoryStarted { connection, .. }
            | ProductUpdate::HistoryFinished { connection, .. }
            | ProductUpdate::Response { connection, .. }
            | ProductUpdate::Event { connection, .. }
            | ProductUpdate::Failed { connection, .. } => connection.generation,
        };
        if generation < native.generation
            || (generation != native.generation && !matches!(update, ProductUpdate::Reset { .. }))
        {
            return;
        }
        if let ProductUpdate::Response { connection, .. }
        | ProductUpdate::HistoryStarted { connection, .. }
        | ProductUpdate::HistoryFinished { connection, .. }
        | ProductUpdate::Event { connection, .. }
        | ProductUpdate::Failed { connection, .. } = &update
            && (!native.ready || native.connection != Some(*connection))
        {
            return;
        }
        match update {
            ProductUpdate::Reset { generation } => {
                *self = Self::native();
                self.native.as_mut().expect("native mode").generation = generation;
            }
            ProductUpdate::Ready { connection } => {
                if native
                    .connection
                    .is_some_and(|known| connection.epoch < known.epoch)
                {
                    return;
                }
                if native.connection != Some(connection) {
                    native.approvals.clear();
                    native.dismissed_approvals.clear();
                    native.queries.clear();
                    native.history_requests.clear();
                    native.active_runs.clear();
                }
                native.connection = Some(connection);
                native.ready = true;
                let session = self.selected_run.id.clone();
                self.queue_native_query("sessions.list", serde_json::json!({}));
                self.queue_native_query("chat.history", serde_json::json!({"sessionKey": session}));
                self.queue_native_query("sessions.get", serde_json::json!({"sessionKey": session}));
                self.queue_native_query(
                    "exec.approval.list",
                    serde_json::json!({"sessionId": session}),
                );
            }
            ProductUpdate::Unavailable { .. } => self.native_unavailable(),
            ProductUpdate::HistoryStarted {
                request, session, ..
            } => {
                if !self.ensure_native_session(&session) {
                    return;
                }
                let native = self.native.as_mut().expect("native mode");
                if native.history_requests.len() >= 4
                    || native.history_requests.contains_key(&request)
                {
                    self.native_unavailable();
                    return;
                }
                let version = native.content_versions.get(&session).copied().unwrap_or(0);
                native.history_requests.insert(request, (session, version));
            }
            ProductUpdate::HistoryFinished {
                request, payload, ..
            } => self.finish_native_history(request, payload.as_ref()),
            ProductUpdate::Failed {
                method,
                params,
                definitive,
                ..
            } => {
                let session = params["sessionKey"]
                    .as_str()
                    .unwrap_or(self.selected_run.id.as_str())
                    .to_owned();
                if method == "chat.send" && self.ensure_native_session(&session) {
                    let native = self.native.as_mut().expect("native mode");
                    if native
                        .pending_submissions
                        .get(&session)
                        .is_some_and(|pending| {
                            pending["idempotencyKey"] == params["idempotencyKey"]
                        })
                    {
                        let memory = params["message"]
                            .as_str()
                            .is_some_and(|message| message.starts_with("!tool "));
                        let unresolved = memory && native.uncertain_submissions.contains(&session);
                        if definitive && !unresolved {
                            native.pending_submissions.remove(&session);
                            native.retryable_submissions.remove(&session);
                        } else if memory {
                            native.uncertain_submissions.insert(session.clone());
                            native.retryable_submissions.insert(session.clone());
                        }
                        self.native_state(
                            &session,
                            if definitive && !unresolved {
                                RunState::Failed
                            } else if memory {
                                RunState::OutcomeUnknown
                            } else {
                                RunState::Blocked
                            },
                        );
                    }
                }
                if let Some(data) = self.sessions.get_mut(&session) {
                    let previous_unknown = self
                        .native
                        .as_ref()
                        .is_some_and(|native| native.uncertain_submissions.contains(&session));
                    data.transcript.push(TranscriptEntry {
                        role: TranscriptRole::System,
                        text: format!("{method} did not complete"),
                        detail: if definitive && !previous_unknown { "Request was not accepted." } else { "Delivery is unknown. Keep the original request key and query its result before another execution." }.to_owned(),
                        timestamp: String::new(),
                    });
                    if data.transcript.len() > MAX_SESSION_HISTORY {
                        data.transcript.remove(0);
                    }
                }
            }
            ProductUpdate::Response {
                method,
                params,
                payload,
                ..
            } => self.native_response(method, &params, &payload),
            ProductUpdate::Event { name, payload, .. } => self.native_event(&name, &payload),
        }
    }

    fn ensure_native_session(&mut self, id: &str) -> bool {
        if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
            return false;
        }
        if self.sessions.contains_key(id) {
            return true;
        }
        if self.sessions.len() >= 256 {
            return false;
        }
        self.sessions.insert(id.to_owned(), empty_session());
        self.runs.rows.push(RunSummary {
            id: id.to_owned(),
            title: id.to_owned(),
            workspace: String::new(),
            state: RunState::Draft,
            detail: String::new(),
            updated: String::new(),
        });
        true
    }

    fn native_state(&mut self, id: &str, state: RunState) {
        if let Some(run) = self.runs.rows.iter_mut().find(|run| run.id == id) {
            run.state = state;
        }
        if self.selected_run.id == id {
            self.selected_run.state = state;
            self.focused_run = RunLifecycle::new(state);
        }
    }

    fn native_response(
        &mut self,
        method: &str,
        params: &serde_json::Value,
        payload: &serde_json::Value,
    ) {
        if method == "sessions.get" {
            let Some(session) = params["sessionKey"].as_str() else {
                return;
            };
            if payload["sessionKey"].as_str() != Some(session) {
                return;
            }
            if let Some(active) = payload["activeRuns"]
                .as_array()
                .filter(|runs| runs.len() <= 32)
            {
                for item in active {
                    if item["sessionId"].as_str() == Some(session)
                        && let Some(run) = native_run_id(&item["runId"])
                        && self.ensure_native_session(session)
                        && self.accept_native_turn(session, item)
                    {
                        self.native
                            .as_mut()
                            .expect("native mode")
                            .active_runs
                            .insert(session.to_owned(), run.to_owned());
                        self.native_state(
                            session,
                            if item["phase"] == "queued" {
                                RunState::Queued
                            } else {
                                RunState::Running
                            },
                        );
                    }
                }
                if let Some(after) = native_run_id(&payload["nextActiveCursor"]) {
                    self.queue_native_query(
                        "sessions.get",
                        serde_json::json!({"sessionKey": session, "activeAfter": after}),
                    );
                }
            }
            let Some(runs) = payload["pendingRuns"]
                .as_array()
                .filter(|runs| runs.len() <= 32)
            else {
                return;
            };
            if let Some(run) = runs.iter().find(|run| {
                run["sessionId"].as_str() == Some(session) && native_run_id(&run["runId"]).is_some()
            }) {
                self.queue_native_query("agent.wait", serde_json::json!({"runId": run["runId"]}));
            } else if let Some(after) = native_run_id(&payload["nextCursor"]) {
                self.queue_native_query(
                    "sessions.get",
                    serde_json::json!({"sessionKey": session, "after": after}),
                );
            }
            return;
        }
        if method == "agent.wait" {
            if payload["durable"] != true {
                self.native_unavailable();
                return;
            }
            let Some(run) = native_run_id(&payload["runId"])
                .filter(|run| params["runId"].as_str() == Some(*run))
            else {
                return;
            };
            let Some(session) = payload["sessionId"].as_str() else {
                return;
            };
            if params.get("acknowledgeRevision").is_some() {
                if payload["acknowledged"] == true
                    && payload["revision"].as_u64().is_some_and(|revision| {
                        revision > 0 && Some(revision) == params["acknowledgeRevision"].as_u64()
                    })
                {
                    self.queue_native_query(
                        "sessions.get",
                        serde_json::json!({"sessionKey": session}),
                    );
                }
                return;
            }
            if !matches!(
                payload["phase"].as_str(),
                Some("finished" | "outcome_unknown")
            ) {
                if matches!(payload["phase"].as_str(), Some("queued" | "executing"))
                    && self.ensure_native_session(session)
                {
                    self.native
                        .as_mut()
                        .expect("native mode")
                        .active_runs
                        .insert(session.to_owned(), run.to_owned());
                }
                return;
            }
            let Some(status) = payload["result"]["status"].as_str().filter(|status| {
                matches!(
                    *status,
                    "completed"
                        | "completed_with_changes"
                        | "failed"
                        | "cancelled"
                        | "outcome_unknown"
                )
            }) else {
                return;
            };
            let Some(text) = payload["result"]["text"]
                .as_str()
                .filter(|text| text.len() <= 64 * 1024)
            else {
                self.record_message(
                    TranscriptRole::System,
                    "The saved result exceeds the display limit.",
                    "The result has not been acknowledged.",
                );
                return;
            };
            let Some(revision) = payload["revision"]
                .as_u64()
                .filter(|revision| *revision > 0)
            else {
                return;
            };
            self.native_event("chat", &serde_json::json!({"sessionId": session, "runId": run, "turn": payload["turn"], "status": status, "text": text}));
            if self.selected_run.id == session
                && self.native.as_ref().is_some_and(|native| {
                    native
                        .completed_runs
                        .get(session)
                        .is_some_and(|current| current == run)
                })
            {
                self.queue_native_query(
                    "agent.wait",
                    serde_json::json!({"runId": run, "acknowledgeRevision": revision}),
                );
            }
            return;
        }
        if method == "exec.approval.list" {
            let Some(requests) = payload["requests"]
                .as_array()
                .filter(|requests| requests.len() <= 32)
            else {
                self.native_unavailable();
                return;
            };
            for request in requests {
                if request["sessionId"].as_str() == Some(self.selected_run.id.as_str())
                    && self.request_native_preview(request)
                {
                    return;
                }
            }
            if let Some(after) = payload["nextCursor"]
                .as_str()
                .filter(|after| after.len() <= 128)
            {
                self.queue_native_query(
                    "exec.approval.list",
                    serde_json::json!({"sessionId": self.selected_run.id, "after": after}),
                );
            }
            return;
        }
        if method == "exec.approval.get" {
            self.install_native_preview(params, payload);
            return;
        }
        if method == "approval.resolve" {
            if payload["ok"] == true && payload["id"] == params["id"] {
                self.native_event("exec.approval.resolved", payload);
            }
            return;
        }
        if method == "chat.abort" {
            if payload["ok"] == true
                && let Some(run) = native_run_id(&params["runId"])
            {
                self.queue_native_query("agent.wait", serde_json::json!({"runId": run}));
            }
            return;
        }
        if method == "sessions.list" {
            if let Some(sessions) = payload["sessions"].as_array() {
                for session in sessions.iter().take(256) {
                    if let Some(id) = session["id"].as_str().or_else(|| session["key"].as_str())
                        && self.ensure_native_session(id)
                    {
                        self.native_state(
                            id,
                            native_run_state(session["state"].as_str().unwrap_or("draft")),
                        );
                    }
                }
            }
            return;
        }
        let Some(id) = params["sessionKey"]
            .as_str()
            .or_else(|| payload["sessionKey"].as_str())
        else {
            return;
        };
        if !self.ensure_native_session(id) {
            return;
        }
        if method == "chat.send" {
            if params["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("!tool "))
            {
                if !self
                    .native
                    .as_ref()
                    .expect("native mode")
                    .pending_submissions
                    .get(id)
                    .is_some_and(|pending| pending["idempotencyKey"] == params["idempotencyKey"])
                {
                    return;
                }
                if payload["durable"] != true
                    || payload["sessionId"].as_str() != Some(id)
                    || payload["status"] != "accepted"
                    || native_run_id(&payload["runId"]).is_none()
                    || payload["revision"]
                        .as_u64()
                        .is_none_or(|revision| revision == 0)
                    || !matches!(
                        payload["phase"].as_str(),
                        Some("queued" | "executing" | "finished" | "outcome_unknown")
                    )
                {
                    let native = self.native.as_mut().expect("native mode");
                    native.uncertain_submissions.insert(id.to_owned());
                    native.retryable_submissions.insert(id.to_owned());
                    self.native_state(id, RunState::OutcomeUnknown);
                    return;
                }
                self.native
                    .as_mut()
                    .expect("native mode")
                    .retryable_submissions
                    .remove(id);
                self.native
                    .as_mut()
                    .expect("native mode")
                    .memory_runs
                    .insert(
                        id.to_owned(),
                        payload["runId"]
                            .as_str()
                            .expect("validated memory run")
                            .to_owned(),
                    );
                self.queue_native_query(
                    "agent.wait",
                    serde_json::json!({"runId":payload["runId"]}),
                );
            }
            if let Some(run) = native_run_id(&payload["runId"]) {
                let native = self.native.as_mut().expect("native mode");
                if native
                    .completed_runs
                    .get(id)
                    .is_none_or(|completed| completed != run)
                {
                    native.active_runs.insert(id.to_owned(), run.to_owned());
                }
                if payload
                    .get("result")
                    .is_some_and(serde_json::Value::is_object)
                {
                    self.queue_native_query("agent.wait", serde_json::json!({"runId": run}));
                }
            }
            let finished = self
                .native
                .as_ref()
                .expect("native mode")
                .completed_runs
                .get(id)
                .is_some_and(|run| payload["runId"].as_str() == Some(run.as_str()));
            if !finished {
                self.native_state(id, RunState::Queued);
            }
        }
    }

    fn native_event(&mut self, name: &str, payload: &serde_json::Value) {
        if name == "exec.approval.resolved" {
            let Some(id) = payload["id"]
                .as_str()
                .filter(|id| !id.is_empty() && id.len() <= 128)
            else {
                return;
            };
            let native = self.native.as_mut().expect("native mode");
            if native.dismissed_approvals.contains(id) {
                return;
            }
            if native.dismissed_approvals.len() >= 256 {
                self.native_unavailable();
                return;
            }
            native.dismissed_approvals.insert(id.to_owned());
            native.approvals.retain(|_, approval| approval.id != id);
            self.queue_native_query(
                "exec.approval.list",
                serde_json::json!({"sessionId": self.selected_run.id}),
            );
            return;
        }
        let Some(id) = payload["sessionId"].as_str() else {
            return;
        };
        if !self.ensure_native_session(id) {
            return;
        }
        match name {
            "exec.approval.requested" => {
                self.native_state(id, RunState::WaitingForApproval);
                if self.selected_run.id == id {
                    self.request_native_preview(payload);
                }
            }
            "session.operation" => {
                if !self.accept_native_turn(id, payload) {
                    return;
                }
                if self
                    .native
                    .as_ref()
                    .expect("native mode")
                    .completed_runs
                    .get(id)
                    .is_some_and(|known| payload["runId"].as_str() == Some(known.as_str()))
                {
                    return;
                }
                if let Some(run) = native_run_id(&payload["runId"]) {
                    self.native
                        .as_mut()
                        .expect("native mode")
                        .active_runs
                        .insert(id.to_owned(), run.to_owned());
                }
                self.native_state(
                    id,
                    native_run_state(payload["state"].as_str().unwrap_or("running")),
                );
            }
            "chat" => {
                if payload["resultAvailable"] == true {
                    if let Some(run) = native_run_id(&payload["runId"]) {
                        self.queue_native_query("agent.wait", serde_json::json!({"runId": run}));
                    }
                    return;
                }
                if !self.accept_native_turn(id, payload) {
                    return;
                }
                let Some(run_id) = payload["runId"].as_str().filter(|run| run.len() <= 256) else {
                    return;
                };
                let native = self.native.as_mut().expect("native mode");
                let pending_memory = native.pending_submissions.get(id).is_some_and(|params| {
                    params["message"]
                        .as_str()
                        .is_some_and(|message| message.starts_with("!tool "))
                });
                let memory_completed =
                    pending_memory && native.memory_runs.get(id).is_some_and(|run| run == run_id);
                if memory_completed {
                    if let Some(text) = payload["text"]
                        .as_str()
                        .filter(|text| text.len() <= 16 * 1024)
                    {
                        native.memory_results.insert(id.to_owned(), text.to_owned());
                    }
                    native.pending_submissions.remove(id);
                    native.uncertain_submissions.remove(id);
                    native.retryable_submissions.remove(id);
                    native.memory_runs.remove(id);
                }
                let completed = &mut self.native.as_mut().expect("native mode").completed_runs;
                if completed.get(id).is_some_and(|known| known == run_id) {
                    return;
                }
                completed.insert(id.to_owned(), run_id.to_owned());
                if !pending_memory {
                    self.native
                        .as_mut()
                        .expect("native mode")
                        .pending_submissions
                        .remove(id);
                }
                if !pending_memory || memory_completed {
                    self.native
                        .as_mut()
                        .expect("native mode")
                        .active_runs
                        .remove(id);
                }
                self.native_content_changed(id);
                let session = self.sessions.get_mut(id).expect("known session");
                session.transcript.push(TranscriptEntry {
                    role: TranscriptRole::Assistant,
                    text: native_text(payload["text"].as_str().unwrap_or("")),
                    detail: String::new(),
                    timestamp: String::new(),
                });
                if session.transcript.len() > MAX_SESSION_HISTORY {
                    session.transcript.remove(0);
                }
                self.native_state(
                    id,
                    native_run_state(payload["status"].as_str().unwrap_or("failed")),
                );
                self.queue_native_query("chat.history", serde_json::json!({"sessionKey": id}));
            }
            _ => {}
        }
    }

    pub(crate) fn native_message(&mut self, message: &str) -> Option<serde_json::Value> {
        if message.lines().any(|line| {
            line.trim_start()
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("!tool"))
        }) {
            return None;
        }
        self.native_submission(message)
    }

    pub(crate) fn memory_binding(&self) -> String {
        self.native_connection()
            .map_or_else(String::new, |connection| {
                format!(
                    "{}:{}:{}",
                    connection.generation, connection.epoch, self.selected_run.id
                )
            })
    }

    pub(crate) fn memory_result(&self) -> &str {
        self.native
            .as_ref()
            .filter(|native| native.ready)
            .and_then(|native| native.memory_results.get(&self.selected_run.id))
            .map_or("", String::as_str)
    }

    pub(crate) fn native_memory(
        &mut self,
        binding: &str,
        form: &MemoryForm<'_>,
    ) -> Result<serde_json::Value, &'static str> {
        if binding.is_empty() || binding != self.memory_binding() {
            return Err(
                "Memory form belongs to a previous connection or session; no command was sent",
            );
        }
        let message = form.message()?;
        self.native_submission(&message).ok_or(
            "Memory was not submitted; a ready session without an unresolved run is required",
        )
    }

    fn native_submission(&mut self, message: &str) -> Option<serde_json::Value> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        if !self.can_send_native_message() {
            return None;
        }
        let native = self.native.as_mut()?;
        if !native.ready
            || native
                .pending_submissions
                .contains_key(&self.selected_run.id)
            || message.trim().is_empty()
            || message.len() > 60 * 1024
        {
            return None;
        }
        let mut nonce = [0_u8; 16];
        getrandom::rand_core::TryRng::try_fill_bytes(&mut getrandom::SysRng, &mut nonce).ok()?;
        let random: String = nonce
            .iter()
            .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
            .map(char::from)
            .collect();
        let idempotency = format!("desktop-{random}");
        let params = serde_json::json!({"sessionKey": self.selected_run.id, "message": message, "idempotencyKey": idempotency});
        Some(params)
    }

    pub(crate) fn native_abort(&self) -> Option<serde_json::Value> {
        let native = self.native.as_ref().filter(|native| native.ready)?;
        let run = native.active_runs.get(&self.selected_run.id)?;
        Some(serde_json::json!({"sessionKey": self.selected_run.id, "runId": run}))
    }

    pub(crate) fn retry_native_memory(&self) -> Option<serde_json::Value> {
        let native = self.native.as_ref().filter(|native| native.ready)?;
        if !native.retryable_submissions.contains(&self.selected_run.id)
            || native.active_runs.contains_key(&self.selected_run.id)
        {
            return None;
        }
        native
            .pending_submissions
            .get(&self.selected_run.id)
            .filter(|params| {
                params["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with("!tool "))
            })
            .cloned()
    }

    pub(crate) fn can_send_native_message(&self) -> bool {
        self.native.as_ref().is_none_or(|native| {
            native.ready
                && !native
                    .pending_submissions
                    .contains_key(&self.selected_run.id)
                && !native.active_runs.contains_key(&self.selected_run.id)
        })
    }

    pub(crate) fn native_message_enqueued(&mut self, params: &serde_json::Value) {
        if let Some(message) = params["message"].as_str()
            && params["sessionKey"].as_str() == Some(self.selected_run.id.as_str())
        {
            let session = self.selected_run.id.clone();
            let repeated = self
                .native
                .as_ref()
                .is_some_and(|native| native.pending_submissions.contains_key(&session));
            self.native_content_changed(&session);
            self.native
                .as_mut()
                .expect("native mode")
                .retryable_submissions
                .remove(&session);
            self.native
                .as_mut()
                .expect("native mode")
                .pending_submissions
                .insert(session, params.clone());
            let text = if message.starts_with("!tool ") {
                "Explicit memory operation (untrusted data)"
            } else {
                message
            };
            if !repeated {
                self.record_message(TranscriptRole::User, text, "Pending server acceptance");
            }
        }
    }

    pub(crate) fn native_unavailable(&mut self) {
        if let Some(native) = &mut self.native {
            native.ready = false;
            native.memory_results.clear();
            for (session, params) in &native.pending_submissions {
                if params["message"]
                    .as_str()
                    .is_some_and(|message| message.starts_with("!tool "))
                {
                    native.uncertain_submissions.insert(session.clone());
                    native.retryable_submissions.insert(session.clone());
                }
            }
            native.approvals.clear();
            native.queries.clear();
            native.history_requests.clear();
        }
    }

    fn native_content_changed(&mut self, session: &str) {
        let native = self.native.as_mut().expect("native mode");
        let version = native
            .content_versions
            .entry(session.to_owned())
            .or_default();
        if let Some(next) = version.checked_add(1) {
            *version = next;
        } else {
            self.native_unavailable();
        }
    }

    fn accept_native_turn(&mut self, session: &str, payload: &serde_json::Value) -> bool {
        let Some(turn) = payload["turn"].as_u64() else {
            return true;
        };
        let turns = &mut self.native.as_mut().expect("native mode").latest_turns;
        if turns.get(session).is_some_and(|latest| turn < *latest) {
            return false;
        }
        turns.insert(session.to_owned(), turn);
        true
    }

    fn finish_native_history(&mut self, request: u64, payload: Option<&serde_json::Value>) {
        let native = self.native.as_mut().expect("native mode");
        let Some((session, version)) = native.history_requests.remove(&request) else {
            return;
        };
        if native.pending_submissions.contains_key(&session) {
            return;
        }
        if native.content_versions.get(&session).copied().unwrap_or(0) != version {
            self.queue_native_query("chat.history", serde_json::json!({"sessionKey": session}));
            return;
        }
        let Some(payload) =
            payload.filter(|payload| payload["sessionKey"].as_str() == Some(session.as_str()))
        else {
            return;
        };
        let Some(messages) = payload["messages"]
            .as_array()
            .filter(|messages| messages.len() <= 256)
        else {
            return;
        };
        let mut bytes = 0_usize;
        let mut transcript = Vec::with_capacity(messages.len());
        for message in messages {
            let (Some(role), Some(text)) = (message["role"].as_str(), message["text"].as_str())
            else {
                return;
            };
            bytes = bytes.saturating_add(text.len());
            if text.len() > 64 * 1024 || bytes > 512 * 1024 {
                return;
            }
            let role = match role {
                "user" => TranscriptRole::User,
                "assistant" => TranscriptRole::Assistant,
                "tool" => TranscriptRole::Activity,
                "system" => TranscriptRole::System,
                _ => return,
            };
            transcript.push(TranscriptEntry {
                role,
                text: text.to_owned(),
                detail: String::new(),
                timestamp: String::new(),
            });
        }
        self.sessions
            .get_mut(&session)
            .expect("known session")
            .transcript = transcript;
        self.native_content_changed(&session);
    }

    pub(crate) fn native_connection(&self) -> Option<crate::controller::ProductConnection> {
        self.native
            .as_ref()
            .filter(|native| native.ready)?
            .connection
    }

    fn queue_native_query(&mut self, method: &'static str, params: serde_json::Value) {
        let native = self.native.as_mut().expect("native mode");
        if !native.ready
            || native
                .queries
                .iter()
                .any(|query| query.0 == method && query.1 == params)
        {
            return;
        }
        if native.queries.len() >= 32 {
            self.native_unavailable();
            return;
        }
        native.queries.push_back((method, params));
    }

    pub(crate) fn next_native_query(&mut self) -> Option<(&'static str, serde_json::Value)> {
        let native = self.native.as_mut()?;
        if !native.ready {
            return None;
        }
        native.queries.pop_front()
    }

    fn request_native_preview(&mut self, payload: &serde_json::Value) -> bool {
        let Some(id) = payload["id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 128)
        else {
            return false;
        };
        let native = self.native.as_ref().expect("native mode");
        if native.dismissed_approvals.contains(id)
            || native.approvals.contains_key(&self.selected_run.id)
        {
            return false;
        }
        self.queue_native_query("exec.approval.get", serde_json::json!({"id": id}));
        true
    }

    fn install_native_preview(&mut self, params: &serde_json::Value, payload: &serde_json::Value) {
        let Some(approval) = params["id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 128)
        else {
            return;
        };
        if payload["id"].as_str() != Some(approval) || payload["previewComplete"] != true {
            return;
        }
        let binding_token = if let Some(token) = payload["bindingToken"].as_str() {
            if claw_protocol::native_approval::checked_bound_approval_prompt(payload, 32 * 1024)
                .is_none()
            {
                return;
            }
            let Some(fingerprint) =
                claw_security::authorization::approval_preview_fingerprint(token)
            else {
                return;
            };
            if payload["previewFingerprint"].as_str() != Some(fingerprint.as_str()) {
                return;
            }
            Some(token.to_owned())
        } else if [
            "previewFingerprint",
            "toolRevision",
            "toolPublication",
            "resourceScope",
            "caller",
        ]
        .iter()
        .any(|field| payload.get(field).is_some())
        {
            return;
        } else {
            None
        };
        let Some(id) = payload["sessionId"].as_str() else {
            return;
        };
        let Some(prompt) = payload["prompt"]
            .as_str()
            .filter(|prompt| !prompt.is_empty() && prompt.len() <= 32 * 1024)
        else {
            return;
        };
        if !self.ensure_native_session(id) {
            return;
        }
        let native = self.native.as_mut().expect("native mode");
        if !native.ready
            || native.dismissed_approvals.contains(approval)
            || native.approvals.contains_key(id)
        {
            return;
        }
        native.approvals.insert(
            id.to_owned(),
            NativeApproval {
                id: approval.to_owned(),
                binding_token,
            },
        );
        let session = self.sessions.get_mut(id).expect("known session");
        prompt.clone_into(&mut session.approval_prompt);
        (if payload["redacted"] == true {
            "This invocation only; sensitive fields redacted"
        } else {
            "This invocation only"
        })
        .clone_into(&mut session.approval_scope);
        self.native_state(id, RunState::WaitingForApproval);
    }

    pub(crate) fn native_approval(&self, approved: bool) -> Option<serde_json::Value> {
        let native = self.native.as_ref()?;
        if !native.ready {
            return None;
        }
        let approval = native.approvals.get(&self.selected_run.id)?;
        let mut decision = serde_json::json!({"id": approval.id, "decision": if approved { "approve" } else { "deny" }});
        if let Some(token) = &approval.binding_token {
            decision["bindingToken"] = serde_json::json!(token);
        }
        Some(decision)
    }

    pub(crate) fn can_present_approval(&self) -> bool {
        if self.native.is_some() {
            self.native_approval(false).is_some()
        } else {
            self.selected_run.state == RunState::WaitingForApproval
        }
    }

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
        self.deliverables
            .get(self.selected_deliverable)
            .unwrap_or(&EMPTY_DELIVERABLE)
    }

    pub(crate) const fn selected_deliverable_index(&self) -> usize {
        self.selected_deliverable
    }

    pub(crate) const fn selected_deliverable_content(&self) -> &'static str {
        if self.native.is_some() {
            return "";
        }
        match self.selected_deliverable {
            0 => {
                "Native desktop architecture\n\n• Rust owns application state\n• Slint provides typed presentation adapters\n• Tokio runs Gateway work off the UI thread\n• Approval and diff review remain explicit"
            }
            1 => {
                "Image preview\n\nSettings screen at 1080 × 720 logical pixels.\nTheme: light · Density: 100% · Accessibility labels included in preview"
            }
            _ => {
                "{\n  \"availability\": \"preview-only\",\n  \"gateway\": \"see live connection summary\",\n  \"renderer\": \"not reported\",\n  \"accessibility\": \"use platform inspector\"\n}"
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
        session
            .files
            .get(session.selected_file)
            .map_or("", |file| file.name.as_str())
    }

    pub(crate) fn diff(&self) -> &[DiffLine] {
        let session = self.selected_session();
        session
            .files
            .get(session.selected_file)
            .map_or(&[], |file| file.diff.as_slice())
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
        if self.native.is_some() {
            return;
        }
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
        if let Some(deliverable) = self.deliverables.get_mut(self.selected_deliverable) {
            deliverable.pinned = !deliverable.pinned;
        }
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

pub(crate) struct MemoryForm<'a> {
    pub(crate) action: i32,
    pub(crate) id: &'a str,
    pub(crate) kind: i32,
    pub(crate) revision: &'a str,
    pub(crate) offset: &'a str,
    pub(crate) content: &'a str,
    pub(crate) overwrite: bool,
}

impl MemoryForm<'_> {
    fn message(&self) -> Result<String, &'static str> {
        let revision = self.revision.trim().parse::<u64>().ok();
        let offset = if self.offset.trim().is_empty() {
            0
        } else {
            self.offset
                .trim()
                .parse::<u64>()
                .map_err(|_| "Memory offset must be an unsigned integer")?
        };
        let id_valid = !self.id.is_empty()
            && self.id.len() <= 64
            && self.id.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || index > 0 && matches!(byte, b'-' | b'_' | b'.')
            });
        let valid_text = |limit| {
            !self.content.trim().is_empty()
                && self.content.len() <= limit
                && !self.content.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                })
        };
        let expected = || revision.ok_or("An exact notebook revision is required");
        let arguments = match self.action {
            0 if self.id.is_empty() => serde_json::json!({"action":"list","limit":16}),
            0 if id_valid => {
                serde_json::json!({"action":"list","limit":16,"after":self.id,"revision":expected()?})
            }
            1 if id_valid && offset <= 8_192 && (offset == 0 || revision.is_some()) => {
                let mut arguments =
                    serde_json::json!({"action":"get","id":self.id,"offset":offset});
                if let Some(revision) = revision {
                    arguments["revision"] = serde_json::json!(revision);
                }
                arguments
            }
            2 if valid_text(4_096) => {
                serde_json::json!({"action":"search","query":self.content,"limit":8})
            }
            3 if id_valid && valid_text(8_192) => {
                let kind = match self.kind {
                    0 => "fact",
                    1 => "preference",
                    2 => "procedure",
                    _ => return Err("Unknown memory kind"),
                };
                serde_json::json!({"action":"save","id":self.id,"kind":kind,"content":self.content,"expectedRevision":expected()?})
            }
            4 if id_valid => {
                serde_json::json!({"action":"delete","id":self.id,"expectedRevision":expected()?})
            }
            5 if offset <= 4 * 1024 * 1024 => {
                serde_json::json!({"action":"export","revision":expected()?,"offset":offset})
            }
            6 => {
                if self.content.len() > 16 * 1024 {
                    return Err("Memory archive input exceeds 16 KiB");
                }
                let raw =
                    claw_protocol::gateway::OpaqueJson::from_json_string(self.content.to_owned())
                        .map_err(|_| "Memory archive must be valid JSON")?;
                let archive: serde_json::Value = claw_protocol::gateway::Codec::authenticated()
                    .decode_opaque(&raw)
                    .map_err(
                        |_| "Memory archive contains duplicate keys or exceeds the JSON policy",
                    )?;
                if !valid_memory_archive(&archive) {
                    return Err("Memory archive schema is unsupported");
                }
                serde_json::json!({"action":"import","expectedRevision":expected()?,"archive":archive,"overwrite":self.overwrite})
            }
            _ => return Err("Memory action, identity, content or cursor is invalid"),
        };
        let message = format!(
            "!tool {}",
            serde_json::json!({"name":"memory_notes","arguments":arguments})
        );
        if message.len() > 16 * 1024 {
            return Err("Encoded memory command exceeds 16 KiB");
        }
        Ok(message)
    }
}

fn valid_memory_archive(archive: &serde_json::Value) -> bool {
    let closed = |value: &serde_json::Value, fields: &[&str]| {
        value.as_object().is_some_and(|object| {
            object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
        })
    };
    let notebook = &archive["notebook"];
    let Some(revision) = notebook["revision"].as_u64() else {
        return false;
    };
    let Some(entries) = notebook["entries"]
        .as_array()
        .filter(|entries| entries.len() <= 256)
    else {
        return false;
    };
    archive["schemaVersion"] == 1
        && closed(archive, &["schemaVersion", "notebook"])
        && closed(notebook, &["revision", "entries"])
        && entries
            .windows(2)
            .all(|pair| pair[0]["id"].as_str() < pair[1]["id"].as_str())
        && entries.iter().all(|entry| {
            closed(
                entry,
                &["id", "kind", "content", "sourceSession", "revision"],
            ) && entry["id"].as_str().is_some_and(|id| {
                !id.is_empty()
                    && id.len() <= 64
                    && id.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphanumeric()
                            || index > 0 && matches!(byte, b'-' | b'_' | b'.')
                    })
            }) && matches!(
                entry["kind"].as_str(),
                Some("fact" | "preference" | "procedure")
            ) && entry["content"].as_str().is_some_and(|content| {
                !content.trim().is_empty()
                    && content.len() <= 8_192
                    && !content.chars().any(|character| {
                        character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                    })
            }) && entry["sourceSession"].as_str().is_some_and(|source| {
                !source.trim().is_empty()
                    && source.len() <= 256
                    && !source.chars().any(char::is_control)
            }) && entry["revision"]
                .as_u64()
                .is_some_and(|entry_revision| entry_revision > 0 && entry_revision <= revision)
        })
}

fn native_text(value: &str) -> String {
    let mut end = value.len().min(64 * 1024);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn native_run_state(value: &str) -> RunState {
    match value {
        "queued" => RunState::Queued,
        "starting" => RunState::Starting,
        "running" => RunState::Running,
        "waiting_for_approval" => RunState::WaitingForApproval,
        "waiting_for_answer" => RunState::WaitingForAnswer,
        "paused" => RunState::Paused,
        "blocked" => RunState::Blocked,
        "outcome_unknown" => RunState::OutcomeUnknown,
        "failed" => RunState::Failed,
        "cancelled" => RunState::Cancelled,
        "completed" => RunState::Completed,
        "completed_with_changes" => RunState::CompletedWithChanges,
        _ => RunState::Draft,
    }
}

fn native_run_id(value: &serde_json::Value) -> Option<&str> {
    value.as_str().filter(|id| {
        id.len() == 64
            && id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::controller::{ProductConnection, ProductUpdate};
    use serde_json::json;

    const fn connection(generation: u64) -> ProductConnection {
        ProductConnection {
            generation,
            epoch: 1,
        }
    }

    #[test]
    fn native_memory_result_before_receipt_cannot_release_the_original_input() {
        let connection = ProductConnection {
            generation: 0,
            epoch: 1,
        };
        let mut state = ProductState::native();
        state.apply_native(ProductUpdate::Ready { connection });
        let params = state
            .native_memory(
                &state.memory_binding(),
                &MemoryForm {
                    action: 0,
                    id: "",
                    kind: 0,
                    revision: "",
                    offset: "",
                    content: "",
                    overwrite: false,
                },
            )
            .expect("memory list");
        state.native_message_enqueued(&params);
        state.apply_native(ProductUpdate::Event { connection, name: "chat".to_owned(), payload: serde_json::json!({"sessionId":params["sessionKey"],"runId":"a".repeat(64),"status":"completed","text":"early result"}) });
        assert!(!state.can_send_native_message());
        assert!(state.memory_result().is_empty());
        state.apply_native(ProductUpdate::Failed {
            connection,
            method: "chat.send",
            params: params.clone(),
            definitive: false,
        });
        assert_eq!(state.retry_native_memory(), Some(params.clone()));
        state.native_message_enqueued(&params);
        state.apply_native(ProductUpdate::Response { connection, method: "chat.send", params: params.clone(), payload: serde_json::json!({"durable":true,"sessionId":params["sessionKey"],"runId":"a".repeat(64),"status":"accepted","revision":1,"phase":"finished"}) });
        assert!(!state.can_send_native_message());
        state.apply_native(ProductUpdate::Response { connection, method: "agent.wait", params: serde_json::json!({"runId":"a".repeat(64)}), payload: serde_json::json!({"durable":true,"sessionId":params["sessionKey"],"runId":"a".repeat(64),"phase":"finished","revision":3,"result":{"status":"completed","text":"complete verified result"}}) });
        assert!(state.can_send_native_message());
        assert_eq!(state.memory_result(), "complete verified result");
    }

    #[test]
    fn native_memory_uncertainty_survives_refused_retry_and_checks_durable_receipts() {
        let connection = ProductConnection {
            generation: 0,
            epoch: 1,
        };
        let mut state = ProductState::native();
        state.apply_native(ProductUpdate::Ready { connection });
        let params = state
            .native_memory(
                &state.memory_binding(),
                &MemoryForm {
                    action: 0,
                    id: "",
                    kind: 0,
                    revision: "",
                    offset: "",
                    content: "",
                    overwrite: false,
                },
            )
            .expect("memory list");
        state.native_message_enqueued(&params);
        state.apply_native(ProductUpdate::Response { connection, method: "chat.send", params: params.clone(), payload: serde_json::json!({"durable":true,"sessionId":"wrong-session","runId":"a".repeat(64),"status":"accepted","revision":1,"phase":"queued"}) });
        assert_eq!(state.selected_run.state, RunState::OutcomeUnknown);
        assert_eq!(state.retry_native_memory(), Some(params.clone()));
        state.native_message_enqueued(&params);
        assert!(state.retry_native_memory().is_none());
        state.apply_native(ProductUpdate::Failed {
            connection,
            method: "chat.send",
            params: params.clone(),
            definitive: true,
        });
        assert_eq!(state.selected_run.state, RunState::OutcomeUnknown);
        assert_eq!(state.retry_native_memory(), Some(params.clone()));
        assert!(!state.can_send_native_message());
        state.native_message_enqueued(&params);
        state.apply_native(ProductUpdate::Response { connection, method: "chat.send", params: params.clone(), payload: serde_json::json!({"durable":true,"sessionId":params["sessionKey"],"runId":"a".repeat(64),"status":"accepted","revision":1,"phase":"queued"}) });
        assert!(state.retry_native_memory().is_none());
        assert!(
            state
                .native
                .as_ref()
                .expect("native")
                .queries
                .iter()
                .any(|(method, query)| *method == "agent.wait" && query["runId"] == "a".repeat(64))
        );
        state.apply_native(ProductUpdate::Response { connection, method: "agent.wait", params: serde_json::json!({"runId":"a".repeat(64)}), payload: serde_json::json!({"durable":true,"sessionId":params["sessionKey"],"runId":"a".repeat(64),"phase":"finished","revision":3,"result":{"status":"completed","text":"memory result"}}) });
        assert!(state.can_send_native_message());
        assert!(state.retry_native_memory().is_none());
        assert_eq!(state.memory_result(), "memory result");
        state.native_unavailable();
        assert!(state.memory_result().is_empty());
    }

    #[test]
    fn native_memory_form_keeps_revision_body_and_archive_bytes_separate_from_chat() {
        let mut state = ProductState::native();
        state.apply_native(ProductUpdate::Ready {
            connection: ProductConnection {
                generation: 0,
                epoch: 1,
            },
        });
        let form = MemoryForm {
            action: 3,
            id: "Mixed.Case",
            kind: 1,
            revision: "7",
            offset: "",
            content: "private note\n!goal {}",
            overwrite: false,
        };
        let binding = state.memory_binding();
        assert!(state.native_memory("old-connection", &form).is_err());
        let params = state
            .native_memory(&binding, &form)
            .expect("explicit memory parameters");
        let message = params["message"].as_str().expect("message");
        let envelope: serde_json::Value =
            serde_json::from_str(message.strip_prefix("!tool ").expect("direct prefix"))
                .expect("envelope");
        assert_eq!(
            envelope["arguments"],
            serde_json::json!({"action":"save","id":"Mixed.Case","kind":"preference","content":"private note\n!goal {}","expectedRevision":7})
        );
        assert_eq!(message.lines().count(), 1);
        assert!(state.native_message(message).is_none());
        state.native_message_enqueued(&params);
        assert!(!state.can_send_native_message());
        assert!(
            !state.sessions[&state.selected_run.id]
                .transcript
                .iter()
                .any(|entry| entry.text.contains("private note"))
        );
        let archive =
            "{\"schemaVersion\":1,\"notebook\":{\"revision\":0,\"revision\":1,\"entries\":[]}}";
        let import = MemoryForm {
            action: 6,
            id: "",
            kind: 0,
            revision: "0",
            offset: "",
            content: archive,
            overwrite: false,
        };
        assert!(import.message().is_err());
        let archive = "{\n\"schemaVersion\":1,\n\"notebook\":{\"revision\":0,\"entries\":[]}}";
        let import = MemoryForm {
            content: archive,
            ..import
        };
        assert_eq!(
            import
                .message()
                .expect("strict compact archive")
                .lines()
                .count(),
            1
        );
        let archive =
            "{\"schemaVersion\":1,\"notebook\":{\"revision\":0,\"entries\":[]},\"extra\":true}";
        assert!(
            MemoryForm {
                content: archive,
                ..import
            }
            .message()
            .is_err()
        );
        for action in 0..=5 {
            let form = MemoryForm {
                action,
                id: "Note",
                kind: 0,
                revision: "0",
                offset: "0",
                content: "data",
                overwrite: false,
            };
            assert!(form.message().is_ok());
        }
        assert!(
            MemoryForm {
                action: 1,
                id: "Note",
                kind: 0,
                revision: "",
                offset: "1",
                content: "",
                overwrite: false
            }
            .message()
            .is_err()
        );
        assert!(
            MemoryForm {
                action: 4,
                id: "Note",
                kind: 0,
                revision: "-1",
                offset: "",
                content: "",
                overwrite: false
            }
            .message()
            .is_err()
        );
        assert!(
            MemoryForm {
                action: 3,
                id: "Note",
                kind: 0,
                revision: "0",
                offset: "",
                content: &"\\".repeat(8_192),
                overwrite: false
            }
            .message()
            .is_err()
        );
    }

    #[test]
    fn native_history_cannot_erase_a_message_queued_after_its_snapshot() {
        let mut state = ProductState::native();
        state.apply_native(ProductUpdate::Ready {
            connection: connection(0),
        });
        state.apply_native(ProductUpdate::HistoryStarted {
            connection: connection(0),
            request: 1,
            session: "native-session".to_owned(),
        });
        let params = state.native_message("new local message").expect("message");
        state.native_message_enqueued(&params);
        state.apply_native(ProductUpdate::HistoryFinished {
            connection: connection(0),
            request: 1,
            payload: Some(json!({"sessionKey": "native-session", "messages": []})),
        });
        assert!(
            state
                .transcript()
                .iter()
                .any(|message| message.text == "new local message")
        );
    }

    #[test]
    fn native_durable_result_unknown_is_terminal_and_unconfirmed_ack_cannot_advance_recovery() {
        for durable in [false, true] {
            let mut state = ProductState::native();
            let connection = connection(0);
            state.apply_native(ProductUpdate::Ready { connection });
            while state.next_native_query().is_some() {}
            let run = "e".repeat(64);
            let payload = json!({"runId":run,"sessionId":"native-session","phase":"outcome_unknown","turn":1,"revision":4,"durable":durable,"result":{"status":"outcome_unknown","text":"Reconcile the original operation before retrying"}});
            state.apply_native(ProductUpdate::Response {
                connection,
                method: "agent.wait",
                params: json!({"runId":run}),
                payload,
            });
            if !durable {
                assert!(state.transcript().is_empty());
                assert!(state.next_native_query().is_none());
                continue;
            }
            assert_eq!(state.selected_run().state, RunState::OutcomeUnknown);
            assert!(state.selected_run().state.is_terminal());
            assert_eq!(state.selected_run().state.label(), "Outcome unknown");
            assert!(state.native_abort().is_none());
            while state.next_native_query().is_some() {}
            for revision in [3, 4] {
                state.apply_native(ProductUpdate::Response { connection, method:"agent.wait", params:json!({"runId":run,"acknowledgeRevision":4}), payload:json!({"runId":run,"sessionId":"native-session","revision":revision,"durable":true,"acknowledged":true}) });
                assert_eq!(
                    state.next_native_query(),
                    (revision == 4)
                        .then(|| ("sessions.get", json!({"sessionKey":"native-session"})))
                );
            }
        }
    }

    #[test]
    fn native_durable_result_is_queried_before_acknowledgement_and_limits_fail_closed() {
        let mut state = ProductState::native();
        let connection = connection(0);
        state.apply_native(ProductUpdate::Ready { connection });
        while state.next_native_query().is_some() {}
        let run = "a".repeat(64);
        state.apply_native(ProductUpdate::Event { connection, name: "chat".to_owned(), payload: json!({"sessionId": "native-session", "runId": run, "resultAvailable": true, "revision": 4, "turn": 2}) });
        assert!(state.transcript().is_empty());
        assert_eq!(
            state.next_native_query(),
            Some(("agent.wait", json!({"runId": run})))
        );
        let mut result = json!({"runId": run, "sessionId": "native-session", "phase": "finished", "turn": 2, "revision": 4, "durable": true, "result": {"status": "completed", "text": "retained answer"}});
        result["result"]["text"] = json!("x".repeat(64 * 1024 + 1));
        state.apply_native(ProductUpdate::Response {
            connection,
            method: "agent.wait",
            params: json!({"runId": run}),
            payload: result.clone(),
        });
        assert!(
            state.next_native_query().is_none(),
            "oversized result must not be acknowledged"
        );
        result["result"]["text"] = json!("retained answer");
        state.apply_native(ProductUpdate::Response {
            connection,
            method: "agent.wait",
            params: json!({"runId": run}),
            payload: result,
        });
        assert!(
            state
                .transcript()
                .iter()
                .any(|entry| entry.text == "retained answer")
        );
        assert_eq!(state.selected_run().state, RunState::Completed);
        assert_eq!(
            state.next_native_query(),
            Some(("chat.history", json!({"sessionKey": "native-session"})))
        );
        assert_eq!(
            state.next_native_query(),
            Some((
                "agent.wait",
                json!({"runId": run, "acknowledgeRevision": 4})
            ))
        );
        state.apply_native(ProductUpdate::Event { connection, name: "session.operation".to_owned(), payload: json!({"sessionId": "native-session", "runId": "older-run", "turn": 1, "state": "running"}) });
        assert_eq!(state.selected_run().state, RunState::Completed);
    }

    #[test]
    fn native_history_responses_cannot_overwrite_newer_content_in_the_same_epoch() {
        let mut state = ProductState::native();
        let connection = connection(0);
        state.apply_native(ProductUpdate::Ready { connection });
        while state.next_native_query().is_some() {}
        state.apply_native(ProductUpdate::HistoryStarted {
            connection,
            request: 1,
            session: "native-session".to_owned(),
        });
        state.apply_native(ProductUpdate::Event { connection, name: "chat".to_owned(), payload: json!({"sessionId": "native-session", "runId": "current", "status": "completed", "text": "new answer"}) });
        state.apply_native(ProductUpdate::HistoryFinished { connection, request: 1, payload: Some(json!({"sessionKey": "native-session", "messages": [{"role": "assistant", "text": "old answer"}]})) });
        assert!(
            state
                .transcript()
                .iter()
                .any(|message| message.text == "new answer")
        );
        assert!(
            !state
                .transcript()
                .iter()
                .any(|message| message.text == "old answer")
        );
        state.apply_native(ProductUpdate::HistoryStarted {
            connection,
            request: 2,
            session: "native-session".to_owned(),
        });
        state.apply_native(ProductUpdate::HistoryFinished { connection, request: 2, payload: Some(json!({"sessionKey": "native-session", "messages": [{"role": "user", "text": "question"}, {"role": "assistant", "text": "new answer"}]})) });
        assert_eq!(state.transcript().len(), 2);
        assert_eq!(state.transcript()[0].text, "question");
        assert_eq!(state.transcript()[1].text, "new answer");
    }

    #[test]
    fn native_idempotency_keys_do_not_repeat_after_application_restart() {
        let mut first = ProductState::native();
        first.apply_native(ProductUpdate::Ready {
            connection: connection(0),
        });
        let original = first
            .native_message("first lifetime")
            .expect("first request");
        let mut second = ProductState::native();
        second.apply_native(ProductUpdate::Ready {
            connection: connection(0),
        });
        let next = second.native_message("new lifetime").expect("new request");
        assert_ne!(original["idempotencyKey"], next["idempotencyKey"]);
    }

    #[test]
    fn native_bound_approval_preserves_its_token_and_rejects_malformed_fingerprints() {
        let token = "c".repeat(64);
        let fingerprint = claw_security::authorization::approval_preview_fingerprint(&token)
            .expect("fingerprint");
        let mut preview = json!({"id": "approval-1", "sessionId": "native-session", "tool": "fs_write", "previewComplete": true, "toolRevision": 1, "bindingToken": token, "previewFingerprint": fingerprint,
            "toolPublication": "workspace-fixture", "resourceScope": "workspace: reviewed.txt",
            "caller": {"source": "Http", "subject": "verified-device", "account": null, "permissionGeneration": 0, "owner": true}});
        preview["prompt"] = json!(format!(
            "{}fs_write\n{{}}",
            claw_protocol::native_approval::bound_approval_context_header(&preview)
                .expect("context")
        ));
        let mut state = ProductState::native();
        state.apply_native(ProductUpdate::Ready {
            connection: connection(0),
        });
        for field in [
            "bindingToken",
            "previewFingerprint",
            "caller",
            "toolPublication",
            "toolRevision",
            "resourceScope",
        ] {
            let mut broken = preview.clone();
            broken.as_object_mut().expect("preview").remove(field);
            state.apply_native(ProductUpdate::Response {
                connection: connection(0),
                method: "exec.approval.get",
                params: json!({"id": "approval-1"}),
                payload: broken,
            });
            assert!(state.native_approval(true).is_none());
        }
        state.apply_native(ProductUpdate::Response {
            connection: connection(0),
            method: "exec.approval.get",
            params: json!({"id": "approval-1"}),
            payload: preview,
        });
        assert_eq!(
            state.native_approval(true).expect("bound decision")["bindingToken"],
            token
        );
        let display = &state
            .sessions
            .get("native-session")
            .expect("approval session")
            .approval_prompt;
        assert!(display.contains("Caller: Http / verified-device"));
        assert!(display.contains("Resource: workspace: reviewed.txt"));
        assert!(!format!("{state:?}").contains(&token));
    }

    #[test]
    fn native_approval_requires_a_complete_current_preview_and_recovers_on_ready() {
        let mut state = ProductState::native();
        state.apply_native(ProductUpdate::Reset { generation: 1 });
        state.apply_native(ProductUpdate::Ready {
            connection: connection(1),
        });
        let mut initial = Vec::new();
        while let Some((method, _)) = state.next_native_query() {
            initial.push(method);
        }
        assert_eq!(
            initial,
            [
                "sessions.list",
                "chat.history",
                "sessions.get",
                "exec.approval.list"
            ]
        );
        let metadata =
            json!({"id": "approval-1", "sessionId": "native-session", "tool": "write-file"});
        state.apply_native(ProductUpdate::Event {
            connection: connection(1),
            name: "exec.approval.requested".to_owned(),
            payload: metadata,
        });
        assert!(!state.can_present_approval());
        assert_eq!(
            state.next_native_query(),
            Some(("exec.approval.get", json!({"id": "approval-1"})))
        );
        let preview = json!({"id": "approval-1", "sessionId": "native-session", "prompt": "write-file\n{\"path\":\"example.txt\"}", "previewComplete": true});
        for (field, value) in [
            ("previewComplete", json!(false)),
            ("id", json!("other-id")),
            ("prompt", json!("x".repeat(32 * 1024 + 1))),
        ] {
            let mut invalid = preview.clone();
            invalid[field] = value;
            state.apply_native(ProductUpdate::Response {
                connection: connection(1),
                method: "exec.approval.get",
                params: json!({"id": "approval-1"}),
                payload: invalid,
            });
            assert!(!state.can_present_approval());
        }
        state.apply_native(ProductUpdate::Response {
            connection: connection(1),
            method: "exec.approval.get",
            params: json!({"id": "approval-1"}),
            payload: preview.clone(),
        });
        assert_eq!(
            state.native_approval(true),
            Some(json!({"id": "approval-1", "decision": "approve"}))
        );
        state.apply_native(ProductUpdate::Event {
            connection: connection(1),
            name: "exec.approval.resolved".to_owned(),
            payload: json!({"id": "approval-1"}),
        });
        state.apply_native(ProductUpdate::Response {
            connection: connection(1),
            method: "exec.approval.get",
            params: json!({"id": "approval-1"}),
            payload: preview,
        });
        assert!(!state.can_present_approval());
        assert_eq!(
            state.next_native_query(),
            Some(("exec.approval.list", json!({"sessionId": "native-session"})))
        );
    }

    #[test]
    fn native_projection_rejects_previous_epoch_history_and_approval_results() {
        let mut state = ProductState::native();
        let first = connection(0);
        let second = ProductConnection { epoch: 2, ..first };
        state.apply_native(ProductUpdate::Ready { connection: first });
        state.apply_native(ProductUpdate::Unavailable { generation: 0 });
        state.apply_native(ProductUpdate::Ready { connection: second });
        state.apply_native(ProductUpdate::Response {
            connection: first,
            method: "chat.history",
            params: json!({"sessionKey": "native-session"}),
            payload: json!({"messages": [{"role": "assistant", "text": "old connection"}]}),
        });
        state.apply_native(ProductUpdate::Response { connection: first, method: "exec.approval.get", params: json!({"id": "approval-1"}), payload: json!({"id": "approval-1", "sessionId": "native-session", "prompt": "stale approval", "previewComplete": true}) });
        state.apply_native(ProductUpdate::Failed {
            connection: first,
            method: "chat.send",
            params: json!({"sessionKey": "native-session"}),
            definitive: false,
        });
        assert!(state.transcript().is_empty());
        assert!(!state.can_present_approval());
        assert_eq!(state.native_connection(), Some(second));
    }

    #[test]
    fn native_reconnect_restores_active_run_without_creating_another_execution() {
        let mut state = ProductState::native();
        let first = connection(0);
        state.apply_native(ProductUpdate::Ready { connection: first });
        let params = state.native_message("pending work").expect("prepared");
        state.native_message_enqueued(&params);
        state.apply_native(ProductUpdate::Unavailable { generation: 0 });
        let second = ProductConnection { epoch: 2, ..first };
        state.apply_native(ProductUpdate::Ready { connection: second });
        assert!(!state.can_send_native_message());
        let run = "b".repeat(64);
        state.apply_native(ProductUpdate::Response { connection: second, method: "sessions.get", params: json!({"sessionKey": "native-session"}), payload: json!({"sessionKey": "native-session", "pendingRuns": [], "activeRuns": [{"runId": run, "sessionId": "native-session", "phase": "executing", "turn": 1}], "nextCursor": null, "nextActiveCursor": null}) });
        assert_eq!(
            state.native_abort(),
            Some(json!({"sessionKey": "native-session", "runId": run}))
        );
        assert!(!state.can_send_native_message());
        while let Some((method, _)) = state.next_native_query() {
            assert_ne!(method, "chat.send");
        }
    }

    #[test]
    fn native_stop_is_bound_to_the_live_run_and_a_late_receipt_cannot_revive_it() {
        let mut state = ProductState::native();
        let connection = connection(0);
        state.apply_native(ProductUpdate::Ready { connection });
        let run = "a".repeat(64);
        let params = state.native_message("one request").expect("prepared");
        state.native_message_enqueued(&params);
        state.apply_native(ProductUpdate::Response {
            connection,
            method: "chat.send",
            params: params.clone(),
            payload: json!({"runId": run, "durable": true, "phase": "executing"}),
        });
        assert_eq!(
            state.native_abort(),
            Some(json!({"sessionKey": "native-session", "runId": run}))
        );
        assert!(!state.can_send_native_message());
        state.apply_native(ProductUpdate::Event { connection, name: "chat".to_owned(), payload: json!({"sessionId": "native-session", "runId": run, "turn": 0, "status": "cancelled", "text": ""}) });
        state.apply_native(ProductUpdate::Response {
            connection,
            method: "chat.send",
            params,
            payload: json!({"runId": run, "phase": "queued", "durable": true}),
        });
        assert!(state.native_abort().is_none());
        assert!(state.can_send_native_message());
        assert_eq!(state.selected_run().state, RunState::Cancelled);
    }

    #[test]
    fn native_unknown_send_preserves_its_key_but_explicit_rejection_releases_the_session() {
        let mut state = ProductState::native();
        let connection = connection(0);
        state.apply_native(ProductUpdate::Ready { connection });
        let params = state.native_message("one request").expect("message");
        state.native_message_enqueued(&params);
        state.apply_native(ProductUpdate::Failed {
            connection,
            method: "chat.send",
            params: params.clone(),
            definitive: false,
        });
        assert!(state.native_message("replacement").is_none());
        assert_eq!(
            state.native.as_ref().expect("native").pending_submissions["native-session"]["idempotencyKey"],
            params["idempotencyKey"]
        );
        state.apply_native(ProductUpdate::Failed {
            connection,
            method: "chat.send",
            params,
            definitive: true,
        });
        assert!(state.native_message("new authorized request").is_some());
    }

    #[test]
    fn native_message_is_not_displayed_until_the_command_is_enqueued() {
        let mut state = ProductState::native();
        state.apply_native(ProductUpdate::Ready {
            connection: connection(0),
        });
        let params = state
            .native_message("queued message")
            .expect("prepared message");
        assert!(state.sessions["native-session"].transcript.is_empty());
        state.native_message_enqueued(&params);
        assert_eq!(state.sessions["native-session"].transcript.len(), 1);
        assert_eq!(
            state.sessions["native-session"].transcript[0].text,
            "queued message"
        );
    }

    #[test]
    fn native_projection_is_empty_bounded_and_ignores_previous_gateway_events() {
        let mut state = ProductState::native();
        assert!(state.transcript().is_empty());
        assert!(state.workspaces().is_empty());
        assert!(state.deliverables().is_empty());
        assert!(state.session_files().is_empty());
        assert_eq!(state.selected_file_name(), "");
        assert_eq!(state.selected_deliverable_content(), "");
        state.apply_native(ProductUpdate::Reset { generation: 2 });
        state.apply_native(ProductUpdate::Event { connection: connection(1), name: "chat".to_owned(), payload: json!({"sessionId": "native-session", "runId": "old", "text": "private old message"}) });
        assert!(state.transcript().is_empty());
        assert!(state.native_message("offline send").is_none());
        state.apply_native(ProductUpdate::Ready {
            connection: connection(2),
        });
        assert!(state.native_message("hello").is_some());
        state.apply_native(ProductUpdate::Event { connection: connection(2), name: "chat".to_owned(), payload: json!({"sessionId": "native-session", "runId": "current", "status": "completed", "text": "answer"}) });
        state.apply_native(ProductUpdate::Response {
            connection: connection(2),
            method: "chat.send",
            params: json!({"sessionKey": "native-session"}),
            payload: json!({"runId": "current"}),
        });
        assert_eq!(state.selected_run().state, RunState::Completed);
        state.apply_native(ProductUpdate::Reset { generation: 3 });
        assert!(state.transcript().is_empty());
        assert!(state.native_approval(true).is_none());
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
            location: "No trusted path loaded".to_owned(),
            kind: "Preview workspace".to_owned(),
            branch: "Workspace trust is not composed".to_owned(),
            active_runs: 3,
        },
        WorkspaceSummary {
            name: "Gateway lab".to_owned(),
            location: "No trusted path loaded".to_owned(),
            kind: "Preview workspace".to_owned(),
            branch: "Workspace trust is not composed".to_owned(),
            active_runs: 1,
        },
        WorkspaceSummary {
            name: "Release workspace".to_owned(),
            location: "No remote workspace loaded".to_owned(),
            kind: "Preview workspace".to_owned(),
            branch: "Remote workspace integration is not composed".to_owned(),
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
            name: "diagnostic-availability.json".to_owned(),
            kind: "Structured data".to_owned(),
            source: "Desktop preview".to_owned(),
            size: "180 B".to_owned(),
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
    fn all_run_states_have_stable_labels_and_tones() {
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
            ("Outcome unknown", SemanticTone::Warning, true),
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
        assert_eq!(
            state.selected_deliverable().name,
            "diagnostic-availability.json"
        );
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
        assert_eq!(state.runs().page_count(), 6);
        let rows = demo_runs();
        assert_eq!(rows.len(), 130);
        let state_counts = RunState::ALL
            .into_iter()
            .map(|run_state| {
                rows.iter()
                    .filter(|summary| summary.state == run_state)
                    .count()
            })
            .collect::<Vec<_>>();
        assert_eq!(state_counts, vec![10; 13]);
        assert!(rows.as_chunks::<24>().0.iter().all(|page| {
            RunState::ALL
                .into_iter()
                .all(|run_state| page.iter().any(|run| run.state == run_state))
        }));
    }
}

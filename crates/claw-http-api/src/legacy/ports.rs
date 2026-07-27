//! Typed services consumed by the legacy Node-compatible routes.

use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::{PortError, PortFuture, ReadinessPort};

/// Current runtime metadata rendered by `/` and `/health`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyRuntimeSnapshot {
    /// Number of loaded skills.
    pub skill_count: usize,
    /// Active model identifier.
    pub active_model: String,
    /// Number of active conversation sessions.
    pub session_count: usize,
    /// Whether chat can currently authenticate to its provider.
    pub authenticated: bool,
}

/// Legacy HTTP chat and runtime-status adapter.
pub trait LegacyRuntimePort: Send + Sync {
    /// Returns the current runtime metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PortError`] when runtime state cannot be observed.
    fn snapshot(&self) -> Result<LegacyRuntimeSnapshot, PortError>;

    /// Runs one conversation turn.
    fn chat(
        &self,
        conversation_id: String,
        message: String,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>>;
}

/// Supplies reusable GitHub Device Flow instructions.
pub trait LegacyDeviceFlowPort: Send + Sync {
    /// Returns current instructions, starting a flow when necessary.
    fn instructions(
        &self,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>>;
}

/// Accepts one bounded Bot Framework activity.
pub trait LegacyTeamsPort: Send + Sync {
    /// Processes one decoded Bot Framework request body.
    fn handle_activity(
        &self,
        activity: Value,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>>;
}

/// One normalized inbound channel message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyChannelMessage {
    /// Stable channel identity.
    pub channel: &'static str,
    /// Conversation/session identity.
    pub conversation_id: String,
    /// Display identity supplied by the channel.
    pub user_name: String,
    /// Trimmed inbound text.
    pub text: String,
}

/// Runs normalized inbound messages through the composed agent runtime.
pub trait LegacyChannelMessagePort: Send + Sync {
    /// Processes one inbound message and returns its reply.
    fn process(
        &self,
        message: LegacyChannelMessage,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<String, PortError>>;
}

/// Sends one already-bounded `WhatsApp` text chunk.
pub trait LegacyWhatsAppPort: Send + Sync {
    /// Sends one chunk to a phone-number identity.
    fn send_text(
        &self,
        to: String,
        text: String,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<(), PortError>>;
}

/// Services required by the `WhatsApp` compatibility route.
#[derive(Clone)]
pub struct LegacyWhatsAppServices {
    /// Shared inbound channel-message processor.
    pub messages: Arc<dyn LegacyChannelMessagePort>,
    /// Concrete outbound `WhatsApp` transport.
    pub sender: Arc<dyn LegacyWhatsAppPort>,
}

/// Successful legacy reload metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyReloadResult {
    /// Optional model selected by the reloaded role.
    pub role_model: Option<String>,
    /// Number of successfully loaded skills.
    pub skill_count: usize,
}

/// Stable reload refusal classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyReloadError {
    /// Another reload owns the transaction.
    InProgress,
    /// The reload transaction failed.
    Failed,
}

/// Transactional role/skill reload adapter.
pub trait LegacyReloadPort: Send + Sync {
    /// Reloads role and skill state.
    fn reload(
        &self,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacyReloadResult, LegacyReloadError>>;
}

/// One legacy read-only command identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyAdminAction {
    /// Host uptime.
    Uptime,
    /// Filesystem capacity.
    Disk,
    /// Host memory summary.
    Memory,
    /// One process snapshot.
    Top,
    /// Running containers.
    DockerPs,
    /// Container resource snapshot.
    DockerStats,
    /// Local container images.
    DockerImages,
    /// Tail one container's logs.
    DockerLogs,
    /// Listening network sockets.
    Netstat,
    /// Logged-in users.
    Who,
    /// Host name.
    Hostname,
    /// Current host date.
    Date,
}

impl LegacyAdminAction {
    /// Parses an exact legacy action name.
    #[must_use]
    pub fn parse(action: &str) -> Option<Self> {
        match action {
            "uptime" => Some(Self::Uptime),
            "disk" => Some(Self::Disk),
            "memory" => Some(Self::Memory),
            "top" => Some(Self::Top),
            "docker_ps" => Some(Self::DockerPs),
            "docker_stats" => Some(Self::DockerStats),
            "docker_images" => Some(Self::DockerImages),
            "docker_logs" => Some(Self::DockerLogs),
            "netstat" => Some(Self::Netstat),
            "who" => Some(Self::Who),
            "hostname" => Some(Self::Hostname),
            "date" => Some(Self::Date),
            _ => None,
        }
    }

    /// Returns the exact legacy action name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uptime => "uptime",
            Self::Disk => "disk",
            Self::Memory => "memory",
            Self::Top => "top",
            Self::DockerPs => "docker_ps",
            Self::DockerStats => "docker_stats",
            Self::DockerImages => "docker_images",
            Self::DockerLogs => "docker_logs",
            Self::Netstat => "netstat",
            Self::Who => "who",
            Self::Hostname => "hostname",
            Self::Date => "date",
        }
    }
}

/// Frozen ordered legacy admin action allowlist.
pub const LEGACY_ADMIN_ACTIONS: &[&str] = &[
    "uptime",
    "disk",
    "memory",
    "top",
    "docker_ps",
    "docker_stats",
    "docker_images",
    "docker_logs",
    "netstat",
    "who",
    "hostname",
    "date",
];

/// Legacy process-memory fields, in rounded MiB.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyProcessMemory {
    /// Resident set size.
    pub rss: u64,
    /// Used managed/runtime heap.
    pub heap_used: u64,
    /// Allocated managed/runtime heap.
    pub heap_total: u64,
}

/// Legacy process metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LegacyProcessInfo {
    /// Runtime version string.
    pub version: String,
    /// Process identifier.
    pub pid: u32,
    /// Floored process uptime in seconds.
    pub uptime_s: u64,
    /// Process memory values.
    pub memory_mb: LegacyProcessMemory,
}

/// Legacy host metadata.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LegacyOsInfo {
    /// Host name.
    pub hostname: String,
    /// Operating-system identity.
    pub platform: String,
    /// CPU architecture.
    pub arch: String,
    /// Logical CPU count.
    pub cpus: usize,
    /// Total host memory in rounded MiB.
    #[serde(rename = "totalMemory_mb")]
    pub total_memory_mb: u64,
    /// Free host memory in rounded MiB.
    #[serde(rename = "freeMemory_mb")]
    pub free_memory_mb: u64,
    /// Floored host uptime in seconds.
    pub uptime_s: u64,
    /// One-, five-, and fifteen-minute load averages.
    pub loadavg: [f64; 3],
}

/// Exact `/admin/system` response structure.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LegacySystemInfo {
    /// Process/runtime section, retained under the historical `node` key.
    pub node: LegacyProcessInfo,
    /// Operating-system section.
    pub os: LegacyOsInfo,
}

/// Result of one allowlisted host command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyExecResult {
    /// Whether the command exited successfully.
    pub success: bool,
    /// Successful standard output.
    pub output: Option<String>,
    /// Safe failure description.
    pub error: Option<String>,
    /// Captured standard error.
    pub stderr: Option<String>,
}

/// Host inspection and allowlisted command adapter.
pub trait LegacyHostAdminPort: Send + Sync {
    /// Returns typed process and host metadata.
    fn system_info(
        &self,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacySystemInfo, PortError>>;

    /// Executes one already-allowlisted action.
    fn execute(
        &self,
        action: LegacyAdminAction,
        target: Option<String>,
        cancellation: CancellationToken,
    ) -> PortFuture<'_, Result<LegacyExecResult, PortError>>;
}

/// All services consumed by [`crate::LegacyHttpApi`].
#[derive(Clone)]
pub struct LegacyApiServices {
    /// Chat and runtime status.
    pub runtime: Arc<dyn LegacyRuntimePort>,
    /// Dependency readiness.
    pub readiness: Arc<dyn ReadinessPort>,
    /// Optional GitHub Device Flow adapter.
    pub device_flow: Option<Arc<dyn LegacyDeviceFlowPort>>,
    /// Optional Teams/Bot Framework adapter.
    pub teams: Option<Arc<dyn LegacyTeamsPort>>,
    /// Optional `WhatsApp` message and outbound adapters.
    pub whatsapp: Option<LegacyWhatsAppServices>,
    /// Optional reload transaction.
    pub reload: Option<Arc<dyn LegacyReloadPort>>,
    /// Optional process/system administration adapter.
    pub admin: Option<Arc<dyn LegacyHostAdminPort>>,
}

//! The subsystem contract: what every plugged-in crate must provide.

use std::fmt::{self, Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

use super::clock::Clock;
use super::error::SubsystemError;
use super::id::SubsystemId;
use super::session::RuntimeSettings;
use super::{BoxFuture, ShutdownSignal};

/// The role a subsystem plays, which decides when it is quiesced.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SubsystemKind {
    /// Configuration, telemetry, persistence and secrets: things every other
    /// subsystem may depend on and which own no request of their own.
    Foundation,
    /// Providers, tools, memory, the plugin host and the session engine: they do
    /// work, but only work someone else asked for.
    Capability,
    /// The gateway, the HTTP API, channels, bridges and automation triggers:
    /// anything that can introduce new work from outside the process.
    ///
    /// Ingress is stopped first during shutdown, before draining, so that the
    /// set of in-flight work stops growing while it is being drained.
    Ingress,
}

impl SubsystemKind {
    /// Returns the stable label used in readiness and shutdown output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Foundation => "foundation",
            Self::Capability => "capability",
            Self::Ingress => "ingress",
        }
    }
}

impl Display for SubsystemKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// What a subsystem is called and what it needs started before it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubsystemDescriptor {
    id: SubsystemId,
    kind: SubsystemKind,
    dependencies: Vec<SubsystemId>,
}

impl SubsystemDescriptor {
    /// Describes a subsystem with no dependencies yet.
    #[must_use]
    pub const fn new(id: SubsystemId, kind: SubsystemKind) -> Self {
        Self {
            id,
            kind,
            dependencies: Vec::new(),
        }
    }

    /// Adds a dependency that must be started first.
    ///
    /// Declaring the same dependency twice is not an error; the plan collapses
    /// repeated edges.
    #[must_use]
    pub fn depends_on(mut self, dependency: SubsystemId) -> Self {
        self.dependencies.push(dependency);
        self
    }

    /// Returns the subsystem identifier.
    #[must_use]
    pub const fn id(&self) -> &SubsystemId {
        &self.id
    }

    /// Returns the subsystem role.
    #[must_use]
    pub const fn kind(&self) -> SubsystemKind {
        self.kind
    }

    /// Returns the declared dependencies in declaration order.
    #[must_use]
    pub fn dependencies(&self) -> &[SubsystemId] {
        &self.dependencies
    }
}

/// Spawns background work on behalf of a subsystem.
///
/// Subsystems are handed this instead of being allowed to reach for an async
/// runtime directly, because the daemon has to be able to prove at shutdown
/// that every task it started has finished. A task spawned through this port is
/// registered with the daemon's task tracker before it is polled, so
/// `TaskTracker::wait` cannot return while it is still running.
///
/// The `name` is used in shutdown diagnostics and must be a compile-time
/// constant so that it cannot leak request data into logs.
pub trait TaskSpawner: Send + Sync + 'static {
    /// Spawns `task`, returning once it is registered but before it completes.
    ///
    /// # Errors
    ///
    /// Returns [`SubsystemError`] with kind
    /// [`Cancelled`](super::error::SubsystemErrorKind::Cancelled) when the
    /// daemon has already begun shutting down, in which case the task is not
    /// started at all.
    fn spawn(&self, name: &'static str, task: BoxFuture<'static, ()>)
    -> Result<(), SubsystemError>;
}

/// Everything a subsystem is given when it initializes and starts.
///
/// Handles are owned and cheaply cloneable so that a subsystem can move them
/// into the `'static` tasks it spawns.
#[derive(Clone)]
pub struct StartContext {
    subsystem: SubsystemId,
    settings: Arc<RuntimeSettings>,
    spawner: Arc<dyn TaskSpawner>,
    shutdown: Arc<dyn ShutdownSignal>,
    clock: Arc<dyn Clock>,
}

impl StartContext {
    /// Creates a context for `subsystem`.
    #[must_use]
    pub fn new(
        subsystem: SubsystemId,
        settings: Arc<RuntimeSettings>,
        spawner: Arc<dyn TaskSpawner>,
        shutdown: Arc<dyn ShutdownSignal>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            subsystem,
            settings,
            spawner,
            shutdown,
            clock,
        }
    }

    /// Returns a copy of this context addressed to a different subsystem.
    #[must_use]
    pub fn for_subsystem(&self, subsystem: SubsystemId) -> Self {
        Self {
            subsystem,
            settings: Arc::clone(&self.settings),
            spawner: Arc::clone(&self.spawner),
            shutdown: Arc::clone(&self.shutdown),
            clock: Arc::clone(&self.clock),
        }
    }

    /// Returns the subsystem this context belongs to.
    #[must_use]
    pub const fn subsystem(&self) -> &SubsystemId {
        &self.subsystem
    }

    /// Returns the settings the daemon was configured with.
    #[must_use]
    pub fn settings(&self) -> &RuntimeSettings {
        &self.settings
    }

    /// Returns the task spawner.
    #[must_use]
    pub fn spawner(&self) -> Arc<dyn TaskSpawner> {
        Arc::clone(&self.spawner)
    }

    /// Returns the shutdown signal.
    #[must_use]
    pub fn shutdown(&self) -> Arc<dyn ShutdownSignal> {
        Arc::clone(&self.shutdown)
    }

    /// Returns the clock.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }
}

impl fmt::Debug for StartContext {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartContext")
            .field("subsystem", &self.subsystem)
            .finish_non_exhaustive()
    }
}

/// What a subsystem reports after it has started.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceHandle {
    subsystem: SubsystemId,
    bound: Vec<SocketAddr>,
    detail: Option<String>,
}

impl ServiceHandle {
    /// Reports a subsystem that started but listens on nothing.
    #[must_use]
    pub const fn inert(subsystem: SubsystemId) -> Self {
        Self {
            subsystem,
            bound: Vec::new(),
            detail: None,
        }
    }

    /// Reports a subsystem listening on `bound`.
    ///
    /// These are the addresses actually bound, not the addresses requested, so
    /// a port of `0` is reported as the port the operating system chose.
    #[must_use]
    pub const fn listening(subsystem: SubsystemId, bound: Vec<SocketAddr>) -> Self {
        Self {
            subsystem,
            bound,
            detail: None,
        }
    }

    /// Attaches a human-readable note for readiness output.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Returns the subsystem that started.
    #[must_use]
    pub const fn subsystem(&self) -> &SubsystemId {
        &self.subsystem
    }

    /// Returns the addresses the subsystem is listening on.
    #[must_use]
    pub fn bound(&self) -> &[SocketAddr] {
        &self.bound
    }

    /// Returns the optional readiness note.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// What a subsystem finished, and what it could not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainReport {
    subsystem: SubsystemId,
    completed: u32,
    abandoned: u32,
}

impl DrainReport {
    /// Reports a drain in which every in-flight item finished.
    #[must_use]
    pub const fn clean(subsystem: SubsystemId, completed: u32) -> Self {
        Self {
            subsystem,
            completed,
            abandoned: 0,
        }
    }

    /// Reports a drain that gave up on `abandoned` in-flight items.
    #[must_use]
    pub const fn partial(subsystem: SubsystemId, completed: u32, abandoned: u32) -> Self {
        Self {
            subsystem,
            completed,
            abandoned,
        }
    }

    /// Returns the subsystem that drained.
    #[must_use]
    pub const fn subsystem(&self) -> &SubsystemId {
        &self.subsystem
    }

    /// Returns how many in-flight items ran to completion.
    #[must_use]
    pub const fn completed(&self) -> u32 {
        self.completed
    }

    /// Returns how many in-flight items were abandoned.
    #[must_use]
    pub const fn abandoned(&self) -> u32 {
        self.abandoned
    }

    /// Returns whether nothing was abandoned.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.abandoned == 0
    }
}

impl Display for DrainReport {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} completed={} abandoned={}",
            self.subsystem, self.completed, self.abandoned
        )
    }
}

/// One pluggable part of the daemon.
///
/// The composition owns the ordering; a subsystem only has to be correct about
/// its own five steps. All five are allowed to be slow, and all five are called
/// exactly once per run.
///
/// Implementations live in the subsystem crates. `apps/gta-claw-daemon` supplies
/// deterministic stand-ins for the ones that have not landed yet.
pub trait Subsystem: Send + Sync + 'static {
    /// Returns the identity and dependencies of this subsystem.
    ///
    /// This is called before initialization and must not depend on any state
    /// established by the other methods.
    fn descriptor(&self) -> SubsystemDescriptor;

    /// Acquires resources without accepting work or spawning background tasks.
    ///
    /// Everything a subsystem needs from its dependencies is already available
    /// when this is called, because dependencies are initialized first.
    ///
    /// # Errors
    ///
    /// Any error aborts startup; already-initialized subsystems are shut down in
    /// reverse order.
    fn initialize<'a>(
        &'a self,
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<(), SubsystemError>>;

    /// Begins serving, spawning background work through
    /// [`StartContext::spawner`].
    ///
    /// # Errors
    ///
    /// Any error aborts startup; already-started subsystems are drained and shut
    /// down in reverse order.
    fn start<'a>(
        &'a self,
        context: &'a StartContext,
    ) -> BoxFuture<'a, Result<ServiceHandle, SubsystemError>>;

    /// Stops accepting new work while leaving in-flight work running.
    ///
    /// Only [`SubsystemKind::Ingress`] subsystems need to do anything here. The
    /// default implementation succeeds without doing anything.
    ///
    /// # Errors
    ///
    /// An error is recorded and shutdown continues, because refusing to quiesce
    /// must not be able to prevent teardown.
    fn quiesce(&self) -> BoxFuture<'_, Result<(), SubsystemError>> {
        Box::pin(async { Ok(()) })
    }

    /// Waits for in-flight work to finish.
    ///
    /// The default implementation reports a clean drain of nothing, which is
    /// correct for subsystems that hold no work of their own.
    ///
    /// # Errors
    ///
    /// An error is recorded and shutdown continues.
    fn drain(&self) -> BoxFuture<'_, Result<DrainReport, SubsystemError>> {
        let subsystem = self.descriptor().id().clone();

        Box::pin(async move { Ok(DrainReport::clean(subsystem, 0)) })
    }

    /// Releases every resource acquired by
    /// [`initialize`](Self::initialize) and [`start`](Self::start).
    ///
    /// This is the last call a subsystem receives. It runs even when startup
    /// failed part-way, so it must tolerate being called after a failed
    /// `initialize`.
    ///
    /// # Errors
    ///
    /// An error is recorded and shutdown continues to the next subsystem.
    fn shutdown(&self) -> BoxFuture<'_, Result<(), SubsystemError>>;
}

#[cfg(test)]
mod tests {
    use super::{DrainReport, ServiceHandle, SubsystemDescriptor, SubsystemKind};
    use crate::composition::id::SubsystemId;

    fn id(value: &str) -> SubsystemId {
        SubsystemId::new(value).expect("valid subsystem id")
    }

    #[test]
    fn a_descriptor_keeps_dependencies_in_declaration_order() {
        let descriptor = SubsystemDescriptor::new(id("engine"), SubsystemKind::Capability)
            .depends_on(id("tools"))
            .depends_on(id("memory"))
            .depends_on(id("providers"));

        assert_eq!(descriptor.id(), &id("engine"));
        assert_eq!(descriptor.kind(), SubsystemKind::Capability);
        assert_eq!(
            descriptor.dependencies(),
            &[id("tools"), id("memory"), id("providers")]
        );
    }

    #[test]
    fn kind_labels_are_distinct() {
        assert_eq!(SubsystemKind::Foundation.to_string(), "foundation");
        assert_eq!(SubsystemKind::Capability.to_string(), "capability");
        assert_eq!(SubsystemKind::Ingress.to_string(), "ingress");
    }

    #[test]
    fn an_inert_handle_advertises_no_addresses() {
        let handle = ServiceHandle::inert(id("memory"));

        assert_eq!(handle.subsystem(), &id("memory"));
        assert!(handle.bound().is_empty());
        assert_eq!(handle.detail(), None);
    }

    #[test]
    fn a_listening_handle_reports_the_addresses_and_note_it_was_given() {
        let address = "127.0.0.1:8080".parse().expect("valid socket address");
        let handle =
            ServiceHandle::listening(id("gateway"), vec![address]).with_detail("protocol v4");

        assert_eq!(handle.bound(), &[address]);
        assert_eq!(handle.detail(), Some("protocol v4"));
    }

    #[test]
    fn a_drain_is_clean_only_when_nothing_was_abandoned() {
        let clean = DrainReport::clean(id("gateway"), 7);
        let partial = DrainReport::partial(id("gateway"), 7, 1);

        assert!(clean.is_clean());
        assert_eq!(clean.completed(), 7);
        assert_eq!(clean.abandoned(), 0);
        assert_eq!(clean.to_string(), "gateway completed=7 abandoned=0");

        assert!(!partial.is_clean());
        assert_eq!(partial.abandoned(), 1);
        assert_eq!(partial.to_string(), "gateway completed=7 abandoned=1");
    }
}

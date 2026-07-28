//! The GTA Claw agent execution runtime.
//!
//! This crate owns everything between "an operator submitted something" and "the turn reached a
//! terminal state": the session/turn state machine, provider stream assembly, tool invocation
//! behind an approval broker, slash-command and directive dispatch, durable session goals,
//! cooperative host suspension, the closed worker protocol, and the context-engine SPI harness.
//!
//! Every external dependency is expressed as a port trait from [`claw_application::ports`], so
//! this crate contains no I/O of its own. Concurrency is built exclusively on
//! [`tokio_util::sync::CancellationToken`], [`tokio_util::task::TaskTracker`], and bounded
//! [`tokio::sync::mpsc`] channels: there are no unbounded queues and no detached tasks.

pub mod approval;
pub mod command;
pub mod context;
pub mod context_engine;
pub mod goal;
pub mod goal_tool;
pub mod runtime;
pub mod session;
pub mod stream;
pub mod suspend;
pub mod tool;
mod wire;
pub mod worker;

pub use approval::{ApprovalBroker, ApprovalError};
pub use command::{
    CommandEffect, CommandError, CommandInvocation, CommandRegistry, CommandSpec, Directive,
    DirectiveError, DirectiveRegistry, DirectiveScan, DirectiveSpec, OperatorScope, ScopeSet,
    TurnOptions,
};
pub use context::{ConformanceCheck, ConformanceReport, verify_context_engine};
pub use context_engine::{
    CONFORMANCE_TOKEN_BUDGET, LifecyclePhase, ReferenceContextEngine, SpiReport, SpiRequirement,
    SpiViolation, verify_spi_conformance,
};
pub use goal::{GoalConfig, GoalError, GoalService};
pub use goal_tool::{
    GOAL_TOOL_NAME, GoalAction, GoalToolError, goal_tool_descriptor, parse_goal_action,
};
pub use runtime::{
    CommandOutcome, Runtime, RuntimeConfig, RuntimeError, RuntimeEvent, RuntimeEventKind,
    RuntimeFailureClass, RuntimePorts, SessionReloadReport, TurnHandle, TurnOutcome,
};
pub use session::{StateMachineError, TurnStateMachine};
pub use stream::{StreamAssembler, StreamError, StreamEvent, StreamPayload};
pub use suspend::{
    PrepareOutcome, PrepareRequest, SuspendError, SuspendLease, SuspensionController,
    SuspensionPhase, SuspensionStatus, WorkPermit, WorkRefused,
};
pub use tool::{ToolExecutionError, ToolExecutor, ToolExecutorConfig};
pub use worker::{
    DEFAULT_WORKER_METHOD_ALLOWLIST, WORKER_PROTOCOL_VERSION, WorkerCall, WorkerConfig,
    WorkerError, WorkerRegistry, WorkerSession, WorkerTicket,
};

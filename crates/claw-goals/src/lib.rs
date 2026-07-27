//! Durable session goals for GTA Claw.
//!
//! [`claw_runtime::GoalService`] already decides *what* a durable goal is: an objective, an
//! ordered progress history, a lifecycle status and a monotonic revision. It writes every
//! mutation through [`GoalStorePort`](claw_application::ports::goal::GoalStorePort) and keeps no
//! cache, so the property the ledger calls "durable" is entirely a property of the adapter behind
//! that port. Every adapter in the tree before this crate was an in-memory test fake, which means
//! "restart" meant "keep using the same `Vec`".
//!
//! This crate supplies the adapter that makes the claim true, plus the two pieces of goal
//! behaviour that live outside the service:
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | [`store`] | [`FileGoalStore`]: crash-safe, revision-checked, on-disk goal records |
//! | [`wire`] | The versioned JSON encoding those records are written in |
//! | [`budget`] | Per-session ceilings on goal count and stored bytes |
//! | [`mod@transition`] | The goal status state machine and its typed refusals |
//! | [`command`] | `/goal`, `/goal-done` and `/goal-drop` lowered onto a durable goal |
//! | [`tool`] | The `update_goal` model-tool call lowered onto a durable goal |
//! | [`anchor`] | The goal statement that context compaction may never drop |
//!
//! # Design rules
//!
//! * **A write is durable before it is acknowledged.** Records are written to a temporary file,
//!   flushed with [`std::fs::File::sync_all`], renamed over the target, and the directory holding
//!   them is flushed in turn. A reader therefore never observes a half-written record, and an
//!   acknowledged write survives both the process and a power cut. Directory flushing exists only
//!   on Unix, and a Unix flush that fails leaves the bytes published but the rename unguaranteed;
//!   [`FileGoalStore::synced_publications`] and [`FileGoalStore::unsynced_publications`] report
//!   which of the three happened instead of leaving the promise to the prose.
//! * **Refusals leave nothing behind.** Revision conflicts and budget refusals are decided before
//!   any byte is written, so a rejected save cannot change what a restart would recover.
//! * **Recovery is explicit, never silent.** [`FileGoalStore::open`] reports what it repaired in a
//!   [`RecoveryReport`] instead of quietly rewriting history.
//! * **The goal outlives the context.** Compaction is free to discard conversation, but
//!   [`anchor::AnchoredContext`] structurally cannot discard the goal statement.
//!
//! # Example
//!
//! ```
//! use std::sync::Arc;
//!
//! use claw_domain::SessionId;
//! use claw_goals::FileGoalStore;
//! use claw_goals::testing::{FixedClock, block_on};
//! use claw_runtime::{GoalConfig, GoalService};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let root = std::env::temp_dir().join("claw-goals-doctest");
//! let _ = std::fs::remove_dir_all(&root);
//! let session = SessionId::new("demo")?;
//!
//! // One process records a goal.
//! let objective = {
//!     let store = Arc::new(FileGoalStore::open(&root)?);
//!     let service = GoalService::new(store, Arc::new(FixedClock::new(1)), GoalConfig::default());
//!     block_on(service.start(&session, "ship the crate"))?.objective
//! };
//! assert_eq!(objective, "ship the crate");
//!
//! // A later process, over the same directory, sees it.
//! let store = Arc::new(FileGoalStore::open(&root)?);
//! let service = GoalService::new(store, Arc::new(FixedClock::new(2)), GoalConfig::default());
//! let recovered = block_on(service.active(&session))?.expect("goal survived");
//! assert_eq!(recovered.objective, "ship the crate");
//! # std::fs::remove_dir_all(&root)?;
//! # Ok(())
//! # }
//! ```

pub mod anchor;
pub mod budget;
pub mod command;
mod retry;
pub mod store;
pub mod testing;
pub mod tool;
pub mod transition;
pub mod wire;

pub use anchor::{AnchoredContext, CompactionOutcome, GoalAnchor};
pub use budget::{BudgetError, BudgetUsage, GoalBudget};
pub use command::{GoalCommandError, GoalCommandOutcome, apply_command_effect, execute_command};
pub use store::{
    CompactionSummary, FileGoalStore, RecoveryReport, StoreError, StoreOperationSemantics,
    WRITE_LOCK_ATTEMPTS, WRITE_LOCK_RETRY_DELAY,
};
pub use tool::{GoalToolOutcome, ToolInvocationError, invoke_goal_tool};
pub use transition::{GoalOperation, TransitionError, admit, legal_targets, transition};
pub use wire::{WireError, decode, encode};

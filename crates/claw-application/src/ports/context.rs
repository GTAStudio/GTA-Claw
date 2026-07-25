//! The context-engine service provider interface.
//!
//! A context engine owns everything between raw session history and the prompt handed to a
//! provider. The lifecycle is fixed: `bootstrap` once per session, `ingest` per new item,
//! `assemble` per provider round, `maintain` between rounds, and `compact` when the engine
//! reports budget pressure.

use claw_domain::SessionId;
use serde::{Deserialize, Serialize};

use super::{PortError, PortFuture};
use crate::model::ids::TurnId;
use crate::model::time::Timestamp;
use crate::ports::provider::PromptMessage;

/// One item offered to a context engine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "item")]
pub enum ContextItem {
    /// Operator-authored input.
    UserInput {
        /// The input text.
        text: String,
    },
    /// A completed assistant message.
    AssistantMessage {
        /// The response text.
        text: String,
    },
    /// The result of a tool call.
    ToolResult {
        /// The tool that produced the output.
        tool_name: String,
        /// The serialised output.
        output: String,
        /// Whether the tool failed.
        failed: bool,
    },
    /// A durable goal restated for the engine.
    GoalStatement {
        /// The objective text.
        objective: String,
    },
    /// A system instruction supplied by the host.
    SystemNote {
        /// The instruction text.
        text: String,
    },
}

/// Why an engine was asked to bootstrap.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapReason {
    /// The session is brand new.
    NewSession,
    /// The host restarted and is rehydrating an existing session.
    Restart,
}

/// The request that opens a context engine for a session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextBootstrap {
    /// The session being opened.
    #[serde(with = "crate::model::session_id_serde")]
    pub session_id: SessionId,
    /// Why the engine is being opened.
    pub reason: BootstrapReason,
    /// The token budget the engine must respect.
    pub token_budget: u32,
    /// When the bootstrap happened.
    pub at: Timestamp,
}

/// The request that offers one item to an engine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextIngest {
    /// The session being updated.
    #[serde(with = "crate::model::session_id_serde")]
    pub session_id: SessionId,
    /// The turn the item belongs to.
    pub turn: TurnId,
    /// The item.
    pub item: ContextItem,
    /// When the item arrived.
    pub at: Timestamp,
}

/// The request that asks an engine for a prompt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextAssembly {
    /// The session being prompted.
    #[serde(with = "crate::model::session_id_serde")]
    pub session_id: SessionId,
    /// The turn being executed.
    pub turn: TurnId,
    /// The zero-based provider round inside the turn.
    pub round: u32,
}

/// The request that asks an engine to perform between-round upkeep.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextMaintenance {
    /// The session being maintained.
    #[serde(with = "crate::model::session_id_serde")]
    pub session_id: SessionId,
    /// When maintenance ran.
    pub at: Timestamp,
}

/// The request that asks an engine to shed context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextCompaction {
    /// The session being compacted.
    #[serde(with = "crate::model::session_id_serde")]
    pub session_id: SessionId,
    /// The number of tokens the engine must free.
    pub reclaim_tokens: u32,
    /// When compaction ran.
    pub at: Timestamp,
}

/// The engine's self-reported state after a lifecycle call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextState {
    /// The number of items the engine is holding.
    pub item_count: u32,
    /// The engine's estimate of the tokens those items occupy.
    pub used_tokens: u32,
    /// The budget the engine is working against.
    pub token_budget: u32,
    /// Whether the engine wants a compaction pass before the next round.
    pub needs_compaction: bool,
    /// The number of items compaction has removed so far.
    pub compacted_items: u32,
}

/// The prompt an engine assembled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssembledContext {
    /// The ordered prompt.
    pub messages: Vec<PromptMessage>,
    /// The engine state that produced it.
    pub state: ContextState,
}

/// The result of a compaction pass.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompactionReport {
    /// The number of items compaction removed.
    pub removed_items: u32,
    /// The number of tokens compaction freed.
    pub reclaimed_tokens: u32,
    /// The engine state after compaction.
    pub state: ContextState,
}

/// Assembles provider prompts from session history.
pub trait ContextEnginePort: Send + Sync + 'static {
    /// Opens the engine for a session.
    fn bootstrap(
        &self,
        request: ContextBootstrap,
    ) -> PortFuture<'_, Result<ContextState, PortError>>;

    /// Offers one item to the engine.
    fn ingest(&self, request: ContextIngest) -> PortFuture<'_, Result<ContextState, PortError>>;

    /// Produces the prompt for one provider round.
    fn assemble(
        &self,
        request: ContextAssembly,
    ) -> PortFuture<'_, Result<AssembledContext, PortError>>;

    /// Performs between-round upkeep.
    fn maintain(
        &self,
        request: ContextMaintenance,
    ) -> PortFuture<'_, Result<ContextState, PortError>>;

    /// Sheds context to fit the budget.
    fn compact(
        &self,
        request: ContextCompaction,
    ) -> PortFuture<'_, Result<CompactionReport, PortError>>;
}

#[cfg(test)]
mod tests {
    use super::{BootstrapReason, ContextItem};

    #[test]
    fn context_items_serialise_with_a_tagged_representation() {
        let encoded = serde_json::to_string(&ContextItem::ToolResult {
            tool_name: "read_file".to_owned(),
            output: "hi".to_owned(),
            failed: false,
        })
        .expect("item serialises");

        assert_eq!(
            encoded,
            "{\"item\":\"tool_result\",\"tool_name\":\"read_file\",\"output\":\"hi\",\"failed\":false}"
        );
    }

    #[test]
    fn bootstrap_reasons_serialise_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&BootstrapReason::NewSession).expect("reason serialises"),
            "\"new_session\""
        );
        assert_eq!(
            serde_json::to_string(&BootstrapReason::Restart).expect("reason serialises"),
            "\"restart\""
        );
    }
}

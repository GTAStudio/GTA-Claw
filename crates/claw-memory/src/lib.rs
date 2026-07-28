//! Conversation memory and context assembly for GTA Claw.
//!
//! This crate answers one question: given everything an agent has ever said,
//! stored, or retrieved, what exactly goes into the next model call?
//!
//! # Design rules
//!
//! * **Determinism.** Every ordering and truncation decision is a pure
//!   function of its inputs. Two runs over the same session, budget and
//!   counter produce byte-identical context. An agent whose input silently
//!   varies cannot be audited.
//! * **Anchors are never silently dropped.** System instructions and pinned
//!   messages survive compaction and truncation. If they cannot fit, assembly
//!   fails loudly rather than quietly discarding the operator's rules — a
//!   dropped instruction is a privilege escalation, not a formatting detail.
//! * **Ports, not vendors.** Summarization, embedding, vector search and
//!   persistence are traits. The only implementations shipped here are
//!   dependency-free and deterministic, so the crate is fully testable
//!   offline; production adapters live outside it.
//! * **Bounded by construction.** Identifier lengths, embedding
//!   dimensionality, retrieval limits, retriever corpora and store capacity
//!   all have explicit ceilings. Nothing grows without a bound an operator
//!   chose.
//!
//! # Layout
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | [`session`] | Immutable messages, monotonic identifiers, summaries |
//! | [`budget`] | Token counting and the truncation rules |
//! | [`summarize`] | When to compact, what to compact, and the summarizer port |
//! | [`vector`] | Embedding port and an exact-search index |
//! | [`retrieval`] | Memory records, queries, and retriever ports |
//! | [`context`] | Budget-aware assembly of the final model input |
//! | [`store`] | Narrow persistence port and an in-memory adapter |
//!
//! # Assembly order
//!
//! ```text
//!   Session ──┐
//!             ├─> retrieval share admitted best-first  ──┐
//!   Retrieved ┘                                          ├─> AssembledContext
//!             ┌─> anchors -> summaries -> recent window ─┘
//!   Budget ───┘        (plan_truncation)
//! ```
//!
//! # Example
//!
//! ```
//! use claw_memory::{
//!     ContextAssembler, HeuristicTokenCounter, Role, Session, SessionId, TokenBudget,
//! };
//!
//! let mut session = Session::new(SessionId::new("demo").expect("valid identifier"));
//! session.append(Role::System, "answer briefly", 1).expect("appended");
//! session.append(Role::User, "what is the capital of France?", 2).expect("appended");
//!
//! let budget = TokenBudget::new(4_096, 512).expect("valid budget");
//! let assembler = ContextAssembler::new(budget, HeuristicTokenCounter::default(), 20)
//!     .expect("valid assembler");
//! let context = assembler.assemble(&session, &[]).expect("assembled");
//!
//! assert_eq!(context.messages.len(), 2);
//! assert!(context.used_tokens <= budget.available());
//! ```

pub mod budget;
pub mod context;
pub mod retrieval;
pub mod session;
pub mod store;
pub mod summarize;
pub mod vector;

pub use budget::{
    Admission, BudgetError, HeuristicTokenCounter, TokenBudget, TokenCounter, TruncationPlan,
    plan_truncation,
};
pub use context::{
    AssembledContext, ContextAssembler, ContextError, ContextTruncation, DroppedMessage,
};
pub use retrieval::{
    KeywordRetriever, MAX_KEYWORD_RECORD_TERMS, MAX_QUERY_BYTES, MAX_RECORD_BYTES, MAX_RECORD_TAGS,
    MAX_RETRIEVAL_LIMIT, MAX_TAG_BYTES, MemoryRecord, RecordError, RecordKind, RetrievalCoverage,
    RetrievalError, RetrievalQuery, RetrievalReport, RetrievedItem, Retriever, VectorRetriever,
};
pub use session::{Message, MessageId, Role, Session, SessionError, SessionId, Summary};
pub use store::{InMemoryMemoryStore, MemoryStore, StoreError};
pub use summarize::{
    ExtractiveSummarizer, SummarizationPlan, SummarizationPolicy, Summarizer, SummaryError,
    SummaryRequest, compact, plan_summarization,
};
pub use vector::{
    Embedding, EmbeddingModel, ExactVectorIndex, HashingEmbeddingModel, RecordId, ScoredMatch,
    VectorError, VectorIndex,
};

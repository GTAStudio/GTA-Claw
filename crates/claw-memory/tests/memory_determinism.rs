//! End-to-end determinism of the memory pipeline.
//!
//! Every expectation here is arithmetic done by hand against the documented
//! token model, never by calling the production function a second time.

use std::collections::BTreeSet;

use claw_memory::budget::{Admission, BudgetError, plan_truncation};
use claw_memory::context::{ContextAssembler, ContextError};
use claw_memory::retrieval::{
    KeywordRetriever, MemoryRecord, RecordKind, RetrievalQuery, RetrievedItem, Retriever,
    VectorRetriever,
};
use claw_memory::session::{MessageId, Role, Session, SessionId, Summary};
use claw_memory::store::{InMemoryMemoryStore, MemoryStore, StoreError};
use claw_memory::summarize::{
    SummarizationPolicy, Summarizer, SummaryError, SummaryRequest, compact, plan_summarization,
};
use claw_memory::vector::{
    Embedding, ExactVectorIndex, HashingEmbeddingModel, RecordId, ScoredMatch, VectorIndex,
};
use claw_memory::{HeuristicTokenCounter, TokenBudget};

/// A counter with no framing overhead so every expectation is exact:
/// `count_message = ceil(chars / 4) + ceil(role_len / 4)`.
fn counter() -> HeuristicTokenCounter {
    HeuristicTokenCounter::new(4, 0).expect("a density of four is valid")
}

fn body(characters: usize) -> String {
    "x".repeat(characters)
}

/// System(16) + User(40) + Assistant(40) + User(40) + Assistant(40),
/// costing 6 + 11 + 13 + 11 + 13 tokens for identifiers 0 through 4.
fn conversation() -> Session {
    let mut session = Session::new(SessionId::new("determinism").expect("valid identifier"));
    session
        .append(Role::System, body(16), 1_000)
        .expect("appended");
    session
        .append(Role::User, body(40), 1_001)
        .expect("appended");
    session
        .append(Role::Assistant, body(40), 1_002)
        .expect("appended");
    session
        .append(Role::User, body(40), 1_003)
        .expect("appended");
    session
        .append(Role::Assistant, body(40), 1_004)
        .expect("appended");
    session
}

fn record(id: &str, session: &str, text: &str, unix_millis: u64) -> MemoryRecord {
    MemoryRecord {
        id: RecordId::new(id).expect("valid record identifier"),
        session: SessionId::new(session).expect("valid session identifier"),
        kind: RecordKind::Note,
        text: text.to_owned(),
        unix_millis,
        tags: BTreeSet::new(),
    }
}

#[test]
fn the_documented_token_model_is_what_the_counter_actually_charges() {
    let session = conversation();
    let counter = counter();
    let costs: Vec<usize> = session
        .messages()
        .iter()
        .map(|message| claw_memory::TokenCounter::count_message(&counter, message))
        .collect();
    // ceil(16/4) + ceil(len("system")/4) = 4 + 2, and so on.
    assert_eq!(costs, vec![6, 11, 13, 11, 13]);
}

#[test]
fn a_generous_budget_admits_the_whole_conversation() {
    let session = conversation();
    let budget = TokenBudget::new(100, 0).expect("valid budget");
    let plan = plan_truncation(session.messages(), &[], budget, &counter()).expect("planned");
    assert_eq!(plan.admitted(), vec![0, 1, 2, 3, 4]);
    assert!(plan.dropped().is_empty());
    assert_eq!(plan.used_tokens(), 54);
    assert_eq!(plan.summaries(), 0);
}

#[test]
fn a_tight_budget_keeps_a_contiguous_suffix_and_every_anchor() {
    let session = conversation();
    // available = 40. Anchors cost 6. Newest first: 4 costs 13 (19),
    // 3 costs 11 (30), 2 costs 13 which would reach 43 and does not fit.
    let budget = TokenBudget::new(40, 0).expect("valid budget");
    let plan = plan_truncation(session.messages(), &[], budget, &counter()).expect("planned");
    assert_eq!(plan.admitted(), vec![0, 3, 4]);
    assert_eq!(
        plan.dropped(),
        [(1, Admission::BehindTruncation), (2, Admission::OverBudget),]
    );
    assert_eq!(plan.used_tokens(), 30);
}

#[test]
fn a_pinned_message_is_resurrected_from_behind_the_truncation_point() {
    let mut session = conversation();
    assert!(session.pin(MessageId::new(2)));
    // Anchors now cost 6 + 13 = 19. Newest first: 4 costs 13 (32),
    // 3 costs 11 which would reach 43 and does not fit.
    let budget = TokenBudget::new(40, 0).expect("valid budget");
    let plan = plan_truncation(session.messages(), &[], budget, &counter()).expect("planned");
    assert_eq!(plan.admitted(), vec![0, 2, 4]);
    assert_eq!(
        plan.dropped(),
        [(1, Admission::BehindTruncation), (3, Admission::OverBudget),]
    );
    assert_eq!(plan.used_tokens(), 32);
}

#[test]
fn a_window_never_opens_on_an_orphaned_tool_result() {
    let mut session = Session::new(SessionId::new("orphan").expect("valid identifier"));
    session
        .append(Role::System, body(16), 1_000)
        .expect("appended");
    session
        .append(Role::User, body(40), 1_001)
        .expect("appended");
    session
        .append(Role::Assistant, body(40), 1_002)
        .expect("appended");
    session
        .append(Role::Tool, body(40), 1_003)
        .expect("appended");
    session
        .append(Role::Assistant, body(40), 1_004)
        .expect("appended");
    // available = 40. Anchor 6. Newest first: 4 costs 13 (19), 3 costs 11
    // (30), 2 costs 13 which would reach 43. The window [3, 4] then opens on
    // a tool result, so identifier 3 and its 11 tokens are given back.
    let budget = TokenBudget::new(40, 0).expect("valid budget");
    let plan = plan_truncation(session.messages(), &[], budget, &counter()).expect("planned");
    assert_eq!(plan.admitted(), vec![0, 4]);
    assert_eq!(
        plan.dropped(),
        [
            (1, Admission::BehindTruncation),
            (2, Admission::OverBudget),
            (3, Admission::OrphanedToolResult),
        ]
    );
    assert_eq!(plan.used_tokens(), 19);
}

#[test]
fn anchors_that_cannot_fit_fail_loudly_instead_of_being_dropped() {
    let mut session = Session::new(SessionId::new("anchors").expect("valid identifier"));
    // ceil(200/4) + 2 = 52 tokens of operator instruction against 40 available.
    session
        .append(Role::System, body(200), 1_000)
        .expect("appended");
    session
        .append(Role::User, body(4), 1_001)
        .expect("appended");
    let budget = TokenBudget::new(40, 0).expect("valid budget");
    assert_eq!(
        plan_truncation(session.messages(), &[], budget, &counter()),
        Err(BudgetError::AnchorsExceedBudget)
    );
}

#[test]
fn planning_is_a_pure_function_of_its_inputs() {
    let budget = TokenBudget::new(40, 0).expect("valid budget");
    let first = plan_truncation(conversation().messages(), &[], budget, &counter());
    let second = plan_truncation(conversation().messages(), &[], budget, &counter());
    let third = plan_truncation(conversation().messages(), &[], budget, &counter());
    assert_eq!(first, second);
    assert_eq!(second, third);
}

#[test]
fn summaries_are_admitted_newest_first_until_the_budget_closes() {
    let session = conversation();
    let summaries = [
        Summary {
            first: MessageId::new(0),
            last: MessageId::new(0),
            text: body(40),
            unix_millis: 900,
        },
        Summary {
            first: MessageId::new(1),
            last: MessageId::new(1),
            text: body(40),
            unix_millis: 901,
        },
    ];
    // available = 40, anchors 6, each summary costs ceil(40/4) = 10. The
    // newest fits (16), the older would reach 26 and also fits, leaving 14
    // for the conversation: only identifier 4 at 13 tokens gets in.
    let budget = TokenBudget::new(40, 0).expect("valid budget");
    let plan =
        plan_truncation(session.messages(), &summaries, budget, &counter()).expect("planned");
    assert_eq!(plan.summaries(), 2);
    assert_eq!(plan.admitted(), vec![0, 4]);
    assert_eq!(plan.used_tokens(), 39);
}

/// A summarizer that records what it was asked and answers deterministically.
struct RecordingSummarizer {
    calls: Vec<(String, usize, usize)>,
    answer: String,
}

impl Summarizer for RecordingSummarizer {
    fn summarize(&mut self, request: &SummaryRequest<'_>) -> Result<String, SummaryError> {
        self.calls.push((
            request.session.as_str().to_owned(),
            request.messages.len(),
            request.max_tokens,
        ));
        Ok(self.answer.clone())
    }
}

#[test]
fn compaction_replaces_the_oldest_run_and_never_touches_an_anchor() {
    let mut session = conversation();
    // available = 100, used = 54, trigger at 50 percent. Non-anchors are
    // [1, 2, 3, 4]; keeping two recent leaves the run [1, 2].
    let budget = TokenBudget::new(100, 0).expect("valid budget");
    let policy = SummarizationPolicy::new(50, 2, 10).expect("valid policy");
    let plan = plan_summarization(&session, budget, &counter(), policy).expect("compaction is due");
    assert_eq!(plan.first, MessageId::new(1));
    assert_eq!(plan.last, MessageId::new(2));
    assert_eq!(plan.message_count, 2);
    assert_eq!(plan.max_tokens, 10);

    let mut summarizer = RecordingSummarizer {
        calls: Vec::new(),
        answer: "the user asked twice".to_owned(),
    };
    let summary = compact(
        &mut session,
        budget,
        &counter(),
        policy,
        &mut summarizer,
        2_000,
    )
    .expect("compaction succeeds")
    .expect("a summary was produced");

    assert_eq!(summarizer.calls, vec![("determinism".to_owned(), 2, 10)]);
    assert_eq!(summary.first, MessageId::new(1));
    assert_eq!(summary.last, MessageId::new(2));
    assert_eq!(summary.text, "the user asked twice");
    assert_eq!(summary.unix_millis, 2_000);

    let remaining: Vec<u64> = session
        .messages()
        .iter()
        .map(|message| message.id.get())
        .collect();
    assert_eq!(remaining, vec![0, 3, 4]);
    assert_eq!(session.summaries().len(), 1);
    assert_eq!(session.summaries()[0].text, "the user asked twice");
}

#[test]
fn a_persisted_session_compacts_exactly_as_the_live_one_did() {
    // Deserialization re-applies the session's bounds, so it has to be an
    // identity on anything the write path produced: a stored conversation
    // must compact into the same summary over the same run, or restoring a
    // session would silently change what the model is shown next.
    let live = conversation();
    let encoded = serde_json::to_string(&live).expect("serialized");
    let mut restored: Session = serde_json::from_str(&encoded).expect("deserialized");
    assert_eq!(restored, live, "restoring a valid session changes nothing");
    assert_eq!(
        serde_json::to_string(&restored).expect("serialized"),
        encoded,
        "re-encoding a restored session is byte-identical"
    );

    let budget = TokenBudget::new(100, 0).expect("valid budget");
    let policy = SummarizationPolicy::new(50, 2, 10).expect("valid policy");
    let mut live = live;
    let mut live_summarizer = RecordingSummarizer {
        calls: Vec::new(),
        answer: "the user asked twice".to_owned(),
    };
    let mut restored_summarizer = RecordingSummarizer {
        calls: Vec::new(),
        answer: "the user asked twice".to_owned(),
    };
    let from_live = compact(
        &mut live,
        budget,
        &counter(),
        policy,
        &mut live_summarizer,
        2_000,
    )
    .expect("compaction succeeds");
    let from_restored = compact(
        &mut restored,
        budget,
        &counter(),
        policy,
        &mut restored_summarizer,
        2_000,
    )
    .expect("compaction succeeds");

    assert_eq!(from_restored, from_live, "the same run was summarized");
    assert_eq!(restored_summarizer.calls, live_summarizer.calls);
    assert_eq!(restored, live, "the sessions stayed identical");
}

#[test]
fn a_failing_summarizer_leaves_the_session_exactly_as_it_was() {
    struct FailingSummarizer;

    impl Summarizer for FailingSummarizer {
        fn summarize(&mut self, _request: &SummaryRequest<'_>) -> Result<String, SummaryError> {
            Err(SummaryError::Backend)
        }
    }

    let mut session = conversation();
    let before: Vec<u64> = session
        .messages()
        .iter()
        .map(|message| message.id.get())
        .collect();
    let budget = TokenBudget::new(100, 0).expect("valid budget");
    let policy = SummarizationPolicy::new(50, 2, 10).expect("valid policy");
    let error = compact(
        &mut session,
        budget,
        &counter(),
        policy,
        &mut FailingSummarizer,
        2_000,
    )
    .expect_err("the failure must surface");
    assert_eq!(error, SummaryError::Backend);

    let after: Vec<u64> = session
        .messages()
        .iter()
        .map(|message| message.id.get())
        .collect();
    assert_eq!(before, after);
    assert!(session.summaries().is_empty());
}

#[test]
fn compaction_is_not_due_below_the_trigger() {
    let session = conversation();
    let budget = TokenBudget::new(1_000, 0).expect("valid budget");
    let policy = SummarizationPolicy::new(50, 2, 10).expect("valid policy");
    assert_eq!(
        plan_summarization(&session, budget, &counter(), policy),
        None
    );
}

#[test]
fn assembly_splits_the_budget_and_hands_back_what_retrieval_did_not_use() {
    let session = conversation();
    let items: Vec<RetrievedItem> = (0..3_u8)
        .map(|index| RetrievedItem {
            record: record(
                &format!("note-{index}"),
                "determinism",
                &body(40),
                2_000 + u64::from(index),
            ),
            score: 1.0 - f32::from(index),
        })
        .collect();

    // available = 100 - 20 = 80. A 25 percent share is 20 tokens, and each
    // item costs ceil(40/4) = 10, so exactly two are admitted.
    let budget = TokenBudget::new(100, 20).expect("valid budget");
    let assembler = ContextAssembler::new(budget, counter(), 25).expect("valid assembler");
    let context = assembler.assemble(&session, &items).expect("assembled");

    assert_eq!(context.retrieved.len(), 2);
    assert_eq!(context.dropped_retrieved, 1);
    assert_eq!(
        context.retrieved[0].record.id,
        RecordId::new("note-0").expect("valid")
    );
    assert_eq!(
        context.retrieved[1].record.id,
        RecordId::new("note-1").expect("valid")
    );
    // The conversation then plans against 100 - 20 = 80 window with 20
    // reserved, so 60 available, and all 54 tokens of conversation fit.
    assert_eq!(
        context
            .messages
            .iter()
            .map(|message| message.id.get())
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(context.dropped_messages, 0);
    assert_eq!(context.used_tokens, 74);
    assert_eq!(context.remaining_tokens, 6);
    assert!(context.summaries.is_empty());
}

#[test]
fn a_zero_retrieval_share_gives_the_whole_budget_to_the_conversation() {
    let session = conversation();
    let items = vec![RetrievedItem {
        record: record("note-0", "determinism", &body(40), 2_000),
        score: 1.0,
    }];
    let budget = TokenBudget::new(100, 20).expect("valid budget");
    let assembler = ContextAssembler::new(budget, counter(), 0).expect("valid assembler");
    let context = assembler.assemble(&session, &items).expect("assembled");
    assert!(context.retrieved.is_empty());
    assert_eq!(context.dropped_retrieved, 1);
    assert_eq!(context.used_tokens, 54);
    assert_eq!(context.remaining_tokens, 26);
}

#[test]
fn a_retrieval_share_that_starves_the_anchors_fails_loudly() {
    let mut session = Session::new(SessionId::new("starved").expect("valid identifier"));
    session
        .append(Role::System, body(120), 1_000)
        .expect("appended");
    let items: Vec<RetrievedItem> = (0..4)
        .map(|index| RetrievedItem {
            record: record(&format!("note-{index}"), "starved", &body(40), 2_000),
            score: 1.0,
        })
        .collect();
    // available = 60. A 100 percent share admits 40 tokens of retrieval,
    // leaving a 20-token conversation window against a 32-token anchor.
    let budget = TokenBudget::new(60, 0).expect("valid budget");
    let assembler = ContextAssembler::new(budget, counter(), 100).expect("valid assembler");
    assert_eq!(
        assembler.assemble(&session, &items),
        Err(ContextError::Budget(BudgetError::AnchorsExceedBudget))
    );
}

#[test]
fn an_impossible_retrieval_share_is_refused_at_construction() {
    let budget = TokenBudget::new(100, 0).expect("valid budget");
    assert_eq!(
        ContextAssembler::new(budget, counter(), 101),
        Err(ContextError::InvalidShare)
    );
}

#[test]
fn the_assembled_context_serializes_every_part_it_carries() {
    let session = conversation();
    let budget = TokenBudget::new(100, 0).expect("valid budget");
    let assembler = ContextAssembler::new(budget, counter(), 0).expect("valid assembler");
    let context = assembler.assemble(&session, &[]).expect("assembled");
    let json = context.to_json();
    assert_eq!(json["used_tokens"], 54);
    assert_eq!(json["remaining_tokens"], 46);
    assert_eq!(json["dropped_messages"], 0);
    assert_eq!(json["dropped_retrieved"], 0);
    let messages = json["messages"].as_array().expect("an array of messages");
    assert_eq!(messages.len(), 5);
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[1]["role"], "user");
    assert_eq!(messages[0]["content"], body(16));
}

#[test]
fn exact_vector_search_is_ordered_by_score_then_identifier() {
    let mut index = ExactVectorIndex::new(3).expect("valid dimensionality");
    let unit_x = Embedding::new(vec![1.0, 0.0, 0.0]).expect("valid embedding");
    let unit_y = Embedding::new(vec![0.0, 1.0, 0.0]).expect("valid embedding");
    let query = Embedding::new(vec![2.0, 1.0, 0.0]).expect("valid embedding");
    // Two records are exactly as similar to the query as each other, so the
    // tie must break on identifier and never on insertion order.
    index
        .upsert(RecordId::new("zulu").expect("valid"), unit_x.clone())
        .expect("upserted");
    index
        .upsert(RecordId::new("alpha").expect("valid"), unit_x.clone())
        .expect("upserted");
    index
        .upsert(RecordId::new("mike").expect("valid"), unit_y)
        .expect("upserted");

    let matches = index.search(&query, 3).expect("searched");
    let identities: Vec<&str> = matches.iter().map(|found| found.id.as_str()).collect();
    assert_eq!(identities, vec!["alpha", "zulu", "mike"]);
    // 2/sqrt(5) for the two x-aligned records and 1/sqrt(5) for the other.
    let expected = [
        2.0 / 5.0_f32.sqrt(),
        2.0 / 5.0_f32.sqrt(),
        1.0 / 5.0_f32.sqrt(),
    ];
    for (found, wanted) in matches.iter().zip(expected) {
        assert!(
            (found.score - wanted).abs() < 1e-6,
            "score {} is not {wanted}",
            found.score
        );
    }

    let limited = index.search(&unit_x, 1).expect("searched");
    assert_eq!(
        limited,
        vec![ScoredMatch {
            id: RecordId::new("alpha").expect("valid"),
            score: 1.0,
        }]
    );
    assert_eq!(index.len(), 3);
    assert!(index.remove(&RecordId::new("mike").expect("valid")));
    assert!(!index.remove(&RecordId::new("mike").expect("valid")));
    assert_eq!(
        index.ids(),
        vec![
            RecordId::new("alpha").expect("valid"),
            RecordId::new("zulu").expect("valid"),
        ]
    );
}

#[test]
fn the_hashing_model_is_stable_across_instances_and_orderings() {
    let mut first = HashingEmbeddingModel::new(16).expect("valid dimensionality");
    let mut second = HashingEmbeddingModel::new(16).expect("valid dimensionality");
    let left = claw_memory::EmbeddingModel::embed(&mut first, "gateway protocol version four")
        .expect("embedded");
    let right = claw_memory::EmbeddingModel::embed(&mut second, "gateway protocol version four")
        .expect("embedded");
    assert_eq!(left.values(), right.values());
    let different = claw_memory::EmbeddingModel::embed(&mut first, "something else entirely")
        .expect("embedded");
    assert_ne!(left.values(), different.values());
    assert_eq!(left.dimensions(), 16);
}

#[test]
fn keyword_retrieval_is_ordered_and_bounded() {
    let mut retriever = KeywordRetriever::new();
    retriever.insert(record("r1", "s", "the gateway protocol is frozen", 10));
    retriever.insert(record("r2", "s", "the gateway is open", 20));
    retriever.insert(record("r3", "s", "unrelated content", 30));
    let query = RetrievalQuery::new("gateway protocol", 10).expect("valid query");
    let hits = retriever.retrieve(&query).expect("retrieved");
    let identities: Vec<&str> = hits.iter().map(|hit| hit.record.id.as_str()).collect();
    // r1 has both terms, r2 has one, r3 has none and is not returned.
    assert_eq!(identities, vec!["r1", "r2"]);
    assert!((hits[0].score - 1.0).abs() < 1e-6);
    assert!((hits[1].score - 0.5).abs() < 1e-6);

    let limited = RetrievalQuery::new("gateway protocol", 1).expect("valid query");
    assert_eq!(retriever.retrieve(&limited).expect("retrieved").len(), 1);
    assert_eq!(retriever.len(), 3);
}

#[test]
fn vector_retrieval_respects_the_session_filter() {
    let mut retriever = VectorRetriever::new(
        HashingEmbeddingModel::new(32).expect("valid dimensionality"),
        ExactVectorIndex::new(32).expect("valid dimensionality"),
    );
    retriever
        .insert(record("mine", "alpha", "the frozen gateway protocol", 10))
        .expect("inserted");
    retriever
        .insert(record("theirs", "beta", "the frozen gateway protocol", 20))
        .expect("inserted");

    let query = RetrievalQuery::new("frozen gateway protocol", 5)
        .expect("valid query")
        .in_session(SessionId::new("alpha").expect("valid identifier"));
    let hits = retriever.retrieve(&query).expect("retrieved");
    let identities: Vec<&str> = hits.iter().map(|hit| hit.record.id.as_str()).collect();
    assert_eq!(identities, vec!["mine"]);
}

#[test]
fn the_store_round_trips_sessions_and_records_through_the_port() {
    let mut store = InMemoryMemoryStore::new(2, 2);
    let session = conversation();
    store.put_session(&session).expect("stored");

    let loaded = store
        .get_session(session.id())
        .expect("read")
        .expect("the session is present");
    assert_eq!(loaded.len(), session.len());
    assert_eq!(loaded.messages(), session.messages());
    assert_eq!(loaded.id(), session.id());

    store
        .put_record(record("r1", "determinism", "a note", 10))
        .expect("stored");
    store
        .put_record(record("r2", "other", "another note", 20))
        .expect("stored");
    assert_eq!(store.record_count(), 2);
    assert_eq!(
        store
            .records(Some(&SessionId::new("determinism").expect("valid")))
            .expect("listed")
            .len(),
        1
    );

    // Deleting a session takes its records with it.
    assert!(
        store
            .delete_session(session.id())
            .expect("delete succeeded")
    );
    assert_eq!(store.session_count(), 0);
    assert_eq!(store.record_count(), 1);
    assert_eq!(
        store
            .get_record(&RecordId::new("r1").expect("valid"))
            .expect("read"),
        None
    );
}

#[test]
fn the_store_refuses_to_grow_past_its_declared_bounds() {
    let mut store = InMemoryMemoryStore::new(1, 1);
    let first = Session::new(SessionId::new("one").expect("valid identifier"));
    let second = Session::new(SessionId::new("two").expect("valid identifier"));
    store.put_session(&first).expect("stored");
    assert_eq!(
        store.put_session(&second),
        Err(StoreError::SessionCapacityExceeded)
    );
    // Replacing an existing key is not growth and stays allowed.
    store.put_session(&first).expect("replaced");

    store
        .put_record(record("r1", "one", "a note", 10))
        .expect("stored");
    assert_eq!(
        store.put_record(record("r2", "one", "another note", 20)),
        Err(StoreError::RecordCapacityExceeded)
    );
    assert_eq!(
        store.put_record(record("r3", "one", "", 20)),
        Err(StoreError::EmptyRecord)
    );
    assert_eq!(store.record_count(), 1);
}

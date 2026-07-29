//! Bounds on every allocation reachable from attacker-influenced input.
//!
//! Message bodies, summaries, retrieval queries and indexed records all
//! originate in model output or tool results. This suite proves each of them
//! is refused past a declared bound rather than allocated, and that the
//! bounded-working-set implementations still produce the globally correct
//! ordering rather than a locally truncated one.

use claw_memory::budget::{Admission, plan_truncation};
use claw_memory::retrieval::{
    KeywordRetriever, MAX_KEYWORD_RECORD_TERMS, MAX_QUERY_BYTES, MAX_RECORD_BYTES, MAX_RECORD_TAGS,
    MAX_RETRIEVAL_LIMIT, MAX_TAG_BYTES, MemoryRecord, RecordError, RecordKind, RetrievalCoverage,
    RetrievalError, RetrievalQuery, Retriever, VectorRetriever,
};
use claw_memory::session::{
    MAX_MESSAGE_BYTES, MAX_MESSAGES, MAX_SUMMARIES, MessageId, Role, Session, SessionError,
    SessionId, Summary,
};
use claw_memory::store::{InMemoryMemoryStore, MemoryStore, StoreError};
use claw_memory::vector::{
    Embedding, ExactVectorIndex, HashingEmbeddingModel, RecordId, VectorError, VectorIndex,
};
use claw_memory::{HeuristicTokenCounter, TokenBudget};
use std::collections::BTreeSet;

fn session(id: &str) -> Session {
    Session::new(SessionId::new(id).expect("valid session identifier"))
}

fn summary(first: u64, last: u64, text: &str) -> Summary {
    Summary {
        first: MessageId::new(first),
        last: MessageId::new(last),
        text: text.to_owned(),
        unix_millis: 5_000,
    }
}

fn record(id: &str, text: &str, unix_millis: u64) -> MemoryRecord {
    MemoryRecord {
        id: RecordId::new(id).expect("valid record identifier"),
        session: SessionId::new("bounds").expect("valid session identifier"),
        kind: RecordKind::Note,
        text: text.to_owned(),
        unix_millis,
        tags: BTreeSet::new(),
    }
}

fn embedding(values: &[f32]) -> Embedding {
    Embedding::new(values.to_vec()).expect("valid embedding")
}

#[test]
fn a_message_body_past_the_byte_bound_is_refused_rather_than_stored() {
    let mut session = session("oversized-message");

    let at_bound = session.append(Role::User, "x".repeat(MAX_MESSAGE_BYTES), 1_000);
    assert_eq!(
        at_bound.map(MessageId::get),
        Ok(0),
        "a body of exactly the bound is accepted"
    );

    let past_bound = session.append(Role::User, "x".repeat(MAX_MESSAGE_BYTES + 1), 1_001);
    assert_eq!(past_bound.err(), Some(SessionError::MessageTooLong));
    assert_eq!(session.len(), 1, "the refused body was never retained");
}

#[test]
fn a_session_stops_accepting_messages_at_the_retained_message_bound() {
    let mut session = session("message-count");
    for ordinal in 0..MAX_MESSAGES {
        session
            .append(Role::User, "x", 1_000 + ordinal as u64)
            .expect("appends below the bound succeed");
    }
    assert_eq!(session.len(), MAX_MESSAGES);

    let past_bound = session.append(Role::User, "x", 9_999);
    assert_eq!(past_bound.err(), Some(SessionError::TooManyMessages));
    assert_eq!(
        session.len(),
        MAX_MESSAGES,
        "the refused message was never retained"
    );
}

#[test]
fn a_summary_body_past_the_byte_bound_is_refused_rather_than_stored() {
    let mut session = session("oversized-summary");
    session.append(Role::User, "kept", 1_000).expect("appended");

    let oversized = summary(9_000, 9_001, &"x".repeat(MAX_MESSAGE_BYTES + 1));
    assert_eq!(
        session.absorb(oversized).err(),
        Some(SessionError::MessageTooLong)
    );
    assert_eq!(
        session.summaries().len(),
        0,
        "the refused summary was never retained"
    );
    assert_eq!(session.len(), 1, "the refusal removed no messages");
}

#[test]
fn a_session_stops_accepting_summaries_at_the_retained_summary_bound() {
    let mut session = session("summary-count");
    for ordinal in 0..MAX_SUMMARIES {
        let first = 1_000_000 + ordinal as u64;
        session
            .absorb(summary(first, first, "compacted"))
            .expect("absorbs below the bound succeed");
    }
    assert_eq!(session.summaries().len(), MAX_SUMMARIES);

    let past_bound = session.absorb(summary(2_000_000, 2_000_000, "one too many"));
    assert_eq!(past_bound.err(), Some(SessionError::TooManySummaries));
    assert_eq!(
        session.summaries().len(),
        MAX_SUMMARIES,
        "the refused summary was never retained"
    );
}

#[test]
fn max_plus_one_persisted_items_are_rejected_by_bounded_visitors() {
    // Every bound above is enforced on the write path. Deserialization is the
    // one way into a `Session` that skips it, so a stored or transmitted
    // document is exactly where an unbounded history would come back in.
    let mut messages = vec![
        "{\"id\":0,\"role\":\"system\",\"content\":\"rules\",\
         \"unix_millis\":1,\"pinned\":false}"
            .to_owned(),
    ];
    for ordinal in 1..=MAX_MESSAGES {
        let id = ordinal as u64;
        messages.push(format!(
            "{{\"id\":{id},\"role\":\"user\",\"content\":\"x\",\
             \"unix_millis\":{id},\"pinned\":false}}"
        ));
    }

    let summaries: Vec<String> = (0..=MAX_SUMMARIES)
        .map(|ordinal| {
            let first = ordinal as u64;
            format!(
                "{{\"first\":{first},\"last\":{first},\"text\":\"compacted\",\
                 \"unix_millis\":1}}"
            )
        })
        .collect();
    let document = format!(
        "{{\"id\":\"restored\",\"messages\":[{}],\"summaries\":[{}],\"next_ordinal\":0}}",
        messages.join(","),
        summaries.join(",")
    );

    assert!(
        serde_json::from_str::<Session>(&document).is_err(),
        "MAX+1 is detected without allocating another Message or Summary"
    );
}

#[test]
fn max_plus_one_nested_strings_and_vectors_are_rejected_on_deserialization() {
    let mut valid_session = session("owned");
    valid_session
        .append(Role::User, "valid", 1)
        .expect("valid message");
    let owned_session = serde_json::to_value(&valid_session).expect("session serializes");
    assert!(
        serde_json::from_value::<Session>(owned_session).is_ok(),
        "owned sessions and identifiers remain compatible"
    );

    let valid_record = serde_json::json!({
        "id": "record",
        "session": "bounds",
        "kind": "note",
        "text": "kept",
        "unix_millis": 1,
        "tags": ["valid"],
    });
    assert!(
        serde_json::from_value::<MemoryRecord>(valid_record).is_ok(),
        "owned serde values remain compatible"
    );

    let oversized_record = serde_json::json!({
        "id": "record",
        "session": "bounds",
        "kind": "note",
        "text": "x",
        "unix_millis": 1,
        "tags": ["x".repeat(MAX_TAG_BYTES + 1)],
    });
    assert!(
        serde_json::from_value::<MemoryRecord>(oversized_record).is_err(),
        "a tag is bounded before MemoryRecord construction"
    );

    let embedding = serde_json::json!({
        "values": vec![1.0_f32; 8192 + 1],
    });
    assert!(
        serde_json::from_value::<Embedding>(embedding).is_err(),
        "MAX+1 is detected without allocating another retained vector component"
    );
}

#[test]
fn a_retrieval_query_past_the_byte_bound_is_refused_before_tokenization() {
    let at_bound = RetrievalQuery::new(&"q".repeat(MAX_QUERY_BYTES), 5);
    assert_eq!(
        at_bound.map(|query| query.text().len()),
        Ok(MAX_QUERY_BYTES),
        "a query of exactly the bound is accepted"
    );

    let past_bound = RetrievalQuery::new(&"q".repeat(MAX_QUERY_BYTES + 1), 5);
    assert_eq!(past_bound.err(), Some(RetrievalError::QueryTooLong));
}

#[test]
fn a_retrieval_limit_past_the_result_bound_is_refused() {
    assert_eq!(
        RetrievalQuery::new("term", MAX_RETRIEVAL_LIMIT + 1).err(),
        Some(RetrievalError::InvalidLimit)
    );
    assert_eq!(
        RetrievalQuery::new("term", 0).err(),
        Some(RetrievalError::InvalidLimit)
    );
}

#[test]
fn memory_record_bounds_are_enforced_before_storage_or_indexing() {
    let at_bound = record("at-bound", &"x".repeat(MAX_RECORD_BYTES), 1);
    assert_eq!(at_bound.validate(), Ok(()));

    let oversized = record("oversized", &"x".repeat(MAX_RECORD_BYTES + 1), 2);
    assert_eq!(oversized.validate(), Err(RecordError::TextTooLong));

    let mut store = InMemoryMemoryStore::default();
    assert_eq!(
        store.put_record(oversized.clone()),
        Err(StoreError::RecordTooLarge)
    );

    let mut keyword = KeywordRetriever::new();
    assert_eq!(
        keyword.insert(oversized.clone()),
        Err(RetrievalError::InvalidRecord(RecordError::TextTooLong))
    );

    let mut vector = VectorRetriever::new(
        HashingEmbeddingModel::new(8).expect("valid model"),
        ExactVectorIndex::new(8).expect("valid index"),
    );
    assert_eq!(
        vector.insert(oversized),
        Err(RetrievalError::InvalidRecord(RecordError::TextTooLong))
    );
    assert!(keyword.is_empty());
    assert!(vector.is_empty());
}

#[test]
fn record_tag_count_and_size_are_bounded() {
    let mut too_many = record("too-many-tags", "body", 1);
    too_many.tags = (0..=MAX_RECORD_TAGS)
        .map(|index| format!("tag-{index}"))
        .collect();
    assert_eq!(too_many.validate(), Err(RecordError::TooManyTags));

    let mut oversized = record("oversized-tag", "body", 2);
    oversized.tags.insert("x".repeat(MAX_TAG_BYTES + 1));
    assert_eq!(oversized.validate(), Err(RecordError::TagTooLong));

    let mut store = InMemoryMemoryStore::default();
    assert_eq!(store.put_record(too_many), Err(StoreError::TooManyTags));
    assert_eq!(store.put_record(oversized), Err(StoreError::TagTooLong));
}

#[test]
fn keyword_records_with_unbounded_lexical_indexes_are_refused() {
    let text = (0..=MAX_KEYWORD_RECORD_TERMS)
        .map(|index| format!("term{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text.len() < MAX_RECORD_BYTES);
    let mut retriever = KeywordRetriever::new();
    assert_eq!(
        retriever.insert(record("many-terms", &text, 1)),
        Err(RetrievalError::TooManyRecordTerms)
    );
    assert!(retriever.is_empty());
}

#[test]
fn retrieval_reports_when_the_result_limit_hides_matches() {
    let mut retriever = KeywordRetriever::with_capacity(3).expect("valid capacity");
    for index in 0..3_u64 {
        retriever
            .insert(record(&format!("r{index}"), "common", index))
            .expect("indexed");
    }

    let limited = RetrievalQuery::new("common", 2).expect("valid query");
    let report = retriever.retrieve_with_report(&limited).expect("retrieved");
    assert_eq!(report.items.len(), 2);
    assert_eq!(report.examined_records, 3);
    assert_eq!(report.matched_records, 3);
    assert_eq!(report.coverage, RetrievalCoverage::Partial);
    assert!(!report.is_complete());

    let complete = RetrievalQuery::new("common", 3).expect("valid query");
    let report = retriever
        .retrieve_with_report(&complete)
        .expect("retrieved");
    assert_eq!(report.items.len(), 3);
    assert_eq!(report.coverage, RetrievalCoverage::Complete);
    assert!(report.is_complete());
}

#[test]
fn vector_retrieval_reports_when_its_candidate_window_is_not_exhaustive() {
    let mut retriever = VectorRetriever::new(
        HashingEmbeddingModel::new(16).expect("valid model"),
        ExactVectorIndex::with_capacity(16, 5).expect("valid index"),
    );
    for index in 0..5_u64 {
        retriever
            .insert(record(&format!("r{index}"), "identical common text", index))
            .expect("indexed");
    }

    let limited = RetrievalQuery::new("identical common text", 1).expect("valid query");
    let report = retriever.retrieve_with_report(&limited).expect("retrieved");
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.examined_records, 4);
    assert_eq!(report.matched_records, 4);
    assert_eq!(report.coverage, RetrievalCoverage::Partial);

    let complete = RetrievalQuery::new("identical common text", 5).expect("valid query");
    let report = retriever
        .retrieve_with_report(&complete)
        .expect("retrieved");
    assert_eq!(report.items.len(), 5);
    assert_eq!(report.examined_records, 5);
    assert_eq!(report.matched_records, 5);
    assert_eq!(report.coverage, RetrievalCoverage::Complete);
}

/// The keyword retriever keeps a bounded working set instead of cloning every
/// match, so this proves the bounded implementation still returns the globally
/// best results and not merely the first ones it happened to see.
#[test]
fn a_bounded_keyword_working_set_still_returns_the_globally_best_matches() {
    let mut retriever = KeywordRetriever::new();
    // Every record matches at least one term, so an unbounded implementation
    // would clone all sixty. Records are inserted worst-first so a naive
    // truncation would keep the wrong ones.
    for ordinal in 0..60_u64 {
        retriever
            .insert(record(
                &format!("weak-{ordinal:03}"),
                "alpha filler text",
                2_000 + ordinal,
            ))
            .expect("indexed");
    }
    retriever
        .insert(record("strong-a", "alpha beta gamma", 3_000))
        .expect("indexed");
    retriever
        .insert(record("strong-b", "alpha beta gamma", 3_001))
        .expect("indexed");
    retriever
        .insert(record("middle", "alpha beta", 3_002))
        .expect("indexed");

    let query = RetrievalQuery::new("alpha beta gamma", 3).expect("valid query");
    let hits = retriever.retrieve(&query).expect("retrieval succeeds");

    let ids: Vec<&str> = hits.iter().map(|hit| hit.record.id.as_str()).collect();
    // Three of three terms, newest first on the tie, then two of three.
    assert_eq!(ids, vec!["strong-b", "strong-a", "middle"]);
    let scores: Vec<f32> = hits.iter().map(|hit| hit.score).collect();
    assert_eq!(scores, vec![1.0, 1.0, 2.0 / 3.0]);
}

#[test]
fn a_full_vector_index_refuses_new_records_but_still_accepts_replacements() {
    let mut index = ExactVectorIndex::with_capacity(2, 2).expect("valid index");
    assert_eq!(index.capacity(), 2);

    index
        .upsert(
            RecordId::new("first").expect("valid identifier"),
            embedding(&[1.0, 0.0]),
        )
        .expect("the first record fits");
    index
        .upsert(
            RecordId::new("second").expect("valid identifier"),
            embedding(&[0.0, 1.0]),
        )
        .expect("the second record fits");

    let overflow = index.upsert(
        RecordId::new("third").expect("valid identifier"),
        embedding(&[1.0, 1.0]),
    );
    assert_eq!(overflow.err(), Some(VectorError::IndexFull));
    assert_eq!(index.len(), 2, "the refused record was never indexed");
    assert_eq!(
        index.ids(),
        vec![
            RecordId::new("first").expect("valid identifier"),
            RecordId::new("second").expect("valid identifier"),
        ]
    );

    index
        .upsert(
            RecordId::new("first").expect("valid identifier"),
            embedding(&[3.0, 4.0]),
        )
        .expect("replacing an indexed record does not grow the index");
    assert_eq!(index.len(), 2);
}

#[test]
fn an_index_with_no_capacity_is_refused_at_construction() {
    assert_eq!(
        ExactVectorIndex::with_capacity(2, 0).err(),
        Some(VectorError::EmptyCapacity)
    );
}

/// Search retains only the running best `limit` matches. This proves the
/// bounded selection preserves the documented order: descending score, then
/// ascending identifier.
#[test]
fn a_bounded_vector_search_returns_the_same_ranking_as_a_full_scan() {
    let mut index = ExactVectorIndex::with_capacity(2, 8).expect("valid index");
    // Inserted so that identifier order and score order disagree, and so the
    // best match is seen last.
    let planted: [(&str, [f32; 2]); 5] = [
        ("a-opposite", [-1.0, 0.0]),
        ("b-orthogonal", [0.0, 1.0]),
        ("c-three-four", [3.0, 4.0]),
        ("d-four-three", [4.0, 3.0]),
        ("e-exact", [1.0, 0.0]),
    ];
    for (id, values) in planted {
        index
            .upsert(
                RecordId::new(id).expect("valid identifier"),
                embedding(&values),
            )
            .expect("the record fits");
    }

    let hits = index
        .search(&embedding(&[1.0, 0.0]), 3)
        .expect("search succeeds");
    let ids: Vec<&str> = hits.iter().map(|hit| hit.id.as_str()).collect();
    assert_eq!(ids, vec!["e-exact", "d-four-three", "c-three-four"]);
    let scores: Vec<f32> = hits.iter().map(|hit| hit.score).collect();
    // cos = 1, 4/5, 3/5 against the unit query.
    assert_eq!(scores, vec![1.0, 4.0 / 5.0, 3.0 / 5.0]);

    let none = index
        .search(&embedding(&[1.0, 0.0]), 0)
        .expect("a zero limit is not an error");
    assert!(none.is_empty());
}

#[test]
fn a_tie_in_vector_search_is_broken_by_ascending_identifier() {
    let mut index = ExactVectorIndex::with_capacity(2, 8).expect("valid index");
    for id in ["zeta", "alpha", "mu"] {
        index
            .upsert(
                RecordId::new(id).expect("valid identifier"),
                embedding(&[1.0, 0.0]),
            )
            .expect("the record fits");
    }

    let hits = index
        .search(&embedding(&[2.0, 0.0]), 2)
        .expect("search succeeds");
    let ids: Vec<&str> = hits.iter().map(|hit| hit.id.as_str()).collect();
    assert_eq!(ids, vec!["alpha", "mu"]);
}

/// A window made entirely of orphaned tool results consumes the whole window
/// through the opening rule. This is the path that previously removed the head
/// element repeatedly; the result must be unchanged.
#[test]
fn a_window_of_only_tool_results_is_dropped_entirely_and_costs_nothing() {
    let mut conversation = session("orphans");
    conversation
        .append(Role::System, "x".repeat(16), 1_000)
        .expect("appended");
    for ordinal in 0..64_u64 {
        conversation
            .append(Role::Tool, "x".repeat(8), 1_001 + ordinal)
            .expect("appended");
    }

    let counter = HeuristicTokenCounter::new(4, 0).expect("a density of four is valid");
    let budget = TokenBudget::new(10_000, 0).expect("valid budget");
    let plan = plan_truncation(
        conversation.messages(),
        conversation.summaries(),
        budget,
        &counter,
    )
    .expect("planning succeeds");

    assert_eq!(plan.admitted(), vec![0], "only the anchor survives");
    let dropped: Vec<(u64, Admission)> = plan.dropped().to_vec();
    let expected: Vec<(u64, Admission)> = (1..=64)
        .map(|id| (id, Admission::OrphanedToolResult))
        .collect();
    assert_eq!(dropped, expected);
    // System body of 16 characters is 4 tokens, plus 2 for the six-character
    // role name, and nothing else was admitted.
    assert_eq!(plan.used_tokens(), 6);
}

/// The keyword corpus is the same attacker-influenced record set the vector
/// index holds, so it carries the same bound rather than relying on whoever
/// owns it to stop inserting.
#[test]
fn a_full_keyword_corpus_refuses_new_records_but_still_accepts_replacements() {
    let mut retriever = KeywordRetriever::with_capacity(2).expect("valid retriever");
    assert_eq!(retriever.capacity(), 2);

    retriever
        .insert(record("first", "alpha", 1))
        .expect("the first record fits");
    retriever
        .insert(record("second", "beta", 2))
        .expect("the second record fits");

    assert_eq!(
        retriever.insert(record("third", "gamma", 3)).err(),
        Some(RetrievalError::RetrieverFull)
    );
    assert_eq!(retriever.len(), 2, "the refused record was never indexed");
    assert!(
        retriever
            .retrieve(&RetrievalQuery::new("gamma", 5).expect("valid query"))
            .expect("retrieval succeeds")
            .is_empty(),
        "a record the retriever refused must not be searchable"
    );

    retriever
        .insert(record("first", "delta", 4))
        .expect("replacing an indexed record does not grow the corpus");
    assert_eq!(retriever.len(), 2);

    assert!(retriever.remove(&RecordId::new("second").expect("valid identifier")));
    retriever
        .insert(record("third", "gamma", 5))
        .expect("removal is the eviction path, and it frees a slot");
    assert_eq!(retriever.len(), 2);
}

#[test]
fn a_retriever_with_no_capacity_is_refused_at_construction() {
    assert_eq!(
        KeywordRetriever::with_capacity(0).err(),
        Some(RetrievalError::EmptyCapacity)
    );
}

#[test]
fn the_default_keyword_and_vector_bounds_are_the_same_number() {
    assert_eq!(
        KeywordRetriever::new().capacity(),
        ExactVectorIndex::new(2).expect("valid index").capacity(),
        "the two holders of the same records must not disagree about how many is too many"
    );
}

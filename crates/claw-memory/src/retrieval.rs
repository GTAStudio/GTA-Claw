//! Memory records, retrieval queries, and retrieval ports.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

use crate::session::SessionId;
use crate::vector::{
    DEFAULT_INDEX_CAPACITY, Embedding, EmbeddingModel, RecordId, VectorError, VectorIndex,
};

/// Inclusive maximum number of results one query may request.
pub const MAX_RETRIEVAL_LIMIT: usize = 100;

/// Inclusive maximum byte length of a query's free text.
///
/// Query text reaches the tokenizer, which allocates proportionally to it.
pub const MAX_QUERY_BYTES: usize = 4096;

/// Inclusive maximum byte length of one stored memory record.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// Inclusive maximum number of operator-assigned tags on one record.
pub const MAX_RECORD_TAGS: usize = 64;

/// Inclusive maximum byte length of one record tag.
pub const MAX_TAG_BYTES: usize = 128;

/// Inclusive maximum number of distinct terms indexed from one record.
pub const MAX_KEYWORD_RECORD_TERMS: usize = 16_384;

/// What a stored memory record represents.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// A verbatim conversation message.
    Message,
    /// A summary standing in for older messages.
    Summary,
    /// An operator or agent authored durable note.
    Note,
}

impl RecordKind {
    /// Every kind in stable order.
    pub const ALL: [Self; 3] = [Self::Message, Self::Summary, Self::Note];

    /// Returns the stable wire identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Summary => "summary",
            Self::Note => "note",
        }
    }
}

impl Display for RecordKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One durable unit of memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// Stable record identity.
    pub id: RecordId,
    /// Session the record belongs to.
    pub session: SessionId,
    /// What the record represents.
    pub kind: RecordKind,
    /// Record body.
    pub text: String,
    /// Wall-clock creation time in Unix milliseconds.
    pub unix_millis: u64,
    /// Operator-assigned labels.
    pub tags: BTreeSet<String>,
}

impl MemoryRecord {
    /// Validates the bounds that keep storage, embedding, and assembly work predictable.
    ///
    /// # Errors
    ///
    /// Returns a [`RecordError`] when the body is empty or oversized, when the
    /// tag count is over [`MAX_RECORD_TAGS`], or when one tag is over
    /// [`MAX_TAG_BYTES`].
    pub fn validate(&self) -> Result<(), RecordError> {
        if self.text.is_empty() {
            return Err(RecordError::EmptyText);
        }
        if self.text.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TextTooLong);
        }
        if self.tags.len() > MAX_RECORD_TAGS {
            return Err(RecordError::TooManyTags);
        }
        if self.tags.iter().any(|tag| tag.len() > MAX_TAG_BYTES) {
            return Err(RecordError::TagTooLong);
        }
        Ok(())
    }
}

/// Why a memory record is unsafe to retain or process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    /// The body was empty.
    EmptyText,
    /// The body exceeded [`MAX_RECORD_BYTES`].
    TextTooLong,
    /// The tag count exceeded [`MAX_RECORD_TAGS`].
    TooManyTags,
    /// One tag exceeded [`MAX_TAG_BYTES`].
    TagTooLong,
}

impl Display for RecordError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyText => "record body must not be empty",
            Self::TextTooLong => "record body exceeds the maximum size",
            Self::TooManyTags => "record has too many tags",
            Self::TagTooLong => "record tag exceeds the maximum size",
        };
        formatter.write_str(message)
    }
}

impl Error for RecordError {}

/// A retrieval request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievalQuery {
    text: String,
    limit: usize,
    session: Option<SessionId>,
    kinds: BTreeSet<RecordKind>,
}

impl RetrievalQuery {
    /// Creates a query, validating the free-text and the result bound.
    ///
    /// # Errors
    ///
    /// Returns [`RetrievalError::EmptyQuery`] when `text` is blank,
    /// [`RetrievalError::QueryTooLong`] past [`MAX_QUERY_BYTES`], and
    /// [`RetrievalError::InvalidLimit`] when `limit` is zero or above
    /// [`MAX_RETRIEVAL_LIMIT`]. The length bound is checked before the text
    /// ever reaches a tokenizer.
    pub fn new(text: &str, limit: usize) -> Result<Self, RetrievalError> {
        if text.trim().is_empty() {
            return Err(RetrievalError::EmptyQuery);
        }
        if text.len() > MAX_QUERY_BYTES {
            return Err(RetrievalError::QueryTooLong);
        }
        if limit == 0 || limit > MAX_RETRIEVAL_LIMIT {
            return Err(RetrievalError::InvalidLimit);
        }
        Ok(Self {
            text: text.to_owned(),
            limit,
            session: None,
            kinds: RecordKind::ALL.into_iter().collect(),
        })
    }

    /// Restricts the query to one session.
    #[must_use]
    pub fn in_session(mut self, session: SessionId) -> Self {
        self.session = Some(session);
        self
    }

    /// Restricts the query to a set of record kinds.
    ///
    /// # Errors
    ///
    /// Returns [`RetrievalError::NoKindsSelected`] when `kinds` is empty,
    /// because a query that admits no kind can only ever return nothing.
    pub fn of_kinds<I: IntoIterator<Item = RecordKind>>(
        mut self,
        kinds: I,
    ) -> Result<Self, RetrievalError> {
        let kinds: BTreeSet<RecordKind> = kinds.into_iter().collect();
        if kinds.is_empty() {
            return Err(RetrievalError::NoKindsSelected);
        }
        self.kinds = kinds;
        Ok(self)
    }

    /// Returns the query text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the result bound.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Returns the session filter.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionId> {
        self.session.as_ref()
    }

    /// Reports whether a record passes the non-scoring filters.
    #[must_use]
    pub fn accepts(&self, record: &MemoryRecord) -> bool {
        if !self.kinds.contains(&record.kind) {
            return false;
        }
        self.session
            .as_ref()
            .is_none_or(|session| *session == record.session)
    }
}

/// One scored retrieval result.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RetrievedItem {
    /// The matched record.
    pub record: MemoryRecord,
    /// Relevance score; higher is better.
    pub score: f32,
}

/// Whether a retrieval report covers every matching record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalCoverage {
    /// Every matching record was considered and returned.
    Complete,
    /// A result or backend-candidate limit left known work outside the report.
    Partial,
    /// The retriever cannot determine whether more matches exist.
    Unknown,
}

/// Bounded retrieval results with enough state for a caller to decide what to do next.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RetrievalReport {
    /// The best matching records, best first.
    pub items: Vec<RetrievedItem>,
    /// Number of records or backend candidates examined.
    pub examined_records: usize,
    /// Number of matches observed while examining those records.
    ///
    /// This is a lower bound when [`Self::coverage`] is not
    /// [`RetrievalCoverage::Complete`].
    pub matched_records: usize,
    /// Whether limits left possible matches unexamined or unreturned.
    pub coverage: RetrievalCoverage,
}

impl RetrievalReport {
    /// Reports whether every match is represented in [`Self::items`].
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self.coverage, RetrievalCoverage::Complete)
    }
}

/// Retrieval port.
pub trait Retriever {
    /// Returns the best matching records, best first.
    ///
    /// # Errors
    ///
    /// Returns [`RetrievalError::EmptyQuery`] when the query text carries no
    /// searchable term for this retriever's tokenizer, and
    /// [`RetrievalError::Vector`] when a retriever backed by an embedding
    /// model or a vector index has that backend refuse the query.
    fn retrieve(&mut self, query: &RetrievalQuery) -> Result<Vec<RetrievedItem>, RetrievalError>;

    /// Returns results plus bounded-work and truncation state.
    ///
    /// Implementations that cannot expose backend coverage retain compatibility
    /// through the default [`RetrievalCoverage::Unknown`] report.
    ///
    /// # Errors
    ///
    /// Returns the same [`RetrievalError`] as [`Self::retrieve`].
    fn retrieve_with_report(
        &mut self,
        query: &RetrievalQuery,
    ) -> Result<RetrievalReport, RetrievalError> {
        let items = self.retrieve(query)?;
        let returned = items.len();
        Ok(RetrievalReport {
            items,
            examined_records: returned,
            matched_records: returned,
            coverage: RetrievalCoverage::Unknown,
        })
    }
}

/// Splits text into lowercase alphanumeric tokens, in order and with
/// duplicates.
fn token_stream(text: &str) -> impl Iterator<Item = String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
}

/// Splits text into its distinct lowercase alphanumeric tokens.
fn tokens(text: &str) -> BTreeSet<String> {
    token_stream(text).collect()
}

fn bounded_record_tokens(text: &str) -> Result<BTreeSet<String>, RetrievalError> {
    let mut indexed = BTreeSet::new();
    for token in token_stream(text) {
        indexed.insert(token);
        if indexed.len() > MAX_KEYWORD_RECORD_TERMS {
            return Err(RetrievalError::TooManyRecordTerms);
        }
    }
    Ok(indexed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KeywordRecord {
    record: MemoryRecord,
    terms: BTreeSet<String>,
}

/// Deterministic lexical retriever with no external dependencies.
///
/// Scoring is the fraction of distinct query terms present in the record.
/// Ties break on newest first, then ascending record identifier, so the same
/// corpus and query always produce the same ordering.
///
/// The corpus is capacity-bounded for the same reason
/// [`ExactVectorIndex`](crate::vector::ExactVectorIndex) is: every record it
/// holds can come from attacker-influenced text, so an unbounded corpus is an
/// unbounded allocation reachable from ordinary agent output. Exceeding the
/// bound is a refusal, never a silent eviction; [`KeywordRetriever::remove`]
/// is the only way a record leaves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeywordRetriever {
    capacity: usize,
    // Bounded by `capacity` in `insert`; `remove` is the eviction path.
    records: BTreeMap<RecordId, KeywordRecord>,
}

impl Default for KeywordRetriever {
    fn default() -> Self {
        Self::new()
    }
}

impl KeywordRetriever {
    /// Creates an empty retriever with the crate's default record capacity,
    /// which is the one [`ExactVectorIndex::new`](crate::vector::ExactVectorIndex::new) uses.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            capacity: DEFAULT_INDEX_CAPACITY,
            records: BTreeMap::new(),
        }
    }

    /// Creates an empty retriever with an explicit record capacity.
    ///
    /// # Errors
    ///
    /// Returns [`RetrievalError::EmptyCapacity`] when `capacity` is zero,
    /// which would make the retriever refuse every record.
    pub const fn with_capacity(capacity: usize) -> Result<Self, RetrievalError> {
        if capacity == 0 {
            return Err(RetrievalError::EmptyCapacity);
        }
        Ok(Self {
            capacity,
            records: BTreeMap::new(),
        })
    }

    /// Returns the maximum number of records this retriever will hold.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Inserts or replaces one validated record.
    ///
    /// Record terms are indexed once here so query latency depends on the
    /// configured corpus bound rather than repeatedly scanning every body.
    ///
    /// # Errors
    ///
    /// Returns [`RetrievalError::InvalidRecord`] for an invalid record,
    /// [`RetrievalError::TooManyRecordTerms`] when its lexical index would be
    /// too large, or [`RetrievalError::RetrieverFull`] when a new record would
    /// exceed this retriever's capacity. Replacements remain allowed at
    /// capacity.
    pub fn insert(&mut self, record: MemoryRecord) -> Result<(), RetrievalError> {
        record.validate().map_err(RetrievalError::InvalidRecord)?;
        if !self.records.contains_key(&record.id) && self.records.len() >= self.capacity {
            return Err(RetrievalError::RetrieverFull);
        }
        let terms = bounded_record_tokens(&record.text)?;
        self.records
            .insert(record.id.clone(), KeywordRecord { record, terms });
        Ok(())
    }

    /// Removes one record, reporting whether it existed.
    pub fn remove(&mut self, id: &RecordId) -> bool {
        self.records.remove(id).is_some()
    }

    /// Returns the number of indexed records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reports whether the retriever holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn retrieve_report(&self, query: &RetrievalQuery) -> Result<RetrievalReport, RetrievalError> {
        let terms: Vec<String> = tokens(query.text()).into_iter().collect();
        if terms.is_empty() {
            return Err(RetrievalError::EmptyQuery);
        }
        let mut scored: Vec<RetrievedItem> = Vec::new();
        let mut examined_records = 0_usize;
        let mut matched_records = 0_usize;
        for indexed in self.records.values() {
            examined_records += 1;
            if !query.accepts(&indexed.record) {
                continue;
            }
            let hits = terms
                .iter()
                .filter(|term| indexed.terms.contains(*term))
                .count();
            if hits == 0 {
                continue;
            }
            matched_records += 1;
            #[expect(
                clippy::cast_precision_loss,
                reason = "both counts are distinct token counts from a query body capped at \
                          MAX_QUERY_BYTES, so neither can exceed a few thousand and both convert \
                          exactly inside f32's 2^24 integer range"
            )]
            let score = hits as f32 / terms.len() as f32;
            scored.push(RetrievedItem {
                record: indexed.record.clone(),
                score,
            });
            if scored.len() >= query.limit().saturating_mul(2) {
                sort_results(&mut scored);
                scored.truncate(query.limit());
            }
        }
        sort_results(&mut scored);
        scored.truncate(query.limit());
        let coverage = if matched_records > scored.len() {
            RetrievalCoverage::Partial
        } else {
            RetrievalCoverage::Complete
        };
        Ok(RetrievalReport {
            items: scored,
            examined_records,
            matched_records,
            coverage,
        })
    }
}

impl Retriever for KeywordRetriever {
    fn retrieve(&mut self, query: &RetrievalQuery) -> Result<Vec<RetrievedItem>, RetrievalError> {
        self.retrieve_report(query).map(|report| report.items)
    }

    fn retrieve_with_report(
        &mut self,
        query: &RetrievalQuery,
    ) -> Result<RetrievalReport, RetrievalError> {
        self.retrieve_report(query)
    }
}

/// Retriever backed by an embedding model and a vector index port.
#[derive(Clone, Debug)]
pub struct VectorRetriever<M: EmbeddingModel, I: VectorIndex> {
    model: M,
    index: I,
    // Bounded transitively: `insert` only reaches this map after the index
    // has accepted the embedding, so the index's capacity is this map's
    // capacity too. `remove` evicts from both together.
    records: BTreeMap<RecordId, MemoryRecord>,
}

impl<M: EmbeddingModel, I: VectorIndex> VectorRetriever<M, I> {
    /// Creates a retriever over a model and an index.
    pub const fn new(model: M, index: I) -> Self {
        Self {
            model,
            index,
            records: BTreeMap::new(),
        }
    }

    /// Embeds and indexes one record.
    ///
    /// The payload is stored only after the index has accepted the embedding,
    /// so a refusal leaves the retriever exactly as it was.
    ///
    /// # Errors
    ///
    /// Returns [`RetrievalError::Vector`] when the model cannot embed the
    /// record body, when the embedding's width is not the one the index
    /// accepts ([`VectorError::DimensionMismatch`]), or when adding a new
    /// record would take the index past its capacity
    /// ([`VectorError::IndexFull`]).
    pub fn insert(&mut self, record: MemoryRecord) -> Result<(), RetrievalError> {
        record.validate().map_err(RetrievalError::InvalidRecord)?;
        let embedding = self
            .model
            .embed(&record.text)
            .map_err(RetrievalError::Vector)?;
        self.index
            .upsert(record.id.clone(), embedding)
            .map_err(RetrievalError::Vector)?;
        self.records.insert(record.id.clone(), record);
        Ok(())
    }

    /// Removes one record from both the index and the payload map.
    pub fn remove(&mut self, id: &RecordId) -> bool {
        let indexed = self.index.remove(id);
        let stored = self.records.remove(id).is_some();
        indexed || stored
    }

    /// Returns the number of indexed records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reports whether the retriever holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Embeds arbitrary text with the configured model.
    ///
    /// # Errors
    ///
    /// Returns the [`VectorError`] the configured [`EmbeddingModel`] reports,
    /// which for the models shipped here means a degenerate vector
    /// ([`VectorError::ZeroEmbedding`], [`VectorError::NonFiniteComponent`])
    /// or an unusable dimensionality.
    pub fn embed(&mut self, text: &str) -> Result<Embedding, VectorError> {
        self.model.embed(text)
    }

    fn retrieve_report(
        &mut self,
        query: &RetrievalQuery,
    ) -> Result<RetrievalReport, RetrievalError> {
        let embedded = self
            .model
            .embed(query.text())
            .map_err(RetrievalError::Vector)?;
        let candidates = query.limit().saturating_mul(4).min(MAX_RETRIEVAL_LIMIT * 4);
        let hits = self
            .index
            .search(&embedded, candidates)
            .map_err(RetrievalError::Vector)?;
        let examined_records = hits.len();
        let backend_exhausted = examined_records < candidates || candidates >= self.records.len();
        let mut scored: Vec<RetrievedItem> = Vec::new();
        for hit in hits {
            let Some(record) = self.records.get(&hit.id) else {
                continue;
            };
            if !query.accepts(record) {
                continue;
            }
            scored.push(RetrievedItem {
                record: record.clone(),
                score: hit.score,
            });
        }
        sort_results(&mut scored);
        let matched_records = scored.len();
        scored.truncate(query.limit());
        let coverage = if backend_exhausted && matched_records <= scored.len() {
            RetrievalCoverage::Complete
        } else {
            RetrievalCoverage::Partial
        };
        Ok(RetrievalReport {
            items: scored,
            examined_records,
            matched_records,
            coverage,
        })
    }
}

impl<M: EmbeddingModel, I: VectorIndex> Retriever for VectorRetriever<M, I> {
    fn retrieve(&mut self, query: &RetrievalQuery) -> Result<Vec<RetrievedItem>, RetrievalError> {
        self.retrieve_report(query).map(|report| report.items)
    }

    fn retrieve_with_report(
        &mut self,
        query: &RetrievalQuery,
    ) -> Result<RetrievalReport, RetrievalError> {
        self.retrieve_report(query)
    }
}

/// Applies the crate-wide result ordering.
fn sort_results(items: &mut [RetrievedItem]) {
    items.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then(right.record.unix_millis.cmp(&left.record.unix_millis))
            .then(left.record.id.cmp(&right.record.id))
    });
}

/// A rejected retrieval request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetrievalError {
    /// The query text had no searchable content.
    EmptyQuery,
    /// The query text exceeded its byte bound.
    QueryTooLong,
    /// The result bound was zero or above the maximum.
    InvalidLimit,
    /// A kind filter selected nothing.
    NoKindsSelected,
    /// A record failed its shared size validation.
    InvalidRecord(RecordError),
    /// A lexical record had too many distinct terms to index predictably.
    TooManyRecordTerms,
    /// The requested retriever capacity was zero.
    EmptyCapacity,
    /// The retriever already holds its maximum number of records.
    RetrieverFull,
    /// The embedding model or index refused the operation.
    Vector(VectorError),
}

impl Display for RetrievalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyQuery => formatter.write_str("query has no searchable terms"),
            Self::QueryTooLong => formatter.write_str("query text exceeds the maximum size"),
            Self::InvalidLimit => formatter.write_str("query result limit is out of range"),
            Self::NoKindsSelected => formatter.write_str("query selected no record kinds"),
            Self::InvalidRecord(error) => write!(formatter, "invalid memory record: {error}"),
            Self::TooManyRecordTerms => {
                formatter.write_str("record has too many distinct terms to index")
            }
            Self::EmptyCapacity => {
                formatter.write_str("retriever capacity must be at least one record")
            }
            Self::RetrieverFull => {
                formatter.write_str("retriever holds its maximum number of records")
            }
            Self::Vector(error) => write!(formatter, "vector backend refused: {error}"),
        }
    }
}

impl Error for RetrievalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRecord(error) => Some(error),
            Self::Vector(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector::{ExactVectorIndex, HashingEmbeddingModel};

    fn session(value: &str) -> SessionId {
        SessionId::new(value).expect("valid session identifier")
    }

    fn record(id: &str, session_id: &str, kind: RecordKind, text: &str, at: u64) -> MemoryRecord {
        MemoryRecord {
            id: RecordId::new(id).expect("valid record identifier"),
            session: session(session_id),
            kind,
            text: text.to_owned(),
            unix_millis: at,
            tags: BTreeSet::new(),
        }
    }

    #[test]
    fn queries_validate_their_bounds() {
        assert_eq!(
            RetrievalQuery::new("  ", 5),
            Err(RetrievalError::EmptyQuery)
        );
        assert_eq!(
            RetrievalQuery::new("hello", 0),
            Err(RetrievalError::InvalidLimit)
        );
        assert_eq!(
            RetrievalQuery::new("hello", MAX_RETRIEVAL_LIMIT + 1),
            Err(RetrievalError::InvalidLimit)
        );
        let query = RetrievalQuery::new("hello", 3).expect("valid query");
        assert_eq!(query.limit(), 3);
        assert_eq!(query.text(), "hello");
        assert_eq!(query.session(), None);
        assert_eq!(
            query.of_kinds(Vec::<RecordKind>::new()),
            Err(RetrievalError::NoKindsSelected)
        );
    }

    #[test]
    fn keyword_scores_are_the_fraction_of_query_terms_present() {
        let mut retriever = KeywordRetriever::new();
        retriever
            .insert(record(
                "all",
                "s",
                RecordKind::Note,
                "deploy the gateway service",
                10,
            ))
            .expect("indexed");
        retriever
            .insert(record("some", "s", RecordKind::Note, "deploy the cat", 20))
            .expect("indexed");
        retriever
            .insert(record("none", "s", RecordKind::Note, "unrelated text", 30))
            .expect("indexed");
        assert_eq!(retriever.len(), 3);

        let query = RetrievalQuery::new("deploy gateway service", 10).expect("valid query");
        let hits = retriever.retrieve(&query).expect("retrieved");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].record.id.as_str(), "all");
        assert!((hits[0].score - 1.0).abs() < 1e-6);
        assert_eq!(hits[1].record.id.as_str(), "some");
        assert!((hits[1].score - 1.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn keyword_ties_break_on_newest_then_identifier() {
        let mut retriever = KeywordRetriever::new();
        retriever
            .insert(record("b", "s", RecordKind::Note, "alpha", 100))
            .expect("indexed");
        retriever
            .insert(record("a", "s", RecordKind::Note, "alpha", 100))
            .expect("indexed");
        retriever
            .insert(record("c", "s", RecordKind::Note, "alpha", 500))
            .expect("indexed");
        let query = RetrievalQuery::new("alpha", 10).expect("valid query");
        let hits = retriever.retrieve(&query).expect("retrieved");
        assert_eq!(
            hits.iter()
                .map(|hit| hit.record.id.as_str())
                .collect::<Vec<_>>(),
            vec!["c", "a", "b"]
        );
    }

    #[test]
    fn session_and_kind_filters_exclude_records_entirely() {
        let mut retriever = KeywordRetriever::new();
        retriever
            .insert(record("m", "one", RecordKind::Message, "shared term", 1))
            .expect("indexed");
        retriever
            .insert(record("n", "one", RecordKind::Note, "shared term", 2))
            .expect("indexed");
        retriever
            .insert(record("o", "two", RecordKind::Note, "shared term", 3))
            .expect("indexed");

        let scoped = RetrievalQuery::new("shared", 10)
            .expect("valid query")
            .in_session(session("one"));
        let hits = retriever.retrieve(&scoped).expect("retrieved");
        assert_eq!(
            hits.iter()
                .map(|hit| hit.record.id.as_str())
                .collect::<Vec<_>>(),
            vec!["n", "m"]
        );

        let kinded = RetrievalQuery::new("shared", 10)
            .expect("valid query")
            .of_kinds([RecordKind::Note])
            .expect("valid kinds");
        let hits = retriever.retrieve(&kinded).expect("retrieved");
        assert_eq!(
            hits.iter()
                .map(|hit| hit.record.id.as_str())
                .collect::<Vec<_>>(),
            vec!["o", "n"]
        );
    }

    #[test]
    fn the_limit_is_honoured_and_removal_works() {
        let mut retriever = KeywordRetriever::new();
        for index in 0..5_u64 {
            retriever
                .insert(record(
                    &format!("r{index}"),
                    "s",
                    RecordKind::Note,
                    "common",
                    index,
                ))
                .expect("indexed");
        }
        let query = RetrievalQuery::new("common", 2).expect("valid query");
        assert_eq!(retriever.retrieve(&query).expect("retrieved").len(), 2);
        assert!(retriever.remove(&RecordId::new("r0").expect("valid identifier")));
        assert!(!retriever.remove(&RecordId::new("r0").expect("valid identifier")));
        assert_eq!(retriever.len(), 4);
        assert!(!retriever.is_empty());
    }

    #[test]
    fn vector_retrieval_finds_the_exact_text_it_indexed() {
        let model = HashingEmbeddingModel::new(128).expect("valid model");
        let index = ExactVectorIndex::new(128).expect("valid index");
        let mut retriever = VectorRetriever::new(model, index);
        retriever
            .insert(record(
                "gateway",
                "s",
                RecordKind::Note,
                "the gateway protocol handshake",
                1,
            ))
            .expect("indexed");
        retriever
            .insert(record(
                "kitchen",
                "s",
                RecordKind::Note,
                "a recipe for lemon cake",
                2,
            ))
            .expect("indexed");

        let query = RetrievalQuery::new("the gateway protocol handshake", 1).expect("valid query");
        let hits = retriever.retrieve(&query).expect("retrieved");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record.id.as_str(), "gateway");
        assert!(
            hits[0].score > 0.99,
            "an exact text match should score near one, got {}",
            hits[0].score
        );
    }

    #[test]
    fn vector_retrieval_applies_filters_after_scoring() {
        let model = HashingEmbeddingModel::new(64).expect("valid model");
        let index = ExactVectorIndex::new(64).expect("valid index");
        let mut retriever = VectorRetriever::new(model, index);
        retriever
            .insert(record("a", "one", RecordKind::Note, "identical body", 1))
            .expect("indexed");
        retriever
            .insert(record("b", "two", RecordKind::Note, "identical body", 2))
            .expect("indexed");
        assert_eq!(retriever.len(), 2);

        let query = RetrievalQuery::new("identical body", 5)
            .expect("valid query")
            .in_session(session("two"));
        let hits = retriever.retrieve(&query).expect("retrieved");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record.id.as_str(), "b");

        assert!(retriever.remove(&RecordId::new("b").expect("valid identifier")));
        assert!(retriever.retrieve(&query).expect("retrieved").is_empty());
    }

    #[test]
    fn the_keyword_corpus_is_bounded_by_the_same_default_its_vector_sibling_uses() {
        assert_eq!(
            KeywordRetriever::new().capacity(),
            ExactVectorIndex::new(8).expect("valid index").capacity()
        );
        assert_eq!(
            KeywordRetriever::with_capacity(0),
            Err(RetrievalError::EmptyCapacity)
        );
        assert_eq!(
            KeywordRetriever::with_capacity(4)
                .expect("valid capacity")
                .capacity(),
            4
        );
    }

    #[test]
    fn a_full_keyword_corpus_refuses_new_records_but_still_accepts_replacements() {
        let mut retriever = KeywordRetriever::with_capacity(2).expect("valid capacity");
        retriever
            .insert(record("a", "s", RecordKind::Note, "first body", 1))
            .expect("indexed");
        retriever
            .insert(record("b", "s", RecordKind::Note, "second body", 2))
            .expect("indexed");

        assert_eq!(
            retriever.insert(record("c", "s", RecordKind::Note, "third body", 3)),
            Err(RetrievalError::RetrieverFull),
            "a bound that could be exceeded is not a bound"
        );
        assert_eq!(retriever.len(), 2, "a refusal must store nothing");
        assert!(
            retriever
                .retrieve(&RetrievalQuery::new("third", 5).expect("valid query"))
                .expect("retrieved")
                .is_empty(),
            "a refused record must not be searchable"
        );

        // A full retriever stays usable: replacing a record it already holds cannot grow it.
        retriever
            .insert(record("a", "s", RecordKind::Note, "rewritten body", 4))
            .expect("a replacement is never refused for capacity");
        assert_eq!(retriever.len(), 2);

        // `remove` is the eviction path, and it frees a slot.
        assert!(retriever.remove(&RecordId::new("b").expect("valid identifier")));
        retriever
            .insert(record("c", "s", RecordKind::Note, "third body", 5))
            .expect("removing a record frees its slot");
        assert_eq!(retriever.len(), 2);
    }
}

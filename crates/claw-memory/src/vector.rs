//! Embedding port and an in-crate exact-search vector index.
//!
//! Nothing here binds to an external vector database. [`VectorIndex`] is the
//! port a production adapter implements; [`ExactVectorIndex`] is a complete,
//! deterministic brute-force implementation used by tests and small
//! workspaces, where an approximate index would only add risk.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

/// Inclusive maximum embedding dimensionality accepted by this crate.
const MAX_DIMENSIONS: usize = 8192;

/// Default maximum number of records one in-crate index will hold.
pub(crate) const DEFAULT_INDEX_CAPACITY: usize = 100_000;

/// A dense embedding with a validated dimensionality.
///
/// [`Deserialize`] runs the same validation as [`Embedding::new`], so a
/// stored vector cannot reintroduce a zero or non-finite direction that would
/// make every score computed against it meaningless.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Embedding {
    values: Vec<f32>,
    /// The magnitude, computed once by the constructor that already had to
    /// compute it to reject the zero vector.
    ///
    /// Cosine similarity is the inner loop of every exact search, and it needs
    /// both magnitudes. Recomputing them there made a search over `n` records
    /// walk the query vector `n` times and each stored vector twice, so a
    /// scoring pass touched three times the floats it had to. The value stored
    /// here is the one [`Embedding::new`] computed, from the same components in
    /// the same order, so scores are bit-for-bit what they were.
    ///
    /// It is not part of the wire shape: it is derived from `values`, and
    /// [`Deserialize`] reconstructs it by running the same validation the
    /// constructor does.
    #[serde(skip)]
    norm: f32,
}

/// The wire shape of an [`Embedding`], before it is validated.
#[derive(Deserialize)]
#[serde(rename = "Embedding")]
struct RawEmbedding {
    values: Vec<f32>,
}

impl<'de> Deserialize<'de> for Embedding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEmbedding::deserialize(deserializer)?;
        Self::new(raw.values).map_err(de::Error::custom)
    }
}

impl Embedding {
    /// Validates and creates an embedding.
    ///
    /// Non-finite components and the zero vector are refused: cosine
    /// similarity is undefined for both, and silently coercing them would
    /// make retrieval order depend on floating-point accidents.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::EmptyEmbedding`] for no components,
    /// [`VectorError::TooManyDimensions`] past the crate's dimensionality
    /// ceiling, [`VectorError::NonFiniteComponent`] when any component is
    /// `NaN` or infinite, and [`VectorError::ZeroEmbedding`] when the
    /// magnitude is zero and the direction is therefore undefined.
    pub fn new(values: Vec<f32>) -> Result<Self, VectorError> {
        if values.is_empty() {
            return Err(VectorError::EmptyEmbedding);
        }
        if values.len() > MAX_DIMENSIONS {
            return Err(VectorError::TooManyDimensions);
        }
        if values.iter().any(|value| !value.is_finite()) {
            return Err(VectorError::NonFiniteComponent);
        }
        let norm = norm(&values);
        if norm == 0.0 || !norm.is_finite() {
            return Err(VectorError::ZeroEmbedding);
        }
        Ok(Self { values, norm })
    }

    /// Returns the components.
    #[must_use]
    pub fn values(&self) -> &[f32] {
        &self.values
    }

    /// Returns the dimensionality.
    #[must_use]
    pub const fn dimensions(&self) -> usize {
        self.values.len()
    }

    /// Returns the cosine similarity with another embedding.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::DimensionMismatch`] when the two embeddings have
    /// different dimensionalities, which makes their dot product meaningless.
    pub fn cosine_similarity(&self, other: &Self) -> Result<f32, VectorError> {
        if self.values.len() != other.values.len() {
            return Err(VectorError::DimensionMismatch);
        }
        let dot: f32 = self
            .values
            .iter()
            .zip(other.values.iter())
            .map(|(left, right)| left * right)
            .sum();
        Ok(dot / (self.norm * other.norm))
    }
}

fn norm(values: &[f32]) -> f32 {
    values.iter().map(|value| value * value).sum::<f32>().sqrt()
}

/// Host-supplied text embedding port.
pub trait EmbeddingModel {
    /// Returns the dimensionality every produced embedding has.
    fn dimensions(&self) -> usize;

    /// Embeds one text fragment.
    ///
    /// # Errors
    ///
    /// Returns a [`VectorError`] when the model cannot produce a usable
    /// vector: [`VectorError::EmptyEmbedding`] or
    /// [`VectorError::TooManyDimensions`] when the configured dimensionality
    /// is unusable, [`VectorError::NonFiniteComponent`] or
    /// [`VectorError::ZeroEmbedding`] when the text yields a degenerate
    /// vector, and [`VectorError::DimensionMismatch`] when a host model
    /// returns a width other than the one it advertises.
    fn embed(&mut self, text: &str) -> Result<Embedding, VectorError>;
}

/// A deterministic hashing embedding used for tests and offline operation.
///
/// This is a bag-of-words feature hash, not a semantic model. It is here so
/// the crate can be exercised end to end with no network and no external
/// service; production deployments supply a real [`EmbeddingModel`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HashingEmbeddingModel {
    dimensions: usize,
}

impl HashingEmbeddingModel {
    /// Creates a model with an explicit dimensionality.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::EmptyEmbedding`] when `dimensions` is zero and
    /// [`VectorError::TooManyDimensions`] when it exceeds the crate's
    /// dimensionality ceiling.
    pub const fn new(dimensions: usize) -> Result<Self, VectorError> {
        if dimensions == 0 {
            return Err(VectorError::EmptyEmbedding);
        }
        if dimensions > MAX_DIMENSIONS {
            return Err(VectorError::TooManyDimensions);
        }
        Ok(Self { dimensions })
    }
}

impl EmbeddingModel for HashingEmbeddingModel {
    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn embed(&mut self, text: &str) -> Result<Embedding, VectorError> {
        let mut values = vec![0.0_f32; self.dimensions];
        for token in tokenize(text) {
            let hash = fnv1a(token.as_bytes());
            let bucket = usize::try_from(hash % self.dimensions as u64).unwrap_or(0);
            // The low bit of an independent hash byte sets the sign, which
            // keeps unrelated tokens from always reinforcing each other.
            let sign = if hash.rotate_left(17) & 1 == 0 {
                1.0_f32
            } else {
                -1.0_f32
            };
            values[bucket] += sign;
        }
        if values.iter().all(|value| *value == 0.0) {
            // An empty or purely punctuational input still needs a defined
            // direction; bucket zero is a stable, documented choice.
            values[0] = 1.0;
        }
        Embedding::new(values)
    }
}

/// Streams the lowercase alphanumeric tokens of `text`.
///
/// The tokens are yielded lazily so hashing a message body never materialises
/// a second copy of it as a vector of owned tokens.
fn tokenize(text: &str) -> impl Iterator<Item = String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A stable record identifier used by the index and the store.
///
/// [`Deserialize`] runs the same validation as [`RecordId::new`], so a stored
/// identifier cannot reintroduce one the constructor would have refused.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RecordId(String);

impl RecordId {
    /// Validates and creates a record identifier.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::InvalidRecordId`] when `value` is empty, longer
    /// than 256 bytes, or contains anything outside ASCII alphanumerics, `-`,
    /// `_`, `.` and `:`, so an identifier is always safe as a storage key and
    /// in a log line.
    pub fn new(value: &str) -> Result<Self, VectorError> {
        if value.is_empty() || value.len() > 256 {
            return Err(VectorError::InvalidRecordId);
        }
        let acceptable = value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        });
        if acceptable {
            Ok(Self(value.to_owned()))
        } else {
            Err(VectorError::InvalidRecordId)
        }
    }

    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for RecordId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RecordId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(&value).map_err(de::Error::custom)
    }
}

/// One scored index hit.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ScoredMatch {
    /// Matched record.
    pub id: RecordId,
    /// Cosine similarity in `[-1, 1]`.
    pub score: f32,
}

/// Vector search port.
pub trait VectorIndex {
    /// Returns the dimensionality the index accepts.
    fn dimensions(&self) -> usize;

    /// Inserts or replaces one embedding.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::DimensionMismatch`] when the embedding's width
    /// is not the one the index accepts, and [`VectorError::IndexFull`] when
    /// adding a record that is not already present would take the index past
    /// its capacity. Replacing an existing record is never refused for
    /// capacity, so a full index stays usable rather than becoming read-only.
    fn upsert(&mut self, id: RecordId, embedding: Embedding) -> Result<(), VectorError>;

    /// Removes one embedding, reporting whether it existed.
    fn remove(&mut self, id: &RecordId) -> bool;

    /// Returns the highest-scoring records, best first.
    ///
    /// A `limit` of zero is not an error: it returns no matches.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::DimensionMismatch`] when the query's width is
    /// not the one the index accepts, so a mis-shaped query is refused rather
    /// than scored against an incompatible corpus.
    fn search(&self, query: &Embedding, limit: usize) -> Result<Vec<ScoredMatch>, VectorError>;

    /// Returns the number of indexed records.
    fn len(&self) -> usize;

    /// Reports whether the index is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Brute-force exact cosine index.
///
/// Ordering is fully specified: descending score, then ascending record
/// identifier. Ties therefore never depend on insertion order or on hash
/// iteration order.
#[derive(Clone, Debug, PartialEq)]
pub struct ExactVectorIndex {
    dimensions: usize,
    capacity: usize,
    // Bounded by `capacity` in `upsert`; `remove` is the eviction path.
    entries: BTreeMap<RecordId, Embedding>,
}

impl ExactVectorIndex {
    /// Creates an empty index of a fixed dimensionality.
    ///
    /// The index is capacity-bounded because every record it holds can come
    /// from attacker-influenced text: an unbounded index is an unbounded
    /// allocation reachable from ordinary agent output.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::EmptyEmbedding`] when `dimensions` is zero and
    /// [`VectorError::TooManyDimensions`] when it exceeds the crate's
    /// dimensionality ceiling.
    pub const fn new(dimensions: usize) -> Result<Self, VectorError> {
        Self::with_capacity(dimensions, DEFAULT_INDEX_CAPACITY)
    }

    /// Creates an empty index with an explicit record capacity.
    ///
    /// # Errors
    ///
    /// Returns [`VectorError::EmptyEmbedding`] when `dimensions` is zero,
    /// [`VectorError::TooManyDimensions`] when it exceeds the crate's
    /// dimensionality ceiling, and [`VectorError::EmptyCapacity`] when
    /// `capacity` is zero, which would make the index refuse every record.
    pub const fn with_capacity(dimensions: usize, capacity: usize) -> Result<Self, VectorError> {
        if dimensions == 0 {
            return Err(VectorError::EmptyEmbedding);
        }
        if dimensions > MAX_DIMENSIONS {
            return Err(VectorError::TooManyDimensions);
        }
        if capacity == 0 {
            return Err(VectorError::EmptyCapacity);
        }
        Ok(Self {
            dimensions,
            capacity,
            entries: BTreeMap::new(),
        })
    }

    /// Returns the maximum number of records this index will hold.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the indexed identifiers in ascending order.
    #[must_use]
    pub fn ids(&self) -> Vec<RecordId> {
        self.entries.keys().cloned().collect()
    }
}

impl VectorIndex for ExactVectorIndex {
    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn upsert(&mut self, id: RecordId, embedding: Embedding) -> Result<(), VectorError> {
        if embedding.dimensions() != self.dimensions {
            return Err(VectorError::DimensionMismatch);
        }
        // Replacing an existing record is always allowed; only growth is
        // capped, so a full index stays usable rather than becoming read-only.
        if !self.entries.contains_key(&id) && self.entries.len() >= self.capacity {
            return Err(VectorError::IndexFull);
        }
        self.entries.insert(id, embedding);
        Ok(())
    }

    fn remove(&mut self, id: &RecordId) -> bool {
        self.entries.remove(id).is_some()
    }

    fn search(&self, query: &Embedding, limit: usize) -> Result<Vec<ScoredMatch>, VectorError> {
        if query.dimensions() != self.dimensions {
            return Err(VectorError::DimensionMismatch);
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        // Only the running best `limit` matches are retained, so the working
        // set is bounded by the caller's limit rather than by the index size.
        // A candidate's identifier is cloned only once it has displaced
        // something, so a scan over a large index does not allocate a string
        // per record it looks at and then throws away.
        let mut best: Vec<ScoredMatch> = Vec::with_capacity(limit.min(self.entries.len()));
        for (id, embedding) in &self.entries {
            let score = query.cosine_similarity(embedding)?;
            if best.len() == limit {
                let worst = best.last().expect("a full buffer has a last element");
                if !ranks_before(score, id, worst) {
                    continue;
                }
                best.pop();
            }
            let position = best
                .iter()
                .position(|existing| ranks_before(score, id, existing))
                .unwrap_or(best.len());
            best.insert(
                position,
                ScoredMatch {
                    id: id.clone(),
                    score,
                },
            );
        }
        Ok(best)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Orders two matches by descending score, then by ascending identifier.
fn ranks_before(score: f32, id: &RecordId, existing: &ScoredMatch) -> bool {
    match existing.score.total_cmp(&score) {
        Ordering::Equal => *id < existing.id,
        Ordering::Less => true,
        Ordering::Greater => false,
    }
}

/// A rejected embedding or index operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VectorError {
    /// The embedding had no components.
    EmptyEmbedding,
    /// The embedding exceeded the dimensionality bound.
    TooManyDimensions,
    /// A component was not a finite number.
    NonFiniteComponent,
    /// The embedding had zero magnitude, so its direction is undefined.
    ZeroEmbedding,
    /// Two embeddings had different dimensionalities.
    DimensionMismatch,
    /// A record identifier was empty or contained unacceptable characters.
    InvalidRecordId,
    /// An index was configured with no capacity at all.
    EmptyCapacity,
    /// The index already holds its maximum number of records.
    IndexFull,
}

impl Display for VectorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyEmbedding => "embedding must have at least one component",
            Self::TooManyDimensions => "embedding exceeds the dimensionality bound",
            Self::NonFiniteComponent => "embedding component is not finite",
            Self::ZeroEmbedding => "embedding has zero magnitude",
            Self::DimensionMismatch => "embedding dimensionalities differ",
            Self::InvalidRecordId => "record identifier is not acceptable",
            Self::EmptyCapacity => "index capacity must be at least one record",
            Self::IndexFull => "index holds its maximum number of records",
        };
        formatter.write_str(message)
    }
}

impl Error for VectorError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> RecordId {
        RecordId::new(value).expect("valid record identifier")
    }

    fn embedding(values: &[f32]) -> Embedding {
        Embedding::new(values.to_vec()).expect("valid embedding")
    }

    #[test]
    fn a_stored_embedding_is_validated_when_it_is_read_back() {
        let original = embedding(&[0.5, -0.25, 1.0]);
        let encoded = serde_json::to_string(&original).expect("serialized");
        let restored: Embedding = serde_json::from_str(&encoded).expect("deserialized");
        assert_eq!(restored, original, "a valid embedding is restored as-is");
        assert_eq!(
            serde_json::to_string(&restored).expect("serialized"),
            encoded
        );

        for degenerate in [
            "{\"values\":[]}",
            "{\"values\":[0.0,0.0]}",
            "{\"values\":[1.0,null]}",
        ] {
            assert!(
                serde_json::from_str::<Embedding>(degenerate).is_err(),
                "restored a degenerate embedding from {degenerate}"
            );
        }
    }

    #[test]
    fn a_stored_record_identifier_is_validated_when_it_is_read_back() {
        assert_eq!(
            serde_json::from_str::<RecordId>("\"rec-1\"").expect("valid identifier"),
            id("rec-1")
        );
        for bad in ["\"\"", "\"a b\"", "\"a/b\""] {
            let error = serde_json::from_str::<RecordId>(bad)
                .expect_err("an identifier the constructor refuses cannot be restored");
            assert!(
                error.to_string().contains("record identifier"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn degenerate_embeddings_are_refused() {
        assert_eq!(Embedding::new(vec![]), Err(VectorError::EmptyEmbedding));
        assert_eq!(
            Embedding::new(vec![0.0, 0.0, 0.0]),
            Err(VectorError::ZeroEmbedding)
        );
        assert_eq!(
            Embedding::new(vec![1.0, f32::NAN]),
            Err(VectorError::NonFiniteComponent)
        );
        assert_eq!(
            Embedding::new(vec![1.0, f32::INFINITY]),
            Err(VectorError::NonFiniteComponent)
        );
        assert_eq!(
            Embedding::new(vec![1.0; MAX_DIMENSIONS + 1]),
            Err(VectorError::TooManyDimensions)
        );
    }

    #[test]
    fn cosine_similarity_matches_hand_computed_values() {
        let a = embedding(&[1.0, 0.0]);
        let b = embedding(&[0.0, 1.0]);
        let c = embedding(&[-1.0, 0.0]);
        let d = embedding(&[3.0, 0.0]);
        assert!((a.cosine_similarity(&a).expect("same dimensions") - 1.0).abs() < 1e-6);
        assert!(a.cosine_similarity(&b).expect("same dimensions").abs() < 1e-6);
        assert!((a.cosine_similarity(&c).expect("same dimensions") + 1.0).abs() < 1e-6);
        assert!((a.cosine_similarity(&d).expect("same dimensions") - 1.0).abs() < 1e-6);
        assert_eq!(
            a.cosine_similarity(&embedding(&[1.0, 2.0, 3.0])),
            Err(VectorError::DimensionMismatch)
        );
    }

    #[test]
    fn search_orders_by_score_then_identifier() {
        let mut index = ExactVectorIndex::new(2).expect("valid index");
        index.upsert(id("b"), embedding(&[1.0, 0.0])).expect("ok");
        index.upsert(id("a"), embedding(&[1.0, 0.0])).expect("ok");
        index.upsert(id("c"), embedding(&[0.0, 1.0])).expect("ok");
        index.upsert(id("d"), embedding(&[-1.0, 0.0])).expect("ok");

        let hits = index.search(&embedding(&[1.0, 0.0]), 10).expect("ok");
        assert_eq!(
            hits.iter().map(|hit| hit.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c", "d"],
            "equal scores must break ties on ascending identifier"
        );
        assert!((hits[0].score - 1.0).abs() < 1e-6);
        assert!(hits[2].score.abs() < 1e-6);
        assert!((hits[3].score + 1.0).abs() < 1e-6);
    }

    #[test]
    fn search_respects_the_limit_and_upsert_replaces() {
        let mut index = ExactVectorIndex::new(2).expect("valid index");
        index.upsert(id("a"), embedding(&[1.0, 0.0])).expect("ok");
        index.upsert(id("b"), embedding(&[0.9, 0.1])).expect("ok");
        assert_eq!(index.len(), 2);
        assert!(!index.is_empty());

        let hits = index.search(&embedding(&[1.0, 0.0]), 1).expect("ok");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, id("a"));

        index.upsert(id("a"), embedding(&[0.0, 1.0])).expect("ok");
        assert_eq!(index.len(), 2);
        let hits = index.search(&embedding(&[1.0, 0.0]), 1).expect("ok");
        assert_eq!(hits[0].id, id("b"));

        assert!(index.remove(&id("a")));
        assert!(!index.remove(&id("a")));
        assert_eq!(index.ids(), vec![id("b")]);
    }

    #[test]
    fn dimension_mismatches_are_refused_on_both_paths() {
        let mut index = ExactVectorIndex::new(3).expect("valid index");
        assert_eq!(
            index.upsert(id("a"), embedding(&[1.0, 0.0])),
            Err(VectorError::DimensionMismatch)
        );
        assert_eq!(
            index.search(&embedding(&[1.0, 0.0]), 1),
            Err(VectorError::DimensionMismatch)
        );
        assert!(index.is_empty());
        assert_eq!(index.dimensions(), 3);
    }

    #[test]
    fn hashing_embeddings_are_deterministic_and_order_insensitive() {
        let mut model = HashingEmbeddingModel::new(64).expect("valid model");
        let first = model.embed("the quick brown fox").expect("embedded");
        let second = model.embed("the quick brown fox").expect("embedded");
        assert_eq!(first, second);
        let reordered = model.embed("fox brown quick the").expect("embedded");
        assert_eq!(first, reordered, "a bag of words ignores order");
        let different = model.embed("entirely unrelated content").expect("embedded");
        assert_ne!(first, different);
        assert_eq!(first.dimensions(), 64);
        assert_eq!(model.dimensions(), 64);
    }

    #[test]
    fn punctuation_only_text_still_yields_a_usable_direction() {
        let mut model = HashingEmbeddingModel::new(8).expect("valid model");
        let embedded = model.embed("!!! ??? ...").expect("embedded");
        assert_eq!(embedded.values(), &[1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn record_identifiers_are_validated() {
        assert_eq!(
            RecordId::new("session:1.msg-3_x")
                .expect("valid identifier")
                .as_str(),
            "session:1.msg-3_x"
        );
        for bad in ["", "a b", "a/b", "a\nb", "\u{202e}"] {
            assert_eq!(RecordId::new(bad), Err(VectorError::InvalidRecordId));
        }
        assert_eq!(
            RecordId::new(&"a".repeat(257)),
            Err(VectorError::InvalidRecordId)
        );
    }
}

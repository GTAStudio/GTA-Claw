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

use serde::{Deserialize, Serialize};

/// Inclusive maximum embedding dimensionality accepted by this crate.
const MAX_DIMENSIONS: usize = 8192;

/// A dense embedding with a validated dimensionality.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Embedding {
    values: Vec<f32>,
}

impl Embedding {
    /// Validates and creates an embedding.
    ///
    /// Non-finite components and the zero vector are refused: cosine
    /// similarity is undefined for both, and silently coercing them would
    /// make retrieval order depend on floating-point accidents.
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
        Ok(Self { values })
    }

    /// Returns the components.
    #[must_use]
    pub fn values(&self) -> &[f32] {
        &self.values
    }

    /// Returns the dimensionality.
    #[must_use]
    pub fn dimensions(&self) -> usize {
        self.values.len()
    }

    /// Returns the cosine similarity with another embedding.
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
        Ok(dot / (norm(&self.values) * norm(&other.values)))
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
    pub fn new(dimensions: usize) -> Result<Self, VectorError> {
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

fn tokenize(text: &str) -> Vec<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RecordId(String);

impl RecordId {
    /// Validates and creates a record identifier.
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
    fn upsert(&mut self, id: RecordId, embedding: Embedding) -> Result<(), VectorError>;

    /// Removes one embedding, reporting whether it existed.
    fn remove(&mut self, id: &RecordId) -> bool;

    /// Returns the highest-scoring records, best first.
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
    entries: BTreeMap<RecordId, Embedding>,
}

impl ExactVectorIndex {
    /// Creates an empty index of a fixed dimensionality.
    pub fn new(dimensions: usize) -> Result<Self, VectorError> {
        if dimensions == 0 {
            return Err(VectorError::EmptyEmbedding);
        }
        if dimensions > MAX_DIMENSIONS {
            return Err(VectorError::TooManyDimensions);
        }
        Ok(Self {
            dimensions,
            entries: BTreeMap::new(),
        })
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
        let mut scored: Vec<ScoredMatch> = Vec::with_capacity(self.entries.len());
        for (id, embedding) in &self.entries {
            scored.push(ScoredMatch {
                id: id.clone(),
                score: query.cosine_similarity(embedding)?,
            });
        }
        scored.sort_by(|left, right| match right.score.total_cmp(&left.score) {
            Ordering::Equal => left.id.cmp(&right.id),
            ordering => ordering,
        });
        scored.truncate(limit);
        Ok(scored)
    }

    fn len(&self) -> usize {
        self.entries.len()
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

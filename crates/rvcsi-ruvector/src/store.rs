//! The [`RfMemoryStore`] trait and its value objects.
//!
//! An RF-memory store keeps embeddings of [`CsiWindow`](rvcsi_core::CsiWindow)s
//! and [`CsiEvent`](rvcsi_core::CsiEvent)s plus per-room baseline embeddings,
//! and answers similarity / drift queries over them. This is a standin for the
//! production RuVector binding (ADR-095 FR8, D8) — see the crate docs.

use serde::{Deserialize, Serialize};

use rvcsi_core::{CsiEvent, CsiWindow, RvcsiError, SourceId};

/// Identifier minted for each stored embedding (monotonic within a store).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EmbeddingId(pub u64);

impl EmbeddingId {
    /// The raw integer value.
    #[inline]
    pub const fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for EmbeddingId {
    #[inline]
    fn from(v: u64) -> Self {
        EmbeddingId(v)
    }
}

/// Which kind of record an embedding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordKind {
    /// Embedding of a [`CsiWindow`](rvcsi_core::CsiWindow).
    Window,
    /// Embedding of a [`CsiEvent`](rvcsi_core::CsiEvent).
    Event,
}

/// One hit returned by [`RfMemoryStore::query_similar`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimilarHit {
    /// Id of the matched stored embedding.
    pub id: EmbeddingId,
    /// Cosine similarity to the query in `[-1.0, 1.0]`.
    pub score: f32,
    /// Whether the matched record was a window or an event.
    pub kind: RecordKind,
    /// Source the matched record came from.
    pub source_id: SourceId,
    /// Timestamp of the matched record (ns).
    pub timestamp_ns: u64,
}

/// Result of a baseline-drift comparison ([`RfMemoryStore::compute_drift`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftReport {
    /// Room the baseline belongs to.
    pub room: String,
    /// Baseline version that was compared against.
    pub baseline_version: String,
    /// Cosine *distance* `1 - cosine_similarity(baseline, current)` in `[0.0, 2.0]`.
    pub distance: f32,
    /// Threshold the distance was compared against.
    pub threshold: f32,
    /// Whether `distance > threshold`.
    pub exceeded: bool,
}

/// A queryable RF-memory store: append window/event embeddings, search by
/// cosine similarity, and track per-room baseline drift.
///
/// Implementations are deterministic given the same sequence of operations.
pub trait RfMemoryStore {
    /// Store the embedding of `w`, returning its newly-minted id.
    fn store_window(&mut self, w: &CsiWindow) -> Result<EmbeddingId, RvcsiError>;

    /// Store the embedding of `e`, returning its newly-minted id.
    fn store_event(&mut self, e: &CsiEvent) -> Result<EmbeddingId, RvcsiError>;

    /// Return up to `k` stored records most similar to `query`, by descending
    /// cosine similarity. Records whose embedding length differs from `query`
    /// (e.g. events vs. window queries) score `0.0` and so sort last.
    fn query_similar(&self, query: &[f32], k: usize) -> Result<Vec<SimilarHit>, RvcsiError>;

    /// Set (or replace) the baseline embedding for `room` at `version`.
    fn set_baseline(
        &mut self,
        room: &str,
        version: &str,
        embedding: Vec<f32>,
    ) -> Result<(), RvcsiError>;

    /// Compare `current` against `room`'s baseline. Returns `None` if there is
    /// no baseline for `room`, otherwise a [`DriftReport`] with
    /// `distance = 1 - cosine_similarity(baseline, current)` and
    /// `exceeded = distance > threshold`.
    fn compute_drift(
        &self,
        room: &str,
        current: &[f32],
        threshold: f32,
    ) -> Result<Option<DriftReport>, RvcsiError>;

    /// Number of stored records (windows + events; baselines are not counted).
    fn len(&self) -> usize;

    /// Whether [`RfMemoryStore::len`] is zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding_id_roundtrips() {
        let id = EmbeddingId::from(42);
        assert_eq!(id.value(), 42);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<EmbeddingId>(&json).unwrap(), id);
    }

    #[test]
    fn value_objects_serde() {
        let hit = SimilarHit {
            id: EmbeddingId(1),
            score: 0.9,
            kind: RecordKind::Window,
            source_id: SourceId::from("s"),
            timestamp_ns: 5,
        };
        let json = serde_json::to_string(&hit).unwrap();
        assert_eq!(serde_json::from_str::<SimilarHit>(&json).unwrap(), hit);

        let d = DriftReport {
            room: "lab".into(),
            baseline_version: "v1".into(),
            distance: 0.1,
            threshold: 0.2,
            exceeded: false,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<DriftReport>(&json).unwrap(), d);
    }
}

//! [`InMemoryRfMemory`] — an in-process [`RfMemoryStore`] backed by plain
//! `Vec`s. Also defines the shared [`RfIndex`] used by the file-backed store.

use std::collections::HashMap;

use rvcsi_core::{CsiEvent, CsiWindow, RvcsiError, SourceId};

use crate::embedding::{cosine_similarity, event_embedding, window_embedding};
use crate::store::{DriftReport, EmbeddingId, RecordKind, RfMemoryStore, SimilarHit};

/// One stored record inside an [`RfIndex`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct IndexRecord {
    pub(crate) id: EmbeddingId,
    pub(crate) kind: RecordKind,
    pub(crate) source_id: SourceId,
    pub(crate) timestamp_ns: u64,
    pub(crate) embedding: Vec<f32>,
}

/// The in-memory index that both [`InMemoryRfMemory`] and the file-backed store
/// build queries on top of. Holds records (with monotonic ids) and the latest
/// baseline per room.
#[derive(Debug, Default, Clone)]
pub(crate) struct RfIndex {
    records: Vec<IndexRecord>,
    /// room -> (version, embedding); the most recently set wins.
    baselines: HashMap<String, (String, Vec<f32>)>,
    next_id: u64,
}

impl RfIndex {
    pub(crate) fn new() -> Self {
        RfIndex::default()
    }

    pub(crate) fn mint_id(&mut self) -> EmbeddingId {
        let id = EmbeddingId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Insert an already-built record. The record's `id` must come from
    /// [`RfIndex::mint_id`] (or be a replay of a previously-minted id, in which
    /// case `next_id` is advanced past it so future mints stay unique).
    pub(crate) fn insert(&mut self, rec: IndexRecord) {
        if rec.id.0 >= self.next_id {
            self.next_id = rec.id.0 + 1;
        }
        self.records.push(rec);
    }

    pub(crate) fn set_baseline(&mut self, room: &str, version: &str, embedding: Vec<f32>) {
        self.baselines
            .insert(room.to_string(), (version.to_string(), embedding));
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn query_similar(&self, query: &[f32], k: usize) -> Vec<SimilarHit> {
        if k == 0 {
            return Vec::new();
        }
        let mut scored: Vec<(usize, f32)> = self
            .records
            .iter()
            .enumerate()
            .map(|(i, r)| (i, cosine_similarity(query, &r.embedding)))
            .collect();
        // Deterministic sort: by score desc, ties broken by record id asc.
        scored.sort_by(|(ia, sa), (ib, sb)| {
            sb.partial_cmp(sa)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(self.records[*ia].id.cmp(&self.records[*ib].id))
        });
        scored
            .into_iter()
            .take(k)
            .map(|(i, score)| {
                let r = &self.records[i];
                SimilarHit {
                    id: r.id,
                    score,
                    kind: r.kind,
                    source_id: r.source_id.clone(),
                    timestamp_ns: r.timestamp_ns,
                }
            })
            .collect()
    }

    pub(crate) fn compute_drift(
        &self,
        room: &str,
        current: &[f32],
        threshold: f32,
    ) -> Option<DriftReport> {
        let (version, baseline) = self.baselines.get(room)?;
        let distance = 1.0 - cosine_similarity(baseline, current);
        Some(DriftReport {
            room: room.to_string(),
            baseline_version: version.clone(),
            distance,
            threshold,
            exceeded: distance > threshold,
        })
    }
}

/// An entirely in-process [`RfMemoryStore`] — no persistence.
///
/// Useful for tests, ephemeral runs, and as the query engine behind the
/// file-backed [`crate::JsonlRfMemory`].
#[derive(Debug, Default, Clone)]
pub struct InMemoryRfMemory {
    index: RfIndex,
}

impl InMemoryRfMemory {
    /// A fresh, empty store.
    pub fn new() -> Self {
        InMemoryRfMemory {
            index: RfIndex::new(),
        }
    }
}

impl RfMemoryStore for InMemoryRfMemory {
    fn store_window(&mut self, w: &CsiWindow) -> Result<EmbeddingId, RvcsiError> {
        let id = self.index.mint_id();
        self.index.insert(IndexRecord {
            id,
            kind: RecordKind::Window,
            source_id: w.source_id.clone(),
            timestamp_ns: w.start_ns,
            embedding: window_embedding(w),
        });
        Ok(id)
    }

    fn store_event(&mut self, e: &CsiEvent) -> Result<EmbeddingId, RvcsiError> {
        let id = self.index.mint_id();
        self.index.insert(IndexRecord {
            id,
            kind: RecordKind::Event,
            source_id: e.source_id.clone(),
            timestamp_ns: e.timestamp_ns,
            embedding: event_embedding(e),
        });
        Ok(id)
    }

    fn query_similar(&self, query: &[f32], k: usize) -> Result<Vec<SimilarHit>, RvcsiError> {
        Ok(self.index.query_similar(query, k))
    }

    fn set_baseline(
        &mut self,
        room: &str,
        version: &str,
        embedding: Vec<f32>,
    ) -> Result<(), RvcsiError> {
        self.index.set_baseline(room, version, embedding);
        Ok(())
    }

    fn compute_drift(
        &self,
        room: &str,
        current: &[f32],
        threshold: f32,
    ) -> Result<Option<DriftReport>, RvcsiError> {
        Ok(self.index.compute_drift(room, current, threshold))
    }

    fn len(&self) -> usize {
        self.index.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{CsiEventKind, EventId, SessionId, SourceId, WindowId};

    fn window(id: u64, amp: f32) -> CsiWindow {
        CsiWindow {
            window_id: WindowId(id),
            session_id: SessionId(1),
            source_id: SourceId::from(format!("src-{id}").as_str()),
            start_ns: 1_000 + id,
            end_ns: 2_000 + id,
            frame_count: 10 + id as u32,
            mean_amplitude: vec![amp, amp + 1.0, amp + 2.0, amp + 3.0],
            phase_variance: vec![0.1, 0.2, 0.1, 0.05],
            motion_energy: amp / 10.0,
            presence_score: 0.5,
            quality_score: 0.9,
        }
    }

    fn event() -> CsiEvent {
        CsiEvent::new(
            EventId(0),
            CsiEventKind::PresenceStarted,
            SessionId(1),
            SourceId::from("ev"),
            9_000,
            0.8,
            vec![WindowId(1)],
        )
    }

    #[test]
    fn store_and_query_windows() {
        let mut mem = InMemoryRfMemory::new();
        let w1 = window(0, 1.0);
        let w2 = window(1, 50.0);
        let w3 = window(2, 100.0);
        let id1 = mem.store_window(&w1).unwrap();
        mem.store_window(&w2).unwrap();
        mem.store_window(&w3).unwrap();
        assert_eq!(mem.len(), 3);
        assert!(!mem.is_empty());

        let q = window_embedding(&w1);
        let hits = mem.query_similar(&q, 3).unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].id, id1);
        assert_eq!(hits[0].kind, RecordKind::Window);
        assert!((hits[0].score - 1.0).abs() < 1e-5);
        // descending
        assert!(hits[0].score >= hits[1].score);
        assert!(hits[1].score >= hits[2].score);
    }

    #[test]
    fn store_and_query_event() {
        let mut mem = InMemoryRfMemory::new();
        mem.store_window(&window(0, 1.0)).unwrap();
        let e = event();
        let eid = mem.store_event(&e).unwrap();
        let hits = mem.query_similar(&event_embedding(&e), 1).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, eid);
        assert_eq!(hits[0].kind, RecordKind::Event);
        assert!((hits[0].score - 1.0).abs() < 1e-5);
        assert_eq!(hits[0].timestamp_ns, 9_000);
    }

    #[test]
    fn baseline_drift() {
        let mut mem = InMemoryRfMemory::new();
        let base = window(0, 10.0);
        let base_emb = window_embedding(&base);
        mem.set_baseline("room1", "v1", base_emb.clone()).unwrap();

        // near-identical: tiny perturbation
        let mut near = base.clone();
        near.motion_energy += 0.001;
        let near_emb = window_embedding(&near);
        let r = mem.compute_drift("room1", &near_emb, 0.2).unwrap().unwrap();
        assert_eq!(r.room, "room1");
        assert_eq!(r.baseline_version, "v1");
        assert!(!r.exceeded, "distance was {}", r.distance);

        // very different
        let far_emb = window_embedding(&window(9, 1_000.0));
        let r2 = mem.compute_drift("room1", &far_emb, 0.001).unwrap().unwrap();
        assert!(r2.exceeded, "distance was {}", r2.distance);

        // unknown room
        assert!(mem.compute_drift("nope", &near_emb, 0.2).unwrap().is_none());
    }

    #[test]
    fn replaying_baseline_keeps_latest() {
        let mut mem = InMemoryRfMemory::new();
        mem.set_baseline("r", "v1", window_embedding(&window(0, 1.0)))
            .unwrap();
        let v2_emb = window_embedding(&window(1, 2.0));
        mem.set_baseline("r", "v2", v2_emb.clone()).unwrap();
        let r = mem.compute_drift("r", &v2_emb, 0.5).unwrap().unwrap();
        assert_eq!(r.baseline_version, "v2");
        assert!(!r.exceeded);
        assert!(r.distance < 1e-5);
    }

    #[test]
    fn deterministic_across_rebuilds() {
        let build = || {
            let mut m = InMemoryRfMemory::new();
            for i in 0..5 {
                m.store_window(&window(i, (i as f32 + 1.0) * 3.0)).unwrap();
            }
            m
        };
        let a = build();
        let b = build();
        assert_eq!(a.len(), b.len());
        let q = window_embedding(&window(2, 9.0));
        assert_eq!(a.query_similar(&q, 5).unwrap(), b.query_similar(&q, 5).unwrap());
    }

    #[test]
    fn k_zero_returns_empty() {
        let mut m = InMemoryRfMemory::new();
        m.store_window(&window(0, 1.0)).unwrap();
        assert!(m.query_similar(&window_embedding(&window(0, 1.0)), 0).unwrap().is_empty());
    }
}

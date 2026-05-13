//! [`JsonlRfMemory`] — a file-backed [`RfMemoryStore`].
//!
//! The store is a [JSONL] file: each line is one JSON object that is *either* a
//! stored record:
//!
//! ```json
//! {"record":{"id":3,"kind":"Window","source_id":"esp32","timestamp_ns":1700,"embedding":[0.1,0.2]}}
//! ```
//!
//! or a baseline write:
//!
//! ```json
//! {"baseline":{"room":"livingroom","version":"v3","embedding":[0.1,0.2]}}
//! ```
//!
//! Opening replays every line into an in-memory index identical to
//! [`crate::InMemoryRfMemory`], so queries are all in-memory; `store_*` /
//! `set_baseline` append a line (and `flush`) so a crash loses at most the
//! line currently being written. The **last** baseline line for a room wins.
//!
//! [JSONL]: https://jsonlines.org/

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use rvcsi_core::{CsiEvent, CsiWindow, RvcsiError, SourceId};

use crate::embedding::{event_embedding, window_embedding};
use crate::memory::{IndexRecord, RfIndex};
use crate::store::{DriftReport, EmbeddingId, RecordKind, RfMemoryStore, SimilarHit};

/// On-disk shape of a stored record line.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordLine {
    id: u64,
    kind: RecordKind,
    source_id: SourceId,
    timestamp_ns: u64,
    embedding: Vec<f32>,
}

/// On-disk shape of a baseline line.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaselineLine {
    room: String,
    version: String,
    embedding: Vec<f32>,
}

/// One line in the JSONL store — exactly one field is present.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreLine {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    record: Option<RecordLine>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    baseline: Option<BaselineLine>,
}

impl StoreLine {
    fn record(r: RecordLine) -> Self {
        StoreLine {
            record: Some(r),
            baseline: None,
        }
    }
    fn baseline(b: BaselineLine) -> Self {
        StoreLine {
            record: None,
            baseline: Some(b),
        }
    }
}

/// A file-backed [`RfMemoryStore`]. See the module docs for the on-disk format.
#[derive(Debug)]
pub struct JsonlRfMemory {
    path: PathBuf,
    writer: BufWriter<File>,
    index: RfIndex,
}

impl JsonlRfMemory {
    /// Create a new, empty store at `path`, truncating any existing file.
    pub fn create(path: impl AsRef<Path>) -> Result<Self, RvcsiError> {
        let path = path.as_ref().to_path_buf();
        let file = File::create(&path)?;
        Ok(JsonlRfMemory {
            path,
            writer: BufWriter::new(file),
            index: RfIndex::new(),
        })
    }

    /// Open an existing store at `path`, replaying every line into the
    /// in-memory index, then positioning for appends. The file must exist (use
    /// [`JsonlRfMemory::create`] otherwise).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RvcsiError> {
        let path = path.as_ref().to_path_buf();
        let mut index = RfIndex::new();
        {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for (i, line) in reader.lines().enumerate() {
                let line = line?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let parsed: StoreLine = serde_json::from_str(trimmed).map_err(|e| {
                    RvcsiError::parse(i + 1, format!("invalid RF-memory line {}: {e}", i + 1))
                })?;
                match (parsed.record, parsed.baseline) {
                    (Some(r), None) => index.insert(IndexRecord {
                        id: EmbeddingId(r.id),
                        kind: r.kind,
                        source_id: r.source_id,
                        timestamp_ns: r.timestamp_ns,
                        embedding: r.embedding,
                    }),
                    (None, Some(b)) => index.set_baseline(&b.room, &b.version, b.embedding),
                    _ => {
                        return Err(RvcsiError::parse(
                            i + 1,
                            format!("RF-memory line {} must have exactly one of 'record'/'baseline'", i + 1),
                        ))
                    }
                }
            }
        }
        let file = OpenOptions::new().append(true).open(&path)?;
        Ok(JsonlRfMemory {
            path,
            writer: BufWriter::new(file),
            index,
        })
    }

    /// Path the store is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flush buffered writes to disk.
    pub fn flush(&mut self) -> Result<(), RvcsiError> {
        self.writer.flush()?;
        Ok(())
    }

    fn append_line(&mut self, line: &StoreLine) -> Result<(), RvcsiError> {
        serde_json::to_writer(&mut self.writer, line)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    fn append_record(
        &mut self,
        kind: RecordKind,
        source_id: SourceId,
        timestamp_ns: u64,
        embedding: Vec<f32>,
    ) -> Result<EmbeddingId, RvcsiError> {
        let id = self.index.mint_id();
        self.append_line(&StoreLine::record(RecordLine {
            id: id.0,
            kind,
            source_id: source_id.clone(),
            timestamp_ns,
            embedding: embedding.clone(),
        }))?;
        self.index.insert(IndexRecord {
            id,
            kind,
            source_id,
            timestamp_ns,
            embedding,
        });
        Ok(id)
    }
}

impl RfMemoryStore for JsonlRfMemory {
    fn store_window(&mut self, w: &CsiWindow) -> Result<EmbeddingId, RvcsiError> {
        self.append_record(
            RecordKind::Window,
            w.source_id.clone(),
            w.start_ns,
            window_embedding(w),
        )
    }

    fn store_event(&mut self, e: &CsiEvent) -> Result<EmbeddingId, RvcsiError> {
        self.append_record(
            RecordKind::Event,
            e.source_id.clone(),
            e.timestamp_ns,
            event_embedding(e),
        )
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
        self.append_line(&StoreLine::baseline(BaselineLine {
            room: room.to_string(),
            version: version.to_string(),
            embedding: embedding.clone(),
        }))?;
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
    use crate::embedding::window_embedding;
    use rvcsi_core::{CsiEventKind, EventId, SessionId, WindowId};

    fn window(id: u64, amp: f32) -> CsiWindow {
        CsiWindow {
            window_id: WindowId(id),
            session_id: SessionId(1),
            source_id: SourceId::from(format!("src-{id}").as_str()),
            start_ns: 1_000 + id,
            end_ns: 2_000 + id,
            frame_count: 10,
            mean_amplitude: vec![amp, amp + 1.0, amp + 2.0],
            phase_variance: vec![0.1, 0.2, 0.1],
            motion_energy: amp / 5.0,
            presence_score: 0.6,
            quality_score: 0.9,
        }
    }

    fn event() -> CsiEvent {
        CsiEvent::new(
            EventId(0),
            CsiEventKind::MotionDetected,
            SessionId(1),
            SourceId::from("ev"),
            9_000,
            0.7,
            vec![WindowId(1), WindowId(2)],
        )
    }

    #[test]
    fn persist_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rf.jsonl");

        let w1 = window(0, 1.0);
        let w2 = window(1, 50.0);
        let e = event();
        let base_emb = window_embedding(&window(7, 5.0));
        {
            let mut mem = JsonlRfMemory::create(&path).unwrap();
            mem.store_window(&w1).unwrap();
            mem.store_window(&w2).unwrap();
            mem.store_event(&e).unwrap();
            mem.set_baseline("room1", "v1", base_emb.clone()).unwrap();
            mem.flush().unwrap();
        }

        let reopened = JsonlRfMemory::open(&path).unwrap();
        assert_eq!(reopened.len(), 3);
        let hits = reopened.query_similar(&window_embedding(&w1), 3).unwrap();
        assert!((hits[0].score - 1.0).abs() < 1e-5);
        let ev_hits = reopened.query_similar(&crate::embedding::event_embedding(&e), 1).unwrap();
        assert_eq!(ev_hits[0].kind, RecordKind::Event);

        // baseline persisted
        let drift = reopened.compute_drift("room1", &base_emb, 0.1).unwrap().unwrap();
        assert_eq!(drift.baseline_version, "v1");
        assert!(!drift.exceeded);
        assert!(drift.distance < 1e-5);
        assert!(reopened.compute_drift("other", &base_emb, 0.1).unwrap().is_none());
    }

    #[test]
    fn newer_baseline_wins_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rf.jsonl");
        let v1_emb = window_embedding(&window(1, 1.0));
        let v2_emb = window_embedding(&window(2, 2.0));
        {
            let mut mem = JsonlRfMemory::create(&path).unwrap();
            mem.set_baseline("r", "v1", v1_emb.clone()).unwrap();
            mem.flush().unwrap();
        }
        {
            let mut mem = JsonlRfMemory::open(&path).unwrap();
            mem.set_baseline("r", "v2", v2_emb.clone()).unwrap();
            mem.flush().unwrap();
        }
        let reopened = JsonlRfMemory::open(&path).unwrap();
        let drift = reopened.compute_drift("r", &v2_emb, 0.5).unwrap().unwrap();
        assert_eq!(drift.baseline_version, "v2");
        assert!(drift.distance < 1e-5);
        assert!(!drift.exceeded);
    }

    #[test]
    fn ids_stay_unique_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rf.jsonl");
        let (id0, id1);
        {
            let mut mem = JsonlRfMemory::create(&path).unwrap();
            id0 = mem.store_window(&window(0, 1.0)).unwrap();
            id1 = mem.store_window(&window(1, 2.0)).unwrap();
            mem.flush().unwrap();
        }
        assert_eq!(id0, EmbeddingId(0));
        assert_eq!(id1, EmbeddingId(1));
        let id2 = {
            let mut mem = JsonlRfMemory::open(&path).unwrap();
            mem.store_window(&window(2, 3.0)).unwrap()
        };
        assert_eq!(id2, EmbeddingId(2));
        assert_eq!(JsonlRfMemory::open(&path).unwrap().len(), 3);
    }

    #[test]
    fn open_missing_file_is_io_error() {
        match JsonlRfMemory::open("/no/such/rf/store.jsonl") {
            Err(RvcsiError::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn garbage_line_is_parse_error_with_line_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rf.jsonl");
        {
            let mut mem = JsonlRfMemory::create(&path).unwrap();
            mem.store_window(&window(0, 1.0)).unwrap();
            mem.flush().unwrap();
        }
        // append a garbage line manually
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{not valid}\n").unwrap();
        }
        match JsonlRfMemory::open(&path) {
            Err(RvcsiError::Parse { offset, .. }) => assert_eq!(offset, 2),
            other => panic!("expected Parse at line 2, got {other:?}"),
        }
    }

    #[test]
    fn determinism_across_rebuilds() {
        let dir = tempfile::tempdir().unwrap();
        let build = |name: &str| {
            let path = dir.path().join(name);
            let mut mem = JsonlRfMemory::create(&path).unwrap();
            for i in 0..4 {
                mem.store_window(&window(i, (i as f32 + 1.0) * 2.0)).unwrap();
            }
            mem.set_baseline("r", "v1", window_embedding(&window(0, 1.0))).unwrap();
            mem.flush().unwrap();
            JsonlRfMemory::open(&path).unwrap()
        };
        let a = build("a.jsonl");
        let b = build("b.jsonl");
        assert_eq!(a.len(), b.len());
        let q = window_embedding(&window(1, 4.0));
        assert_eq!(a.query_similar(&q, 4).unwrap(), b.query_similar(&q, 4).unwrap());
    }
}

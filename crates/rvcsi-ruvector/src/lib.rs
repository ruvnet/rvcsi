//! # rvCSI RuVector bridge
//!
//! Exports temporal RF embeddings + event metadata as a queryable RF-memory
//! store (ADR-095 FR8, D8).
//!
//! This crate is a **standin** for the production RuVector vector-database
//! binding (which gets wired in later). It provides:
//!
//! * deterministic, dependency-free embedding functions —
//!   [`window_embedding`] / [`event_embedding`] / [`cosine_similarity`];
//! * the [`RfMemoryStore`] trait plus value objects ([`EmbeddingId`],
//!   [`RecordKind`], [`SimilarHit`], [`DriftReport`]);
//! * two implementations: the in-process [`InMemoryRfMemory`] and the
//!   file-backed [`JsonlRfMemory`] (JSONL append log, identical query semantics).
//!
//! Everything here is pure and deterministic given the same sequence of
//! operations — no clocks, randomness, or order-dependent reductions — so
//! captures replayed twice yield byte-identical stores and query results.
//!
//! ```
//! use rvcsi_ruvector::{InMemoryRfMemory, RfMemoryStore, window_embedding};
//! use rvcsi_core::{CsiWindow, SessionId, SourceId, WindowId};
//!
//! let w = CsiWindow {
//!     window_id: WindowId(0),
//!     session_id: SessionId(1),
//!     source_id: SourceId::from("esp32"),
//!     start_ns: 1_000,
//!     end_ns: 2_000,
//!     frame_count: 10,
//!     mean_amplitude: vec![1.0, 2.0, 3.0],
//!     phase_variance: vec![0.1, 0.2, 0.1],
//!     motion_energy: 0.3,
//!     presence_score: 0.7,
//!     quality_score: 0.9,
//! };
//! let mut mem = InMemoryRfMemory::new();
//! let id = mem.store_window(&w).unwrap();
//! let hits = mem.query_similar(&window_embedding(&w), 1).unwrap();
//! assert_eq!(hits[0].id, id);
//! assert!((hits[0].score - 1.0).abs() < 1e-5);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod embedding;
mod jsonl;
mod memory;
mod store;

pub use embedding::{
    cosine_similarity, event_embedding, window_embedding, EVENT_EMBEDDING_DIM,
    WINDOW_EMBEDDING_DIM,
};
pub use jsonl::JsonlRfMemory;
pub use memory::InMemoryRfMemory;
pub use store::{DriftReport, EmbeddingId, RecordKind, RfMemoryStore, SimilarHit};

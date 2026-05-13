//! # rvCSI events — window aggregation + semantic event extraction (ADR-095 FR5)
//!
//! This crate turns a stream of validated [`rvcsi_core::CsiFrame`]s into
//! [`rvcsi_core::CsiWindow`]s and then into [`rvcsi_core::CsiEvent`]s.
//!
//! The pipeline has three layers:
//!
//! 1. [`WindowBuffer`] — buffers exposable frames from one
//!    `(session_id, source_id)` and emits a [`rvcsi_core::CsiWindow`] when a
//!    frame-count or duration threshold is hit. Per-subcarrier statistics
//!    (`mean_amplitude`, `phase_variance`) and the scalar `motion_energy`,
//!    `presence_score` and `quality_score` are computed here.
//! 2. [`EventDetector`] implementations — small, deterministic state machines
//!    that consume windows and emit events:
//!    [`PresenceDetector`], [`MotionDetector`], [`QualityDetector`] and
//!    [`BaselineDriftDetector`].
//! 3. [`EventPipeline`] — wires a [`WindowBuffer`] and a set of detectors
//!    together and owns an [`rvcsi_core::IdGenerator`].
//!
//! Determinism: feeding the same frame stream through an [`EventPipeline`]
//! always produces the same event list (modulo the ids, which are minted in a
//! deterministic order). All "noise" in the tests comes from a tiny LCG, never
//! from `rand`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod detectors;
mod pipeline;
mod window_buffer;

pub use detectors::{
    BaselineDriftConfig, BaselineDriftDetector, EventDetector, MotionConfig, MotionDetector,
    PresenceConfig, PresenceDetector, QualityConfig, QualityDetector,
};
pub use pipeline::EventPipeline;
pub use window_buffer::{WindowBuffer, WindowBufferConfig};

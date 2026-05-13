//! # rvCSI DSP — reusable signal-processing stages (ADR-095 FR4)
//!
//! `rvcsi-dsp` is the dependency-light DSP layer of the rvCSI edge RF sensing
//! runtime. It implements **FR4 of [ADR-095]** — *"reusable Rust
//! signal-processing stages"* — as a small library of deterministic primitives
//! plus a composable per-frame [`SignalPipeline`].
//!
//! The crate is split into three modules:
//!
//! * [`stages`] — pure per-vector DSP primitives operating on `&[f32]` /
//!   `&mut [f32]`: [`mean`](stages::mean), [`variance`](stages::variance),
//!   [`std_dev`](stages::std_dev), [`median`](stages::median),
//!   [`remove_dc_offset`](stages::remove_dc_offset),
//!   [`unwrap_phase`](stages::unwrap_phase),
//!   [`moving_average`](stages::moving_average), [`ewma`](stages::ewma),
//!   [`hampel_filter`](stages::hampel_filter) /
//!   [`hampel_filter_count`](stages::hampel_filter_count),
//!   [`short_window_variance`](stages::short_window_variance),
//!   [`subtract_baseline`](stages::subtract_baseline). Failable stages report
//!   [`DspError`](stages::DspError).
//! * [`features`] — frame/window-level scalar features:
//!   [`motion_energy`](features::motion_energy) /
//!   [`motion_energy_series`](features::motion_energy_series),
//!   [`presence_score`](features::presence_score),
//!   [`confidence_score`](features::confidence_score),
//!   [`breathing_band_estimate`](features::breathing_band_estimate) (heuristic,
//!   FFT-free, meant to be quality-gated by the caller).
//! * [`pipeline`] — the [`SignalPipeline`](pipeline::SignalPipeline): a tiny
//!   configuration bag with a non-destructive `process_frame` step that cleans a
//!   [`rvcsi_core::CsiFrame`]'s `amplitude` / `phase` vectors *after*
//!   `rvcsi_core::validate_frame` has run, never touching validation state.
//!
//! Everything here is deterministic: the same input always produces the same
//! output. There are no heavy dependencies — the math is hand-rolled.
//!
//! [ADR-095]: ../../../docs/adr/ADR-095-rvcsi-edge-rf-sensing-platform.md

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod features;
pub mod pipeline;
pub mod stages;

pub use features::{
    breathing_band_estimate, confidence_score, motion_energy, motion_energy_series, presence_score,
};
pub use pipeline::SignalPipeline;
pub use stages::{
    ewma, hampel_filter, hampel_filter_count, mean, median, moving_average, remove_dc_offset,
    short_window_variance, std_dev, subtract_baseline, unwrap_phase, variance, DspError,
};

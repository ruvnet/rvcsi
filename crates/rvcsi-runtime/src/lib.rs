//! # rvCSI runtime composition
//!
//! The glue layer that wires the leaf crates together — a [`rvcsi_core::CsiSource`]
//! → [`rvcsi_core::validate_frame`] → [`rvcsi_dsp::SignalPipeline`] →
//! [`rvcsi_events::EventPipeline`] → [`rvcsi_ruvector`] export — into a small set
//! of operations the `rvcsi` CLI and the `rvcsi-node` napi-rs addon both build
//! on (ADR-096). Pure Rust, no FFI, no Node — fully unit-tested here.
//!
//! Two entry points:
//!
//! * one-shot helpers in [`summary`] — [`summarize_capture`], [`decode_nexmon_records`],
//!   [`events_from_capture`], [`export_capture_to_rf_memory`], [`rf_memory_self_check`];
//! * the streaming [`CaptureRuntime`] in [`capture`] — `next_validated_frame` /
//!   `next_clean_frame` / `drain_events` / `health`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capture;
pub mod summary;

pub use capture::CaptureRuntime;
pub use summary::{
    decode_nexmon_pcap, decode_nexmon_pcap_for, decode_nexmon_records, events_from_capture,
    export_capture_to_rf_memory, nexmon_profile_for, rf_memory_self_check, summarize_capture,
    summarize_nexmon_pcap, CaptureSummary, NexmonPcapSummary, ValidationBreakdown,
};

/// ABI version of the linked napi-c Nexmon shim (re-exported for convenience).
pub fn nexmon_shim_abi_version() -> u32 {
    rvcsi_adapter_nexmon::shim_abi_version()
}

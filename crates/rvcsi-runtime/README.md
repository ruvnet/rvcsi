# rvcsi-runtime

[![crates.io](https://img.shields.io/crates/v/rvcsi-runtime.svg)](https://crates.io/crates/rvcsi-runtime)
[![docs.rs](https://img.shields.io/docsrs/rvcsi-runtime)](https://docs.rs/rvcsi-runtime)

The composition layer of [rvCSI](https://github.com/ruvnet/rvcsi) — no FFI of its own; the shared layer that `rvcsi-node` and `rvcsi-cli` are built on (ADR-096). This is the crate most applications want.

- **`CaptureRuntime`** — wires a `CsiSource` + `rvcsi_core::validate_frame` + `rvcsi_dsp::SignalPipeline` + `rvcsi_events::EventPipeline` into one stream: `next_validated_frame()` (validated only), `next_clean_frame()` (validated **and** DSP-cleaned), and a clean-frame iterator that also drains events.
- **One-shot helpers** for the offline path: `summarize_capture` (frame count, channels, subcarrier counts, quality, validation breakdown), `decode_nexmon_records` / `decode_nexmon_pcap` (+ `_for`, per-chip) / `summarize_nexmon_pcap`, `nexmon_profile_for`, `events_from_capture` (replay a `.rvcsi` through DSP + the detectors), `export_capture_to_rf_memory` (run it into a `rvcsi_ruvector` store).

`#![forbid(unsafe_code)]`. The pipeline is `source → validate_frame → SignalPipeline → EventPipeline → rvcsi_ruvector export`.

```toml
[dependencies]
rvcsi-runtime = "0.3"
```

Licensed under MIT OR Apache-2.0.

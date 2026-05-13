# rvcsi-events

[![crates.io](https://img.shields.io/crates/v/rvcsi-events.svg)](https://crates.io/crates/rvcsi-events)
[![docs.rs](https://img.shields.io/docsrs/rvcsi-events)](https://docs.rs/rvcsi-events)

Window aggregation and event detection for [rvCSI](https://github.com/ruvnet/rvcsi) (ADR-095 FR5).

- **`WindowBuffer`** — buffers exposable `CsiFrame`s from one `(session_id, source_id)` and emits a `CsiWindow` every N frames or T nanoseconds: per-subcarrier mean amplitude + phase variance, scalar motion energy (mean RMS amplitude delta over consecutive frames), a logistic presence score, and the mean quality. Frames with a different subcarrier count from the window's first frame are skipped (mixed legacy/HT streams aren't aggregated together).
- **`EventDetector`** trait + four state machines:
  - `PresenceDetector` — hysteresis on `presence_score` → `PresenceStarted` / `PresenceEnded`.
  - `MotionDetector` — debounced edges on `motion_energy` → `MotionDetected` / `MotionSettled`.
  - `QualityDetector` — debounced low `quality_score` → `SignalQualityDropped`, then `CalibrationRequired`.
  - `BaselineDriftDetector` — tracks an EWMA baseline of `mean_amplitude`; flags sustained drift (`BaselineChanged`) and single-window jumps (`AnomalyDetected`). Thresholds are **scale-relative** — a fraction of the baseline's RMS magnitude — so one tuning works across raw-`int8` ESP32 CSI, `int16`-scaled Nexmon CSI, and baseline-subtracted streams alike.
- **`EventPipeline`** — wires a `WindowBuffer` to a set of detectors; `process_frame(&CsiFrame) -> Vec<CsiEvent>`, `flush()` drains the tail. Owns its own `IdGenerator` so window/event ids are deterministic.

Detectors are tiny and side-effect-free; replaying the same window stream yields identical events. `#![forbid(unsafe_code)]`.

```toml
[dependencies]
rvcsi-events = "0.3"
```

Licensed under MIT OR Apache-2.0.

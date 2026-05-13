# rvcsi-dsp

[![crates.io](https://img.shields.io/crates/v/rvcsi-dsp.svg)](https://crates.io/crates/rvcsi-dsp)
[![docs.rs](https://img.shields.io/docsrs/rvcsi-dsp)](https://docs.rs/rvcsi-dsp)

The dependency-light DSP layer of [rvCSI](https://github.com/ruvnet/rvcsi) (ADR-095 FR4). Everything here is deterministic and hand-rolled — no `rustfft`, no `ndarray`.

- **`stages`** — pure per-vector primitives on `&[f32]` / `&mut [f32]`: `mean`, `variance`, `std_dev`, `median`, `remove_dc_offset`, `unwrap_phase` (1-D phase unwrap), `moving_average`, `ewma`, `hampel_filter` / `hampel_filter_count` (MAD outlier rejection), `short_window_variance`, `subtract_baseline`. Failable stages report `DspError`.
- **`features`** — frame/window-level scalar features: `motion_energy` / `motion_energy_series`, `presence_score` (logistic squash of motion energy), `confidence_score` (`mean − 0.5·std` of per-frame quality), and `breathing_band_estimate` — a heuristic, FFT-free autocorrelation respiration estimate in bpm, meant to be quality-gated by the caller (**not** a medical reading).
- **`pipeline`** — `SignalPipeline`: a small config bag with a non-destructive `process_frame` that cleans a `CsiFrame`'s `amplitude` / `phase` (Hampel → moving-average → DC removal → optional learned-baseline subtraction → phase unwrap), in a fixed order, **never** touching `validation` / `quality_score` / `quality_reasons` — DSP cleanup must not silently re-trust a frame. Also `learn_baseline` (per-subcarrier mean amplitude over a batch).

`#![forbid(unsafe_code)]`.

```toml
[dependencies]
rvcsi-dsp = "0.3"
```

Licensed under MIT OR Apache-2.0.

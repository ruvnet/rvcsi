---
description: Learn a v0 per-subcarrier baseline (mean amplitude) from a .rvcsi capture.
argument-hint: "--in <file.rvcsi> [--out baseline.json]"
---

# /rvcsi-calibrate

Learn a baseline from a (preferably quiet / empty-room) capture.

1. Run `rvcsi calibrate --in <file.rvcsi> [--out baseline.json]` (no `--out` → prints to stdout) — or `cargo run -p rvcsi-cli -- calibrate …` in a checkout.
2. It scans frames at the dominant subcarrier count and emits the element-wise mean amplitude as the baseline, with a `version` like `<source>@auto-<n>` (n = frames used), the subcarrier count, and the frame count. Versioned calibration (ADR-095 D14) means event outputs can reference exactly which baseline they ran against.
3. Use it: feed the `baseline_amplitude` array into a `SignalPipeline` (`with_baseline_amplitude(Some(vec))`) so DC is removed *per subcarrier*, not just the scalar mean — this is what makes `/rvcsi-events` behave well on real CSI (otherwise a hot DC/pilot subcarrier dominates the window vector and the drift detector over-triggers).
4. Capture hygiene: record the baseline from a *known-quiet* period (empty room, stable environment). Re-calibrate when `/rvcsi-events` emits `CalibrationRequired` or frequent `BaselineChanged`.

---
description: Replay a .rvcsi capture through the DSP + event pipeline and print the detected CsiEvents.
argument-hint: "<file.rvcsi> [--json]"
---

# /rvcsi-events

Run the rvCSI signal + event pipeline over a capture.

1. Run `rvcsi events <file.rvcsi>` (add `--json` for the full `CsiEvent` objects) — or `cargo run -p rvcsi-cli -- events <file.rvcsi>` in a checkout.
2. Under the hood: each exposable (`Accepted`/`Degraded`/`Recovered`) frame goes through `SignalPipeline::process_frame` (Hampel outlier filter → moving-average smoothing → DC removal → optional learned-baseline subtraction → phase unwrap), then into `WindowBuffer` (16 frames / 1 s windows, fixed subcarrier count per window), then the four detectors run on each closed window: presence (hysteresis on `presence_score`), motion (debounced edges on `motion_energy`), quality (`SignalQualityDropped` / `CalibrationRequired`), baseline-drift (`BaselineChanged` on sustained relative drift, `AnomalyDetected` on a single large relative jump).
3. Summarize: count events by kind, note the timeline (when presence starts/ends, motion bursts, baseline shifts), and call out any storm of one kind (often means the input has mixed subcarrier counts, no learned baseline, or genuinely high activity — suggest `/rvcsi-calibrate` then re-run with the baseline).
4. Remember: **detection ≠ decision** — these are confidence-scored evidence signals, not ground truth. Quality-gate before acting on them; the heuristic breathing-band estimate especially is not a medical reading.

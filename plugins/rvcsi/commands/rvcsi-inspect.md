---
description: Summarize a .rvcsi capture — frame count, time span, channels, subcarrier counts, mean quality, validation breakdown.
argument-hint: "<file.rvcsi> [--json]"
---

# /rvcsi-inspect

Print a one-screen summary of a `.rvcsi` capture.

1. Run `rvcsi inspect <file.rvcsi>` (add `--json` for machine-readable output) — or `cargo run -p rvcsi-cli -- inspect <file.rvcsi>` in a checkout.
2. Report: capture version, session/source ids, adapter kind, frame count, first/last timestamp + span (ns), the set of channels seen, the set of subcarrier counts seen, mean quality score, the validation breakdown (`accepted` / `degraded` / `recovered` / `rejected` / `pending`), and the calibration version if any.
3. Flag anything suspicious: many `rejected` (bad source or wrong profile), several distinct subcarrier counts (mixed legacy/HT frames — the window pipeline only aggregates consistent runs), `channel = 0` (channel detection failed at the source), low mean quality.
4. Natural next steps: `/rvcsi-events <file>` (run the detectors), `/rvcsi-calibrate --in <file>` (learn a baseline), `/rvcsi-record …` if you need to re-transcode.

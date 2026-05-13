# rvcsi — Claude Code plugin for the edge RF sensing runtime

Slash commands and an agent for working with [rvCSI](https://github.com/ruvnet/rvcsi): record/transcode WiFi CSI into validated `.rvcsi` captures, inspect & replay them, run the DSP + event pipeline (presence / motion / anomaly / baseline-drift), decode Broadcom chanspecs and list Nexmon chips, learn calibration baselines, and export to RuVector RF memory.

Part of the **`rvcsi` marketplace** — manifest at the repo root: `.claude-plugin/marketplace.json` (this plugin's `source` is `./plugins/rvcsi`).

## Install / test

```bash
# In Claude Code:
/plugin marketplace add ruvnet/rvcsi
/plugin install rvcsi@rvcsi

# Or locally from a clone:
claude --plugin-dir ./plugins/rvcsi
```

Prereq for most commands: the `rvcsi` binary on `PATH` (`cargo install rvcsi-cli`) or a checkout where `cargo run -p rvcsi-cli -- …` works.

## Commands

| Command | What it does |
|---------|--------------|
| `/rvcsi-record [--source nexmon-pcap] --in <file> --out <file.rvcsi> [--chip pi5]` | Transcode a Nexmon record dump or a `tcpdump … dst port 5500` `.pcap` into a validated `.rvcsi` capture (one `CsiFrame` JSON per line, header first). Bad frames are quarantined. |
| `/rvcsi-inspect <file.rvcsi>` | Summarize a capture — frame count, time span, channels, subcarrier counts, mean quality, validation breakdown. Add a note for `--json`. |
| `/rvcsi-events <file.rvcsi>` | Replay through `SignalPipeline` + the event detectors and print the `CsiEvent`s (presence started/ended, motion detected/settled, baseline changed, anomaly, signal-quality dropped, calibration required, breathing candidate). |
| `/rvcsi-calibrate --in <file.rvcsi> [--out baseline.json]` | Learn a v0 per-subcarrier baseline (mean amplitude) from a capture. |
| `/rvcsi-nexmon [<pcap>] [decode-chanspec <hex>] [chips]` | `inspect-nexmon <pcap>` (link type, CSI frames, channels, bandwidths, chip versions, RSSI range, time span), `decode-chanspec 0xe024` (Broadcom d11ac → channel/bandwidth/band), or `nexmon-chips` (the chip / Raspberry-Pi-model registry incl. Pi 5). |

## Agent

`rvcsi-engineer` — knows the normalized schema (`CsiFrame` → `CsiWindow` → `CsiEvent`), the `validate_frame` pipeline + quality scoring, the `CsiSource` plugin trait and `AdapterProfile`, the `.rvcsi` JSONL format, the napi-c shim contract (the rvCSI Nexmon record vs. the real nexmon_csi UDP payload, the chanspec decode), the napi-rs surface, and the ADRs (ADR-095 the 15 platform decisions, ADR-096 the crate topology / FFI seams). Use it for: adding a new `CsiSource` adapter, extending the DSP or event detectors, debugging a validation rejection, or wiring rvCSI into an app/agent.

## See also

- [`docs/adr/ADR-095-rvcsi-edge-rf-sensing-platform.md`](../../docs/adr/ADR-095-rvcsi-edge-rf-sensing-platform.md) — the 15 platform decisions
- [`docs/adr/ADR-096-rvcsi-ffi-crate-layout.md`](../../docs/adr/ADR-096-rvcsi-ffi-crate-layout.md) — crate topology, the napi-c shim contract, the napi-rs surface
- [`docs/prd/rvcsi-platform-prd.md`](../../docs/prd/rvcsi-platform-prd.md) · [`docs/ddd/rvcsi-domain-model.md`](../../docs/ddd/rvcsi-domain-model.md)

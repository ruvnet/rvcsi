# rvcsi-cli

[![crates.io](https://img.shields.io/crates/v/rvcsi-cli.svg)](https://crates.io/crates/rvcsi-cli)

The `rvcsi` command-line tool for [rvCSI](https://github.com/ruvnet/rvcsi) (ADR-095 FR7) — works against `.rvcsi` capture files and Nexmon record dumps / `.pcap` captures. (Live capture and the WebSocket stream live in the not-yet-shipped `rvcsi-daemon`.)

```bash
cargo install rvcsi-cli      # installs the `rvcsi` binary
```

| Command | What it does |
|---------|--------------|
| `rvcsi record --source nexmon\|nexmon-pcap --in <file> --out <file.rvcsi> [--chip pi5] [--port 5500]` | Transcode a Nexmon record dump or a real nexmon_csi `.pcap` (`tcpdump -i wlan0 dst port 5500 -w csi.pcap`) into a validated `.rvcsi` capture (rejected frames quarantined). |
| `rvcsi inspect <file.rvcsi> [--json]` | Summarize a capture — frame count, time span, channels, subcarrier counts, mean quality, validation breakdown. |
| `rvcsi inspect-nexmon <file.pcap> [--json] [--port <p>]` | Summarize a nexmon_csi `.pcap` — link type, CSI frames, channels, bandwidths, subcarrier counts, chip versions, RSSI range, time span. |
| `rvcsi decode-chanspec <hex\|dec> [--json]` | Decode a Broadcom d11ac chanspec word → channel / bandwidth / band. |
| `rvcsi nexmon-chips` | List the known Nexmon chips / Raspberry-Pi models (incl. Pi 5 → BCM43455c0) and their `AdapterProfile`s. |
| `rvcsi replay <file.rvcsi> [--json] [--limit N] [--speed S]` | Replay a capture, one line per frame. |
| `rvcsi stream --in <file.rvcsi> [--format json]` | Stream frames to stdout as JSON lines (a v0 stand-in for the daemon's WebSocket). |
| `rvcsi events <file.rvcsi> [--json]` | Replay through `SignalPipeline` + the event detectors and print the `CsiEvent`s. |
| `rvcsi health --source <file\|replay\|nexmon> [--target <path>]` | Open a source, drain it, print its `SourceHealth` as JSON. |
| `rvcsi calibrate --in <file.rvcsi> [--out baseline.json]` | Learn a v0 per-subcarrier baseline (mean amplitude) from a capture. |
| `rvcsi export ruvector …` | Export a capture's windows/events into an RF-memory store (JSONL). |

Licensed under MIT OR Apache-2.0.

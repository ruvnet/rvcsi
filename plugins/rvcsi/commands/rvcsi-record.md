---
description: Transcode a Nexmon record dump or a nexmon_csi .pcap into a validated .rvcsi capture (bad frames quarantined).
argument-hint: "[--source nexmon-pcap] --in <file> --out <file.rvcsi> [--chip pi5] [--port 5500]"
---

# /rvcsi-record

Turn raw Nexmon CSI into a validated, replayable `.rvcsi` capture.

1. Parse `$ARGUMENTS`. Two source modes:
   - `--source nexmon` (default): `--in` is a `.bin` of "rvCSI Nexmon records" (the napi-c shim's compact self-describing format).
   - `--source nexmon-pcap`: `--in` is a real libpcap capture, typically `tcpdump -i wlan0 dst port 5500 -w csi.pcap` on a Raspberry Pi. `--port` overrides the CSI UDP port (default 5500); `--chip pi5` (or another known chip) selects the `AdapterProfile`.
2. Run: `rvcsi record --source <mode> --in <file> --out <file.rvcsi> [--chip …] [--port …]` (or `cargo run -p rvcsi-cli -- record …` in a checkout).
3. Each frame is run through `rvcsi_core::validate_frame`; rejected frames are quarantined (dropped from the capture) — the command reports how many. The output `.rvcsi` is JSONL: line 1 is a `CaptureHeader`, every later line a `CsiFrame`.
4. Next: `/rvcsi-inspect <file.rvcsi>`, `/rvcsi-events <file.rvcsi>`, `/rvcsi-calibrate --in <file.rvcsi>`.

If there is no `.pcap` yet, tell the user how to capture one: on the Pi (with the nexmon_csi firmware patch active), `tcpdump -i wlan0 dst port 5500 -w csi.pcap`. There is **no ESP32 source crate yet** — for an ESP32 `.csi.jsonl` recording, use `scripts/esp32_jsonl_to_rvcsi.py` to produce a `.rvcsi`, then continue with the same toolchain.

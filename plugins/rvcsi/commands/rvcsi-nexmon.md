---
description: Nexmon CSI helpers — inspect a nexmon_csi .pcap, decode a Broadcom chanspec, or list the known Nexmon chips / Raspberry-Pi models.
argument-hint: "[<file.pcap>] | [decode-chanspec <hex|dec>] | [chips]"
---

# /rvcsi-nexmon

Three Nexmon-side helpers, dispatched on `$ARGUMENTS`:

- **`<file.pcap>`** → `rvcsi inspect-nexmon <file.pcap>` (add a note for `--json`, `--port <p>`): link type, CSI frame count, channels, bandwidths, subcarrier counts, chip versions, RSSI range, time span. This parses the libpcap container in pure Rust and decodes each CSI UDP payload (18-byte `magic 0x1111 · rssi · fctl · src_mac · seq · core/stream · chanspec · chip_ver` header + `nsub` `int16` I/Q samples) via the napi-c shim.
- **`decode-chanspec <hex|dec>`** → `rvcsi decode-chanspec 0xe024` — Broadcom d11ac chanspec word → `channel` (`chanspec & 0xff`), bandwidth (bits `[13:11]`, cross-checked against the FFT size), band (bits `[15:14]`, cross-checked against the channel number).
- **`chips`** (or empty) → `rvcsi nexmon-chips` — the chip / Raspberry-Pi-model registry: BCM43455c0 (Raspberry Pi 3B+ / 4 / 400 / **5**, and the standalone Pi-less BCM43455c0), 4358, 4366c0, BCM43436b0 (Pi Zero 2 W) — with the `AdapterProfile` each one builds (channels, bandwidths, subcarrier counts, capabilities).

In a checkout, prefix with `cargo run -p rvcsi-cli -- …`. To produce a `.pcap` to inspect: on a Raspberry Pi with the nexmon_csi firmware patch active, `tcpdump -i wlan0 dst port 5500 -w csi.pcap`.

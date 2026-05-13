# rvcsi-adapter-nexmon

[![crates.io](https://img.shields.io/crates/v/rvcsi-adapter-nexmon.svg)](https://crates.io/crates/rvcsi-adapter-nexmon)
[![docs.rs](https://img.shields.io/docsrs/rvcsi-adapter-nexmon)](https://docs.rs/rvcsi-adapter-nexmon)

The Nexmon CSI adapter for [rvCSI](https://github.com/ruvnet/rvcsi) — and the **napi-c** seam: the only crate in the runtime with `unsafe`, and within it `unsafe` is confined to one `ffi` module wrapping a thin C shim (ADR-095 D2/D15, ADR-096).

- **`native/rvcsi_nexmon_shim.{c,h}`** — the only C in the runtime, compiled via `build.rs` + `cc`. Allocation-free, global-free, bounds-checked against caller-supplied lengths, never panics, ABI-versioned (`0x0001_0001`). Handles two byte formats: the compact self-describing **"rvCSI Nexmon record"** (`'RVNX'` magic, version, flags, RSSI/noise, channel, bandwidth, timestamp, then `int16` I/Q in Q8.8), and the **real nexmon_csi UDP payload** (the 18-byte `magic 0x1111 · rssi int8 · fctl · src_mac · seq_cnt · core/stream · chanspec · chip_ver` header + `nsub` `int16` `(real, imag)` samples — the modern BCM43455c0 / 4358 / 4366c0 export read by CSIKit / `csireader.py`; `nsub = (len − 18) / 4`). Plus a Broadcom **d11ac chanspec decoder** (channel `= chanspec & 0xff`, bandwidth from bits `[13:11]`, band from bits `[15:14]`, cross-checked against the FFT size and channel).
- **`pcap.rs`** — a dependency-free **classic-libpcap reader** (all four byte-order / timestamp-resolution magics; Ethernet / raw-IPv4 / Linux-SLL link types; tolerates a truncated final record), plus `extract_udp_payload` and a synthetic-pcap generator for tests. The container is parsed in pure Rust — peeling Ethernet/IPv4/UDP headers is not a vendor-fragility concern.
- **`chips.rs`** — a `NexmonChip` / `RaspberryPiModel` registry (BCM43455c0 → Raspberry Pi 3B+ / 4 / 400 / **5**; 4358; 4366c0; BCM43436b0 → Pi Zero 2 W) with per-chip `AdapterProfile` builders and `chip_ver`-word auto-detection.
- **`CsiSource`s** — `NexmonAdapter` (rvCSI-record buffers) and `NexmonPcapAdapter` (reads the CSI UDP packets out of a `tcpdump -i wlan0 dst port 5500 -w csi.pcap` capture, decodes each via the C shim, stamps the frame timestamp from the pcap packet time; chip auto-detected from `chip_ver`, overridable).

The Rust `ffi` module wraps the shim in safe functions; every `unsafe` block is limited to the FFI call (and reading back C-initialised structs) and carries a `// SAFETY:` comment.

```toml
[dependencies]
rvcsi-adapter-nexmon = "0.3"
```

Building this crate needs a C toolchain (`cc` finds it). Licensed under MIT OR Apache-2.0.

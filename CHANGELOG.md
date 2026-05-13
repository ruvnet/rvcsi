# Changelog

All notable changes to rvCSI are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] — 2026-05-12

### Fixed

- **`rvcsi-adapter-nexmon`: NaN-safe encode in the napi-c shim.** The C encode
  helpers `f_to_q88` / `f_to_i16_sat` converted their `float` argument directly to
  `int16_t`, which is undefined behaviour in C when the value is NaN — a NaN reaching
  `encode_record` / `encode_nexmon_udp` (e.g. a "synthesize a payload" test path)
  would hit it. The shim's contract is "never UB": NaN now maps to `0` on encode
  (`±inf` was already saturation-handled). The decode path was unaffected. Regression
  test `encode_with_nan_iq_is_well_defined_not_ub` added (`rvcsi-adapter-nexmon`
  28 → 29 tests; 170 total, 0 failures, clippy-clean). Surfaced by a deep review of
  the FFI / `unsafe` boundary — the rest of which checked out clean (bounds-checked
  C, ABI-versioned + `debug_assert`ed, `#[repr(C)]` layouts matched, every `unsafe`
  block documented + length-checked, the pure-Rust libpcap reader guards every slice).
- All `rvcsi-*` crates bumped 0.3.0 → 0.3.1 in lockstep (workspace version);
  `^0.3` consumers pick up 0.3.1 automatically.

## [0.3.0] — 2026-05-12

First public release. rvCSI was incubated inside the
[RuView / WiFi-DensePose](https://github.com/ruvnet/RuView) project (ADR-095,
ADR-096) and is now extracted into this standalone repo; RuView consumes it back
as a `vendor/rvcsi` submodule.

### Added

- **`rvcsi-core`** — the normalized `CsiFrame` / `CsiWindow` / `CsiEvent` schema,
  `AdapterProfile`, the `CsiSource` plugin trait, id newtypes + `IdGenerator`,
  `RvcsiError`, and the `validate_frame` pipeline + quality scoring. `forbid(unsafe_code)`.
- **`rvcsi-dsp`** — pure per-vector DSP primitives (`mean`/`variance`/`median`,
  `remove_dc_offset`, `unwrap_phase`, `moving_average`, `ewma`, `hampel_filter` /
  `hampel_filter_count`, `short_window_variance`, `subtract_baseline`), scalar
  features (`motion_energy` / `motion_energy_series`, `presence_score`,
  `confidence_score`, heuristic `breathing_band_estimate`), and a non-destructive
  per-frame `SignalPipeline`. `forbid(unsafe_code)`.
- **`rvcsi-events`** — `WindowBuffer` (frames → `CsiWindow`), the `EventDetector`
  trait + presence / motion / quality / baseline-drift state machines, and
  `EventPipeline`. The baseline-drift detector uses **scale-relative** thresholds
  (drift as a fraction of the running baseline's RMS magnitude) so one tuning works
  across raw-`int8` ESP32, `int16`-scaled Nexmon, and baseline-subtracted streams.
  `forbid(unsafe_code)`.
- **`rvcsi-adapter-file`** — the `.rvcsi` capture container (JSONL: a header line
  + one `CsiFrame` per line), `FileRecorder`, `FileReplayAdapter` (deterministic
  replay). `forbid(unsafe_code)`.
- **`rvcsi-adapter-nexmon`** — the **napi-c** seam: `native/rvcsi_nexmon_shim.{c,h}`
  (the only C in the runtime — allocation-free, bounds-checked, ABI `1.1`, never
  panics) compiled via `build.rs`+`cc`, handling the rvCSI Nexmon record **and** the
  real nexmon_csi UDP payload (18-byte `magic 0x1111 · rssi · fctl · src_mac · seq ·
  core/stream · chanspec · chip_ver` header + `nsub` `int16` I/Q samples — the modern
  BCM43455c0 / 4358 / 4366c0 export read by CSIKit/`csireader.py`) with a Broadcom
  d11ac **chanspec decoder** (channel / bandwidth / band); a pure-Rust **libpcap
  reader** (classic `.pcap`, all byte-order / timestamp-resolution magics, Ethernet /
  raw-IPv4 / Linux-SLL link types); a **Nexmon-chip / Raspberry-Pi-model registry**
  (incl. **Pi 5 → BCM43455c0**, Pi 3B+/4/400, Pi Zero 2 W; `chip_ver` auto-detection);
  a documented `ffi` module (every `unsafe` block has a `// SAFETY:` comment); and two
  `CsiSource`s — `NexmonAdapter` (record buffers) and `NexmonPcapAdapter` (real
  nexmon_csi UDP inside a `tcpdump -i wlan0 dst port 5500 -w csi.pcap` capture).
- **`rvcsi-ruvector`** — the RuVector RF-memory bridge: deterministic
  `window_embedding` / `event_embedding`, `cosine_similarity`, the `RfMemoryStore`
  trait, `InMemoryRfMemory` + `JsonlRfMemory` (standins until the production RuVector
  binding lands). `forbid(unsafe_code)`.
- **`rvcsi-runtime`** — the no-FFI composition layer: `CaptureRuntime` = `CsiSource`
  + `validate_frame` + `SignalPipeline` + `EventPipeline`, plus one-shot helpers
  (`summarize_capture`, `decode_nexmon_records`, `decode_nexmon_pcap` (+ `_for`,
  per-chip), `summarize_nexmon_pcap`, `events_from_capture`, `export_capture_to_rf_memory`,
  `nexmon_profile_for`). `forbid(unsafe_code)`.
- **`rvcsi-node`** — the **napi-rs** seam: a `["cdylib","rlib"]` Node addon (`build.rs`
  runs `napi_build::setup()`) with thin `#[napi]` wrappers over `rvcsi-runtime` —
  `rvcsiVersion`, `nexmonShimAbiVersion`, `nexmonDecodeRecords`, `nexmonDecodePcap`
  (with optional `chip`), `inspectNexmonPcap`, `decodeChanspec`, `nexmonChipName`,
  `nexmonProfile`, `nexmonChips`, `inspectCaptureFile`, `eventsFromCaptureFile`,
  `exportCaptureToRfMemory`, and the `RvcsiRuntime` streaming class. Ships as the
  [`@ruv/rvcsi`](https://www.npmjs.com/package/@ruv/rvcsi) npm package. `deny(clippy::all)`.
- **`rvcsi-cli`** — the `rvcsi` binary: `record` (Nexmon-dump *or* `--source
  nexmon-pcap [--chip pi5]` → `.rvcsi`), `inspect`, `inspect-nexmon`, `nexmon-chips`,
  `decode-chanspec`, `replay`, `stream`, `events`, `health`, `calibrate`, `export ruvector`.
- **Docs** — `docs/adr/ADR-095-rvcsi-edge-rf-sensing-platform.md` (the 15 platform
  decisions), `docs/adr/ADR-096-rvcsi-ffi-crate-layout.md` (crate topology, the napi-c
  shim contract, the napi-rs surface), `docs/prd/rvcsi-platform-prd.md`,
  `docs/ddd/rvcsi-domain-model.md` (7 bounded contexts).
- **Claude plugin** — `.claude-plugin/marketplace.json` + `plugins/rvcsi/` (slash
  commands for capture/inspect/replay/events/calibrate/nexmon + an agent that knows
  the schema, validation rules, and adapter contract).
- **`scripts/esp32_jsonl_to_rvcsi.py`** — bridge for ESP32 `.csi.jsonl` recordings →
  `.rvcsi` (stand-in until `rvcsi-adapter-esp32` lands).

### Notes

- 170 tests across the rvcsi crates (core 29, dsp 28, events 19, adapter-file 20 +
  1 doctest, adapter-nexmon 29, ruvector 20 + 1 doctest, runtime 13, cli 10),
  0 failures; all crates build together and are clippy-clean.
- napi-c shim hardening (FFI-boundary review): the encode helpers (`f_to_q88` /
  `f_to_i16_sat`) now map a NaN input to `0` instead of converting NaN directly to
  an integer (which is undefined behaviour in C); the contract is "never UB". The
  decode path was unaffected. Regression test in `rvcsi-adapter-nexmon::ffi`.
- Validated end-to-end against a real 7,000-frame ESP32 CSI capture: `rvcsi inspect`
  / `replay` / `calibrate` / `events` all run on real hardware data.
- Not yet shipped: `rvcsi-adapter-esp32` (live ESP32 serial/UDP source), `rvcsi-daemon`
  (live radio capture + WebSocket), `rvcsi-mcp` (MCP tool server), the legacy nexmon
  *packed-float* CSI export.

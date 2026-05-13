# ADR-096: rvCSI — Crate Topology, the napi-c Shim, and the napi-rs Node Surface

| Field | Value |
|-------|-------|
| **Status** | Proposed |
| **Date** | 2026-05-12 |
| **Deciders** | ruv |
| **Codename** | **rvCSI** — RuVector Channel State Information runtime |
| **Relates to** | ADR-095 (rvCSI platform — D1 Rust core, D2 C-at-the-boundary, D3 TS SDK, D4 napi-rs, D5 normalized schema, D6 validate-before-FFI, D15 plugin adapters), ADR-009/ADR-040 (WASM runtimes), ADR-049 (cross-platform WiFi interface detection) |
| **PRD** | [rvCSI Platform PRD](../prd/rvcsi-platform-prd.md) |
| **Domain model** | [rvCSI Domain Model](../ddd/rvcsi-domain-model.md) |
| **Implements** | `v2/crates/rvcsi-core`, `rvcsi-dsp`, `rvcsi-events`, `rvcsi-adapter-file`, `rvcsi-adapter-nexmon`, `rvcsi-ruvector`, `rvcsi-node`, `rvcsi-cli` |

---

## 1. Context

ADR-095 set the platform-level invariant `C → Rust → TypeScript` and the fifteen decisions that constrain rvCSI. This ADR makes the *implementation* concrete: which crates exist, what each owns, where the two FFI seams are (the **napi-c** C shim below Rust, and the **napi-rs** Node addon above it), and the rules that keep `unsafe` confined and the boundary objects validated.

The two seams:

- **napi-c** — the *downward* seam to fragile vendor/firmware/driver code. Per ADR-095 D2, C is the only language allowed here, and only as a thin, allocation-free, bounds-checked shim. The Nexmon family is the first consumer.
- **napi-rs** — the *upward* seam to Node.js/TypeScript. Per ADR-095 D3/D4, the Rust runtime is exposed to JS via [napi-rs](https://napi.rs/); nothing crosses this seam that hasn't been validated (D6) and normalized (D5).

Both seams are *narrow on purpose*: everything in between — parsing, validation, DSP, windowing, event extraction, RuVector export — is safe Rust (`#![forbid(unsafe_code)]` in every crate except `rvcsi-adapter-nexmon`, which needs `extern "C"`).

---

## 2. Decision

### 2.1 Crate topology

Eight new workspace members under `v2/crates/`:

| Crate | `unsafe`? | Depends on | Owns |
|-------|-----------|------------|------|
| `rvcsi-core` | no (`forbid`) | — (serde, thiserror) | The normalized schema (`CsiFrame`/`CsiWindow`/`CsiEvent`), `AdapterProfile`, the `CsiSource` plugin trait, id newtypes + `IdGenerator`, `RvcsiError`, and the `validate_frame` pipeline + quality scoring. The shared kernel. |
| `rvcsi-dsp` | no (`forbid`) | `rvcsi-core` | Reusable DSP stages (DC removal, phase unwrap, smoothing, Hampel/MAD outlier filter, sliding variance, baseline subtraction) and scalar features (motion energy, presence score, confidence, heuristic breathing-band estimate), plus a non-destructive `SignalPipeline::process_frame`. |
| `rvcsi-events` | no (`forbid`) | `rvcsi-core` | `WindowBuffer` (frames → `CsiWindow`), the `EventDetector` trait + presence/motion/quality/baseline-drift state machines, and `EventPipeline` (windows → `CsiEvent`s). The baseline-drift detector measures drift **relative to the running baseline's RMS magnitude** (a fraction, not absolute amplitude units), so the same thresholds work for raw `int8` ESP32 CSI, `int16`-scaled Nexmon CSI, and baseline-subtracted streams alike — see ADR-095 D13. |
| `rvcsi-adapter-file` | no (`forbid`) | `rvcsi-core` | The `.rvcsi` capture format (JSONL: a header line + one `CsiFrame` per line), `FileRecorder`, and `FileReplayAdapter` (a `CsiSource`) — deterministic replay (D9). |
| `rvcsi-adapter-nexmon` | **yes** (FFI only) | `rvcsi-core` + the C shim | The **napi-c** seam: `native/rvcsi_nexmon_shim.{c,h}` compiled via `build.rs`+`cc`, a documented `ffi` module wrapping it, a pure-Rust libpcap reader (`pcap.rs`), the Nexmon-chip / Raspberry-Pi-model registry (`chips.rs` — `NexmonChip`, `RaspberryPiModel` incl. **Pi 5**, profile builders), and two `CsiSource`s — `NexmonAdapter` (rvCSI-record buffers) and `NexmonPcapAdapter` (real nexmon_csi UDP payloads inside a `.pcap`, with chip auto-detection). |
| `rvcsi-ruvector` | no (`forbid`) | `rvcsi-core` | The RuVector RF-memory bridge: deterministic `window_embedding`/`event_embedding`, `cosine_similarity`, the `RfMemoryStore` trait, and `InMemoryRfMemory` + `JsonlRfMemory` (a standin until the production RuVector binding lands). |
| `rvcsi-runtime` | no (`forbid`) | core, dsp, events, adapter-file, adapter-nexmon, ruvector | The composition layer (no FFI): `CaptureRuntime` (a `CsiSource` + `validate_frame` + `SignalPipeline` + `EventPipeline`) plus one-shot helpers (`summarize_capture`, `decode_nexmon_records`, `decode_nexmon_pcap`, `summarize_nexmon_pcap`, `events_from_capture`, `export_capture_to_rf_memory`). The shared layer under `rvcsi-node` and `rvcsi-cli`. |
| `rvcsi-node` | no (`deny(clippy::all)`) | `rvcsi-core`, `rvcsi-runtime`, `rvcsi-adapter-nexmon` | The **napi-rs** seam: the `.node` addon (cdylib + rlib) exposing a safe TS-facing surface (thin `#[napi]` wrappers over `rvcsi-runtime`); `build.rs` runs `napi_build::setup()`. |
| `rvcsi-cli` | no | core, adapter-file, adapter-nexmon, runtime | The `rvcsi` binary: `record` (Nexmon-dump or nexmon-pcap → `.rvcsi`), `inspect`, `inspect-nexmon`, `decode-chanspec`, `replay`, `stream`, `events`, `health`, `calibrate`, `export ruvector` (ADR-095 FR7). |

`rvcsi-events` does **not** call into `rvcsi-dsp`: window statistics are simple enough to compute in `WindowBuffer` itself, and keeping the two leaves independent removes a coordination point. `rvcsi-cli` does **not** depend on `rvcsi-node` (a binary can't link a napi cdylib's undefined Node symbols) — the shared logic lives in `rvcsi-runtime`, which both build on. Higher layers wire `SignalPipeline::process_frame` → `WindowBuffer::push` when they want cleaned frames.

The MCP tool server (`rvcsi-mcp`) and the long-running daemon (`rvcsi-daemon`) — and live radio capture — are *not* in this ADR's scope; they sit on top of `rvcsi-runtime` / the crates above and are tracked as follow-ups. The `@ruv/rvcsi` npm package ships alongside `rvcsi-node`.

### 2.2 The napi-c shim — record formats and contract

`native/rvcsi_nexmon_shim.{c,h}` is the only C in the runtime. It handles **two byte formats** (ABI `1.1`):

**(1) The "rvCSI Nexmon record"** — a compact, self-describing record (`'RVNX'` magic, version, flags, RSSI/noise, channel, bandwidth, timestamp, then interleaved `int16` I/Q in Q8.8 fixed point; total `24 + 4*N`). Used by the `rvcsi capture`/`record` recorder, the file replay path, and tests. Functions: `rvcsi_nx_record_len`, `rvcsi_nx_parse_record`, `rvcsi_nx_write_record`.

**(2) The *real* nexmon_csi UDP payload** — what the patched Broadcom firmware actually sends to the host (port 5500 by default): the 18-byte header `magic=0x1111 (2) · rssi int8 (1) · fctl (1) · src_mac (6) · seq_cnt (2) · core/stream (2) · chanspec (2) · chip_ver (2)`, followed by `nsub` complex CSI samples. The shim implements the **modern int16 I/Q export** (`nsub` pairs of little-endian `int16` `(real, imag)`, raw counts — what CSIKit / `csireader.py` read for the BCM43455c0 / 4358 / 4366c0); `nsub` is derived from the payload length, `(len − 18) / 4`. Functions: `rvcsi_nx_csi_udp_header` (just the 18-byte header), `rvcsi_nx_csi_udp_decode` (header + CSI body, `csi_format` selector), `rvcsi_nx_csi_udp_write` (synthesize a payload — tests/examples), and `rvcsi_nx_decode_chanspec` (decode a Broadcom d11ac chanspec word → `channel` = `chanspec & 0xff`, bandwidth from bits `[13:11]` cross-checked against the FFT size, band from bits `[15:14]` cross-checked against the channel number). The legacy nexmon *packed-float* export used by some 4339/4358 firmwares is a documented follow-up (it sits behind the same `csi_format` selector).

The `timestamp_ns` of a frame from format (2) comes from the **pcap packet timestamp**, not the wire (nexmon_csi doesn't carry one). The pcap file itself is parsed in **pure Rust** (`rvcsi-adapter-nexmon::pcap` — classic libpcap, all four byte-order/timestamp-resolution magics, Ethernet / raw-IPv4 / Linux-SLL link types; pcapng is a follow-up): peeling the Ethernet/IPv4/UDP headers down to the payload is not a vendor-fragility concern, so it doesn't belong in C.

Contract (both formats):

- **Allocation-free, global-free.** Every read is bounds-checked against the caller-supplied length; nothing can scribble outside caller buffers; no `malloc`, no statics.
- **Structured errors, never panics.** Functions return one of a small set of `RvcsiNxError` codes (`TOO_SHORT`, `BAD_MAGIC`, `BAD_VERSION`, `CAPACITY`, `TRUNCATED`, `ZERO_SUBCARRIERS`, `TOO_MANY_SUBCARRIERS`, `NULL_ARG`, `BAD_NEXMON_MAGIC`, `BAD_CSI_LEN`, `UNKNOWN_FORMAT`); `rvcsi_nx_strerror` maps each to a static string.
- **ABI versioned.** `rvcsi_nx_abi_version()` returns `major << 16 | minor` (`0x0001_0001`); the Rust side `debug_assert`s the major matches the header it was compiled against. The minor was bumped from `1.0` → `1.1` when the format-(2) entry points landed (additive — format (1) is unchanged).
- The Rust `ffi` module wraps these in safe functions (`record_len`, `decode_record`, `encode_record`, `decode_chanspec`, `parse_nexmon_udp_header`, `decode_nexmon_udp`, `encode_nexmon_udp`, `shim_abi_version`); every `unsafe` block is limited to the FFI call (and reading back C-initialised structs) and carries a `// SAFETY:` comment, per the project rule.

**Chip registry (`rvcsi-adapter-nexmon::chips`).** nexmon_csi runs on a handful of patched Broadcom/Cypress chips; `NexmonChip` names them, `RaspberryPiModel` maps Pi boards to their chip, and `nexmon_adapter_profile` / `raspberry_pi_profile` build the [`AdapterProfile`] (supported channels / bandwidths / expected subcarrier counts — 20→64, 40→128, 80→256, 160→512) `validate_frame` bounds CSI frames against. The **Raspberry Pi 5** carries the same **CYW43455 / BCM43455c0** 802.11ac wireless as the Pi 3B+ / Pi 4 / Pi 400 (20/40/80 MHz, 2.4 + 5 GHz) — the chip with the most mature nexmon_csi support — so `RaspberryPiModel::Pi5 → NexmonChip::Bcm43455c0`; the Pi Zero 2 W is `Bcm43436b0` (2.4 GHz, ≤40 MHz). `NexmonPcapAdapter` **auto-detects** the chip from each packet's `chip_ver` word (`0x4345` → `Bcm43455c0`, etc.) and uses the matching profile; `.with_chip(...)` / `.with_pi_model(...)` override it. `NexmonChip::from_chip_ver` and the `chip_ver` field are best-effort/preserved respectively — the c0/b0 revision suffix isn't carried by that word, and the int16-vs-packed-float export distinction is handled by the `csi_format` selector, not by chip-ver parsing.

A real deployment captures with `tcpdump -i wlan0 dst port 5500 -w csi.pcap` on the Pi and feeds the `.pcap` to `NexmonPcapAdapter::open` (or `rvcsi record --source nexmon-pcap --in csi.pcap --out cap.rvcsi --chip pi5`, then the rest of the toolchain works on the `.rvcsi`; `rvcsi inspect-nexmon` reports the resolved chip, `rvcsi nexmon-chips` lists the matrix). Production *live* capture (binding the UDP socket, monitor mode, firmware patch hooks) is a later increment that reuses the same shim parse path — the shim's job is the *parse*, not the *socket*.

### 2.3 The napi-rs surface — what crosses the seam

`rvcsi-node` is a `["cdylib", "rlib"]` crate (cdylib = the `.node` addon; rlib so `cargo test --workspace` can link and test the Rust side without Node). Rules:

- **Only normalized/validated data crosses.** The boundary types are JS-friendly mirrors of `CsiFrame`/`CsiWindow`/`CsiEvent`/`AdapterProfile`/`SourceHealth`, or plain JSON strings — never raw pointers, never `Pending` frames. A frame is run through `rvcsi_core::validate_frame` before it is handed to JS.
- **Errors map to JS exceptions** via napi-rs's `Result` integration; `RvcsiError`'s `Display` is the message.
- **The build emits link args + `binding.js`/`binding.d.ts`** via `napi_build::setup()` in `build.rs`; the `@ruv/rvcsi` npm package's hand-written `index.js`/`index.d.ts` wrap that loader and `JSON.parse` the addon's returns into plain `CsiFrame`/`CsiWindow`/`CsiEvent`/`SourceHealth`/`CaptureSummary`/`NexmonPcapSummary`/`DecodedChanspec` objects.
- The free functions exposed are: `rvcsiVersion`, `nexmonShimAbiVersion` (the linked shim's ABI), `nexmonDecodeRecords`, `nexmonDecodePcap`, `inspectNexmonPcap`, `decodeChanspec`, `inspectCaptureFile`, `eventsFromCaptureFile`, `exportCaptureToRfMemory`; plus the `RvcsiRuntime` streaming class (`openCaptureFile` / `openNexmonFile` / `openNexmonPcap` factories + `nextFrameJson` / `nextCleanFrameJson` / `drainEventsJson` / `healthJson`).

### 2.4 Build & test invariants

- `cargo build --workspace` and `cargo test --workspace --no-default-features` (the repo's pre-merge gate) must stay green; the new crates add tests and don't regress the existing 1,031+.
- `rvcsi-node` stays a workspace *member* (not `exclude`d like `wifi-densepose-wasm-edge`): on Linux/macOS a napi cdylib links fine with Node symbols left undefined (resolved at addon-load time), so `cargo build`/`cargo test` work without a Node toolchain. Only `napi build` (npm packaging) needs Node.
- No new heavy dependencies in the rvCSI crates: `serde`, `serde_json`, `thiserror`, `cc` (build only), `napi`/`napi-derive`/`napi-build`, `clap` (CLI only), `tempfile` (dev only). DSP math is hand-rolled — no `ndarray`/`rustfft`.

---

## 3. Consequences

**Positive**

- The two FFI seams are small, audited, and independently testable: the C shim round-trips through Rust tests; the napi surface tests run under `cargo test` without Node.
- `unsafe` is confined to one crate (`rvcsi-adapter-nexmon`) and within it to one module (`ffi`), every block documented.
- Each leaf crate (`rvcsi-dsp`, `rvcsi-events`, `rvcsi-adapter-file`, `rvcsi-ruvector`) depends only on `rvcsi-core`, so they can evolve (and be reviewed, and be swarm-implemented) independently.
- The `.rvcsi` JSONL capture format and the `JsonlRfMemory` standin make the whole pipeline runnable and testable end-to-end before any hardware or the real RuVector binding exists.

**Negative / costs**

- A `cc`-built C library means a C toolchain is required to build `rvcsi-adapter-nexmon` (already true for many workspace crates via transitive `cc` deps; acceptable).
- The "rvCSI Nexmon record" is a *normalized* format, not byte-identical to any upstream nexmon_csi build — a thin demux/transcode step is needed when wiring real Nexmon output. This is intentional (we control the contract the shim parses) and documented.
- JSONL captures are larger than a packed binary format; fine for v0 (and the PRD already standardizes on JSON/WebSocket on the wire), revisit if capture size becomes a problem.
- `rvcsi-node` as a workspace member adds the `napi` dependency tree to `cargo build --workspace`; mitigated by it being a small, well-maintained crate.

**Risks**

- napi-rs major-version churn could change the macro/`build.rs` surface; pinned to `napi = "2.16"` in workspace deps, bumped deliberately.
- If a future platform can't link a napi cdylib under plain `cargo build`, `rvcsi-node` moves to the workspace `exclude` list (like `wifi-densepose-wasm-edge`) with a separate build command — same pattern, already established.

---

## 4. Alternatives considered

| Alternative | Why not |
|-------------|---------|
| One mega-crate `rvcsi` instead of eight | Couples DSP/events/adapters/FFI; can't review or implement them independently; bloats compile units for downstream users who only want `rvcsi-core`. |
| `bindgen` for the C shim | Pulls in `libclang`; the shim's C API is six functions — hand-written `extern "C"` decls are clearer and dependency-free. |
| Binary `.rvcsi` capture format (bincode/custom) | Smaller, but not human-inspectable; JSONL is debuggable, append-friendly, and matches the PRD's on-the-wire JSON. Revisit if size matters. |
| Expose raw `CsiFrame` pointers / typed arrays across napi for zero-copy | Violates ADR-095 D6 (validate-before-FFI) and the "no raw pointers to TS" safety NFR; the per-frame copy cost is negligible at the target rates. |
| `wasm-bindgen` instead of napi-rs for the JS surface | WASM can't do live capture (no raw sockets/serial); great for offline parsing (a later target) but not the primary Node runtime. |
| `rvcsi-events` depending on `rvcsi-dsp` for window stats | Adds a coordination point for two leaf crates; the stats are a few lines — keep the leaves independent and let higher layers compose them. |

---

## 5. Status of the implementation

- `rvcsi-core` — implemented, `forbid(unsafe_code)`, 29 unit tests.
- `rvcsi-adapter-nexmon` + the napi-c shim — implemented; C (ABI `1.1`) compiled via `build.rs`+`cc`; the `ffi` module wraps both record formats (rvCSI record **and** the real nexmon_csi UDP payload + chanspec decode); a pure-Rust `pcap` reader; the Nexmon-chip / Raspberry-Pi-model registry (`chips.rs` — incl. **Pi 5 → BCM43455c0** + chip auto-detection from `chip_ver`); `NexmonAdapter` + `NexmonPcapAdapter` `CsiSource`s; 28 tests, several round-tripping through the C shim and through synthetic libpcap files.
- `rvcsi-dsp` (28 tests), `rvcsi-events` (19 tests — incl. a scale-invariance regression for the baseline-drift detector), `rvcsi-adapter-file` (20 + 1 doctest), `rvcsi-ruvector` (20 + 1 doctest) — implemented.
- `rvcsi-runtime` (13 tests) — composition layer + the one-shot helpers, including `decode_nexmon_pcap` / `decode_nexmon_pcap_for` (per-chip) / `summarize_nexmon_pcap` / `nexmon_profile_for`.
- `rvcsi-node` (napi-rs surface — incl. `nexmonDecodePcap` (with `chip`) / `inspectNexmonPcap` / `decodeChanspec` / `nexmonChipName` / `nexmonProfile` / `nexmonChips` / `RvcsiRuntime.openNexmonPcap`) and `rvcsi-cli` (10 tests — incl. `record --source nexmon-pcap [--chip pi5]`, `inspect-nexmon`, `nexmon-chips`, `decode-chanspec`) — implemented; the `@ruv/rvcsi` npm package + a Node smoke test ship alongside.
- Totals: 169 rvcsi unit/integration tests + 2 doctests, 0 failures; all rvcsi crates build together and are clippy-clean.
- **Validated against real ESP32 CSI** (a 7,000-frame node-1 capture, transcoded to `.rvcsi` via `scripts/esp32_jsonl_to_rvcsi.py` — the stand-in for the not-yet-shipped `record --source esp32-jsonl`): `rvcsi inspect` / `replay` / `calibrate` / `events` all run end-to-end. This surfaced and fixed the baseline-drift over-trigger (absolute → relative thresholds, above).
- `rvcsi-adapter-esp32` (live serial/UDP ESP32 source — ADR-095 §1.2 / D15), `rvcsi-mcp` (MCP tool server), `rvcsi-daemon` (live capture + WebSocket), and the legacy nexmon *packed-float* CSI export — not in this PR; tracked as follow-ups.

---

## 6. References

- [ADR-095 — rvCSI Edge RF Sensing Platform](ADR-095-rvcsi-edge-rf-sensing-platform.md)
- [rvCSI Platform PRD](../prd/rvcsi-platform-prd.md)
- [rvCSI Domain Model](../ddd/rvcsi-domain-model.md)
- napi-rs — https://napi.rs/
- nexmon_csi — the upstream Broadcom CSI extractor the record format normalizes

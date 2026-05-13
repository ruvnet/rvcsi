# rvCSI — Edge RF Sensing Runtime

## Product Design Requirements (PRD)

| Field | Value |
|-------|-------|
| **Product name** | rvCSI |
| **Category** | Edge RF sensing runtime and developer platform |
| **Status** | Proposed (v0 design) |
| **Date** | 2026-05-12 |
| **Owner** | ruv |
| **Relates to** | [ADR-095](../adr/ADR-095-rvcsi-edge-rf-sensing-platform.md) (rvCSI platform), [ADR-012](../adr/ADR-012-esp32-csi-sensor-mesh.md) (ESP32 mesh), [ADR-013](../adr/ADR-013-feature-level-sensing-commodity-gear.md) (feature-level sensing), [ADR-014](../adr/ADR-014-sota-signal-processing.md) (SOTA signal processing), [ADR-016](../adr/ADR-016-ruvector-integration.md) (RuVector integration), [ADR-024](../adr/ADR-024-contrastive-csi-embedding-model.md) (AETHER embeddings), [ADR-031](../adr/ADR-031-ruview-sensing-first-rf-mode.md) (RuView sensing-first RF mode), [ADR-040](../adr/ADR-040-wasm-programmable-sensing.md) (WASM programmable sensing) |
| **Domain model** | [rvCSI Domain Model](../ddd/rvcsi-domain-model.md) |

---

## 1. Purpose

rvCSI is a **Rust-first, TypeScript-accessible, hardware-abstracted Channel State Information (CSI) platform** for WiFi-based spatial sensing.

The goal is to convert CSI from fragile research data into a durable edge sensing runtime that can feed RuView, RuVector, Cognitum, and agentic systems with validated live radio-field observations.

rvCSI does **not** try to replace Nexmon on day one. It wraps, validates, normalizes, streams, embeds, and learns from CSI produced by Nexmon, ESP32 CSI, Intel CSI, Atheros CSI, SDR pipelines, and future RF sensor sources.

### 1.1 System framing

CSI is treated as a **physical-world delta stream**.

A room, hallway, vehicle, warehouse, machine bay, or care facility has a radio-field baseline. Human motion, breathing, door movement, equipment vibration, device movement, and environmental change perturb that baseline. rvCSI captures those perturbations, normalizes them into tensors, converts them into events, stores them as temporal memory, and exposes them to agents.

The core invariant:

| Layer | Owns |
|-------|------|
| **C** | Fragile vendor and firmware compatibility |
| **Rust** | Safety, validation, signal processing, memory discipline, deterministic runtime behavior |
| **TypeScript** | Developer experience, orchestration, dashboards, SDKs, agent integration |
| **RuVector** | Memory, similarity, drift, graph relationships, coherence over time |
| **Cognitum** | Low-power event-driven deployment, local decision loops |

### 1.2 Strategic framing

Most CSI projects today are Linux shell scripts, kernel patching, Python notebooks, PCAP dumps, and ad-hoc signal processing. A Rust + TypeScript + napi-rs architecture turns CSI into **real-time sensor infrastructure**: npm-installable, reproducible, typed, safe-parsed, embeddable, WebSocket-streamable, WASM-portable, MCP-exposed, agent-integrable, and edge/cloud-federated.

The right framing is **structural sensing**, not "magic X-ray vision". CSI is excellent for detecting change, presence, and learned patterns; it is weak for exact identity, exact pose, legal/security certainty, and highly dynamic RF spaces. rvCSI's product claims stay inside that boundary (see Non-goals, §6).

---

## 2. Users

| User | Need |
|------|------|
| AI engineers building physical-world agents | A stable sensing primitive that emits typed events agents can react to |
| Researchers working with WiFi CSI and RF sensing | Reproducible ingestion, replay, and benchmark datasets |
| Smart-building and elder-care solution builders | Privacy-preserving presence/motion/breathing without cameras |
| Industrial monitoring teams | Camera-free movement/anomaly detection that runs unattended |
| Developers using RuView / RuVector / Cognitum | A drop-in source of RF observations for the broader ruvnet stack |

---

## 3. Problem & Hypothesis

**Problem.** WiFi CSI is useful but hard to operationalize. Most CSI pipelines are built from fragile scripts, patched firmware, lab notebooks, inconsistent packet formats, unstable drivers, and device-specific assumptions. This makes CSI difficult to deploy outside research settings. The system needs a production-grade runtime that can ingest CSI from multiple sources, validate packets, normalize formats, stream typed events, support signal processing, and feed vector-based learning systems.

**Hypothesis.** If rvCSI provides a stable Rust core with TypeScript APIs and hardware adapters, then CSI can become a reusable sensing primitive for camera-free spatial intelligence.

---

## 4. Success criteria

1. A developer can install rvCSI and parse recorded CSI files in **under five minutes**.
2. A supported live device can stream **validated** CSI frames into TypeScript.
3. Bad packets **cannot crash** the process.
4. The same application code consumes CSI from Nexmon, ESP32, Intel, or Atheros adapters.
5. Presence and motion detection work from **normalized tensors**, not device-specific raw packets.
6. rvCSI can publish embeddings and event summaries into **RuVector**.
7. rvCSI can run as a **local daemon on Raspberry Pi-class hardware**.
8. rvCSI can expose events to **MCP tools and local agents**.

---

## 5. Scope

### 5.1 Version zero — safe ingestion, normalized data, live streaming, SDK usability, RuVector integration

1. Recorded CSI file parser
2. Live capture adapter for existing Nexmon CSI output where supported
3. ESP32 CSI adapter
4. Unified CSI frame schema
5. Rust validation pipeline
6. TypeScript SDK through napi-rs
7. CLI for capture, inspect, replay, stream
8. WebSocket output
9. Presence and motion baseline detectors
10. RuVector export interface
11. Basic calibration model
12. Hardware and driver health checks

### 5.2 Version one

1. Multi-node synchronization
2. RF room signatures
3. Breathing-rate estimation where signal quality permits
4. Temporal embeddings
5. Drift detection
6. Graph-based room topology
7. Local MCP tool server
8. Replayable benchmark datasets
9. Sensor fusion with RuView
10. Deployment profile for Cognitum Seed and Appliance

### 5.3 Version two

1. Hardware-agnostic RF sensor fabric
2. Multi-room RF memory
3. Streaming anomaly detection
4. RF SLAM research mode
5. On-device embedding model
6. Federated learning of room signatures
7. Secure signed sensor-evidence records
8. Proof-gated event publication
9. Dynamic cut-based coherence over RF graphs
10. Agent-driven calibration and self-repair

---

## 6. Non-goals (version zero)

1. Pure-Rust replacement for Broadcom firmware patches
2. Universal support for all WiFi chips
3. Identity recognition from RF signals
4. Medical-grade vital-sign diagnosis
5. Legal-grade occupancy proof
6. Guaranteed through-wall pose detection
7. Cloud dependency
8. Camera-replacement claims

---

## 7. Functional requirements

### FR1 — CSI ingestion

rvCSI shall ingest CSI from multiple sources. Initial source types: recorded binary dump, PCAP file, Nexmon CSI live stream, ESP32 CSI serial/UDP stream, Intel CSI logs (where supported), Atheros CSI logs (where supported). **Output:** a normalized `CsiFrame` object.

### FR2 — Packet validation

rvCSI shall validate every frame before exposing it to TypeScript or RuVector:

1. Frame length must match declared schema.
2. Subcarrier count must be inside adapter-profile limits.
3. Timestamp must be monotonic within a capture session unless marked as recovered.
4. RSSI must be within plausible device bounds.
5. Complex values must be finite.
6. Corrupt frames must be rejected or quarantined.
7. Parser failures must return structured errors.

### FR3 — Normalized frame schema

rvCSI shall normalize all hardware output into a common schema. Required fields: `frame_id`, `session_id`, `source_id`, `adapter_kind`, `timestamp_ns`, `channel`, `bandwidth_mhz`, `rssi_dbm`, `noise_floor_dbm` (when available), `antenna_index` (when available), `tx_chain` (when available), `rx_chain` (when available), `subcarrier_count`, `i_values`, `q_values`, `amplitude`, `phase`, `validation_status`, `quality_score`, `calibration_version`.

### FR4 — Signal processing

rvCSI shall provide reusable Rust signal-processing stages: DC offset removal, phase unwrap, amplitude smoothing, Hampel/median outlier filter, short-window variance, baseline subtraction, motion energy, presence score, breathing-band estimator (where supported), confidence scoring.

### FR5 — Event extraction

rvCSI shall convert frame streams into typed events: `PresenceStarted`, `PresenceEnded`, `MotionDetected`, `MotionSettled`, `BaselineChanged`, `SignalQualityDropped`, `DeviceDisconnected`, `BreathingCandidate`, `AnomalyDetected`, `CalibrationRequired`.

### FR6 — TypeScript SDK

rvCSI shall expose a TypeScript SDK:

```ts
import { RvCsi } from "@ruv/rvcsi";

const sensor = await RvCsi.open({
  source: "nexmon",
  iface: "wlan0",
  channel: 6,
  bandwidthMHz: 20,
});

sensor.on("frame", (frame) => {
  console.log(frame.qualityScore);
});

sensor.on("presence", (event) => {
  console.log(event.confidence);
});

await sensor.start();
```

### FR7 — CLI

```bash
rvcsi inspect file sample.csi
rvcsi capture start --source nexmon --iface wlan0 --channel 6
rvcsi replay sample.csi --speed 1x
rvcsi stream --format json --port 8787
rvcsi calibrate --room livingroom --duration 60
rvcsi health --source nexmon
rvcsi export ruvector --collection room_rf
```

### FR8 — RuVector integration

rvCSI shall export temporal RF embeddings and event metadata to RuVector. Data stored: frame embeddings, window embeddings, room baseline vectors, event vectors, drift snapshots, sensor-topology graph edges, source health records.

### FR9 — MCP integration

rvCSI shall expose MCP tools for local agents: `rvcsi_status`, `rvcsi_list_sources`, `rvcsi_start_capture`, `rvcsi_stop_capture`, `rvcsi_get_presence`, `rvcsi_get_recent_events`, `rvcsi_calibrate_room`, `rvcsi_export_window`, `rvcsi_query_ruvector`, `rvcsi_health_report`. Tools default to read actions; capture start/stop, calibration, and export are write-gated.

### FR10 — Replay and audit

rvCSI shall support deterministic replay of captured sessions, preserving: original timestamps, frame ordering, validation decisions, event-extraction output, calibration version, runtime configuration.

---

## 8. Non-functional requirements

### 8.1 Safety

1. TypeScript shall never receive raw unchecked pointers.
2. Rust shall validate all frames before the FFI boundary export.
3. C shims shall be minimal and isolated.
4. All `unsafe` blocks shall be documented.
5. Fuzz tests shall cover parsers.

### 8.2 Performance (v0 targets)

1. Parse one CSI frame in **< 1 ms** on Raspberry Pi 5.
2. Sustain **≥ 1000 frames/s** on Pi 5 for normalized parsing.
3. Keep memory **< 256 MB** for one active source.
4. Keep event latency **< 50 ms** for presence and motion.
5. Avoid heap growth during steady capture.

### 8.3 Reliability

1. Bad packets shall not crash the daemon.
2. Device disconnect shall produce a typed event.
3. Capture sessions shall be restartable.
4. Logs shall include source, adapter, session, and validation details.
5. Health checks shall identify unsupported firmware or driver state.

### 8.4 Privacy

1. rvCSI shall operate locally by default.
2. No cloud endpoint shall be required.
3. Raw CSI export shall be disableable by policy.
4. Event-level export shall be supported for privacy-preserving deployments.
5. Retention policies shall be configurable.

### 8.5 Security

1. Device-control operations shall require explicit permission.
2. Firmware-installation operations shall be separated from capture operations.
3. Signed capture profiles shall be supported in later versions.
4. MCP tools shall mark write actions as gated.
5. File parsing shall be fuzzed and sandbox-friendly.

### 8.6 Portability

1. Linux first.
2. Raspberry Pi first among edge devices.
3. macOS and Windows support for file replay and SDK development.
4. Live-capture support depends on adapter and driver capability.
5. WASM support for offline parsing and visualization is a later target.

---

## 9. System architecture

### 9.1 High-level pipeline

```
CSI Source
  ↓
Adapter Layer            (vendor-specific decode, C shims isolated here)
  ↓
Rust Validation Pipeline (bounds, finiteness, monotonicity, quarantine)
  ↓
Normalized CSI Frame     (CsiFrame schema — the FFI-safe boundary object)
  ↓
Signal Processing        (DC removal, phase unwrap, smoothing, motion energy …)
  ↓
Window Aggregator        (bounded frame sequences → CsiWindow)
  ↓
Event Extractor          (state machines → CsiEvent with confidence + evidence)
  ↓
TypeScript SDK · CLI · MCP · RuVector
```

### 9.2 Runtime components

| # | Component | Role |
|---|-----------|------|
| 1 | `rvcsi-core` | Frame types, parser traits, validation, quality scoring, shared abstractions |
| 2 | `rvcsi-adapter-*` | Rust/C-backed adapters: Nexmon, ESP32, Intel, Atheros, files, replay |
| 3 | `rvcsi-dsp` | Rust signal-processing primitives |
| 4 | `rvcsi-events` | Windowing, baseline modeling, event extraction, state machines |
| 5 | `rvcsi-node` | napi-rs bindings exposing safe APIs to Node.js |
| 6 | `rvcsi-sdk` | TypeScript SDK |
| 7 | `rvcsi-cli` | Command-line interface |
| 8 | `rvcsi-daemon` | Long-running capture and event service |
| 9 | `rvcsi-mcp` | MCP tool server |
| 10 | `rvcsi-ruvector` | Exporter and query bridge |

### 9.3 Reference repository layout

```
rvcsi/
  crates/
    rvcsi-core/
    rvcsi-adapter-file/
    rvcsi-adapter-nexmon/
    rvcsi-adapter-esp32/
    rvcsi-dsp/
    rvcsi-events/
    rvcsi-ruvector/
    rvcsi-daemon/
    rvcsi-node/
    rvcsi-mcp/
  packages/
    sdk/
    cli/
    dashboard/
  native/
    nexmon-shim-c/
  docs/
    adr/
    ddd/
    prd/
    benchmarks/
  testdata/
    captures/
    malformed/
    replay/
```

> Within the RuView monorepo, rvCSI would be introduced as a new bounded context (see the [domain model](../ddd/rvcsi-domain-model.md)) and a small set of `v2/crates/rvcsi-*` crates, reusing existing `wifi-densepose-signal` DSP and `wifi-densepose-ruvector` integration where they overlap rather than duplicating them.

---

## 10. Data model (summary)

The authoritative definitions live in the [rvCSI domain model](../ddd/rvcsi-domain-model.md). Summary:

- **`CsiFrame`** — one validated CSI observation at a timestamp (the FFI-safe object). Carries I/Q, amplitude, phase, RSSI, channel/bandwidth, optional antenna/chain metadata, validation status, quality score, calibration version.
- **`CsiWindow`** — a bounded sequence of frames from one source/session, with mean amplitude, phase variance, motion energy, presence score, quality score.
- **`CsiEvent`** — a semantic interpretation of one or more windows, with `kind`, confidence, evidence window IDs, and metadata.
- **`AdapterProfile`** — capability descriptor for a source: chip, firmware/driver versions, supported channels/bandwidths, expected subcarrier counts, capture/injection/monitor-mode support.

---

## 11. Open questions

1. **Embedding model.** What produces frame/window embeddings in v0 — a fixed DSP feature vector, the existing AETHER contrastive model (ADR-024), or a lightweight on-device model? v0 leans on a deterministic DSP feature vector; v2 targets an on-device model.
2. **Calibration UX.** How long must a calibration window be before `StabilityScore` is trustworthy, and how is that surfaced in the SDK/CLI?
3. **Nexmon coupling.** Which Nexmon-supported chips/firmwares are in the v0 "supported" matrix vs. "best effort"?
4. **Monorepo vs. standalone.** Does rvCSI ship as `v2/crates/rvcsi-*` inside RuView or as a separate `rvcsi/` repo? This PRD assumes monorepo crates that reuse `wifi-densepose-signal` and `wifi-densepose-ruvector`.
5. **MCP transport.** stdio-only for v1, or also a local socket for multi-agent fan-out?

---

## 12. References

- [ADR-095 — rvCSI Edge RF Sensing Platform](../adr/ADR-095-rvcsi-edge-rf-sensing-platform.md)
- [rvCSI Domain Model](../ddd/rvcsi-domain-model.md)
- [ADR-013 — Feature-Level Sensing on Commodity Gear](../adr/ADR-013-feature-level-sensing-commodity-gear.md)
- [ADR-014 — SOTA Signal Processing](../adr/ADR-014-sota-signal-processing.md)
- [ADR-016 — RuVector Integration](../adr/ADR-016-ruvector-integration.md)
- [ADR-024 — Project AETHER: Contrastive CSI Embeddings](../adr/ADR-024-contrastive-csi-embedding-model.md)
- [ADR-031 — RuView Sensing-First RF Mode](../adr/ADR-031-ruview-sensing-first-rf-mode.md)
- [ADR-040 — WASM Programmable Sensing](../adr/ADR-040-wasm-programmable-sensing.md)

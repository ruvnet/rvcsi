# ADR-095: rvCSI — Edge RF Sensing Runtime Platform

| Field | Value |
|-------|-------|
| **Status** | Proposed |
| **Date** | 2026-05-12 |
| **Deciders** | ruv |
| **Codename** | **rvCSI** — RuVector Channel State Information runtime |
| **Relates to** | ADR-012 (ESP32 CSI mesh), ADR-013 (feature-level sensing on commodity gear), ADR-014 (SOTA signal processing), ADR-016 (RuVector integration), ADR-024 (AETHER contrastive embeddings), ADR-031 (RuView sensing-first RF mode), ADR-040 (WASM programmable sensing), ADR-049 (cross-platform WiFi interface detection) |
| **PRD** | [rvCSI Platform PRD](../prd/rvcsi-platform-prd.md) |
| **Domain model** | [rvCSI Domain Model](../ddd/rvcsi-domain-model.md) |

---

## 1. Context

WiFi Channel State Information (CSI) is a powerful camera-free sensing primitive — but in practice it is hard to operationalize. Most CSI pipelines today are Linux shell scripts, patched firmware, kernel modules, Python notebooks, PCAP dumps, and ad-hoc signal processing. Packet formats are inconsistent across chips; drivers are unstable; malformed packets are common; and device-specific assumptions leak everywhere. CSI works in the lab and falls over in the field.

RuView already contains substantial CSI infrastructure (`wifi-densepose-signal`, `wifi-densepose-ruvector`, the ESP32 mesh of ADR-012, the RuView multistatic work of ADR-031). What is missing is a **stable, hardware-abstracted runtime layer** that:

- ingests CSI from many sources behind one interface,
- validates every packet before it can touch application code,
- normalizes everything into one schema,
- runs reusable signal processing,
- emits typed, confidence-scored events,
- exposes a safe TypeScript SDK, a CLI, MCP tools, and a RuVector bridge,
- and runs unattended on Raspberry Pi-class hardware.

This ADR establishes that runtime — **rvCSI** — and the architectural decisions that constrain it. Detailed requirements are in the [PRD](../prd/rvcsi-platform-prd.md); the bounded contexts, aggregates, and ubiquitous language are in the [domain model](../ddd/rvcsi-domain-model.md).

### 1.1 What rvCSI is not (day one)

rvCSI is *not* a pure-Rust replacement for vendor firmware patches, *not* a universal driver for all WiFi chips, and *not* an identity/pose/medical/legal-grade claim. It is a **structural sensing** runtime: excellent at detecting change, presence, motion, drift, and learned patterns; deliberately silent on exact identity, exact pose, and certainty guarantees. The product surface stays inside that boundary (see Decision D7).

### 1.2 Existing assets rvCSI builds on

| Asset | Source | Reuse in rvCSI |
|-------|--------|----------------|
| SOTA DSP (Hampel, phase unwrap, Fresnel, BVP, spectrograms) | `wifi-densepose-signal` (ADR-014) | `rvcsi-dsp` wraps/extends rather than re-implements |
| RuVector integration (5 crates) | `wifi-densepose-ruvector` (ADR-016) | `rvcsi-ruvector` exporter rides on the existing integration |
| ESP32 CSI firmware + aggregator | `wifi-densepose-hardware` / firmware (ADR-012) | `rvcsi-adapter-esp32` consumes the existing serial/UDP stream |
| AETHER contrastive embeddings | ADR-024 | optional embedding backend for window/event vectors |
| Cross-platform interface detection | ADR-049 | adapter discovery / health checks |

---

## 2. Decision

**Adopt rvCSI as a layered edge RF sensing runtime** with the boundary discipline `C → Rust → TypeScript`, a single normalized `CsiFrame` schema, mandatory validation before any language boundary crossing, and RuVector as RF memory. The fifteen decisions below are the architectural contract.

### D1 — Rust is the core runtime

CSI parsing and DSP require memory safety, predictable latency, and high throughput; C/Python research stacks are fragile for unattended edge deployment. **rvCSI uses Rust** for parsing, validation, signal processing, event extraction, and daemon execution.
*Consequences:* safer packet handling; better long-running stability; stronger portability to edge devices; more complex build system than pure TypeScript.

### D2 — C only at the hardware-compatibility boundary

Nexmon and similar CSI sources often require C shims, legacy drivers, or firmware-patch hooks. **C is isolated to thin shims** for existing capture and firmware compatibility — never in the data path beyond decode.
*Consequences:* existing Nexmon capability reused; unsafe surface stays small; full firmware rewrite avoided; some device support stays dependent on upstream tools.

### D3 — TypeScript for SDK, CLI, and developer orchestration

Developers need an approachable SDK, agent integrations, dashboards, and scripts. **rvCSI exposes a first-class TypeScript SDK** (`@ruv/rvcsi`) and CLI; native performance stays in Rust.
*Consequences:* easy adoption by app/agent developers; native perf preserved; requires a native build + prebuild release pipeline.

### D4 — napi-rs for Node bindings

Native Node modules need a stable ABI and ergonomic Rust integration. **rvCSI uses napi-rs** for the `rvcsi-node` bindings.
*Consequences:* Rust exposes typed APIs to TypeScript; prebuilt binaries distributable; careful memory-ownership rules required.

### D5 — Normalize all sources into one `CsiFrame` / `CsiWindow` schema

Different CSI sources expose incompatible formats; application code must not know device-specific details. **Every source is normalized into `CsiFrame` and `CsiWindow`** (schema in the domain model).
*Consequences:* hardware-agnostic application code; easier RuVector integration; some source-specific metadata needs extension fields.

### D6 — Validate before crossing language boundaries

Malformed packets and unsafe pointers are the dominant stability risk. **All raw data is validated in Rust before it crosses into TypeScript or RuVector**; rejected frames are quarantined (when enabled); parser failures return structured errors; TypeScript never receives raw unchecked pointers.
*Consequences:* safer SDK; cleaner error model; small validation overhead.

### D7 — Treat CSI as a temporal delta, not absolute truth

CSI is noisy and environment-specific. **rvCSI frames CSI as a temporal delta stream against learned baselines**, not as exact vision.
*Consequences:* honest product claims; good fit for presence/motion/drift/anomaly; identity and exact pose excluded from core claims.

### D8 — RuVector is RF memory

CSI becomes far more valuable stored as temporal embeddings and room signatures. **rvCSI integrates with RuVector** for vector storage, similarity search, drift detection, and sensor-graph relationships.
*Consequences:* rvCSI joins the broader ruvnet cognitive stack; RF field history becomes queryable; requires embedding design and retention policy.

### D9 — Design for replayability

Signal algorithms need repeatable benchmarks and debugging. **rvCSI supports deterministic replay** of captured sessions (timestamps, ordering, validation decisions, event output, calibration version, runtime config all preserved).
*Consequences:* easier testing; better audit trail; enables benchmark datasets.

### D10 — Separate detection from decision

rvCSI detects RF events; agents/applications decide what to do. **rvCSI emits events with confidence and evidence and performs no high-consequence actions by default.**
*Consequences:* cleaner safety model; clean integration with Cognitum proof-gated execution; applications implement policy.

### D11 — Local-first operation

RF sensing is privacy-sensitive and often valuable offline. **rvCSI runs locally by default and requires no cloud service**; remote observability is opt-in.
*Consequences:* better privacy posture; usable in industrial/care/sovereign deployments; remote observability must be explicitly enabled.

### D12 — MCP tools are read-first, write-gated

Agents should observe RF state safely; device mutation and calibration change system behavior. **MCP tools default to read actions**; capture start/stop, calibration, and export are gated.
*Consequences:* safer agent integration; lower accidental device disruption; more explicit operational control.

### D13 — Quality scoring is mandatory

CSI quality varies widely by chip, antenna, environment, channel, and interference. **Every frame, window, and event carries quality or confidence scoring.**
*Consequences:* downstream systems can suppress weak evidence; easier debugging; requires calibration and thresholds. Where a detector compares against a learned baseline (e.g. baseline-drift / anomaly), thresholds are expressed **relative to the baseline's magnitude**, not as absolute amplitude units, so a single tuning is valid across sources whose raw CSI scales differ by orders of magnitude (raw `int8` ESP32 vs. `int16`-scaled Nexmon vs. baseline-subtracted streams).

### D14 — Versioned calibration profiles

Room baselines change over time. **Calibration profiles are versioned**, and event outputs reference the calibration version used.
*Consequences:* more auditable detection; replay can reproduce prior outputs; slight storage overhead.

### D15 — Hardware adapters are plugins

Device support will evolve and vary by platform. **Source adapters are plugins behind a common Rust trait** (`CsiSource`).
*Consequences:* easier support for Nexmon/ESP32/Intel/Atheros/SDR/future sources; cleaner testability; adapter certification becomes important.

---

## 3. Architecture

```
CSI Source
  ↓                          ┌─ Capture context ──────────────┐
Adapter Layer (C shims here)  │  Source · CaptureSession ·     │
  ↓                          │  AdapterProfile                │
Rust Validation Pipeline ─────┤  Validation context           │
  ↓                          │  ValidationPolicy · Quarantine │
Normalized CsiFrame ──────────┘  ← FFI-safe boundary object
  ↓                          ┌─ Signal context ───────────────┐
Signal Processing            │  SignalPipeline · WindowBuffer │
  ↓                          ├─ Calibration context ──────────┤
Window Aggregator ───────────┤  CalibrationProfile ·          │
  ↓                          │  RoomSignature · BaselineModel │
Event Extractor ─────────────┤  Event context                │
  ↓                          │  EventDetector · StateMachine  │
TS SDK · CLI · MCP · RuVector └─ Memory + Agent contexts ──────┘
```

**Crates (within RuView's `v2/crates/`, or a standalone `rvcsi/crates/`):**
`rvcsi-core` · `rvcsi-adapter-file` · `rvcsi-adapter-nexmon` · `rvcsi-adapter-esp32` · `rvcsi-dsp` · `rvcsi-events` · `rvcsi-ruvector` · `rvcsi-daemon` · `rvcsi-node` · `rvcsi-mcp` — plus TypeScript packages `sdk`, `cli`, `dashboard`, and `native/nexmon-shim-c`.

See the [PRD §9](../prd/rvcsi-platform-prd.md#9-system-architecture) for the full component table and reference layout, and the [domain model](../ddd/rvcsi-domain-model.md) for bounded contexts, aggregates, invariants, and domain services.

---

## 4. Consequences

**Positive**

- CSI becomes reusable infrastructure: npm-installable, reproducible, typed, safe-parsed, embeddable, WebSocket-streamable, WASM-portable, MCP-exposed, agent-integrable.
- One application codebase works across Nexmon, ESP32, Intel, and Atheros sources.
- Bad packets cannot crash the daemon; unattended operation becomes realistic.
- RuView/RuVector/Cognitum/agents gain a validated live source of RF observations.
- Honest product framing ("structural sensing") avoids over-claiming.

**Negative / costs**

- Larger build surface: Rust core + napi-rs native module + C shims + TypeScript packages + prebuild pipeline.
- Adapter certification and a supported-hardware matrix become ongoing maintenance.
- Embedding design, calibration thresholds, and retention policy are non-trivial open questions (tracked in the PRD).
- Risk of duplicating `wifi-densepose-signal` / `wifi-densepose-ruvector`; mitigated by wrapping, not re-implementing.

**Risks**

- Nexmon coupling: some device support remains dependent on upstream firmware/driver projects.
- CSI quality variance: weak-signal environments may yield low-confidence events; mitigated by mandatory quality scoring (D13) and versioned calibration (D14).

---

## 5. Alternatives considered

| Alternative | Why not |
|-------------|---------|
| Pure-Python runtime (extend the v1 stack) | Fragile under malformed packets; GC pauses break the < 50 ms latency target; poor unattended stability. |
| Pure-Rust including firmware (replace Nexmon) | Enormous scope; vendor-specific; would block v0 indefinitely. D2 keeps C at the boundary instead. |
| Per-source SDKs (no normalized schema) | Pushes device specifics into application code; defeats the "same app code across adapters" success criterion. |
| WASM-only core | No raw socket / serial / monitor-mode access for live capture; fine for offline parsing (a later target) but not v0 live capture. |
| Cloud-first ingestion | Violates the privacy posture and the local-first requirement; unacceptable for care/industrial/sovereign deployments. |

---

## 6. Implementation phases (proposed)

1. **v0** — `rvcsi-core` + file/replay/ESP32 adapters + validation + `rvcsi-dsp` (presence/motion) + `rvcsi-node` SDK + `rvcsi-cli` + WebSocket output + `rvcsi-ruvector` export + basic calibration + health checks. Targets all eight PRD success criteria.
2. **v1** — multi-node sync, RF room signatures, breathing-rate where signal permits, temporal embeddings, drift detection, room-topology graph, `rvcsi-mcp` tool server, replayable benchmark datasets, RuView sensor fusion, Cognitum deployment profile.
3. **v2** — hardware-agnostic RF sensor fabric, multi-room RF memory, streaming anomaly detection, RF-SLAM research mode, on-device embedding model, federated room-signature learning, signed sensor-evidence records, proof-gated event publication, dynamic cut-based coherence over RF graphs, agent-driven calibration and self-repair.

---

## 7. References

- [rvCSI Platform PRD](../prd/rvcsi-platform-prd.md)
- [rvCSI Domain Model](../ddd/rvcsi-domain-model.md)
- ADR-012 — ESP32 CSI Sensor Mesh
- ADR-013 — Feature-Level Sensing on Commodity Gear
- ADR-014 — SOTA Signal Processing
- ADR-016 — RuVector Integration
- ADR-024 — Project AETHER: Contrastive CSI Embeddings
- ADR-031 — RuView Sensing-First RF Mode
- ADR-040 — WASM Programmable Sensing
- ADR-049 — Cross-Platform WiFi Interface Detection

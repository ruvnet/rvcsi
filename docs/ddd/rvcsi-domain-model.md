# rvCSI — Edge RF Sensing Runtime Domain Model

## Domain-Driven Design Specification

> Companion documents: [rvCSI Platform PRD](../prd/rvcsi-platform-prd.md) · [ADR-095 — rvCSI Edge RF Sensing Platform](../adr/ADR-095-rvcsi-edge-rf-sensing-platform.md)

### Domain

Camera-free RF spatial sensing from WiFi Channel State Information (CSI).

### Core domain

**RF field interpretation.** rvCSI converts noisy radio channel measurements into validated events and temporal embeddings that represent changes in physical space. CSI is treated as a *temporal delta stream* against learned baselines — not as exact vision.

### Supporting subdomains

Hardware adapter management · packet parsing · signal processing · calibration · event extraction · temporal memory · agent integration · replay and audit.

### Generic subdomains

Logging · configuration · CLI parsing · WebSocket streaming · package publishing · dashboard visualization.

---

## Ubiquitous Language

| Term | Definition |
|------|------------|
| **CSI** | Channel State Information — per-subcarrier complex channel response measured by a WiFi receiver |
| **Source** | A physical or replayed producer of CSI frames (a NIC, an ESP32 node, a PCAP file, a recorded capture) |
| **Adapter** | A software module that knows how to receive and decode source-specific CSI and normalize it into a `CsiFrame` |
| **Frame** | One CSI observation at a timestamp — the unit of ingestion |
| **Window** | A bounded sequence of frames from one source/session, used for analysis |
| **Baseline** | The learned normal RF-field state for a space |
| **Delta** | The measured difference of the current field from baseline |
| **Event** | A semantic interpretation of one or more windows (presence started, motion detected, anomaly, …) |
| **Quality score** | Confidence, in [0, 1], that a signal/frame/window is usable |
| **Calibration** | The process of learning a stable baseline for a space |
| **Room signature** | A vector representation of a space under normal conditions |
| **Drift** | Slow movement of the field away from baseline |
| **Anomaly** | A significant, unexplained deviation from baseline |
| **RF memory** | Persisted temporal vectors and events for a physical space (stored in RuVector) |
| **Coherence** | Consistency among sources, windows, and learned baselines |
| **Quarantine** | A holding store for rejected/corrupt frames, kept for audit rather than discarded |
| **Adapter profile** | A capability descriptor for a source (chip, firmware/driver versions, supported channels/bandwidths, expected subcarrier counts, capture/injection/monitor-mode support) |
| **Calibration version** | An immutable identifier for a particular learned baseline; every event references the calibration version it was detected against |
| **Evidence window set** | The set of `WindowId`s an event references as its justification — an event with no evidence is invalid |

---

## Bounded Contexts

```
┌─────────────┐   ┌──────────────┐   ┌────────────┐   ┌──────────────┐
│  Capture    │──▶│  Validation  │──▶│   Signal   │──▶│ Calibration  │
│  context    │   │   context    │   │  context   │   │   context    │
└─────────────┘   └──────────────┘   └─────┬──────┘   └──────┬───────┘
                                            │                 │
                                            ▼                 │
                                     ┌────────────┐           │
                                     │   Event    │◀──────────┘
                                     │  context   │
                                     └─────┬──────┘
                                            │
                              ┌─────────────┴─────────────┐
                              ▼                           ▼
                       ┌────────────┐              ┌────────────┐
                       │   Memory   │              │   Agent    │
                       │  context   │              │  context   │
                       └────────────┘              └────────────┘
```

- **Capture** upstreams raw input from sources.
- **Validation** protects every downstream context — nothing crosses into SDK/DSP/memory/agents unvalidated.
- **Signal** turns frames into windows.
- **Calibration** gives windows a room-specific baseline.
- **Event** converts deltas into meaning.
- **Memory** stores time, similarity, drift, and coherence (RuVector).
- **Agent** exposes safe actions and queries (MCP / TypeScript).

---

### 1. Capture context

**Responsibility:** connect to CSI sources and produce raw frames.

```
┌──────────────────────────────────────────────────────────────┐
│                      Capture Context                          │
├──────────────────────────────────────────────────────────────┤
│  ┌────────────┐   ┌─────────────────┐   ┌─────────────────┐   │
│  │  Source    │   │ CaptureSession  │   │ AdapterProfile  │   │
│  │ (adapter   │   │ (aggregate root)│   │ (capability     │   │
│  │  plugin)   │   │                 │   │  descriptor)    │   │
│  └────────────┘   └─────────────────┘   └─────────────────┘   │
│                                                                │
│  CsiSource trait: open · start · next_frame · stop · health    │
└──────────────────────────────────────────────────────────────┘
```

| Element | Kind | Notes |
|---------|------|-------|
| `Source` | Entity | A configured adapter instance bound to a device or file |
| `CaptureSession` | Entity / **aggregate root** | Owns exactly one `AdapterProfile` and one runtime configuration |
| `AdapterProfile` | Entity | Chip, firmware/driver versions, supported channels/bandwidths, expected subcarrier counts, capability flags |
| `Channel`, `Bandwidth`, `FirmwareVersion`, `DriverVersion` | Value objects | Immutable |

**Commands:** `StartCapture` · `StopCapture` · `RestartCapture` · `InspectSource`
**Domain events:** `CaptureStarted` · `CaptureStopped` · `SourceDisconnected` · `AdapterUnsupported`

---

### 2. Validation context

**Responsibility:** make frames safe and trustworthy before any language-boundary crossing.

| Element | Kind | Notes |
|---------|------|-------|
| `ValidationPolicy` | Entity | Bounds, monotonicity rules, finiteness checks, quarantine on/off |
| `QuarantineStore` | Entity | Holds rejected/corrupt frames for audit |
| `ValidatedFrame` | **Aggregate root** | The frame once it has passed (or been degraded by) validation |
| `ValidationError`, `QualityScore`, `FrameBounds` | Value objects | `QualityScore` ∈ [0, 1] |

**Commands:** `ValidateFrame` · `QuarantineFrame`
**Domain events:** `FrameAccepted` · `FrameRejected` · `QualityDropped`

---

### 3. Signal context

**Responsibility:** DSP and window features.

```
Frame stream ─▶ SignalPipeline ─▶ WindowBuffer ─▶ CsiWindow
              (DC removal, phase unwrap,        (mean amplitude,
               smoothing, Hampel filter,         phase variance,
               variance, baseline subtraction,   motion energy,
               motion energy, presence score)    presence/quality scores)
```

| Element | Kind | Notes |
|---------|------|-------|
| `SignalPipeline` | Entity | Ordered DSP stages; reuses `wifi-densepose-signal` primitives |
| `WindowBuffer` | Entity | Accumulates frames into bounded windows |
| `CsiWindow` | **Aggregate root** | Frames from exactly one source/session |
| `AmplitudeVector`, `PhaseVector`, `MotionEnergy`, `PresenceScore` | Value objects | |

**Commands:** `ProcessFrame` · `BuildWindow` · `EstimateBaselineDelta`
**Domain events:** `WindowReady` · `BaselineDeltaMeasured`

---

### 4. Calibration context

**Responsibility:** learn and version the normal RF state and room signatures.

| Element | Kind | Notes |
|---------|------|-------|
| `CalibrationProfile` | **Aggregate root** | Linked to source, room, adapter profile, configuration |
| `RoomSignature` | Entity | Vector representation of a space under normal conditions |
| `BaselineModel` | Entity | Statistical model of the baseline field; carries version history |
| `CalibrationVersion`, `StabilityScore`, `RoomId` | Value objects | Calibration cannot complete if `StabilityScore` < threshold |

**Commands:** `StartCalibration` · `CompleteCalibration` · `UpdateBaseline` · `RejectUnstableCalibration`
**Domain events:** `CalibrationStarted` · `CalibrationCompleted` · `CalibrationFailed` · `BaselineUpdated`

---

### 5. Event context

**Responsibility:** semantic event extraction with confidence and evidence.

| Element | Kind | Notes |
|---------|------|-------|
| `EventDetector` | Entity | One per event family (presence, motion, breathing, anomaly, …) |
| `EventStateMachine` | Entity | Holds the per-source detection state; emits transitions |
| `CsiEvent` | **Aggregate root** | Must reference ≥ 1 evidence window; confidence ∈ [0, 1]; references calibration version |
| `Confidence`, `EvidenceWindowSet`, `EventKind` | Value objects | |

**Commands:** `DetectEvents` · `PublishEvent` · `SuppressEvent`
**Domain events (the `CsiEventKind` enum):** `PresenceStarted` · `PresenceEnded` · `MotionDetected` · `MotionSettled` · `BaselineChanged` · `SignalQualityDropped` · `DeviceDisconnected` · `BreathingCandidate` · `AnomalyDetected` · `CalibrationRequired`

---

### 6. Memory context

**Responsibility:** RuVector storage and retrieval — RF memory.

| Element | Kind | Notes |
|---------|------|-------|
| `RfMemoryCollection` | Entity | A RuVector collection scoped to a deployment |
| `TemporalEmbedding` | Entity | Frame / window / event embedding with timestamp |
| `SensorGraph` | Entity | Graph of sources and their topological relationships |
| `RoomMemory` | **Aggregate root** | Stored embeddings must be traceable to frame windows or event windows |
| `EmbeddingVector`, `DriftScore`, `CoherenceScore` | Value objects | `DriftScore` must include the baseline version |

**Commands:** `StoreWindowEmbedding` · `StoreEventEmbedding` · `QuerySimilarWindows` · `ComputeDrift`
**Domain events:** `EmbeddingStored` · `DriftDetected` · `SimilarPatternFound`

Data stored: frame embeddings · window embeddings · room baseline vectors · event vectors · drift snapshots · sensor-topology graph edges · source health records. Retention policy applies at collection level. No orphan embeddings.

---

### 7. Agent context

**Responsibility:** MCP and TypeScript agent interaction — safe actions and queries.

| Element | Kind | Notes |
|---------|------|-------|
| `AgentSubscription` | Entity | An agent's filtered stream of events |
| `McpToolSession` | Entity | A tool invocation context with permissions |
| `AgentSession` | **Aggregate root** | |
| `ToolPermission`, `EventFilter`, `AgentIntent` | Value objects | `ToolPermission` distinguishes read vs. write-gated |

**Commands:** `SubscribeToEvents` · `RequestStatus` · `RequestCalibration` · `QueryMemory`
**Domain events:** `AgentSubscribed` · `ToolExecuted` · `PermissionDenied`

**MCP tools** (read by default; write-gated marked `*`): `rvcsi_status` · `rvcsi_list_sources` · `rvcsi_start_capture *` · `rvcsi_stop_capture *` · `rvcsi_get_presence` · `rvcsi_get_recent_events` · `rvcsi_calibrate_room *` · `rvcsi_export_window *` · `rvcsi_query_ruvector` · `rvcsi_health_report`.

---

## Context Map

| Upstream → Downstream | Relationship | ACL / contract |
|-----------------------|--------------|----------------|
| Capture → Validation | Customer/Supplier | Raw frames pass through `ValidationPolicy`; only `Accepted`/`Degraded` continue |
| Validation → Signal | Conformist (Signal accepts `ValidatedFrame` as-is) | `CsiFrame` schema is the published language |
| Signal → Calibration | Customer/Supplier | Windows + baseline-delta measurements feed baseline modeling |
| Calibration → Event | Customer/Supplier | Detectors declare which `CalibrationVersion` they used |
| Signal/Event → Memory | Published Language (`EmbeddingVector`, event metadata) | `rvcsi-ruvector` ACL translates to RuVector's API |
| Event → Agent | Open Host Service (event stream + MCP tools) | `EventFilter` + `ToolPermission` enforced at the boundary |
| Capture → Agent | Conformist (health/status only, via MCP read tools) | No raw frames cross to agents |

The **`CsiFrame` schema is the shared kernel** between Capture, Validation, Signal, and the language-boundary (napi-rs) layer. It is the FFI-safe object; nothing device-specific leaks past it.

---

## Aggregates and Invariants

### `CaptureSession` aggregate

**Invariant:** a capture session has exactly one source profile and one runtime configuration.

1. A session cannot emit frames before it is started.
2. A session cannot change channel without restart unless the adapter supports dynamic retune.
3. A session must emit `SourceDisconnected` before stopping due to device loss.

### `ValidatedFrame` aggregate

**Invariant:** no frame crosses into SDK, DSP, memory, or agents unless its validation status is `Accepted` or `Degraded`.

1. Rejected frames go to quarantine when quarantine is enabled.
2. Degraded frames must carry quality-reason metadata.
3. Missing *optional* hardware metadata must not invalidate a frame.

### `CsiWindow` aggregate

**Invariant:** a window contains frames from exactly one source and one session.

1. Mixed-source windows are not allowed.
2. Window start time must be strictly less than end time.
3. Window quality is bounded in [0, 1].

### `CalibrationProfile` aggregate

**Invariant:** a calibration profile is linked to source, room, adapter profile, and configuration.

1. Calibration cannot complete if `StabilityScore` is below threshold.
2. Baseline updates must preserve version history.
3. Event detectors must declare which calibration version they used.

### `CsiEvent` aggregate

**Invariant:** an event must have evidence.

1. Every event references at least one evidence window.
2. Confidence is bounded in [0, 1].
3. Event suppression must be explainable by policy.
4. Typed sensing evidence is valid only before its expiry. Equality with the expiry is expired. Consumers call `validate_at(now_ns)` at publication boundaries.
5. Typed evidence, valid application tokens, associations, and typed events have a maximum five second lifetime. An event cannot outlive any nested evidence or association, and evidence cannot claim a capture timestamp after event publication.
6. A track association must have fresh, non-abstained, authenticated BLE advertisement evidence for the same rotating token and fresh, non-abstained WiFi CSI evidence for the same track token. Both supports must cover the association lifetime. `authenticated` requires a retained verified `RuView/GW/v1` envelope receipt; an inner flag or caller boolean is insufficient.
7. Association confidence is at least 0.60 and cannot exceed the weaker eligible BLE or WiFi CSI support confidence. Exact crossing ambiguity removes the association; a later unambiguous sample must rebind it.
8. A BLE pseudonym has exactly the `blep:` prefix and 64 lowercase hexadecimal digest characters. BLE evidence preserves authenticated `token_epoch` and `source_sequence` fields for replay protection.
9. BLE advertisement RSSI and Bluetooth Channel Sounding phase or timing are distinct evidence variants and capabilities. RVCS has no pseudonymous identity join. Channel Sounding is grouped by a nonzero source session and canonical decimal nonzero u32 procedure id, has an exact declared step count, and includes at least four unique channels no greater than 78. Signed phase is normalized to `[-π, π)` and RTT picoseconds are divided by 1000 and bounded to 250 ns.
10. Exact `respiratory_component` values and Channel Sounding phase/RTT are P0. They fail an external export check and may leave the normalized event only under the explicit governed edge-only scope.
11. Fusion nanosecond values serialize as decimal JSON strings so JavaScript does not lose precision.
12. An abstained event must include at least one typed quality reason.

### `RoomMemory` aggregate

**Invariant:** stored embeddings are traceable to frame windows or event windows.

1. No orphan embeddings.
2. Retention policy applies at collection level.
3. Drift scores must include the baseline version.

---

## Data Model

```rust
pub struct CsiFrame {
    pub frame_id: FrameId,
    pub session_id: SessionId,
    pub source_id: SourceId,
    pub adapter_kind: AdapterKind,
    pub timestamp_ns: u64,
    pub channel: u16,
    pub bandwidth_mhz: u16,
    pub rssi_dbm: Option<i16>,
    pub noise_floor_dbm: Option<i16>,
    pub antenna_index: Option<u8>,
    pub tx_chain: Option<u8>,
    pub rx_chain: Option<u8>,
    pub subcarrier_count: u16,
    pub i_values: Vec<f32>,
    pub q_values: Vec<f32>,
    pub amplitude: Vec<f32>,
    pub phase: Vec<f32>,
    pub validation: ValidationStatus,
    pub quality_score: f32,
    pub calibration_version: Option<String>,
}

pub struct CsiWindow {
    pub window_id: WindowId,
    pub session_id: SessionId,
    pub source_id: SourceId,
    pub start_ns: u64,
    pub end_ns: u64,
    pub frame_count: u32,
    pub mean_amplitude: Vec<f32>,
    pub phase_variance: Vec<f32>,
    pub motion_energy: f32,
    pub presence_score: f32,
    pub quality_score: f32,
}

pub enum CsiEventKind {
    PresenceStarted,
    PresenceEnded,
    MotionDetected,
    MotionSettled,
    BaselineChanged,
    SignalQualityDropped,
    DeviceDisconnected,
    BreathingCandidate,
    AnomalyDetected,
    CalibrationRequired,
}

pub struct CsiEvent {
    pub event_id: EventId,
    pub kind: CsiEventKind,
    pub session_id: SessionId,
    pub source_id: SourceId,
    pub timestamp_ns: u64,
    pub confidence: f32,
    pub evidence_window_ids: Vec<WindowId>,
    pub metadata_json: String,
    pub disposition: EventDisposition,
    pub quality_reasons: Vec<QualityReason>,
    pub sensing_evidence: Vec<SensingEvidence>,
    pub track_association: Option<TrackAssociation>,
    pub synthetic_label: Option<SyntheticLabel>,
    pub expires_at_ns: Option<u64>,
}

pub struct AdapterProfile {
    pub adapter_kind: AdapterKind,
    pub chip: Option<String>,
    pub firmware_version: Option<String>,
    pub driver_version: Option<String>,
    pub supported_channels: Vec<u16>,
    pub supported_bandwidths_mhz: Vec<u16>,
    pub expected_subcarrier_counts: Vec<u16>,
    pub supports_live_capture: bool,
    pub supports_injection: bool,
    pub supports_monitor_mode: bool,
}

pub enum ValidationStatus { Accepted, Degraded, Rejected, Recovered }
```

---

## Domain Services

| Service | Input | Output | Responsibility |
|---------|-------|--------|----------------|
| `FrameValidationService` | `RawFrame`, `AdapterProfile`, `ValidationPolicy` | `ValidatedFrame` or `RejectedFrame` | Enforce bounds, finiteness, monotonicity; assign initial `QualityScore`; route rejects to quarantine; emit structured errors |
| `SignalProcessingService` | `ValidatedFrame` stream | `CsiWindow` stream | Run the DSP pipeline; build bounded windows; compute motion energy, presence score, window quality |
| `BaselineDeltaService` | `CsiWindow`, `BaselineModel` | `BaselineDelta` | Subtract the calibrated baseline; measure deviation magnitude |
| `CalibrationService` | `CsiWindow` stream over a calibration window | `CalibrationProfile` (new version) or `CalibrationFailed` | Learn a stable baseline; compute `StabilityScore`; reject unstable calibrations; preserve version history |
| `EventDetectionService` | `CsiWindow` + `BaselineDelta` + `CalibrationVersion` | `CsiEvent` stream | Drive per-source state machines; attach confidence + evidence windows + calibration version; apply suppression policy |
| `EmbeddingService` | `CsiWindow` / `CsiEvent` | `TemporalEmbedding` | Produce frame/window/event vectors (v0: deterministic DSP feature vector; later: AETHER / on-device model) |
| `RfMemoryService` | `TemporalEmbedding`, query | `EmbeddingStored` / similar windows / `DriftScore` | Store to RuVector; similarity search; drift computation against a baseline version |
| `ReplayService` | A captured session bundle | A deterministic frame/window/event stream | Replay preserving timestamps, ordering, validation decisions, event output, calibration version, runtime config |
| `AdapterRegistryService` | — | List of available adapters + `AdapterProfile`s | Discover sources (reuses ADR-049 interface detection); report health; flag unsupported firmware/driver state |
| `AgentGatewayService` | MCP tool call / SDK subscription | Tool result / filtered event stream | Enforce `ToolPermission` (read vs. write-gated), apply `EventFilter`, audit `ToolExecuted` / `PermissionDenied` |

---

## Related

- [rvCSI Platform PRD](../prd/rvcsi-platform-prd.md) — requirements, success criteria, scope
- [ADR-095 — rvCSI Edge RF Sensing Platform](../adr/ADR-095-rvcsi-edge-rf-sensing-platform.md) — the fifteen architectural decisions
- [RuvSense Domain Model](ruvsense-domain-model.md) — adjacent multistatic sensing context
- [Signal Processing Domain Model](signal-processing-domain-model.md) — the DSP primitives `rvcsi-dsp` reuses
- [ADR Index](../adr/README.md)

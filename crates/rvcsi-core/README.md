# rvcsi-core

[![crates.io](https://img.shields.io/crates/v/rvcsi-core.svg)](https://crates.io/crates/rvcsi-core)
[![docs.rs](https://img.shields.io/docsrs/rvcsi-core)](https://docs.rs/rvcsi-core)

The shared kernel of [rvCSI](https://github.com/ruvnet/rvcsi) — the edge RF sensing runtime.

Owns the **normalized schema** every CSI source is mapped onto:

- `CsiFrame` — one CSI observation at a timestamp (I/Q + derived amplitude/phase per subcarrier, channel/bandwidth, RSSI/noise/antenna/chains, `ValidationStatus`, `quality_score`, `quality_reasons`, `calibration_version`).
- `CsiWindow` — a bounded run of frames from one source, summarized into per-subcarrier mean amplitude / phase variance plus scalar motion / presence / quality scores.
- `CsiEvent` — a semantic interpretation with `CsiEventKind`, confidence, evidence window ids, and free-form metadata JSON. Optional fusion fields carry expiring typed evidence, an explicit publication or abstention decision, and a rotating-token track association without changing legacy capture JSON.

BLE advertisement RSSI and Bluetooth Channel Sounding phase/timing use distinct `SensingEvidencePayload` variants and `SourceCapability` values. Authenticated evidence retains a verified `RuView/GW/v1` receipt; an inner flag is insufficient. RVCS Channel Sounding carries no pseudonymous token. Its canonical decimal u32 procedure id, channels through 78, signed phase, and picosecond-to-nanosecond RTT conversion are bounded again by core validation. `CsiEvent::validate_at` enforces a five-second maximum TTL and nested fail-closed expiry. Associations require fresh authenticated BLE plus matching CSI, confidence from 0.60 through the weaker support, and abstention at exact crossings before rebinding. Fusion nanosecond fields serialize as exact decimal strings.

`run_ble_csi_crossing_simulation` provides a deterministic two-person crossing fixture. A stateful replay guard and RSSI geometry associator derive expiry, replay, spoof, association, exact-crossing abstention, and post-crossing rebinding from raw records, then compare their decisions with independent ground truth. Optional Channel Sounding is an identity-free grouped four-step procedure from a separate future radio and preserves the RuView companion source session plus exact declared step count. Exact `respiratory_component`, phase, and RTT values classify their evidence as P0; `validate_for_export_at` permits them only under an explicit governed edge-only scope. The default ESP32-S3 profile exposes WiFi CSI plus BLE advertisement RSSI only; it does not claim raw CTE IQ or Bluetooth 6 Channel Sounding.

Plus: `AdapterProfile` (a source's capability descriptor — gates validation), the `CsiSource` plugin trait (every hardware/file/replay adapter implements it), id newtypes (`FrameId`/`WindowId`/`EventId`/`SessionId`/`SourceId`) + a `Send+Sync` `IdGenerator`, the structured `RvcsiError`, and **`validate_frame`** — the only door between raw adapter output and anything downstream. Validation mutates a frame in place: on success it sets `Accepted` / `Degraded` / `Recovered` and fills `quality_score`; on a hard failure it sets `Rejected` and returns a `ValidationError`. A `Pending` or `Rejected` frame must never cross a language boundary.

`#![forbid(unsafe_code)]`. Dependency-light (serde + thiserror) and `no_std`-clean in spirit.

```toml
[dependencies]
rvcsi-core = "0.3"
```

See [ADR-095](https://github.com/ruvnet/rvcsi/blob/main/docs/adr/ADR-095-rvcsi-edge-rf-sensing-platform.md) (the 15 platform decisions), [ADR-096](https://github.com/ruvnet/rvcsi/blob/main/docs/adr/ADR-096-rvcsi-ffi-crate-layout.md) (crate topology / FFI seams), and [ADR-097](https://github.com/ruvnet/rvcsi/blob/main/docs/adr/ADR-097-ble-csi-fusion-evidence.md) (BLE plus CSI evidence and privacy contract). Licensed under MIT OR Apache-2.0.

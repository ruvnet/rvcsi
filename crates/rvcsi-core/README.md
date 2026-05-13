# rvcsi-core

[![crates.io](https://img.shields.io/crates/v/rvcsi-core.svg)](https://crates.io/crates/rvcsi-core)
[![docs.rs](https://img.shields.io/docsrs/rvcsi-core)](https://docs.rs/rvcsi-core)

The shared kernel of [rvCSI](https://github.com/ruvnet/rvcsi) — the edge RF sensing runtime.

Owns the **normalized schema** every CSI source is mapped onto:

- `CsiFrame` — one CSI observation at a timestamp (I/Q + derived amplitude/phase per subcarrier, channel/bandwidth, RSSI/noise/antenna/chains, `ValidationStatus`, `quality_score`, `quality_reasons`, `calibration_version`).
- `CsiWindow` — a bounded run of frames from one source, summarized into per-subcarrier mean amplitude / phase variance plus scalar motion / presence / quality scores.
- `CsiEvent` — a semantic interpretation with `CsiEventKind`, confidence, evidence window ids, and free-form metadata JSON.

Plus: `AdapterProfile` (a source's capability descriptor — gates validation), the `CsiSource` plugin trait (every hardware/file/replay adapter implements it), id newtypes (`FrameId`/`WindowId`/`EventId`/`SessionId`/`SourceId`) + a `Send+Sync` `IdGenerator`, the structured `RvcsiError`, and **`validate_frame`** — the only door between raw adapter output and anything downstream. Validation mutates a frame in place: on success it sets `Accepted` / `Degraded` / `Recovered` and fills `quality_score`; on a hard failure it sets `Rejected` and returns a `ValidationError`. A `Pending` or `Rejected` frame must never cross a language boundary.

`#![forbid(unsafe_code)]`. Dependency-light (serde + thiserror) and `no_std`-clean in spirit.

```toml
[dependencies]
rvcsi-core = "0.3"
```

See [ADR-095](https://github.com/ruvnet/rvcsi/blob/main/docs/adr/ADR-095-rvcsi-edge-rf-sensing-platform.md) (the 15 platform decisions) and [ADR-096](https://github.com/ruvnet/rvcsi/blob/main/docs/adr/ADR-096-rvcsi-ffi-crate-layout.md) (crate topology / FFI seams). Licensed under MIT OR Apache-2.0.

# rvcsi-adapter-file

[![crates.io](https://img.shields.io/crates/v/rvcsi-adapter-file.svg)](https://crates.io/crates/rvcsi-adapter-file)
[![docs.rs](https://img.shields.io/docsrs/rvcsi-adapter-file)](https://docs.rs/rvcsi-adapter-file)

The `.rvcsi` capture container and a deterministic replay `CsiSource` for [rvCSI](https://github.com/ruvnet/rvcsi) (ADR-095 FR1/FR10, D9).

A **`.rvcsi` file is plain JSONL**: the first line is a `CaptureHeader` (capture version, session/source ids, the source's `AdapterProfile`, the `ValidationPolicy` in force, calibration version, an opaque runtime-config blob, creation time); every subsequent line is one `rvcsi_core::CsiFrame` serialized as compact JSON. Simple, deterministic, append-friendly, debuggable with `head` / `jq`.

- **`FileRecorder`** — `create(path, &header)` writes the header line; `write_frame(&CsiFrame)` appends one frame; `finish()` / `flush()` makes sure it hit disk.
- **`FileReplayAdapter`** — a `CsiSource` that replays a capture frame by frame, exactly as recorded: timestamps, ordering, and each frame's `ValidationStatus` are preserved verbatim (replay does **not** re-validate or re-order — it only deserializes). Carries `replay_speed` for the daemon/CLI to pace with; the adapter itself never sleeps.

`#![forbid(unsafe_code)]`.

```toml
[dependencies]
rvcsi-adapter-file = "0.3"
```

Licensed under MIT OR Apache-2.0.

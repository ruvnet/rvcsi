# rvcsi-ruvector

[![crates.io](https://img.shields.io/crates/v/rvcsi-ruvector.svg)](https://crates.io/crates/rvcsi-ruvector)
[![docs.rs](https://img.shields.io/docsrs/rvcsi-ruvector)](https://docs.rs/rvcsi-ruvector)

The [RuVector](https://github.com/ruvnet/ruvector) RF-memory bridge for [rvCSI](https://github.com/ruvnet/rvcsi) (ADR-095 FR8, D8) — CSI becomes far more valuable stored as temporal embeddings and room signatures.

- Deterministic `window_embedding` and `event_embedding` — fixed-length vectors derived from a `CsiWindow` / `CsiEvent` (same input → same vector), so storage and similarity search are reproducible.
- `cosine_similarity` on those embeddings.
- The `RfMemoryStore` trait — store windows/events as embedding records, query by similarity, track a running baseline, detect drift.
- `InMemoryRfMemory` and `JsonlRfMemory` — a usable standin until the production RuVector binding lands; `JsonlRfMemory` persists records as JSON lines so the whole pipeline (capture → validate → DSP → events → RF memory) is runnable and testable end-to-end today.

`#![forbid(unsafe_code)]`.

```toml
[dependencies]
rvcsi-ruvector = "0.3"
```

Licensed under MIT OR Apache-2.0.

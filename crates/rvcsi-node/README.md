# @ruv/rvcsi

Node.js bindings (napi-rs) for **rvCSI** — the edge RF sensing runtime: ingest
WiFi CSI from files / Nexmon dumps, validate and normalize it, run reusable DSP,
emit typed presence / motion / quality / anomaly events, and export temporal
embeddings to an RF-memory store. See [ADR-095](../../docs/adr/ADR-095-rvcsi-edge-rf-sensing-platform.md)
and [ADR-096](../../docs/adr/ADR-096-rvcsi-ffi-crate-layout.md).

> This package wraps the Rust crates in `crates/rvcsi-*`. The Rust side does
> all the work (parsing, validation, DSP, events, embeddings); this is a thin,
> safe JS surface — nothing crosses the boundary except validated/normalized
> objects (delivered as JSON the SDK parses for you).

## Build

The native addon is produced from the `rvcsi-node` Rust crate:

```bash
# from v2/crates/rvcsi-node
npm install              # installs @napi-rs/cli
npm run build            # -> rvcsi-node.<triple>.node + binding.js + binding.d.ts
```

(`cargo build -p rvcsi-node` also compiles the addon as a `cdylib`; `napi build`
additionally emits the platform loader and `.d.ts`.)

## Usage

```js
const { RvCsi, inspectCaptureFile, eventsFromCaptureFile, nexmonDecodeRecords } = require('@ruv/rvcsi');

// One-shot: summarize a capture
const summary = inspectCaptureFile('lab.rvcsi');
console.log(summary.frame_count, summary.channels, summary.mean_quality);

// One-shot: replay a capture into events
for (const e of eventsFromCaptureFile('lab.rvcsi')) {
  console.log(e.kind, e.timestamp_ns, e.confidence);
}

// Streaming
const rt = RvCsi.openCaptureFile('lab.rvcsi');
let frame;
while ((frame = rt.nextCleanFrame()) !== null) {
  // frame.validation is 'Accepted' | 'Degraded' | 'Recovered' — never 'Pending'/'Rejected'
  if (frame.quality_score > 0.5) { /* ... */ }
}
const events = rt.drainEvents();
console.log(rt.health());

// Decode raw Nexmon records (the napi-c shim format) straight from a Buffer
const fs = require('fs');
const frames = nexmonDecodeRecords(fs.readFileSync('nexmon.bin'), 'wlan0', 1);
```

TypeScript types ship in `index.d.ts` (`CsiFrame`, `CsiWindow`, `CsiEvent`,
`SourceHealth`, `CaptureSummary`, `ValidationStatus`, `CsiEventKind`, ...).

## What's here vs. not (yet)

Implemented: file/replay + Nexmon sources, the validation pipeline, the DSP
stages, window aggregation + the event state machines, RuVector-style RF-memory
export. Not yet wired into this addon: live radio capture, the WebSocket daemon,
and the MCP tool server — those come with `rvcsi-daemon` / `rvcsi-mcp`.

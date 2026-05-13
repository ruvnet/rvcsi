//! # rvCSI Node.js bindings — napi-rs (ADR-095 D3/D4, ADR-096)
//!
//! The safe TypeScript-facing surface over the rvCSI Rust runtime. Nothing here
//! exposes raw pointers; every value that crosses the boundary is either a
//! normalized rvCSI struct *serialized to JSON* or a scalar. Frames are run
//! through [`rvcsi_core::validate_frame`] inside [`rvcsi_runtime`] before they
//! reach JS (D6), so a JS caller never sees a `Pending` or `Rejected` frame.
//!
//! All real logic lives in the `rvcsi-runtime` crate (plain Rust, unit-tested
//! without a Node env); the `#[napi]` items below are one-liner wrappers.
//!
//! ## JS surface (also see the generated `index.d.ts` in the npm package)
//!
//! Free functions:
//! * `rvcsiVersion(): string`
//! * `nexmonShimAbiVersion(): number` — ABI of the linked napi-c shim
//! * `nexmonDecodeRecords(buf: Buffer, sourceId: string, sessionId: number): string`
//!   — JSON array of validated `CsiFrame`s decoded from the C-shim record format
//! * `inspectCaptureFile(path: string): string` — JSON `CaptureSummary`
//! * `eventsFromCaptureFile(path: string): string` — JSON array of `CsiEvent`s
//! * `exportCaptureToRfMemory(capturePath: string, outJsonlPath: string): number`
//!   — windows stored
//!
//! Class `RvcsiRuntime` (streaming):
//! * `RvcsiRuntime.openCaptureFile(path): RvcsiRuntime`
//! * `RvcsiRuntime.openNexmonFile(path, sourceId, sessionId): RvcsiRuntime`
//! * `.nextFrameJson(): string | null` / `.nextCleanFrameJson(): string | null`
//! * `.drainEventsJson(): string` — JSON array of `CsiEvent`s
//! * `.healthJson(): string` — JSON `SourceHealth`
//! * `.framesSeen` / `.framesDropped` (getters)

#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use napi::bindgen_prelude::Buffer;

use rvcsi_runtime::{self as runtime, CaptureRuntime};

fn napi_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

fn to_json<T: serde::Serialize>(v: &T) -> napi::Result<String> {
    serde_json::to_string(v).map_err(napi_err)
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// rvCSI runtime version (the workspace crate version).
#[napi]
pub fn rvcsi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// ABI version of the linked napi-c Nexmon shim (`major << 16 | minor`).
#[napi]
pub fn nexmon_shim_abi_version() -> u32 {
    runtime::nexmon_shim_abi_version()
}

/// Decode a `Buffer` of "rvCSI Nexmon records" (the napi-c shim format) into a
/// JSON array of validated `CsiFrame`s. Throws on a malformed record.
#[napi]
pub fn nexmon_decode_records(buf: Buffer, source_id: String, session_id: u32) -> napi::Result<String> {
    let frames = runtime::decode_nexmon_records(buf.as_ref(), &source_id, session_id as u64).map_err(napi_err)?;
    to_json(&frames)
}

/// Summarize a `.rvcsi` capture file; returns JSON for a `CaptureSummary`.
#[napi]
pub fn inspect_capture_file(path: String) -> napi::Result<String> {
    let summary = runtime::summarize_capture(&path).map_err(napi_err)?;
    to_json(&summary)
}

/// Replay a `.rvcsi` capture through the DSP + event pipeline; returns a JSON
/// array of `CsiEvent`s.
#[napi]
pub fn events_from_capture_file(path: String) -> napi::Result<String> {
    let events = runtime::events_from_capture(&path).map_err(napi_err)?;
    to_json(&events)
}

/// Replay a `.rvcsi` capture, window it, and store each window's embedding into
/// a JSONL RF-memory file; returns the number of windows stored.
#[napi]
pub fn export_capture_to_rf_memory(capture_path: String, out_jsonl_path: String) -> napi::Result<u32> {
    let n = runtime::export_capture_to_rf_memory(&capture_path, &out_jsonl_path).map_err(napi_err)?;
    Ok(n as u32)
}

/// Decode the *real* nexmon_csi UDP payloads inside a libpcap `.pcap` `Buffer`
/// into a JSON array of validated `CsiFrame`s. `port` is the CSI UDP port
/// (omit / `null` ⇒ 5500); `chip` is an optional chip / Raspberry-Pi-model spec
/// (`"pi5"`, `"bcm43455c0"`, ...) — when given, frames are validated against
/// that device's profile and the non-conforming ones dropped. Throws if the
/// buffer isn't a parseable classic pcap or `chip` is unrecognised.
#[napi]
pub fn nexmon_decode_pcap(
    pcap: Buffer,
    source_id: String,
    session_id: u32,
    port: Option<u16>,
    chip: Option<String>,
) -> napi::Result<String> {
    let frames = runtime::decode_nexmon_pcap_for(pcap.as_ref(), &source_id, session_id as u64, port, chip.as_deref())
        .map_err(napi_err)?;
    to_json(&frames)
}

/// Summarize a nexmon_csi `.pcap` file (link type, frame counts, channels,
/// bandwidths, chip versions + resolved chip names, RSSI range, time span);
/// returns JSON for a `NexmonPcapSummary`. `port` defaults to 5500.
#[napi]
pub fn inspect_nexmon_pcap(path: String, port: Option<u16>) -> napi::Result<String> {
    let summary = runtime::summarize_nexmon_pcap(&path, port).map_err(napi_err)?;
    to_json(&summary)
}

/// Decode a Broadcom d11ac chanspec word; returns JSON
/// `{ chanspec, channel, bandwidth_mhz, is_5ghz }`.
#[napi]
pub fn decode_chanspec(chanspec: u32) -> napi::Result<String> {
    let d = rvcsi_adapter_nexmon::decode_chanspec((chanspec & 0xFFFF) as u16);
    to_json(&serde_json::json!({
        "chanspec": d.chanspec,
        "channel": d.channel,
        "bandwidth_mhz": d.bandwidth_mhz,
        "is_5ghz": d.is_5ghz,
    }))
}

/// Resolve a `chip_ver` word from a nexmon_csi packet to a chip slug
/// (`"bcm43455c0"` for a Raspberry Pi 3B+/4/400/5; `"unknown:0xNNNN"` otherwise).
#[napi]
pub fn nexmon_chip_name(chip_ver: u32) -> String {
    rvcsi_adapter_nexmon::NexmonChip::from_chip_ver((chip_ver & 0xFFFF) as u16).slug()
}

/// The `AdapterProfile` (channels / bandwidths / expected subcarrier counts /
/// capability flags) for a chip / Raspberry-Pi-model spec (`"pi5"`,
/// `"bcm43455c0"`, `"raspberry pi 4"`, ...); returns JSON. Throws if unknown.
#[napi]
pub fn nexmon_profile(spec: String) -> napi::Result<String> {
    let p = runtime::nexmon_profile_for(&spec)
        .ok_or_else(|| napi::Error::from_reason(format!("unknown nexmon chip / Raspberry Pi model `{spec}`")))?;
    to_json(&p)
}

/// JSON listing of the Nexmon-supported chips + the Raspberry Pi models that
/// carry them (incl. the Pi 5 → BCM43455c0): `{ chips: [...], raspberryPiModels: [...] }`.
#[napi]
pub fn nexmon_chips() -> napi::Result<String> {
    use rvcsi_adapter_nexmon::{known_chips, known_pi_models, nexmon_adapter_profile, NexmonChip};
    let chips: Vec<_> = known_chips()
        .iter()
        .map(|c| {
            let p = nexmon_adapter_profile(*c);
            serde_json::json!({
                "slug": c.slug(), "description": c.description(),
                "dualBand": c.dual_band(), "int16IqExport": c.uses_int16_iq(),
                "bandwidthsMhz": p.supported_bandwidths_mhz,
                "expectedSubcarrierCounts": p.expected_subcarrier_counts,
            })
        })
        .collect();
    let pis: Vec<_> = known_pi_models()
        .iter()
        .map(|m| {
            let chip = m.nexmon_chip();
            serde_json::json!({
                "slug": m.slug(),
                "chip": if matches!(chip, NexmonChip::Unknown { .. }) { serde_json::Value::Null } else { serde_json::Value::String(chip.slug()) },
                "csiSupported": m.csi_supported(),
            })
        })
        .collect();
    to_json(&serde_json::json!({ "chips": chips, "raspberryPiModels": pis }))
}

// ---------------------------------------------------------------------------
// Streaming runtime class
// ---------------------------------------------------------------------------

/// A streaming capture runtime: a source + the DSP stage + the event pipeline.
#[napi]
pub struct RvcsiRuntime {
    inner: CaptureRuntime,
}

#[napi]
impl RvcsiRuntime {
    /// Open a `.rvcsi` capture file as the source.
    #[napi(factory)]
    pub fn open_capture_file(path: String) -> napi::Result<RvcsiRuntime> {
        Ok(RvcsiRuntime {
            inner: CaptureRuntime::open_capture_file(&path).map_err(napi_err)?,
        })
    }

    /// Open a Nexmon capture file (concatenated rvCSI Nexmon records) as the source.
    #[napi(factory)]
    pub fn open_nexmon_file(path: String, source_id: String, session_id: u32) -> napi::Result<RvcsiRuntime> {
        Ok(RvcsiRuntime {
            inner: CaptureRuntime::open_nexmon_file(&path, &source_id, session_id as u64).map_err(napi_err)?,
        })
    }

    /// Open a real nexmon_csi `.pcap` capture as the source. `port` is the CSI
    /// UDP port (omit / `null` ⇒ 5500).
    #[napi(factory)]
    pub fn open_nexmon_pcap(
        path: String,
        source_id: String,
        session_id: u32,
        port: Option<u16>,
    ) -> napi::Result<RvcsiRuntime> {
        Ok(RvcsiRuntime {
            inner: CaptureRuntime::open_nexmon_pcap(&path, &source_id, session_id as u64, port)
                .map_err(napi_err)?,
        })
    }

    /// Next exposable, validated frame as JSON, or `null` at end-of-stream.
    #[napi]
    pub fn next_frame_json(&mut self) -> napi::Result<Option<String>> {
        match self.inner.next_validated_frame().map_err(napi_err)? {
            Some(f) => Ok(Some(to_json(&f)?)),
            None => Ok(None),
        }
    }

    /// Like `nextFrameJson` but with the DSP pipeline applied (cleaned amplitude/phase).
    #[napi]
    pub fn next_clean_frame_json(&mut self) -> napi::Result<Option<String>> {
        match self.inner.next_clean_frame().map_err(napi_err)? {
            Some(f) => Ok(Some(to_json(&f)?)),
            None => Ok(None),
        }
    }

    /// Drain the rest of the stream through DSP + the event pipeline; JSON array of `CsiEvent`s.
    #[napi]
    pub fn drain_events_json(&mut self) -> napi::Result<String> {
        let events = self.inner.drain_events().map_err(napi_err)?;
        to_json(&events)
    }

    /// Health snapshot as JSON (`SourceHealth`).
    #[napi]
    pub fn health_json(&self) -> napi::Result<String> {
        to_json(&self.inner.health())
    }

    /// Frames pulled from the source so far.
    #[napi(getter)]
    pub fn frames_seen(&self) -> u32 {
        self.inner.frames_seen() as u32
    }

    /// Frames dropped by validation so far.
    #[napi(getter)]
    pub fn frames_dropped(&self) -> u32 {
        self.inner.frames_dropped() as u32
    }
}

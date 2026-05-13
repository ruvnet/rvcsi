//! One-shot capture operations: summarize a `.rvcsi` file, decode a buffer of
//! napi-c Nexmon records, replay a capture into events, export windows to a
//! JSONL RF-memory file. Everything returns normalized/validated rvCSI types —
//! frames are always run through `validate_frame` and never returned `Pending`
//! or `Rejected` (ADR-095 D6).

use serde::{Deserialize, Serialize};

use rvcsi_adapter_file::{read_all, CaptureHeader};
use rvcsi_adapter_nexmon::NexmonAdapter;
use rvcsi_core::{
    validate_frame, AdapterProfile, CsiEvent, CsiFrame, RvcsiError, SessionId, SourceId,
    ValidationPolicy, ValidationStatus,
};
use rvcsi_dsp::SignalPipeline;
use rvcsi_events::EventPipeline;
use rvcsi_ruvector::{window_embedding, InMemoryRfMemory, JsonlRfMemory, RfMemoryStore};

/// A compact summary of a `.rvcsi` capture file (the `rvcsi inspect` payload /
/// the `inspectCaptureFile` napi return).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureSummary {
    /// The recorded capture format version.
    pub capture_version: u32,
    /// Session id from the header.
    pub session_id: u64,
    /// Source id from the header.
    pub source_id: String,
    /// Adapter kind slug from the header's profile.
    pub adapter_kind: String,
    /// The header's adapter-profile `chip` string, if any (e.g. `"bcm43455c0 (pi5)"`).
    pub chip: Option<String>,
    /// Number of frames in the capture.
    pub frame_count: usize,
    /// First / last frame timestamp (ns); `0` for an empty capture.
    pub first_timestamp_ns: u64,
    /// Last frame timestamp (ns).
    pub last_timestamp_ns: u64,
    /// Distinct WiFi channels seen.
    pub channels: Vec<u16>,
    /// Distinct subcarrier counts seen.
    pub subcarrier_counts: Vec<u16>,
    /// Mean `quality_score` over all frames (`0.0` for an empty capture).
    pub mean_quality: f32,
    /// Count of frames by `ValidationStatus` (`accepted`, `degraded`, `recovered`,
    /// `rejected`, `pending`).
    pub validation_breakdown: ValidationBreakdown,
    /// Calibration version recorded in the header, if any.
    pub calibration_version: Option<String>,
}

/// Per-`ValidationStatus` frame counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationBreakdown {
    /// `ValidationStatus::Pending`
    pub pending: usize,
    /// `ValidationStatus::Accepted`
    pub accepted: usize,
    /// `ValidationStatus::Degraded`
    pub degraded: usize,
    /// `ValidationStatus::Rejected`
    pub rejected: usize,
    /// `ValidationStatus::Recovered`
    pub recovered: usize,
}

impl ValidationBreakdown {
    fn tally(&mut self, s: ValidationStatus) {
        match s {
            ValidationStatus::Pending => self.pending += 1,
            ValidationStatus::Accepted => self.accepted += 1,
            ValidationStatus::Degraded => self.degraded += 1,
            ValidationStatus::Rejected => self.rejected += 1,
            ValidationStatus::Recovered => self.recovered += 1,
        }
    }
}

fn sorted_unique<T: Ord + Copy>(mut v: Vec<T>) -> Vec<T> {
    v.sort_unstable();
    v.dedup();
    v
}

/// Summarize a `.rvcsi` capture file.
pub fn summarize_capture(path: &str) -> Result<CaptureSummary, RvcsiError> {
    let (header, frames): (CaptureHeader, Vec<CsiFrame>) = read_all(path)?;
    let mut channels = Vec::new();
    let mut subcarrier_counts = Vec::new();
    let mut breakdown = ValidationBreakdown::default();
    let mut quality_sum = 0.0f32;
    let (mut first_ts, mut last_ts) = (u64::MAX, 0u64);
    for f in &frames {
        channels.push(f.channel);
        subcarrier_counts.push(f.subcarrier_count);
        breakdown.tally(f.validation);
        quality_sum += f.quality_score;
        first_ts = first_ts.min(f.timestamp_ns);
        last_ts = last_ts.max(f.timestamp_ns);
    }
    if frames.is_empty() {
        first_ts = 0;
    }
    Ok(CaptureSummary {
        capture_version: header.rvcsi_capture_version,
        session_id: header.session_id.value(),
        source_id: header.source_id.0,
        adapter_kind: header.adapter_profile.adapter_kind.slug().to_string(),
        chip: header.adapter_profile.chip.clone(),
        frame_count: frames.len(),
        first_timestamp_ns: first_ts,
        last_timestamp_ns: last_ts,
        channels: sorted_unique(channels),
        subcarrier_counts: sorted_unique(subcarrier_counts),
        mean_quality: if frames.is_empty() {
            0.0
        } else {
            quality_sum / frames.len() as f32
        },
        validation_breakdown: breakdown,
        calibration_version: header.calibration_version,
    })
}

/// Validate a batch of raw (`Pending`) frames against `profile`, in timestamp
/// order; drop the hard-rejected ones and return the survivors.
fn validate_frames_against(raw: Vec<CsiFrame>, profile: &AdapterProfile) -> Vec<CsiFrame> {
    let policy = ValidationPolicy::default();
    let mut out = Vec::with_capacity(raw.len());
    let mut prev_ts: Option<u64> = None;
    for mut f in raw {
        let ts = f.timestamp_ns;
        if f.validation == ValidationStatus::Pending {
            match validate_frame(&mut f, profile, &policy, prev_ts) {
                Ok(()) if f.is_exposable() => {
                    prev_ts = Some(ts);
                    out.push(f);
                }
                _ => { /* hard-rejected — dropped */ }
            }
        } else if f.is_exposable() {
            out.push(f);
        }
    }
    out
}

/// Validate against a permissive (offline-Nexmon) profile — accepts any
/// subcarrier count / channel. Used when no specific chip was requested.
fn validate_frames_permissive(raw: Vec<CsiFrame>) -> Vec<CsiFrame> {
    validate_frames_against(raw, &AdapterProfile::offline(rvcsi_core::AdapterKind::Nexmon))
}

/// Resolve a chip / Raspberry-Pi-model spec (`"pi5"`, `"bcm43455c0"`,
/// `"raspberry pi 4"`, `"4366c0"`, ...) to an [`AdapterProfile`], for the
/// `--chip` flag and SDK callers. Returns `None` for an unknown spec.
pub fn nexmon_profile_for(spec: &str) -> Option<AdapterProfile> {
    if let Some(model) = rvcsi_adapter_nexmon::RaspberryPiModel::from_slug(spec) {
        return Some(rvcsi_adapter_nexmon::raspberry_pi_profile(model));
    }
    rvcsi_adapter_nexmon::NexmonChip::from_slug(spec)
        .map(rvcsi_adapter_nexmon::nexmon_adapter_profile)
}

/// Decode a buffer of "rvCSI Nexmon records" (the napi-c shim format) into
/// validated [`CsiFrame`]s. Frames that hard-fail validation are dropped (never
/// returned to JS).
pub fn decode_nexmon_records(
    bytes: &[u8],
    source_id: &str,
    session_id: u64,
) -> Result<Vec<CsiFrame>, RvcsiError> {
    let raw = NexmonAdapter::frames_from_bytes(SourceId::from(source_id), SessionId(session_id), bytes)?;
    Ok(validate_frames_permissive(raw))
}

/// Decode the *real* nexmon_csi UDP payloads inside a libpcap (`.pcap`) buffer
/// into validated [`CsiFrame`]s. `port` is the CSI UDP port (`None` ⇒ 5500).
/// Validation is permissive (any subcarrier count / channel survives); pass a
/// chip spec to [`decode_nexmon_pcap_for`] to bound against a specific device.
pub fn decode_nexmon_pcap(
    pcap_bytes: &[u8],
    source_id: &str,
    session_id: u64,
    port: Option<u16>,
) -> Result<Vec<CsiFrame>, RvcsiError> {
    decode_nexmon_pcap_for(pcap_bytes, source_id, session_id, port, None)
}

/// Like [`decode_nexmon_pcap`] but, when `chip_spec` is `Some` (`"pi5"`,
/// `"bcm43455c0"`, ...), validates each frame against that device's profile and
/// drops the non-conforming ones (e.g. a 256-subcarrier VHT80 frame against a
/// 2.4 GHz-only `bcm43436b0` profile). An unrecognised spec is a `Config` error.
pub fn decode_nexmon_pcap_for(
    pcap_bytes: &[u8],
    source_id: &str,
    session_id: u64,
    port: Option<u16>,
    chip_spec: Option<&str>,
) -> Result<Vec<CsiFrame>, RvcsiError> {
    let raw = rvcsi_adapter_nexmon::NexmonPcapAdapter::frames_from_pcap_bytes(
        SourceId::from(source_id),
        SessionId(session_id),
        pcap_bytes,
        port,
    )?;
    match chip_spec {
        None => Ok(validate_frames_permissive(raw)),
        Some(spec) => {
            let profile = nexmon_profile_for(spec)
                .ok_or_else(|| RvcsiError::Config(format!("unknown nexmon chip / Raspberry Pi model `{spec}`")))?;
            Ok(validate_frames_against(raw, &profile))
        }
    }
}

/// A compact summary of a nexmon_csi `.pcap` capture (the `rvcsi inspect-nexmon`
/// payload).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NexmonPcapSummary {
    /// libpcap link-layer type of the capture.
    pub link_type: u32,
    /// CSI frames decoded from the capture.
    pub csi_frame_count: usize,
    /// Non-CSI / skipped UDP packets (wrong port, not IPv4/UDP, bad nexmon magic).
    pub skipped_packets: u64,
    /// First / last CSI packet timestamp (ns since the Unix epoch); `0` if empty.
    pub first_timestamp_ns: u64,
    /// Last CSI packet timestamp (ns).
    pub last_timestamp_ns: u64,
    /// Distinct WiFi channels seen (decoded from the chanspec).
    pub channels: Vec<u16>,
    /// Distinct bandwidths (MHz) seen.
    pub bandwidths_mhz: Vec<u16>,
    /// Distinct subcarrier (FFT) counts seen.
    pub subcarrier_counts: Vec<u16>,
    /// Distinct chip-version words seen (e.g. `0x4345` = the BCM4345 family).
    pub chip_versions: Vec<u16>,
    /// Distinct resolved chip slugs (`"bcm43455c0"` for a Raspberry Pi 3B+/4/400/5; `"unknown:0xNNNN"` otherwise).
    pub chip_names: Vec<String>,
    /// The chip the adapter settled on (all packets agreed) — `"bcm43455c0"` for a Pi 5 capture.
    pub detected_chip: String,
    /// Min / max RSSI (dBm) over the CSI packets; `None` if empty.
    pub rssi_dbm_range: Option<(i16, i16)>,
}

/// Summarize a nexmon_csi `.pcap` file (link type, frame counts, channels, etc.).
pub fn summarize_nexmon_pcap(path: &str, port: Option<u16>) -> Result<NexmonPcapSummary, RvcsiError> {
    let bytes = std::fs::read(path)?;
    let adapter = rvcsi_adapter_nexmon::NexmonPcapAdapter::parse(
        SourceId::from(format!("pcap:{path}")),
        SessionId(0),
        &bytes,
        port,
    )?;
    let health = adapter.health();
    let detected_chip = adapter.detected_chip().slug();
    let headers = adapter.headers();
    let mut channels = Vec::new();
    let mut bandwidths = Vec::new();
    let mut subs = Vec::new();
    let mut chips = Vec::new();
    let mut chip_names = Vec::new();
    let (mut rssi_lo, mut rssi_hi) = (i16::MAX, i16::MIN);
    for h in headers {
        channels.push(h.channel);
        bandwidths.push(h.bandwidth_mhz);
        subs.push(h.subcarrier_count);
        chips.push(h.chip_ver);
        chip_names.push(h.chip().slug());
        rssi_lo = rssi_lo.min(h.rssi_dbm);
        rssi_hi = rssi_hi.max(h.rssi_dbm);
    }
    chip_names.sort();
    chip_names.dedup();
    let (mut first_ts, mut last_ts) = (u64::MAX, 0u64);
    // re-iterate frames for timestamps (headers don't carry the pcap time)
    let mut a2 = rvcsi_adapter_nexmon::NexmonPcapAdapter::parse(
        SourceId::from("pcap-ts"),
        SessionId(0),
        &bytes,
        port,
    )?;
    use rvcsi_core::CsiSource;
    while let Some(f) = a2.next_frame()? {
        first_ts = first_ts.min(f.timestamp_ns);
        last_ts = last_ts.max(f.timestamp_ns);
    }
    if headers.is_empty() {
        first_ts = 0;
    }
    Ok(NexmonPcapSummary {
        link_type: adapter.link_type(),
        csi_frame_count: headers.len(),
        skipped_packets: health.frames_rejected,
        first_timestamp_ns: first_ts,
        last_timestamp_ns: last_ts,
        channels: sorted_unique(channels),
        bandwidths_mhz: sorted_unique(bandwidths),
        subcarrier_counts: sorted_unique(subs),
        chip_versions: sorted_unique(chips),
        chip_names,
        detected_chip,
        rssi_dbm_range: (!headers.is_empty()).then_some((rssi_lo, rssi_hi)),
    })
}

/// Replay a `.rvcsi` capture through the DSP + event pipeline and collect every
/// emitted [`CsiEvent`]. Frames that arrive `Pending` are validated first;
/// already-validated frames are trusted (replay fidelity).
pub fn events_from_capture(path: &str) -> Result<Vec<CsiEvent>, RvcsiError> {
    let (header, frames) = read_all(path)?;
    let dsp = SignalPipeline::default();
    let mut pipeline = EventPipeline::with_defaults(header.session_id, header.source_id.clone());
    let profile = header.adapter_profile.clone();
    let policy = header.validation_policy.clone();
    let mut prev_ts: Option<u64> = None;
    let mut events = Vec::new();
    for mut f in frames {
        if f.validation == ValidationStatus::Pending {
            let ts = f.timestamp_ns;
            if validate_frame(&mut f, &profile, &policy, prev_ts).is_err() || !f.is_exposable() {
                continue;
            }
            prev_ts = Some(ts);
        }
        dsp.process_frame(&mut f);
        events.extend(pipeline.process_frame(&f));
    }
    events.extend(pipeline.flush());
    Ok(events)
}

/// Replay a `.rvcsi` capture, window it, and store every window's embedding into
/// a JSONL RF-memory file (the `rvcsi export ruvector` payload). Returns the
/// number of windows stored.
pub fn export_capture_to_rf_memory(capture_path: &str, out_jsonl_path: &str) -> Result<usize, RvcsiError> {
    let (header, frames) = read_all(capture_path)?;
    let mut pipeline = EventPipeline::with_defaults(header.session_id, header.source_id.clone());
    let dsp = SignalPipeline::default();
    let mut store = JsonlRfMemory::create(out_jsonl_path)?;
    let mut stored = 0usize;
    for mut f in frames {
        if !f.is_exposable() {
            continue;
        }
        dsp.process_frame(&mut f);
        let _ = pipeline.process_frame(&f);
    }
    let _ = pipeline.flush();
    for w in pipeline.recent_windows() {
        store.store_window(w)?;
        stored += 1;
    }
    Ok(stored)
}

/// Convenience used by tests / examples: window a capture in memory and return
/// `(window_count, top_self_similarity)` — storing each window then querying
/// with the first window's embedding should yield itself with score ≈ 1.0.
pub fn rf_memory_self_check(capture_path: &str) -> Result<(usize, f32), RvcsiError> {
    let (header, frames) = read_all(capture_path)?;
    let mut pipeline = EventPipeline::with_defaults(header.session_id, header.source_id.clone());
    for f in &frames {
        if f.is_exposable() {
            let _ = pipeline.process_frame(f);
        }
    }
    let _ = pipeline.flush();
    let windows: Vec<_> = pipeline.recent_windows().to_vec();
    let mut store = InMemoryRfMemory::new();
    for w in &windows {
        store.store_window(w)?;
    }
    if windows.is_empty() {
        return Ok((0, 0.0));
    }
    let q = window_embedding(&windows[0]);
    let hits = store.query_similar(&q, 1)?;
    Ok((windows.len(), hits.first().map(|h| h.score).unwrap_or(0.0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_adapter_file::FileRecorder;
    use rvcsi_adapter_nexmon::{encode_record, NexmonCsiHeader, NexmonRecord};
    use rvcsi_core::{AdapterKind, FrameId};

    fn write_capture(path: &std::path::Path, n: usize) {
        let header = CaptureHeader::new(
            SessionId(1),
            SourceId::from("it"),
            AdapterProfile::offline(AdapterKind::File),
        );
        let mut rec = FileRecorder::create(path, &header).unwrap();
        for k in 0..n {
            // alternate "quiet" and "active" amplitudes so the event pipeline has something to do
            let amp_scale = if (k / 8) % 2 == 0 { 0.0 } else { 1.5 };
            let i: Vec<f32> = (0..32).map(|s| 1.0 + amp_scale * (((k + s) % 5) as f32 - 2.0)).collect();
            let q: Vec<f32> = (0..32).map(|s| 0.5 + amp_scale * (((k * 3 + s) % 7) as f32 - 3.0) * 0.1).collect();
            let mut f = CsiFrame::from_iq(
                FrameId(k as u64),
                SessionId(1),
                SourceId::from("it"),
                AdapterKind::File,
                1_000 + k as u64 * 50_000_000, // 50 ms apart
                6,
                20,
                i,
                q,
            )
            .with_rssi(-55);
            f.validation = ValidationStatus::Accepted;
            f.quality_score = 0.9;
            rec.write_frame(&f).unwrap();
        }
        rec.finish().unwrap();
    }

    #[test]
    fn summarize_a_recorded_capture() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 10);
        let s = summarize_capture(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(s.capture_version, 1);
        assert_eq!(s.session_id, 1);
        assert_eq!(s.frame_count, 10);
        assert_eq!(s.channels, vec![6]);
        assert_eq!(s.subcarrier_counts, vec![32]);
        assert_eq!(s.validation_breakdown.accepted, 10);
        assert!((s.mean_quality - 0.9).abs() < 1e-5);
        assert_eq!(s.first_timestamp_ns, 1_000);
        assert!(s.last_timestamp_ns > s.first_timestamp_ns);
    }

    #[test]
    fn summarize_empty_capture() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = CaptureHeader::new(SessionId(9), SourceId::from("e"), AdapterProfile::offline(AdapterKind::File));
        FileRecorder::create(tmp.path(), &header).unwrap().finish().unwrap();
        let s = summarize_capture(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(s.frame_count, 0);
        assert_eq!(s.mean_quality, 0.0);
        assert_eq!(s.first_timestamp_ns, 0);
    }

    #[test]
    fn decode_nexmon_records_validates_and_returns_frames() {
        // two 64-subcarrier records
        let mk = |ts: u64, rssi: i16| {
            let rec = NexmonRecord {
                subcarrier_count: 64,
                channel: 36,
                bandwidth_mhz: 80,
                rssi_dbm: Some(rssi),
                noise_floor_dbm: Some(-92),
                timestamp_ns: ts,
                i_values: (0..64).map(|k| (k as f32) * 0.25).collect(),
                q_values: (0..64).map(|k| -(k as f32) * 0.1).collect(),
            };
            encode_record(&rec).unwrap()
        };
        let mut buf = mk(1_000, -58);
        buf.extend(mk(2_000, -59));
        let frames = decode_nexmon_records(&buf, "nexmon-test", 7).unwrap();
        assert_eq!(frames.len(), 2);
        for f in &frames {
            assert!(f.is_exposable());
            assert_eq!(f.subcarrier_count, 64);
            assert_eq!(f.adapter_kind, AdapterKind::Nexmon);
        }
        assert_eq!(frames[1].timestamp_ns, 2_000);
    }

    #[test]
    fn events_and_export_from_capture() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 64);
        let events = events_from_capture(tmp.path().to_str().unwrap()).unwrap();
        // the alternating quiet/active stream should produce at least one event,
        // and every event must be well-formed.
        assert!(!events.is_empty(), "expected the event pipeline to emit something");
        for e in &events {
            e.validate().unwrap();
            assert!((0.0..=1.0).contains(&e.confidence));
            assert!(!e.evidence_window_ids.is_empty());
        }

        let out = tempfile::NamedTempFile::new().unwrap();
        let stored = export_capture_to_rf_memory(
            tmp.path().to_str().unwrap(),
            out.path().to_str().unwrap(),
        )
        .unwrap();
        assert!(stored > 0);
        // re-open the JSONL store and confirm the records round-tripped
        let reopened = JsonlRfMemory::open(out.path().to_str().unwrap()).unwrap();
        assert_eq!(reopened.len(), stored);

        let (wc, score) = rf_memory_self_check(tmp.path().to_str().unwrap()).unwrap();
        assert!(wc > 0);
        assert!((score - 1.0).abs() < 1e-4, "self-similarity should be ~1.0, got {score}");
    }

    #[test]
    fn missing_capture_file_is_a_structured_error() {
        assert!(summarize_capture("/nonexistent/path/x.rvcsi").is_err());
        assert!(events_from_capture("/nonexistent/path/x.rvcsi").is_err());
        assert!(decode_nexmon_pcap(&[0u8; 8], "s", 0, None).is_err());
        assert!(summarize_nexmon_pcap("/nonexistent/path/x.pcap", None).is_err());
    }

    fn synth_nexmon_header(rssi: i16, chanspec: u16, nsub: u16, seq: u16) -> NexmonCsiHeader {
        NexmonCsiHeader {
            rssi_dbm: rssi,
            fctl: 0x08,
            src_mac: [0, 1, 2, 3, 4, 5],
            seq_cnt: seq,
            core: 0,
            spatial_stream: 0,
            chanspec,
            chip_ver: 0x4345,
            channel: 0,
            bandwidth_mhz: 0,
            is_5ghz: false,
            subcarrier_count: nsub,
        }
    }

    fn synth_nexmon_pcap_bytes() -> Vec<u8> {
        let chanspec = 0xc000u16 | 0x2000 | 36; // 5 GHz ch36 80 MHz
        let nsub = 256u16;
        let frames: Vec<(u64, NexmonCsiHeader, Vec<f32>, Vec<f32>)> = (0..4u64)
            .map(|k| {
                let i: Vec<f32> = (0..nsub).map(|s| (s as i16 - 128 + k as i16) as f32).collect();
                let q: Vec<f32> = (0..nsub).map(|s| (s as i16 % 7 + k as i16) as f32).collect();
                (1_000_000_000 + k * 50_000_000, synth_nexmon_header(-58 - k as i16, chanspec, nsub, k as u16 + 1), i, q)
            })
            .collect();
        rvcsi_adapter_nexmon::synthetic_nexmon_pcap(&frames, 5500).expect("build pcap")
    }

    #[test]
    fn decode_nexmon_pcap_yields_validated_frames() {
        let pcap = synth_nexmon_pcap_bytes();
        let frames = decode_nexmon_pcap(&pcap, "nexmon-pcap", 7, None).unwrap();
        assert_eq!(frames.len(), 4);
        for f in &frames {
            assert!(f.is_exposable());
            assert_eq!(f.adapter_kind, AdapterKind::Nexmon);
            assert_eq!(f.channel, 36);
            assert_eq!(f.bandwidth_mhz, 80);
            assert_eq!(f.subcarrier_count, 256);
        }
        assert_eq!(frames[0].timestamp_ns, 1_000_000_000);
        assert_eq!(frames[3].timestamp_ns, 1_000_000_000 + 3 * 50_000_000);
        // explicit-port form works too
        assert_eq!(decode_nexmon_pcap(&pcap, "s", 0, Some(5500)).unwrap().len(), 4);
        assert_eq!(decode_nexmon_pcap(&pcap, "s", 0, Some(9999)).unwrap().len(), 0);

        // --chip pi5 / bcm43455c0: the 256-sc VHT80 ch36 frames all conform
        assert_eq!(decode_nexmon_pcap_for(&pcap, "s", 0, None, Some("pi5")).unwrap().len(), 4);
        assert_eq!(decode_nexmon_pcap_for(&pcap, "s", 0, None, Some("bcm43455c0")).unwrap().len(), 4);
        // --chip pizero2w (bcm43436b0): 2.4 GHz only, max 128 sc -> all dropped
        assert_eq!(decode_nexmon_pcap_for(&pcap, "s", 0, None, Some("pizero2w")).unwrap().len(), 0);
        // unknown spec -> Config error
        assert!(decode_nexmon_pcap_for(&pcap, "s", 0, None, Some("not-a-chip")).is_err());
        // nexmon_profile_for resolves both chip slugs and Pi model slugs
        assert!(nexmon_profile_for("pi5").is_some());
        assert!(nexmon_profile_for("bcm4366c0").is_some());
        assert!(nexmon_profile_for("nope").is_none());
    }

    #[test]
    fn summarize_nexmon_pcap_reports_metadata_and_pi5_chip() {
        let pcap = synth_nexmon_pcap_bytes();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &pcap).unwrap();
        let s = summarize_nexmon_pcap(tmp.path().to_str().unwrap(), None).unwrap();
        assert_eq!(s.link_type, rvcsi_adapter_nexmon::LINKTYPE_ETHERNET);
        assert_eq!(s.csi_frame_count, 4);
        assert_eq!(s.channels, vec![36]);
        assert_eq!(s.bandwidths_mhz, vec![80]);
        assert_eq!(s.subcarrier_counts, vec![256]);
        assert_eq!(s.chip_versions, vec![0x4345]);
        // 0x4345 resolves to the BCM43455c0 — the chip on a Raspberry Pi 3B+/4/400/5
        assert_eq!(s.chip_names, vec!["bcm43455c0".to_string()]);
        assert_eq!(s.detected_chip, "bcm43455c0");
        assert_eq!(s.rssi_dbm_range, Some((-61, -58)));
        assert_eq!(s.first_timestamp_ns, 1_000_000_000);
        assert!(s.last_timestamp_ns > s.first_timestamp_ns);
    }
}

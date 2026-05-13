//! A streaming capture runtime: a [`CsiSource`](rvcsi_core::CsiSource) + the DSP
//! stage + the event pipeline, wired together. The `rvcsi-node` napi-rs
//! `RvcsiRuntime` class is a thin `#[napi]` wrapper around [`CaptureRuntime`].

use rvcsi_adapter_file::FileReplayAdapter;
use rvcsi_adapter_nexmon::NexmonAdapter;
use rvcsi_core::{
    validate_frame, AdapterProfile, CsiEvent, CsiFrame, CsiSource, RvcsiError, SessionId,
    SourceHealth, SourceId, ValidationPolicy, ValidationStatus,
};
use rvcsi_dsp::SignalPipeline;
use rvcsi_events::EventPipeline;

/// Owns a source and the per-frame processing chain.
///
/// `next_validated_frame` pulls from the source and guarantees the returned
/// frame is *exposable* (Accepted/Degraded/Recovered) — frames that arrive
/// `Pending` are validated against the source's profile, and hard-rejected
/// frames are skipped (never surfaced). `drain_events` runs the remainder of the
/// stream through `SignalPipeline` + `EventPipeline`.
pub struct CaptureRuntime {
    source: Box<dyn CsiSource>,
    profile: AdapterProfile,
    policy: ValidationPolicy,
    dsp: SignalPipeline,
    events: EventPipeline,
    prev_ts: Option<u64>,
    frames_seen: u64,
    frames_dropped: u64,
}

impl CaptureRuntime {
    fn new(source: Box<dyn CsiSource>, policy: ValidationPolicy) -> Self {
        let profile = source.profile().clone();
        let session_id = source.session_id();
        let source_id = source.source_id().clone();
        CaptureRuntime {
            source,
            profile,
            policy,
            dsp: SignalPipeline::default(),
            events: EventPipeline::with_defaults(session_id, source_id),
            prev_ts: None,
            frames_seen: 0,
            frames_dropped: 0,
        }
    }

    /// Open a `.rvcsi` capture file as the source.
    pub fn open_capture_file(path: &str) -> Result<Self, RvcsiError> {
        let source = FileReplayAdapter::open(path)?;
        Ok(Self::new(Box::new(source), ValidationPolicy::default()))
    }

    /// Open a buffer of "rvCSI Nexmon records" (the napi-c shim format) as the source.
    pub fn open_nexmon_bytes(bytes: Vec<u8>, source_id: &str, session_id: u64) -> Self {
        let source = NexmonAdapter::from_bytes(SourceId::from(source_id), SessionId(session_id), bytes);
        // Permissive policy: the C-shim records may carry non-default subcarrier counts.
        Self::new(Box::new(source), ValidationPolicy::default())
    }

    /// Open a Nexmon capture *file* (concatenated records) as the source.
    pub fn open_nexmon_file(path: &str, source_id: &str, session_id: u64) -> Result<Self, RvcsiError> {
        let bytes = std::fs::read(path)?;
        Ok(Self::open_nexmon_bytes(bytes, source_id, session_id))
    }

    /// Open a real nexmon_csi `.pcap` capture (`tcpdump -i wlan0 dst port 5500 -w …`)
    /// as the source. `port` is the CSI UDP port (`None` ⇒ 5500).
    pub fn open_nexmon_pcap(
        path: &str,
        source_id: &str,
        session_id: u64,
        port: Option<u16>,
    ) -> Result<Self, RvcsiError> {
        let source = rvcsi_adapter_nexmon::NexmonPcapAdapter::open(
            SourceId::from(source_id),
            SessionId(session_id),
            path,
            port,
        )?;
        Ok(Self::new(Box::new(source), ValidationPolicy::default()))
    }

    /// Open a real nexmon_csi `.pcap` from an in-memory byte buffer.
    pub fn open_nexmon_pcap_bytes(
        pcap_bytes: &[u8],
        source_id: &str,
        session_id: u64,
        port: Option<u16>,
    ) -> Result<Self, RvcsiError> {
        let source = rvcsi_adapter_nexmon::NexmonPcapAdapter::parse(
            SourceId::from(source_id),
            SessionId(session_id),
            pcap_bytes,
            port,
        )?;
        Ok(Self::new(Box::new(source), ValidationPolicy::default()))
    }

    /// Validate (if needed) a freshly pulled frame; `None` if it was hard-rejected.
    fn admit(&mut self, mut frame: CsiFrame) -> Option<CsiFrame> {
        self.frames_seen += 1;
        if frame.validation == ValidationStatus::Pending {
            let ts = frame.timestamp_ns;
            match validate_frame(&mut frame, &self.profile, &self.policy, self.prev_ts) {
                Ok(()) if frame.is_exposable() => {
                    self.prev_ts = Some(ts);
                    Some(frame)
                }
                _ => {
                    self.frames_dropped += 1;
                    None
                }
            }
        } else if frame.is_exposable() {
            Some(frame)
        } else {
            self.frames_dropped += 1;
            None
        }
    }

    /// Pull the next exposable frame, validating it if necessary. `Ok(None)` at
    /// end-of-stream. The frame's `amplitude`/`phase` are NOT yet DSP-cleaned
    /// (call [`CaptureRuntime::next_clean_frame`] for that).
    pub fn next_validated_frame(&mut self) -> Result<Option<CsiFrame>, RvcsiError> {
        loop {
            match self.source.next_frame()? {
                None => return Ok(None),
                Some(frame) => {
                    if let Some(f) = self.admit(frame) {
                        return Ok(Some(f));
                    }
                }
            }
        }
    }

    /// Like [`CaptureRuntime::next_validated_frame`] but with `SignalPipeline`
    /// applied (DC removal, phase unwrap, Hampel filter, smoothing).
    pub fn next_clean_frame(&mut self) -> Result<Option<CsiFrame>, RvcsiError> {
        match self.next_validated_frame()? {
            None => Ok(None),
            Some(mut f) => {
                self.dsp.process_frame(&mut f);
                Ok(Some(f))
            }
        }
    }

    /// Drain the rest of the stream through DSP + the event pipeline and return
    /// every emitted event (in order).
    pub fn drain_events(&mut self) -> Result<Vec<CsiEvent>, RvcsiError> {
        let mut out = Vec::new();
        while let Some(mut f) = self.next_validated_frame()? {
            self.dsp.process_frame(&mut f);
            out.extend(self.events.process_frame(&f));
        }
        out.extend(self.events.flush());
        Ok(out)
    }

    /// Health snapshot combining the source's view and the runtime's counters.
    pub fn health(&self) -> SourceHealth {
        let mut h = self.source.health();
        // Augment the status with the runtime's drop count.
        let extra = format!("frames_seen={}, frames_dropped={}", self.frames_seen, self.frames_dropped);
        h.status = Some(match h.status {
            Some(s) => format!("{s}; {extra}"),
            None => extra,
        });
        h
    }

    /// Frames pulled from the source so far.
    pub fn frames_seen(&self) -> u64 {
        self.frames_seen
    }

    /// Frames dropped by validation so far.
    pub fn frames_dropped(&self) -> u64 {
        self.frames_dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_adapter_file::{CaptureHeader, FileRecorder};
    use rvcsi_adapter_nexmon::{encode_record, NexmonRecord};
    use rvcsi_core::{AdapterKind, FrameId};

    fn write_capture(path: &std::path::Path, n: usize) {
        let header = CaptureHeader::new(
            SessionId(1),
            SourceId::from("rt"),
            AdapterProfile::offline(AdapterKind::File),
        );
        let mut rec = FileRecorder::create(path, &header).unwrap();
        for k in 0..n {
            let amp_scale = if (k / 8) % 2 == 0 { 0.0 } else { 1.5 };
            let i: Vec<f32> = (0..32).map(|s| 1.0 + amp_scale * (((k + s) % 5) as f32 - 2.0)).collect();
            let q: Vec<f32> = (0..32).map(|_| 0.5).collect();
            let mut f = CsiFrame::from_iq(
                FrameId(k as u64),
                SessionId(1),
                SourceId::from("rt"),
                AdapterKind::File,
                1_000 + k as u64 * 50_000_000,
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
    fn streams_validated_frames_from_a_capture() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 5);
        let mut rt = CaptureRuntime::open_capture_file(tmp.path().to_str().unwrap()).unwrap();
        let mut count = 0;
        while let Some(f) = rt.next_validated_frame().unwrap() {
            assert!(f.is_exposable());
            count += 1;
        }
        assert_eq!(count, 5);
        assert_eq!(rt.frames_seen(), 5);
        assert_eq!(rt.frames_dropped(), 0);
        let h = rt.health();
        assert!(h.status.unwrap().contains("frames_seen=5"));
    }

    #[test]
    fn clean_frame_applies_dsp_without_changing_validation() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 3);
        let mut rt = CaptureRuntime::open_capture_file(tmp.path().to_str().unwrap()).unwrap();
        let f = rt.next_clean_frame().unwrap().unwrap();
        assert_eq!(f.validation, ValidationStatus::Accepted);
        assert_eq!(f.quality_score, 0.9);
        assert_eq!(f.amplitude.len(), 32);
    }

    #[test]
    fn drains_events_from_an_alternating_stream() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 64);
        let mut rt = CaptureRuntime::open_capture_file(tmp.path().to_str().unwrap()).unwrap();
        let events = rt.drain_events().unwrap();
        assert!(!events.is_empty());
        for e in &events {
            e.validate().unwrap();
        }
    }

    #[test]
    fn runs_a_nexmon_record_stream() {
        let mk = |ts: u64| {
            let rec = NexmonRecord {
                subcarrier_count: 64,
                channel: 36,
                bandwidth_mhz: 80,
                rssi_dbm: Some(-60),
                noise_floor_dbm: Some(-92),
                timestamp_ns: ts,
                i_values: (0..64).map(|k| (k as f32 % 3.0) - 1.0).collect(),
                q_values: (0..64).map(|k| (k as f32 % 5.0) * 0.1).collect(),
            };
            encode_record(&rec).unwrap()
        };
        let mut buf = Vec::new();
        for k in 0..40 {
            buf.extend(mk(1_000 + k * 50_000_000));
        }
        let mut rt = CaptureRuntime::open_nexmon_bytes(buf, "nexmon-rt", 3);
        let mut n = 0;
        while let Some(f) = rt.next_validated_frame().unwrap() {
            assert_eq!(f.adapter_kind, AdapterKind::Nexmon);
            assert!(f.is_exposable());
            n += 1;
        }
        assert_eq!(n, 40);
    }

    #[test]
    fn runs_a_real_nexmon_csi_pcap() {
        use rvcsi_adapter_nexmon::NexmonCsiHeader;
        let chanspec = 0x1000u16 | 6; // 2.4 GHz ch6 20 MHz
        let nsub = 64u16;
        let frames: Vec<(u64, NexmonCsiHeader, Vec<f32>, Vec<f32>)> = (0..12u64)
            .map(|k| {
                let i: Vec<f32> = (0..nsub).map(|s| (s as i16 - 32 + k as i16) as f32).collect();
                let q: Vec<f32> = (0..nsub).map(|_| 1.0f32).collect();
                (
                    1_000_000_000 + k * 50_000_000,
                    NexmonCsiHeader {
                        rssi_dbm: -55 - k as i16,
                        fctl: 8,
                        src_mac: [0, 1, 2, 3, 4, 5],
                        seq_cnt: k as u16,
                        core: 0,
                        spatial_stream: 0,
                        chanspec,
                        chip_ver: 0x4345,
                        channel: 0,
                        bandwidth_mhz: 0,
                        is_5ghz: false,
                        subcarrier_count: nsub,
                    },
                    i,
                    q,
                )
            })
            .collect();
        let pcap = rvcsi_adapter_nexmon::synthetic_nexmon_pcap(&frames, 5500).unwrap();
        let mut rt = CaptureRuntime::open_nexmon_pcap_bytes(&pcap, "nexmon-pcap-rt", 1, None).unwrap();
        let mut got = 0;
        while let Some(f) = rt.next_validated_frame().unwrap() {
            assert_eq!(f.adapter_kind, AdapterKind::Nexmon);
            assert_eq!(f.channel, 6);
            assert_eq!(f.bandwidth_mhz, 20);
            assert!(f.is_exposable());
            got += 1;
        }
        assert_eq!(got, 12);
        let events = {
            let mut rt2 = CaptureRuntime::open_nexmon_pcap_bytes(&pcap, "n", 2, None).unwrap();
            rt2.drain_events().unwrap()
        };
        for e in &events {
            e.validate().unwrap();
        }
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(CaptureRuntime::open_capture_file("/nope/x.rvcsi").is_err());
        assert!(CaptureRuntime::open_nexmon_file("/nope/x.bin", "s", 0).is_err());
        assert!(CaptureRuntime::open_nexmon_pcap("/nope/x.pcap", "s", 0, None).is_err());
        assert!(CaptureRuntime::open_nexmon_pcap_bytes(&[0u8; 8], "s", 0, None).is_err());
    }
}

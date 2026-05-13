//! # rvCSI Nexmon adapter (napi-c boundary)
//!
//! Wraps the isolated C shim in `native/rvcsi_nexmon_shim.{c,h}` — the only C
//! in the rvCSI runtime (ADR-095 D2, ADR-096). The shim parses a compact,
//! byte-defined "rvCSI Nexmon record" (a normalized superset of the nexmon_csi
//! UDP payload). Everything above [`ffi`] is safe Rust; all `unsafe` is
//! confined to this crate, bounds-checked on the C side, and documented.
//!
//! Two source paths:
//!
//! * the compact, self-describing **rvCSI Nexmon record** — fed to
//!   [`NexmonAdapter::from_bytes`] (records concatenated in a buffer/file);
//! * the **real nexmon_csi UDP payload** inside a libpcap capture
//!   (`tcpdump -i wlan0 dst port 5500 -w csi.pcap`) — fed to
//!   [`NexmonPcapAdapter::open`] / [`NexmonPcapAdapter::parse`].
//!
//! Both yield `Pending` [`CsiFrame`]s; the runtime runs
//! [`rvcsi_core::validate_frame`] on each before exposing it.

#![warn(missing_docs)]

use std::path::Path;

use rvcsi_core::{
    AdapterKind, AdapterProfile, CsiFrame, CsiSource, RvcsiError, SessionId, SourceHealth, SourceId,
};

pub mod chips;
pub mod ffi;
pub mod pcap;

pub use chips::{
    known_chips, known_pi_models, nexmon_adapter_profile, raspberry_pi_profile, NexmonChip,
    RaspberryPiModel,
};
pub use ffi::{
    decode_chanspec, decode_nexmon_udp, decode_record, encode_nexmon_udp, encode_record,
    parse_nexmon_udp_header, shim_abi_version, DecodedChanspec, NexmonCsiHeader, NexmonFfiError,
    NexmonRecord, NEXMON_CSI_FMT_INT16_IQ, NEXMON_HEADER_BYTES, NEXMON_MAGIC, RECORD_HEADER_BYTES,
};
pub use pcap::{
    extract_udp_payload, synthetic_udp_pcap, PcapPacket, PcapReader, LINKTYPE_ETHERNET,
    LINKTYPE_IPV4, LINKTYPE_LINUX_SLL, LINKTYPE_RAW, NEXMON_DEFAULT_PORT, PCAP_MAGIC_NS,
    PCAP_MAGIC_US,
};

/// Build a synthetic nexmon_csi `.pcap` (LE/µs/Ethernet) from
/// `(timestamp_ns, NexmonCsiHeader, i_values, q_values)` entries, sending every
/// CSI packet to UDP port `port`. Useful for tests, examples and the `rvcsi`
/// self-tests; real captures come off a Pi running patched firmware.
pub fn synthetic_nexmon_pcap(
    frames: &[(u64, NexmonCsiHeader, Vec<f32>, Vec<f32>)],
    port: u16,
) -> Result<Vec<u8>, NexmonFfiError> {
    let payloads: Vec<Vec<u8>> = frames
        .iter()
        .map(|(_, h, i, q)| encode_nexmon_udp(h, i, q))
        .collect::<Result<_, _>>()?;
    let refs: Vec<(u64, u16, &[u8])> = frames
        .iter()
        .zip(payloads.iter())
        .map(|((ts, ..), p)| (*ts, port, p.as_slice()))
        .collect();
    Ok(pcap::synthetic_udp_pcap(&refs))
}

/// A [`CsiSource`] that replays a buffer of rvCSI Nexmon records.
///
/// Records are decoded lazily by [`CsiSource::next_frame`]; an exhausted buffer
/// returns `Ok(None)`. Frames are produced with `validation = Pending`.
pub struct NexmonAdapter {
    source_id: SourceId,
    session_id: SessionId,
    profile: AdapterProfile,
    buf: Vec<u8>,
    cursor: usize,
    next_frame_id: u64,
    delivered: u64,
    rejected: u64,
    status: Option<String>,
}

impl NexmonAdapter {
    /// Build an adapter from a buffer of concatenated records.
    pub fn from_bytes(
        source_id: impl Into<SourceId>,
        session_id: SessionId,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        // ABI guard — the static lib we linked must match the header we coded against.
        debug_assert_eq!(
            shim_abi_version() >> 16,
            1,
            "rvcsi_nexmon_shim major ABI mismatch"
        );
        NexmonAdapter {
            source_id: source_id.into(),
            session_id,
            profile: AdapterProfile::nexmon_default(),
            buf: bytes.into(),
            cursor: 0,
            next_frame_id: 0,
            delivered: 0,
            rejected: 0,
            status: None,
        }
    }

    /// Build an adapter from a capture file of concatenated records.
    pub fn from_file(
        source_id: impl Into<SourceId>,
        session_id: SessionId,
        path: impl AsRef<Path>,
    ) -> Result<Self, RvcsiError> {
        let bytes = std::fs::read(path)?;
        Ok(Self::from_bytes(source_id, session_id, bytes))
    }

    /// Override the capability profile (e.g. when the firmware version is known).
    pub fn with_profile(mut self, profile: AdapterProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Decode every record in `bytes` into `Pending` frames in one shot.
    ///
    /// Stops at the first malformed record and returns what was decoded so far
    /// alongside the error (`Err` carries the partial vec via the message; use
    /// [`NexmonAdapter`] iteration if you need to inspect partial progress).
    pub fn frames_from_bytes(
        source_id: impl Into<SourceId>,
        session_id: SessionId,
        bytes: &[u8],
    ) -> Result<Vec<CsiFrame>, RvcsiError> {
        let mut adapter = NexmonAdapter::from_bytes(source_id, session_id, bytes.to_vec());
        let mut out = Vec::new();
        while let Some(frame) = adapter.next_frame()? {
            out.push(frame);
        }
        Ok(out)
    }

    fn record_to_frame(&mut self, rec: NexmonRecord) -> CsiFrame {
        let fid = self.next_frame_id;
        self.next_frame_id += 1;
        let mut frame = CsiFrame::from_iq(
            fid.into(),
            self.session_id,
            self.source_id.clone(),
            AdapterKind::Nexmon,
            rec.timestamp_ns,
            rec.channel,
            rec.bandwidth_mhz,
            rec.i_values,
            rec.q_values,
        );
        if let Some(r) = rec.rssi_dbm {
            frame.rssi_dbm = Some(r);
        }
        if let Some(n) = rec.noise_floor_dbm {
            frame.noise_floor_dbm = Some(n);
        }
        frame
    }
}

impl CsiSource for NexmonAdapter {
    fn profile(&self) -> &AdapterProfile {
        &self.profile
    }

    fn session_id(&self) -> SessionId {
        self.session_id
    }

    fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    fn next_frame(&mut self) -> Result<Option<CsiFrame>, RvcsiError> {
        if self.cursor >= self.buf.len() {
            return Ok(None);
        }
        let remaining = &self.buf[self.cursor..];
        match decode_record(remaining) {
            Ok((rec, consumed)) => {
                self.cursor += consumed;
                self.delivered += 1;
                Ok(Some(self.record_to_frame(rec)))
            }
            Err(e) => {
                self.rejected += 1;
                self.status = Some(format!("malformed record at byte {}: {e}", self.cursor));
                // Skip the rest of the buffer — a corrupt record means we've lost
                // framing; the daemon would reconnect/re-sync rather than guess.
                self.cursor = self.buf.len();
                Err(RvcsiError::adapter(
                    "nexmon",
                    format!("malformed record: {e}"),
                ))
            }
        }
    }

    fn health(&self) -> SourceHealth {
        SourceHealth {
            connected: self.cursor < self.buf.len(),
            frames_delivered: self.delivered,
            frames_rejected: self.rejected,
            status: self.status.clone(),
        }
    }
}

/// A [`CsiSource`] that reads the *real* nexmon_csi UDP payloads out of a
/// libpcap (`.pcap`) capture (`tcpdump -i wlan0 dst port 5500 -w csi.pcap`).
///
/// The pcap is parsed eagerly on construction: every UDP packet to the CSI port
/// is decoded via the napi-c shim ([`decode_nexmon_udp`]); packets that aren't
/// CSI (wrong port / not IPv4-UDP / bad nexmon magic) are counted as `rejected`
/// and skipped. Each surviving frame carries the pcap packet timestamp and
/// `validation = Pending`.
pub struct NexmonPcapAdapter {
    source_id: SourceId,
    session_id: SessionId,
    profile: AdapterProfile,
    detected_chip: NexmonChip,
    frames: Vec<CsiFrame>,
    headers: Vec<NexmonCsiHeader>,
    link_type: u32,
    cursor: usize,
    skipped: u64,
}

/// Resolve the chip when every decoded packet agrees on `chip_ver`; otherwise
/// (mixed or empty) fall back to a generic 802.11ac default.
fn detect_chip(headers: &[NexmonCsiHeader]) -> NexmonChip {
    match headers.first() {
        None => NexmonChip::Bcm43455c0, // a sensible default; profile stays generic-enough
        Some(h0) => {
            let ver = h0.chip_ver;
            if headers.iter().all(|h| h.chip_ver == ver) {
                NexmonChip::from_chip_ver(ver)
            } else {
                NexmonChip::Unknown { chip_ver: 0 }
            }
        }
    }
}

impl NexmonPcapAdapter {
    /// Parse a libpcap byte buffer; `port` is the CSI UDP port to filter on
    /// (`None` ⇒ [`NEXMON_DEFAULT_PORT`] = 5500). The chip is auto-detected from
    /// the packets' `chip_ver` (e.g. a Raspberry Pi 5 capture ⇒ BCM43455c0);
    /// override with [`NexmonPcapAdapter::with_chip`] / [`NexmonPcapAdapter::with_pi_model`].
    pub fn parse(
        source_id: impl Into<SourceId>,
        session_id: SessionId,
        pcap_bytes: &[u8],
        port: Option<u16>,
    ) -> Result<Self, RvcsiError> {
        debug_assert_eq!(shim_abi_version() >> 16, 1, "rvcsi_nexmon_shim major ABI mismatch");
        let source_id = source_id.into();
        let reader = PcapReader::parse(pcap_bytes)?;
        let link_type = reader.link_type();
        let want_port = port.or(Some(NEXMON_DEFAULT_PORT));
        let mut frames = Vec::new();
        let mut headers = Vec::new();
        let mut skipped = 0u64;
        let mut next_fid = 0u64;
        for (ts_ns, _dst_port, payload) in reader.udp_payloads(want_port) {
            match decode_nexmon_udp(payload, NEXMON_CSI_FMT_INT16_IQ) {
                Ok((hdr, rec)) => {
                    let mut frame = CsiFrame::from_iq(
                        next_fid.into(),
                        session_id,
                        source_id.clone(),
                        AdapterKind::Nexmon,
                        ts_ns,
                        rec.channel,
                        rec.bandwidth_mhz,
                        rec.i_values,
                        rec.q_values,
                    );
                    next_fid += 1;
                    frame.rssi_dbm = rec.rssi_dbm;
                    frame.noise_floor_dbm = rec.noise_floor_dbm;
                    frames.push(frame);
                    headers.push(hdr);
                }
                Err(_) => skipped += 1,
            }
        }
        // Count non-CSI UDP packets on other ports as "skipped" too, for health.
        if let Some(p) = want_port {
            skipped += reader.udp_payloads(None).filter(|(_, dp, _)| *dp != p).count() as u64;
        }
        let detected_chip = detect_chip(&headers);
        Ok(NexmonPcapAdapter {
            source_id,
            session_id,
            profile: nexmon_adapter_profile(detected_chip),
            detected_chip,
            frames,
            headers,
            link_type,
            cursor: 0,
            skipped,
        })
    }

    /// Override the validation profile to the given Nexmon chip (e.g. when the
    /// `chip_ver` word is unreliable). This does not change the decoded frames.
    pub fn with_chip(mut self, chip: NexmonChip) -> Self {
        self.detected_chip = chip;
        self.profile = nexmon_adapter_profile(chip);
        self
    }

    /// Override the validation profile to a Raspberry Pi model's chip
    /// (`RaspberryPiModel::Pi5` ⇒ BCM43455c0, 20/40/80 MHz, 64/128/256 sc).
    pub fn with_pi_model(mut self, model: RaspberryPiModel) -> Self {
        self.detected_chip = model.nexmon_chip();
        self.profile = raspberry_pi_profile(model);
        self
    }

    /// The chip resolved from the capture's `chip_ver` words (or set via
    /// [`NexmonPcapAdapter::with_chip`] / [`NexmonPcapAdapter::with_pi_model`]).
    pub fn detected_chip(&self) -> NexmonChip {
        self.detected_chip
    }

    /// Open and parse a `.pcap` file.
    pub fn open(
        source_id: impl Into<SourceId>,
        session_id: SessionId,
        path: impl AsRef<Path>,
        port: Option<u16>,
    ) -> Result<Self, RvcsiError> {
        let bytes = std::fs::read(path)?;
        Self::parse(source_id, session_id, &bytes, port)
    }

    /// Decode every CSI frame in a `.pcap` buffer in one shot (`Pending` frames).
    pub fn frames_from_pcap_bytes(
        source_id: impl Into<SourceId>,
        session_id: SessionId,
        pcap_bytes: &[u8],
        port: Option<u16>,
    ) -> Result<Vec<CsiFrame>, RvcsiError> {
        Ok(Self::parse(source_id, session_id, pcap_bytes, port)?.frames)
    }

    /// The capture's link-layer type.
    pub fn link_type(&self) -> u32 {
        self.link_type
    }

    /// The parsed nexmon_csi UDP headers, one per decoded frame, in order.
    pub fn headers(&self) -> &[NexmonCsiHeader] {
        &self.headers
    }

    /// Total CSI frames decoded from the capture.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
}

impl CsiSource for NexmonPcapAdapter {
    fn profile(&self) -> &AdapterProfile {
        &self.profile
    }

    fn session_id(&self) -> SessionId {
        self.session_id
    }

    fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    fn next_frame(&mut self) -> Result<Option<CsiFrame>, RvcsiError> {
        let frame = self.frames.get(self.cursor).cloned();
        if frame.is_some() {
            self.cursor += 1;
        }
        Ok(frame)
    }

    fn health(&self) -> SourceHealth {
        SourceHealth {
            connected: self.cursor < self.frames.len(),
            frames_delivered: self.cursor as u64,
            frames_rejected: self.skipped,
            status: Some(format!(
                "pcap link_type={}, {} CSI frame(s), {} non-CSI/skipped",
                self.link_type,
                self.frames.len(),
                self.skipped
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{validate_frame, ValidationPolicy, ValidationStatus};

    fn make_record(ts: u64, ch: u16, n: usize, rssi: Option<i16>) -> Vec<u8> {
        let i: Vec<f32> = (0..n).map(|k| (k as f32) * 0.5).collect();
        let q: Vec<f32> = (0..n).map(|k| -(k as f32) * 0.25).collect();
        let rec = NexmonRecord {
            subcarrier_count: n as u16,
            channel: ch,
            bandwidth_mhz: 80,
            rssi_dbm: rssi,
            noise_floor_dbm: Some(-92),
            timestamp_ns: ts,
            i_values: i,
            q_values: q,
        };
        encode_record(&rec).expect("encode")
    }

    #[test]
    fn abi_version_is_one_point_one() {
        // 1.1 — minor bump when the nexmon_csi UDP/chanspec entry points landed.
        assert_eq!(shim_abi_version(), 0x0001_0001);
        assert_eq!(shim_abi_version() >> 16, 1, "major ABI must stay 1");
    }

    #[test]
    fn roundtrip_single_record_via_c_shim() {
        let bytes = make_record(123_456, 36, 64, Some(-58));
        let (rec, consumed) = decode_record(&bytes).expect("decode");
        assert_eq!(consumed, bytes.len());
        assert_eq!(rec.subcarrier_count, 64);
        assert_eq!(rec.channel, 36);
        assert_eq!(rec.bandwidth_mhz, 80);
        assert_eq!(rec.rssi_dbm, Some(-58));
        assert_eq!(rec.noise_floor_dbm, Some(-92));
        assert_eq!(rec.timestamp_ns, 123_456);
        assert_eq!(rec.i_values.len(), 64);
        // Q8.8 fixed point: 0.5 and -0.25 are exactly representable.
        assert_eq!(rec.i_values[1], 0.5);
        assert_eq!(rec.q_values[1], -0.25);
    }

    #[test]
    fn adapter_streams_multiple_records_then_validates() {
        let mut buf = make_record(1_000, 6, 56, Some(-60));
        buf.extend(make_record(2_000, 6, 56, Some(-61)));
        buf.extend(make_record(3_000, 6, 56, None));

        let mut adapter = NexmonAdapter::from_bytes("nexmon-test", SessionId(7), buf);
        let mut frames = Vec::new();
        while let Some(f) = adapter.next_frame().unwrap() {
            frames.push(f);
        }
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].timestamp_ns, 1_000);
        assert_eq!(frames[2].rssi_dbm, None);
        assert_eq!(adapter.health().frames_delivered, 3);
        assert!(!adapter.health().connected);

        // 56 is not in the default Nexmon profile (64/128/256) → rejected.
        let mut f = frames[0].clone();
        let err = validate_frame(&mut f, adapter.profile(), &ValidationPolicy::default(), None);
        assert!(err.is_err());

        // With a permissive profile it validates fine.
        let mut f = frames[0].clone();
        validate_frame(
            &mut f,
            &AdapterProfile::offline(AdapterKind::Nexmon),
            &ValidationPolicy::default(),
            None,
        )
        .unwrap();
        assert_eq!(f.validation, ValidationStatus::Accepted);
    }

    #[test]
    fn truncated_buffer_is_a_structured_error_not_a_panic() {
        let bytes = make_record(1, 6, 64, Some(-60));
        let truncated = &bytes[..bytes.len() - 10];
        let err = decode_record(truncated).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("trunc") || err.to_string().to_lowercase().contains("short"));

        let mut adapter = NexmonAdapter::from_bytes("t", SessionId(0), truncated.to_vec());
        assert!(adapter.next_frame().is_err());
        assert_eq!(adapter.health().frames_rejected, 1);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = make_record(1, 6, 64, Some(-60));
        bytes[0] = 0xFF;
        assert!(decode_record(&bytes).is_err());
    }

    #[test]
    fn frames_from_bytes_helper() {
        let mut buf = make_record(10, 1, 64, Some(-50));
        buf.extend(make_record(20, 1, 64, Some(-51)));
        let frames = NexmonAdapter::frames_from_bytes("t", SessionId(1), &buf).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].timestamp_ns, 20);
    }

    // ----- NexmonPcapAdapter (real nexmon_csi UDP inside a libpcap file) -----

    /// Build a synthetic nexmon_csi UDP payload (18-byte header + int16 I/Q).
    fn synth_nexmon_payload(rssi: i16, chanspec: u16, nsub: u16, seq: u16) -> Vec<u8> {
        let hdr = NexmonCsiHeader {
            rssi_dbm: rssi,
            fctl: 0x08,
            src_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02],
            seq_cnt: seq,
            core: 0,
            spatial_stream: 0,
            chanspec,
            chip_ver: 0x4345,
            channel: 0,
            bandwidth_mhz: 0,
            is_5ghz: false,
            subcarrier_count: nsub,
        };
        let i: Vec<f32> = (0..nsub).map(|k| (k as i16 - 32) as f32).collect();
        let q: Vec<f32> = (0..nsub).map(|k| (seq as i16 + k as i16) as f32).collect();
        encode_nexmon_udp(&hdr, &i, &q).expect("encode nexmon payload")
    }

    /// Wrap `payload` in an Ethernet/IPv4/UDP frame to `dst_port`.
    fn eth_ip_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![
            1, 2, 3, 4, 5, 6, // dst mac
            10, 11, 12, 13, 14, 15, // src mac
        ];
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
        let total = (20 + 8 + payload.len()) as u16;
        f.extend_from_slice(&[0x45, 0x00]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]); // id/frag/ttl/proto=UDP/cksum
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 20]); // src/dst ip
        f.extend_from_slice(&54321u16.to_be_bytes()); // src port
        f.extend_from_slice(&dst_port.to_be_bytes()); // dst port
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes()); // udp len
        f.extend_from_slice(&[0, 0]); // udp cksum
        f.extend_from_slice(payload);
        f
    }

    /// Build a classic LE/microsecond pcap from `(ts_sec, ts_usec, frame)` records.
    fn pcap_le_us(link_type: u32, recs: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        b.extend_from_slice(&[2, 0, 4, 0]); // ver major/minor
        b.extend_from_slice(&0u32.to_le_bytes()); // thiszone
        b.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        b.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        b.extend_from_slice(&link_type.to_le_bytes());
        for (s, us, f) in recs {
            b.extend_from_slice(&s.to_le_bytes());
            b.extend_from_slice(&us.to_le_bytes());
            b.extend_from_slice(&(f.len() as u32).to_le_bytes());
            b.extend_from_slice(&(f.len() as u32).to_le_bytes());
            b.extend_from_slice(f);
        }
        b
    }

    #[test]
    fn pcap_adapter_decodes_real_nexmon_csi_packets() {
        let chanspec = 0xc000u16 | 0x2000 | 36; // 5 GHz, ch 36, 80 MHz
        let nsub = 256u16;
        let recs = vec![
            (1_000u32, 100_000u32, eth_ip_udp(5500, &synth_nexmon_payload(-58, chanspec, nsub, 1))),
            (1_000u32, 600_000u32, eth_ip_udp(9999, &[0xaa; 8])), // unrelated UDP
            (1_001u32, 0u32, eth_ip_udp(5500, &synth_nexmon_payload(-61, chanspec, nsub, 2))),
            (1_001u32, 50_000u32, eth_ip_udp(5500, &[0x42; 30])), // bad nexmon magic -> skipped
        ];
        let pcap = pcap_le_us(LINKTYPE_ETHERNET, &recs);

        let mut adapter = NexmonPcapAdapter::parse("nexmon-pcap", SessionId(9), &pcap, None).unwrap();
        assert_eq!(adapter.link_type(), LINKTYPE_ETHERNET);
        assert_eq!(adapter.frame_count(), 2);
        assert_eq!(adapter.headers().len(), 2);
        assert_eq!(adapter.headers()[0].chanspec, chanspec);
        assert_eq!(adapter.headers()[0].channel, 36);
        assert_eq!(adapter.headers()[0].bandwidth_mhz, 80);
        assert!(adapter.headers()[0].is_5ghz);
        assert_eq!(adapter.headers()[1].seq_cnt, 2);

        let mut frames = Vec::new();
        while let Some(f) = adapter.next_frame().unwrap() {
            frames.push(f);
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].adapter_kind, AdapterKind::Nexmon);
        assert_eq!(frames[0].channel, 36);
        assert_eq!(frames[0].bandwidth_mhz, 80);
        assert_eq!(frames[0].rssi_dbm, Some(-58));
        assert_eq!(frames[0].subcarrier_count, nsub);
        // pcap timestamp -> frame timestamp (1000 s + 100000 us)
        assert_eq!(frames[0].timestamp_ns, 1_000 * 1_000_000_000 + 100_000 * 1_000);
        assert_eq!(frames[1].timestamp_ns, 1_001 * 1_000_000_000);

        let h = adapter.health();
        assert!(!h.connected);
        assert_eq!(h.frames_delivered, 2);
        assert!(h.frames_rejected >= 2); // the bad-magic one + the unrelated-port one
    }

    #[test]
    fn pcap_adapter_validates_decoded_frames() {
        let pcap = pcap_le_us(
            LINKTYPE_ETHERNET,
            &[(1u32, 0u32, eth_ip_udp(5500, &synth_nexmon_payload(-60, 0x1000 | 6, 64, 7)))],
        );
        let frames = NexmonPcapAdapter::frames_from_pcap_bytes("p", SessionId(0), &pcap, Some(5500)).unwrap();
        assert_eq!(frames.len(), 1);
        // 64 sc, channel 6 — accepted by a permissive (offline) profile
        let mut f = frames[0].clone();
        validate_frame(
            &mut f,
            &AdapterProfile::offline(AdapterKind::Nexmon),
            &ValidationPolicy::default(),
            None,
        )
        .unwrap();
        assert_eq!(f.validation, ValidationStatus::Accepted);
        assert_eq!(f.channel, 6);
        assert_eq!(f.bandwidth_mhz, 20);
    }

    #[test]
    fn pcap_adapter_rejects_garbage_pcap() {
        assert!(NexmonPcapAdapter::parse("p", SessionId(0), &[0u8; 8], None).is_err());
        assert!(NexmonPcapAdapter::open("p", SessionId(0), "/no/such/file.pcap", None).is_err());
    }

    #[test]
    fn pcap_adapter_auto_detects_raspberry_pi_5_chip() {
        // synth_nexmon_payload stamps chip_ver = 0x4345 (BCM4345 family chip ID),
        // which is the CYW43455 / BCM43455c0 on a Raspberry Pi 3B+ / 4 / 400 / 5.
        let chanspec = 0xc000u16 | 0x2000 | 36; // 5 GHz, ch 36, 80 MHz
        let nsub = 256u16;
        let pcap = pcap_le_us(
            LINKTYPE_ETHERNET,
            &[
                (1u32, 0u32, eth_ip_udp(5500, &synth_nexmon_payload(-58, chanspec, nsub, 1))),
                (1u32, 50_000u32, eth_ip_udp(5500, &synth_nexmon_payload(-59, chanspec, nsub, 2))),
            ],
        );
        let adapter = NexmonPcapAdapter::parse("pi5-cap", SessionId(1), &pcap, None).unwrap();
        assert_eq!(adapter.detected_chip(), NexmonChip::Bcm43455c0);
        assert_eq!(adapter.headers()[0].chip(), NexmonChip::Bcm43455c0);
        // the adapter's validation profile is the 43455c0 one (20/40/80, 64/128/256)
        let p = adapter.profile();
        assert_eq!(p.supported_bandwidths_mhz, vec![20, 40, 80]);
        assert!(p.accepts_subcarrier_count(256));
        assert!(p.accepts_channel(36));
        // 256-sc, ch 36 frame validates fine against the Pi 5 profile
        let mut f = adapter.frames[0].clone();
        validate_frame(&mut f, &raspberry_pi_profile(RaspberryPiModel::Pi5), &ValidationPolicy::default(), None).unwrap();
        assert_eq!(f.validation, ValidationStatus::Accepted);

        // explicit override to a Pi 5 also works
        let a2 = NexmonPcapAdapter::parse("p", SessionId(0), &pcap, None).unwrap().with_pi_model(RaspberryPiModel::Pi5);
        assert_eq!(a2.detected_chip(), NexmonChip::Bcm43455c0);
        assert!(a2.profile().chip.as_deref().unwrap().contains("pi5"));
    }
}

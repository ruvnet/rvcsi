//! Raw FFI to the napi-c shim plus safe wrappers (ADR-096).
//!
//! The C side (`native/rvcsi_nexmon_shim.c`) is allocation-free and bounds-checks
//! every read against the caller-supplied lengths. The `unsafe` here is limited
//! to: calling those C functions with correct pointers/lengths, and reading back
//! the metadata struct the C side fully initialized on `RVCSI_NX_OK`.

use std::os::raw::c_char;

/// Bytes in a record header (the fixed prefix before the I/Q samples).
pub const RECORD_HEADER_BYTES: usize = 24;

/// Largest subcarrier count the shim will parse (mirrors `RVCSI_NX_MAX_SUBCARRIERS`).
pub const MAX_SUBCARRIERS: usize = 2048;

/// Sentinel the C side uses for "metadata field absent".
const ABSENT_I16: i16 = 0x7FFF;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RvcsiNxMeta {
    subcarrier_count: u16,
    channel: u16,
    bandwidth_mhz: u16,
    rssi_dbm: i16,
    noise_floor_dbm: i16,
    timestamp_ns: u64,
}

extern "C" {
    fn rvcsi_nx_record_len(buf: *const u8, len: usize) -> usize;
    fn rvcsi_nx_parse_record(
        buf: *const u8,
        len: usize,
        meta: *mut RvcsiNxMeta,
        i_out: *mut f32,
        q_out: *mut f32,
        cap: usize,
    ) -> i32;
    fn rvcsi_nx_write_record(
        buf: *mut u8,
        cap: usize,
        meta: *const RvcsiNxMeta,
        i_in: *const f32,
        q_in: *const f32,
    ) -> usize;
    fn rvcsi_nx_decode_chanspec(
        chanspec: u16,
        out_channel: *mut u16,
        out_bw_mhz: *mut u16,
        out_is_5ghz: *mut u8,
    );
    fn rvcsi_nx_csi_udp_header(payload: *const u8, len: usize, out: *mut RvcsiNxUdpHeader) -> i32;
    fn rvcsi_nx_csi_udp_decode(
        payload: *const u8,
        len: usize,
        csi_format: i32,
        hdr_out: *mut RvcsiNxUdpHeader,
        meta: *mut RvcsiNxMeta,
        i_out: *mut f32,
        q_out: *mut f32,
        cap: usize,
    ) -> i32;
    fn rvcsi_nx_csi_udp_write(
        buf: *mut u8,
        cap: usize,
        hdr: *const RvcsiNxUdpHeader,
        subcarrier_count: u16,
        i_in: *const f32,
        q_in: *const f32,
    ) -> usize;
    fn rvcsi_nx_strerror(code: i32) -> *const c_char;
    fn rvcsi_nx_abi_version() -> u32;
}

/// Mirrors the C `RvcsiNxUdpHeader` (the parsed 18-byte nexmon_csi UDP header).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct RvcsiNxUdpHeader {
    rssi_dbm: i16,
    fctl: u8,
    src_mac: [u8; 6],
    seq_cnt: u16,
    core: u16,
    spatial_stream: u16,
    chanspec: u16,
    chip_ver: u16,
    channel: u16,
    bandwidth_mhz: u16,
    is_5ghz: u8,
    subcarrier_count: u16,
}

/// `csi_format` selector for [`decode_nexmon_udp`]: `nsub` pairs of int16 LE
/// `(real, imag)` — the modern BCM43455c0 chip ID / 4358 / 4366c0 export (mirrors
/// `RVCSI_NX_CSI_FMT_INT16_IQ`). The legacy packed-float export is not yet wired.
pub const NEXMON_CSI_FMT_INT16_IQ: i32 = 0;

/// ABI version of the linked C shim (`major << 16 | minor`).
pub fn shim_abi_version() -> u32 {
    // SAFETY: no arguments, returns a plain u32 by value.
    unsafe { rvcsi_nx_abi_version() }
}

/// Errors decoding a record (a structured view of the C error codes).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NexmonFfiError {
    /// The C shim returned a non-zero error code.
    #[error("nexmon shim error {code}: {message}")]
    Shim {
        /// Numeric `RvcsiNxError` code.
        code: i32,
        /// Static description from `rvcsi_nx_strerror`.
        message: String,
    },
    /// The buffer didn't even contain a parseable header / record length.
    #[error("not a record (bad magic, unsupported version, or too short)")]
    NotARecord,
}

fn strerror(code: i32) -> String {
    // SAFETY: rvcsi_nx_strerror always returns a non-NULL pointer to a static,
    // NUL-terminated C string (see the C source); we only borrow it here.
    unsafe {
        let p = rvcsi_nx_strerror(code);
        if p.is_null() {
            return format!("error {code}");
        }
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// A record decoded from the wire: fixed metadata + the I/Q sample vectors.
#[derive(Debug, Clone, PartialEq)]
pub struct NexmonRecord {
    /// Number of subcarriers (== length of `i_values`/`q_values`).
    pub subcarrier_count: u16,
    /// WiFi channel number.
    pub channel: u16,
    /// Bandwidth in MHz.
    pub bandwidth_mhz: u16,
    /// RSSI in dBm, if present in the record.
    pub rssi_dbm: Option<i16>,
    /// Noise floor in dBm, if present.
    pub noise_floor_dbm: Option<i16>,
    /// Source timestamp, ns.
    pub timestamp_ns: u64,
    /// In-phase samples.
    pub i_values: Vec<f32>,
    /// Quadrature samples.
    pub q_values: Vec<f32>,
}

/// Length, in bytes, of the record starting at `buf[0]`, or `None` if `buf`
/// doesn't begin with a complete, valid record.
pub fn record_len(buf: &[u8]) -> Option<usize> {
    // SAFETY: passing a valid pointer + the slice's true length; the C side
    // reads at most `len` bytes and returns 0 on any problem.
    let n = unsafe { rvcsi_nx_record_len(buf.as_ptr(), buf.len()) };
    if n == 0 {
        None
    } else {
        Some(n)
    }
}

/// Decode the first record in `buf`. Returns the record and the number of bytes
/// it consumed (so callers can advance a cursor over a concatenated stream).
pub fn decode_record(buf: &[u8]) -> Result<(NexmonRecord, usize), NexmonFfiError> {
    let total = record_len(buf).ok_or(NexmonFfiError::NotARecord)?;
    debug_assert!(total >= RECORD_HEADER_BYTES && total <= buf.len());
    let n = (total - RECORD_HEADER_BYTES) / 4;

    let mut meta = RvcsiNxMeta {
        subcarrier_count: 0,
        channel: 0,
        bandwidth_mhz: 0,
        rssi_dbm: 0,
        noise_floor_dbm: 0,
        timestamp_ns: 0,
    };
    let mut i_out = vec![0.0f32; n];
    let mut q_out = vec![0.0f32; n];

    // SAFETY: `buf` is valid for `buf.len()` bytes; `i_out`/`q_out` are valid
    // for `n` f32s each and we pass `n` as the capacity; `meta` points to a
    // fully owned, properly aligned RvcsiNxMeta. The C side writes only within
    // those bounds and fully initializes `meta` on RVCSI_NX_OK.
    let rc = unsafe {
        rvcsi_nx_parse_record(
            buf.as_ptr(),
            buf.len(),
            &mut meta as *mut RvcsiNxMeta,
            i_out.as_mut_ptr(),
            q_out.as_mut_ptr(),
            n,
        )
    };
    if rc != 0 {
        return Err(NexmonFfiError::Shim {
            code: rc,
            message: strerror(rc),
        });
    }
    debug_assert_eq!(meta.subcarrier_count as usize, n);

    let rec = NexmonRecord {
        subcarrier_count: meta.subcarrier_count,
        channel: meta.channel,
        bandwidth_mhz: meta.bandwidth_mhz,
        rssi_dbm: (meta.rssi_dbm != ABSENT_I16).then_some(meta.rssi_dbm),
        noise_floor_dbm: (meta.noise_floor_dbm != ABSENT_I16).then_some(meta.noise_floor_dbm),
        timestamp_ns: meta.timestamp_ns,
        i_values: i_out,
        q_values: q_out,
    };
    Ok((rec, total))
}

/// Encode a record to bytes via the C writer (used by tests and the recorder).
pub fn encode_record(rec: &NexmonRecord) -> Result<Vec<u8>, NexmonFfiError> {
    let n = rec.subcarrier_count as usize;
    if n == 0 || n > MAX_SUBCARRIERS || rec.i_values.len() != n || rec.q_values.len() != n {
        return Err(NexmonFfiError::Shim {
            code: 6,
            message: "bad subcarrier count or i/q length".to_string(),
        });
    }
    let meta = RvcsiNxMeta {
        subcarrier_count: rec.subcarrier_count,
        channel: rec.channel,
        bandwidth_mhz: rec.bandwidth_mhz,
        rssi_dbm: rec.rssi_dbm.unwrap_or(ABSENT_I16),
        noise_floor_dbm: rec.noise_floor_dbm.unwrap_or(ABSENT_I16),
        timestamp_ns: rec.timestamp_ns,
    };
    let cap = RECORD_HEADER_BYTES + n * 4;
    let mut buf = vec![0u8; cap];
    // SAFETY: `buf` is valid for `cap` bytes; `i_in`/`q_in` are valid for `n`
    // f32s each (checked above); `meta` is a fully initialized owned struct.
    let written = unsafe {
        rvcsi_nx_write_record(
            buf.as_mut_ptr(),
            cap,
            &meta as *const RvcsiNxMeta,
            rec.i_values.as_ptr(),
            rec.q_values.as_ptr(),
        )
    };
    if written == 0 {
        return Err(NexmonFfiError::Shim {
            code: 4,
            message: "write_record failed (capacity or argument error)".to_string(),
        });
    }
    debug_assert_eq!(written, cap);
    buf.truncate(written);
    Ok(buf)
}

// ===== real nexmon_csi UDP payload (format 2) ==========================

/// A Broadcom d11ac `chanspec` decoded into (channel, bandwidth-MHz, 5 GHz?).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedChanspec {
    /// Raw chanspec word.
    pub chanspec: u16,
    /// `chanspec & 0xff`.
    pub channel: u16,
    /// 20 / 40 / 80 / 160, or `0` if the bandwidth bits are unrecognised.
    pub bandwidth_mhz: u16,
    /// `true` if the band bits (cross-checked against the channel number) say 5 GHz.
    pub is_5ghz: bool,
}

/// Decode a Broadcom d11ac chanspec word (via the C shim).
pub fn decode_chanspec(chanspec: u16) -> DecodedChanspec {
    let (mut ch, mut bw, mut b5) = (0u16, 0u16, 0u8);
    // SAFETY: three valid out-pointers to owned locals; the C side only writes them.
    unsafe { rvcsi_nx_decode_chanspec(chanspec, &mut ch, &mut bw, &mut b5) };
    DecodedChanspec {
        chanspec,
        channel: ch,
        bandwidth_mhz: bw,
        is_5ghz: b5 != 0,
    }
}

/// The parsed 18-byte nexmon_csi UDP header (raw vendor fields preserved, plus
/// the chanspec-decoded channel/bandwidth/band and the length-derived subcarrier
/// count).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NexmonCsiHeader {
    /// RSSI in dBm (sign-extended from the int8 in the packet).
    pub rssi_dbm: i16,
    /// 802.11 frame-control byte.
    pub fctl: u8,
    /// Source MAC address.
    pub src_mac: [u8; 6],
    /// 802.11 sequence-control word.
    pub seq_cnt: u16,
    /// Receive core index (`core_stream` bits [2:0]).
    pub core: u16,
    /// Spatial-stream index (`core_stream` bits [5:3]).
    pub spatial_stream: u16,
    /// Raw Broadcom chanspec word.
    pub chanspec: u16,
    /// Chip version (e.g. `0x4345` = BCM43455c0 chip ID).
    pub chip_ver: u16,
    /// Channel number decoded from the chanspec.
    pub channel: u16,
    /// Bandwidth (MHz) — from the FFT size when known, else the chanspec bits.
    pub bandwidth_mhz: u16,
    /// `true` if the band bits say 5 GHz.
    pub is_5ghz: bool,
    /// Subcarrier (FFT) count, `(payload_len - 18) / 4`.
    pub subcarrier_count: u16,
}

impl From<RvcsiNxUdpHeader> for NexmonCsiHeader {
    fn from(h: RvcsiNxUdpHeader) -> Self {
        NexmonCsiHeader {
            rssi_dbm: h.rssi_dbm,
            fctl: h.fctl,
            src_mac: h.src_mac,
            seq_cnt: h.seq_cnt,
            core: h.core,
            spatial_stream: h.spatial_stream,
            chanspec: h.chanspec,
            chip_ver: h.chip_ver,
            channel: h.channel,
            bandwidth_mhz: h.bandwidth_mhz,
            is_5ghz: h.is_5ghz != 0,
            subcarrier_count: h.subcarrier_count,
        }
    }
}

impl NexmonCsiHeader {
    fn to_c(&self) -> RvcsiNxUdpHeader {
        RvcsiNxUdpHeader {
            rssi_dbm: self.rssi_dbm,
            fctl: self.fctl,
            src_mac: self.src_mac,
            seq_cnt: self.seq_cnt,
            core: self.core,
            spatial_stream: self.spatial_stream,
            chanspec: self.chanspec,
            chip_ver: self.chip_ver,
            channel: self.channel,
            bandwidth_mhz: self.bandwidth_mhz,
            is_5ghz: self.is_5ghz as u8,
            subcarrier_count: self.subcarrier_count,
        }
    }
}

fn check(rc: i32) -> Result<(), NexmonFfiError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(NexmonFfiError::Shim {
            code: rc,
            message: strerror(rc),
        })
    }
}

/// Parse just the 18-byte nexmon_csi UDP header of `payload`.
pub fn parse_nexmon_udp_header(payload: &[u8]) -> Result<NexmonCsiHeader, NexmonFfiError> {
    let mut hdr = RvcsiNxUdpHeader::default();
    // SAFETY: `payload` valid for `payload.len()`; `hdr` is an owned struct the
    // C side only writes on RVCSI_NX_OK (and zero-initialises first).
    let rc = unsafe { rvcsi_nx_csi_udp_header(payload.as_ptr(), payload.len(), &mut hdr) };
    check(rc)?;
    Ok(hdr.into())
}

/// Fully decode a nexmon_csi UDP payload (the 18-byte header + the CSI body).
/// Returns the parsed header and a [`NexmonRecord`] whose `timestamp_ns` is `0`
/// (the caller stamps it from the pcap packet time). `csi_format` is currently
/// only [`NEXMON_CSI_FMT_INT16_IQ`].
pub fn decode_nexmon_udp(
    payload: &[u8],
    csi_format: i32,
) -> Result<(NexmonCsiHeader, NexmonRecord), NexmonFfiError> {
    // First parse the header so we know `nsub` (and reject bad packets early).
    let header = parse_nexmon_udp_header(payload)?;
    let n = header.subcarrier_count as usize;
    if n == 0 || n > MAX_SUBCARRIERS {
        return Err(NexmonFfiError::Shim {
            code: 7,
            message: "subcarrier count out of range".to_string(),
        });
    }
    let mut hdr = RvcsiNxUdpHeader::default();
    let mut meta = RvcsiNxMeta {
        subcarrier_count: 0,
        channel: 0,
        bandwidth_mhz: 0,
        rssi_dbm: 0,
        noise_floor_dbm: 0,
        timestamp_ns: 0,
    };
    let mut i_out = vec![0.0f32; n];
    let mut q_out = vec![0.0f32; n];
    // SAFETY: `payload` valid for its length; `i_out`/`q_out` valid for `n`
    // f32s each (we pass `n` as the capacity); `hdr`/`meta` are owned structs
    // the C side fully initialises on RVCSI_NX_OK and writes nothing else.
    let rc = unsafe {
        rvcsi_nx_csi_udp_decode(
            payload.as_ptr(),
            payload.len(),
            csi_format,
            &mut hdr,
            &mut meta,
            i_out.as_mut_ptr(),
            q_out.as_mut_ptr(),
            n,
        )
    };
    check(rc)?;
    debug_assert_eq!(meta.subcarrier_count as usize, n);
    let rec = NexmonRecord {
        subcarrier_count: meta.subcarrier_count,
        channel: meta.channel,
        bandwidth_mhz: meta.bandwidth_mhz,
        rssi_dbm: (meta.rssi_dbm != ABSENT_I16).then_some(meta.rssi_dbm),
        noise_floor_dbm: (meta.noise_floor_dbm != ABSENT_I16).then_some(meta.noise_floor_dbm),
        timestamp_ns: meta.timestamp_ns,
        i_values: i_out,
        q_values: q_out,
    };
    Ok((NexmonCsiHeader::from(hdr), rec))
}

/// Serialize a synthetic nexmon_csi UDP payload (18-byte header + int16 I/Q body)
/// — used by tests and the synthetic Nexmon source. `i_values`/`q_values` are the
/// raw int16-valued samples (clamped to the int16 range on write); their length
/// must equal `header.subcarrier_count`.
pub fn encode_nexmon_udp(
    header: &NexmonCsiHeader,
    i_values: &[f32],
    q_values: &[f32],
) -> Result<Vec<u8>, NexmonFfiError> {
    let n = header.subcarrier_count as usize;
    if n == 0 || n > MAX_SUBCARRIERS || i_values.len() != n || q_values.len() != n {
        return Err(NexmonFfiError::Shim {
            code: 6,
            message: "bad subcarrier count or i/q length".to_string(),
        });
    }
    let c_hdr = header.to_c();
    let cap = NEXMON_HEADER_BYTES + n * 4;
    let mut buf = vec![0u8; cap];
    // SAFETY: `buf` valid for `cap` bytes; `i_in`/`q_in` valid for `n` f32s each
    // (checked above); `c_hdr` is a fully initialised owned struct.
    let written = unsafe {
        rvcsi_nx_csi_udp_write(
            buf.as_mut_ptr(),
            cap,
            &c_hdr as *const RvcsiNxUdpHeader,
            header.subcarrier_count,
            i_values.as_ptr(),
            q_values.as_ptr(),
        )
    };
    if written == 0 {
        return Err(NexmonFfiError::Shim {
            code: 4,
            message: "csi_udp_write failed (capacity or argument error)".to_string(),
        });
    }
    debug_assert_eq!(written, cap);
    buf.truncate(written);
    Ok(buf)
}

/// Bytes in the nexmon_csi UDP header (mirrors `RVCSI_NX_NEXMON_HDR_BYTES`).
pub const NEXMON_HEADER_BYTES: usize = 18;

/// nexmon_csi UDP payload magic (`0x1111`, the first two LE bytes of the header).
pub const NEXMON_MAGIC: u16 = 0x1111;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_is_not_a_record() {
        assert!(record_len(&[]).is_none());
        assert_eq!(decode_record(&[]).unwrap_err(), NexmonFfiError::NotARecord);
    }

    #[test]
    fn encode_then_decode_is_identity() {
        let rec = NexmonRecord {
            subcarrier_count: 4,
            channel: 11,
            bandwidth_mhz: 20,
            rssi_dbm: Some(-70),
            noise_floor_dbm: None,
            timestamp_ns: 999,
            i_values: vec![1.0, -2.0, 0.0, 3.5],
            q_values: vec![0.5, 0.25, -1.0, 0.0],
        };
        let bytes = encode_record(&rec).unwrap();
        assert_eq!(bytes.len(), RECORD_HEADER_BYTES + 16);
        let (back, consumed) = decode_record(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(back, rec);
    }

    #[test]
    fn rejects_zero_subcarriers_on_encode() {
        let rec = NexmonRecord {
            subcarrier_count: 0,
            channel: 1,
            bandwidth_mhz: 20,
            rssi_dbm: None,
            noise_floor_dbm: None,
            timestamp_ns: 0,
            i_values: vec![],
            q_values: vec![],
        };
        assert!(encode_record(&rec).is_err());
    }

    // ----- nexmon_csi UDP payload (format 2) -----

    #[test]
    fn chanspec_decode_known_values() {
        // 2.4 GHz, channel 6, 20 MHz: band 2G (0x0000) | BW_20 (0x1000) | 0x06
        let c = decode_chanspec(0x1000 | 6);
        assert_eq!(c.channel, 6);
        assert_eq!(c.bandwidth_mhz, 20);
        assert!(!c.is_5ghz);
        // 5 GHz, channel 36, 80 MHz: band 5G (0xc000) | BW_80 (0x2000) | 0x24
        let c = decode_chanspec(0xc000 | 0x2000 | 36);
        assert_eq!(c.channel, 36);
        assert_eq!(c.bandwidth_mhz, 80);
        assert!(c.is_5ghz);
        // 5 GHz, channel 149, 40 MHz: band 5G | BW_40 (0x1800) | 0x95
        let c = decode_chanspec(0xc000 | 0x1800 | 149);
        assert_eq!(c.channel, 149);
        assert_eq!(c.bandwidth_mhz, 40);
        assert!(c.is_5ghz);
        // channel > 14 with no/odd band bits still resolves to 5 GHz
        let c = decode_chanspec(40);
        assert_eq!(c.channel, 40);
        assert!(c.is_5ghz);
    }

    fn synth_header(rssi: i16, chanspec: u16, nsub: u16) -> NexmonCsiHeader {
        NexmonCsiHeader {
            rssi_dbm: rssi,
            fctl: 0x08,
            src_mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            seq_cnt: 0x1234,
            core: 1,
            spatial_stream: 0,
            chanspec,
            chip_ver: 0x4345, // BCM43455c0 chip ID
            channel: 0,       // filled by decode
            bandwidth_mhz: 0, // filled by decode
            is_5ghz: false,   // filled by decode
            subcarrier_count: nsub,
        }
    }

    #[test]
    fn nexmon_udp_roundtrip_and_metadata() {
        let nsub = 64u16; // 20 MHz
        let chanspec = 0x1000u16 | 6; // 2.4G, ch6, 20 MHz
        let hdr = synth_header(-58, chanspec, nsub);
        let i: Vec<f32> = (0..nsub).map(|k| (k as i16 - 32) as f32).collect();
        let q: Vec<f32> = (0..nsub).map(|k| -(k as i16) as f32 + 5.0).collect();
        let payload = encode_nexmon_udp(&hdr, &i, &q).expect("encode");
        assert_eq!(payload.len(), NEXMON_HEADER_BYTES + (nsub as usize) * 4);
        assert_eq!(u16::from_le_bytes([payload[0], payload[1]]), NEXMON_MAGIC);

        // header-only parse
        let h = parse_nexmon_udp_header(&payload).expect("hdr");
        assert_eq!(h.rssi_dbm, -58);
        assert_eq!(h.fctl, 0x08);
        assert_eq!(h.src_mac, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(h.seq_cnt, 0x1234);
        assert_eq!(h.core, 1);
        assert_eq!(h.chanspec, chanspec);
        assert_eq!(h.chip_ver, 0x4345);
        assert_eq!(h.channel, 6);
        assert_eq!(h.bandwidth_mhz, 20);
        assert!(!h.is_5ghz);
        assert_eq!(h.subcarrier_count, nsub);

        // full decode — raw int16 counts come back exactly
        let (h2, rec) = decode_nexmon_udp(&payload, NEXMON_CSI_FMT_INT16_IQ).expect("decode");
        assert_eq!(h2, h);
        assert_eq!(rec.subcarrier_count, nsub);
        assert_eq!(rec.channel, 6);
        assert_eq!(rec.bandwidth_mhz, 20);
        assert_eq!(rec.rssi_dbm, Some(-58));
        assert_eq!(rec.timestamp_ns, 0); // caller stamps from pcap
        assert_eq!(rec.i_values.len(), nsub as usize);
        assert_eq!(rec.i_values[0], -32.0);
        assert_eq!(rec.i_values[33], 1.0);
        assert_eq!(rec.q_values[0], 5.0);
        assert_eq!(rec.q_values[10], -5.0);
    }

    #[test]
    fn nexmon_udp_rejects_bad_magic_and_lengths() {
        let hdr = synth_header(-60, 0x1000 | 11, 64);
        let i = vec![1.0f32; 64];
        let q = vec![0.0f32; 64];
        let mut payload = encode_nexmon_udp(&hdr, &i, &q).unwrap();
        // bad magic
        payload[0] = 0xFF;
        assert!(parse_nexmon_udp_header(&payload).is_err());
        payload[0] = 0x11;
        // too short for header
        assert!(parse_nexmon_udp_header(&payload[..10]).is_err());
        // CSI body not a multiple of 4
        assert!(parse_nexmon_udp_header(&payload[..NEXMON_HEADER_BYTES + 3]).is_err());
        // zero-length CSI body
        assert!(parse_nexmon_udp_header(&payload[..NEXMON_HEADER_BYTES]).is_err());
        // unknown CSI format
        assert!(decode_nexmon_udp(&payload, 99).is_err());
    }

    #[test]
    fn nexmon_udp_80mhz_and_160mhz_bandwidths() {
        for (nsub, want_bw) in [(256u16, 80u16), (512u16, 160u16), (128u16, 40u16)] {
            let hdr = synth_header(-55, 0xc000 | 0x2000 | 36, nsub);
            let i = vec![0.0f32; nsub as usize];
            let q = vec![0.0f32; nsub as usize];
            let payload = encode_nexmon_udp(&hdr, &i, &q).unwrap();
            let h = parse_nexmon_udp_header(&payload).unwrap();
            assert_eq!(h.bandwidth_mhz, want_bw, "nsub={nsub}");
            assert!(h.is_5ghz);
            assert_eq!(h.channel, 36);
        }
    }
}

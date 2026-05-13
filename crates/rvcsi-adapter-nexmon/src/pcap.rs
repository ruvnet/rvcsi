//! Minimal, dependency-free reader for the classic libpcap (`.pcap`) file
//! format — enough to pull the UDP payloads out of a nexmon_csi capture
//! (`tcpdump -i wlan0 dst port 5500 -w csi.pcap`).
//!
//! Supports the standard byte-order / timestamp-resolution magics
//! (`0xa1b2c3d4`, `0xd4c3b2a1`, and the nanosecond variants `0xa1b23c4d` /
//! `0x4d3cb2a1`) and the link-layer types that show up for nexmon CSI captures:
//! Ethernet (`1`), raw IPv4 (`101` / `228`), and Linux SLL (`113`). pcapng is a
//! documented follow-up. No `unsafe`, no allocation beyond owning the packet
//! bytes, and every read is bounds-checked.

use rvcsi_core::RvcsiError;

/// Classic-pcap magic (microsecond timestamps), as the 32-bit value.
pub const PCAP_MAGIC_US: u32 = 0xa1b2_c3d4;
/// Classic-pcap magic (nanosecond timestamps), as the 32-bit value.
pub const PCAP_MAGIC_NS: u32 = 0xa1b2_3c4d;

/// Link-layer types we know how to peel down to an IPv4 packet.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// Raw IPv4 (no link header).
pub const LINKTYPE_RAW: u32 = 101;
/// Linux "cooked" capture v1 (16-byte pseudo-header).
pub const LINKTYPE_LINUX_SLL: u32 = 113;
/// Raw IPv4 (the IANA-assigned value).
pub const LINKTYPE_IPV4: u32 = 228;

/// The default UDP port nexmon_csi sends CSI frames to.
pub const NEXMON_DEFAULT_PORT: u16 = 5500;

/// One captured packet: its timestamp (ns since the Unix epoch) and raw bytes
/// (starting at the link layer named by [`PcapReader::link_type`]).
#[derive(Debug, Clone)]
pub struct PcapPacket {
    /// Capture timestamp, nanoseconds since the Unix epoch.
    pub timestamp_ns: u64,
    /// The packet bytes (truncated to the capture's snaplen, as on disk).
    pub data: Vec<u8>,
}

/// A parsed classic-pcap file.
#[derive(Debug, Clone)]
pub struct PcapReader {
    link_type: u32,
    packets: Vec<PcapPacket>,
}

fn parse_err(offset: usize, msg: impl Into<String>) -> RvcsiError {
    RvcsiError::parse(offset, format!("pcap: {}", msg.into()))
}

struct Endian(bool /* big-endian writer? */);
impl Endian {
    fn u32(&self, b: &[u8]) -> u32 {
        if self.0 {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        }
    }
}

impl PcapReader {
    /// Parse a classic-pcap byte buffer.
    pub fn parse(bytes: &[u8]) -> Result<PcapReader, RvcsiError> {
        if bytes.len() < 24 {
            return Err(parse_err(0, "buffer shorter than the 24-byte global header"));
        }
        // The 4 magic bytes on disk identify both byte order and ts resolution.
        // 0xa1b2c3d4 written by a LE host -> [d4,c3,b2,a1]; by a BE host -> [a1,b2,c3,d4].
        // 0xa1b23c4d (nanosecond ts): LE -> [4d,3c,b2,a1]; BE -> [a1,b2,3c,4d].
        let m = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let (endian, ts_is_ns) = match m {
            [0xd4, 0xc3, 0xb2, 0xa1] => (Endian(false), false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (Endian(true), false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (Endian(false), true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (Endian(true), true),
            _ => {
                let raw = u32::from_le_bytes(m);
                return Err(parse_err(
                    0,
                    format!("unrecognised pcap magic 0x{raw:08x} (pcapng is not supported)"),
                ));
            }
        };
        // bytes 4..6 version_major, 6..8 version_minor, 8..12 thiszone,
        // 12..16 sigfigs, 16..20 snaplen, 20..24 network (link type)
        let link_type = endian.u32(&bytes[20..24]);

        let mut packets = Vec::new();
        let mut off = 24usize;
        while off + 16 <= bytes.len() {
            let ts_sec = endian.u32(&bytes[off..off + 4]) as u64;
            let ts_frac = endian.u32(&bytes[off + 4..off + 8]) as u64;
            let incl_len = endian.u32(&bytes[off + 8..off + 12]) as usize;
            // orig_len at off+12..off+16 is informational; ignored.
            let data_start = off + 16;
            if incl_len > bytes.len().saturating_sub(data_start) {
                // Truncated final record — stop cleanly rather than erroring.
                break;
            }
            let timestamp_ns = ts_sec
                .saturating_mul(1_000_000_000)
                .saturating_add(if ts_is_ns { ts_frac } else { ts_frac.saturating_mul(1_000) });
            packets.push(PcapPacket {
                timestamp_ns,
                data: bytes[data_start..data_start + incl_len].to_vec(),
            });
            off = data_start + incl_len;
        }
        Ok(PcapReader { link_type, packets })
    }

    /// The capture's link-layer type (one of the `LINKTYPE_*` constants, or another value).
    pub fn link_type(&self) -> u32 {
        self.link_type
    }

    /// All captured packets, in file order.
    pub fn packets(&self) -> &[PcapPacket] {
        &self.packets
    }

    /// Iterate the UDP payloads in the capture whose destination port matches
    /// `port` (or all UDP payloads if `port` is `None`), as `(timestamp_ns,
    /// dst_port, payload)`. Non-IPv4 / non-UDP / non-matching packets are skipped.
    pub fn udp_payloads(
        &self,
        port: Option<u16>,
    ) -> impl Iterator<Item = (u64, u16, &[u8])> + '_ {
        let link_type = self.link_type;
        self.packets.iter().filter_map(move |pkt| {
            let (dst_port, payload) = extract_udp_payload(&pkt.data, link_type)?;
            if let Some(p) = port {
                if dst_port != p {
                    return None;
                }
            }
            Some((pkt.timestamp_ns, dst_port, payload))
        })
    }
}

/// Strip the link / network / transport headers from a captured frame with the
/// given link type and return `(udp_dst_port, udp_payload)`, or `None` if it
/// isn't an IPv4/UDP packet we can peel.
pub fn extract_udp_payload(frame: &[u8], link_type: u32) -> Option<(u16, &[u8])> {
    let ip = match link_type {
        LINKTYPE_ETHERNET => {
            if frame.len() < 14 {
                return None;
            }
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            if ethertype != 0x0800 {
                return None; // not IPv4 (ignore VLAN-tagged for now)
            }
            &frame[14..]
        }
        LINKTYPE_LINUX_SLL => {
            if frame.len() < 16 {
                return None;
            }
            let proto = u16::from_be_bytes([frame[14], frame[15]]);
            if proto != 0x0800 {
                return None;
            }
            &frame[16..]
        }
        LINKTYPE_RAW | LINKTYPE_IPV4 => frame,
        _ => return None,
    };

    // IPv4 header
    if ip.len() < 20 {
        return None;
    }
    if (ip[0] >> 4) != 4 {
        return None; // not IPv4
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != 17 {
        return None; // not UDP
    }
    let udp = &ip[ihl..];
    if udp.len() < 8 {
        return None;
    }
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize; // includes the 8-byte UDP header
    let payload_len = udp_len.saturating_sub(8).min(udp.len() - 8);
    Some((dst_port, &udp[8..8 + payload_len]))
}

/// Build a synthetic classic-pcap byte buffer — little-endian, microsecond
/// timestamps, [`LINKTYPE_ETHERNET`] — wrapping the given UDP payloads, one
/// Ethernet/IPv4/UDP packet each. Entries are `(timestamp_ns, dst_port,
/// payload)`. Intended for tests, examples and the `rvcsi` self-tests: real
/// captures come off a Raspberry Pi running patched firmware
/// (`tcpdump -i wlan0 dst port 5500 -w csi.pcap`).
pub fn synthetic_udp_pcap(packets: &[(u64, u16, &[u8])]) -> Vec<u8> {
    fn eth_ip_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst mac
            0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // src mac
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
    let mut b = Vec::new();
    b.extend_from_slice(&PCAP_MAGIC_US.to_le_bytes());
    b.extend_from_slice(&[2, 0, 4, 0]); // version major/minor
    b.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    b.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    b.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    b.extend_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    for (ts_ns, dst_port, payload) in packets {
        let frame = eth_ip_udp(*dst_port, payload);
        let ts_sec = (ts_ns / 1_000_000_000) as u32;
        let ts_usec = ((ts_ns % 1_000_000_000) / 1_000) as u32;
        b.extend_from_slice(&ts_sec.to_le_bytes());
        b.extend_from_slice(&ts_usec.to_le_bytes());
        b.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
        b.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
        b.extend_from_slice(&frame);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic Ethernet/IPv4/UDP frame carrying `payload` to `dst_port`.
    fn eth_ip_udp(dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        // Ethernet II: dst[6] src[6] ethertype[2]
        f.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        f.extend_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        // IPv4: 20-byte header
        let total_len = (20 + 8 + payload.len()) as u16;
        let mut ip = vec![
            0x45, 0x00, // version/IHL, DSCP/ECN
        ];
        ip.extend_from_slice(&total_len.to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17]); // id, flags/frag, ttl, proto=UDP
        ip.extend_from_slice(&[0, 0]); // header checksum (not checked here)
        ip.extend_from_slice(&[10, 0, 0, 1]); // src ip
        ip.extend_from_slice(&[10, 0, 0, 20]); // dst ip
        assert_eq!(ip.len(), 20);
        f.extend_from_slice(&ip);
        // UDP: src_port[2] dst_port[2] length[2] checksum[2]
        f.extend_from_slice(&54321u16.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(payload);
        f
    }

    /// Build a minimal classic-pcap file (LE, microsecond) wrapping the frames.
    fn pcap_le_us(link_type: u32, frames: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&PCAP_MAGIC_US.to_le_bytes());
        b.extend_from_slice(&2u16.to_le_bytes()); // version major
        b.extend_from_slice(&4u16.to_le_bytes()); // version minor
        b.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        b.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        b.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        b.extend_from_slice(&link_type.to_le_bytes());
        for (ts_sec, ts_usec, frame) in frames {
            b.extend_from_slice(&ts_sec.to_le_bytes());
            b.extend_from_slice(&ts_usec.to_le_bytes());
            b.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
            b.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
            b.extend_from_slice(frame);
        }
        b
    }

    #[test]
    fn parses_global_header_and_iterates_udp_payloads() {
        let p1 = vec![0xaa; 30];
        let p2 = vec![0xbb; 12];
        let other = vec![0xcc; 8];
        let frames = vec![
            (100u32, 250_000u32, eth_ip_udp(5500, &p1)),
            (101u32, 500_000u32, eth_ip_udp(9999, &other)), // different port
            (102u32, 0u32, eth_ip_udp(5500, &p2)),
        ];
        let file = pcap_le_us(LINKTYPE_ETHERNET, &frames);
        let r = PcapReader::parse(&file).unwrap();
        assert_eq!(r.link_type(), LINKTYPE_ETHERNET);
        assert_eq!(r.packets().len(), 3);

        let csi: Vec<_> = r.udp_payloads(Some(5500)).collect();
        assert_eq!(csi.len(), 2);
        assert_eq!(csi[0].0, 100 * 1_000_000_000 + 250_000 * 1_000); // ts_ns
        assert_eq!(csi[0].1, 5500);
        assert_eq!(csi[0].2, &p1[..]);
        assert_eq!(csi[1].2, &p2[..]);

        // no filter -> all 3 UDP payloads
        assert_eq!(r.udp_payloads(None).count(), 3);
    }

    #[test]
    fn handles_raw_ipv4_linktype() {
        // raw IPv4 frame = the IPv4 packet directly (no Ethernet header)
        let payload = vec![0x11; 20];
        let eth = eth_ip_udp(5500, &payload);
        let raw_ip = eth[14..].to_vec(); // strip the 14-byte Ethernet header
        let file = pcap_le_us(LINKTYPE_RAW, &[(5u32, 0u32, raw_ip)]);
        let r = PcapReader::parse(&file).unwrap();
        let v: Vec<_> = r.udp_payloads(Some(5500)).collect();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].2, &payload[..]);
    }

    #[test]
    fn nanosecond_magic_scales_timestamps_correctly() {
        let mut file = pcap_le_us(LINKTYPE_ETHERNET, &[(7u32, 123u32, eth_ip_udp(5500, &[0u8; 8]))]);
        // patch the magic to the nanosecond variant
        file[0..4].copy_from_slice(&PCAP_MAGIC_NS.to_le_bytes());
        let r = PcapReader::parse(&file).unwrap();
        let v: Vec<_> = r.udp_payloads(Some(5500)).collect();
        assert_eq!(v[0].0, 7 * 1_000_000_000 + 123); // ts_frac taken as ns, not us
    }

    #[test]
    fn rejects_garbage_and_pcapng() {
        assert!(PcapReader::parse(&[0u8; 10]).is_err()); // too short
        assert!(PcapReader::parse(&[0u8; 24]).is_err()); // zero magic
        // pcapng section-header-block magic (0x0a0d0d0a) — not supported
        let mut ng = vec![0x0a, 0x0d, 0x0d, 0x0a];
        ng.extend_from_slice(&[0u8; 24]);
        assert!(PcapReader::parse(&ng).is_err());
    }

    #[test]
    fn truncated_final_record_is_tolerated() {
        let mut file = pcap_le_us(LINKTYPE_ETHERNET, &[(1u32, 0u32, eth_ip_udp(5500, &[0u8; 16]))]);
        // append a partial record header + claim a huge incl_len
        file.extend_from_slice(&2u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&9999u32.to_le_bytes()); // incl_len > remaining
        file.extend_from_slice(&9999u32.to_le_bytes());
        file.extend_from_slice(&[0xde, 0xad]); // only 2 bytes of "data"
        let r = PcapReader::parse(&file).unwrap();
        assert_eq!(r.packets().len(), 1); // the complete one only
    }

    #[test]
    fn extract_udp_payload_rejects_non_udp() {
        // build an Ethernet/IPv4 frame but with proto = TCP (6)
        let mut eth = eth_ip_udp(5500, &[0u8; 8]);
        // IPv4 proto byte is at Ethernet(14) + 9 = 23
        eth[14 + 9] = 6; // TCP
        assert!(extract_udp_payload(&eth, LINKTYPE_ETHERNET).is_none());
        // wrong ethertype
        let mut eth = eth_ip_udp(5500, &[0u8; 8]);
        eth[12] = 0x86;
        eth[13] = 0xdd; // IPv6
        assert!(extract_udp_payload(&eth, LINKTYPE_ETHERNET).is_none());
        // unknown link type
        assert!(extract_udp_payload(&eth, 9999).is_none());
    }
}

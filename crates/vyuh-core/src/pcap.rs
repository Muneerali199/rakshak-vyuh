//! Classic libpcap file reader plus IPv4/IPv6 and UDP demultiplexing.
//!
//! Scope is deliberately narrow: enough to reach UDP 500/4500 and IP protocol
//! 50/51. Anything else is skipped rather than guessed at.

use crate::error::{Result, VyuhError};
use crate::reader::Reader;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const LINKTYPE_NULL: u16 = 0;
pub const LINKTYPE_ETHERNET: u16 = 1;
pub const LINKTYPE_RAW: u16 = 101;
pub const LINKTYPE_LINUX_SLL: u16 = 113;

pub const IPPROTO_HOPOPT: u8 = 0;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_AH: u8 = 51;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_DSTOPTS: u8 = 60;
pub const IPPROTO_UDP: u8 = 17;

/// One IP packet lifted out of the capture. `index` is the citation handle that
/// every finding downstream points at.
#[derive(Debug, Clone)]
pub struct IpPacket {
    /// 1-based position in the capture file.
    pub index: u32,
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub wire_len: u32,
    pub src: String,
    pub dst: String,
    pub protocol: u8,
    pub ip_version: u8,
    /// Transport payload: UDP header already stripped, or the whole AH header.
    pub payload: Vec<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// True when the IP layer carried a non-zero fragment offset.
    pub fragmented: bool,
}

/// Streaming pcap reader. Holds the underlying reader, not a buffer, so a
/// multi-gigabyte capture streams in constant memory.
pub struct PcapReader<R> {
    inner: R,
    linktype: u16,
    big_endian: bool,
    nanosecond: bool,
    index: u32,
}

impl<R: std::io::Read> PcapReader<R> {
    /// Parse the 24-byte global header and position the reader at packet 1.
    pub fn open(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        read_exact_or_eof(&mut r, &mut magic)
            .map_err(|_| VyuhError::Pcap("file too short to contain a pcap header".into()))?;

        let (big_endian, nanosecond) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
            other => {
                return Err(VyuhError::Pcap(format!(
                    "unrecognised magic {:02x?} — this file is not classic pcap (pcapng is not yet supported)",
                    other
                )))
            }
        };

        let mut gh = [0u8; 20];
        r.read_exact(&mut gh).map_err(|e| VyuhError::Pcap(format!("short global header: {e}")))?;

        let linktype = order32(&gh[16..20], big_endian) as u32;
        if linktype > u16::MAX as u32 {
            return Err(VyuhError::Pcap(format!("implausible linktype {linktype}")));
        }

        Ok(Self {
            inner: r,
            linktype: linktype as u16,
            big_endian,
            nanosecond,
            index: 0,
        })
    }

    /// Return the next decodable IP packet, or `None` at clean end of file.
    ///
    /// Frames we cannot use (ARP, DNS, IP fragments needing reassembly) are
    /// skipped internally so callers see only actionable packets.
    pub fn next_packet(&mut self) -> Result<Option<IpPacket>> {
        loop {
            let mut ph = [0u8; 16];
            match read_exact_or_eof(&mut self.inner, &mut ph) {
                Ok(()) => {}
                Err(VyuhError::Pcap(_)) => return Ok(None),
                Err(e) => return Err(e),
            }

            let ts_sec = order32(&ph[0..4], self.big_endian);
            let ts_raw = order32(&ph[4..8], self.big_endian);
            let incl_len = order32(&ph[8..12], self.big_endian) as usize;
            let orig_len = order32(&ph[12..16], self.big_endian);

            // Defensive bound: no single IP packet we care about needs 16 MiB.
            if incl_len > 0x0100_0000 {
                return Err(VyuhError::Pcap(format!(
                    "packet record claims {incl_len} bytes, which is not plausible"
                )));
            }

            let frame = match self.read_frame(incl_len) {
                Some(f) => f,
                None => return Ok(None),
            };

            self.index = self.index.wrapping_add(1);
            let index = self.index;
            let ts_usec = if self.nanosecond { ts_raw / 1000 } else { ts_raw };

            if let Some(mut pkt) = self.decode_frame(&frame) {
                pkt.index = index;
                pkt.ts_sec = ts_sec;
                pkt.ts_usec = ts_usec;
                pkt.wire_len = orig_len;
                return Ok(Some(pkt));
            }
        }
    }

    fn read_frame(&mut self, n: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; n];
        read_exact_or_eof(&mut self.inner, &mut buf).ok()?;
        Some(buf)
    }

    fn decode_frame(&self, frame: &[u8]) -> Option<IpPacket> {
        let mut r = Reader::new(frame);
        let network = match self.linktype {
            LINKTYPE_ETHERNET => {
                r.skip(12).ok()?; // destination + source MAC
                match r.u16_be().ok()? {
                    0x0800 => 4,
                    0x86DD => 6,
                    0x8100 => {
                        r.skip(2).ok()?; // 802.1Q tag
                        match r.u16_be().ok()? {
                            0x0800 => 4,
                            0x86DD => 6,
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
            LINKTYPE_RAW => match frame.first()? >> 4 {
                4 => 4,
                6 => 6,
                _ => return None,
            },
            LINKTYPE_NULL => match r.u32_be().ok()? {
                2 => 4,
                24 | 28 | 30 => 6,
                _ => return None,
            },
            LINKTYPE_LINUX_SLL => {
                r.skip(14).ok()?;
                match r.u16_be().ok()? {
                    0x0800 => 4,
                    0x86DD => 6,
                    _ => return None,
                }
            }
            _ => return None,
        };

        if network == 4 {
            self.decode_ipv4(&mut r)
        } else {
            self.decode_ipv6(&mut r)
        }
    }

    fn decode_ipv4(&self, r: &mut Reader<'_>) -> Option<IpPacket> {
        let vihl = r.u8().ok()?;
        let ihl = (vihl & 0x0F) as usize * 4;
        if ihl < 20 {
            return None;
        }
        r.skip(1).ok()?; // DSCP/ECN
        let total_len = r.u16_be().ok()? as usize;
        r.skip(2).ok()?; // identification
        let flags_frag = r.u16_be().ok()?;
        r.skip(1).ok()?; // TTL
        let protocol = r.u8().ok()?;
        r.skip(2).ok()?; // header checksum — offload makes this unreliable anyway
        let src = Ipv4Addr::new(r.u8().ok()?, r.u8().ok()?, r.u8().ok()?, r.u8().ok()?);
        let dst = Ipv4Addr::new(r.u8().ok()?, r.u8().ok()?, r.u8().ok()?, r.u8().ok()?);
        r.skip(ihl - 20).ok()?;

        // Never parse a fragment as if it were a whole datagram.
        let fragment_offset = flags_frag & 0x1FFF;
        let more_fragments = flags_frag & 0x2000 != 0;

        let ip_payload = r.remaining().min(total_len.saturating_sub(ihl));
        if ip_payload == 0 {
            return None;
        }
        let l4 = r.take(ip_payload).ok()?;

        let (src_port, dst_port, payload) = match protocol {
            IPPROTO_UDP => {
                if l4.len() < 8 {
                    return None;
                }
                let sp = u16::from_be_bytes([l4[0], l4[1]]);
                let dp = u16::from_be_bytes([l4[2], l4[3]]);
                (Some(sp), Some(dp), l4[8..].to_vec())
            }
            _ => (None, None, l4.to_vec()),
        };

        Some(IpPacket {
            index: 0,
            ts_sec: 0,
            ts_usec: 0,
            wire_len: 0,
            src: src.to_string(),
            dst: dst.to_string(),
            protocol,
            ip_version: 4,
            payload,
            src_port,
            dst_port,
            fragmented: more_fragments || fragment_offset != 0,
        })
    }

    fn decode_ipv6(&self, r: &mut Reader<'_>) -> Option<IpPacket> {
        r.skip(4).ok()?; // version / traffic class / flow label
        let payload_len = r.u16_be().ok()? as usize;
        let mut next_header = r.u8().ok()?;
        r.skip(1).ok()?; // hop limit

        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(r.take(16).ok()?);
        dst.copy_from_slice(r.take(16).ok()?);

        // Walk the extension chain, bounded so a malformed chain cannot loop.
        let mut guard = 0;
        let mut fragmented = false;
        while matches!(
            next_header,
            IPPROTO_HOPOPT | IPPROTO_ROUTING | IPPROTO_DSTOPTS
        ) {
            guard += 1;
            if guard > 8 {
                return None;
            }
            let hdr_ext_len = r.u8().ok()? as usize;
            r.skip(1).ok()?;
            r.skip(2).ok()?; // ext length field
            // Length is in 8-octet units, not counting the first 8 octets.
            let extra = hdr_ext_len.saturating_mul(8);
            r.skip(extra).ok()?;
            next_header = r.u8().ok()?;
        }

        if next_header == IPPROTO_FRAGMENT {
            fragmented = true;
            r.skip(8).ok()?;
            next_header = r.u8().ok()?;
        }

        let avail = r.remaining().min(payload_len);
        if avail == 0 {
            return None;
        }
        let l4 = r.take(avail).ok()?;

        let (src_port, dst_port, payload) = match next_header {
            IPPROTO_UDP => {
                if l4.len() < 8 {
                    return None;
                }
                let sp = u16::from_be_bytes([l4[0], l4[1]]);
                let dp = u16::from_be_bytes([l4[2], l4[3]]);
                (Some(sp), Some(dp), l4[8..].to_vec())
            }
            _ => (None, None, l4.to_vec()),
        };

        Some(IpPacket {
            index: 0,
            ts_sec: 0,
            ts_usec: 0,
            wire_len: 0,
            src: Ipv6Addr::from(src).to_string(),
            dst: Ipv6Addr::from(dst).to_string(),
            protocol: next_header,
            ip_version: 6,
            payload,
            src_port,
            dst_port,
            fragmented,
        })
    }
}

#[inline]
fn order32(b: &[u8], big_endian: bool) -> u32 {
    if big_endian {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }
}

fn read_exact_or_eof<R: std::io::Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(VyuhError::Pcap(
                    "end of file in the middle of a record".into(),
                ))
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(VyuhError::Io(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet / IPv4 / UDP / 500 with a 4-byte marker payload.
    fn synth_pcap() -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xAA; 6]); // dst mac
        frame.extend_from_slice(&[0xBB; 6]); // src mac
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4

        let udp_len: u16 = 8 + 4;
        let total_len: u16 = 20 + udp_len;
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]); // id
        frame.extend_from_slice(&[0x00, 0x00]); // flags + fragment offset
        frame.push(64); // TTL
        frame.push(17); // UDP
        frame.extend_from_slice(&[0x00, 0x00]); // checksum (offloaded in the wild)
        frame.extend_from_slice(&[10, 0, 0, 1]); // src
        frame.extend_from_slice(&[10, 0, 0, 2]); // dst

        frame.extend_from_slice(&500u16.to_be_bytes());
        frame.extend_from_slice(&500u16.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // magic, little-endian
        v.extend_from_slice(&[2, 0, 4, 0]); // version 2.4
        v.extend_from_slice(&[0, 0, 0, 0]); // thiszone
        v.extend_from_slice(&[0, 0, 0, 0]); // sigfigs
        v.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]); // snaplen 65535
        v.extend_from_slice(&[1, 0, 0, 0]); // LINKTYPE_ETHERNET

        v.extend_from_slice(&[1, 0, 0, 0]); // ts_sec
        v.extend_from_slice(&[2, 0, 0, 0]); // ts_usec
        v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        v.extend_from_slice(&frame);
        v
    }

    #[test]
    fn decodes_udp_500_and_keeps_citation_index() {
        let mut rd = PcapReader::open(std::io::Cursor::new(synth_pcap())).unwrap();
        let pkt = rd.next_packet().unwrap().expect("one packet expected");
        assert_eq!(pkt.index, 1);
        assert_eq!(pkt.ip_version, 4);
        assert_eq!(pkt.protocol, IPPROTO_UDP);
        assert_eq!(pkt.src_port, Some(500));
        assert_eq!(pkt.dst_port, Some(500));
        assert_eq!(pkt.src, "10.0.0.1");
        assert_eq!(pkt.dst, "10.0.0.2");
        assert_eq!(pkt.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(!pkt.fragmented);
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut rd = PcapReader::open(std::io::Cursor::new(synth_pcap())).unwrap();
        assert!(rd.next_packet().unwrap().is_some());
        assert!(rd.next_packet().unwrap().is_none());
    }

    #[test]
    fn rejects_a_non_pcap_file() {
        assert!(PcapReader::open(std::io::Cursor::new(vec![0u8; 24])).is_err());
    }

    #[test]
    fn skips_non_ip_frames_without_inflating_the_index() {
        let mut v = synth_pcap();
        // Append an ARP frame (EtherType 0x0806) with a valid record header.
        let arp: Vec<u8> = {
            let mut f = vec![0xFF; 6];
            f.extend_from_slice(&[0xFF; 6]);
            f.extend_from_slice(&[0x08, 0x06]);
            f.extend_from_slice(&[0u8; 28]);
            f
        };
        v.extend_from_slice(&[3, 0, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&(arp.len() as u32).to_le_bytes());
        v.extend_from_slice(&(arp.len() as u32).to_le_bytes());
        v.extend_from_slice(&arp);

        let mut rd = PcapReader::open(std::io::Cursor::new(v)).unwrap();
        assert!(rd.next_packet().unwrap().is_some());
        // The ARP frame is dropped, so the counter never reaches 2.
        assert!(rd.next_packet().unwrap().is_none());
    }
}

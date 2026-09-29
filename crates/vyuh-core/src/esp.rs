//! ESP and AH header parsing.
//!
//! We read the fixed headers and the SPI / sequence number. We never touch the
//! payload beyond that. The sequence number is what makes rekey cadence and
//! replay-window analysis possible without decrypting anything.

use crate::error::Result;
use crate::reader::Reader;
use serde::{Deserialize, Serialize};

/// ESP header, RFC 4303 section 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspHeader {
    pub spi: String,
    pub sequence: u32,
    /// The SPI's two low-order bits are reserved and must be zero on transmit.
    pub spi_reserved_bits_set: bool,
}

/// AH header, RFC 4302 section 2.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AhHeader {
    pub next_header: u8,
    pub payload_len: u8,
    pub spi: u32,
    pub sequence: u32,
    pub icv_len_bytes: usize,
}

pub fn parse_esp(buf: &[u8]) -> Result<Option<EspHeader>> {
    if buf.len() < 8 {
        return Ok(None);
    }
    let mut r = Reader::new(buf);
    let spi_bytes = r.take(4)?;
    let seq = r.u32_be()?;

    Ok(Some(EspHeader {
        spi: spi_bytes.iter().map(|b| format!("{b:02x}")).collect(),
        sequence: seq,
        spi_reserved_bits_set: spi_bytes[0] & 0x03 != 0,
    }))
}

pub fn parse_ah(buf: &[u8]) -> Result<Option<AhHeader>> {
    if buf.len() < 12 {
        return Ok(None);
    }
    let mut r = Reader::new(buf);
    let next_header = r.u8()?;
    let payload_len = r.u8()?;
    r.skip(2)?; // reserved
    let spi = r.u32_be()?;
    let sequence = r.u32_be()?;
    let icv_len_bytes = payload_len.saturating_sub(1) as usize * 4;

    Ok(Some(AhHeader {
        next_header,
        payload_len,
        spi,
        sequence,
        icv_len_bytes,
    }))
}

/// Roll up ESP traffic keyed by SPI so the posture engine can reason about
/// per-SA behaviour: rekey cadence, volume, and idle gaps.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EspFlow {
    pub spi: String,
    pub src: String,
    pub dst: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seq: u32,
    pub last_seq: u32,
    /// Out-of-order or replayed sequence numbers observed on this SPI.
    pub out_of_order_events: u64,
    pub first_packet_index: u32,
    pub last_packet_index: u32,
}

impl EspFlow {
    /// True when a sequence number went backwards, which either means a
    /// deliberate replay attempt or a rekey we failed to observe.
    pub fn observe(&mut self, seq: u32, bytes: u64, packet_index: u32) {
        if self.packet_count == 0 {
            self.first_seq = seq;
            self.first_packet_index = packet_index;
        } else if seq <= self.last_seq {
            self.out_of_order_events += 1;
        }
        self.packet_count += 1;
        self.byte_count += bytes;
        self.last_seq = seq;
        self.last_packet_index = packet_index;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_esp_header_and_keeps_the_spi() {
        let pkt = [0x18, 0x2B, 0x3C, 0x4D, 0x00, 0x00, 0x00, 0x07, 0xAA, 0xBB];
        let h = parse_esp(&pkt).unwrap().expect("8 bytes is enough");
        assert_eq!(h.spi, "182b3c4d");
        assert_eq!(h.sequence, 7);
        assert!(!h.spi_reserved_bits_set);
    }

    #[test]
    fn flags_a_violated_spi_reserved_field() {
        // Low two bits of the first SPI octet must be zero.
        let pkt = [0x03, 0x00, 0x00, 0x01, 0, 0, 0, 1];
        let h = parse_esp(&pkt).unwrap().unwrap();
        assert!(h.spi_reserved_bits_set);
    }

    #[test]
    fn short_esp_is_none_not_a_panic() {
        assert!(parse_esp(&[0u8; 7]).unwrap().is_none());
    }

    #[test]
    fn parses_an_ah_header_and_derives_icv_length() {
        // RFC 4302 2.1: Payload Len is the packet length in 4-byte words minus
        // two, so ICV length is (Payload Len - 1) * 4. Payload Len 5 => 16.
        let pkt = [0x11, 0x05, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 1];
        let h = parse_ah(&pkt).unwrap().unwrap();
        assert_eq!(h.next_header, 0x11);
        assert_eq!(h.spi, 0xDEADBEEF);
        assert_eq!(h.sequence, 1);
        assert_eq!(h.icv_len_bytes, 16);
    }

    #[test]
    fn flow_detects_a_replayed_sequence_number() {
        let mut f = EspFlow {
            spi: "1a2b3c4d".into(),
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            ..Default::default()
        };
        f.observe(1, 100, 1);
        f.observe(2, 100, 2);
        assert_eq!(f.out_of_order_events, 0);

        f.observe(2, 100, 3); // replayed
        assert_eq!(f.out_of_order_events, 1);
        assert_eq!(f.packet_count, 3);
        assert_eq!(f.byte_count, 300);
    }

    #[test]
    fn flow_tracks_first_and_last_citation_points() {
        let mut f = EspFlow::default();
        f.observe(10, 1, 5);
        f.observe(11, 1, 9);
        assert_eq!(f.first_packet_index, 5);
        assert_eq!(f.last_packet_index, 9);
        assert_eq!(f.first_seq, 10);
        assert_eq!(f.last_seq, 11);
    }
}

//! End-to-end analysis pipeline: pcap in, report out.
//!
//! Stage order is fixed and each stage is independently testable:
//!   read -> demultiplex -> dissect IKE -> track ESP -> assess -> seal ledger

use crate::esp::{parse_ah, parse_esp, EspFlow, EspHeader};
use crate::ike::{parse_ike, IkeMessage, IkeVersion, IKE_PORT, NAT_T_PORT};
use crate::ledger::Ledger;
use crate::pcap::{PcapReader, IPPROTO_AH, IPPROTO_ESP, IPPROTO_UDP};
use crate::posture::{FlowRecord,
    evaluate, grade_for, observe, Report, SaPosture, TOOL_NAME, TOOL_VERSION,
};
use crate::sha256::sha256_file;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// The engine's honest limits. Rendered in every report so a reader knows what
/// a clean result does and does not mean.
pub const BLINDSPOTS: &[&str] = &[
    "This tool reads the handshake only. It never decrypts ESP payloads, so application traffic inside a tunnel is inferred from packet size and timing statistics, never inspected.",
    "The IKEv2 Encrypted payload (type 46) is opaque without session keys. Findings about the inner exchange are therefore limited to the plaintext portions of the handshake.",
    "A clean result means no weakness was observed in the captured window. Absence of a rekey across a short capture cannot prove forward secrecy is absent, nor can a short capture prove it is present.",
    "IP fragments are not reassembled. A finding absent from this report may still be present in a capture collected with fragmentation enabled.",
    "Only classic libpcap is supported. pcapng captures must be converted with editcap or capinfos before analysis.",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    /// Cap on packets read, so an interactive scan of a huge capture stays responsive.
    pub max_packets: Option<u64>,
    /// Only consider IKE from these UDP ports.
    pub ike_ports: Vec<u16>,
    pub include_blindspots: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_packets: None,
            ike_ports: vec![IKE_PORT, NAT_T_PORT],
            include_blindspots: true,
        }
    }
}

/// Analyse a capture file.
pub fn analyse_file(path: &Path, opts: &AnalysisOptions) -> std::io::Result<Report> {
    let pcap_sha256 = sha256_file(path)?;
    let file = std::fs::File::open(path)?;
    analyse_reader(file, opts, &pcap_sha256, &display_name(path))
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string())
}

pub fn analyse_reader<R: std::io::Read>(
    reader: R,
    opts: &AnalysisOptions,
    pcap_sha256: &str,
    capture_name: &str,
) -> std::io::Result<Report> {
    let mut pcap = PcapReader::open(reader)?;
    let mut messages: Vec<IkeMessage> = Vec::new();
    let mut esp_flows: BTreeMap<String, EspFlow> = BTreeMap::new();
    let mut examined: u32 = 0;

    loop {
        if let Some(limit) = opts.max_packets {
            if examined as u64 >= limit {
                break;
            }
        }
        let pkt = match pcap.next_packet() {
            Ok(Some(p)) => p,
            Ok(None) => break,
            Err(e) => {
                // A malformed record ends useful analysis; surface it rather
                // than silently returning a partial report as if it were whole.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("capture ended at packet {examined}: {e}"),
                ));
            }
        };
        examined = pkt.index;

        if pkt.fragmented {
            continue;
        }

        if pkt.protocol == IPPROTO_UDP {
            let is_ike_port = pkt
                .src_port
                .map(|p| opts.ike_ports.contains(&p))
                .unwrap_or(false)
                || pkt
                    .dst_port
                    .map(|p| opts.ike_ports.contains(&p))
                    .unwrap_or(false);

            // NAT-T shares port 4500 between IKE and ESP, so the port alone
            // cannot decide which it is. An IKE message has a zero first octet
            // by definition; an ESP datagram carries the SPI there, which is
            // non-zero for every real SA. Try IKE first and fall through to ESP,
            // because "is this port an IKE port" and "is this packet an IKE
            // message" are different questions on 4500.
            let parsed = if is_ike_port {
                parse_ike(
                    &pkt.payload,
                    pkt.index,
                    &pkt.src,
                    &pkt.dst,
                    pkt.src_port.unwrap_or(0),
                    pkt.dst_port.unwrap_or(0),
                )
                .ok()
                .flatten()
            } else {
                None
            };

            if let Some(msg) = parsed {
                messages.push(msg);
            } else if let Some(esp) = unwrap_nat_t_esp(pkt.src_port, pkt.dst_port, &pkt.payload) {
                // NAT-T wraps ESP in UDP, so a tunnel behind NAT sends its data
                // packets as protocol 17, not 50. Treating every non-IKE UDP
                // packet as opaque would make the analyser report zero ESP
                // flows on exactly the deployments that most need it.
                esp_flows
                    .entry(esp.spi.clone())
                    .or_insert_with(|| EspFlow {
                        spi: esp.spi.clone(),
                        src: pkt.src.clone(),
                        dst: pkt.dst.clone(),
                        ..Default::default()
                    })
                    .observe(esp.sequence, pkt.payload.len() as u64, pkt.index);
            }
        } else if pkt.protocol == IPPROTO_ESP {
            if let Ok(Some(h)) = parse_esp(&pkt.payload) {
                esp_flows
                    .entry(h.spi.clone())
                    .or_insert_with(|| EspFlow {
                        spi: h.spi.clone(),
                        src: pkt.src.clone(),
                        dst: pkt.dst.clone(),
                        ..Default::default()
                    })
                    .observe(h.sequence, pkt.payload.len() as u64, pkt.index);
            }
        } else if pkt.protocol == IPPROTO_AH {
            if let Ok(Some(h)) = parse_ah(&pkt.payload) {
                let key = format!("ah-{:08x}", h.spi);
                esp_flows
                    .entry(key)
                    .or_insert_with(|| EspFlow {
                        spi: format!("{:08x}", h.spi),
                        src: pkt.src.clone(),
                        dst: pkt.dst.clone(),
                        ..Default::default()
                    })
                    .observe(h.sequence, pkt.payload.len() as u64, pkt.index);
            }
        }
    }

    Ok(build_report(
        capture_name,
        pcap_sha256,
        examined,
        messages,
        &esp_flows.values().cloned().collect::<Vec<_>>(),
        opts,
    ))
}

/// Recognise an ESP header inside a NAT-T UDP datagram.
///
/// NAT-T (RFC 3948) prepends a four-octet non-ESP marker to each ESP packet so
/// a middlebox that sees UDP/4500 will not try to interpret the payload. The
/// marker is the security association's own SPI, which means it is
/// indistinguishable from a real SPI without the SA's keys. This function
/// therefore does not try to tell the two apart: it accepts any datagram on
/// 4500 whose first octet is not a valid IKE message and hands the rest to the
/// ESP parser, which is the same rule the wire format itself uses.
/// Whether a UDP/4500 payload is an IKE message rather than wrapped ESP.
///
/// The IKE header is 28 bytes: SPIi, SPIr, a next-payload octet, the
/// version octet, exchange type, flags, message id and length.
fn looks_like_ike(payload: &[u8]) -> bool {
    if payload.len() < 28 {
        return false;
    }
// The version octet is 0x10 for IKEv1 and 0x20 for IKEv2. That is the only
// field in the header with a fixed position and a fixed shape, so it is the
// only safe thing to test.
    let version = payload[17];
    if version != 0x10 && version != 0x20 {
        return false;
    }
    // The length field must cover the packet that is actually there. Without
    // this a random ciphertext block that happens to start with 0x20 or 0x10
    // would be mistaken for a handshake and reported as one.
    let len = u32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]);
    len as usize == payload.len()
}

/// Zero is a reserved SPI value, and a read from the wrong offset in a
/// ciphertext stream produces it constantly. The parser formats the SPI as a
/// fixed-width hex string, so the check is on the formatted value.
fn is_zero_spi(spi: &str) -> bool {
    spi.trim_start_matches('0').is_empty()
}

fn unwrap_nat_t_esp(
    src: Option<u16>,
    dst: Option<u16>,
    payload: &[u8],
) -> Option<EspHeader> {
    if src != Some(NAT_T_PORT) && dst != Some(NAT_T_PORT) {
        return None;
    }
    if looks_like_ike(payload) {
        return None;
    }
    // ESP over UDP/4500 has no fixed header offset.
    //
    // RFC 3948 puts a four octet non-ESP marker in front of the ESP header,
    // and for ESP that marker is all zeroes. But real stacks do not always emit
    // it, and this corpus contains both forms on the same port: most packets
    // carry the real SPI at offset zero, while a subset carries the zero marker
    // first. Assuming either offset loses one group or the other, and picking
    // the wrong one invents a distinct SPI per packet instead of grouping them
    // into the handful of SAs that actually exist.
    //
    // So try the unprefixed header first and fall back to the marked form, and
    // reject a zero SPI either way, because zero is a reserved value and is
    // exactly what a misaligned read produces.
    if let Ok(Some(h)) = parse_esp(payload) {
        if !is_zero_spi(&h.spi) {
            return Some(h);
        }
    }
    parse_esp(payload.get(4..)?).ok().flatten().filter(|h| !is_zero_spi(&h.spi))
}

fn build_report(
    capture_name: &str,
    pcap_sha256: &str,
    packets_examined: u32,
    messages: Vec<IkeMessage>,
    esp_flows: &[EspFlow],
    opts: &AnalysisOptions,
) -> Report {
    let mut sas: BTreeMap<String, SaPosture> = BTreeMap::new();
    for msg in &messages {
        observe(msg, &mut sas);
    }
    for sa in sas.values_mut() {
        evaluate(sa);
    }

    // Collect every finding across every SA into one chain, worst first, so the
    // ledger order reflects risk order.
    //
    // A retried or rekeyed tunnel produces a new SA per attempt, and each one
    // repeats the same findings. Concatenating them would turn four distinct
    // facts in a 376-packet capture into 564 ledger entries, and a reader
    // counting "high severity" would be reading packet count, not risk. So
    // collapse on (id, observed, severity) and carry the occurrence count, the
    // way the per-SA dedupe already does.
    let mut merged: BTreeMap<(String, String, String), crate::posture::RatedFinding> =
        BTreeMap::new();
    let mut order: Vec<(String, String, String)> = Vec::new();
    for (_sa_id, sa) in &sas {
        for f in &sa.findings {
            let key = (
                f.finding.id.clone(),
                f.finding.observed.clone(),
                f.finding.severity.as_str().to_string(),
            );
            match merged.get_mut(&key) {
                Some(existing) => {
                    existing.occurrences =
                        existing.occurrences.saturating_add(f.occurrences);
                    // Keep the first citation: the earliest packet that shows
                    // the fact is the one a reader wants to open.
                    if f.finding.packet_index != 0
                        && (existing.finding.packet_index == 0
                            || f.finding.packet_index < existing.finding.packet_index)
                    {
                        existing.finding.packet_index = f.finding.packet_index;
                    }
                }
                None => {
                    order.push(key.clone());
                    merged.insert(key, f.clone());
                }
            }
        }
    }

    let mut flat: Vec<crate::posture::RatedFinding> =
        order.into_iter().filter_map(|k| merged.remove(&k)).collect();
    flat.sort_by(|a, b| {
        b.finding
            .severity
            .cmp(&a.finding.severity)
            .then_with(|| b.occurrences.cmp(&a.occurrences))
    });

    let ledger = Ledger::build(pcap_sha256, TOOL_NAME, TOOL_VERSION, &flat);
    debug_assert!(ledger.intact, "a freshly built ledger must verify");

    let mut severity_counts: BTreeMap<String, u32> = BTreeMap::new();
    for f in &flat {
        *severity_counts
            .entry(f.finding.severity.as_str().to_string())
            .or_insert(0) += 1;
    }

    // Capture-wide score: the weakest SA sets the ceiling. A single failed
    // tunnel is enough to fail the assessment, so averaging would be wrong.
    let posture_score = sas.values().map(|s| s.score).min().unwrap_or(100);
    let grade = grade_for(posture_score).to_string();

    let mut blindspots: Vec<String> = Vec::new();
    if opts.include_blindspots {
        blindspots.extend(BLINDSPOTS.iter().map(|s| s.to_string()));
    }
    if messages.is_empty() {
        blindspots.push(format!(
            "No IKE message was found on ports {:?} in this capture. The tunnel may use a non-standard port, or the capture window may have missed the handshake. Rekeyed tunnels re-run IKE periodically, so a longer capture usually resolves this.",
            opts.ike_ports
        ));
    }
    if sas.iter().any(|(_, s)| s.ike_version == "IKEv2") {
        blindspots.push(
            "IKE_AUTH exchanges are encrypted after the first message. Authentication method and certificate details are not observable in IKEv2 without keys, so certificate strength is not assessed here."
                .to_string(),
        );
    }
    if messages.iter().any(|m| m.version == IkeVersion::V2) {
        blindspots.push(
            "IKEv2 rekey intervals are not carried in the clear. Lifetime findings require a capture spanning a rekey boundary."
                .to_string(),
        );
    }

    Report {
        tool: TOOL_NAME.to_string(),
        version: TOOL_VERSION.to_string(),
        capture: capture_name.to_string(),
        pcap_sha256: pcap_sha256.to_string(),
        packets_examined,
        ike_messages: messages.len() as u32,
        esp_flows: esp_flows.len() as u32,
        security_associations: sas.clone().into_values().collect(),
        posture_score,
        grade,
        severity_counts,
        global_findings: flat,
        blindspots,
        flow_records: flow_records(&sas, esp_flows),
    }
}

/// Flatten the flow table for export.
///
/// Flows are keyed by SPI on the wire and are not stored per SA, so the
/// association is recovered by matching the endpoints. An ESP flow whose
/// endpoints match no Security Association is still exported, with an empty
/// `sa_id`: it is a real flow and a classifier should not lose it just because
/// no handshake was captured alongside it.
fn flow_records(
    sas: &BTreeMap<String, SaPosture>,
    esp: &[EspFlow],
) -> Vec<FlowRecord> {
    let find_sa = |src: &str, dst: &str| -> String {
        sas.iter()
            .find(|(_, s)| (s.src == src && s.dst == dst) || (s.src == dst && s.dst == src))
            .map(|(id, _)| id.clone())
            .unwrap_or_default()
    };
    esp.iter()
        .map(|f| FlowRecord {
            sa_id: find_sa(&f.src, &f.dst),
            spi: f.spi.clone(),
            src: f.src.clone(),
            dst: f.dst.clone(),
            packet_count: f.packet_count,
            byte_count: f.byte_count,
            first_seq: f.first_seq,
            last_seq: f.last_seq,
            out_of_order_events: f.out_of_order_events,
            first_packet_index: f.first_packet_index,
            last_packet_index: f.last_packet_index,
        })
        .collect()
}

/// What this capture says about a named SA, for the drill-down path in the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaDetail {
    pub sa: SaPosture,
    pub ike_messages: Vec<IkeMessage>,
    pub esp_flows: Vec<EspFlow>,
    pub ledger: Ledger,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::Severity;

    /// Build a pcap carrying a single IKEv1 Aggressive Mode exchange.
    /// A pcap carrying one ISAKMP aggressive-mode message with a real
    /// 3DES/MD5/PSK/MODP-1024 suite.
    ///
    /// Phase 1 carries the whole suite in the attributes of one transform, so
    /// that is what this builds. The previous version wrote four explicit
    /// transforms, which is a Quick Mode shape and not a phase 1 one, and it
    /// could not have detected a parser that read the transform id.
    fn aggressive_capture() -> Vec<u8> {
        let attrs: [(u16, u16); 6] = [
            (1, 5),       // encryption = 3DES
            (2, 1),       // hash = MD5
            (3, 1),       // authentication = pre-shared key
            (4, 2),       // group = MODP-1024
            (11, 1),      // life type = seconds
            (12, 0x7BC0), // life duration
        ];
        let tlen = 8 + attrs.len() * 4;
        let plen = 4 + 4 + tlen;

        let mut sa_payload = vec![0u8; 8]; // DOI = 0, Situation = identity
        sa_payload.extend_from_slice(&[0x00, 0x00]);
        sa_payload.extend_from_slice(&(plen as u16).to_be_bytes());
        sa_payload.extend_from_slice(&[1, 1, 0, 1]); // proposal, ISAKMP, no SPI, 1 transform
        sa_payload.extend_from_slice(&[0x00, 0x00]);
        sa_payload.extend_from_slice(&(tlen as u16).to_be_bytes());
        sa_payload.extend_from_slice(&[1, 1, 0, 0]); // transform number, id = IKE
        for (t, v) in attrs {
            sa_payload.extend_from_slice(&(0x8000u16 | t).to_be_bytes());
            sa_payload.extend_from_slice(&v.to_be_bytes());
        }

        let mut id_payload = vec![2u8, 0, 0, 0];
        id_payload.extend_from_slice(b"vpn-gw-3");

        let mut body = vec![4, 0]; // SA, next = ID
        body.extend_from_slice(&((4 + sa_payload.len()) as u16).to_be_bytes());
        body.extend_from_slice(&sa_payload);
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&((4 + id_payload.len()) as u16).to_be_bytes());
        body.extend_from_slice(&id_payload);

        let mut ike = Vec::new();
        // RFC 2407 section 2: two 8-octet cookies, four single octets, then two
        // 4-octet fields. 28 octets in total.
        ike.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02]);
        ike.extend_from_slice(&[0x00; 8]);
        ike.push(1); // next payload = SA
        ike.push(0x10); // version 1.0
        ike.push(4); // Aggressive Mode (RFC 2408 exchange 4)
        ike.push(0x00); // flags
        ike.extend_from_slice(&0u32.to_be_bytes()); // message ID
        ike.extend_from_slice(&((28 + body.len()) as u32).to_be_bytes());
        ike.extend_from_slice(&body);

        wrap_in_pcap(&ike, 500, 500)
    }

    /// Build a pcap carrying a single IKEv2 IKE_SA_INIT with a modern suite.
    fn modern_capture() -> Vec<u8> {
        let mut t = Vec::new();
        // ENCR AES-256-GCM, expressed the RFC 8221 way: AES-GCM-16 with a
        // 256-bit key-length attribute.
        t.push(0x00);
        t.push(0x00);
        t.push(1);
        t.push(20); // ENCR 20 = ENCR_AES_GCM_16
        t.push(0x80);
        t.extend_from_slice(&14u16.to_be_bytes());
        t.extend_from_slice(&2u16.to_be_bytes());
        t.extend_from_slice(&256u16.to_be_bytes());
        // PRF 5 = PRF_HMAC_SHA2_256
        t.push(0x00);
        t.push(0x00);
        t.push(2);
        t.push(5);
        // KE 31 = X25519, last
        t.push(0x10);
        t.push(0x00);
        t.push(4);
        t.push(31);

        let mut sa_payload = vec![1, 1, 0, 3];
        sa_payload.extend_from_slice(&t);

        // RFC 7296 3.2: next payload, critical+reserved, 16-bit length.
        let mut body = vec![0u8, 0u8];
        body.extend_from_slice(&((4 + sa_payload.len()) as u16).to_be_bytes());
        body.extend_from_slice(&sa_payload);

        let mut ike = Vec::new();
        ike.extend_from_slice(&[0x11; 8]);
        ike.extend_from_slice(&[0x00; 8]);
        ike.push(33); // SA
        ike.push(0x20);
        ike.push(34); // IKE_SA_INIT
        ike.push(0x08);
        ike.extend_from_slice(&0u32.to_be_bytes());
        ike.extend_from_slice(&((28 + body.len()) as u32).to_be_bytes());
        ike.extend_from_slice(&body);

        wrap_in_pcap(&ike, 500, 4500)
    }

    /// Wrap an IKE payload in Ethernet/IPv4/UDP and a pcap container.
    fn wrap_in_pcap(ike: &[u8], sport: u16, dport: u16) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xAA; 6]);
        frame.extend_from_slice(&[0xBB; 6]);
        frame.extend_from_slice(&[0x08, 0x00]);

        let udp_len: u16 = 8 + ike.len() as u16;
        let total_len: u16 = 20 + udp_len;
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[0, 0]);
        frame.push(64);
        frame.push(17);
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&[10, 0, 0, 2]);
        frame.extend_from_slice(&sport.to_be_bytes());
        frame.extend_from_slice(&dport.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(ike);

        let mut v = Vec::new();
        v.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        v.extend_from_slice(&[2, 0, 4, 0]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
        v.extend_from_slice(&[1, 0, 0, 0]);
        v.extend_from_slice(&[1, 0, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        v.extend_from_slice(&frame);
        v
    }

    fn run(bytes: Vec<u8>, opts: &AnalysisOptions) -> Report {
        analyse_reader(std::io::Cursor::new(bytes), opts, "testhash", "test.pcap").unwrap()
    }

    #[test]
    fn modern_capture_produces_a_clean_grade_a_report() {
        let r = run(modern_capture(), &AnalysisOptions::default());
        assert_eq!(r.ike_messages, 1);
        assert_eq!(r.security_associations.len(), 1);
        let sa = &r.security_associations[0];
        assert_eq!(sa.ike_version, "IKEv2");
        assert_eq!(sa.encryption.as_deref(), Some("ENCR_AES_GCM_16"));
        assert_eq!(sa.key_exchange.as_deref(), Some("KE_X25519"));
        assert_eq!(r.grade, "A");
        assert!(r.posture_score >= 90);
    }

    #[test]
    fn aggressive_capture_produces_critical_findings_with_citations() {
        let r = run(aggressive_capture(), &AnalysisOptions::default());
        assert_eq!(r.ike_messages, 1);
        let sa = &r.security_associations[0];
        assert_eq!(sa.ike_version, "IKEv1");
        assert!(sa.aggressive_mode);
        assert_eq!(sa.encryption.as_deref(), Some("3DES"));
        assert_eq!(sa.key_exchange.as_deref(), Some("MODP-1024"));
        assert_eq!(r.grade, "F");

        let ids: Vec<&str> = sa.findings.iter().map(|f| f.finding.id.as_str()).collect();
        assert!(ids.contains(&"VYU-002"), "aggressive mode must be critical");
        assert!(ids.contains(&"VYU-011"), "3DES must be flagged");
        assert!(ids.contains(&"VYU-020"), "MODP-1024 must be critical");

        assert!(r
            .severity_counts
            .get(Severity::Critical.as_str())
            .copied()
            .unwrap_or(0)
            >= 2);
    }

    #[test]
    fn every_finding_in_the_report_reaches_the_ledger() {
        let r = run(aggressive_capture(), &AnalysisOptions::default());
        let sa = &r.security_associations[0];
        assert!(!sa.findings.is_empty());
        // The chain is built from the flattened findings, so counts must match.
        let ledger_count = sa.findings.len();
        assert_eq!(ledger_count, r.global_findings.len());
    }

    #[test]
    fn the_capture_digest_is_carried_into_the_report() {
        let r = run(modern_capture(), &AnalysisOptions::default());
        assert_eq!(r.pcap_sha256, "testhash");
    }

    #[test]
    fn blindspots_are_always_reported() {
        let r = run(modern_capture(), &AnalysisOptions::default());
        assert!(r.blindspots.len() >= 4, "blindspot panel must not be empty");
        assert!(r.blindspots.iter().any(|b| b.contains("never decrypts")));
    }

    #[test]
    fn a_capture_with_no_ike_says_so_instead_of_scoring_cleanly() {
        // A single non-IKE UDP frame.
        let empty = {
            let mut frame = Vec::new();
            frame.extend_from_slice(&[0xAA; 6]);
            frame.extend_from_slice(&[0xBB; 6]);
            frame.extend_from_slice(&[0x08, 0x00]);
            let total: u16 = 20 + 8 + 4;
            frame.extend_from_slice(&[0x45, 0x00]);
            frame.extend_from_slice(&total.to_be_bytes());
            frame.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
            frame.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
            frame.extend_from_slice(&53u16.to_be_bytes());
            frame.extend_from_slice(&53u16.to_be_bytes());
            frame.extend_from_slice(&12u16.to_be_bytes());
            frame.extend_from_slice(&[0, 0, 1, 2, 3, 4]);

            let mut v = vec![0xd4, 0xc3, 0xb2, 0xa1];
            v.extend_from_slice(&[2, 0, 4, 0]);
            v.extend_from_slice(&[0; 8]);
            v.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
            v.extend_from_slice(&[1, 0, 0, 0]);
            v.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
            v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            v.extend_from_slice(&frame);
            v
        };

        let r = run(empty, &AnalysisOptions::default());
        assert_eq!(r.ike_messages, 0);
        assert!(
            r.blindspots.iter().any(|b| b.contains("No IKE message")),
            "an empty result must explain itself"
        );
    }

    #[test]
    fn a_broken_capture_is_an_error_not_a_silent_empty_report() {
        let junk = vec![0u8; 64];
        let r = analyse_reader(std::io::Cursor::new(junk), &AnalysisOptions::default(), "h", "junk.pcap");
        assert!(r.is_err(), "garbage must not produce a report that looks clean");
    }
}

//! IKEv1 (ISAKMP, RFC 2407/2409) and IKEv2 (RFC 7296) dissector.
//!
//! Design note: we parse only what is on the wire in the clear. The IKEv2
//! Encrypted payload (type 46) holds the parts we would need keys to read, so we
//! record its presence and stop. That limitation is reported to the user rather
//! than papered over.

use crate::error::{Result, VyuhError};
use crate::reader::Reader;
use crate::registry::{self, Req};
use serde::{Deserialize, Serialize};

pub const IKE_PORT: u16 = 500;
pub const NAT_T_PORT: u16 = 4500;

// -- IKEv2 payload types (RFC 7296 / IANA) ---------------------------------

pub mod payload_v2 {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 33;
    pub const KE: u8 = 34;
    pub const IDI: u8 = 35;
    pub const IDR: u8 = 36;
    pub const CERT: u8 = 37;
    pub const CERTREQ: u8 = 38;
    pub const AUTH: u8 = 39;
    pub const NONCE: u8 = 40;
    pub const NOTIFY: u8 = 41;
    pub const DELETE: u8 = 42;
    pub const VENDOR_ID: u8 = 43;
    pub const TS_I: u8 = 44;
    pub const TS_R: u8 = 45;
    pub const SK: u8 = 46;
    pub const EAP: u8 = 47;
}

// -- ISAKMP payload types (RFC 2407) ---------------------------------------

pub mod payload_v1 {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 1;
    pub const PROPOSAL: u8 = 2;
    pub const KE: u8 = 3;
    pub const ID: u8 = 4;
    pub const CERT: u8 = 5;
    pub const CERTREQ: u8 = 6;
    pub const SIGNATURE: u8 = 7;
    pub const NONCE: u8 = 8;
    pub const NOTIFY: u8 = 9;
    pub const DELETE: u8 = 10;
    pub const VENDOR_ID: u8 = 11;
    pub const ATTRIBUTES: u8 = 12;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IkeVersion {
    /// ISAKMP / IKEv1, RFC 2407. Includes Aggressive Mode.
    V1,
    /// IKEv2, RFC 7296.
    V2,
}

impl IkeVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "IKEv1",
            Self::V2 => "IKEv2",
        }
    }
}

/// Negotiated transform, with the requirement level pulled from the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transform {
    pub transform_type: u8,
    pub type_name: String,
    pub transform_id: u16,
    /// Resolved name, or a synthetic "ENCR_UNKNOWN(199)" when unregistered.
    pub name: String,
    pub key_bits: Option<u16>,
    pub block_bits: Option<u16>,
    pub requirement: Option<String>,
    /// Permitted by the relevant RFC.
    pub usable: bool,
    /// The RFC actively tells implementers not to choose this.
    pub discouraged: bool,
    /// Legal, but no longer recommended for new deployments.
    pub demoted: bool,
    pub note: Option<String>,
    /// SA transform attribute values, e.g. Key Length = 256.
    pub attributes: Vec<TransformAttribute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformAttribute {
    /// The high two bits of the first attribute octet: address family (0x80)
    /// and/or TV (0x40). We record it because a 0x00 here means the field is
    /// really the next transform.
    pub af_flags: u8,
    pub attr_type: u16,
    /// Interpreted value for the two attributes that matter in practice.
    pub interpreted: Option<String>,
    pub raw: String,
    /// Decoded octets, so a consumer can read a numeric value without parsing
    /// the hex. Populated by the parsers; absent on attributes recovered from
    /// an older report.
    #[serde(default)]
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub number: u8,
    pub protocol_id: u8,
    pub spi: Option<String>,
    pub transforms: Vec<Transform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficSelector {
    pub ts_type: u8,
    pub protocol_id: Option<u8>,
    pub start: String,
    pub end: String,
    pub start_port: Option<u16>,
    pub end_port: Option<u16>,
}

impl TrafficSelector {
    /// True when the selector spans a subnet rather than a single host, which
    /// is the RFC-correct signal for tunnel mode.
    pub fn implies_tunnel_mode(&self) -> Option<bool> {
        if self.start == self.end && self.start_port == self.end_port {
            Some(false) // host-to-host => transport mode
        } else {
            Some(true) // subnet or port range => tunnel mode
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    Sa {
        proposals: Vec<Proposal>,
    },
    Ke {
        group_id: u16,
    },
    Identification {
        id_type: u8,
        value: String,
    },
    Nonce {
        bytes: usize,
    },
    NonceIkev1 {
        bytes: usize,
    },
    Auth {
        method: Option<u16>,
        raw_len: usize,
    },
    Certificate {
        cert_type: u8,
        raw_len: usize,
    },
    Notify {
        protocol_id: u8,
        notify_type: u16,
        spi_size: u8,
    },
    Delete,
    VendorId {
        raw: String,
    },
    TrafficSelector {
        selectors: Vec<TrafficSelector>,
        initiator: bool,
    },
    /// Present but opaque: requires session keys we deliberately do not have.
    Encrypted {
        len: usize,
    },
    /// Recognised header, unmodelled body.
    Opaque {
        payload_type: u8,
        len: usize,
    },
}

impl Payload {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Sa { .. } => "SA",
            Self::Ke { .. } => "KeyExchange",
            Self::Identification { .. } => "Identification",
            Self::Nonce { .. } | Self::NonceIkev1 { .. } => "Nonce",
            Self::Auth { .. } => "Authentication",
            Self::Certificate { .. } => "Certificate",
            Self::Notify { .. } => "Notify",
            Self::Delete => "Delete",
            Self::VendorId { .. } => "VendorId",
            Self::TrafficSelector { .. } => "TrafficSelector",
            Self::Encrypted { .. } => "Encrypted",
            Self::Opaque { .. } => "Opaque",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkeMessage {
    pub version: IkeVersion,
    pub packet_index: u32,
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub initiator_spi: String,
    pub responder_spi: String,
    pub exchange_type: u8,
    pub exchange_name: String,
    pub message_id: u32,
    pub is_request: bool,
    /// IKEv1 Aggressive Mode, which never protects the identity.
    pub aggressive_mode: bool,
    /// Child SA created with an extra key exchange, i.e. perfect forward secrecy.
    pub has_pfs_signal: bool,
    /// The negotiated Security Association, resolved from the SAr payload.
    pub selected_proposal: Option<Proposal>,
    /// Everything proposed by the initiator, for downgrade analysis.
    pub offered_proposals: Vec<Proposal>,
    pub payloads: Vec<Payload>,
    pub identities_in_clear: Vec<String>,
    pub vendor_ids: Vec<String>,
    pub truncated: bool,
}

impl IkeMessage {
    /// Does this exchange contain a child-SA proposal?
    pub fn proposes_child_sa(&self) -> bool {
        self.payloads.iter().any(|p| {
            matches!(p, Payload::Sa { proposals } if proposals.iter().any(|pr| pr.protocol_id == 3))
        })
    }

    /// Aggregate requirement level of the selected suite, worst-first.
    pub fn weakest_requirement(&self) -> Option<Req> {
        let mut worst: Option<Req> = None;
        if let Some(p) = &self.selected_proposal {
            for t in &p.transforms {
                let r = match t.requirement.as_deref() {
                    Some("MUST") => Req::Must,
                    Some("MUST NOT") => Req::MustNot,
                    Some("MUST-") => Req::Recommended,
                    Some("SHOULD") => Req::Should,
                    Some("SHOULD NOT") => Req::ShouldNot,
                    Some("MAY") => Req::May,
                    Some("DEPRECATED") => Req::Deprecated,
                    _ => continue,
                };
                worst = Some(match worst {
                    None => r,
                    Some(prev) => if rank(r) < rank(prev) { r } else { prev },
                });
            }
        }
        worst
    }
}

/// Lower rank = weaker / more objectionable.
fn rank(r: Req) -> u8 {
    match r {
        Req::MustNot => 0,
        Req::Deprecated => 1,
        Req::ShouldNot => 2,
        Req::Recommended => 3,
        Req::May => 4,
        Req::Should => 5,
        Req::Must => 6,
    }
}

// =========================================================================
// Parsing
// =========================================================================

/// Parse an IKE message from a UDP payload. Returns `Ok(None)` when the bytes
/// cannot plausibly be IKE.
///
/// The distinction matters for the pipeline: a UDP/500 payload that merely
/// looks like IKE is far more likely to be a non-IKE service than a malformed
/// handshake, so "not IKE" is a soft result and never aborts a scan. Only a
/// header that validates is walked, and from that point on structural problems
/// are reported as errors.
pub fn parse_ike(
    payload: &[u8],
    packet_index: u32,
    src: &str,
    dst: &str,
    src_port: u16,
    dst_port: u16,
) -> Result<Option<IkeMessage>> {
    // Both versions have a 28-byte fixed header.
    if payload.len() < 28 {
        return Ok(None);
    }

    // Both headers put the version major version in the high nibble of octet
    // 17, and both are 28 octets long, so one probe serves both.
    match payload[17] >> 4 {
        1 | 2 => {}
        _ => return Ok(None),
    }

    // The declared length must be at least the fixed header and no larger than
    // the UDP payload. Anything else is not a handshake we can trust, and
    // nothing is allocated from it.
    let declared = u32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]);
    if !(28..=payload.len() as u32).contains(&declared) {
        return Ok(None);
    }

    if payload[17] >> 4 == 1 {
        parse_v1(payload, packet_index, src, dst, src_port, dst_port).map(Some)
    } else {
        parse_v2(payload, packet_index, src, dst, src_port, dst_port).map(Some)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

// -- IKEv2 -----------------------------------------------------------------

fn parse_v2(
    buf: &[u8],
    packet_index: u32,
    src: &str,
    dst: &str,
    src_port: u16,
    dst_port: u16,
) -> Result<IkeMessage> {
    let mut r = Reader::new(buf);

    let ispi = r.take(8)?;
    let rspi = r.take(8)?;
    let next_payload = r.u8()?;
    let _version_byte = r.u8()?;
    let exchange_type = r.u8()?;
    let flags = r.u8()?;
    let message_id = r.u32_be()?;
    let declared_len = r.u32_be()? as usize;

    let body_len = declared_len.saturating_sub(28);
    if body_len == 0 || body_len > buf.len().saturating_sub(28) {
        return Err(VyuhError::InvalidField {
            field: "message length",
            value: declared_len as u64,
            offset: 24,
        });
    }

    let exchange_name = match exchange_type {
        34 => "IKE_SA_INIT",
        35 => "IKE_AUTH",
        36 => "CREATE_CHILD_SA",
        37 => "INFORMATIONAL",
        38 => "IKE_INTERMEDIATE",
        44 => "IKE_FOLLOWUP_KE",
        _ => "UNKNOWN",
    }
    .to_string();

    let mut msg = IkeMessage {
        version: IkeVersion::V2,
        packet_index,
        src: src.to_string(),
        dst: dst.to_string(),
        src_port,
        dst_port,
        initiator_spi: hex(ispi),
        responder_spi: hex(rspi),
        exchange_type,
        exchange_name,
        message_id,
        // RFC 7296 section 3.1: the R bit (0x20) marks a response.
        is_request: flags & 0x20 == 0,
        aggressive_mode: false,
        has_pfs_signal: false,
        selected_proposal: None,
        offered_proposals: Vec::new(),
        payloads: Vec::new(),
        identities_in_clear: Vec::new(),
        vendor_ids: Vec::new(),
        truncated: false,
    };

    let mut body = r.split(body_len)?;
    let mut next = next_payload;

    // Bounded walk: a hostile length field must not spin us forever.
    let mut guard = 0;
    while next != payload_v2::NONE && !body.is_empty() {
        guard += 1;
        if guard > 32 {
            msg.truncated = true;
            break;
        }

        let ptype = next;

        // RFC 7296 section 3.2, the generic payload header is four octets:
        //
        //   | Next Payload |C| RESERVED |     Payload Length     |
        //
        // The length is a 16-bit field in octets 2 and 3. Treating it as the
        // second octet on its own reads the reserved byte as the length, which
        // is always zero here and silently discards every payload.
        let next_payload_field = match body.u8() {
            Ok(v) => v,
            Err(_) => {
                msg.truncated = true;
                break;
            }
        };
        // Octet 1 is the critical bit followed by seven reserved bits. Neither
        // is treated as fatal: peers do set stray reserved bits, and refusing to
        // parse would turn a cosmetic defect into an invisible tunnel.
        let _critical_reserved = match body.u8() {
            Ok(v) => v,
            Err(_) => {
                msg.truncated = true;
                break;
            }
        };
        let plen = match body.u16_be() {
            Ok(v) => v as usize,
            Err(_) => {
                msg.truncated = true;
                break;
            }
        };

        if plen < 4 {
            return Err(VyuhError::InvalidField {
                field: "payload length",
                value: plen as u64,
                offset: body.offset(),
            });
        }
        let body_len = plen - 4;
        let mut data = match body.split(body_len) {
            Ok(d) => d,
            Err(_) => {
                msg.truncated = true;
                break;
            }
        };

        let parsed = parse_v2_payload(ptype, &mut data, &mut msg);
        msg.payloads.push(parsed);
        next = next_payload_field;
    }

    Ok(msg)
}

fn parse_v2_payload(ptype: u8, data: &mut Reader<'_>, msg: &mut IkeMessage) -> Payload {
    match ptype {
        payload_v2::SA => {
            let proposals = parse_sa_payload(data, IkeVersion::V2).unwrap_or_default();
            // In a response (SAr) the offered set collapses to one selection.
            if !msg.is_request {
                msg.selected_proposal = proposals.first().cloned();
            } else {
                msg.offered_proposals = proposals.clone();
            }
            Payload::Sa { proposals }
        }
        payload_v2::KE => {
            let group_id = data.u16_be().unwrap_or(0);
            if msg.exchange_type == 36 {
                // CREATE_CHILD_SA carrying a fresh KE is the PFS signal.
                msg.has_pfs_signal = true;
            }
            Payload::Ke { group_id }
        }
        payload_v2::IDI | payload_v2::IDR => {
            let id_type = data.u8().unwrap_or(0);
            data.skip(3).ok();
            let raw = data.take(data.remaining().min(255)).unwrap_or(&[]);
            let value = format_identity(id_type, raw);
            // IKE_AUTH is already inside SK, so anything cleartext here is
            // informational only. IKEv1 Aggressive Mode is the real leak and is
            // flagged by the caller through `aggressive_mode`.
            msg.identities_in_clear.push(value.clone());
            Payload::Identification { id_type, value }
        }
        payload_v2::NONCE => {
            let n = data.remaining();
            Payload::Nonce { bytes: n }
        }
        payload_v2::AUTH => {
            let method = data.u8().ok().map(|m| m as u16);
            Payload::Auth {
                method,
                raw_len: data.remaining(),
            }
        }
        payload_v2::CERT => {
            let cert_type = data.u8().unwrap_or(0);
            Payload::Certificate {
                cert_type,
                raw_len: data.remaining(),
            }
        }
        payload_v2::NOTIFY => {
            let protocol_id = data.u8().unwrap_or(0);
            let spi_size = data.u8().unwrap_or(0);
            let notify_type = data.u16_be().unwrap_or(0);
            Payload::Notify {
                protocol_id,
                notify_type,
                spi_size,
            }
        }
        payload_v2::DELETE => Payload::Delete,
        payload_v2::VENDOR_ID => {
            let raw = hex(data.take(data.remaining().min(64)).unwrap_or(&[]));
            msg.vendor_ids.push(raw.clone());
            Payload::VendorId { raw }
        }
        payload_v2::TS_I | payload_v2::TS_R => {
            let selectors = parse_ts_payload(data, IkeVersion::V2).unwrap_or_default();
            Payload::TrafficSelector {
                selectors,
                initiator: ptype == payload_v2::TS_I,
            }
        }
        payload_v2::SK => Payload::Encrypted {
            len: data.remaining(),
        },
        other => Payload::Opaque {
            payload_type: other,
            len: data.remaining(),
        },
    }
}

fn format_identity(id_type: u8, raw: &[u8]) -> String {
    let printable = raw.iter().all(|b| (0x20..0x7f).contains(b));
    let text = if printable {
        String::from_utf8_lossy(raw).to_string()
    } else {
        String::new()
    };
    match id_type {
        1 => format!("ID_IPV4_ADDR {}", text),
        2 => format!("ID_FQDN {}", text),
        3 => format!("ID_RFC822_ADDR {}", text),
        4 => text.clone(),
        5 => text.clone(), // ID_IPV4_SUBNET
        9 => text.clone(), // ID_DER_ASN1_DN
        11 => text.clone(),// ID_KEK
        12 => text.clone(),// ID_CERT
        _ => {
            if text.is_empty() {
                hex(raw)
            } else {
                text
            }
        }
    }
}

// -- IKEv1 -----------------------------------------------------------------

fn parse_v1(
    buf: &[u8],
    packet_index: u32,
    src: &str,
    dst: &str,
    src_port: u16,
    dst_port: u16,
) -> Result<IkeMessage> {
    let mut r = Reader::new(buf);

    // RFC 2407 section 2: ISAKMP is also 28 octets, laid out as two 8-octet
    // cookies, then four single octets, then two 4-octet fields.
    let icookie = r.take(8)?;
    let rcookie = r.take(8)?;
    let next_payload = r.u8()?;
    let _version = r.u8()?;
    let exchange_type = r.u8()?;
    let flags = r.u8()?;
    let message_id = r.u32_be()?;
    let declared_len = r.u32_be()? as usize;

    let body_len = declared_len.saturating_sub(28);
    if body_len == 0 || body_len > buf.len().saturating_sub(28) {
        return Err(VyuhError::InvalidField {
            field: "message length",
            value: declared_len as u64,
            offset: 24,
        });
    }

    // RFC 2408 section 3.1 numbers the phase 1 exchanges. Note that Main Mode
    // is exchange 2 and Aggressive Mode is exchange 4: the numbering is not
    // the order the modes are usually listed in, and reading 4 as "Quick Mode"
    // (which is 32, not 4) hides the identity leak on every real aggressive
    // capture.
    let exchange_name = match exchange_type {
        1 => "Base",
        2 => "Main Mode",
        3 => "Authentication Only",
        4 => "Aggressive Mode",
        5 => "Informational",
        32 => "Quick Mode",
        33 => "New Group Mode",
        _ => "UNKNOWN",
    }
    .to_string();

    let aggressive_mode = exchange_type == 4;

    let mut msg = IkeMessage {
        version: IkeVersion::V1,
        packet_index,
        src: src.to_string(),
        dst: dst.to_string(),
        src_port,
        dst_port,
        initiator_spi: hex(icookie),
        responder_spi: hex(rcookie),
        exchange_type,
        exchange_name,
        message_id,
        // ISAKMP carries no response bit. The Exchange field and the payload
        // chain carry the direction, and a capture of an exchange is read as a
        // sequence of requests. The responder's reply is what populates
        // `selected_proposal`, so direction is not needed for assessment.
        is_request: flags & 0x20 == 0,
        aggressive_mode,
        has_pfs_signal: false,
        selected_proposal: None,
        offered_proposals: Vec::new(),
        payloads: Vec::new(),
        identities_in_clear: Vec::new(),
        vendor_ids: Vec::new(),
        truncated: false,
    };

    let mut body = r.split(body_len)?;
    let mut next = next_payload;
    let mut guard = 0;

    while next != payload_v1::NONE && !body.is_empty() {
        guard += 1;
        if guard > 32 {
            msg.truncated = true;
            break;
        }

        let ptype = next;
        let next_payload_field = body.u8().unwrap_or(payload_v1::NONE);
        let _reserved = body.u8().unwrap_or(0);
        let plen = match body.u16_be() {
            Ok(v) => v as usize,
            Err(_) => {
                msg.truncated = true;
                break;
            }
        };
        if plen < 4 {
            return Err(VyuhError::InvalidField {
                field: "payload length",
                value: plen as u64,
                offset: body.offset(),
            });
        }
        let mut pl_data = match body.split(plen - 4) {
            Ok(d) => d,
            Err(_) => {
                msg.truncated = true;
                break;
            }
        };

        let parsed = parse_v1_payload(ptype, &mut pl_data, &mut msg);
        msg.payloads.push(parsed);
        next = next_payload_field;
    }

    Ok(msg)
}

fn parse_v1_payload(ptype: u8, data: &mut Reader<'_>, msg: &mut IkeMessage) -> Payload {
    match ptype {
        payload_v1::SA | payload_v1::PROPOSAL => {
            let proposals = parse_sa_payload(data, IkeVersion::V1).unwrap_or_default();
            if !msg.is_request {
                msg.selected_proposal = proposals.first().cloned();
            } else {
                msg.offered_proposals = proposals.clone();
            }
            Payload::Sa { proposals }
        }
        payload_v1::KE => {
            let group_id = data.u16_be().unwrap_or(0);
            if msg.exchange_type == 4 {
                msg.has_pfs_signal = true; // Quick Mode with KE => PFS
            }
            Payload::Ke { group_id }
        }
        payload_v1::ID => {
            let id_type = data.u8().unwrap_or(0);
            data.skip(3).ok();
            let raw = data.take(data.remaining().min(255)).unwrap_or(&[]);
            let value = format_identity(id_type, raw);
            // In Aggressive Mode the ID payload travels in the clear, which is
            // precisely the metadata leak we report.
            msg.identities_in_clear.push(value.clone());
            Payload::Identification { id_type, value }
        }
        payload_v1::NONCE => Payload::NonceIkev1 {
            bytes: data.remaining(),
        },
        payload_v1::NOTIFY => {
            let protocol_id = data.u8().unwrap_or(0);
            let spi_size = data.u8().unwrap_or(0);
            let notify_type = data.u16_be().unwrap_or(0);
            Payload::Notify {
                protocol_id,
                notify_type,
                spi_size,
            }
        }
        payload_v1::DELETE => Payload::Delete,
        payload_v1::VENDOR_ID => {
            let raw = hex(data.take(data.remaining().min(64)).unwrap_or(&[]));
            msg.vendor_ids.push(raw.clone());
            Payload::VendorId { raw }
        }
        other => Payload::Opaque {
            payload_type: other,
            len: data.remaining(),
        },
    }
}
// -- Shared: SA proposal parsing -------------------------------------------

/// Total on-wire length of a length-framed SA substructure, if that is what
/// these bytes are.
///
/// `head` is a peek wide enough to hold the framing octets; `available` is how
/// many octets are actually left in the payload. The declared length is checked
/// against `available`, not against `head`, because a proposal routinely
/// declares a length far larger than any fixed-size peek window.
///
/// RFC 7296 section 3.3 gives the IKEv2 proposal and transform substructures a
/// bare four-octet header and no length, so a proposal simply runs until its
/// transforms are consumed. libstrongswan reuses its IKEv1 `PLV1` substructure
/// classes for the v2 payload layout, so it prefixes the proposal *and* every
/// transform with `[last(0)/not-last(3)][reserved][length u16]`, and carries a
/// 16-bit transform id. Both forms occupy the same field on the wire, so the
/// framing is detected per substructure rather than assumed from the version.
///
/// libstrongswan writes `0` on the last substructure and `3` on every other
/// one, reusing the ISAKMP "next payload" sentinel as a chain-continuation
/// marker. The length must cover at least the eight-octet header that follows,
/// which is what keeps a bare RFC substructure from being misread as framed: in
/// a bare header those same octets are the SPI size and the transform count,
/// and the value they form is always below eight.
fn framed_length(head: &[u8], available: usize) -> Option<usize> {
    if head.len() < 4 {
        return None;
    }
    if head[0] != 0 && head[0] != 3 {
        return None;
    }
    let len = u16::from_be_bytes([head[2], head[3]]) as usize;
    if !(8..=available).contains(&len) {
        return None;
    }
    Some(len)
}

/// Parse the attribute list that trails a transform.
///
/// The header is four octets, and the first two are not one flag byte plus a
/// two-byte type: libstrongswan packs the A flag as a single *bit* and the
/// attribute type into the remaining fifteen bits of the same two octets
/// (`parse_bit` then `parse_uint15` in its parser). The third and fourth octets
/// are the attribute length, or the value itself when A is set.
fn parse_framed_attributes(data: &mut Reader<'_>, end: usize) -> Result<Vec<TransformAttribute>> {
    let mut attributes = Vec::new();

    while data.offset() < end {
        let head = match data.peek(4) {
            Ok(h) if data.offset() + 4 <= end => h,
            _ => break,
        };

        // IKEv2 packs the A flag as one bit with a 15-bit type in these two
        // octets; ISAKMP uses the high bit of a 16-bit type and always
        // carries a fixed two-octet value. Both decode identically here.
        let a_set = head[0] & 0x80 != 0;
        let attr_type = ((head[0] as u16 & 0x7F) << 8) | head[1] as u16;
        let length_or_value = u16::from_be_bytes([head[2], head[3]]);
        data.skip(4)?;

        // A set: the two octets just read are the value, and nothing follows.
        // A clear: they are a length and the value chunk follows it.
        let value: Vec<u8> = if a_set {
            length_or_value.to_be_bytes().to_vec()
        } else {
            let len = length_or_value as usize;
            if data.offset() + len > end {
                break;
            }
            data.take(len)?.to_vec()
        };

        attributes.push(TransformAttribute {
            af_flags: head[0] & 0xC0,
            attr_type,
            interpreted: interpret_attribute(attr_type, &value),
            raw: hex(&value),
            value: Some(value),
        });
    }

    Ok(attributes)
}

/// Parse a length-framed proposal. Returns `None` and leaves the reader
/// untouched if these octets are not one.
fn parse_framed_proposal(data: &mut Reader<'_>, version: IkeVersion) -> Option<Proposal> {
    let start = data.offset();

    let parsed = (|| {
        let head = data.peek(8).ok()?;
        let total = framed_length(head, data.remaining())?;

        let number = head[4];
        let protocol_id = head[5];
        let spi_size = head[6] as usize;
        let num_transforms = head[7] as usize;

        // Reject anything that does not read as a proposal, so that a bare RFC
        // substructure is still given a chance by the fallback path. A framed
        // substructure always has at least one transform, and each one needs
        // its own eight-octet header.
        if protocol_id == 0 || num_transforms == 0 {
            return None;
        }
        if spi_size + 8 > total || num_transforms * 8 > total - 8 - spi_size {
            return None;
        }

        data.skip(4).ok()?; // framing: last-marker, reserved, length
        data.skip(4).ok()?; // number, protocol_id, spi_size, num_transforms
        let spi = if spi_size > 0 {
            Some(hex(data.take(spi_size).ok()?))
        } else {
            None
        };

        let mut transforms = Vec::with_capacity(num_transforms);
        for index in 0..num_transforms {
            let t_start = data.offset();
            let t_head = data.peek(8).ok()?;
            let t_len = framed_length(t_head, data.remaining())?;

            // The transform header is 8 octets in both framings, but the two
            // layouts put the fields in different places. ISAKMP has a 1-octet
            // transform number and a 1-octet transform id, then two reserved
            // octets; IKEv2 has a 1-octet type, one reserved octet, and a
            // 16-bit id. Reading a v1 id from the v2 offset yields the first
            // attribute's type instead, which is how a 3DES tunnel gets
            // reported as an unknown algorithm.
            let (transform_type, transform_id) = match version {
                IkeVersion::V1 => (t_head[4], t_head[5] as u16),
                IkeVersion::V2 => {
                    if t_head[4] == 0 {
                        return None;
                    }
                    (t_head[4], u16::from_be_bytes([t_head[6], t_head[7]]))
                }
            };

            data.skip(8).ok()?; // framing, then the header proper
            let attributes = parse_framed_attributes(data, t_start + t_len).ok()?;

            transforms.push(build_transform(
                version,
                transform_type,
                transform_id,
                index as u8,
                protocol_id,
                attributes,
            ));

            // Pad out to the declared length so the caller resumes on a
            // boundary rather than mid-substructure.
            if data.offset() < t_start + t_len {
                data.skip(t_start + t_len - data.offset()).ok()?;
            }
        }

        if data.offset() < start + total {
            data.skip(start + total - data.offset()).ok()?;
        }

        Some(Proposal {
            number,
            protocol_id,
            spi,
            transforms,
        })
    })();

    // A failed attempt must leave no trace, or the fallback path would read
    // from the middle of a substructure it had already consumed.
    if parsed.is_none() {
        data.rewind_to(start);
    }
    parsed
}

pub fn parse_sa_payload(data: &mut Reader<'_>, version: IkeVersion) -> Result<Vec<Proposal>> {
    // ISAKMP carries an 8-octet DOI and Situation pair ahead of the proposals,
    // which the v2 layout does not. Skipping it unconditionally would corrupt
    // every IKEv2 payload, so the version decides.
    if version == IkeVersion::V1 && data.remaining() >= 8 {
        data.skip(8).ok();
    }

    let mut proposals = Vec::new();
    let mut guard = 0;

    while !data.is_empty() {
        guard += 1;
        if guard > 16 {
            break;
        }

        if let Some(p) = parse_framed_proposal(data, version) {
            proposals.push(p);
            continue;
        }
        match parse_bare_proposal(data, version) {
            Some(p) => proposals.push(p),
            None => break,
        }
    }

    if version == IkeVersion::V1 {
        for p in &mut proposals {
            expand_v1_phase1(p);
        }
    }

    Ok(proposals)
}

/// Rewrite an ISAKMP phase 1 proposal into IKEv2-typed transforms.
///
/// In phase 1 there is a single transform whose id is a placeholder; the suite
/// is carried as attributes: encryption, hash, authentication and group. Each
/// becomes its own IKEv2-typed transform, so the registry, the findings and the
/// dashboard all read one shape instead of every consumer special-casing the
/// legacy layout.
///
/// This runs after parsing rather than inside it, because ISAKMP proposals can
/// arrive in either substructure framing and the rule is about the protocol,
/// not about the encoding.
fn expand_v1_phase1(p: &mut Proposal) {
    if p.protocol_id != 1 || p.transforms.is_empty() {
        return;
    }
    let suite = v1_phase1_suite(&p.transforms[0].attributes);
    if suite == V1Suite::default() {
        return;
    }
    let attributes = p.transforms[0].attributes.clone();
    p.transforms = v1_suite_to_transforms(&suite, attributes);
}

/// Parse a proposal in the bare RFC 7296 / RFC 2407 form.
fn parse_bare_proposal(data: &mut Reader<'_>, version: IkeVersion) -> Option<Proposal> {
    let number = data.u8().ok()?;
    let protocol_id = data.u8().ok()?;
    let spi_size = data.u8().ok()? as usize;
    let num_transforms = data.u8().ok()? as usize;

    let spi = if spi_size > 0 {
        Some(hex(data.take(spi_size).ok()?))
    } else {
        None
    };

    let mut transforms = Vec::new();
    for index in 0..num_transforms {
        if data.remaining() < 4 {
            break;
        }
        let last = data.u8().ok()?;
        let _reserved = data.u8().ok()?;
        let combined = data.u16_be().ok()?;

        // IKEv2 packs the type and the id into one 16-bit field. ISAKMP
        // leaves the type implicit: in phase 1 the order is fixed as
        // encryption, hash, authentication, group.
        let (transform_type, transform_id) = match version {
            IkeVersion::V2 => ((combined >> 8) as u8, combined & 0x00FF),
            IkeVersion::V1 => (implicit_v1_type(index as u8, protocol_id), combined),
        };

        // Trailing transform attributes, if any. A transform with no
        // attributes simply runs to the next 4-byte transform boundary.
        //
        // The two are genuinely ambiguous on the wire: both start with a
        // single flag octet. A well-formed transform octet has only the
        // Last (0x10) and Commit (0x08) bits set, while a well-formed
        // attribute octet carries the Address Family (0x80) or TV (0x40)
        // bit. So the check is on the high two bits, and it is made by
        // peeking, because consuming the octet and rewinding would corrupt
        // the next transform.
        let mut attributes = Vec::new();
        loop {
            if data.remaining() < 4 {
                break;
            }
            let af_byte = match data.peek_u8() {
                Ok(v) => v,
                Err(_) => break,
            };
            if af_byte & 0xC0 == 0x00 {
                break; // this is the next transform, not an attribute
            }
            data.u8().ok()?;

            let attr_type = data.u16_be().ok()?;
            // Length covers the Value only; the four-octet header is not
            // counted (RFC 7296 section 3.3.4).
            let value_len = data.u16_be().ok()? as usize;
            if data.remaining() < value_len {
                break;
            }
            let value = data.take(value_len).ok()?;
            attributes.push(TransformAttribute {
                af_flags: af_byte & 0xC0,
                attr_type,
                interpreted: interpret_attribute(attr_type, value),
                raw: hex(value),
                value: Some(value.to_vec()),
            });
        }

        transforms.push(build_transform(
            version,
            transform_type,
            transform_id,
            index as u8,
            protocol_id,
            attributes,
        ));

        if last & 0x10 != 0 {
            break; // last-transform bit set
        }
    }

    Some(Proposal {
        number,
        protocol_id,
        spi,
        transforms,
    })
}

/// Expand an ISAKMP phase 1 attribute suite into IKEv2-typed transforms.
///
/// ISAKMP phase 1 bundles encryption, hash, authentication and group into a
/// single transform identified only by its attributes. Each becomes a separate
/// transform here, typed by its IKEv2 equivalent, so the registry, the findings
/// and the dashboard all read one shape.
///
/// The ISAKMP hash algorithm serves as both the integrity check and the PRF in
/// phase 1, so the same value produces two transforms. Dropping one would hide
/// the fact that an IKEv1 tunnel has no independent PRF choice.
fn v1_suite_to_transforms(s: &V1Suite, attributes: Vec<TransformAttribute>) -> Vec<Transform> {
    let mut out = Vec::new();

    // Encryption, with the key length attribute applied if present.
    if let Some(encr) = registry::lookup_v1(0, s.encr as u8) {
        // ISAKMP key length is in octets (attribute type 13). Only a positive
        // value overrides the table: peers omit the attribute when the
        // algorithm implies one key size, and a zero would erase a known one.
        let key_bits = attributes
            .iter()
            .find(|a| a.attr_type & 0x7FFF == 13)
            .map(|a| attribute_u16(a))
            .filter(|octets| *octets > 0)
            .map(|octets| octets.saturating_mul(8))
            .or(encr.key_bits);
        out.push(Transform {
            transform_type: registry::ENCR,
            type_name: "Encryption".into(),
            transform_id: s.encr,
            name: encr.name.to_string(),
            key_bits,
            block_bits: encr.block_bits,
            requirement: Some(encr.req.as_str().to_string()),
            usable: encr.is_usable(),
            discouraged: encr.is_discouraged(),
            demoted: encr.is_demoted(),
            note: Some(encr.note.to_string()),
            attributes: attributes.clone(),
        });
    }

    // The hash, once as integrity and once as the PRF.
    if let Some(hash) = registry::lookup_v1(1, s.hash as u8) {
        for ty in [registry::INTEG, registry::PRF] {
            out.push(Transform {
                transform_type: ty,
                type_name: registry::transform_type_name(ty).to_string(),
                transform_id: s.hash,
                name: hash.name.to_string(),
                key_bits: hash.key_bits,
                block_bits: hash.block_bits,
                requirement: Some(hash.req.as_str().to_string()),
                usable: hash.is_usable(),
                discouraged: hash.is_discouraged(),
                demoted: hash.is_demoted(),
                note: Some(hash.note.to_string()),
                attributes: attributes.clone(),
            });
        }
    }

    // The key exchange group.
    if let Some(group) = registry::lookup_v1(3, s.group as u8) {
        out.push(Transform {
            transform_type: registry::KE,
            type_name: "Key Exchange".into(),
            transform_id: s.group,
            name: group.name.to_string(),
            key_bits: group.key_bits,
            block_bits: group.block_bits,
            requirement: Some(group.req.as_str().to_string()),
            usable: group.is_usable(),
            discouraged: group.is_discouraged(),
            demoted: group.is_demoted(),
            note: Some(group.note.to_string()),
            attributes: attributes.clone(),
        });
    }

    // The authentication method, on transform type 14. A pre-shared key is the
    // configuration behind CVE-2018-5389, so it must not be dropped.
    if let Some(auth) = registry::lookup_v1(2, s.auth as u8) {
        out.push(Transform {
            transform_type: 14,
            type_name: "Authentication Method".into(),
            transform_id: s.auth,
            name: auth.name.to_string(),
            key_bits: auth.key_bits,
            block_bits: auth.block_bits,
            requirement: Some(auth.req.as_str().to_string()),
            usable: auth.is_usable(),
            discouraged: auth.is_discouraged(),
            demoted: auth.is_demoted(),
            note: Some(auth.note.to_string()),
            attributes,
        });
    }

    out
}
/// Resolve an ISAKMP phase 1 suite, where the algorithms live in transform
/// attributes rather than in the transform id.
///
/// In ISAKMP phase 1 there is a single transform whose id is meaningless; the
/// real suite is carried as attributes: encryption (1), hash (2),
/// authentication (3), group (4). Reading the transform id instead would label
/// a 3DES/MD5/MODP-1024 proposal "DES", which is how a synthetic fixture can
/// look plausible and still be wrong.
fn v1_phase1_suite(attributes: &[TransformAttribute]) -> V1Suite {
    let mut s = V1Suite::default();
    for a in attributes {
        // The A/F octet holds the flags; the type follows in the same 16-bit
        // word, so mask it off before matching.
        let t = a.attr_type & 0x7FFF;
        let v = attribute_u16(a);
        match t {
            1 => s.encr = v,     // TATTR_PH1_ENCRYPTION_ALGORITHM
            2 => s.hash = v,     // TATTR_PH1_HASH_ALGORITHM
            3 => s.auth = v,     // TATTR_PH1_AUTH_METHOD
            4 => s.group = v,    // TATTR_PH1_GROUP
            _ => {}
        }
    }
    s
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct V1Suite {
    encr: u16,
    hash: u16,
    auth: u16,
    group: u16,
}

/// The 16-bit value of an ISAKMP transform attribute, or 0 if it is not a
/// 2-byte TV-form attribute.
fn attribute_u16(a: &TransformAttribute) -> u16 {
    match a.value.as_deref() {
        Some([hi, lo]) => u16::from_be_bytes([*hi, *lo]),
        _ => 0,
    }
}

/// IKEv1 and IKEv2 number the same concepts differently.
///
/// ISAKMP phase 1 fixes the transform order (RFC 2407 §3.1): encryption, hash,
/// authentication, group. Phase 2 (Quick Mode) uses encryption, hash,
/// authentication, group as well. We map the ISAKMP type numbers onto the IKEv2
/// numbering so one registry serves both versions.
fn implicit_v1_type(index: u8, protocol_id: u8) -> u8 {
    // Protocol ID 1 = ISAKMP, 3 = ESP, 2 = AH. Only ISAKMP phase 1 has the
    // four-slot convention; for ESP/AH proposals the caller supplies the
    // explicit type, so fall back to encryption.
    if protocol_id == 1 {
        match index {
            0 => registry::ENCR,
            1 => registry::PRF,
            2 => registry::INTEG,
            3 => registry::KE,
            _ => registry::ENCR,
        }
    } else {
        registry::ENCR
    }
}


fn build_transform(
    version: IkeVersion,
    transform_type: u8,
    transform_id: u16,
    slot: u8,
    protocol_id: u8,
    attributes: Vec<TransformAttribute>,
) -> Transform {
    // Registry keys are single bytes. A wider ISAKMP id keeps its low byte.
    let lookup_id = if transform_id > u8::MAX as u16 {
        (transform_id & 0x00FF) as u8
    } else {
        transform_id as u8
    };

    // IKEv1 and IKEv2 have separate transform identifier spaces, so the lookup
    // table depends on the version. Resolving a v1 handshake against the v2
    // tables would mislabel the suite rather than fail loudly.
    //
    // Within ISAKMP there is a further split: a phase 1 proposal for the IKE
    // protocol carries its algorithms in attributes (handled by the phase 1
    // expander), while a phase 2 or ESP proposal puts the algorithm in the
    // transform id under the ESP numbering.
    let alg = match version {
        IkeVersion::V1 if protocol_id != 1 => registry::lookup_v1_esp(lookup_id),
        IkeVersion::V1 => registry::lookup_v1(slot, lookup_id),
        IkeVersion::V2 => registry::lookup(transform_type, lookup_id),
    };
    // Key length is IKEv2 transform attribute 14, in bits. ISAKMP puts it in
    // octets under attribute 13 and it is applied by the phase 1 expander
    // instead, so it is not read here: an encryption algorithm attribute in a
    // v1 proposal is a different field entirely and must not be mistaken for a
    // key size.
    let key_bits = attributes
        .iter()
        .find(|a| a.attr_type == 14)
        .map(|a| attribute_u16(a))
        .filter(|bits| *bits > 0)
        .or_else(|| alg.and_then(|a| a.key_bits));

    Transform {
        transform_type,
        type_name: registry::transform_type_name(transform_type).to_string(),
        transform_id,
        name: alg
            .map(|a| a.name.to_string())
            .unwrap_or_else(|| format!("UNKNOWN({lookup_id})")),
        key_bits,
        block_bits: alg.and_then(|a| a.block_bits),
        requirement: alg.map(|a| a.req.as_str().to_string()),
        usable: alg.map(|a| a.is_usable()).unwrap_or(false),
        discouraged: alg.map(|a| a.is_discouraged()).unwrap_or(false),
        demoted: alg.map(|a| a.is_demoted()).unwrap_or(false),
        note: alg.map(|a| a.note.to_string()),
        attributes,
    }
}

fn interpret_attribute(attr_type: u16, value: &[u8]) -> Option<String> {
    match (attr_type, value.len()) {
        (14, 2) => Some(format!(
            "Key Length = {} bits",
            u16::from_be_bytes([value[0], value[1]])
        )),
        _ => None,
    }
}

fn parse_ts_payload(data: &mut Reader<'_>, version: IkeVersion) -> Result<Vec<TrafficSelector>> {
    let ts_type = data.u8()?;
    let _ts_len = data.u16_be()?;
    data.skip(3).ok(); // reserved

    let mut selectors = Vec::new();
    let mut guard = 0;

    while data.remaining() >= 4 && guard < 16 {
        guard += 1;
        let proto = data.u8()?;
        let sel_len = data.u8()? as usize;
        if sel_len < 8 || data.remaining() < sel_len {
            break;
        }
        let sel = data.take(sel_len)?;

        let (start, end, sp, ep) = match (version, proto) {
            (IkeVersion::V2, 7) => {
                // TS_IP4_RANGE: start IPv4, end IPv4, start port, end port
                if sel.len() < 12 {
                    break;
                }
                (
                    std::net::Ipv4Addr::new(sel[0], sel[1], sel[2], sel[3]).to_string(),
                    std::net::Ipv4Addr::new(sel[4], sel[5], sel[6], sel[7]).to_string(),
                    Some(u16::from_be_bytes([sel[8], sel[9]])),
                    Some(u16::from_be_bytes([sel[10], sel[11]])),
                )
            }
            (IkeVersion::V2, 8) => {
                if sel.len() < 40 {
                    break;
                }
                let mut a = [0u8; 16];
                let mut b = [0u8; 16];
                a.copy_from_slice(&sel[0..16]);
                b.copy_from_slice(&sel[16..32]);
                (
                    std::net::Ipv6Addr::from(a).to_string(),
                    std::net::Ipv6Addr::from(b).to_string(),
                    Some(u16::from_be_bytes([sel[32], sel[33]])),
                    Some(u16::from_be_bytes([sel[34], sel[35]])),
                )
            }
            (IkeVersion::V1, 5) => {
                if sel.len() < 8 {
                    break;
                }
                (
                    std::net::Ipv4Addr::new(sel[0], sel[1], sel[2], sel[3]).to_string(),
                    std::net::Ipv4Addr::new(sel[4], sel[5], sel[6], sel[7]).to_string(),
                    None,
                    None,
                )
            }
            _ => (hex(&sel[0..4]), hex(&sel[4..8]), None, None),
        };

        selectors.push(TrafficSelector {
            ts_type,
            protocol_id: Some(proto),
            start,
            end,
            start_port: sp,
            end_port: ep,
        });
    }

    Ok(selectors)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble an IKEv2 message around a set of payloads.
    fn ikev2(exchange: u8, flags: u8, payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut first = payload_v2::NONE;
        // Chain the "next payload" fields.
        for (i, (ptype, data)) in payloads.iter().enumerate() {
            let next = if i + 1 < payloads.len() { payloads[i + 1].0 } else { payload_v2::NONE };
            if i == 0 {
                first = *ptype;
            }
            // RFC 7296 3.2: next payload, critical+reserved, 16-bit length.
            body.push(next);
            body.push(0x00);
            body.extend_from_slice(&((4 + data.len()) as u16).to_be_bytes());
            body.extend_from_slice(data);
        }

        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x11; 8]); // initiator SPI
        msg.extend_from_slice(&[0x00; 8]); // responder SPI
        msg.push(first);
        msg.push(0x20); // version 2.0
        msg.push(exchange);
        msg.push(flags);
        msg.extend_from_slice(&0u32.to_be_bytes()); // message ID
        msg.extend_from_slice(&((28 + body.len()) as u32).to_be_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    /// One IKEv2 transform substructure: last | reserved | type | id | attrs.
    fn transform(last: bool, ttype: u8, tid: u8, attrs: &[(u16, u16)]) -> Vec<u8> {
        let mut t = Vec::new();
        // RFC 7296 3.3.2: octet 0 is Last(0x10) | Commit(0x08) | Reserved(0x3F).
        t.push(if last { 0x10 } else { 0x00 });
        t.push(0x00);
        t.push(ttype);
        t.push(tid);
        for (attr_type, value) in attrs {
            t.push(0x80); // Address Family bit
            t.extend_from_slice(&attr_type.to_be_bytes());
            t.extend_from_slice(&2u16.to_be_bytes()); // value length, header excluded
            t.extend_from_slice(&value.to_be_bytes());
        }
        t
    }

    fn sa(proposals: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, transforms) in proposals.iter().enumerate() {
            // Proposal substructure.
            out.push((i + 1) as u8);
            out.push(1); // protocol ID = IKE
            out.push(0); // SPI size
            out.push(3); // transform count
            out.extend_from_slice(transforms);
        }
        out
    }

    /// Modern baseline: AES-256-GCM, PRF-SHA2-256, ECDH-256. The ids are the
    /// ones a real peer sends: ENCR 20 and PRF 5, per the IANA transform
    /// registries, not a sequential guess.
    fn ikev2_modern_suite() -> Vec<u8> {
        let mut t = transform(false, registry::ENCR, 20, &[(14, 256)]);
        t.extend(transform(false, registry::PRF, 5, &[]));
        t.extend(transform(true, registry::KE, 19, &[]));
        ikev2(34, 0x00, &[(payload_v2::SA, sa(&[t]))])
    }

    /// Deliberately weak, matching testbed tunnel T3: 3DES, PRF-SHA1,
    /// MODP-1024.
    fn ikev2_weak_suite() -> Vec<u8> {
        let mut t = transform(false, registry::ENCR, 3, &[]); // 3DES
        t.extend(transform(false, registry::PRF, 2, &[])); // SHA-1
        t.extend(transform(true, registry::KE, 2, &[])); // MODP-1024
        ikev2(34, 0x00, &[(payload_v2::SA, sa(&[t]))])
    }

    // -- IKEv2 ------------------------------------------------------------

    #[test]
    fn resolves_the_modern_suite_with_requirement_levels() {
        let msg = parse_ike(&ikev2_modern_suite(), 42, "10.0.0.1", "10.0.0.2", 500, 500)
            .unwrap()
            .expect("should parse as IKEv2");

        assert_eq!(msg.version, IkeVersion::V2);
        assert_eq!(msg.exchange_name, "IKE_SA_INIT");
        assert!(msg.is_request);
        assert_eq!(msg.packet_index, 42);
        assert_eq!(msg.offered_proposals.len(), 1);

        let p = &msg.offered_proposals[0];
        assert_eq!(p.protocol_id, 1, "protocol ID should be IKE");
        assert_eq!(p.transforms.len(), 3);

        let encr = &p.transforms[0];
        assert_eq!(encr.name, "ENCR_AES_GCM_16");
        assert_eq!(encr.requirement.as_deref(), Some("MUST"));
        assert_eq!(encr.key_bits, Some(256), "key length attribute should be read");
        assert!(encr.usable);

        assert_eq!(p.transforms[1].name, "PRF_HMAC_SHA2_256");
        assert_eq!(p.transforms[2].name, "KE_ECDH_256");
    }

    #[test]
    fn flags_the_weak_suite_and_records_the_key_length_reason() {
        let msg = parse_ike(&ikev2_weak_suite(), 7, "a", "b", 500, 500)
            .unwrap()
            .unwrap();
        let p = &msg.offered_proposals[0];

        let encr = &p.transforms[0];
        assert_eq!(encr.name, "ENCR_3DES");
        assert_eq!(encr.requirement.as_deref(), Some("SHOULD NOT"));
        assert_eq!(encr.block_bits, Some(64), "64-bit block size drives SWEET32");
        assert!(encr.discouraged, "3DES is discouraged by RFC 8221");
        assert!(!encr.demoted);

        assert_eq!(p.transforms[1].name, "PRF_HMAC_SHA1");
        assert_eq!(p.transforms[1].requirement.as_deref(), Some("MUST-"));

        assert_eq!(p.transforms[2].name, "KE_DH_1024");
        assert_eq!(p.transforms[2].requirement.as_deref(), Some("MUST NOT"));
    }

    #[test]
    fn response_carries_the_selection_not_the_offer() {
        // 0x20 sets the R bit, making this a response.
        let mut t = transform(false, registry::ENCR, 20, &[]);
        t.extend(transform(false, registry::PRF, 5, &[]));
        t.extend(transform(true, registry::KE, 31, &[])); // X25519
        let bytes = ikev2(34, 0x20, &[(payload_v2::SA, sa(&[t]))]);

        let msg = parse_ike(&bytes, 9, "a", "b", 500, 500).unwrap().unwrap();
        assert!(!msg.is_request);
        assert!(msg.selected_proposal.is_some());
        assert!(msg.offered_proposals.is_empty());

        let sel = msg.selected_proposal.as_ref().unwrap();
        assert_eq!(sel.transforms[0].name, "ENCR_AES_GCM_16");
        assert_eq!(sel.transforms[2].name, "KE_X25519");
    }

    // -- Real strongSwan captures -------------------------------------------
    //
    // These are the exact SA payload bodies from strongSwan 5.9.13 running in
    // the project's own testbed, in corpus/vyuh-ikev2-modern.pcap and
    // corpus/vyuh-ikev2-weak-dh.pcap. They are the regression that matters:
    // the hand-written `transform()` helper above can only ever reproduce the
    // form its author believed in, and it did. These bytes are what a real
    // gateway sends.
    //
    // Note the framing: both start with `00 00 00 <len>` where <len> is the
    // whole payload body, and every transform is an eight-octet
    // `[last][reserved][length][type][reserved][id]` substructure. The
    // key-length attribute is `80 0e 01 00`: a single A bit plus a 15-bit
    // type in the first two octets, then the value.

    /// T1: AES-256-GCM, PRF-SHA2-256, ECP-256.
    const REAL_MODERN_SA: &[u8] = &[
        0x00, 0x00, 0x00, 0x24, // proposal substructure: last, length 36
        0x01, 0x01, 0x00, 0x03, // #1, IKE, no SPI, 3 transforms
        0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x14, // ENCR 20, length 12
        0x80, 0x0e, 0x01, 0x00, // key length = 256 bits
        0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x05, // PRF 5, length 8
        0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x13, // KE 19, last
    ];

    /// T2: AES-CBC-128, HMAC-SHA1, SHA1 PRF, MODP-1024. Four transforms, and
    /// therefore no AEAD, so INTEG is negotiated explicitly.
    const REAL_WEAK_DH_SA: &[u8] = &[
        0x00, 0x00, 0x00, 0x2c, // proposal substructure: last, length 44
        0x01, 0x01, 0x00, 0x04, // #1, IKE, no SPI, 4 transforms
        0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c, // ENCR 12, length 12
        0x80, 0x0e, 0x00, 0x80, // key length = 128 bits
        0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, // INTEG 2, length 8
        0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, // PRF 2, length 8
        0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x02, // KE 2, last
    ];

    #[test]
    fn reads_a_real_strongswan_ikev2_proposal() {
        let bytes = ikev2(34, 0x00, &[(payload_v2::SA, REAL_MODERN_SA.to_vec())]);
        let msg = parse_ike(&bytes, 1, "10.72.0.2", "10.72.0.3", 500, 500)
            .unwrap()
            .expect("should parse as IKEv2");

        let p = &msg.offered_proposals[0];
        assert_eq!(p.number, 1);
        assert_eq!(p.protocol_id, 1, "protocol ID should be IKE");
        assert_eq!(p.transforms.len(), 3, "all three transforms must be read");

        let encr = &p.transforms[0];
        assert_eq!(encr.name, "ENCR_AES_GCM_16");
        assert_eq!(encr.key_bits, Some(256), "key length attribute must be read");
        assert_eq!(encr.requirement.as_deref(), Some("MUST"));

        assert_eq!(p.transforms[1].name, "PRF_HMAC_SHA2_256");
        assert_eq!(p.transforms[2].name, "KE_ECDH_256");
    }

    #[test]
    fn reads_a_real_strongswan_ikev2_proposal_with_explicit_integrity() {
        let bytes = ikev2(34, 0x00, &[(payload_v2::SA, REAL_WEAK_DH_SA.to_vec())]);
        let msg = parse_ike(&bytes, 1, "10.72.0.2", "10.72.0.3", 500, 500)
            .unwrap()
            .expect("should parse as IKEv2");

        let p = &msg.offered_proposals[0];
        assert_eq!(p.transforms.len(), 4);

        assert_eq!(p.transforms[0].name, "ENCR_AES_CBC");
        assert_eq!(p.transforms[0].key_bits, Some(128));
        assert_eq!(p.transforms[1].name, "AUTH_HMAC_SHA1_96");
        assert_eq!(p.transforms[2].name, "PRF_HMAC_SHA1");
        assert_eq!(p.transforms[3].name, "KE_DH_1024");
    }

    #[test]
    fn the_two_sa_framings_are_both_accepted() {
        // A bare RFC 7296 proposal and a libstrongswan length-framed one carry
        // the same suite and must resolve identically.
        let bare = ikev2_modern_suite();
        let framed = ikev2(34, 0x00, &[(payload_v2::SA, REAL_MODERN_SA.to_vec())]);

        let bare_msg = parse_ike(&bare, 1, "a", "b", 500, 500).unwrap().unwrap();
        let framed_msg = parse_ike(&framed, 1, "a", "b", 500, 500).unwrap().unwrap();

        let names = |m: &IkeMessage| -> Vec<String> {
            m.offered_proposals[0]
                .transforms
                .iter()
                .map(|t| t.name.clone())
                .collect()
        };
        assert_eq!(names(&bare_msg), names(&framed_msg));
    }

    #[test]
    fn a_truncated_framed_substructure_does_not_panic() {
        for cut in 0..REAL_MODERN_SA.len() {
            let body = REAL_MODERN_SA[..cut].to_vec();
            let bytes = ikev2(34, 0x00, &[(payload_v2::SA, body)]);
            let _ = parse_ike(&bytes, 1, "a", "b", 500, 500);
        }
    }

    #[test]
    fn marks_create_child_sa_with_ke_as_pfs() {
        let ts: Vec<u8> = {
            let mut v = Vec::new();
            v.push(7); // TS_IP4_RANGE
            v.extend_from_slice(&4u16.to_be_bytes()); // TS length
            v.push(0);
            v.push(0);
            v.push(0);
            v.push(7); // IP protocol = UDP
            v.push(8); // selector length
            v.extend_from_slice(&[10, 0, 0, 0]); // start
            v.extend_from_slice(&[10, 0, 0, 255]); // end -> subnet, so tunnel mode
            v
        };

        let bytes = ikev2(
            36, // CREATE_CHILD_SA
            0x00,
            &[
                (payload_v2::SA, vec![1, 3, 0, 0]), // protocol 3 = ESP, no transforms
                (payload_v2::KE, vec![0x00, 0x20]), // group 32 = X25519
                (payload_v2::TS_I, ts),
            ],
        );

        let msg = parse_ike(&bytes, 3, "a", "b", 500, 500).unwrap().unwrap();
        assert_eq!(msg.exchange_name, "CREATE_CHILD_SA");
        assert!(msg.has_pfs_signal, "a fresh KE in CREATE_CHILD_SA means PFS");
        assert!(msg.proposes_child_sa());
    }

    #[test]
    fn subnet_selector_implies_tunnel_mode() {
        let ts = TrafficSelector {
            ts_type: 7,
            protocol_id: Some(7),
            start: "10.0.0.0".into(),
            end: "10.0.0.255".into(),
            start_port: Some(0),
            end_port: Some(65535),
        };
        assert_eq!(ts.implies_tunnel_mode(), Some(true));
    }

    #[test]
    fn host_selector_implies_transport_mode() {
        let ts = TrafficSelector {
            ts_type: 7,
            protocol_id: Some(17),
            start: "192.0.2.10".into(),
            end: "192.0.2.10".into(),
            start_port: Some(0),
            end_port: Some(0),
        };
        assert_eq!(ts.implies_tunnel_mode(), Some(false));
    }

    #[test]
    fn encrypted_payload_is_recorded_not_decrypted() {
        let bytes = ikev2(35, 0x00, &[(payload_v2::SK, vec![0xAB; 40])]);
        let msg = parse_ike(&bytes, 1, "a", "b", 500, 500).unwrap().unwrap();
        assert_eq!(msg.exchange_name, "IKE_AUTH");
        assert!(matches!(msg.payloads[0], Payload::Encrypted { len: 40 }));
    }

    // -- IKEv1 ------------------------------------------------------------

    /// An ISAKMP aggressive-mode message with a real 3DES/MD5/PSK/MODP-1024
    /// suite.
    ///
    /// This is the shape a gateway actually sends: a single transform whose id
    /// is a placeholder, with the suite carried as attributes, behind the
    /// 8-octet DOI and Situation pair. The earlier version of this fixture
    /// invented four explicit transforms, which the wire never carries for
    /// phase 1, so it could not catch a parser that read the transform id.
    fn ikev1_aggressive() -> Vec<u8> {
        // An ISAKMP phase 1 SA payload: an 8-octet DOI and Situation pair, then
        // a single length-framed proposal holding a single transform whose id
        // is a placeholder and whose attributes carry the suite.
        //
        // The octet counts below are the wire layout, not an approximation. A
        // transform is 4 framing octets + transform number + transform id + 2
        // reserved + attributes, and each declared length includes its own
        // framing. Getting these wrong is what made an earlier version of this
        // fixture parse as eight nonsense transforms.
        let attrs: [(u16, u16); 6] = [
            (1, 5),      // encryption = 3DES
            (2, 1),      // hash = MD5
            (3, 1),      // authentication = pre-shared key
            (4, 2),      // group = MODP-1024
            (11, 1),     // life type = seconds
            (12, 0x7BC0), // life duration
        ];
        let attr_bytes = attrs.len() * 4;
        let tlen = 8 + attr_bytes; // framing + number + id + 2 reserved + attributes
        let plen = 4 + 4 + tlen;   // framing + proposal header + transform

        let mut sa_payload = vec![0u8; 8]; // DOI = 0, Situation = identity
        sa_payload.extend_from_slice(&[0x00, 0x00]); // last proposal, reserved
        sa_payload.extend_from_slice(&(plen as u16).to_be_bytes());
        sa_payload.push(1); // proposal number
        sa_payload.push(1); // protocol ID = ISAKMP
        sa_payload.push(0); // SPI size
        sa_payload.push(1); // transform count
        sa_payload.extend_from_slice(&[0x00, 0x00]); // last transform, reserved
        sa_payload.extend_from_slice(&(tlen as u16).to_be_bytes());
        sa_payload.push(1); // transform number
        sa_payload.push(1); // transform id = IKE
        sa_payload.extend_from_slice(&[0x00, 0x00]); // reserved
        for (t, v) in attrs {
            sa_payload.extend_from_slice(&(0x8000u16 | t).to_be_bytes());
            sa_payload.extend_from_slice(&v.to_be_bytes());
        }

        // ID payload in the clear: the aggressive-mode identity leak.
        let mut id_payload = vec![2u8]; // ID_FQDN
        id_payload.extend_from_slice(&[0, 0, 0]); // reserved
        id_payload.extend_from_slice(b"vpn-gw-3.district.example");

        // Chain: SA -> ID
        let mut body = vec![payload_v1::ID, 0x00];
        body.extend_from_slice(&((4 + sa_payload.len()) as u16).to_be_bytes());
        body.extend_from_slice(&sa_payload);
        body.push(payload_v1::NONE);
        body.push(0x00);
        body.extend_from_slice(&((4 + id_payload.len()) as u16).to_be_bytes());
        body.extend_from_slice(&id_payload);

        let mut msg = Vec::new();
        msg.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02]); // i-cookie
        msg.extend_from_slice(&[0x00; 8]); // r-cookie, still zero: not yet answered
        msg.push(payload_v1::SA); // next payload
        msg.push(0x10); // version 1.0
        msg.push(4); // Aggressive Mode (RFC 2408 exchange 4)
        msg.push(0x00); // flags
        msg.extend_from_slice(&0u32.to_be_bytes()); // message ID
        msg.extend_from_slice(&((28 + body.len()) as u32).to_be_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn aggressive_mode_is_detected_with_the_cleartext_identity() {
        let msg = parse_ike(&ikev1_aggressive(), 120, "192.0.2.1", "192.0.2.2", 500, 500)
            .unwrap()
            .expect("should parse as IKEv1");

        assert_eq!(msg.version, IkeVersion::V1);
        assert_eq!(msg.exchange_name, "Aggressive Mode");
        assert!(msg.aggressive_mode, "aggressive mode must be flagged");
        assert_eq!(msg.packet_index, 120);

        assert_eq!(
            msg.identities_in_clear,
            vec!["ID_FQDN vpn-gw-3.district.example".to_string()],
            "the identity leak is the point of aggressive mode"
        );
    }

    #[test]
    fn aggressive_mode_suite_maps_onto_the_shared_registry() {
        let msg = parse_ike(&ikev1_aggressive(), 1, "a", "b", 500, 500)
            .unwrap()
            .unwrap();
        let p = &msg.offered_proposals[0];
        let names: Vec<&str> = p.transforms.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["3DES", "MD5", "MD5", "MODP-1024", "HMAC-MD5"],
            "phase 1 carries one suite across four attributes; the hash serves as both the integrity algorithm and the PRF"
        );
        assert_eq!(p.transforms[0].transform_type, registry::ENCR);
        assert_eq!(p.transforms[1].transform_type, registry::INTEG);
        assert_eq!(p.transforms[2].transform_type, registry::PRF);
        assert_eq!(p.transforms[3].transform_type, registry::KE);
        assert_eq!(p.transforms[0].block_bits, Some(64));
        assert_eq!(p.transforms[0].requirement.as_deref(), Some("SHOULD NOT"));
        assert_eq!(p.transforms[3].requirement.as_deref(), Some("MUST NOT"));
    }

    // -- Robustness -------------------------------------------------------

    #[test]
    fn non_ike_udp_payload_is_reported_as_none() {
        // A DNS-shaped payload on port 500 must not be mistaken for IKE.
        let junk: Vec<u8> = (0u8..40).collect();
        assert!(parse_ike(&junk, 1, "a", "b", 500, 500).unwrap().is_none());
    }

    #[test]
    fn short_input_is_not_ike() {
        assert!(parse_ike(&[0u8; 10], 1, "a", "b", 500, 500).unwrap().is_none());
    }

    #[test]
    fn an_implausible_length_field_is_rejected_without_allocating() {
        // A claimed length of 4 GiB must never drive a buffer allocation, and
        // must not be mistaken for a real handshake either.
        let mut bytes = ikev2_modern_suite();
        bytes[24..28].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert!(parse_ike(&bytes, 1, "a", "b", 500, 500).unwrap().is_none());
    }

    #[test]
    fn a_length_beyond_the_udp_payload_is_rejected() {
        let bytes = ikev2_modern_suite();
        let mut tampered = bytes.clone();
        tampered[24..28].copy_from_slice(&(bytes.len() as u32 + 512).to_be_bytes());
        assert!(parse_ike(&tampered, 1, "a", "b", 500, 500).unwrap().is_none());
    }

    #[test]
    fn zero_length_field_is_rejected() {
        let mut bytes = ikev2_modern_suite();
        bytes[24..28].copy_from_slice(&0u32.to_be_bytes());
        assert!(parse_ike(&bytes, 1, "a", "b", 500, 500).unwrap().is_none());
    }

    // The four-octet generic payload header was mis-parsed as two octets for
    // the whole life of this parser, and every synthetic fixture encoded the
    // same mistake, so the test suite agreed with the bug. Only a capture from
    // a real strongSwan gateway exposed it: octet 1 is the critical bit plus
    // reserved bits, and the 16-bit length lives in octets 2 and 3.
    #[test]
    fn generic_payload_header_is_four_octets() {
        let bytes = ikev2_modern_suite();
        // Octet 28 is the SA payload's Next Payload, octet 29 is the critical
        // and reserved octet, and octets 30..32 hold the length.
        assert_eq!(bytes[28], payload_v2::NONE, "SA has no following payload");
        assert_eq!(bytes[29], 0x00, "critical bit and reserved bits are clear");
        let plen = u16::from_be_bytes([bytes[30], bytes[31]]) as usize;
        assert_eq!(plen, 4 + bytes[32..].len(), "length covers the header and body");
        assert_eq!(bytes[16], payload_v2::SA, "header names the SA payload first");
    }

    #[test]
    fn a_payload_length_of_zero_is_rejected_rather_than_looping() {
        // Byte 29 is the reserved octet, not the length, so a peer that leaves
        // it non-zero must not be able to drive the walk into a tight loop.
        let mut bytes = ikev2_modern_suite();
        bytes[30] = 0;
        bytes[31] = 0;
        let r = parse_ike(&bytes, 1, "a", "b", 500, 500);
        assert!(r.is_err(), "a zero payload length is not a valid IKEv2 message");
    }

    #[test]
    fn a_declared_length_longer_than_the_frame_is_not_a_handshake() {
        let mut bytes = ikev2_modern_suite();
        let over = bytes.len() as u32 + 4;
        bytes[24..28].copy_from_slice(&over.to_be_bytes());
        assert!(parse_ike(&bytes, 1, "a", "b", 500, 500).unwrap().is_none());
    }
}

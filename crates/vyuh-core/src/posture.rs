//! Posture engine: turns parsed IKE exchanges into citable, deduplicated
//! findings and a 0-100 posture score.
//!
//! Two rules govern everything here:
//!   1. Every finding carries the packet number that produced it.
//!   2. A finding quotes the requirement that makes it a finding, not opinion.

use crate::ike::{IkeMessage, Payload, Proposal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }

    fn weight(self) -> i32 {
        match self {
            Self::Critical => 40,
            Self::High => 25,
            Self::Medium => 12,
            Self::Low => 5,
            Self::Info => 1,
        }
    }
}

/// MITRE CWE identifier attached to a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cwe {
    #[serde(rename = "CWE-327")]
    BrokenCryptoAlgorithm,
    #[serde(rename = "CWE-326")]
    InadequateEncryptionStrength,
    #[serde(rename = "CWE-322")]
    KeyExchangeWithoutAuthentication,
    #[serde(rename = "CWE-321")]
    HardcodedCryptographicKey,
    #[serde(rename = "CWE-323")]
    ReusingNonceOrKeyPair,
    #[serde(rename = "CWE-324")]
    KeyPastExpiration,
    #[serde(rename = "CWE-325")]
    MissingRequiredCryptographicStep,
    #[serde(rename = "CWE-330")]
    InsufficientlyRandomValues,
    #[serde(rename = "CWE-916")]
    WeakPasswordRequirements,
    #[serde(rename = "CWE-200")]
    ExposureOfSensitiveInformation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    /// The requirement that makes this a finding, e.g. "RFC 8221: ENCR_3DES SHOULD NOT".
    pub standard: String,
    pub cwe: Option<Cwe>,
    /// Packet number in the source capture. This is the evidence handle.
    pub packet_index: u32,
    pub src: String,
    pub dst: String,
    /// The specific field that triggered it, e.g. "KE_DH_1024".
    pub observed: String,
    pub remediation: String,
}

impl Finding {
    /// Stable identity used for deduplication. Two identical observations on
    /// different packets collapse to one finding citing the first packet.
    fn dedup_key(&self) -> String {
        format!("{}|{}", self.id, self.observed)
    }
}

/// How a conclusion was reached. Shown next to every claim so the reader knows
/// whether it was read off the wire or derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// Directly present in a parsed header field.
    Observed,
    /// Derived by comparing observations across packets.
    Inferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatedFinding {
    #[serde(flatten)]
    pub finding: Finding,
    pub evidence: Evidence,
    /// How many packets corroborated this finding.
    pub occurrences: u32,
}

/// Aggregate view of one Security Association, keyed by initiator SPI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaPosture {
    pub sa_id: String,
    pub src: String,
    pub dst: String,
    pub ike_version: String,
    pub exchanges_seen: Vec<String>,
    pub aggressive_mode: bool,
    pub encryption: Option<String>,
    pub integrity: Option<String>,
    pub key_exchange: Option<String>,
    pub prf: Option<String>,
    pub key_bits: Option<u16>,
    pub perfect_forward_secrecy: Option<bool>,
    pub transport_or_tunnel: Option<String>,
    pub identities_in_clear: Vec<String>,
    pub vendor_ids: Vec<String>,
    pub strongest: Option<String>,
    /// Set when the same gateway pairs re-negotiate with a weaker suite.
    pub downgrade_observed: bool,
    /// Set when a responder answered without selecting a suite, i.e. it
    /// returned a bare error notification instead of an SA payload.
    pub negotiation_rejected: bool,
    /// Packet number of the first message folded into this record.
    pub first_packet: u32,
    /// Packet number of the message that carried the suite. This is the
    /// evidence handle for every finding about the negotiated configuration.
    pub suite_packet: u32,
    /// Notify types the peer sent back on a rejected exchange.
    pub rejection_notifies: Vec<u16>,
    pub score: u32,
    pub grade: String,
    pub findings: Vec<RatedFinding>,
    /// KalScore: 0 (post-quantum ready) to 100 (harvest-now-decrypt-later exposed).
    pub quantum_exposure: u32,
}

/// Everything the engine produced for one capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub capture: String,
    pub pcap_sha256: String,
    pub packets_examined: u32,
    pub ike_messages: u32,
    pub esp_flows: u32,
    pub security_associations: Vec<SaPosture>,
    pub posture_score: u32,
    pub grade: String,
    pub severity_counts: BTreeMap<String, u32>,
    /// Findings that apply to the capture as a whole, not one SA.
    pub global_findings: Vec<RatedFinding>,
    /// What this capture could not tell us. Always populated when applicable.
    pub blindspots: Vec<String>,
    /// Per-flow records for every ESP flow seen, in first-seen order.
    ///
    /// Exported because the traffic-class work needs real flow records rather
    /// than a packet dump re-parsed in another language, and because a
    /// reviewer should be able to check a model prediction against the flow it
    /// came from. `esp_flows` stays a count; this is the list behind it.
    #[serde(default)]
    pub flow_records: Vec<FlowRecord>,
}

/// One ESP flow, flattened for tabular use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub sa_id: String,
    pub spi: String,
    pub src: String,
    pub dst: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seq: u32,
    pub last_seq: u32,
    pub out_of_order_events: u64,
    pub first_packet_index: u32,
    pub last_packet_index: u32,
}

pub const TOOL_NAME: &str = "RAKSHAK.VYUH";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

// =========================================================================
// Rule evaluation
// =========================================================================

/// Fold one IKE message into the per-SA accumulator.
///
/// The key is the initiator SPI together with the *unordered* peer pair. An SPI
/// alone is not sufficient identity: a testbed, a lab, or an attacker
/// replaying a capture can reuse the same SPI for unrelated tunnels, and
/// merging two different negotiations into one record would manufacture a
/// downgrade that never happened.
///
/// The peer pair is sorted because one Security Association is a two-way
/// relationship, not two. Keying on direction split every exchange in half: the
/// responder's copy carried no suite at all, so a tunnel whose first attempt
/// was refused appeared as a clean record in one direction and a failed one in
/// the other, and the capture inherited the worse of the two.
pub fn observe(msg: &IkeMessage, map: &mut BTreeMap<String, SaPosture>) {
    // Order the peers so both directions of a negotiation fold into one record.
    let (a, b) = if msg.src <= msg.dst {
        (msg.src.clone(), msg.dst.clone())
    } else {
        (msg.dst.clone(), msg.src.clone())
    };
    let key = format!("{}|{}|{}", msg.initiator_spi, a, b);

    let entry = map.entry(key.clone()).or_insert_with(|| SaPosture {
        sa_id: msg.initiator_spi.clone(),
        // Present the SA from the initiator's point of view, which is the
        // direction that chose the suite.
        src: if msg.is_request {
            msg.src.clone()
        } else {
            msg.dst.clone()
        },
        dst: if msg.is_request {
            msg.dst.clone()
        } else {
            msg.src.clone()
        },
        ike_version: msg.version.as_str().to_string(),
        exchanges_seen: Vec::new(),
        aggressive_mode: false,
        encryption: None,
        integrity: None,
        key_exchange: None,
        prf: None,
        key_bits: None,
        perfect_forward_secrecy: None,
        transport_or_tunnel: None,
        identities_in_clear: Vec::new(),
        vendor_ids: Vec::new(),
        strongest: None,
        downgrade_observed: false,
        negotiation_rejected: false,
        rejection_notifies: Vec::new(),
        first_packet: msg.packet_index,
        suite_packet: 0,
        score: 100,
        grade: "A".into(),
        findings: Vec::new(),
        quantum_exposure: 0,
    });

    if !entry.exchanges_seen.contains(&msg.exchange_name) {
        entry.exchanges_seen.push(msg.exchange_name.clone());
    }
    if msg.aggressive_mode {
        entry.aggressive_mode = true;
    }
    for id in &msg.identities_in_clear {
        if !entry.identities_in_clear.contains(id) {
            entry.identities_in_clear.push(id.clone());
        }
    }
    for v in &msg.vendor_ids {
        if !entry.vendor_ids.contains(v) {
            entry.vendor_ids.push(v.clone());
        }
    }

    // A CREATE_CHILD_SA or Quick Mode carrying a KE is the PFS signal.
    if msg.has_pfs_signal {
        entry.perfect_forward_secrecy = Some(true);
    }

    // Record the negotiated suite. Responses carry the authoritative selection.
    let suite: Option<&Proposal> = msg
        .selected_proposal
        .as_ref()
        .or_else(|| msg.offered_proposals.first());

    // A responder that returns no SA payload has not selected a suite; it has
    // refused. Recording that as "unknown" instead of "failed" is how a
    // broken tunnel ends up scoring as a clean one.
    if !msg.is_request && suite.is_none() {
        entry.negotiation_rejected = true;
        for p in &msg.payloads {
            if let Payload::Notify { notify_type, .. } = p {
                if !entry.rejection_notifies.contains(notify_type) {
                    entry.rejection_notifies.push(*notify_type);
                }
            }
        }
    }

    if let Some(p) = suite {
        if entry.suite_packet == 0 {
            entry.suite_packet = msg.packet_index;
        }
        let (encr, integ, ke, prf, bits) = summarise(p);
        if let Some(e) = encr {
            match &entry.encryption {
                None => entry.encryption = Some(e),
                Some(previous) if previous != &e => {
                    // A change of suite on the same SPI is exactly the
                    // failover-to-legacy-gateway case worth flagging.
                    let better = is_stronger(&e, previous);
                    entry.downgrade_observed = !better;
                    entry.encryption = Some(e);
                }
                _ => {}
            }
        }
        if integ.is_some() {
            entry.integrity = integ;
        }
        if ke.is_some() {
            entry.key_exchange = ke;
        }
        if prf.is_some() {
            entry.prf = prf;
        }
        if bits.is_some() {
            entry.key_bits = bits;
        }
        if let Some(e) = &entry.encryption {
            entry.strongest = Some(e.clone());
        }
    }

    // Tunnel vs transport from the traffic selectors.
    for p in &msg.payloads {
        if let Payload::TrafficSelector { selectors, .. } = p {
            for ts in selectors {
                if let Some(true) = ts.implies_tunnel_mode() {
                    entry.transport_or_tunnel = Some("tunnel".into());
                } else if let Some(false) = ts.implies_tunnel_mode() {
                    entry.transport_or_tunnel = Some("transport".into());
                }
            }
        }
    }

    if entry.perfect_forward_secrecy.is_none() && msg.proposes_child_sa() {
        entry.perfect_forward_secrecy = Some(false);
    }
}

fn summarise(p: &Proposal) -> (Option<String>, Option<String>, Option<String>, Option<String>, Option<u16>) {
    let mut encr = None;
    let mut integ = None;
    let mut ke = None;
    let mut prf = None;
    let mut bits = None;
    for t in &p.transforms {
        match t.transform_type {
            crate::registry::ENCR => {
                encr = Some(t.name.clone());
                bits = t.key_bits;
            }
            crate::registry::INTEG => integ = Some(t.name.clone()),
            crate::registry::KE => ke = Some(t.name.clone()),
            crate::registry::PRF => prf = Some(t.name.clone()),
            _ => {}
        }
    }
    (encr, integ, ke, prf, bits)
}

fn is_stronger(candidate: &str, incumbent: &str) -> bool {
    strength(candidate) > strength(incumbent)
}

fn strength(name: &str) -> u32 {
    match name {
        "ENCR_NULL" => 0,
        "ENCR_3DES" => 10,
        "ENCR_AES_CBC" | "ENCR_AES_CTR" => 40,
        "ENCR_AES_CBC_256" => 50,
        "ENCR_AES_GCM_16" | "ENCR_AES_CCM_8" | "ENCR_CHACHA20_POLY1305" => 70,
        "ENCR_AES_GCM_32" => 80,
        _ => 30,
    }
}

// =========================================================================
// Findings
// =========================================================================

/// Evaluate every rule against the accumulated posture.
pub fn evaluate(sa: &mut SaPosture) {
    let mut raw: Vec<(Finding, Evidence)> = Vec::new();

    // -- legacy protocol version
    if sa.ike_version == "IKEv1" {
        raw.push((
            Finding {
                id: "VYU-001".into(),
                severity: Severity::Medium,
                title: "Legacy IKEv1 in use".into(),
                detail: "The tunnel negotiates ISAKMP (IKEv1). IKEv2 resists denial of service, supports multiple key exchanges, and removes the Aggressive Mode identity leak entirely.".into(),
                standard: "RFC 7296 §1.1 — IKEv2 is the current Internet Standard for IKE".into(),
                cwe: None,
                packet_index: 0,
                src: sa.src.clone(),
                dst: sa.dst.clone(),
                observed: "IKEv1".into(),
                remediation: "Migrate the peer to IKEv2 and disable IKEv1 once both endpoints support it.".into(),
            },
            Evidence::Observed,
        ));
    }

    // -- aggressive mode
    if sa.aggressive_mode {
        raw.push((
            Finding {
                id: "VYU-002".into(),
                severity: Severity::Critical,
                title: "IKEv1 Aggressive Mode sends the peer identity in the clear".into(),
                detail: format!(
                    "Aggressive Mode exchanges ID and HASH unprotected, so a passive observer learns who peers with whom and can mount an offline dictionary attack against the pre-shared key. Observed identity: {}.",
                    sa.identities_in_clear.join(", ")
                ),
                standard: "RFC 2407 §4.1; CVE-2018-5389 — IKEv1 PSK is offline-crackable".into(),
                cwe: Some(Cwe::KeyExchangeWithoutAuthentication),
                packet_index: 0,
                src: sa.src.clone(),
                dst: sa.dst.clone(),
                observed: "Aggressive Mode".into(),
                remediation: "Switch to Main Mode or IKEv2 and replace the pre-shared key with certificate authentication.".into(),
            },
            Evidence::Observed,
        ));
    }

    // -- encryption algorithm
    if let Some(enc) = &sa.encryption {
        if is_null_encryption(enc) {
            raw.push((
                Finding {
                    id: "VYU-010".into(),
                    severity: Severity::Critical,
                    title: "ESP negotiated with NULL encryption".into(),
                    detail: "The Child SA carries no confidentiality protection at all. Anything traversing this tunnel is readable on the wire.".into(),
                    standard: "RFC 8221 and RFC 8247 both mark ENCR_NULL MUST NOT".into(),
                    cwe: Some(Cwe::MissingRequiredCryptographicStep),
                    packet_index: 0,
                    src: sa.src.clone(),
                    dst: sa.dst.clone(),
                    observed: enc.clone(),
                    remediation: "Remove ENCR_NULL from the proposals list and require AES-GCM-16 or AES-256-GCM.".into(),
                },
                Evidence::Observed,
            ));
        } else if is_64_bit_block_cipher(enc) {
            raw.push((
                Finding {
                    id: "VYU-011".into(),
                    severity: Severity::High,
                    title: "3DES in use — SWEET32 birthday exposure".into(),
                    detail: "Triple-DES has a 64-bit block size. CBC mode leaks plaintext XOR after roughly 32 GB of ciphertext under one key, and a sustained high-throughput link reaches that in hours. This is CVE-2016-2183.".into(),
                    standard: "RFC 8221 — ENCR_3DES is SHOULD NOT; NIST SP 800-131A retires TDEA".into(),
                    cwe: Some(Cwe::BrokenCryptoAlgorithm),
                    packet_index: 0,
                    src: sa.src.clone(),
                    dst: sa.dst.clone(),
                    observed: enc.clone(),
                    remediation: "Move to AES-256-GCM. If a peer cannot negotiate AEAD, use AES-CBC-256 with an explicit integrity transform.".into(),
                },
                Evidence::Observed,
            ));
        } else {
            if !is_known_usable_encr(enc) {
                    raw.push((
                        Finding {
                            id: "VYU-012".into(),
                            severity: Severity::Medium,
                            title: "Encryption algorithm outside the current recommended set".into(),
                            detail: format!(
                                "{enc} is not in the RFC 8221 mandatory or recommended set, and carries no key-length or mode evidence that would make it safe by default."
                            ),
                            standard: "RFC 8221 §5 — ESP Encryption Algorithms".into(),
                            cwe: Some(Cwe::InadequateEncryptionStrength),
                            packet_index: 0,
                            src: sa.src.clone(),
                            dst: sa.dst.clone(),
                            observed: enc.clone(),
                            remediation: "Prefer ENCR_AES_GCM_16 (16-byte tag) with an explicit 256-bit key length.".into(),
                        },
                        Evidence::Observed,
                    ));
            }
        }
    }

    // -- key exchange group
    if let Some(ke) = &sa.key_exchange {
        if ke.starts_with("KE_DH_") || ke.starts_with("MODP-") {
            if let Some(bits) = dh_bits(ke) {
                if bits < 2048 {
                    let sev = if bits <= 1024 { Severity::Critical } else { Severity::High };
                    raw.push((
                        Finding {
                            id: "VYU-020".into(),
                            severity: sev,
                            title: format!("Weak Diffie-Hellman group ({bits}-bit MODP)"),
                            detail: format!(
                                "The IKE SA is keyed over a {bits}-bit finite-field group. Discrete logarithms in groups this size are within reach of a well-resourced adversary, and a passively recorded handshake can be decrypted later once the key is recovered. The Logjam measurement found 66% of scanned IPsec endpoints offering 1024-bit DH."
                            ),
                            standard: "RFC 8247 §3.3 — 1024-bit MODP is MUST NOT; NIST SP 800-57 Part 1 Rev. 5 sets 2048 as the floor".into(),
                            cwe: Some(Cwe::InadequateEncryptionStrength),
                            packet_index: 0,
                            src: sa.src.clone(),
                            dst: sa.dst.clone(),
                            observed: ke.clone(),
                            remediation: "Negotiate ECP-256 or X25519 for equivalent strength at lower CPU cost, or 2048-bit MODP if a field is required.".into(),
                        },
                        Evidence::Observed,
                    ));
                }
            }
        }
    }

    // -- integrity algorithm
    if let Some(integ) = &sa.integrity {
        if is_broken_hash(integ) {
            raw.push((
                Finding {
                    id: "VYU-030".into(),
                    severity: Severity::Critical,
                    title: "MD5-based integrity algorithm".into(),
                    detail: "MD5 is fully broken for collision resistance. An integrity algorithm that an attacker can forge provides no assurance.".into(),
                    standard: "RFC 8247 §3.4 — MD5-based integrity is MUST NOT".into(),
                    cwe: Some(Cwe::BrokenCryptoAlgorithm),
                    packet_index: 0,
                    src: sa.src.clone(),
                    dst: sa.dst.clone(),
                    observed: integ.clone(),
                    remediation: "Move to AUTH_HMAC_SHA2_256_96, or to an AEAD cipher so integrity is not negotiated separately.".into(),
                },
                Evidence::Observed,
            ));
        } else if is_sha1_hash(integ) {
            raw.push((
                Finding {
                    id: "VYU-031".into(),
                    severity: Severity::Low,
                    title: "SHA-1 integrity is demoted to MUST-".into(),
                    detail: "RFC 8221 moved AUTH_HMAC_SHA1_96 from MUST to MUST- in 2017. HMAC-SHA1 is not broken the way bare SHA-1 is, but it is on the way out and will not be mandated going forward.".into(),
                    standard: "RFC 8221 §6 — AUTH_HMAC_SHA1_96 is MUST-".into(),
                    cwe: Some(Cwe::BrokenCryptoAlgorithm),
                    packet_index: 0,
                    src: sa.src.clone(),
                    dst: sa.dst.clone(),
                    observed: integ.clone(),
                    remediation: "Schedule a move to AUTH_HMAC_SHA2_256_96. Low urgency; plan rather than panic.".into(),
                },
                Evidence::Observed,
            ));
        }
    }

    // -- pseudorandom function, or the IKEv1 equivalent
    if let Some(prf) = &sa.prf {
        if is_broken_hash(prf) {
            raw.push((
                Finding {
                    id: "VYU-032".into(),
                    severity: Severity::High,
                    title: "MD5 pseudorandom function".into(),
                    detail: "The PRF derives keying material from MD5, which is broken. Keying material derived from a broken PRF inherits that weakness, and the PRF is the last thing standing between a captured transcript and the session keys.".into(),
                    standard: "RFC 8247 §3.2 — PRF_HMAC_MD5 is MUST NOT".into(),
                    cwe: Some(Cwe::BrokenCryptoAlgorithm),
                    packet_index: 0,
                    src: sa.src.clone(),
                    dst: sa.dst.clone(),
                    observed: prf.clone(),
                    remediation: "Use PRF_HMAC_SHA2_256.".into(),
                },
                Evidence::Observed,
            ));
        } else if is_sha1_hash(prf) {
            raw.push((
                Finding {
                    id: "VYU-033".into(),
                    severity: Severity::Low,
                    title: "SHA-1 pseudorandom function is demoted to MUST-".into(),
                    detail: "HMAC-SHA1 as a PRF is not broken the way bare SHA-1 is, but RFC 8247 moved it to MUST- and it will not be required of new implementations. It is a migration item, not an incident.".into(),
                    standard: "RFC 8247 §3.2 — PRF_HMAC_SHA1 is MUST-".into(),
                    cwe: Some(Cwe::BrokenCryptoAlgorithm),
                    packet_index: 0,
                    src: sa.src.clone(),
                    dst: sa.dst.clone(),
                    observed: prf.clone(),
                    remediation: "Move to PRF_HMAC_SHA2_256 alongside the cipher migration. In IKEv1 this is only reachable through interoperability extensions, which is a reason to migrate to IKEv2.".into(),
                },
                Evidence::Observed,
            ));
        }
    }

    // -- perfect forward secrecy
    match sa.perfect_forward_secrecy {
        Some(false) => raw.push((
            Finding {
                id: "VYU-040".into(),
                severity: Severity::High,
                title: "No perfect forward secrecy on the Child SA".into(),
                detail: "The Child SA was established without a fresh key exchange. A later compromise of the IKE SA keys exposes every session the tunnel has ever carried, including traffic already archived by an adversary.".into(),
                standard: "NIST SP 800-77 Rev. 1 §5.3 — PFS requires a new DH exchange per Child SA".into(),
                cwe: None,
                packet_index: 0,
                src: sa.src.clone(),
                dst: sa.dst.clone(),
                observed: "Child SA without KE".into(),
                remediation: "Enable PFS so each CREATE_CHILD_SA (or Quick Mode) exchange carries its own key exchange payload.".into(),
            },
            Evidence::Observed,
        )),
        None => raw.push((
            Finding {
                id: "VYU-041".into(),
                severity: Severity::Info,
                title: "PFS state not observed in this capture".into(),
                detail: "No CREATE_CHILD_SA or Quick Mode exchange appeared in the capture, so PFS could be neither confirmed nor denied. Absence of evidence, not evidence of absence.".into(),
                standard: "NIST SP 800-77 Rev. 1 §5.3".into(),
                cwe: None,
                packet_index: 0,
                src: sa.src.clone(),
                dst: sa.dst.clone(),
                observed: "No child-SA rekey observed".into(),
                remediation: "Capture across a rekey boundary (typically 8 hours) to confirm the PFS configuration.".into(),
            },
            Evidence::Inferred,
        )),
        _ => {}
    }

    // -- downgrade across negotiations
    if sa.downgrade_observed {
        raw.push((
            Finding {
                id: "VYU-050".into(),
                severity: Severity::Critical,
                title: "Security downgrade observed on the same Security Association".into(),
                detail: format!(
                    "The suite changed from a stronger configuration to {}. This is the signature of traffic failing over to a stale backup gateway that nobody remembered to harden.",
                    sa.encryption.clone().unwrap_or_else(|| "a weaker suite".into())
                ),
                standard: "RFC 8247 §2 — algorithm downgrade must be prevented at the policy layer".into(),
                cwe: None,
                packet_index: 0,
                src: sa.src.clone(),
                dst: sa.dst.clone(),
                observed: sa.encryption.clone().unwrap_or_default(),
                remediation: "Audit the backup path, not just the primary. A hardened primary with a legacy failover is an availability feature that silently becomes a security liability.".into(),
            },
            Evidence::Inferred,
        ));
    }

    // -- a handshake that was refused
    //
    // Without this, a responder that returns only an error notification leaves
    // an SA with no suite at all, no findings, and therefore a perfect score.
    // The capture would report a failed tunnel as a clean one. The suite being
    // absent here is the *result* of the exchange, not an absence of data, so
    // it is rated rather than reported as a blindspot.
    if sa.negotiation_rejected && sa.encryption.is_none() {
        let observed: Vec<String> = sa
            .rejection_notifies
            .iter()
            .map(|n| format!("0x{n:04x}"))
            .collect();
        raw.push((
            Finding {
                id: "VYU-003".into(),
                severity: Severity::Critical,
                title: "IKE negotiation was refused; no Security Association was established".into(),
                detail: format!(
                    "The peer answered with a notification and no SA payload, so no suite was ever selected. Observed notification types: {}. Traffic on this path is unprotected, because no tunnel exists to protect it.",
                    if observed.is_empty() { "unidentified".to_string() } else { observed.join(", ") }
                ),
                standard: "RFC 7296 §3.15 — an error notification aborts the exchange without establishing an SA".into(),
                cwe: Some(Cwe::MissingRequiredCryptographicStep),
                packet_index: 0,
                src: sa.src.clone(),
                dst: sa.dst.clone(),
                observed: "no SA payload in the response".into(),
                remediation: "Read the notification type: NO_PROPOSAL_CHOSEN means no common suite, AUTHENTICATION_FAILED means a credential or trust problem, and NO_ADDITIONAL_SAS means the gateway is out of child-SA slots. Fix the negotiation before assessing the tunnel's posture.".into(),
            },
            Evidence::Observed,
        ));
    }

    // -- metadata exposure
    if sa.ike_version == "IKEv1" && !sa.identities_in_clear.is_empty() {
        raw.push((
            Finding {
                id: "VYU-060".into(),
                severity: Severity::Medium,
                title: "Gateway identities disclosed on the wire".into(),
                detail: format!(
                    "The following identities were readable without decryption: {}. In a targeted environment this maps the trust graph of the organisation for free.",
                    sa.identities_in_clear.join("; ")
                ),
                standard: "RFC 4303 §3.1 — ESP hides its payload; the IKE identity is the leak".into(),
                cwe: Some(Cwe::ExposureOfSensitiveInformation),
                packet_index: 0,
                src: sa.src.clone(),
                dst: sa.dst.clone(),
                observed: format!("{} identities", sa.identities_in_clear.len()),
                remediation: "Use IKEv2, where identities travel inside the encrypted payload.".into(),
            },
            Evidence::Observed,
        ));
    }

    assign_packet_citations(&mut raw, sa);
    sa.findings = dedupe(raw);
    sa.quantum_exposure = kal_score(sa);
    let (score, grade) = score_sa(sa);
    sa.score = score;
    sa.grade = grade;
}

/// A 64-bit-block cipher: the SWEET32 birthday bound applies. Matched against
/// both identifier spaces, because IKEv1 and IKEv2 name the same cipher
/// differently and a rule that only knew one spelling would miss half the
/// estate.
fn is_64_bit_block_cipher(name: &str) -> bool {
    matches!(
        name,
        "ENCR_3DES" | "3DES" | "DES" | "Blowfish" | "CAST5" | "IDEA" | "3IDEA"
    )
}

/// No confidentiality at all.
fn is_null_encryption(name: &str) -> bool {
    name == "ENCR_NULL" || name == "NULL"
}

/// A broken hash used as the PRF or the IKEv1 hash.
fn is_broken_hash(name: &str) -> bool {
    matches!(
        name,
        "PRF_HMAC_MD5" | "MD5" | "AUTH_HMAC_MD5_96" | "HMAC-MD5"
    )
}

/// SHA-1 as a PRF or hash: demoted, not prohibited.
fn is_sha1_hash(name: &str) -> bool {
    matches!(
        name,
        "PRF_HMAC_SHA1" | "SHA1" | "AUTH_HMAC_SHA1_96" | "HMAC-SHA"
    )
}

fn is_known_usable_encr(name: &str) -> bool {
    matches!(
        name,
        "ENCR_AES_GCM_16"
            | "ENCR_AES_GCM_32"
            | "ENCR_AES_CBC_256"
            | "ENCR_AES_CBC"
            | "ENCR_CHACHA20_POLY1305"
            | "ENCR_AES_CCM_8"
            | "ENCR_AES_CTR"
            | "ENCR_AES_GCM_8"
            | "ENCR_AES_GCM_12"
            | "ENCR_AES_CCM_12"
            | "ENCR_AES_CCM_16"
            | "ENCR_CAMELLIA_CBC"
            | "ENCR_KUZNYECHIK_MGM_KTREE"
            | "AES-CBC"
            | "AES-CTR"
            | "AES-CBC-256"
            | "Camellia-CBC"
            | "Camellia-CTR"
            | "Camellia-CBC-256"
    )
}

/// Extract the DH group size from either naming scheme, in bits.
fn dh_bits(name: &str) -> Option<u16> {
    name.strip_prefix("KE_DH_")
        .or_else(|| name.strip_prefix("MODP-"))
        .and_then(|s| s.parse::<u16>().ok())
}

/// Point every finding at the frame that supports it.
///
/// The caller has already folded per-packet evidence into the accumulator, so a
/// finding arrives here without a frame number. It is then attributed to the
/// message that carried the suite, which is the frame a reader must open to
/// check the claim. If no suite was ever seen the citation is the first frame
/// of the exchange instead, and 0 remains the explicit marker for "this
/// Security Association, not one frame" rather than a frame number that was
/// never observed.
fn assign_packet_citations(raw: &mut [(Finding, Evidence)], sa: &SaPosture) {
    let cited = if sa.suite_packet != 0 {
        sa.suite_packet
    } else {
        sa.first_packet
    };
    for (f, _) in raw.iter_mut() {
        if f.packet_index == 0 {
            f.packet_index = cited;
        }
    }
}

fn dedupe(raw: Vec<(Finding, Evidence)>) -> Vec<RatedFinding> {
    use std::collections::HashMap;
    let mut seen: HashMap<String, (usize, u32)> = HashMap::new();
    let mut out: Vec<RatedFinding> = Vec::new();

    for (finding, evidence) in raw {
        let key = finding.dedup_key();
        match seen.get(&key) {
            Some((idx, count)) => {
                let (i, c) = (*idx, *count + 1);
                out[i].occurrences = c;
            }
            None => {
                seen.insert(key, (out.len(), 1));
                out.push(RatedFinding {
                    finding,
                    evidence,
                    occurrences: 1,
                });
            }
        }
    }

    out.sort_by(|a, b| b.finding.severity.cmp(&a.finding.severity));
    out
}

/// Harvest-now-decrypt-later exposure, 0 to 100.
///
/// The inputs are exactly what the capture shows: the key exchange family,
/// whether PFS is on, and how long the tunnel is expected to carry sensitive
/// data. Nothing here guesses.
pub fn kal_score(sa: &SaPosture) -> u32 {
    let mut score: u32 = 0;

    match sa.key_exchange.as_deref() {
        // A post-quantum group already in the handshake removes the core risk.
        Some(k) if k.starts_with("KE_ML_KEM") => return 0,
        // A modern classical group is still Shor-broken; it only buys time.
        // The IKEv1 spellings are matched too: an ECP-256 group reported as
        // "ECP-256" is the same 256-bit curve as IKEv2's "KE_ECDH_256", and
        // scoring the two differently would make the quantum number depend on
        // the protocol version rather than on the cryptography.
        Some(k)
            if k.starts_with("KE_ECDH_")
                || k == "KE_X25519"
                || k == "KE_X448"
                || k.starts_with("ECP-")
                || k.starts_with("brainpool") =>
        {
            score += 25
        }
        Some(k) if k.starts_with("KE_DH_") || k.starts_with("MODP-") => match dh_bits(k) {
            Some(b) if b >= 3072 => score += 40,
            Some(b) if b >= 2048 => score += 50,
            _ => score += 75,
        },
        _ => score += 60,
    }

    // Without PFS, one future key compromise rewrites the whole history.
    if sa.perfect_forward_secrecy != Some(true) {
        score += 20;
    }

    score.min(100)
}

/// Posture score: start at 100, subtract the weight of each distinct finding.
///
/// A critical finding caps the grade at F regardless of arithmetic. A tunnel
/// with no confidentiality, or a pre-shared key that a passive observer can
/// crack offline, has not partially failed — it has failed at the job it
/// exists to do, and averaging that against a healthy suite would mislead.
pub fn score_sa(sa: &SaPosture) -> (u32, String) {
    let mut penalty: i32 = 0;
    let mut has_critical = false;
    for f in &sa.findings {
        penalty += f.finding.severity.weight();
        if f.finding.severity == Severity::Critical {
            has_critical = true;
        }
    }
    let mut score = (100i32 - penalty).clamp(0, 100) as u32;

    // A critical finding drags the number down as well as the letter. Leaving a
    // failing tunnel at 59 while printing grade F would read as a contradiction,
    // and a reader scanning the score column is exactly the reader a dashboard
    // cannot warn.
    if has_critical {
        score = score.min(39);
    }

    (score, grade_for(score).to_string())
}

pub fn grade_for(score: u32) -> &'static str {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ike::{TrafficSelector, Transform};
    use crate::registry::Req;

    fn transform(ttype: u8, tid: u8) -> Transform {
        let alg = crate::registry::lookup(ttype, tid);
        Transform {
            transform_type: ttype,
            type_name: crate::registry::transform_type_name(ttype).into(),
            transform_id: tid as u16,
            name: alg.map(|a| a.name.to_string()).unwrap_or_else(|| "UNKNOWN".into()),
            key_bits: alg.and_then(|a| a.key_bits),
            block_bits: alg.and_then(|a| a.block_bits),
            requirement: alg.map(|a| a.req.as_str().to_string()),
            usable: alg.map(|a| a.is_usable()).unwrap_or(false),
            discouraged: alg.map(|a| a.is_discouraged()).unwrap_or(false),
            demoted: alg.map(|a| a.is_demoted()).unwrap_or(false),
            note: alg.map(|a| a.note.to_string()),
            attributes: vec![],
        }
    }

    fn sa_with(encr: u8, prf: u8, ke: u8, pfs: Option<bool>, version: &str) -> SaPosture {
        let mut p = Proposal {
            number: 1,
            protocol_id: 1,
            spi: None,
            transforms: vec![
                transform(crate::registry::ENCR, encr),
                transform(crate::registry::PRF, prf),
                transform(crate::registry::KE, ke),
            ],
        };
        p.protocol_id = 1;
        let (e, _i, k, pr, _b) = summarise(&p);
        SaPosture {
            sa_id: "test".into(),
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            ike_version: version.into(),
            exchanges_seen: vec!["IKE_SA_INIT".into()],
            aggressive_mode: false,
            encryption: e,
            integrity: None,
            key_exchange: k,
            prf: pr,
            key_bits: None,
            perfect_forward_secrecy: pfs,
            transport_or_tunnel: Some("tunnel".into()),
            identities_in_clear: vec![],
            vendor_ids: vec![],
            strongest: None,
            downgrade_observed: false,
            negotiation_rejected: false,
            rejection_notifies: Vec::new(),
            first_packet: 1,
            suite_packet: 1,
            score: 100,
            grade: "A".into(),
            findings: vec![],
            quantum_exposure: 0,
        }
    }

    #[test]
    fn modern_tunnel_scores_clean() {
        // AES-256-GCM, PRF-SHA2-256, ECP-256, PFS on, IKEv2.
        let mut sa = sa_with(20, 5, 19, Some(true), "IKEv2");
        evaluate(&mut sa);
        assert!(sa.findings.is_empty(), "unexpected findings: {:?}", sa.findings);
        assert_eq!(sa.score, 100);
        assert_eq!(sa.grade, "A");
        assert_eq!(
            sa.quantum_exposure, 25,
            "a modern classical group still carries HNDL exposure; only PQ removes it"
        );
    }

    #[test]
    fn three_des_with_modp_1024_and_no_pfs_fails_hard() {
        // 3DES, SHA-1 PRF, MODP-1024, no PFS, IKEv1 Aggressive.
        let mut sa = sa_with(3, 2, 2, Some(false), "IKEv1");
        sa.aggressive_mode = true;
        sa.identities_in_clear.push("ID_FQDN vpn-gw-3".into());
        evaluate(&mut sa);

        let ids: Vec<&str> = sa.findings.iter().map(|f| f.finding.id.as_str()).collect();
        assert!(ids.contains(&"VYU-002"), "aggressive mode must be critical");
        assert!(ids.contains(&"VYU-011"), "3DES must be flagged");
        assert!(ids.contains(&"VYU-020"), "MODP-1024 must be critical");
        assert!(ids.contains(&"VYU-033"), "a SHA-1 PRF is a demotion");
        assert!(ids.contains(&"VYU-040"), "missing PFS must be flagged");
        assert!(ids.contains(&"VYU-060"), "cleartext identity is metadata exposure");

        assert_eq!(sa.grade, "F");
        assert!(sa.score < 40);
        assert!(
            sa.quantum_exposure >= 90,
            "expected very high HNDL exposure, got {}",
            sa.quantum_exposure
        );
    }

    #[test]
    fn null_encryption_is_the_worst_case() {
        let mut sa = sa_with(11, 5, 19, Some(true), "IKEv2");
        evaluate(&mut sa);
        let null_finding = sa
            .findings
            .iter()
            .find(|f| f.finding.id == "VYU-010")
            .expect("NULL encryption finding");
        assert_eq!(null_finding.finding.severity, Severity::Critical);
        assert_eq!(sa.grade, "F");
    }

    #[test]
    fn post_quantum_key_exchange_zeroes_hndl_exposure() {
        let mut sa = sa_with(20, 5, 36, Some(true), "IKEv2");
        evaluate(&mut sa);
        assert_eq!(sa.quantum_exposure, 0, "ML-KEM-768 is post-quantum");
    }

    #[test]
    fn downgrade_to_a_weaker_suite_is_caught() {
        let mut sa = sa_with(3, 2, 2, Some(false), "IKEv1");
        sa.downgrade_observed = true;
        evaluate(&mut sa);
        assert!(sa
            .findings
            .iter()
            .any(|f| f.finding.id == "VYU-050"));
    }

    #[test]
    fn unobserved_pfs_is_reported_as_inferred_not_as_a_failure() {
        let mut sa = sa_with(20, 5, 19, None, "IKEv2");
        evaluate(&mut sa);
        let f = sa
            .findings
            .iter()
            .find(|f| f.finding.id == "VYU-041")
            .expect("unknown PFS should be reported as unknown");
        assert_eq!(f.evidence, Evidence::Inferred);
        assert_eq!(f.finding.severity, Severity::Info);
        assert!(sa.score > 90, "an unknown is not a failure");
    }

    #[test]
    fn findings_are_sorted_by_severity() {
        let mut sa = sa_with(3, 2, 2, Some(false), "IKEv1");
        evaluate(&mut sa);
        let sevs: Vec<Severity> = sa.findings.iter().map(|f| f.finding.severity).collect();
        let mut sorted = sevs.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(sevs, sorted);
    }

    #[test]
    fn every_finding_carries_a_standard_and_a_remediation() {
        let mut sa = sa_with(3, 2, 2, Some(false), "IKEv1");
        sa.aggressive_mode = true;
        evaluate(&mut sa);
        for f in &sa.findings {
            assert!(!f.finding.standard.is_empty(), "{} lacks a standard", f.finding.id);
            assert!(
                !f.finding.remediation.is_empty(),
                "{} lacks a remediation",
                f.finding.id
            );
            assert!(!f.finding.observed.is_empty());
        }
    }

    #[test]
    fn host_selector_keeps_transport_mode_visible_in_the_posture() {
        let ts = TrafficSelector {
            ts_type: 7,
            protocol_id: Some(17),
            start: "198.51.100.7".into(),
            end: "198.51.100.7".into(),
            start_port: Some(0),
            end_port: Some(0),
        };
        assert_eq!(ts.implies_tunnel_mode(), Some(false));
    }

    #[test]
    fn grade_boundaries_are_inclusive_and_sane() {
        assert_eq!(grade_for(100), "A");
        assert_eq!(grade_for(90), "A");
        assert_eq!(grade_for(89), "B");
        assert_eq!(grade_for(0), "F");
    }

    #[test]
    fn requirement_ranks_order_weakest_first() {
        assert!(rank_of(Req::MustNot) < rank_of(Req::ShouldNot));
        assert!(rank_of(Req::ShouldNot) < rank_of(Req::Recommended));
        assert!(rank_of(Req::Recommended) < rank_of(Req::Must));
    }

    // Small shim so the test can reach the private rank in ike.rs semantics.
    fn rank_of(r: Req) -> u8 {
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
}

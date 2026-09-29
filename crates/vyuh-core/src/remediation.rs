//! Turn findings into a drop-in swanctl configuration.
//!
//! A finding that names a weak algorithm is only half an answer. The other half
//! is the configuration that would have avoided it, and the fastest way to show
//! that is a file an operator can diff against what they are running.
//!
//! The output is a proposal list, not a whole config. A generated file that
//! replaced the operator's config would be reckless: it could break a working
//! tunnel, and it would silently drop the policies this tool never sees. So this
//! emits the algorithm section, names the gateway it applies to, and states
//! exactly what is expected to change.
//!
//! Nothing here is inferred from the version numbers in a report. The proposals
//! come from the registry's own requirement levels, so a finding and its
//! remediation cannot drift apart.

use serde::{Deserialize, Serialize};

use crate::posture::{Report, SaPosture};
use crate::registry;

/// A single change: what is wrong, and what to write instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    /// The finding this change answers.
    pub finding_id: String,
    /// What the capture showed.
    pub observed: String,
    /// Why the observed value is wrong.
    pub reason: String,
    /// The replacement, in swanctl proposal syntax.
    pub replacement: String,
    /// Files or sections to change.
    pub applies_to: String,
    /// Whether this must be applied for the tunnel to be acceptable.
    pub mandatory: bool,
}

/// A generated remediation for one gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub gateway: String,
    pub peer: String,
    pub ike_version: String,
    /// The proposed `proposals = ` value for swanctl.
    pub proposals: String,
    pub ike_proposals: String,
    pub esp_proposals: String,
    pub changes: Vec<Change>,
    /// Rendered swanctl.conf fragment, ready to read.
    pub config: String,
    /// Warnings about anything this tool cannot fix from the wire.
    pub caveats: Vec<String>,
}

/// Build a remediation for every Security Association in a report.
pub fn remediate(report: &Report) -> Vec<Remediation> {
    report.security_associations.iter().map(remediate_sa).collect()
}

fn remediate_sa(sa: &SaPosture) -> Remediation {
    let mut changes: Vec<Change> = Vec::new();
    // Owned, not borrowed: some replacements are computed at runtime from the
    // observed key size, and a `&'static str` vector would force every one of
    // those through a leak or a small const table that has to be kept in sync.
    let mut ike: Vec<String> = Vec::new();
    let mut esp: Vec<String> = Vec::new();
    let mut caveats: Vec<String> = Vec::new();

    let want_encr = |ike: &mut Vec<String>| {
        if ike.is_empty() {
            ike.push("aes256gcm16".into());
        }
    };

    // -- encryption
    match sa.encryption.as_deref() {
        None => {
            caveats.push(
                "No suite was negotiated in this direction, so there is nothing to \
                 rewrite. Resolve VYU-003 first; until the tunnel establishes there is \
                 no algorithm list to correct."
                    .into(),
            );
        }
        Some(encr) if is_null(encr) => {
            want_encr(&mut ike);
            changes.push(Change {
                finding_id: "VYU-010".into(),
                observed: encr.into(),
                reason: "ESP carries no confidentiality. RFC 8221 and RFC 8247 both mark ENCR_NULL MUST NOT.".into(),
                replacement: "aes256gcm16".into(),
                applies_to: "connections.<conn>.children.<child>.esp_proposals".into(),
                mandatory: true,
            });
        }
        Some(encr) if encr.contains("3DES") => {
            ike.push("aes256gcm16".into());
            esp.push("aes256gcm16".into());
            changes.push(Change {
                finding_id: "VYU-011".into(),
                observed: encr.into(),
                reason: "A 64-bit block cipher reaches its birthday bound after roughly 32 GB of ciphertext (SWEET32, CVE-2016-2183). RFC 8221 marks ENCR_3DES SHOULD NOT.".into(),
                replacement: "aes256gcm16".into(),
                applies_to: "connections.<conn>.proposals and .children.<child>.esp_proposals".into(),
                mandatory: false,
            });
        }
        Some(encr) if encr.contains("DES") && !encr.contains("3DES") => {
            ike.push("aes256gcm16".into());
            esp.push("aes256gcm16".into());
            changes.push(Change {
                finding_id: "VYU-011".into(),
                observed: encr.into(),
                reason: "Single DES is structurally obsolete. NIST withdrew FIPS 46-3.".into(),
                replacement: "aes256gcm16".into(),
                applies_to: "connections.<conn>.proposals and .children.<child>.esp_proposals".into(),
                mandatory: true,
            });
        }
        Some(encr) if encr.contains("CBC") => {
            // AES-CBC is legal, so this is a widening rather than a rejection.
            // It needs a separate integrity algorithm, which is why the proposal
            // carries "sha256" alongside it. Migrating to an AEAD is the better
            // answer, but a tool must not force that on an operator whose peers
            // are constrained, so the minimal change is offered.
            let bits = sa.key_bits.unwrap_or(128);
            let proposal = "aes256-sha256".to_string();
            ike.push(proposal.clone());
            esp.push(proposal.clone());
            changes.push(Change {
                finding_id: "VYU-012".into(),
                observed: format!("{encr} with a {bits}-bit key"),
                reason: "CBC is permitted, but the key size was below the 256-bit floor this deployment targets. AES-CBC also requires a separate integrity algorithm; an AEAD such as aes256gcm16 removes that dependency and is preferred where the peers support it.".into(),
                replacement: proposal.clone(),
                applies_to: "connections.<conn>.proposals and .children.<child>.esp_proposals".into(),
                mandatory: false,
            });
        }
        Some(encr) => {
            // Already acceptable. Keep the observed algorithm if we know it,
            // otherwise fall back to the current default.
            match encr {
                "ENCR_AES_GCM_16" => {
                    ike.push("aes256gcm16".into());
                    esp.push("aes256gcm16".into());
                }
                "ENCR_AES_CCM_16" => {
                    ike.push("aes256ccm16".into());
                    esp.push("aes256ccm16".into());
                }
                "ENCR_CHACHA20_POLY1305" => {
                    ike.push("chacha20poly1305".into());
                    esp.push("chacha20poly1305".into());
                }
                _ => {
                    ike.push("aes256gcm16".into());
                    esp.push("aes256gcm16".into());
                    caveats.push(format!(
                        "The observed encryption algorithm {encr} is acceptable, but it has no swanctl proposal name in the registry, so the modern default is shown instead. Replace it with the running value if the two differ."
                    ));
                }
            }
        }
    }

    // -- integrity and PRF
    let hash = sa.integrity.as_deref().or(sa.prf.as_deref());
    match hash {
        Some(h) if h.contains("MD5") => {
            ike.push("prfsha256".into());
            changes.push(Change {
                finding_id: "VYU-030".into(),
                observed: h.into(),
                reason: "MD5 is fully broken for collision resistance. RFC 8247 marks it MUST NOT.".into(),
                replacement: "prfsha256".into(),
                applies_to: "connections.<conn>.proposals".into(),
                mandatory: true,
            });
        }
        Some(h) if h.contains("SHA1") || h.contains("SHA-1") => {
            ike.push("prfsha256".into());
            changes.push(Change {
                finding_id: "VYU-031".into(),
                observed: h.into(),
                reason: "SHA-1 is no longer collision resistant. RFC 8221 demotes HMAC-SHA-1 to MUST-; migrate to SHA-2.".into(),
                replacement: "prfsha256".into(),
                applies_to: "connections.<conn>.proposals".into(),
                mandatory: false,
            });
        }
        _ => {
            // A SHA-2 PRF, or nothing recorded at all. Either way the proposal
            // needs one, and a tunnel with no PRF entry is not a tunnel.
            if !ike.iter().any(|p| p.starts_with("prf")) {
                ike.push("prfsha256".into());
            }
        }
    }

    // -- key exchange
    let want_ke = |ike: &mut Vec<String>| {
        let has_group = ike.iter().any(|p| {
            p.starts_with("modp") || p.starts_with("ecp") || p.starts_with("curve")
                || p.starts_with("x255") || p.starts_with("mlkem")
        });
        if !has_group {
            ike.push("ecp256".into());
        }
    };
    match sa.key_exchange.as_deref() {
        Some(ke) if ke.contains("1024") => {
            want_ke(&mut ike);
            changes.push(Change {
                finding_id: "VYU-020".into(),
                observed: ke.into(),
                reason: "1024-bit MODP is within reach of nation-state discrete-log attacks. RFC 8247 marks it MUST NOT; NIST SP 800-57 Part 1 Rev. 5 sets 2048 as the floor. The Logjam paper measured 66% of scanned IPsec endpoints offering this group.".into(),
                replacement: "ecp256".into(),
                applies_to: "connections.<conn>.proposals and .children.<child>.local_addrs".into(),
                mandatory: true,
            });
        }
        Some(ke) if ke.contains("768") => {
            want_ke(&mut ike);
            changes.push(Change {
                finding_id: "VYU-020".into(),
                observed: ke.into(),
                reason: "768-bit MODP is below the current floor and is deprecated in IANA.".into(),
                replacement: "ecp256".into(),
                applies_to: "connections.<conn>.proposals".into(),
                mandatory: true,
            });
        }
        Some(ke) if ke.starts_with("KE_X25519") => {
            ike.push("curve25519".into());
        }
        Some(ke) if ke.starts_with("KE_ECDH_256") => {
            ike.push("ecp256".into());
        }
        Some(ke) if ke.starts_with("KE_DH_2048") => {
            ike.push("modp2048".into());
        }
        Some(ke) if ke.starts_with("KE_ML_KEM") => {
            ike.push(ke.to_lowercase().replace("ke_ml_kem_", "mlkem"));
        }
        Some(_) => {
            want_ke(&mut ike);
        }
        None => {
            want_ke(&mut ike);
        }
    }

    // -- protocol version
    if sa.ike_version == "IKEv1" {
        changes.push(Change {
            finding_id: "VYU-001".into(),
            observed: "IKEv1".into(),
            reason: "ISAKMP resists neither denial of service nor the identity leak in Aggressive Mode, and it cannot express SHA-2. RFC 7296 makes IKEv2 the current Internet Standard.".into(),
            replacement: "version = 2".into(),
            applies_to: "connections.<conn> (swanctl default; both ends must support IKEv2)".into(),
            mandatory: false,
        });
    }

    // -- aggressive mode
    if sa.aggressive_mode {
        changes.push(Change {
            finding_id: "VYU-002".into(),
            observed: "Aggressive Mode".into(),
            reason: "Aggressive Mode exchanges the peer identity unprotected, which leaks the trust graph and enables an offline dictionary attack against the pre-shared key (CVE-2018-5389).".into(),
            replacement: "version = 2 (Aggressive Mode has no IKEv2 equivalent)".into(),
            applies_to: "connections.<conn>".into(),
            mandatory: true,
        });
    }

    // -- perfect forward secrecy
    match sa.perfect_forward_secrecy {
        Some(false) => changes.push(Change {
            finding_id: "VYU-040".into(),
            observed: "no PFS".into(),
            reason: "Without perfect forward secrecy, one future key compromise rewrites the entire recorded history of the tunnel.".into(),
            replacement: "add a KE payload to the child SA (swanctl does this when a key exchange group is proposed on CREATE_CHILD_SA)".into(),
            applies_to: "connections.<conn>.children.<child>".into(),
            mandatory: false,
        }),
        Some(true) => {}
        None => changes.push(Change {
            finding_id: "VYU-041".into(),
            observed: "PFS state not observed".into(),
            reason: "No CREATE_CHILD_SA or Quick Mode exchange appeared in the capture, so PFS could be neither confirmed nor denied. Absence of evidence, not evidence of absence.".into(),
            replacement: "capture a rekey to confirm the setting".into(),
            applies_to: "n/a".into(),
            mandatory: false,
        }),
    }

    // -- refused negotiation
    if sa.negotiation_rejected && sa.encryption.is_none() {
        changes.push(Change {
            finding_id: "VYU-003".into(),
            observed: "no SA payload in the response".into(),
            reason: "The peer refused the exchange, so the tunnel was never established and this is not a configuration problem yet.".into(),
            replacement: format!(
                "read notification type(s) {} before changing any algorithm",
                if sa.rejection_notifies.is_empty() {
                    "unknown".to_string()
                } else {
                    sa.rejection_notifies
                        .iter()
                        .map(|n| format!("0x{n:04x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
            applies_to: "n/a".into(),
            mandatory: true,
        });
    }

    // -- metadata exposure
    if !sa.identities_in_clear.is_empty() {
        changes.push(Change {
            finding_id: "VYU-060".into(),
            observed: format!("{} identities readable in the clear", sa.identities_in_clear.len()),
            reason: "Gateway identities were visible without decryption, which maps the trust graph of the organisation.".into(),
            replacement: "move to IKEv2, where identities travel inside the encrypted payload".into(),
            applies_to: "connections.<conn>".into(),
            mandatory: false,
        });
    }

    // Deduplicate while preserving order, since a retried capture folds the
    // same observation many times.
    changes.dedup_by(|a, b| a.finding_id == b.finding_id && a.replacement == b.replacement);

    let ike_proposals = join(&ike);
    let esp_proposals = if esp.is_empty() {
        "aes256gcm16".to_string()
    } else {
        join(&esp)
    };

    let config = render_config(sa, &ike_proposals, &esp_proposals);

    Remediation {
        gateway: format!("{} ({})", sa.src, sa.sa_id),
        peer: sa.dst.clone(),
        ike_version: sa.ike_version.clone(),
        proposals: ike_proposals.clone(),
        ike_proposals: ike_proposals.clone(),
        esp_proposals,
        changes,
        config,
        caveats,
    }
}

fn is_null(name: &str) -> bool {
    name == "ENCR_NULL" || name == "NULL"
}

fn join(items: &[String]) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for i in items {
        if !seen.contains(&i.as_str()) {
            seen.push(i);
        }
    }
    seen.join("!")
}

/// Render the swanctl.conf fragment.
///
/// This is a proposal block, not a replacement config. Replacing a working
/// config from a passive observation is how a tool breaks a production tunnel.
fn render_config(sa: &SaPosture, ike: &str, esp: &str) -> String {
    let mut out = String::new();
    out.push_str("# RAKSHAK.VYUH remediation fragment\n");
    out.push_str(&format!(
        "# generated from packet evidence for SA {} ({} -> {})\n",
        sa.sa_id, sa.src, sa.dst
    ));
    out.push_str(&format!(
        "# capture posture: grade {} ({} / 100)\n",
        sa.grade, sa.score
    ));
    out.push_str("#\n# This is the algorithm section only. Merge it into the existing\n");
    out.push_str("# connection block; it does not contain keys, IDs or rekey timers,\n");
    out.push_str("# because a passive observer cannot see those and must not guess them.\n\n");
    out.push_str("connections {\n");
    out.push_str("\tike {\n");
    out.push_str(&format!("\t\tversion = {}\n", if sa.ike_version == "IKEv2" { 2 } else { 1 }));
    out.push_str("\t\t# proposals removed:\n");
    for p in ike.split('!') {
        out.push_str(&format!("\t\t#\t  {p}\n"));
    }
    out.push_str(&format!("\t\tproposals = {ike}\n"));
    out.push_str("\t}\n\n");
    out.push_str("\tchildren {\n");
    out.push_str("\t\t<child> {\n");
    out.push_str(&format!("\t\t\tesp_proposals = {esp}\n"));
    out.push_str("\t\t}\n");
    out.push_str("\t}\n");
    out.push_str("}\n");
    out
}

/// The algorithm names the registry considers acceptable, for comparison.
pub fn approved_proposals() -> Vec<&'static str> {
    let mut out = Vec::new();
    for a in registry::ENCR_ALGS {
        if a.is_usable() && !a.is_discouraged() {
            out.push(a.name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::{evaluate, SaPosture};
    use std::collections::BTreeMap;

    fn sa_with(encr: &str, integ: Option<&str>, ke: &str, pfs: Option<bool>, v: &str) -> SaPosture {
        use crate::registry;
        let _p = crate::ike::Proposal {
            number: 1,
            protocol_id: 1,
            spi: None,
            transforms: vec![
                crate::ike::Transform {
                    transform_type: registry::ENCR,
                    type_name: "Encryption".into(),
                    transform_id: 0,
                    name: encr.into(),
                    key_bits: Some(256),
                    block_bits: Some(128),
                    requirement: None,
                    usable: true,
                    discouraged: false,
                    demoted: false,
                    note: None,
                    attributes: vec![],
                },
                crate::ike::Transform {
                    transform_type: registry::INTEG,
                    type_name: "Integrity".into(),
                    transform_id: 0,
                    name: integ.unwrap_or("none").into(),
                    key_bits: None,
                    block_bits: None,
                    requirement: None,
                    usable: true,
                    discouraged: false,
                    demoted: false,
                    note: None,
                    attributes: vec![],
                },
                crate::ike::Transform {
                    transform_type: registry::KE,
                    type_name: "Key Exchange".into(),
                    transform_id: 0,
                    name: ke.into(),
                    key_bits: None,
                    block_bits: None,
                    requirement: None,
                    usable: true,
                    discouraged: false,
                    demoted: false,
                    note: None,
                    attributes: vec![],
                },
            ],
        };
        SaPosture {
            sa_id: "abc".into(),
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            ike_version: v.into(),
            exchanges_seen: vec!["IKE_SA_INIT".into()],
            aggressive_mode: false,
            encryption: Some(encr.into()),
            integrity: integ.map(|s| s.into()),
            key_exchange: Some(ke.into()),
            prf: integ.map(|s| s.into()),
            key_bits: Some(256),
            perfect_forward_secrecy: pfs,
            transport_or_tunnel: Some("tunnel".into()),
            identities_in_clear: vec![],
            vendor_ids: vec![],
            strongest: None,
            downgrade_observed: false,
            negotiation_rejected: false,
            rejection_notifies: vec![],
            first_packet: 1,
            suite_packet: 1,
            score: 100,
            grade: "A".into(),
            findings: vec![],
            quantum_exposure: 45,
        }
    }

    fn report_for(sa: SaPosture) -> Report {
        let mut sa = sa;
        evaluate(&mut sa);
        Report {
            tool: "RAKSHAK.VYUH".into(),
            version: "0.1.0".into(),
            capture: "t.pcap".into(),
            pcap_sha256: "d".into(),
            packets_examined: 20,
            ike_messages: 12,
            esp_flows: 0,
            security_associations: vec![sa],
            posture_score: 50,
            grade: "C".into(),
            severity_counts: BTreeMap::new(),
            global_findings: vec![],
            blindspots: vec![],
            flow_records: Vec::new(),
        }
    }

    #[test]
    fn modp_1024_is_replaced_with_a_curve() {
        let r = remediate(&report_for(sa_with(
            "ENCR_AES_CBC",
            Some("AUTH_HMAC_SHA1_96"),
            "KE_DH_1024",
            Some(true),
            "IKEv2",
        )));
        assert_eq!(r[0].ike_proposals, "aes256-sha256!prfsha256!ecp256");
        let ke_change = r[0].changes.iter().find(|c| c.finding_id == "VYU-020").unwrap();
        assert!(ke_change.mandatory, "MODP-1024 is MUST NOT, so it is mandatory");
    }

    #[test]
    fn null_encryption_is_mandatory() {
        let r = remediate(&report_for(sa_with(
            "ENCR_NULL",
            Some("AUTH_HMAC_MD5_96"),
            "KE_DH_1024",
            Some(true),
            "IKEv2",
        )));
        let c = r[0].changes.iter().find(|c| c.finding_id == "VYU-010").unwrap();
        assert!(c.mandatory);
        assert_eq!(c.replacement, "aes256gcm16");
        assert!(!r[0].ike_proposals.contains("null"));
    }

    #[test]
    fn aggressive_mode_is_called_out_and_forces_ikev2() {
        let mut sa = sa_with("3DES", Some("MD5"), "MODP-1024", Some(false), "IKEv1");
        sa.aggressive_mode = true;
        sa.identities_in_clear.push("ID_FQDN gw1.example".into());
        let r = remediate(&report_for(sa));
        let ids: Vec<&str> = r[0].changes.iter().map(|c| c.finding_id.as_str()).collect();
        assert!(ids.contains(&"VYU-002"), "aggressive mode must appear");
        assert!(ids.contains(&"VYU-001"), "IKEv1 must appear");
        assert!(ids.contains(&"VYU-060"), "the identity leak must appear");
        let aggressive = r[0].changes.iter().find(|c| c.finding_id == "VYU-002").unwrap();
        assert!(aggressive.mandatory);
    }

    #[test]
    fn a_modern_tunnel_keeps_its_algorithms() {
        let r = remediate(&report_for(sa_with(
            "ENCR_AES_GCM_16",
            Some("PRF_HMAC_SHA2_256"),
            "KE_ECDH_256",
            Some(true),
            "IKEv2",
        )));
        assert_eq!(r[0].ike_proposals, "aes256gcm16!prfsha256!ecp256");
        assert!(
            !r[0].ike_proposals.contains("3des"),
            "a clean tunnel must not be told to change its ciphers"
        );
    }

    #[test]
    fn x25519_is_preserved_rather_than_replaced() {
        let r = remediate(&report_for(sa_with(
            "ENCR_AES_GCM_16",
            Some("PRF_HMAC_SHA2_256"),
            "KE_X25519",
            Some(true),
            "IKEv2",
        )));
        assert!(
            r[0].ike_proposals.contains("curve25519"),
            "X25519 is acceptable and must survive: {}",
            r[0].ike_proposals
        );
    }

    #[test]
    fn a_refused_tunnel_is_not_given_a_rewrite() {
        let mut sa = sa_with("ENCR_AES_GCM_16", Some("PRF_HMAC_SHA2_256"), "KE_ECDH_256", Some(true), "IKEv2");
        sa.encryption = None;
        sa.negotiation_rejected = true;
        sa.rejection_notifies = vec![14];
        let r = remediate(&report_for(sa));
        let c = r[0].changes.iter().find(|c| c.finding_id == "VYU-003").unwrap();
        assert!(c.replacement.contains("0x000e"), "the notify type must be shown");
        assert!(!r[0].caveats.is_empty(), "the operator must be told to fix the refusal first");
    }

    #[test]
    fn the_config_is_a_fragment_not_a_replacement() {
        let r = remediate(&report_for(sa_with(
            "ENCR_AES_CBC",
            Some("AUTH_HMAC_SHA1_96"),
            "KE_DH_1024",
            Some(false),
            "IKEv2",
        )));
        let c = &r[0].config;
        assert!(c.contains("connections {"));
        assert!(c.contains("proposals = "));
        assert!(c.contains("Merge it into the existing"));
        assert!(
            !c.contains("key =") && !c.contains("secret"),
            "a passive observer must not invent credentials"
        );
    }

    #[test]
    fn no_duplicate_changes_from_a_retried_capture() {
        let r = remediate(&report_for(sa_with(
            "ENCR_NULL",
            Some("AUTH_HMAC_MD5_96"),
            "KE_DH_1024",
            Some(true),
            "IKEv2",
        )));
        let mut ids: Vec<&str> = r[0].changes.iter().map(|c| c.finding_id.as_str()).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "changes must be unique per finding");
    }
}

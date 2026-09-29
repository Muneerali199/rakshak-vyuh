//! Ground-truth checks against the real strongSwan captures.
//!
//! Every expectation in this file was read from `tcpdump -nvv` run on the same
//! pcap, or from `swanctl --list-sas` on the live gateway. Nothing here is
//! derived from the parser under test, which is the point: a test that agrees
//! with a broken parser proves nothing.
//!
//! The captures are committed to the repository, so these run in CI with no
//! Docker and no network.

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use vyuh_core::analysis::{analyse_reader, AnalysisOptions};
use vyuh_core::posture::{Report, SaPosture};

/// The corpus lives at the repository root, two levels above this crate.
fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(name)
}

fn report(name: &str) -> Report {
    let path = corpus(name);
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| panic!("{}: {e}. Run scripts/make-corpus.py first.", path.display()));
    let opts = AnalysisOptions::default();
    analyse_reader(Cursor::new(bytes), &opts, "corpus-test", &path.display().to_string())
        .expect("capture should analyse")
}

/// The first SA record that actually carries a suite, skipping records built
/// only from a refusal notification.
fn negotiated(r: &Report) -> &SaPosture {
    r.security_associations
        .iter()
        .find(|sa| sa.encryption.is_some())
        .unwrap_or_else(|| {
            panic!(
                "no SA carried a negotiated suite; SAs seen: {:?}",
                r.security_associations
                    .iter()
                    .map(|s| (&s.src, &s.dst, &s.encryption))
                    .collect::<Vec<_>>()
            )
        })
}

fn finding_ids(sa: &SaPosture) -> Vec<String> {
    sa.findings.iter().map(|f| f.finding.id.clone()).collect()
}

/// A Security Association that was offered a suite and refused: a suite-less
/// record with the refusal flag and the notification that caused it.
fn refused_sa() -> SaPosture {
    use vyuh_core::posture::{evaluate, SaPosture};
    let mut sa = SaPosture {
        sa_id: "0a0b0c0d0e0f1011".into(),
        src: "192.0.2.1".into(),
        dst: "192.0.2.2".into(),
        ike_version: "IKEv2".into(),
        exchanges_seen: vec!["IKE_SA_INIT".into()],
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
        negotiation_rejected: true,
        rejection_notifies: vec![14], // NO_PROPOSAL_CHOSEN
        first_packet: 1,
        suite_packet: 0,
        score: 100,
        grade: "A".into(),
        findings: Vec::new(),
        quantum_exposure: 0,
    };
    evaluate(&mut sa);
    sa
}

#[test]
fn t1_modern_matches_tcpdump() {
    // tcpdump: t#1 encr id=#20 keylen 0x0100, t#2 prf id=#5, t#3 dh id=#19.
    let r = report("vyuh-ikev2-modern.pcap");
    let sa = negotiated(&r);
    assert_eq!(sa.encryption.as_deref(), Some("ENCR_AES_GCM_16"));
    assert_eq!(sa.key_bits, Some(256));
    assert_eq!(sa.prf.as_deref(), Some("PRF_HMAC_SHA2_256"));
    assert_eq!(sa.key_exchange.as_deref(), Some("KE_ECDH_256"));
    assert_eq!(r.grade, "A");
}

#[test]
fn t2_weak_dh_matches_tcpdump() {
    // tcpdump: encr aes keylen 0x0080, integ hmac-sha, prf hmac-sha, dh modp1024.
    let r = report("vyuh-ikev2-weak-dh.pcap");
    let sa = negotiated(&r);
    assert_eq!(sa.encryption.as_deref(), Some("ENCR_AES_CBC"));
    assert_eq!(sa.key_bits, Some(128));
    assert_eq!(sa.integrity.as_deref(), Some("AUTH_HMAC_SHA1_96"));
    assert_eq!(sa.prf.as_deref(), Some("PRF_HMAC_SHA1"));
    assert_eq!(sa.key_exchange.as_deref(), Some("KE_DH_1024"));
    assert_eq!(r.grade, "F", "a 1024-bit group is MUST NOT, so the tunnel fails");

    let ids = finding_ids(sa);
    assert!(ids.contains(&"VYU-020".to_string()), "MODP-1024 must be critical");
}

#[test]
fn t4_x25519_matches_tcpdump() {
    // tcpdump: t#3 dh id=#31, v2ke group=#31. IANA registers 31 as Curve25519;
    // an earlier table read 31 as unassigned and 32 as X25519.
    let r = report("vyuh-ikev2-x25519.pcap");
    let sa = negotiated(&r);
    assert_eq!(sa.key_exchange.as_deref(), Some("KE_X25519"));
    assert_eq!(r.grade, "A");
}

#[test]
fn t5_legacy_integrity_matches_tcpdump() {
    // tcpdump: encr aes keylen 0x0080, integ hmac-sha, prf hmac-sha, dh modp2048.
    let r = report("vyuh-ikev2-legacy-integrity.pcap");
    let sa = negotiated(&r);
    assert_eq!(sa.integrity.as_deref(), Some("AUTH_HMAC_SHA1_96"));
    assert_eq!(sa.key_exchange.as_deref(), Some("KE_DH_2048"));
    let ids = finding_ids(sa);
    assert!(ids.contains(&"VYU-031".to_string()), "SHA-1 integrity is demoted");
    assert!(
        !ids.contains(&"VYU-020".to_string()),
        "MODP-2048 is acceptable, so it must not be reported as the 1024-bit failure"
    );
}

#[test]
fn t6_null_encryption_matches_tcpdump() {
    // tcpdump: encr id=null, integ hmac-md5, prf hmac-md5, dh modp1024.
    let r = report("vyuh-ikev2-null-encryption.pcap");
    let sa = negotiated(&r);
    assert_eq!(sa.encryption.as_deref(), Some("ENCR_NULL"));
    assert_eq!(sa.integrity.as_deref(), Some("AUTH_HMAC_MD5_96"));
    assert_eq!(sa.prf.as_deref(), Some("PRF_HMAC_MD5"));
    assert_eq!(sa.key_exchange.as_deref(), Some("KE_DH_1024"));

    let ids = finding_ids(sa);
    assert!(ids.contains(&"VYU-010".to_string()), "NULL encryption is critical");
    assert_eq!(r.grade, "F");
    assert_eq!(r.posture_score, 0);
}

#[test]
fn t3_ikev1_aggressive_matches_tcpdump() {
    // tcpdump -nvv on the capture: phase 1 I agg, one transform, id=ike,
    // enc 3des, hash sha1, group modp1024, auth rsa sig. The suite lives in
    // the transform attributes, not the transform id.
    let r = report("vyuh-ikev1-aggressive-3des.pcap");
    let sa = negotiated(&r);
    assert_eq!(sa.ike_version, "IKEv1");
    assert!(sa.aggressive_mode);
    assert_eq!(sa.encryption.as_deref(), Some("3DES"));
    assert_eq!(sa.integrity.as_deref(), Some("SHA1"));
    assert_eq!(sa.key_exchange.as_deref(), Some("MODP-1024"));
    assert!(!sa.identities_in_clear.is_empty(), "the identity leak is the point");

    let ids = finding_ids(sa);
    assert!(ids.contains(&"VYU-002".to_string()), "aggressive mode is critical");
    assert!(ids.contains(&"VYU-011".to_string()), "3DES is flagged");
    assert!(ids.contains(&"VYU-020".to_string()), "MODP-1024 is critical");
    assert_eq!(r.grade, "F");
}

/// Count the ESP packets tcpdump reports in a capture.
///
/// The ground truth has to come from the independent tool, not from a constant
/// someone wrote down once. The corpus is regenerated regularly and the number
/// moves; a pinned figure would need editing on every run.
fn tcpdump_esp_packets(name: &str) -> u64 {
    let out = std::process::Command::new("tcpdump")
        .args(["-r", &corpus(name).to_string_lossy()])
        .output()
        .expect("tcpdump must be installed; the ground truth depends on it");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().filter(|l| l.contains("ESP") || l.contains("esp")).count() as u64
}

#[test]
fn esp_packets_group_into_sa_count_flows_not_one_each() {
    // Regression. tcpdump reports the same ESP packet total as the analyser
    // does, and the flows group into one Security Association per direction
    // plus a couple of short ones from the two encapsulation forms.
    //
    // The analyser used to read the ESP header at a fixed offset on UDP 4500
    // and landed on the sequence number, so every four packets acquired a fresh
    // "SPI" of 00000001, 00000002, ... and one real association was reported as
    // a hundred and forty separate flows. The packet total was right
    // throughout, which is what made it easy to miss: only the grouping was
    // wrong, and the count of flows is exactly the number an operator would
    // quote.
    let r = report("vyuh-ikev2-modern.pcap");
    let flows = &r.flow_records;
    assert!(!flows.is_empty(), "a tunnel with data has flows");

    // Cross-checked against tcpdump rather than hardcoded, because the corpus is
    // regenerated and the count moves with it. A pinned constant here would
    // either fail on every regeneration or invite someone to relax it.
    let tcpdump_total = tcpdump_esp_packets("vyuh-ikev2-modern.pcap");
    let esp_packets: u64 = flows.iter().map(|f| f.packet_count).sum();
    assert_eq!(
        esp_packets, tcpdump_total,
        "every ESP packet tcpdump sees must land in exactly one flow"
    );
    assert!(
        flows.len() <= 6,
        "one SA per direction means a handful of flows, got {}",
        flows.len()
    );
    for f in flows {
        assert_ne!(
            f.spi, "00000000",
            "a zero SPI is a reserved value and means a misaligned read"
        );
        assert!(
            f.packet_count > 4,
            "a four-packet flow is the symptom this test exists to catch"
        );
    }
}

#[test]
fn repeated_handshakes_do_not_inflate_the_finding_count() {
    // The IKEv1 association is retried with fresh cookies and never settles,
    // so the capture repeats one proposal. Four distinct facts must not become
    // hundreds of ledger entries.
    let r = report("vyuh-ikev1-aggressive-3des.pcap");
    assert!(r.ike_messages > 30, "the capture is a retry by design");
    assert!(
        r.global_findings.len() <= 16,
        "expected a handful of distinct findings, got {}",
        r.global_findings.len()
    );
    assert!(r
        .global_findings
        .iter()
        .any(|f| f.occurrences > 1),
        "occurrences should record how many exchanges showed the fact");
}

#[test]
fn every_finding_cites_a_real_packet() {
    for name in [
        "vyuh-ikev2-modern.pcap",
        "vyuh-ikev2-weak-dh.pcap",
        "vyuh-ikev2-x25519.pcap",
        "vyuh-ikev2-legacy-integrity.pcap",
        "vyuh-ikev2-null-encryption.pcap",
        "vyuh-ikev1-aggressive-3des.pcap",
    ] {
        let r = report(name);
        assert!(r.packets_examined > 0, "{name} read no packets");
        for f in &r.global_findings {
            assert!(
                f.finding.packet_index >= 1 && f.finding.packet_index <= r.packets_examined,
                "{name}: {} cites packet {} but the capture holds {} packets",
                f.finding.id,
                f.finding.packet_index,
                r.packets_examined
            );
        }
    }
}

#[test]
fn a_refused_negotiation_that_recovers_is_not_reported_as_a_failure() {
    // Every IKEv2 tunnel here is refused once and then re-negotiated, so each
    // SA both records a refusal and ends up with a suite. The tunnel exists, so
    // it must not be graded on the aborted attempt.
    let mut saw_refusal = false;
    for name in [
        "vyuh-ikev2-weak-dh.pcap",
        "vyuh-ikev2-x25519.pcap",
        "vyuh-ikev2-legacy-integrity.pcap",
        "vyuh-ikev2-null-encryption.pcap",
    ] {
        for sa in report(name).security_associations.iter() {
            if sa.negotiation_rejected {
                saw_refusal = true;
                assert!(
                    sa.encryption.is_some(),
                    "{name}: a refusal that was retried into success must carry the suite"
                );
                assert!(
                    !finding_ids(sa).contains(&"VYU-003".to_string()),
                    "{name}: a recovered negotiation must not be reported as refused"
                );
            }
        }
    }
    assert!(saw_refusal, "these captures contain refused attempts");
}

#[test]
fn an_unestablished_sa_is_reported_rather_than_scored_clean() {
    // A request proposes a suite, and the response answers with only a
    // notification. There is no suite to grade, so the record must say so
    // rather than inherit a perfect score.
    let sa = refused_sa();
    let ids = finding_ids(&sa);
    assert!(
        ids.contains(&"VYU-003".to_string()),
        "an unestablished SA must be reported, got {ids:?}"
    );
    assert_ne!(sa.grade, "A", "an unestablished tunnel must not read as a pass");
    assert_eq!(sa.grade, "F");
    assert_eq!(sa.quantum_exposure, 80, "no key exchange means unknown exposure");
}

#[test]
fn a_refused_sa_records_the_notification_that_refused_it() {
    // The remediation text tells an operator to read the notify type, so the
    // type has to survive into the report.
    let sa = refused_sa();
    let f = sa
        .findings
        .iter()
        .find(|f| f.finding.id == "VYU-003")
        .expect("VYU-003");
    assert!(
        f.finding.detail.contains("0x") || f.finding.detail.contains("unidentified"),
        "the finding should carry the observed notification type: {}",
        f.finding.detail
    );
    assert_eq!(f.finding.cwe.is_some(), true, "a refused negotiation has a CWE");
}

#[test]
fn a_capture_with_no_ike_explains_itself() {
    // Every finding needs a suite behind it, so an empty capture must produce a
    // blindspot rather than a clean report.
    let opts = AnalysisOptions::default();
    // A valid classic-pcap global header and no records: 4 octets of magic,
    // 2 each of version, 4 each of zone, timestamp resolution and snaplen, and
    // 4 of link type. A header-only file is a real, empty capture.
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    pcap.extend_from_slice(&2u16.to_le_bytes()); // version major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // version minor
    pcap.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
    let r = analyse_reader(Cursor::new(pcap), &opts, "empty", "empty.pcap").unwrap();
    assert_eq!(r.ike_messages, 0);
    assert!(r
        .blindspots
        .iter()
        .any(|b| b.contains("No IKE message")));
}

#[test]
fn the_six_captures_rank_the_way_the_rfc_requirements_predict() {
    // The engine's credibility rests on this: a modern tunnel must score better
    // than a broken one, using the same code path, with no capture-specific
    // tuning. If the ordering ever inverts, either the registry or the scoring
    // has drifted.
    let r = report("vyuh-ikev1-aggressive-3des.pcap");
    assert_eq!(r.posture_score, 0, "IKEv1 aggressive + 3DES + MD5 + MODP-1024 is the worst case");

    let null = report("vyuh-ikev2-null-encryption.pcap");
    assert_eq!(null.posture_score, 0, "NULL encryption MUST NOT means no score");

    let weak = report("vyuh-ikev2-weak-dh.pcap");
    assert!(
        (35..60).contains(&weak.posture_score),
        "MODP-1024 caps the grade at F, got {}",
        weak.posture_score
    );

    let legacy = report("vyuh-ikev2-legacy-integrity.pcap");
    assert!(
        (80..95).contains(&legacy.posture_score),
        "SHA-1 is only a demotion, so the tunnel stays in the B range, got {}",
        legacy.posture_score
    );

    let modern = report("vyuh-ikev2-modern.pcap");
    let x25519 = report("vyuh-ikev2-x25519.pcap");
    assert!(modern.posture_score >= 95, "a modern tunnel must score high");
    assert!(x25519.posture_score >= 95, "X25519 must not be penalised");

    // The strict ordering, weakest first.
    let scores = [
        null.posture_score,
        weak.posture_score,
        legacy.posture_score,
        modern.posture_score,
        x25519.posture_score,
    ];
    for w in scores.windows(2) {
        assert!(w[0] <= w[1], "scores must be non-decreasing in strength: {scores:?}");
    }
}

#[test]
fn harvest_now_decrypt_later_exposure_ranks_by_key_exchange() {
    // KalScore is the quantum claim. It must order by the key exchange family
    // and nothing else, or the number is marketing.
    let cases = [
        ("vyuh-ikev2-modern.pcap", "KE_ECDH_256"),
        ("vyuh-ikev2-x25519.pcap", "KE_X25519"),
        ("vyuh-ikev1-aggressive-3des.pcap", "MODP-1024"),
        ("vyuh-ikev2-weak-dh.pcap", "KE_DH_1024"),
    ];
    let mut out = Vec::new();
    for (name, ke) in cases {
        let r = report(name);
        let sa = negotiated(&r);
        assert_eq!(sa.key_exchange.as_deref(), Some(ke));
        out.push((ke, sa.quantum_exposure));
    }
    let by_name = |n: &str| out.iter().find(|(k, _)| *k == n).unwrap().1;
    assert!(
        by_name("KE_ECDH_256") == by_name("KE_X25519"),
        "P-256 and X25519 are the same strength, so the number must not depend on which one the peer chose"
    );
    assert!(
        by_name("KE_ECDH_256") < by_name("KE_DH_1024"),
        "an elliptic curve must score below a 1024-bit MODP group"
    );
    assert!(
        by_name("KE_DH_1024") == by_name("MODP-1024"),
        "IKEv1 and IKEv2 names for the same group must score identically, got {} and {}",
        by_name("KE_DH_1024"),
        by_name("MODP-1024")
    );
    assert!(by_name("KE_ECDH_256") < 60, "a modern classical group still has HNDL exposure");
    assert!(by_name("KE_DH_1024") >= 90, "a 1024-bit group is close to fully exposed");
}

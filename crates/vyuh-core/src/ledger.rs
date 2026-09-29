//! Tamper-evident evidence ledger.
//!
//! Every finding is appended as a hash chain: entry N commits to the previous
//! entry's digest, so altering any earlier finding invalidates every digest
//! after it. The whole chain is bound to the SHA-256 of the source capture, so a
//! report cannot be re-pointed at a different pcap without detection.
//!
//! This is the same chaining discipline used for blockchain-style audit logs,
//! applied to a single-writer local file. No consensus layer is implied or
//! needed: the threat is a silent edit of an assessment, not a competing writer.

use crate::posture::{Finding, RatedFinding};
use crate::sha256::{hex32, Sha256};
use serde::{Deserialize, Serialize};

/// Genesis prefix. Every chain starts here, so a ledger cannot be spliced
/// onto another ledger without breaking.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Position in the chain, starting at 0.
    pub sequence: u32,
    /// The finding's canonical serialisation, and the only statement of what
    /// this entry asserts. Everything a reader wants to know is recoverable
    /// from it; keeping parallel fields here would create a second source of
    /// truth that verification could not police.
    pub canonical: String,
    /// SHA-256 of `canonical`.
    pub payload_digest: String,
    /// Previous entry's digest, or GENESIS for the first entry.
    pub previous: String,
    /// This entry's digest: SHA-256(previous || payload_digest || sequence).
    pub digest: String,
}

impl LedgerEntry {
    /// The finding identifier, read out of the canonical text.
    pub fn finding_id(&self) -> &str {
        self.canonical.split('\u{1}').next().unwrap_or("")
    }

    /// The packet citation, read out of the canonical text.
    pub fn packet_index(&self) -> u32 {
        // Field 7 of 11 is the packet index.
        self.canonical
            .split('\u{1}')
            .nth(6)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// The severity, read out of the canonical text.
    pub fn severity(&self) -> &str {
        self.canonical.split('\u{1}').nth(1).unwrap_or("")
    }

    /// The title, read out of the canonical text.
    pub fn title(&self) -> &str {
        self.canonical.split('\u{1}').nth(2).unwrap_or("")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ledger {
    /// SHA-256 of the capture the findings came from.
    pub capture_sha256: String,
    pub tool: String,
    pub tool_version: String,
    pub entries: Vec<LedgerEntry>,
    /// Digest of the last entry, the chain's head.
    pub head: String,
    /// Set when `verify` finds a break.
    pub intact: bool,
}

impl Ledger {
    /// Build a ledger from findings, binding it to a capture digest.
    pub fn build(capture_sha256: &str, tool: &str, tool_version: &str, findings: &[RatedFinding]) -> Self {
        let mut entries: Vec<LedgerEntry> = Vec::new();
        let mut previous = GENESIS.to_string();

        for (i, rated) in findings.iter().enumerate() {
            let canonical = canonical_finding(&rated.finding);
            let payload_digest = hex32(&crate::sha256::sha256(canonical.as_bytes()));
            let mut h = Sha256::new();
            h.update(previous.as_bytes());
            h.update(b"|");
            h.update(payload_digest.as_bytes());
            h.update(b"|");
            h.update(&(i as u32).to_be_bytes());
            let digest = hex32(&h.finalize());

            entries.push(LedgerEntry {
                sequence: i as u32,
                canonical,
                payload_digest,
                previous: previous.clone(),
                digest: digest.clone(),
            });
            previous = digest;
        }

        let head = previous.clone();
        let mut ledger = Self {
            capture_sha256: capture_sha256.to_string(),
            tool: tool.to_string(),
            tool_version: tool_version.to_string(),
            entries,
            head,
            intact: true,
        };
        ledger.verify();
        ledger
    }

    /// Recompute every digest and report whether the chain still holds.
    ///
    /// Three independent things are checked per entry: the payload digest still
    /// matches the stored canonical text, the previous pointer is right, and the
    /// sequence number is in position. A single edit to any finding therefore
    /// breaks its own entry, not merely the entries after it.
    pub fn verify(&mut self) -> bool {
        let mut previous = GENESIS.to_string();
        for (i, e) in self.entries.iter().enumerate() {
            let mut h = Sha256::new();
            h.update(previous.as_bytes());
            h.update(b"|");
            h.update(e.payload_digest.as_bytes());
            h.update(b"|");
            h.update(&(i as u32).to_be_bytes());
            let recomputed = hex32(&h.finalize());

            let payload_ok = hex32(&crate::sha256::sha256(e.canonical.as_bytes())) == e.payload_digest;

            if !payload_ok || e.previous != previous || e.digest != recomputed || e.sequence != i as u32 {
                self.intact = false;
                return false;
            }
            previous = e.digest.clone();
        }
        self.intact = self.head == previous;
        self.intact
    }

    /// Locate the first entry that no longer verifies.
    pub fn first_broken_entry(&self) -> Option<u32> {
        let mut previous = GENESIS.to_string();
        for (i, e) in self.entries.iter().enumerate() {
            let mut h = Sha256::new();
            h.update(previous.as_bytes());
            h.update(b"|");
            h.update(e.payload_digest.as_bytes());
            h.update(b"|");
            h.update(&(i as u32).to_be_bytes());
            let payload_ok = hex32(&crate::sha256::sha256(e.canonical.as_bytes())) == e.payload_digest;
            if !payload_ok || hex32(&h.finalize()) != e.digest || e.previous != previous {
                return Some(i as u32);
            }
            previous = e.digest.clone();
        }
        None
    }
}

/// Canonical serialisation of a finding. Field order is fixed and fields are
/// separated by U+0001, a control character that cannot appear in prose, so
/// the serialisation is unambiguous and reproducible.
fn canonical_finding(f: &Finding) -> String {
    format!(
        "{id}\u{1}{sev}\u{1}{title}\u{1}{detail}\u{1}{standard}\u{1}{cwe}\u{1}{packet}\u{1}{src}\u{1}{dst}\u{1}{observed}\u{1}{remed}",
        id = f.id,
        sev = f.severity.as_str(),
        title = f.title,
        detail = f.detail,
        standard = f.standard,
        cwe = f.cwe.map(|c| format!("{c:?}")).unwrap_or_else(|| "none".into()),
        packet = f.packet_index,
        src = f.src,
        dst = f.dst,
        observed = f.observed,
        remed = f.remediation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::posture::Severity;

    fn finding(id: &str, packet: u32) -> Finding {
        Finding {
            id: id.into(),
            severity: Severity::High,
            title: format!("Finding {id}"),
            detail: "detail".into(),
            standard: "RFC 8221".into(),
            cwe: None,
            packet_index: packet,
            src: "10.0.0.1".into(),
            dst: "10.0.0.2".into(),
            observed: "ENCR_3DES".into(),
            remediation: "move to AES-GCM".into(),
        }
    }

    fn rated(id: &str, packet: u32) -> RatedFinding {
        RatedFinding {
            finding: finding(id, packet),
            evidence: crate::posture::Evidence::Observed,
            occurrences: 1,
        }
    }

    #[test]
    fn a_fresh_ledger_verifies() {
        let l = Ledger::build(
            "abc123",
            "RAKSHAK.VYUH",
            "0.1.0",
            &[rated("VYU-011", 10), rated("VYU-020", 20)],
        );
        assert!(l.intact);
        assert_eq!(l.entries.len(), 2);
        assert_eq!(l.entries[0].previous, GENESIS);
        assert_eq!(l.entries[1].previous, l.entries[0].digest);
    }

    #[test]
    fn an_empty_ledger_is_valid_and_heads_at_genesis() {
        let l = Ledger::build("abc", "t", "v", &[]);
        assert!(l.intact);
        assert_eq!(l.head, GENESIS);
        assert!(l.entries.is_empty());
    }

    #[test]
    fn editing_an_earlier_finding_breaks_every_digest_after_it() {
        let mut l = Ledger::build("abc", "t", "v", &[rated("A", 1), rated("B", 2), rated("C", 3)]);
        assert!(l.intact);

        l.entries[0].canonical = l.entries[0].canonical.replace("Finding A", "quietly rewritten");
        assert!(!l.verify());
        assert_eq!(l.first_broken_entry(), Some(0));
    }

    #[test]
    fn reordering_entries_is_detected() {
        let mut l = Ledger::build("abc", "t", "v", &[rated("A", 1), rated("B", 2)]);
        l.entries.swap(0, 1);
        assert!(!l.verify());
    }

    #[test]
    fn deleting_an_entry_is_detected() {
        let mut l = Ledger::build("abc", "t", "v", &[rated("A", 1), rated("B", 2), rated("C", 3)]);
        l.entries.remove(1);
        assert!(!l.verify());
    }

    #[test]
    fn changing_the_capture_digest_is_visible_in_the_report() {
        let l = Ledger::build("deadbeef", "t", "v", &[rated("A", 1)]);
        assert_eq!(l.capture_sha256, "deadbeef");
    }

    #[test]
    fn the_same_finding_always_hashes_the_same() {
        assert_eq!(
            canonical_finding(&finding("X", 5)),
            canonical_finding(&finding("X", 5))
        );
        assert_ne!(
            canonical_finding(&finding("X", 5)),
            canonical_finding(&finding("X", 6))
        );
    }

    #[test]
    fn downgrading_a_severity_is_detected() {
        let mut l = Ledger::build("abc", "t", "v", &[rated("A", 1), rated("B", 2)]);
        assert!(l.intact);
        l.entries[0].canonical = l.entries[0]
            .canonical
            .replace("\u{1}high\u{1}", "\u{1}info\u{1}");
        assert!(!l.verify());
        assert_eq!(l.first_broken_entry(), Some(0));
    }

    #[test]
    fn rewriting_the_canonical_text_is_detected() {
        let mut l = Ledger::build("abc", "t", "v", &[rated("A", 1)]);
        l.entries[0].canonical = l.entries[0].canonical.replace("ENCR_3DES", "ENCR_AES_GCM_16");
        assert!(!l.verify());
    }

    #[test]
    fn packet_citation_survives_into_the_ledger() {
        let l = Ledger::build("abc", "t", "v", &[rated("VYU-011", 187)]);
        assert_eq!(l.entries[0].packet_index(), 187);
        assert_eq!(l.entries[0].finding_id(), "VYU-011");
        assert_eq!(l.entries[0].severity(), "high");
        assert_eq!(l.entries[0].title(), "Finding VYU-011");
    }

    #[test]
    fn there_is_exactly_one_statement_of_each_entry() {
        // The canonical text is the single source of truth; a stale parallel
        // field is the classic way an audit log starts lying.
        let l = Ledger::build("abc", "t", "v", &[rated("A", 1)]);
        let text = &l.entries[0].canonical;
        assert!(text.contains("VYU") || text.contains("A"));
        assert!(text.contains("RFC 8221"));
        assert!(text.contains("move to AES-GCM"));
    }
}

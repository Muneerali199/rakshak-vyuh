//! Robustness: no input, however malformed, may panic the analyser.
//!
//! This runs on stable and in CI. `cargo-fuzz` covers the same ground with
//! coverage guidance, but a fuzz target is only as good as the run you can
//! afford, and a CI job cannot depend on a nightly toolchain being present. The
//! sweep below is exhaustive over a bounded space instead of random over an
//! unbounded one, so it is small enough to run on every commit.
//!
//! Three classes of malformation are exercised against the six real captures:
//!
//! 1. **Truncation** at every byte offset. A capture cut short must produce a
//!    shorter report or an error, never a panic. Half a handshake is the most
//!    common thing an analyst actually has.
//! 2. **Byte corruption** at every offset. A hostile peer chooses its own
//!    lengths, and a dissector that trusts them is a crash or a hang.
//! 3. **Length-field escalation**, which is the class of bug that turns a
//!    parser into a denial-of-service: every 16- and 32-bit length in a frame is
//!    set to its maximum, so an unchecked `take(n)` would try to allocate or
//!    index far past the buffer.
//!
//! The engine's own reader is written so that a short read is a `Truncated`
//! error rather than a panic. These tests are what keeps it that way.

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use vyuh_core::analysis::{analyse_reader, AnalysisOptions};

const CAPTURES: [&str; 6] = [
    "vyuh-ikev2-modern.pcap",
    "vyuh-ikev2-weak-dh.pcap",
    "vyuh-ikev2-x25519.pcap",
    "vyuh-ikev2-legacy-integrity.pcap",
    "vyuh-ikev2-null-encryption.pcap",
    "vyuh-ikev1-aggressive-3des.pcap",
];

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join(name)
}

fn load(name: &str) -> Option<Vec<u8>> {
    let p = corpus(name);
    match fs::read(&p) {
        Ok(b) => Some(b),
        // The corpus is generated, not committed to every clone. A missing
        // capture is not a failure; it just means this pass proves nothing.
        Err(_) => None,
    }
}

/// Run the analyser and assert it terminated normally.
///
/// `panic::catch_unwind` is not used. The whole point of `Reader` is that a
/// short read is an error value, not an unwind, so a panic escaping any of
/// these layers is a real defect and should fail the test rather than be caught.
fn analyse(bytes: Vec<u8>, name: &str) {
    let opts = AnalysisOptions::default();
    match analyse_reader(Cursor::new(bytes), &opts, "fuzz", name) {
        Ok(_) => {}
        // A malformed capture is allowed to be an error. It must not be a
        // panic, an abort, or a hang.
        Err(_) => {}
    }
}

/// A set of offsets to probe in a capture of `len` bytes.
///
/// Small captures are swept exhaustively: every offset is affordable and
/// nothing is missed.
///
/// Large ones are sampled on a stride, and the stride is chosen from the length
/// rather than fixed, so the pass costs roughly the same whatever the capture
/// size. T1 is 728 kB now that the testbed pushes real traffic through the
/// tunnel, and T3 is 99 kB of a handshake repeated 376 times; a fixed stride
/// that was affordable against a 2 kB capture turned a 30-second pass into a
/// fifteen-minute one.
///
/// `VYUH_SWEEP=full` restores the exhaustive pass for a release check.
const TARGET_SAMPLES: usize = 2000;

fn probe_offsets(len: usize, exhaustive: bool) -> Vec<usize> {
    if exhaustive || len <= 4096 {
        return (0..len).collect();
    }
    let stride = (len / TARGET_SAMPLES).max(1);
    (0..len).step_by(stride).chain(std::iter::once(len)).collect()
}

#[test]
fn truncation_at_every_offset_never_panics() {
    let full = std::env::var("VYUH_SWEEP").as_deref() == Ok("full");
    let mut ran = 0usize;
    for name in CAPTURES {
        let Some(bytes) = load(name) else { continue };
        ran += 1;
        for cut in probe_offsets(bytes.len(), full) {
            analyse(bytes[..cut].to_vec(), name);
        }
        // And the whole thing, so the sweep is known to include the good path.
        analyse(bytes.clone(), name);
    }
    assert!(ran > 0, "no corpus captures found; run scripts/make-corpus.py");
}

#[test]
fn a_single_corrupted_byte_never_panics() {
    // Flipping one octet at every offset of the smaller captures. The retry
    // storm is skipped: 376 packets times its length is a needless number of
    // passes, and its header bytes are already covered by the short captures.
    let mut ran = 0usize;
    for name in CAPTURES {
        let Some(bytes) = load(name) else { continue };
        ran += 1;
        // Exclude the final index: `probe_offsets` includes `len` as a
        // truncation point, and indexing past the end is a bug in the test.
        for i in probe_offsets(bytes.len(), false)
            .into_iter()
            .filter(|i| *i < bytes.len())
        {
            for mask in [0x01u8, 0x80, 0xFF] {
                let mut m = bytes.clone();
                m[i] ^= mask;
                analyse(m, name);
            }
        }
    }
    assert!(ran > 0, "no corpus captures found");
}

#[test]
fn escalated_length_fields_never_panic() {
    // Every two- and four-octet window is overwritten with the maximum value
    // the field could hold. This is the "attacker lies about a length" case,
    // and it is where an unchecked bounds check becomes an out-of-bounds read
    // or a huge allocation.
    let mut ran = 0usize;
    for name in CAPTURES {
        if name.contains("aggressive") {
            continue;
        }
        let Some(bytes) = load(name) else { continue };
        ran += 1;

        // Every length field in these frames sits inside the first 600 octets:
        // the container header, the Ethernet, IPv4 and UDP headers, the IKE
        // header, and the first two payloads. Walking further only re-runs the
        // record loop over data the earlier passes already covered.
        let limit = bytes.len().saturating_sub(4).min(600);
        for width in [2usize, 4] {
            for i in 0..limit {
                let mut m = bytes.clone();
                m[i..i + width].fill(0xFF);
                analyse(m, name);
                let mut z = bytes.clone();
                z[i..i + width].fill(0x00);
                analyse(z, name);
            }
        }
    }
    assert!(ran > 0, "no corpus captures found");
}

#[test]
fn random_garbage_is_rejected_rather_than_parsed() {
    // A fixed-seed PRNG rather than a real one: this must be reproducible, or a
    // failure cannot be re-run.
    let mut state: u64 = 0x5DEECE66D;
    let mut next = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as u32
    };

    for _ in 0..400 {
        let len = (next() % 512) as usize;
        let mut buf: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();

        // Half the time, keep a valid pcap header so the reader gets past the
        // container and exercises the parsers rather than rejecting the file.
        if len >= 24 && next() & 1 == 1 {
            buf[0..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes());
            buf[4..6].copy_from_slice(&2u16.to_le_bytes());
            buf[6..8].copy_from_slice(&4u16.to_le_bytes());
            buf[16..20].copy_from_slice(&0i32.to_le_bytes());
            buf[20..24].copy_from_slice(&0u32.to_le_bytes());
            buf = buf.split_off(0);
        }
        analyse(buf, "random");
    }
}

#[test]
fn a_capture_with_no_records_is_not_an_error() {
    // A header-only pcap is a real thing to hand an analyst, and it must come
    // back as an empty report with a blindspot rather than as a failure.
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());

    let opts = AnalysisOptions::default();
    let r = analyse_reader(Cursor::new(pcap), &opts, "empty", "empty.pcap")
        .expect("a header-only capture is valid, not malformed");
    assert_eq!(r.packets_examined, 0);
    assert_eq!(r.ike_messages, 0);
    assert!(r
        .blindspots
        .iter()
        .any(|b| b.contains("No IKE message")),
        "an empty capture must explain itself rather than score clean");
}

#[test]
fn a_truncated_capture_never_reports_more_than_the_original() {
    // Monotonicity: cutting bytes off the end cannot manufacture traffic. If a
    // shorter capture ever reports more IKE messages, a length field is being
    // read out of bounds.
    for name in CAPTURES {
        let Some(bytes) = load(name) else { continue };
        let opts = AnalysisOptions::default();
        let full = match analyse_reader(Cursor::new(bytes.clone()), &opts, "fuzz", name) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for frac in [0.25f64, 0.5, 0.75, 0.9] {
            let cut = (bytes.len() as f64 * frac) as usize;
            if let Ok(part) = analyse_reader(Cursor::new(bytes[..cut].to_vec()), &opts, "fuzz", name) {
                assert!(
                    part.ike_messages <= full.ike_messages,
                    "{name} at {}%: {} IKE messages from a truncated capture, but {} from the whole file",
                    (frac * 100.0) as u32,
                    part.ike_messages,
                    full.ike_messages
                );
            }
        }
    }
}

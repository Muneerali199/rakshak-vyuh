//! RAKSHAK.VYUH core engine.
//!
//! A passive IPsec posture analyser. It reads IKE handshakes and ESP headers
//! from packet captures and produces evidence-cited security findings. It never
//! decrypts a payload, never sends a packet, and never contacts the network.
//!
//! ```
//! use vyuh_core::{analyse_reader, AnalysisOptions};
//!
//! // A valid but empty libpcap container: magic, version, snaplen, linktype.
//! let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
//! bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
//! bytes.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF, 1, 0, 0, 0]);
//!
//! let report = analyse_reader(
//!     std::io::Cursor::new(bytes),
//!     &AnalysisOptions::default(),
//!     "digest",
//!     "example.pcap",
//! )
//! .unwrap();
//!
//! assert_eq!(report.tool, "RAKSHAK.VYUH");
//! assert_eq!(report.ike_messages, 0);
//! ```

pub mod analysis;
pub mod cbom;
pub mod esp;
pub mod error;
pub mod html;
pub mod ike;
pub mod ledger;
pub mod pcap;
pub mod posture;
pub mod reader;
pub mod remediation;
pub mod registry;
pub mod sha256;

pub use analysis::{analyse_file, analyse_reader, AnalysisOptions, SaDetail, BLINDSPOTS};
pub use cbom::to_cyclonedx;
pub use remediation::remediate;
pub use error::{Result, VyuhError};
pub use ledger::{Ledger, LedgerEntry};
pub use posture::{Cwe, Evidence, Finding, RatedFinding, Report, SaPosture, Severity};

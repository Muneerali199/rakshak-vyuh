//! Error types for the VYUH core engine.

use std::fmt;

/// Every fallible operation in the engine returns this. We never panic on
/// untrusted input: a malformed packet produces a `Parse` error that carries
/// the offset so the caller can cite the exact byte that broke the parse.
#[derive(Debug)]
pub enum VyuhError {
    /// The underlying byte stream ended before the structure was complete.
    Truncated { need: usize, have: usize, offset: usize },
    /// A field held a value outside the range the specification allows.
    InvalidField { field: &'static str, value: u64, offset: usize },
    /// The pcap container itself could not be understood.
    Pcap(String),
    /// A link-layer frame could not be decoded.
    LinkLayer(String),
    /// Nothing usable was found in the capture.
    EmptyCapture,
    Io(std::io::Error),
}

impl fmt::Display for VyuhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { need, have, offset } => write!(
                f,
                "truncated at offset {offset}: needed {need} bytes, had {have}"
            ),
            Self::InvalidField { field, value, offset } => {
                write!(f, "invalid {field} value {value} at offset {offset}")
            }
            Self::Pcap(m) => write!(f, "pcap error: {m}"),
            Self::LinkLayer(m) => write!(f, "link-layer error: {m}"),
            Self::EmptyCapture => write!(f, "capture contains no packets"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for VyuhError {}

impl From<std::io::Error> for VyuhError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<VyuhError> for std::io::Error {
    fn from(e: VyuhError) -> Self {
        match e {
            VyuhError::Io(inner) => inner,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, VyuhError>;

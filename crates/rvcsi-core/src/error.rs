//! Error type for the rvCSI runtime.

use thiserror::Error;

use crate::validation::ValidationError;

/// Errors surfaced by the rvCSI core, adapters, DSP and event pipeline.
///
/// Parser failures are structured (never panics, never raw pointers across
/// boundaries — ADR-095 D6). A `Validation` error means a frame was *rejected*;
/// a *degraded* frame is not an error and is returned normally with reduced
/// `quality_score`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RvcsiError {
    /// A source/adapter could not be opened or talked to.
    #[error("adapter '{kind}' failed: {message}")]
    Adapter {
        /// The adapter kind (`"file"`, `"nexmon"`, `"esp32"`, ...).
        kind: String,
        /// Human-readable detail.
        message: String,
    },

    /// A raw byte buffer could not be parsed into a frame.
    #[error("parse error at offset {offset}: {message}")]
    Parse {
        /// Byte offset where parsing failed (best effort).
        offset: usize,
        /// Human-readable detail.
        message: String,
    },

    /// A frame failed validation and was rejected.
    #[error("frame rejected: {0}")]
    Validation(#[from] ValidationError),

    /// A configuration value was out of range or inconsistent.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// An I/O error (file capture, replay, WebSocket, ...).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization / deserialization error (JSON capture sidecars, RuVector export).
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),

    /// The requested operation is not supported by this source/adapter.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl RvcsiError {
    /// Convenience constructor for adapter errors.
    pub fn adapter(kind: impl Into<String>, message: impl Into<String>) -> Self {
        RvcsiError::Adapter {
            kind: kind.into(),
            message: message.into(),
        }
    }

    /// Convenience constructor for parse errors.
    pub fn parse(offset: usize, message: impl Into<String>) -> Self {
        RvcsiError::Parse {
            offset,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_useful() {
        let e = RvcsiError::adapter("nexmon", "device /dev/wlan0 not in monitor mode");
        assert!(e.to_string().contains("nexmon"));
        assert!(e.to_string().contains("monitor mode"));

        let e = RvcsiError::parse(12, "frame length 0");
        assert!(e.to_string().contains("offset 12"));
    }
}

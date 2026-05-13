//! The `.rvcsi` capture container format (ADR-095 FR1/FR10, D9).
//!
//! A `.rvcsi` file is plain [JSONL]: the **first line** is a
//! [`CaptureHeader`] object describing the session; every **subsequent line**
//! is one [`rvcsi_core::CsiFrame`] serialized as JSON. This keeps the format
//! simple, deterministic, append-friendly and trivially debuggable with `head`
//! / `jq`.
//!
//! [JSONL]: https://jsonlines.org/

use rvcsi_core::{AdapterProfile, SessionId, SourceId, ValidationPolicy};
use serde::{Deserialize, Serialize};

/// Current `.rvcsi` capture format version. Written into every header and
/// checked on read.
pub const CAPTURE_VERSION: u32 = 1;

/// Header object — the first line of every `.rvcsi` capture file.
///
/// It records enough context to replay the session faithfully: the originating
/// session/source ids, the source's [`AdapterProfile`], the
/// [`ValidationPolicy`] that was in force, the calibration version (if any),
/// and an opaque `runtime_config_json` blob the caller may use for whatever it
/// likes (defaults to `"{}"`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureHeader {
    /// Capture format version (always [`CAPTURE_VERSION`] when written).
    pub rvcsi_capture_version: u32,
    /// Session this capture belongs to.
    pub session_id: SessionId,
    /// Source the frames were captured from.
    pub source_id: SourceId,
    /// Capability descriptor of the source at capture time.
    pub adapter_profile: AdapterProfile,
    /// Validation policy that was in force during capture.
    pub validation_policy: ValidationPolicy,
    /// Calibration version frames were processed against, if any.
    pub calibration_version: Option<String>,
    /// Opaque caller-supplied runtime config (JSON; default `"{}"`).
    pub runtime_config_json: String,
    /// Wall-clock creation time, nanoseconds since the Unix epoch (`0` if unknown).
    pub created_unix_ns: u64,
}

impl CaptureHeader {
    /// Build a header for `session_id` / `source_id` / `adapter_profile` with
    /// sensible defaults: version [`CAPTURE_VERSION`], [`ValidationPolicy::default`],
    /// no calibration version, `runtime_config_json == "{}"`, and
    /// `created_unix_ns` taken from the system clock (or `0` if it is unavailable
    /// or before the epoch).
    pub fn new(session_id: SessionId, source_id: SourceId, adapter_profile: AdapterProfile) -> Self {
        CaptureHeader {
            rvcsi_capture_version: CAPTURE_VERSION,
            session_id,
            source_id,
            adapter_profile,
            validation_policy: ValidationPolicy::default(),
            calibration_version: None,
            runtime_config_json: "{}".to_string(),
            created_unix_ns: now_unix_ns(),
        }
    }

    /// Builder: override the validation policy.
    pub fn with_validation_policy(mut self, policy: ValidationPolicy) -> Self {
        self.validation_policy = policy;
        self
    }

    /// Builder: set the calibration version.
    pub fn with_calibration_version(mut self, version: impl Into<String>) -> Self {
        self.calibration_version = Some(version.into());
        self
    }

    /// Builder: set the opaque runtime config blob.
    pub fn with_runtime_config_json(mut self, json: impl Into<String>) -> Self {
        self.runtime_config_json = json.into();
        self
    }

    /// Builder: pin `created_unix_ns` (useful for deterministic tests).
    pub fn with_created_unix_ns(mut self, ns: u64) -> Self {
        self.created_unix_ns = ns;
        self
    }
}

/// Best-effort "nanoseconds since the Unix epoch" using the system clock;
/// returns `0` when the clock is unavailable or set before the epoch.
fn now_unix_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::AdapterKind;

    #[test]
    fn header_defaults() {
        let h = CaptureHeader::new(
            SessionId(7),
            SourceId::from("file:lab.rvcsi"),
            AdapterProfile::offline(AdapterKind::File),
        );
        assert_eq!(h.rvcsi_capture_version, CAPTURE_VERSION);
        assert_eq!(h.runtime_config_json, "{}");
        assert!(h.calibration_version.is_none());
        assert_eq!(h.validation_policy, ValidationPolicy::default());
    }

    #[test]
    fn header_builders() {
        let h = CaptureHeader::new(
            SessionId(1),
            SourceId::from("s"),
            AdapterProfile::offline(AdapterKind::File),
        )
        .with_calibration_version("room@v2")
        .with_runtime_config_json(r#"{"foo":1}"#)
        .with_created_unix_ns(42);
        assert_eq!(h.calibration_version.as_deref(), Some("room@v2"));
        assert_eq!(h.runtime_config_json, r#"{"foo":1}"#);
        assert_eq!(h.created_unix_ns, 42);
    }

    #[test]
    fn header_json_roundtrips() {
        let h = CaptureHeader::new(
            SessionId(3),
            SourceId::from("esp32"),
            AdapterProfile::esp32_default(),
        )
        .with_created_unix_ns(123);
        let json = serde_json::to_string(&h).unwrap();
        let back: CaptureHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }
}

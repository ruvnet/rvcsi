//! The [`CsiEvent`] aggregate — semantic interpretation of one or more windows.

use serde::{Deserialize, Serialize};

use crate::ids::{EventId, SessionId, SourceId, WindowId};

/// Kinds of event the runtime emits (ADR-095 FR5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsiEventKind {
    /// Presence appeared in the sensed space.
    PresenceStarted,
    /// Presence ended.
    PresenceEnded,
    /// Motion above threshold detected.
    MotionDetected,
    /// Motion fell back to baseline.
    MotionSettled,
    /// The learned baseline shifted (re-calibration may be warranted).
    BaselineChanged,
    /// Signal quality dropped below a usable threshold.
    SignalQualityDropped,
    /// The source disconnected.
    DeviceDisconnected,
    /// A candidate breathing-rate observation (when signal quality permits).
    BreathingCandidate,
    /// A significant unexplained deviation.
    AnomalyDetected,
    /// Calibration is required before detection can be trusted.
    CalibrationRequired,
}

impl CsiEventKind {
    /// Stable lower-case slug used in logs and the SDK (`"presence_started"`...).
    pub fn slug(self) -> &'static str {
        match self {
            CsiEventKind::PresenceStarted => "presence_started",
            CsiEventKind::PresenceEnded => "presence_ended",
            CsiEventKind::MotionDetected => "motion_detected",
            CsiEventKind::MotionSettled => "motion_settled",
            CsiEventKind::BaselineChanged => "baseline_changed",
            CsiEventKind::SignalQualityDropped => "signal_quality_dropped",
            CsiEventKind::DeviceDisconnected => "device_disconnected",
            CsiEventKind::BreathingCandidate => "breathing_candidate",
            CsiEventKind::AnomalyDetected => "anomaly_detected",
            CsiEventKind::CalibrationRequired => "calibration_required",
        }
    }
}

/// A detected event with confidence and the evidence windows that justify it.
///
/// Invariant: `evidence_window_ids` is non-empty and `0.0 <= confidence <= 1.0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CsiEvent {
    /// Event id.
    pub event_id: EventId,
    /// What happened.
    pub kind: CsiEventKind,
    /// Owning session.
    pub session_id: SessionId,
    /// Source that produced the evidence.
    pub source_id: SourceId,
    /// When the event was detected (ns).
    pub timestamp_ns: u64,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Windows that justify this event (at least one).
    pub evidence_window_ids: Vec<WindowId>,
    /// Calibration version detection ran against, if any.
    pub calibration_version: Option<String>,
    /// Free-form JSON metadata (motion energy, estimated rate, ...).
    pub metadata_json: String,
}

/// Why a [`CsiEvent`] is malformed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum EventError {
    /// No evidence window referenced.
    #[error("event has no evidence window")]
    NoEvidence,
    /// `confidence` escaped `[0, 1]`.
    #[error("confidence {0} out of [0,1]")]
    ConfidenceOutOfRange(f32),
}

impl CsiEvent {
    /// Minimal constructor; sets `metadata_json` to `"{}"`.
    pub fn new(
        event_id: EventId,
        kind: CsiEventKind,
        session_id: SessionId,
        source_id: SourceId,
        timestamp_ns: u64,
        confidence: f32,
        evidence_window_ids: Vec<WindowId>,
    ) -> Self {
        CsiEvent {
            event_id,
            kind,
            session_id,
            source_id,
            timestamp_ns,
            confidence,
            evidence_window_ids,
            calibration_version: None,
            metadata_json: "{}".to_string(),
        }
    }

    /// Attach a calibration version.
    pub fn with_calibration(mut self, version: impl Into<String>) -> Self {
        self.calibration_version = Some(version.into());
        self
    }

    /// Attach metadata (any serializable value).
    pub fn with_metadata<T: Serialize>(mut self, meta: &T) -> Result<Self, serde_json::Error> {
        self.metadata_json = serde_json::to_string(meta)?;
        Ok(self)
    }

    /// Check the aggregate invariant.
    pub fn validate(&self) -> Result<(), EventError> {
        if self.evidence_window_ids.is_empty() {
            return Err(EventError::NoEvidence);
        }
        if !(0.0..=1.0).contains(&self.confidence) || !self.confidence.is_finite() {
            return Err(EventError::ConfidenceOutOfRange(self.confidence));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_are_stable() {
        assert_eq!(CsiEventKind::PresenceStarted.slug(), "presence_started");
        assert_eq!(CsiEventKind::AnomalyDetected.slug(), "anomaly_detected");
    }

    #[test]
    fn requires_evidence_and_bounded_confidence() {
        let mut e = CsiEvent::new(
            EventId(0),
            CsiEventKind::MotionDetected,
            SessionId(0),
            SourceId::from("t"),
            1_000,
            0.7,
            vec![WindowId(3)],
        );
        assert!(e.validate().is_ok());

        e.evidence_window_ids.clear();
        assert_eq!(e.validate(), Err(EventError::NoEvidence));

        e.evidence_window_ids.push(WindowId(3));
        e.confidence = 1.2;
        assert_eq!(e.validate(), Err(EventError::ConfidenceOutOfRange(1.2)));
    }

    #[test]
    fn metadata_and_calibration_roundtrip() {
        #[derive(Serialize)]
        struct M {
            motion_energy: f32,
        }
        let e = CsiEvent::new(
            EventId(1),
            CsiEventKind::PresenceStarted,
            SessionId(0),
            SourceId::from("t"),
            5,
            0.9,
            vec![WindowId(0)],
        )
        .with_calibration("livingroom@v3")
        .with_metadata(&M { motion_energy: 1.25 })
        .unwrap();
        assert_eq!(e.calibration_version.as_deref(), Some("livingroom@v3"));
        assert!(e.metadata_json.contains("1.25"));
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<CsiEvent>(&json).unwrap(), e);
    }
}

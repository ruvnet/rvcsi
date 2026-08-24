//! The [`CsiEvent`] aggregate — semantic interpretation of one or more windows.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::evidence::{
    EventDisposition, EvidenceError, EvidenceExportScope, EvidenceQuality, QualityReason,
    SensingEvidence, SensingEvidencePayload, SyntheticLabel, TokenAuthentication, TokenStatus,
    TrackAssociation, MAX_ASSOCIATION_TTL_NS,
};
use crate::ids::{EventId, SessionId, SourceId, WindowId};

/// Maximum validity window for a typed fusion event.
pub const MAX_EVENT_TTL_NS: u64 = 5_000_000_000;

mod option_u64_string {
    use super::*;
    use serde::de::Error as _;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum WireValue {
        String(String),
        Number(u64),
    }

    pub(super) fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<WireValue>::deserialize(deserializer)?;
        value
            .map(|value| match value {
                WireValue::String(value) => value.parse::<u64>().map_err(D::Error::custom),
                WireValue::Number(value) => Ok(value),
            })
            .transpose()
    }
}

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
    #[serde(with = "crate::evidence::u64_string")]
    pub timestamp_ns: u64,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Windows that justify this event (at least one).
    pub evidence_window_ids: Vec<WindowId>,
    /// Calibration version detection ran against, if any.
    pub calibration_version: Option<String>,
    /// Free-form JSON metadata (motion energy, estimated rate, ...).
    pub metadata_json: String,
    /// Fusion publication decision. Defaults to `observed` for old captures.
    #[serde(default, skip_serializing_if = "EventDisposition::is_observed")]
    pub disposition: EventDisposition,
    /// Typed reasons supporting degradation or mandatory abstention.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quality_reasons: Vec<QualityReason>,
    /// Expiring, capability-labelled radio evidence used by sensor fusion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sensing_evidence: Vec<SensingEvidence>,
    /// Optional, time-bounded track association using a rotating token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_association: Option<TrackAssociation>,
    /// Ground-truth label that is valid only for generated simulations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthetic_label: Option<SyntheticLabel>,
    /// End of this event candidate's validity interval.
    #[serde(
        default,
        with = "option_u64_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at_ns: Option<u64>,
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
    /// Event validity is empty or ended before the event was produced.
    #[error("event expiry is not later than its timestamp")]
    ExpiryBeforeEvent,
    /// A typed evidence event omitted its expiry.
    #[error("event with typed sensing evidence requires an expiry")]
    MissingEventExpiry,
    /// Event lifetime exceeded the governed maximum.
    #[error("event lifetime exceeds five seconds")]
    EventLifetimeTooLong,
    /// Event validity extends beyond one of its evidence items.
    #[error("event expiry exceeds sensing evidence at index {0}")]
    EventOutlivesEvidence(usize),
    /// An abstained event lacked a typed reason.
    #[error("abstained event has no quality reason")]
    MissingAbstentionReason,
    /// One typed sensing evidence item is structurally invalid.
    #[error("invalid sensing evidence at index {index}: {source}")]
    InvalidSensingEvidence {
        /// Position in `sensing_evidence`.
        index: usize,
        /// Evidence validation failure.
        #[source]
        source: EvidenceError,
    },
    /// The optional track association is structurally invalid.
    #[error("invalid track association: {0}")]
    InvalidTrackAssociation(#[source] EvidenceError),
    /// An evidence item was already expired when the event was produced.
    #[error("sensing evidence at index {0} expired before event publication")]
    ExpiredSensingEvidence(usize),
    /// An evidence item claimed a capture time after event publication.
    #[error("sensing evidence at index {0} is from the future")]
    FutureSensingEvidence(usize),
    /// A track association had no lifetime remaining at publication.
    #[error("track association expiry is not later than the event timestamp")]
    ExpiredTrackAssociation,
    /// A track association lacked fresh authenticated advertisement evidence.
    #[error("track association lacks fresh authenticated BLE evidence")]
    UnauthenticatedTrackAssociation,
    /// A track association lacked a fresh CSI track with the same track token.
    #[error("track association lacks fresh matching WiFi CSI track evidence")]
    MissingTrackEvidence,
    /// Track association confidence exceeded its weakest supporting evidence.
    #[error("track association confidence exceeds supporting evidence")]
    AssociationConfidenceTooHigh,
    /// Track association lifetime exceeded the governed maximum.
    #[error("track association lifetime exceeds five seconds")]
    AssociationLifetimeTooLong,
    /// Event remains valid after its embedded track association.
    #[error("event expiry exceeds track association expiry")]
    EventOutlivesAssociation,
    /// Evaluation occurred before this event was produced.
    #[error("event evaluated before its timestamp")]
    EvaluationBeforeEvent,
    /// Event expired at the requested evaluation watermark.
    #[error("event expired at evaluation watermark")]
    EventExpired,
    /// Evidence expired at the requested evaluation watermark.
    #[error("sensing evidence at index {0} expired at evaluation watermark")]
    EvidenceExpiredAt(usize),
    /// Track association expired at the requested evaluation watermark.
    #[error("track association expired at evaluation watermark")]
    TrackAssociationExpiredAt,
    /// The event's simulation-only label is malformed.
    #[error("invalid synthetic label: {0}")]
    InvalidSyntheticLabel(#[source] EvidenceError),
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
            disposition: EventDisposition::Observed,
            quality_reasons: Vec::new(),
            sensing_evidence: Vec::new(),
            track_association: None,
            synthetic_label: None,
            expires_at_ns: None,
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

    /// Attach typed sensing evidence without replacing legacy metadata.
    pub fn with_sensing_evidence(mut self, evidence: Vec<SensingEvidence>) -> Self {
        self.sensing_evidence = evidence;
        self
    }

    /// Set the fusion disposition and its typed reasons.
    pub fn with_disposition(
        mut self,
        disposition: EventDisposition,
        reasons: Vec<QualityReason>,
    ) -> Self {
        self.disposition = disposition;
        self.quality_reasons = reasons;
        self
    }

    /// Attach a rotating-token to RF-track association.
    pub fn with_track_association(mut self, association: TrackAssociation) -> Self {
        self.track_association = Some(association);
        self
    }

    /// Mark an event as generated test data with an explicit ground-truth label.
    pub fn with_synthetic_label(mut self, label: SyntheticLabel) -> Self {
        self.synthetic_label = Some(label);
        self
    }

    /// Set the point after which consumers must discard this event candidate.
    pub fn with_expiry(mut self, expires_at_ns: u64) -> Self {
        self.expires_at_ns = Some(expires_at_ns);
        self
    }

    /// Check the aggregate invariant.
    pub fn validate(&self) -> Result<(), EventError> {
        if self.evidence_window_ids.is_empty() {
            return Err(EventError::NoEvidence);
        }
        if !(0.0..=1.0).contains(&self.confidence) || !self.confidence.is_finite() {
            return Err(EventError::ConfidenceOutOfRange(self.confidence));
        }
        if !self.sensing_evidence.is_empty() && self.expires_at_ns.is_none() {
            return Err(EventError::MissingEventExpiry);
        }
        if let Some(expires_at_ns) = self.expires_at_ns {
            if expires_at_ns <= self.timestamp_ns {
                return Err(EventError::ExpiryBeforeEvent);
            }
            if expires_at_ns.saturating_sub(self.timestamp_ns) > MAX_EVENT_TTL_NS {
                return Err(EventError::EventLifetimeTooLong);
            }
        }
        if self.disposition == EventDisposition::Abstained && self.quality_reasons.is_empty() {
            return Err(EventError::MissingAbstentionReason);
        }
        if let Some(label) = &self.synthetic_label {
            label
                .validate()
                .map_err(EventError::InvalidSyntheticLabel)?;
        }
        for (index, evidence) in self.sensing_evidence.iter().enumerate() {
            evidence
                .validate()
                .map_err(|source| EventError::InvalidSensingEvidence { index, source })?;
            if evidence.timestamp_ns > self.timestamp_ns {
                return Err(EventError::FutureSensingEvidence(index));
            }
            if evidence.is_expired_at(self.timestamp_ns) {
                return Err(EventError::ExpiredSensingEvidence(index));
            }
            if self
                .expires_at_ns
                .is_some_and(|event_expiry| event_expiry > evidence.expires_at_ns)
            {
                return Err(EventError::EventOutlivesEvidence(index));
            }
        }
        if let Some(association) = &self.track_association {
            association
                .validate()
                .map_err(EventError::InvalidTrackAssociation)?;
            if association.expires_at_ns <= self.timestamp_ns {
                return Err(EventError::ExpiredTrackAssociation);
            }
            if association.expires_at_ns.saturating_sub(self.timestamp_ns) > MAX_ASSOCIATION_TTL_NS
            {
                return Err(EventError::AssociationLifetimeTooLong);
            }
            if self
                .expires_at_ns
                .is_some_and(|event_expiry| event_expiry > association.expires_at_ns)
            {
                return Err(EventError::EventOutlivesAssociation);
            }

            let best_ble_confidence = self
                .sensing_evidence
                .iter()
                .filter_map(|evidence| match &evidence.payload {
                    SensingEvidencePayload::BleAdvertisementRssi {
                        pseudonymous_token,
                        token_expires_at_ns,
                        token_status: TokenStatus::Valid,
                        authentication: TokenAuthentication::Authenticated,
                        ..
                    } if pseudonymous_token == &association.pseudonymous_token
                        && evidence.quality != EvidenceQuality::Abstained
                        && !evidence.is_expired_at(self.timestamp_ns)
                        && evidence.expires_at_ns >= association.expires_at_ns
                        && *token_expires_at_ns >= association.expires_at_ns =>
                    {
                        Some(evidence.confidence)
                    }
                    _ => None,
                })
                .reduce(f32::max);
            let Some(ble_confidence) = best_ble_confidence else {
                return Err(EventError::UnauthenticatedTrackAssociation);
            };

            let best_track_confidence = self
                .sensing_evidence
                .iter()
                .filter_map(|evidence| match &evidence.payload {
                    SensingEvidencePayload::WifiCsiTrack { track_token, .. }
                        if track_token == &association.track_token
                            && evidence.quality != EvidenceQuality::Abstained
                            && !evidence.is_expired_at(self.timestamp_ns)
                            && evidence.expires_at_ns >= association.expires_at_ns =>
                    {
                        Some(evidence.confidence)
                    }
                    _ => None,
                })
                .reduce(f32::max);
            let Some(track_confidence) = best_track_confidence else {
                return Err(EventError::MissingTrackEvidence);
            };

            let weakest_support = ble_confidence.min(track_confidence);
            if association.confidence > weakest_support {
                return Err(EventError::AssociationConfidenceTooHigh);
            }
        }
        Ok(())
    }

    /// Validate structure and freshness at a monotonic consumer watermark.
    /// Equality with any expiry is expired.
    pub fn validate_at(&self, now_ns: u64) -> Result<(), EventError> {
        self.validate()?;
        if now_ns < self.timestamp_ns {
            return Err(EventError::EvaluationBeforeEvent);
        }
        if self
            .expires_at_ns
            .is_some_and(|expires_at_ns| now_ns >= expires_at_ns)
        {
            return Err(EventError::EventExpired);
        }
        for (index, evidence) in self.sensing_evidence.iter().enumerate() {
            if evidence.is_expired_at(now_ns) {
                return Err(EventError::EvidenceExpiredAt(index));
            }
        }
        if self
            .track_association
            .as_ref()
            .is_some_and(|association| now_ns >= association.expires_at_ns)
        {
            return Err(EventError::TrackAssociationExpiredAt);
        }
        Ok(())
    }

    /// Validate freshness and the privacy policy at an output boundary.
    pub fn validate_for_export_at(
        &self,
        now_ns: u64,
        scope: EvidenceExportScope,
    ) -> Result<(), EventError> {
        self.validate_at(now_ns)?;
        for (index, evidence) in self.sensing_evidence.iter().enumerate() {
            evidence
                .validate_for_export(scope)
                .map_err(|source| EventError::InvalidSensingEvidence { index, source })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> crate::PseudonymousToken {
        crate::PseudonymousToken::new(format!("blep:{}", "c".repeat(64))).unwrap()
    }

    fn gateway_receipt() -> crate::VerifiedGatewayEnvelope {
        crate::VerifiedGatewayEnvelope {
            contract: crate::GatewayEnvelopeContract::RuViewGatewayV1,
            gateway_node_id: 7,
            gateway_key_id: 3,
            gateway_sequence: 1,
            gateway_boot_nonce: 99,
            received_at_boot_us: 1_000,
            timing_uncertainty_us: 25,
        }
    }

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
        .with_metadata(&M {
            motion_energy: 1.25,
        })
        .unwrap();
        assert_eq!(e.calibration_version.as_deref(), Some("livingroom@v3"));
        assert!(e.metadata_json.contains("1.25"));
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<CsiEvent>(&json).unwrap(), e);
    }

    #[test]
    fn legacy_json_deserializes_with_fusion_defaults() {
        let json = r#"{
            "event_id":1,
            "kind":"PresenceStarted",
            "session_id":0,
            "source_id":"legacy",
            "timestamp_ns":5,
            "confidence":0.9,
            "evidence_window_ids":[0],
            "calibration_version":null,
            "metadata_json":"{}"
        }"#;
        let event: CsiEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.disposition, EventDisposition::Observed);
        assert!(event.quality_reasons.is_empty());
        assert!(event.sensing_evidence.is_empty());
        assert!(event.track_association.is_none());
        assert!(event.validate().is_ok());
    }

    #[test]
    fn abstained_event_requires_typed_reason() {
        let event = CsiEvent::new(
            EventId(2),
            CsiEventKind::SignalQualityDropped,
            SessionId(0),
            SourceId::from("fusion"),
            10,
            0.0,
            vec![WindowId(0)],
        )
        .with_disposition(EventDisposition::Abstained, vec![]);
        assert_eq!(event.validate(), Err(EventError::MissingAbstentionReason));
    }

    #[test]
    fn event_and_association_expiry_fail_closed_at_equality() {
        let event = CsiEvent::new(
            EventId(3),
            CsiEventKind::PresenceStarted,
            SessionId(0),
            SourceId::from("fusion"),
            10,
            0.8,
            vec![WindowId(0)],
        )
        .with_expiry(10);
        assert_eq!(event.validate(), Err(EventError::ExpiryBeforeEvent));

        let token = token();
        let evidence = crate::SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: crate::SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 9,
            expires_at_ns: 20,
            confidence: 0.9,
            quality: crate::EvidenceQuality::Usable,
            privacy_class: crate::PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: crate::SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token.clone(),
                rssi_dbm: -50,
                token_expires_at_ns: 20,
                token_epoch: 1,
                source_sequence: 1,
                token_status: crate::TokenStatus::Valid,
                authentication: crate::TokenAuthentication::Authenticated,
                gateway_envelope: Some(gateway_receipt()),
            },
        };
        let event = CsiEvent::new(
            EventId(4),
            CsiEventKind::PresenceStarted,
            SessionId(0),
            SourceId::from("fusion"),
            10,
            0.8,
            vec![WindowId(0)],
        )
        .with_sensing_evidence(vec![evidence])
        .with_expiry(20)
        .with_track_association(crate::TrackAssociation {
            pseudonymous_token: token,
            track_token: "track_test".into(),
            confidence: 0.8,
            expires_at_ns: 10,
        });
        assert_eq!(event.validate(), Err(EventError::ExpiredTrackAssociation));
    }

    #[test]
    fn event_rejects_evidence_expiring_at_publication_time() {
        let evidence = crate::SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: crate::SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 9,
            expires_at_ns: 10,
            confidence: 0.9,
            quality: crate::EvidenceQuality::Usable,
            privacy_class: crate::PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: crate::SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token(),
                rssi_dbm: -50,
                token_expires_at_ns: 10,
                token_epoch: 1,
                source_sequence: 1,
                token_status: crate::TokenStatus::Valid,
                authentication: crate::TokenAuthentication::Authenticated,
                gateway_envelope: Some(gateway_receipt()),
            },
        };
        let event = CsiEvent::new(
            EventId(5),
            CsiEventKind::PresenceStarted,
            SessionId(0),
            SourceId::from("fusion"),
            10,
            0.8,
            vec![WindowId(0)],
        )
        .with_sensing_evidence(vec![evidence])
        .with_expiry(11);
        assert_eq!(event.validate(), Err(EventError::ExpiredSensingEvidence(0)));
    }

    #[test]
    fn event_rejects_future_sensing_evidence() {
        let mut event = valid_associated_event();
        event.sensing_evidence[0].timestamp_ns = event.timestamp_ns + 1;
        assert_eq!(event.validate(), Err(EventError::FutureSensingEvidence(0)));
    }

    #[test]
    fn unauthenticated_advertisement_cannot_establish_track_association() {
        let token = token();
        let evidence = crate::SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: crate::SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 9,
            expires_at_ns: 20,
            confidence: 0.5,
            quality: crate::EvidenceQuality::Degraded,
            privacy_class: crate::PrivacyClass::P5,
            quality_reasons: vec![crate::QualityReason::UnauthenticatedSource],
            synthetic_label: None,
            payload: crate::SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token.clone(),
                rssi_dbm: -50,
                token_expires_at_ns: 20,
                token_epoch: 1,
                source_sequence: 1,
                token_status: crate::TokenStatus::Valid,
                authentication: crate::TokenAuthentication::Unauthenticated,
                gateway_envelope: None,
            },
        };
        let event = CsiEvent::new(
            EventId(6),
            CsiEventKind::PresenceStarted,
            SessionId(0),
            SourceId::from("fusion"),
            10,
            0.5,
            vec![WindowId(0)],
        )
        .with_sensing_evidence(vec![evidence])
        .with_expiry(20)
        .with_track_association(crate::TrackAssociation {
            pseudonymous_token: token,
            track_token: "track_test".into(),
            confidence: 0.6,
            expires_at_ns: 20,
        });
        assert_eq!(
            event.validate(),
            Err(EventError::UnauthenticatedTrackAssociation)
        );
    }

    #[test]
    fn deserialized_identity_like_simulation_label_is_rejected() {
        let mut event = CsiEvent::new(
            EventId(7),
            CsiEventKind::AnomalyDetected,
            SessionId(0),
            SourceId::from("sim"),
            10,
            0.5,
            vec![WindowId(0)],
        );
        event.synthetic_label = Some(serde_json::from_str("\"Alice\"").unwrap());
        assert!(matches!(
            event.validate(),
            Err(EventError::InvalidSyntheticLabel(_))
        ));
    }

    fn valid_associated_event() -> CsiEvent {
        let token = token();
        let ble = crate::SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: crate::SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.8,
            quality: crate::EvidenceQuality::Usable,
            privacy_class: crate::PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: crate::SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token.clone(),
                rssi_dbm: -50,
                token_expires_at_ns: 20,
                token_epoch: 1,
                source_sequence: 1,
                token_status: crate::TokenStatus::Valid,
                authentication: crate::TokenAuthentication::Authenticated,
                gateway_envelope: Some(gateway_receipt()),
            },
        };
        let csi = crate::SensingEvidence {
            source_id: SourceId::from("csi-node"),
            source_capability: crate::SourceCapability::WifiCsiPhaseAmplitude,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.7,
            quality: crate::EvidenceQuality::Usable,
            privacy_class: crate::PrivacyClass::P0,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: crate::SensingEvidencePayload::WifiCsiTrack {
                track_token: "track_test".into(),
                position_x_m: 1.0,
                track_ambiguity: 0.1,
                respiratory_component: 0.2,
                motion_contaminated: false,
            },
        };
        CsiEvent::new(
            EventId(8),
            CsiEventKind::BreathingCandidate,
            SessionId(0),
            SourceId::from("fusion"),
            10,
            0.7,
            vec![WindowId(0)],
        )
        .with_sensing_evidence(vec![ble, csi])
        .with_track_association(crate::TrackAssociation {
            pseudonymous_token: token,
            track_token: "track_test".into(),
            confidence: 0.7,
            expires_at_ns: 20,
        })
        .with_expiry(20)
    }

    #[test]
    fn association_requires_matching_csi_and_weakest_confidence() {
        let event = valid_associated_event();
        assert!(event.validate().is_ok());

        let mut missing_track = event.clone();
        missing_track.sensing_evidence.retain(|evidence| {
            evidence.source_capability != crate::SourceCapability::WifiCsiPhaseAmplitude
        });
        assert_eq!(
            missing_track.validate(),
            Err(EventError::MissingTrackEvidence)
        );

        let mut mismatched_token = event.clone();
        mismatched_token
            .track_association
            .as_mut()
            .unwrap()
            .pseudonymous_token =
            crate::PseudonymousToken::new(format!("blep:{}", "d".repeat(64))).unwrap();
        assert_eq!(
            mismatched_token.validate(),
            Err(EventError::UnauthenticatedTrackAssociation)
        );

        let mut mismatched_track = event.clone();
        mismatched_track
            .track_association
            .as_mut()
            .unwrap()
            .track_token = "track_other".into();
        assert_eq!(
            mismatched_track.validate(),
            Err(EventError::MissingTrackEvidence)
        );

        let mut overconfident = event;
        overconfident.track_association.as_mut().unwrap().confidence = 0.71;
        assert_eq!(
            overconfident.validate(),
            Err(EventError::AssociationConfidenceTooHigh)
        );

        let mut below_floor = valid_associated_event();
        below_floor.track_association.as_mut().unwrap().confidence = 0.59;
        assert_eq!(
            below_floor.validate(),
            Err(EventError::InvalidTrackAssociation(
                EvidenceError::AssociationConfidenceBelowFloor(0.59)
            ))
        );
    }

    #[test]
    fn association_cannot_outlive_either_matching_support() {
        let mut ble_short = valid_associated_event();
        ble_short.expires_at_ns = Some(19);
        ble_short.sensing_evidence[0].expires_at_ns = 19;
        assert_eq!(
            ble_short.validate(),
            Err(EventError::UnauthenticatedTrackAssociation)
        );

        let mut csi_short = valid_associated_event();
        csi_short.expires_at_ns = Some(19);
        csi_short.sensing_evidence[1].expires_at_ns = 19;
        assert_eq!(csi_short.validate(), Err(EventError::MissingTrackEvidence));
    }

    #[test]
    fn event_and_association_ttls_are_bounded() {
        let mut event_too_long = valid_associated_event();
        event_too_long.expires_at_ns = Some(event_too_long.timestamp_ns + MAX_EVENT_TTL_NS + 1);
        assert_eq!(
            event_too_long.validate(),
            Err(EventError::EventLifetimeTooLong)
        );

        let mut association_too_long = valid_associated_event();
        association_too_long
            .track_association
            .as_mut()
            .unwrap()
            .expires_at_ns = association_too_long.timestamp_ns + MAX_ASSOCIATION_TTL_NS + 1;
        assert_eq!(
            association_too_long.validate(),
            Err(EventError::AssociationLifetimeTooLong)
        );
    }

    #[test]
    fn validate_at_expires_at_exact_watermark() {
        let event = valid_associated_event();
        assert!(event.validate_at(19).is_ok());
        assert!(event
            .validate_for_export_at(19, EvidenceExportScope::EdgeOnly)
            .is_ok());
        assert!(matches!(
            event.validate_for_export_at(19, EvidenceExportScope::External),
            Err(EventError::InvalidSensingEvidence {
                source: EvidenceError::P0ExportRequiresEdgeOnly,
                ..
            })
        ));
        assert_eq!(event.validate_at(20), Err(EventError::EventExpired));
        assert_eq!(event.validate_at(9), Err(EventError::EvaluationBeforeEvent));
    }

    #[test]
    fn nanosecond_deadlines_serialize_as_exact_strings() {
        let event = valid_associated_event();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["timestamp_ns"], "10");
        assert_eq!(json["expires_at_ns"], "20");
        assert_eq!(json["sensing_evidence"][0]["timestamp_ns"], "10");
        assert_eq!(json["sensing_evidence"][0]["expires_at_ns"], "20");
        assert_eq!(
            json["sensing_evidence"][0]["payload"]["token_expires_at_ns"],
            "20"
        );
        assert_eq!(json["sensing_evidence"][0]["payload"]["token_epoch"], "1");
        assert_eq!(json["sensing_evidence"][0]["payload"]["source_sequence"], 1);
        assert_eq!(
            json["track_association"]["expires_at_ns"],
            serde_json::Value::String("20".into())
        );
        assert_eq!(serde_json::from_value::<CsiEvent>(json).unwrap(), event);
    }
}

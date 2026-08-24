//! Deterministic BLE plus CSI fusion scenario for replayable integration tests.
//!
//! The generator creates raw authenticated advertisement records and anonymous
//! CSI track candidates. A stateful replay guard and RSSI geometry associator
//! derive token status, track association, and abstention. Simulation ground
//! truth is kept outside that decision path and is used only for scoring.

use core::f32::consts::PI;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    ChannelSoundingRole, ChannelSoundingStep, CsiEvent, CsiEventKind, EventDisposition, EventError,
    EventId, EvidenceExportScope, EvidenceQuality, GatewayEnvelopeContract, PrivacyClass,
    PseudonymousToken, QualityReason, SensingEvidence, SensingEvidencePayload, SessionId,
    SourceCapability, SourceId, SyntheticLabel, TokenAuthentication, TokenStatus, TrackAssociation,
    VerifiedGatewayEnvelope, WindowId, MAX_EVIDENCE_TTL_NS, MIN_ASSOCIATION_CONFIDENCE,
};

const SIM_BASE_TS_NS: u64 = 1_000_000_000;
const ASSOCIATION_MARGIN_DB: f32 = 1.0;
const MAX_GEOMETRY_ERROR_DB: f32 = 8.0;

/// Configuration for the deterministic crossing scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionSimulationConfig {
    /// Number of time steps. Must be odd and at least nine so there is one exact crossing.
    pub steps: u16,
    /// Nanoseconds between steps.
    pub step_ns: u64,
    /// Add simulated measurements from a future Channel Sounding capable radio.
    pub include_channel_sounding: bool,
}

impl Default for FusionSimulationConfig {
    fn default() -> Self {
        Self {
            steps: 13,
            step_ns: 250_000_000,
            include_channel_sounding: false,
        }
    }
}

/// Machine-readable outcome counters without tokens or physiological samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FusionSimulationSummary {
    /// Total semantic events.
    pub event_count: usize,
    /// Events retaining a valid rotating-token to CSI-track association.
    pub identity_associations: usize,
    /// Incorrect associations compared with independent simulation ground truth.
    pub identity_swaps: usize,
    /// Associations retained at the exact spatial crossing; governed output requires zero.
    pub crossing_associations: usize,
    /// Events that explicitly refused an estimate.
    pub abstentions: usize,
    /// Abstentions caused by gross motion.
    pub motion_abstentions: usize,
    /// Expired identity evidence correctly rejected.
    pub expired_token_rejections: usize,
    /// Replay or geometry conflicts correctly rejected.
    pub spoof_rejections: usize,
    /// Usable or degraded respiratory candidates.
    pub respiratory_candidates: usize,
}

impl FusionSimulationSummary {
    fn empty() -> Self {
        Self {
            event_count: 0,
            identity_associations: 0,
            identity_swaps: 0,
            crossing_associations: 0,
            abstentions: 0,
            motion_abstentions: 0,
            expired_token_rejections: 0,
            spoof_rejections: 0,
            respiratory_candidates: 0,
        }
    }
}

/// Reproducible synthetic event stream and its acceptance counters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FusionSimulationReport {
    /// Contract version for fixtures and downstream consumers.
    pub schema_version: u16,
    /// Effective scenario configuration.
    pub config: FusionSimulationConfig,
    /// Capabilities represented in this generated stream.
    pub source_capabilities: Vec<SourceCapability>,
    /// Extended [`CsiEvent`] records consumed by the normal fusion boundary.
    pub events: Vec<CsiEvent>,
    /// Deterministic acceptance counters.
    pub summary: FusionSimulationSummary,
}

impl FusionSimulationReport {
    /// Recheck every event at its publication watermark before serialization.
    pub fn validate_for_output(
        &self,
        scope: EvidenceExportScope,
    ) -> Result<(), FusionSimulationError> {
        for event in &self.events {
            event.validate_for_export_at(event.timestamp_ns, scope)?;
        }
        Ok(())
    }
}

/// Invalid simulation setup or a generated event violating the shared contract.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum FusionSimulationError {
    /// An odd number of at least nine steps is needed for one unambiguous midpoint.
    #[error("steps must be odd and at least 9")]
    InvalidSteps,
    /// Step duration must be positive.
    #[error("step_ns must be greater than zero")]
    InvalidStepDuration,
    /// Measurement freshness would exceed the five-second contract.
    #[error("step_ns is too large for the bounded evidence lifetime")]
    StepDurationTooLarge,
    /// Timestamp arithmetic overflowed.
    #[error("simulation timestamp overflow")]
    TimestampOverflow,
    /// A generated event failed the production event invariant.
    #[error("generated event failed validation: {0}")]
    InvalidEvent(#[from] EventError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subject {
    A,
    B,
}

impl Subject {
    fn label(self) -> SyntheticLabel {
        SyntheticLabel::new(match self {
            Subject::A => "sim_subject_a",
            Subject::B => "sim_subject_b",
        })
        .expect("static simulation label is valid")
    }

    fn token(self) -> PseudonymousToken {
        let digest = match self {
            Subject::A => "a".repeat(64),
            Subject::B => "b".repeat(64),
        };
        PseudonymousToken::new(format!("blep:{digest}"))
            .expect("static simulation pseudonym is valid")
    }

    const fn frequency_hz(self) -> f32 {
        match self {
            Subject::A => 0.22,
            Subject::B => 0.30,
        }
    }

    const fn procedure_offset(self) -> u32 {
        match self {
            Subject::A => 1,
            Subject::B => 2,
        }
    }
}

#[derive(Debug, Clone)]
struct CsiCandidate {
    track_token: &'static str,
    position_x_m: f32,
    ambiguity: f32,
    respiratory_component: f32,
    motion_contaminated: bool,
}

impl CsiCandidate {
    fn confidence(&self) -> f32 {
        if self.motion_contaminated {
            0.72
        } else {
            (0.94 - 0.35 * self.ambiguity).clamp(0.0, 1.0)
        }
    }
}

#[derive(Debug, Clone)]
struct RawAdvertisement {
    source_id: &'static str,
    anchor_x_m: f32,
    timestamp_ns: u64,
    pseudonymous_token: PseudonymousToken,
    token_epoch: u64,
    source_sequence: u32,
    rssi_dbm: i16,
    token_expires_at_ns: u64,
    authentication: TokenAuthentication,
    gateway_envelope: VerifiedGatewayEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReplayKey {
    source_id: &'static str,
    pseudonymous_token: PseudonymousToken,
    token_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TokenEpochKey {
    pseudonymous_token: PseudonymousToken,
    token_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GatewayReplayKey {
    gateway_node_id: u8,
    gateway_key_id: u8,
    gateway_boot_nonce: u64,
}

#[derive(Debug, Default)]
struct AssociatorState {
    gateway_sequences: BTreeMap<GatewayReplayKey, u32>,
    last_sequence: BTreeMap<ReplayKey, u32>,
    expired_tokens: BTreeSet<TokenEpochKey>,
}

#[derive(Debug)]
struct AssociationDecision {
    status: TokenStatus,
    selected_track: Option<String>,
    confidence: f32,
    reasons: Vec<QualityReason>,
}

impl AssociatorState {
    fn associate(
        &mut self,
        now_ns: u64,
        records: &[RawAdvertisement],
        candidates: &[CsiCandidate],
    ) -> AssociationDecision {
        let Some(first) = records.first() else {
            return AssociationDecision {
                status: TokenStatus::SpoofSuspected,
                selected_track: None,
                confidence: 0.0,
                reasons: vec![QualityReason::LowSignal],
            };
        };

        let token_epoch_key = TokenEpochKey {
            pseudonymous_token: first.pseudonymous_token.clone(),
            token_epoch: first.token_epoch,
        };
        let mut status = if self.expired_tokens.contains(&token_epoch_key) {
            TokenStatus::Expired
        } else {
            TokenStatus::Valid
        };
        let mut saw_expired = status == TokenStatus::Expired;
        for record in records {
            if record.authentication != TokenAuthentication::Authenticated
                || record.gateway_envelope.validate().is_err()
                || record.pseudonymous_token != first.pseudonymous_token
                || record.token_epoch != first.token_epoch
                || record.source_sequence == 0
            {
                status = TokenStatus::SpoofSuspected;
                continue;
            }
            let gateway_key = GatewayReplayKey {
                gateway_node_id: record.gateway_envelope.gateway_node_id,
                gateway_key_id: record.gateway_envelope.gateway_key_id,
                gateway_boot_nonce: record.gateway_envelope.gateway_boot_nonce,
            };
            if self
                .gateway_sequences
                .get(&gateway_key)
                .is_some_and(|last| record.gateway_envelope.gateway_sequence <= *last)
            {
                status = TokenStatus::SpoofSuspected;
            } else {
                self.gateway_sequences
                    .insert(gateway_key, record.gateway_envelope.gateway_sequence);
            }
            if record.token_expires_at_ns <= now_ns && status != TokenStatus::SpoofSuspected {
                status = TokenStatus::Expired;
                saw_expired = true;
            }
            let key = ReplayKey {
                source_id: record.source_id,
                pseudonymous_token: record.pseudonymous_token.clone(),
                token_epoch: record.token_epoch,
            };
            if self
                .last_sequence
                .get(&key)
                .is_some_and(|last| record.source_sequence <= *last)
            {
                status = TokenStatus::SpoofSuspected;
            } else {
                self.last_sequence.insert(key, record.source_sequence);
            }
        }
        if saw_expired {
            self.expired_tokens.insert(token_epoch_key);
        }

        if status != TokenStatus::Valid {
            return AssociationDecision {
                status,
                selected_track: None,
                confidence: 0.0,
                reasons: vec![if status == TokenStatus::Expired {
                    QualityReason::EvidenceExpired
                } else {
                    QualityReason::SpoofSuspected
                }],
            };
        }

        let mut scores: Vec<(&CsiCandidate, f32)> = candidates
            .iter()
            .map(|candidate| {
                let residual = records
                    .iter()
                    .map(|record| {
                        let expected = rssi_for_anchor(candidate.position_x_m, record.anchor_x_m);
                        f32::from((record.rssi_dbm - expected).abs())
                    })
                    .sum::<f32>()
                    / records.len() as f32;
                (candidate, residual)
            })
            .collect();
        scores.sort_by(|left, right| left.1.total_cmp(&right.1));
        let Some((best, best_score)) = scores.first().copied() else {
            return AssociationDecision {
                status: TokenStatus::Valid,
                selected_track: None,
                confidence: 0.0,
                reasons: vec![QualityReason::TrackAmbiguity],
            };
        };
        if best_score > MAX_GEOMETRY_ERROR_DB {
            return AssociationDecision {
                status: TokenStatus::SpoofSuspected,
                selected_track: None,
                confidence: 0.0,
                reasons: vec![QualityReason::SpoofSuspected],
            };
        }

        let margin = scores
            .get(1)
            .map_or(f32::INFINITY, |second| second.1 - best_score);
        let selected = (margin >= ASSOCIATION_MARGIN_DB).then(|| best.track_token.to_string());
        let Some(selected_track) = selected else {
            return AssociationDecision {
                status: TokenStatus::Valid,
                selected_track: None,
                confidence: 0.0,
                reasons: vec![QualityReason::TrackAmbiguity],
            };
        };
        let selected_candidate = candidates
            .iter()
            .find(|candidate| candidate.track_token == selected_track.as_str())
            .expect("selected track came from candidate set");
        let selected_score = scores
            .iter()
            .find(|(candidate, _)| candidate.track_token == selected_track.as_str())
            .map(|(_, score)| *score)
            .expect("selected track has a geometry score");
        let geometry_confidence = (1.0 - selected_score / MAX_GEOMETRY_ERROR_DB).clamp(0.0, 1.0);
        let confidence = 0.88_f32
            .min(selected_candidate.confidence())
            .min(geometry_confidence);
        if confidence < MIN_ASSOCIATION_CONFIDENCE {
            return AssociationDecision {
                status: TokenStatus::Valid,
                selected_track: None,
                confidence: 0.0,
                reasons: vec![QualityReason::LowSignal],
            };
        }
        AssociationDecision {
            status: TokenStatus::Valid,
            selected_track: Some(selected_track),
            confidence,
            reasons: Vec::new(),
        }
    }
}

/// Generate the two-person crossing scenario.
///
/// No random number generator or wall clock is used. Repeated calls with the
/// same configuration return identical events. The default represents an
/// ESP32-S3 class source and excludes raw CTE IQ and Channel Sounding.
pub fn run_ble_csi_crossing_simulation(
    config: FusionSimulationConfig,
) -> Result<FusionSimulationReport, FusionSimulationError> {
    if config.steps < 9 || config.steps.is_multiple_of(2) {
        return Err(FusionSimulationError::InvalidSteps);
    }
    if config.step_ns == 0 {
        return Err(FusionSimulationError::InvalidStepDuration);
    }
    if config.step_ns > MAX_EVIDENCE_TTL_NS / 2 {
        return Err(FusionSimulationError::StepDurationTooLarge);
    }
    u64::from(config.steps - 1)
        .checked_mul(config.step_ns)
        .and_then(|offset| SIM_BASE_TS_NS.checked_add(offset))
        .ok_or(FusionSimulationError::TimestampOverflow)?;

    let middle = config.steps / 2;
    let expired_step = config.steps - 1;
    let spoof_step = config.steps - 2;
    let session_id = SessionId(7_001);
    let mut events = Vec::with_capacity(config.steps as usize * 2);
    let mut summary = FusionSimulationSummary::empty();
    let mut associator = AssociatorState::default();

    for step in 0..config.steps {
        let progress = step as f32 / (config.steps - 1) as f32;
        let position_a = -1.2 + 2.4 * progress;
        let position_b = 1.2 - 2.4 * progress;
        let separation = (position_a - position_b).abs();
        let ambiguity = (1.0 - separation / 0.8).clamp(0.0, 0.98);
        let timestamp_ns = SIM_BASE_TS_NS
            .checked_add(
                u64::from(step)
                    .checked_mul(config.step_ns)
                    .ok_or(FusionSimulationError::TimestampOverflow)?,
            )
            .ok_or(FusionSimulationError::TimestampOverflow)?;
        let motion_contaminated = step.abs_diff(middle) <= 1;
        let measurement_expiry = timestamp_ns
            .checked_add(config.step_ns.saturating_mul(2))
            .ok_or(FusionSimulationError::TimestampOverflow)?;

        let candidates = csi_candidates(
            step,
            middle,
            timestamp_ns,
            position_a,
            position_b,
            ambiguity,
            motion_contaminated,
        );

        for subject in [Subject::A, Subject::B] {
            let position = if subject == Subject::A {
                position_a
            } else {
                position_b
            };
            // Ground truth is used only after the associator has decided.
            let ground_truth_track = if position_a <= position_b {
                if subject == Subject::A {
                    "track_slot_left"
                } else {
                    "track_slot_right"
                }
            } else if subject == Subject::A {
                "track_slot_right"
            } else {
                "track_slot_left"
            };
            let label = subject.label();
            let token = subject.token();
            let token_epoch = 41;
            let sequence = u32::from(step) + 1;
            let gateway_sequence = u32::from(step) * 2 + subject.procedure_offset();
            let token_expiry = if subject == Subject::B && step == expired_step {
                timestamp_ns.saturating_sub(1)
            } else {
                timestamp_ns
                    .checked_add(4_000_000_000)
                    .ok_or(FusionSimulationError::TimestampOverflow)?
            };
            let mut raw_records = vec![
                raw_advertisement(
                    "sim_ble_anchor_left",
                    -1.8,
                    timestamp_ns,
                    token.clone(),
                    token_epoch,
                    sequence,
                    gateway_sequence,
                    position,
                    token_expiry,
                ),
                raw_advertisement(
                    "sim_ble_anchor_right",
                    1.8,
                    timestamp_ns,
                    token.clone(),
                    token_epoch,
                    sequence,
                    gateway_sequence,
                    position,
                    token_expiry,
                ),
            ];
            // The replay carries no pre-labelled status. The stateful guard sees
            // the duplicated source, epoch, token, and sequence and rejects it.
            if subject == Subject::A && step == spoof_step {
                let mut replay = raw_records[0].clone();
                replay.rssi_dbm = -31;
                raw_records.push(replay);
            }

            let decision = associator.associate(timestamp_ns, &raw_records, &candidates);
            let mut event_reasons = decision.reasons.clone();
            if ambiguity >= 0.60 && !event_reasons.contains(&QualityReason::TrackAmbiguity) {
                event_reasons.push(QualityReason::TrackAmbiguity);
            }
            if motion_contaminated {
                event_reasons.push(QualityReason::MotionContamination);
            }

            let mut evidence: Vec<SensingEvidence> = raw_records
                .iter()
                .map(|record| {
                    advertisement_evidence(
                        record,
                        decision.status,
                        measurement_expiry,
                        label.clone(),
                    )
                })
                .collect();
            let selected_candidate = decision.selected_track.as_deref().and_then(|track| {
                candidates
                    .iter()
                    .find(|candidate| candidate.track_token == track)
            });
            if let Some(candidate) = selected_candidate {
                evidence.push(wifi_evidence(
                    timestamp_ns,
                    measurement_expiry,
                    label.clone(),
                    candidate,
                ));
                if config.include_channel_sounding && decision.status == TokenStatus::Valid {
                    let procedure_id = u32::from(step) * 2 + subject.procedure_offset();
                    evidence.push(channel_sounding_evidence(
                        timestamp_ns,
                        measurement_expiry,
                        label.clone(),
                        procedure_id,
                        candidate,
                    ));
                }
            }

            let disposition = if decision.status != TokenStatus::Valid
                || decision.selected_track.is_none()
                || motion_contaminated
            {
                EventDisposition::Abstained
            } else if ambiguity >= 0.60 {
                EventDisposition::Degraded
            } else {
                EventDisposition::Observed
            };
            let kind = match decision.status {
                TokenStatus::Expired => CsiEventKind::SignalQualityDropped,
                TokenStatus::SpoofSuspected => CsiEventKind::AnomalyDetected,
                TokenStatus::Valid => CsiEventKind::BreathingCandidate,
            };
            let confidence = match disposition {
                EventDisposition::Observed => 0.88_f32.min(decision.confidence),
                EventDisposition::Degraded => 0.72_f32.min(decision.confidence),
                EventDisposition::Abstained => 0.0,
            };
            let event_expiry = evidence
                .iter()
                .map(|item| item.expires_at_ns)
                .min()
                .unwrap_or(measurement_expiry);

            let mut event = CsiEvent::new(
                EventId(events.len() as u64),
                kind,
                session_id,
                SourceId::from("sim_ble_csi_fusion"),
                timestamp_ns,
                confidence,
                vec![WindowId(u64::from(step))],
            )
            .with_sensing_evidence(evidence)
            .with_disposition(disposition, event_reasons)
            .with_synthetic_label(label.clone())
            .with_expiry(event_expiry);

            if let (TokenStatus::Valid, Some(track), Some(candidate)) = (
                decision.status,
                decision.selected_track.as_ref(),
                selected_candidate,
            ) {
                let support_confidence = 0.88_f32.min(candidate.confidence());
                event = event.with_track_association(TrackAssociation {
                    pseudonymous_token: token,
                    track_token: track.clone(),
                    confidence: decision.confidence.min(support_confidence),
                    expires_at_ns: event_expiry.min(token_expiry),
                });
            }
            event.validate_at(timestamp_ns)?;
            update_summary(&mut summary, &event, ground_truth_track, step == middle);
            events.push(event);
        }
    }

    summary.event_count = events.len();
    let mut source_capabilities = vec![
        SourceCapability::WifiCsiPhaseAmplitude,
        SourceCapability::BleAdvertisementRssi,
    ];
    if config.include_channel_sounding {
        source_capabilities.push(SourceCapability::BluetoothChannelSoundingPhaseTiming);
    }
    let report = FusionSimulationReport {
        schema_version: 3,
        config,
        source_capabilities,
        events,
        summary,
    };
    report.validate_for_output(EvidenceExportScope::EdgeOnly)?;
    Ok(report)
}

fn csi_candidates(
    step: u16,
    middle: u16,
    timestamp_ns: u64,
    position_a: f32,
    position_b: f32,
    ambiguity: f32,
    motion_contaminated: bool,
) -> Vec<CsiCandidate> {
    let component = |subject: Subject| {
        let seconds = timestamp_ns as f32 / 1_000_000_000.0;
        let respiratory = (2.0 * PI * subject.frequency_hz() * seconds).sin();
        if motion_contaminated {
            respiratory + 3.0 * (2.0 * PI * 1.1 * seconds).sin()
        } else {
            respiratory
        }
    };
    let (left_subject, left_position, right_subject, right_position) = if step <= middle {
        (Subject::A, position_a, Subject::B, position_b)
    } else {
        (Subject::B, position_b, Subject::A, position_a)
    };
    vec![
        CsiCandidate {
            track_token: "track_slot_left",
            position_x_m: left_position,
            ambiguity,
            respiratory_component: component(left_subject),
            motion_contaminated,
        },
        CsiCandidate {
            track_token: "track_slot_right",
            position_x_m: right_position,
            ambiguity,
            respiratory_component: component(right_subject),
            motion_contaminated,
        },
    ]
}

#[allow(clippy::too_many_arguments)]
fn raw_advertisement(
    source_id: &'static str,
    anchor_x_m: f32,
    timestamp_ns: u64,
    pseudonymous_token: PseudonymousToken,
    token_epoch: u64,
    source_sequence: u32,
    gateway_sequence: u32,
    position_x_m: f32,
    token_expires_at_ns: u64,
) -> RawAdvertisement {
    let gateway_node_id = if source_id.ends_with("left") { 7 } else { 8 };
    RawAdvertisement {
        source_id,
        anchor_x_m,
        timestamp_ns,
        pseudonymous_token,
        token_epoch,
        source_sequence,
        rssi_dbm: rssi_for_anchor(position_x_m, anchor_x_m),
        token_expires_at_ns,
        authentication: TokenAuthentication::Authenticated,
        gateway_envelope: gateway_receipt(gateway_node_id, gateway_sequence),
    }
}

fn gateway_receipt(gateway_node_id: u8, gateway_sequence: u32) -> VerifiedGatewayEnvelope {
    VerifiedGatewayEnvelope {
        contract: GatewayEnvelopeContract::RuViewGatewayV1,
        gateway_node_id,
        gateway_key_id: 3,
        gateway_sequence,
        gateway_boot_nonce: 99,
        received_at_boot_us: 1_000 + u64::from(gateway_sequence),
        timing_uncertainty_us: 25,
    }
}

fn advertisement_evidence(
    record: &RawAdvertisement,
    token_status: TokenStatus,
    measurement_expiry: u64,
    label: SyntheticLabel,
) -> SensingEvidence {
    let (quality, confidence, quality_reasons) = match token_status {
        TokenStatus::Valid => (EvidenceQuality::Usable, 0.88, vec![]),
        TokenStatus::Expired => (
            EvidenceQuality::Abstained,
            0.0,
            vec![QualityReason::EvidenceExpired],
        ),
        TokenStatus::SpoofSuspected => (
            EvidenceQuality::Abstained,
            0.0,
            vec![QualityReason::SpoofSuspected],
        ),
    };
    let expires_at_ns = if token_status == TokenStatus::Valid {
        measurement_expiry.min(record.token_expires_at_ns)
    } else {
        measurement_expiry
    };
    SensingEvidence {
        source_id: SourceId::from(record.source_id),
        source_capability: SourceCapability::BleAdvertisementRssi,
        timestamp_ns: record.timestamp_ns,
        expires_at_ns,
        confidence,
        quality,
        privacy_class: PrivacyClass::P5,
        quality_reasons,
        synthetic_label: Some(label),
        payload: SensingEvidencePayload::BleAdvertisementRssi {
            pseudonymous_token: record.pseudonymous_token.clone(),
            rssi_dbm: record.rssi_dbm,
            token_expires_at_ns: record.token_expires_at_ns,
            token_epoch: record.token_epoch,
            source_sequence: record.source_sequence,
            token_status,
            authentication: record.authentication,
            gateway_envelope: Some(record.gateway_envelope.clone()),
        },
    }
}

fn wifi_evidence(
    timestamp_ns: u64,
    expires_at_ns: u64,
    label: SyntheticLabel,
    candidate: &CsiCandidate,
) -> SensingEvidence {
    let quality = if candidate.motion_contaminated || candidate.ambiguity >= 0.60 {
        EvidenceQuality::Degraded
    } else {
        EvidenceQuality::Usable
    };
    let mut quality_reasons = Vec::new();
    if candidate.ambiguity >= 0.60 {
        quality_reasons.push(QualityReason::TrackAmbiguity);
    }
    if candidate.motion_contaminated {
        quality_reasons.push(QualityReason::MotionContamination);
    }
    SensingEvidence {
        source_id: SourceId::from("sim_esp32_s3_csi"),
        source_capability: SourceCapability::WifiCsiPhaseAmplitude,
        timestamp_ns,
        expires_at_ns,
        confidence: candidate.confidence(),
        quality,
        privacy_class: PrivacyClass::P0,
        quality_reasons,
        synthetic_label: Some(label),
        payload: SensingEvidencePayload::WifiCsiTrack {
            track_token: candidate.track_token.to_string(),
            position_x_m: candidate.position_x_m,
            track_ambiguity: candidate.ambiguity,
            respiratory_component: candidate.respiratory_component,
            motion_contaminated: candidate.motion_contaminated,
        },
    }
}

fn channel_sounding_evidence(
    timestamp_ns: u64,
    expires_at_ns: u64,
    label: SyntheticLabel,
    procedure_id: u32,
    candidate: &CsiCandidate,
) -> SensingEvidence {
    let channels = [5_u16, 21, 37, 61];
    let steps: Vec<ChannelSoundingStep> = channels
        .into_iter()
        .enumerate()
        .map(|(index, channel_index)| {
            let phase_milliradians = (candidate.position_x_m * 700.0
                + candidate.respiratory_component * 30.0
                + index as f32 * 170.0)
                .round() as i32;
            let rtt_picoseconds =
                ((10.0 + candidate.position_x_m.abs() * 1.5 + index as f32 * 0.02) * 1_000.0)
                    .round() as i32;
            let quality_permille = 910 - index as u16 * 10;
            ChannelSoundingStep::from_rvcs_v1(
                channel_index,
                phase_milliradians,
                rtt_picoseconds,
                quality_permille,
            )
            .expect("bounded synthetic RVCS v1 primitive")
        })
        .collect();
    let procedure_step_count =
        u16::try_from(steps.len()).expect("bounded Channel Sounding procedure step count");
    SensingEvidence {
        source_id: SourceId::from("sim_bt6_channel_sounding"),
        source_capability: SourceCapability::BluetoothChannelSoundingPhaseTiming,
        timestamp_ns,
        expires_at_ns,
        confidence: 0.89,
        quality: EvidenceQuality::Usable,
        privacy_class: PrivacyClass::P0,
        quality_reasons: vec![],
        synthetic_label: Some(label),
        payload: SensingEvidencePayload::BluetoothChannelSounding {
            procedure_id: procedure_id.to_string(),
            source_session_id: 7_001,
            procedure_step_count,
            local_role: ChannelSoundingRole::Initiator,
            antenna_path: 0,
            calibration_id: "cal_cs_sim_v1".into(),
            gateway_envelope: gateway_receipt(9, procedure_id),
            steps,
        },
    }
}

fn rssi_for_anchor(position_x_m: f32, anchor_x_m: f32) -> i16 {
    let path_m = 0.8 + (position_x_m - anchor_x_m).abs();
    (-43.0 - 9.0 * path_m).round() as i16
}

fn update_summary(
    summary: &mut FusionSimulationSummary,
    event: &CsiEvent,
    ground_truth_track: &str,
    crossing: bool,
) {
    if let Some(association) = &event.track_association {
        summary.identity_associations += 1;
        if crossing {
            summary.crossing_associations += 1;
        }
        if association.track_token != ground_truth_track {
            summary.identity_swaps += 1;
        }
    }
    if event.disposition == EventDisposition::Abstained {
        summary.abstentions += 1;
    }
    if event
        .quality_reasons
        .contains(&QualityReason::MotionContamination)
    {
        summary.motion_abstentions += 1;
    }
    if event
        .quality_reasons
        .contains(&QualityReason::EvidenceExpired)
    {
        summary.expired_token_rejections += 1;
    }
    if event
        .quality_reasons
        .contains(&QualityReason::SpoofSuspected)
    {
        summary.spoof_rejections += 1;
    }
    if event.kind == CsiEventKind::BreathingCandidate
        && event.disposition != EventDisposition::Abstained
    {
        summary.respiratory_candidates += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulation_is_deterministic_and_abstains_then_rebinds_at_crossing() {
        let first = run_ble_csi_crossing_simulation(FusionSimulationConfig::default()).unwrap();
        let second = run_ble_csi_crossing_simulation(FusionSimulationConfig::default()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.schema_version, 3);
        assert_eq!(first.summary.event_count, 26);
        assert_eq!(first.summary.identity_swaps, 0);
        assert_eq!(first.summary.crossing_associations, 0);
        assert_eq!(first.summary.expired_token_rejections, 1);
        assert_eq!(first.summary.spoof_rejections, 1);
        assert_eq!(first.summary.motion_abstentions, 6);
        assert!(first
            .events
            .iter()
            .all(|event| event.validate_at(event.timestamp_ns).is_ok()));

        let middle = u64::from(first.config.steps / 2);
        let crossing: Vec<_> = first
            .events
            .iter()
            .filter(|event| event.evidence_window_ids == [WindowId(middle)])
            .collect();
        assert_eq!(crossing.len(), 2);
        assert!(crossing.iter().all(|event| {
            event.disposition == EventDisposition::Abstained
                && event.track_association.is_none()
                && event
                    .quality_reasons
                    .contains(&QualityReason::TrackAmbiguity)
        }));

        let rebound: Vec<_> = first
            .events
            .iter()
            .filter(|event| event.evidence_window_ids == [WindowId(middle + 1)])
            .collect();
        assert_eq!(rebound.len(), 2);
        assert!(rebound.iter().all(|event| {
            event
                .track_association
                .as_ref()
                .is_some_and(|association| association.confidence >= MIN_ASSOCIATION_CONFIDENCE)
        }));
    }

    #[test]
    fn duplicate_sequence_is_derived_as_spoof() {
        let token = Subject::A.token();
        let record = raw_advertisement("anchor_left", -1.8, 100, token, 1, 7, 7, -1.0, 1_000);
        let candidate = CsiCandidate {
            track_token: "track_left",
            position_x_m: -1.0,
            ambiguity: 0.0,
            respiratory_component: 0.0,
            motion_contaminated: false,
        };
        let mut state = AssociatorState::default();
        let first = state.associate(
            100,
            core::slice::from_ref(&record),
            core::slice::from_ref(&candidate),
        );
        assert_eq!(first.status, TokenStatus::Valid);
        let replay = state.associate(101, &[record], &[candidate]);
        assert_eq!(replay.status, TokenStatus::SpoofSuspected);
        assert!(replay.selected_track.is_none());
    }

    #[test]
    fn duplicate_gateway_envelope_sequence_is_derived_as_spoof() {
        let token = Subject::A.token();
        let first_record = raw_advertisement(
            "anchor_left",
            -1.8,
            100,
            token.clone(),
            1,
            1,
            1,
            -1.0,
            1_000,
        );
        let second_record =
            raw_advertisement("anchor_left", -1.8, 101, token, 1, 2, 1, -1.0, 1_000);
        let candidate = CsiCandidate {
            track_token: "track_left",
            position_x_m: -1.0,
            ambiguity: 0.0,
            respiratory_component: 0.0,
            motion_contaminated: false,
        };
        let mut state = AssociatorState::default();
        assert_eq!(
            state
                .associate(100, &[first_record], core::slice::from_ref(&candidate))
                .status,
            TokenStatus::Valid
        );
        let replay = state.associate(101, &[second_record], &[candidate]);
        assert_eq!(replay.status, TokenStatus::SpoofSuspected);
        assert!(replay.selected_track.is_none());
    }

    #[test]
    fn inconsistent_rssi_geometry_is_derived_as_spoof() {
        let token = Subject::A.token();
        let mut left = raw_advertisement(
            "anchor_left",
            -1.8,
            100,
            token.clone(),
            1,
            1,
            1,
            -1.0,
            1_000,
        );
        let mut right = raw_advertisement("anchor_right", 1.8, 100, token, 1, 1, 1, -1.0, 1_000);
        left.rssi_dbm = -20;
        right.rssi_dbm = -20;
        let candidate = CsiCandidate {
            track_token: "track_left",
            position_x_m: -1.0,
            ambiguity: 0.0,
            respiratory_component: 0.0,
            motion_contaminated: false,
        };
        let decision = AssociatorState::default().associate(
            100,
            &[left, right],
            core::slice::from_ref(&candidate),
        );
        assert_eq!(decision.status, TokenStatus::SpoofSuspected);
        assert!(decision.selected_track.is_none());
        assert_eq!(decision.reasons, vec![QualityReason::SpoofSuspected]);
    }

    #[test]
    fn association_below_confidence_floor_abstains() {
        let token = Subject::A.token();
        let mut record = raw_advertisement("anchor_left", -1.8, 100, token, 1, 1, 1, -1.0, 1_000);
        record.rssi_dbm += 4;
        let candidate = CsiCandidate {
            track_token: "track_left",
            position_x_m: -1.0,
            ambiguity: 0.0,
            respiratory_component: 0.0,
            motion_contaminated: false,
        };
        let decision = AssociatorState::default().associate(100, &[record], &[candidate]);
        assert_eq!(decision.status, TokenStatus::Valid);
        assert!(decision.selected_track.is_none());
        assert_eq!(decision.confidence, 0.0);
        assert_eq!(decision.reasons, vec![QualityReason::LowSignal]);
    }

    #[test]
    fn expired_token_epoch_cannot_be_resurrected() {
        let token = Subject::B.token();
        let expired =
            raw_advertisement("anchor_left", -1.8, 100, token.clone(), 7, 1, 1, -1.0, 100);
        let candidate = CsiCandidate {
            track_token: "track_left",
            position_x_m: -1.0,
            ambiguity: 0.0,
            respiratory_component: 0.0,
            motion_contaminated: false,
        };
        let mut state = AssociatorState::default();
        let first = state.associate(
            100,
            core::slice::from_ref(&expired),
            core::slice::from_ref(&candidate),
        );
        assert_eq!(first.status, TokenStatus::Expired);

        let apparently_renewed =
            raw_advertisement("anchor_left", -1.8, 101, token, 7, 2, 2, -1.0, 1_000);
        let second = state.associate(101, &[apparently_renewed], &[candidate]);
        assert_eq!(second.status, TokenStatus::Expired);
        assert!(second.selected_track.is_none());
    }

    #[test]
    fn expired_and_spoofed_tokens_never_create_associations() {
        let report = run_ble_csi_crossing_simulation(FusionSimulationConfig::default()).unwrap();
        for event in &report.events {
            let rejected = event.quality_reasons.iter().any(|reason| {
                matches!(
                    reason,
                    QualityReason::EvidenceExpired | QualityReason::SpoofSuspected
                )
            });
            if rejected {
                assert_eq!(event.disposition, EventDisposition::Abstained);
                assert!(event.track_association.is_none());
            }
        }
    }

    #[test]
    fn motion_abstention_drops_only_the_exact_crossing_association() {
        let report = run_ble_csi_crossing_simulation(FusionSimulationConfig::default()).unwrap();
        let contaminated: Vec<_> = report
            .events
            .iter()
            .filter(|event| {
                event
                    .quality_reasons
                    .contains(&QualityReason::MotionContamination)
            })
            .collect();
        assert_eq!(contaminated.len(), 6);
        assert!(contaminated
            .iter()
            .all(|event| event.disposition == EventDisposition::Abstained));
        assert_eq!(
            contaminated
                .iter()
                .filter(|event| event.track_association.is_none())
                .count(),
            2
        );
    }

    #[test]
    fn channel_sounding_is_grouped_and_not_attributed_to_esp32_s3() {
        let report = run_ble_csi_crossing_simulation(FusionSimulationConfig {
            include_channel_sounding: true,
            ..FusionSimulationConfig::default()
        })
        .unwrap();
        let sweeps: Vec<_> = report
            .events
            .iter()
            .flat_map(|event| &event.sensing_evidence)
            .filter(|evidence| {
                evidence.source_capability == SourceCapability::BluetoothChannelSoundingPhaseTiming
            })
            .collect();
        assert!(!sweeps.is_empty());
        assert!(sweeps.iter().all(|evidence| {
            evidence.source_id.as_str() == "sim_bt6_channel_sounding"
                && matches!(
                    &evidence.payload,
                    SensingEvidencePayload::BluetoothChannelSounding {
                        procedure_id,
                        source_session_id,
                        procedure_step_count,
                        gateway_envelope,
                        steps,
                        ..
                    } if *source_session_id == 7_001
                        && procedure_id
                            .parse::<u32>()
                            .is_ok_and(|id| id != 0 && id.to_string() == procedure_id.as_str())
                        && usize::from(*procedure_step_count) == steps.len()
                        && steps.len() >= 4
                        && gateway_envelope.contract == GatewayEnvelopeContract::RuViewGatewayV1
                        && steps.iter().all(|step| step.channel_index <= 78
                            && (-PI..PI).contains(&step.phase_radians)
                            && (0.0..=250.0).contains(&step.round_trip_time_ns))
                )
        }));
        let wire = serde_json::to_value(&report).unwrap();
        assert!(wire["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["sensing_evidence"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|evidence| evidence["payload"]["kind"] == "bluetooth_channel_sounding")
                .all(|evidence| evidence["payload"].get("pseudonymous_token").is_none())));
        assert!(matches!(
            report.validate_for_output(EvidenceExportScope::External),
            Err(FusionSimulationError::InvalidEvent(
                EventError::InvalidSensingEvidence {
                    source: crate::EvidenceError::P0ExportRequiresEdgeOnly,
                    ..
                }
            ))
        ));
        assert!(report
            .validate_for_output(EvidenceExportScope::EdgeOnly)
            .is_ok());
        assert!(report.events.iter().all(|event| {
            event.sensing_evidence.iter().all(|evidence| {
                evidence.source_id.as_str() != "sim_esp32_s3_csi"
                    || evidence.source_capability.supported_by_esp32_s3()
            })
        }));
    }

    #[test]
    fn invalid_simulation_config_is_rejected_without_overflow() {
        assert_eq!(
            run_ble_csi_crossing_simulation(FusionSimulationConfig {
                steps: 10,
                ..FusionSimulationConfig::default()
            }),
            Err(FusionSimulationError::InvalidSteps)
        );
        assert_eq!(
            run_ble_csi_crossing_simulation(FusionSimulationConfig {
                step_ns: 0,
                ..FusionSimulationConfig::default()
            }),
            Err(FusionSimulationError::InvalidStepDuration)
        );
        assert_eq!(
            run_ble_csi_crossing_simulation(FusionSimulationConfig {
                step_ns: MAX_EVIDENCE_TTL_NS,
                ..FusionSimulationConfig::default()
            }),
            Err(FusionSimulationError::StepDurationTooLarge)
        );
    }
}

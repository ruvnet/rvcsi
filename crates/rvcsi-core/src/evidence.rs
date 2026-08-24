//! Typed evidence carried by [`crate::CsiEvent`] during multi-radio fusion.
//!
//! The types in this module deliberately keep BLE advertisement RSSI separate
//! from Bluetooth Channel Sounding measurements. RSSI is weak, identity-like
//! proximity evidence. Channel Sounding phase and round-trip timing are
//! cooperative ranging evidence. Treating either as the other creates false
//! precision at the fusion boundary.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SourceId;

/// Maximum lifetime of one fusion measurement: five seconds.
pub const MAX_EVIDENCE_TTL_NS: u64 = 5_000_000_000;

/// Maximum lifetime of a valid BLE application token: five seconds.
pub const MAX_TOKEN_TTL_NS: u64 = 5_000_000_000;

/// Maximum lifetime of an RF track association: five seconds.
pub const MAX_ASSOCIATION_TTL_NS: u64 = 5_000_000_000;

/// Minimum confidence required to publish a BLE-to-CSI track association.
pub const MIN_ASSOCIATION_CONFIDENCE: f32 = 0.60;

/// Minimum unique frequency steps in a Channel Sounding sweep.
pub const MIN_CHANNEL_SOUNDING_STEPS: usize = 4;

/// Maximum unique channels retained after grouping RVCS v1 steps `0..=78`.
pub const MAX_CHANNEL_SOUNDING_STEPS: usize = 79;

/// Largest Bluetooth RF channel index carried by RVCS v1.
pub const MAX_CHANNEL_SOUNDING_CHANNEL_INDEX: u8 = 78;

/// Largest RVCS v1 round-trip timing primitive after picosecond conversion.
pub const MAX_CHANNEL_SOUNDING_RTT_NS: f32 = 250.0;

/// Largest signed phase primitive admitted by RVCS v1, in milliradians.
pub const MAX_RVCS_PHASE_MILLIRADIANS: i32 = 3_142;

/// Largest round-trip timing primitive admitted by RVCS v1, in picoseconds.
pub const MAX_RVCS_RTT_PICOSECONDS: i32 = 250_000;

/// Maximum authenticated gateway receive-time uncertainty in RuView/GW/v1.
pub const MAX_GATEWAY_TIMING_UNCERTAINTY_US: u32 = 1_000_000;

/// JSON codec for nanosecond values. Strings preserve all 64 bits in
/// JavaScript while the visitor continues to accept legacy numeric fixtures.
pub(crate) mod u64_string {
    use super::*;
    use serde::de::Visitor;
    use std::fmt;

    pub(crate) fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct U64StringVisitor;

        impl<'de> Visitor<'de> for U64StringVisitor {
            type Value = u64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a decimal u64 string or legacy u64 number")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(value)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse::<u64>().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(U64StringVisitor)
    }
}

/// Radio measurement a source can actually produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCapability {
    /// WiFi channel amplitude and phase across OFDM subcarriers.
    WifiCsiPhaseAmplitude,
    /// BLE advertising packet RSSI. This is not coherent carrier phase.
    BleAdvertisementRssi,
    /// Raw IQ samples from a BLE direction-finding Constant Tone Extension.
    BleDirectionFindingCteIq,
    /// Bluetooth Channel Sounding phase and round-trip timing measurements.
    BluetoothChannelSoundingPhaseTiming,
}

impl SourceCapability {
    /// Capabilities available from an ESP32-S3 through supported public APIs.
    ///
    /// ESP32-S3 can provide WiFi CSI and BLE advertisement RSSI. Its radio does
    /// not expose raw CTE IQ and does not implement Bluetooth Channel Sounding.
    pub const fn supported_by_esp32_s3(self) -> bool {
        matches!(
            self,
            SourceCapability::WifiCsiPhaseAmplitude | SourceCapability::BleAdvertisementRssi
        )
    }
}

/// A rotating, non-identifying correlation token.
///
/// This is a transport type, not a pseudonymization algorithm. Producers must
/// derive tokens with a keyed construction, rotate them, and keep the mapping
/// outside rvCSI. Its wire form exactly matches RuField: `blep:` followed by a
/// 32 byte lowercase hexadecimal digest.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PseudonymousToken(String);

impl PseudonymousToken {
    /// Construct a validated token.
    pub fn new(value: impl Into<String>) -> Result<Self, EvidenceError> {
        let token = Self(value.into());
        token.validate()?;
        Ok(token)
    }

    /// Borrow the opaque token value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Revalidate a deserialized token before it reaches fusion.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        let Some(digest) = self.0.strip_prefix("blep:") else {
            return Err(EvidenceError::InvalidPseudonymousToken);
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EvidenceError::InvalidPseudonymousToken);
        }
        Ok(())
    }
}

impl core::fmt::Debug for PseudonymousToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PseudonymousToken([redacted])")
    }
}

/// Ground-truth label that may appear only in generated test data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SyntheticLabel(String);

impl SyntheticLabel {
    /// Construct a simulation-only label.
    pub fn new(value: impl Into<String>) -> Result<Self, EvidenceError> {
        let label = Self(value.into());
        label.validate()?;
        Ok(label)
    }

    /// Borrow the simulation label.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Revalidate a deserialized simulation label before use.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if !is_safe_token(&self.0, "sim_", 8, 64) {
            return Err(EvidenceError::InvalidSyntheticLabel);
        }
        Ok(())
    }
}

fn is_safe_token(value: &str, prefix: &str, min_len: usize, max_len: usize) -> bool {
    value.starts_with(prefix)
        && (min_len..=max_len).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn is_safe_track_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn is_safe_metadata_id(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn is_canonical_nonzero_u32(value: &str) -> bool {
    value
        .parse::<u32>()
        .is_ok_and(|parsed| parsed != 0 && parsed.to_string() == value)
}

/// Whether a measurement can be used for the requested interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceQuality {
    /// The evidence passed source and fusion checks.
    #[default]
    Usable,
    /// The evidence remains usable with reduced confidence.
    Degraded,
    /// The evidence must not produce an estimate.
    Abstained,
}

/// Governance classification applied to each typed evidence item.
///
/// The most sensitive field determines the class of the entire item. Exact
/// respiratory waveforms and Channel Sounding phase/timing primitives are P0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyClass {
    /// Raw or exact waveform / sensor primitive; governed edge only.
    P0,
    /// Derived non-identity feature.
    P1,
    /// Occupancy or motion only.
    P2,
    /// Anonymous aggregate state.
    P3,
    /// Biometric or health inference.
    P4,
    /// Identity-linked inference.
    P5,
}

/// Destination policy checked before typed evidence crosses an output boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceExportScope {
    /// Output remains inside the governed edge trust boundary.
    EdgeOnly,
    /// Output may leave the governed edge boundary.
    External,
}

/// Typed reasons for quality reduction or abstention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityReason {
    /// Two CSI tracks overlap enough that spatial assignment is ambiguous.
    TrackAmbiguity,
    /// Gross motion masks the much smaller respiratory component.
    MotionContamination,
    /// The identity evidence expired before it was used.
    EvidenceExpired,
    /// Conflicting observations indicate token replay or spoofing.
    SpoofSuspected,
    /// Received power or coherent measurement quality is insufficient.
    LowSignal,
    /// The named source does not provide the requested measurement.
    UnsupportedCapability,
    /// Source record was not cryptographically authenticated.
    UnauthenticatedSource,
}

/// Status of a rotating BLE identity token at observation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStatus {
    /// Token is current and no conflicting observation was found.
    Valid,
    /// Token lifetime elapsed before association.
    Expired,
    /// Token appeared in a physically inconsistent or duplicate observation.
    SpoofSuspected,
}

/// Verification result for the source record carrying the rotating token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuthentication {
    /// The host adapter verified the enrolled RuView/GW/v1 envelope.
    Authenticated,
    /// Legacy or explicitly low-trust source supplied no authentication.
    Unauthenticated,
    /// Authentication was present but failed verification.
    Invalid,
}

/// Authenticated source receipt retained from a verified RuView/GW/v1 envelope.
///
/// This receipt is produced only after the host adapter verifies the envelope
/// HMAC, enrolled node and key, boot nonce, replay sequence, receive time, and
/// timing uncertainty. An inner flag or UDP source address is not a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedGatewayEnvelope {
    /// Exact authenticated envelope contract.
    pub contract: GatewayEnvelopeContract,
    /// Enrolled gateway node identifier.
    pub gateway_node_id: u8,
    /// Enrolled gateway key selector.
    pub gateway_key_id: u8,
    /// Nonzero sequence within the authenticated boot session.
    pub gateway_sequence: u32,
    /// Nonzero authenticated replay namespace.
    #[serde(with = "u64_string")]
    pub gateway_boot_nonce: u64,
    /// Gateway receive time on its boot-relative clock.
    #[serde(with = "u64_string")]
    pub received_at_boot_us: u64,
    /// Authenticated uncertainty on the receive timestamp.
    pub timing_uncertainty_us: u32,
}

impl VerifiedGatewayEnvelope {
    /// Recheck the retained authenticated-envelope metadata.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.contract != GatewayEnvelopeContract::RuViewGatewayV1
            || self.gateway_sequence == 0
            || self.gateway_boot_nonce == 0
            || self.timing_uncertainty_us > MAX_GATEWAY_TIMING_UNCERTAINTY_US
        {
            return Err(EvidenceError::InvalidGatewayEnvelopeReceipt);
        }
        Ok(())
    }
}

/// Authenticated gateway envelope domain accepted by rvCSI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayEnvelopeContract {
    /// RuView authenticated radio-evidence gateway envelope version 1.
    #[serde(rename = "RuView/GW/v1")]
    RuViewGatewayV1,
}

/// Local role in a cooperative Bluetooth Channel Sounding procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelSoundingRole {
    /// Device that initiated the procedure.
    Initiator,
    /// Device that reflected the sounding exchange.
    Reflector,
}

/// One calibrated frequency step in a grouped Channel Sounding procedure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelSoundingStep {
    /// Bluetooth sounding channel index.
    pub channel_index: u8,
    /// Corrected phase for this step, normalized to signed `[-π, π)` radians.
    pub phase_radians: f32,
    /// Round trip timing estimate for this step, in nanoseconds.
    pub round_trip_time_ns: f32,
    /// Per step controller quality in `[0, 1]`.
    pub quality: f32,
}

impl ChannelSoundingStep {
    /// Convert one bounded RVCS v1 primitive into normalized rvCSI units.
    ///
    /// RVCS carries signed milliradians and signed picoseconds. This conversion
    /// rejects wire values outside the authenticated v1 contract, converts RTT
    /// with `nanoseconds = picoseconds / 1000`, and wraps phase to `[-π, π)`.
    pub fn from_rvcs_v1(
        channel_index: u16,
        phase_milliradians: i32,
        rtt_picoseconds: i32,
        quality_permille: u16,
    ) -> Result<Self, EvidenceError> {
        if channel_index > u16::from(MAX_CHANNEL_SOUNDING_CHANNEL_INDEX)
            || !(-MAX_RVCS_PHASE_MILLIRADIANS..=MAX_RVCS_PHASE_MILLIRADIANS)
                .contains(&phase_milliradians)
            || !(0..=MAX_RVCS_RTT_PICOSECONDS).contains(&rtt_picoseconds)
            || quality_permille > 1_000
        {
            return Err(EvidenceError::InvalidRvcsPrimitive);
        }
        let phase_radians = phase_milliradians as f32 / 1_000.0;
        Ok(Self {
            channel_index: channel_index as u8,
            phase_radians: normalize_signed_phase(phase_radians),
            round_trip_time_ns: rtt_picoseconds as f32 / 1_000.0,
            quality: f32::from(quality_permille) / 1_000.0,
        })
    }
}

fn normalize_signed_phase(phase_radians: f32) -> f32 {
    (phase_radians + core::f32::consts::PI).rem_euclid(core::f32::consts::TAU)
        - core::f32::consts::PI
}

/// Measurement-specific evidence. Variants are intentionally non-interchangeable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SensingEvidencePayload {
    /// A spatial track and normalized respiratory component derived from WiFi CSI.
    WifiCsiTrack {
        /// Opaque, short-lived spatial track token. It is not a person identity.
        track_token: String,
        /// One-dimensional simulation coordinate, in metres.
        position_x_m: f32,
        /// Ambiguity in `[0, 1]`; high values indicate overlapping tracks.
        track_ambiguity: f32,
        /// Unitless, zero-centred respiratory waveform component.
        respiratory_component: f32,
        /// Whether macro motion masks micro motion in this sample.
        motion_contaminated: bool,
    },
    /// BLE advertisement proximity and rotating-token evidence.
    BleAdvertisementRssi {
        /// Application-provisioned rotating token, never a BLE MAC address.
        pseudonymous_token: PseudonymousToken,
        /// Packet RSSI reported by the receiver.
        rssi_dbm: i16,
        /// End of the token's validity interval.
        #[serde(with = "u64_string")]
        token_expires_at_ns: u64,
        /// Rotation epoch authenticated by the firmware record.
        #[serde(with = "u64_string")]
        token_epoch: u64,
        /// Monotonic sequence within source and token epoch.
        source_sequence: u32,
        /// Replay, expiry, or basic consistency result.
        token_status: TokenStatus,
        /// Host-side verification result for the firmware telemetry record.
        authentication: TokenAuthentication,
        /// Verified outer gateway receipt when `authentication` is authenticated.
        gateway_envelope: Option<VerifiedGatewayEnvelope>,
    },
    /// Cooperative Bluetooth Channel Sounding measurement.
    BluetoothChannelSounding {
        /// Canonical decimal form of the nonzero RVCS v1 u32 procedure id.
        procedure_id: String,
        /// Nonzero source session copied from the RuView companion record.
        #[serde(with = "u64_string")]
        source_session_id: u64,
        /// Number of steps declared by every record in the grouped procedure.
        procedure_step_count: u16,
        /// Local controller role.
        local_role: ChannelSoundingRole,
        /// Antenna path selected for the grouped sweep.
        antenna_path: u8,
        /// Governed calibration receipt for phase and timing correction.
        calibration_id: String,
        /// Verified outer RuView/GW/v1 receipt for the grouped procedure.
        gateway_envelope: VerifiedGatewayEnvelope,
        /// Unique calibrated frequency steps in this procedure.
        steps: Vec<ChannelSoundingStep>,
    },
}

/// One confidence-scored, expiring measurement used by fusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensingEvidence {
    /// Source node that made the measurement.
    pub source_id: SourceId,
    /// Measurement type the source claims to support.
    pub source_capability: SourceCapability,
    /// Measurement timestamp.
    #[serde(with = "u64_string")]
    pub timestamp_ns: u64,
    /// Time after which fusion must not consume this measurement.
    #[serde(with = "u64_string")]
    pub expires_at_ns: u64,
    /// Measurement confidence in `[0, 1]`.
    pub confidence: f32,
    /// Overall usability decision.
    #[serde(default)]
    pub quality: EvidenceQuality,
    /// Privacy classification determined by the most sensitive carried field.
    pub privacy_class: PrivacyClass,
    /// Reasons supporting degradation or abstention.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quality_reasons: Vec<QualityReason>,
    /// Ground truth for deterministic simulation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthetic_label: Option<SyntheticLabel>,
    /// Typed measurement body.
    pub payload: SensingEvidencePayload,
}

impl SensingEvidence {
    /// Whether the measurement has expired at `now_ns`.
    pub const fn is_expired_at(&self, now_ns: u64) -> bool {
        now_ns >= self.expires_at_ns
    }

    /// Validate capability, lifetime, quality, and finite numeric fields.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if !(0.0..=1.0).contains(&self.confidence) || !self.confidence.is_finite() {
            return Err(EvidenceError::ConfidenceOutOfRange(self.confidence));
        }
        if self.expires_at_ns <= self.timestamp_ns {
            return Err(EvidenceError::ExpiryBeforeMeasurement);
        }
        if self.expires_at_ns.saturating_sub(self.timestamp_ns) > MAX_EVIDENCE_TTL_NS {
            return Err(EvidenceError::EvidenceLifetimeTooLong);
        }
        if self.quality == EvidenceQuality::Abstained && self.quality_reasons.is_empty() {
            return Err(EvidenceError::MissingAbstentionReason);
        }
        if let Some(label) = &self.synthetic_label {
            label.validate()?;
        }

        let (expected_capability, expected_privacy) = match &self.payload {
            SensingEvidencePayload::WifiCsiTrack {
                track_token,
                position_x_m,
                track_ambiguity,
                respiratory_component,
                ..
            } => {
                if !is_safe_track_token(track_token) {
                    return Err(EvidenceError::InvalidTrackToken);
                }
                if !position_x_m.is_finite()
                    || !respiratory_component.is_finite()
                    || !track_ambiguity.is_finite()
                    || !(0.0..=1.0).contains(track_ambiguity)
                {
                    return Err(EvidenceError::InvalidMeasurement);
                }
                (SourceCapability::WifiCsiPhaseAmplitude, PrivacyClass::P0)
            }
            SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token,
                rssi_dbm,
                token_expires_at_ns,
                source_sequence,
                token_status,
                authentication,
                gateway_envelope,
                ..
            } => {
                pseudonymous_token.validate()?;
                if !(-127..=20).contains(rssi_dbm) {
                    return Err(EvidenceError::InvalidMeasurement);
                }
                if *source_sequence == 0 {
                    return Err(EvidenceError::InvalidSourceSequence);
                }
                match (authentication, gateway_envelope) {
                    (TokenAuthentication::Authenticated, Some(receipt)) => receipt.validate()?,
                    (TokenAuthentication::Authenticated, None) => {
                        return Err(EvidenceError::MissingVerifiedGatewayEnvelope);
                    }
                    (TokenAuthentication::Unauthenticated | TokenAuthentication::Invalid, None) => {
                    }
                    (
                        TokenAuthentication::Unauthenticated | TokenAuthentication::Invalid,
                        Some(_),
                    ) => return Err(EvidenceError::UnexpectedVerifiedGatewayEnvelope),
                }
                if *authentication == TokenAuthentication::Invalid
                    && (*token_status != TokenStatus::SpoofSuspected
                        || self.quality != EvidenceQuality::Abstained
                        || !self
                            .quality_reasons
                            .contains(&QualityReason::SpoofSuspected))
                {
                    return Err(EvidenceError::InvalidAuthenticationDisposition);
                }
                if *authentication == TokenAuthentication::Unauthenticated
                    && (self.quality == EvidenceQuality::Usable
                        || !self
                            .quality_reasons
                            .contains(&QualityReason::UnauthenticatedSource))
                {
                    return Err(EvidenceError::UnauthenticatedEvidencePromoted);
                }
                let status_matches_lifetime = match token_status {
                    TokenStatus::Valid => *token_expires_at_ns > self.timestamp_ns,
                    TokenStatus::Expired => *token_expires_at_ns <= self.timestamp_ns,
                    TokenStatus::SpoofSuspected => true,
                };
                if !status_matches_lifetime {
                    return Err(EvidenceError::InconsistentTokenStatus);
                }
                if *token_status == TokenStatus::Valid {
                    if self.expires_at_ns > *token_expires_at_ns {
                        return Err(EvidenceError::EvidenceOutlivesToken);
                    }
                    if token_expires_at_ns.saturating_sub(self.timestamp_ns) > MAX_TOKEN_TTL_NS {
                        return Err(EvidenceError::TokenLifetimeTooLong);
                    }
                }
                match token_status {
                    TokenStatus::Valid => {}
                    TokenStatus::Expired
                        if self.quality == EvidenceQuality::Abstained
                            && self
                                .quality_reasons
                                .contains(&QualityReason::EvidenceExpired) => {}
                    TokenStatus::SpoofSuspected
                        if self.quality == EvidenceQuality::Abstained
                            && self
                                .quality_reasons
                                .contains(&QualityReason::SpoofSuspected) => {}
                    TokenStatus::Expired | TokenStatus::SpoofSuspected => {
                        return Err(EvidenceError::InvalidTokenDisposition);
                    }
                }
                (SourceCapability::BleAdvertisementRssi, PrivacyClass::P5)
            }
            SensingEvidencePayload::BluetoothChannelSounding {
                procedure_id,
                source_session_id,
                procedure_step_count,
                antenna_path,
                calibration_id,
                gateway_envelope,
                steps,
                ..
            } => {
                gateway_envelope.validate()?;
                if *source_session_id == 0 {
                    return Err(EvidenceError::InvalidChannelSoundingSession);
                }
                if !is_canonical_nonzero_u32(procedure_id)
                    || !is_safe_metadata_id(calibration_id, 96)
                    || *antenna_path > 31
                {
                    return Err(EvidenceError::InvalidChannelSoundingProcedure);
                }
                if usize::from(*procedure_step_count) != steps.len() {
                    return Err(EvidenceError::ChannelSoundingStepCountMismatch {
                        declared: *procedure_step_count,
                        actual: steps.len(),
                    });
                }
                if !(MIN_CHANNEL_SOUNDING_STEPS..=MAX_CHANNEL_SOUNDING_STEPS).contains(&steps.len())
                {
                    return Err(EvidenceError::InvalidChannelSoundingStepCount);
                }
                let mut channels = BTreeSet::new();
                for step in steps {
                    if !channels.insert(step.channel_index) {
                        return Err(EvidenceError::DuplicateChannelSoundingStep);
                    }
                    if step.channel_index > MAX_CHANNEL_SOUNDING_CHANNEL_INDEX
                        || !step.phase_radians.is_finite()
                        || !(-core::f32::consts::PI..core::f32::consts::PI)
                            .contains(&step.phase_radians)
                        || !step.round_trip_time_ns.is_finite()
                        || !(0.0..=MAX_CHANNEL_SOUNDING_RTT_NS).contains(&step.round_trip_time_ns)
                        || !step.quality.is_finite()
                        || !(0.0..=1.0).contains(&step.quality)
                    {
                        return Err(EvidenceError::InvalidMeasurement);
                    }
                }
                (
                    SourceCapability::BluetoothChannelSoundingPhaseTiming,
                    PrivacyClass::P0,
                )
            }
        };
        if expected_capability != self.source_capability {
            return Err(EvidenceError::CapabilityPayloadMismatch);
        }
        if expected_privacy != self.privacy_class {
            return Err(EvidenceError::PrivacyClassMismatch);
        }
        Ok(())
    }

    /// Validate an evidence item before it crosses a named export boundary.
    pub fn validate_for_export(&self, scope: EvidenceExportScope) -> Result<(), EvidenceError> {
        self.validate()?;
        if self.privacy_class == PrivacyClass::P0 && scope != EvidenceExportScope::EdgeOnly {
            return Err(EvidenceError::P0ExportRequiresEdgeOnly);
        }
        Ok(())
    }
}

/// Fusion disposition attached to a [`crate::CsiEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventDisposition {
    /// Publish the candidate normally.
    #[default]
    Observed,
    /// Publish it with explicit quality reduction.
    Degraded,
    /// Do not publish a physiological or identity estimate.
    Abstained,
}

impl EventDisposition {
    /// Serde helper that omits the legacy-compatible default disposition.
    pub(crate) const fn is_observed(value: &Self) -> bool {
        matches!(value, EventDisposition::Observed)
    }
}

/// Time-bounded association between an RF track and a rotating identity token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrackAssociation {
    /// Rotating application token, not a real-world identity.
    pub pseudonymous_token: PseudonymousToken,
    /// Opaque CSI track token.
    pub track_token: String,
    /// Association confidence in governed range `[0.60, 1]`.
    pub confidence: f32,
    /// Association expiry. Consumers must re-establish it after this time.
    #[serde(with = "u64_string")]
    pub expires_at_ns: u64,
}

impl TrackAssociation {
    /// Validate the confidence floor and opaque track token.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.pseudonymous_token.validate()?;
        if !(0.0..=1.0).contains(&self.confidence) || !self.confidence.is_finite() {
            return Err(EvidenceError::ConfidenceOutOfRange(self.confidence));
        }
        if self.confidence < MIN_ASSOCIATION_CONFIDENCE {
            return Err(EvidenceError::AssociationConfidenceBelowFloor(
                self.confidence,
            ));
        }
        if !is_safe_track_token(&self.track_token) {
            return Err(EvidenceError::InvalidTrackToken);
        }
        Ok(())
    }
}

/// Structural validation failures for typed sensing evidence.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum EvidenceError {
    /// Confidence escaped `[0, 1]`.
    #[error("confidence {0} out of [0,1]")]
    ConfidenceOutOfRange(f32),
    /// A track association fell below the governed publication floor.
    #[error("association confidence {0} is below 0.60")]
    AssociationConfidenceBelowFloor(f32),
    /// Measurement validity is empty or ended before it was captured.
    #[error("evidence expiry is not later than its measurement timestamp")]
    ExpiryBeforeMeasurement,
    /// Evidence lifetime exceeded the bounded fusion window.
    #[error("evidence lifetime exceeds five seconds")]
    EvidenceLifetimeTooLong,
    /// A usable BLE measurement outlived its application token.
    #[error("BLE evidence expiry exceeds token expiry")]
    EvidenceOutlivesToken,
    /// BLE application token lifetime exceeded the governed maximum.
    #[error("BLE token lifetime exceeds five seconds")]
    TokenLifetimeTooLong,
    /// Abstention lacked a typed reason.
    #[error("abstained evidence has no quality reason")]
    MissingAbstentionReason,
    /// Claimed source capability does not match the payload variant.
    #[error("source capability does not match evidence payload")]
    CapabilityPayloadMismatch,
    /// One or more numeric fields are non-finite or outside physical bounds.
    #[error("evidence contains an invalid measurement")]
    InvalidMeasurement,
    /// Pseudonymous token did not use the safe opaque-token format.
    #[error("invalid pseudonymous token")]
    InvalidPseudonymousToken,
    /// Simulation label did not use the simulation-only format.
    #[error("invalid synthetic label")]
    InvalidSyntheticLabel,
    /// Track token was empty, too long, or contained unsafe characters.
    #[error("invalid track token")]
    InvalidTrackToken,
    /// Failed record authentication was not converted to spoof-suspected abstention.
    #[error("invalid authentication must be spoof-suspected and abstained")]
    InvalidAuthenticationDisposition,
    /// Unauthenticated evidence was not explicitly degraded or abstained.
    #[error("unauthenticated evidence cannot be promoted as usable")]
    UnauthenticatedEvidencePromoted,
    /// Authenticated evidence did not retain a verified outer gateway receipt.
    #[error("authenticated evidence requires a verified RuView/GW/v1 envelope")]
    MissingVerifiedGatewayEnvelope,
    /// Unauthenticated evidence incorrectly carried a verified-envelope receipt.
    #[error("unverified evidence cannot carry a verified gateway receipt")]
    UnexpectedVerifiedGatewayEnvelope,
    /// Gateway receipt metadata violated the RuView/GW/v1 contract.
    #[error("invalid RuView/GW/v1 envelope receipt")]
    InvalidGatewayEnvelopeReceipt,
    /// Token lifetime and declared status disagree at the measurement timestamp.
    #[error("token status is inconsistent with its expiry")]
    InconsistentTokenStatus,
    /// Token status was not paired with mandatory abstention and reason.
    #[error("token status does not match evidence disposition")]
    InvalidTokenDisposition,
    /// Source sequence zero cannot participate in replay protection.
    #[error("BLE source sequence must be non-zero")]
    InvalidSourceSequence,
    /// Declared privacy did not match the sensitive fields in the payload.
    #[error("privacy class does not match evidence payload")]
    PrivacyClassMismatch,
    /// P0 evidence was requested at a boundary outside the governed edge.
    #[error("P0 respiratory or exact phase/timing evidence is edge-only")]
    P0ExportRequiresEdgeOnly,
    /// Raw RVCS primitive could not be safely converted into normalized units.
    #[error("RVCS v1 primitive is outside conversion bounds")]
    InvalidRvcsPrimitive,
    /// Channel Sounding procedure metadata was missing or malformed.
    #[error("invalid Channel Sounding procedure metadata")]
    InvalidChannelSoundingProcedure,
    /// Channel Sounding source session zero cannot identify an aggregation scope.
    #[error("Channel Sounding source session must be nonzero")]
    InvalidChannelSoundingSession,
    /// Grouped step count disagreed with the companion record declaration.
    #[error("Channel Sounding declared {declared} steps but grouped {actual}")]
    ChannelSoundingStepCountMismatch {
        /// Step count declared in the RuView companion records.
        declared: u16,
        /// Number of unique procedure records grouped by rvCSI.
        actual: usize,
    },
    /// Channel Sounding sweep did not contain the required bounded step count.
    #[error("invalid Channel Sounding sweep step count")]
    InvalidChannelSoundingStepCount,
    /// Channel Sounding sweep repeated a channel index.
    #[error("duplicate channel in Channel Sounding sweep")]
    DuplicateChannelSoundingStep,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> PseudonymousToken {
        PseudonymousToken::new(format!("blep:{}", "a".repeat(64))).unwrap()
    }

    fn gateway_receipt(sequence: u32) -> VerifiedGatewayEnvelope {
        VerifiedGatewayEnvelope {
            contract: GatewayEnvelopeContract::RuViewGatewayV1,
            gateway_node_id: 7,
            gateway_key_id: 3,
            gateway_sequence: sequence,
            gateway_boot_nonce: 99,
            received_at_boot_us: 1_000,
            timing_uncertainty_us: 25,
        }
    }

    #[test]
    fn esp32_s3_capabilities_are_not_overclaimed() {
        assert!(SourceCapability::WifiCsiPhaseAmplitude.supported_by_esp32_s3());
        assert!(SourceCapability::BleAdvertisementRssi.supported_by_esp32_s3());
        assert!(!SourceCapability::BleDirectionFindingCteIq.supported_by_esp32_s3());
        assert!(!SourceCapability::BluetoothChannelSoundingPhaseTiming.supported_by_esp32_s3());
    }

    #[test]
    fn tokens_reject_mac_addresses_and_free_form_identity() {
        assert!(PseudonymousToken::new("AA:BB:CC:DD:EE:FF").is_err());
        assert!(PseudonymousToken::new("alice@example.com").is_err());
        assert!(PseudonymousToken::new(format!("blep:{}", "a".repeat(64))).is_ok());
        assert!(PseudonymousToken::new(format!("blep:{}", "A".repeat(64))).is_err());
        assert!(SyntheticLabel::new("sim_subject_a").is_ok());
        assert!(SyntheticLabel::new("Alice").is_err());

        let decoded_token: PseudonymousToken =
            serde_json::from_str("\"AA:BB:CC:DD:EE:FF\"").unwrap();
        assert_eq!(
            decoded_token.validate(),
            Err(EvidenceError::InvalidPseudonymousToken)
        );
        let decoded_label: SyntheticLabel = serde_json::from_str("\"Alice\"").unwrap();
        assert_eq!(
            decoded_label.validate(),
            Err(EvidenceError::InvalidSyntheticLabel)
        );
    }

    #[test]
    fn advertisement_and_channel_sounding_are_distinct_contracts() {
        let adv = SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.8,
            quality: EvidenceQuality::Usable,
            privacy_class: PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token(),
                rssi_dbm: -60,
                token_expires_at_ns: 100,
                token_epoch: 1,
                source_sequence: 1,
                token_status: TokenStatus::Valid,
                authentication: TokenAuthentication::Authenticated,
                gateway_envelope: Some(gateway_receipt(1)),
            },
        };
        assert!(adv.validate().is_ok());

        let mut mismatched = adv.clone();
        mismatched.source_capability = SourceCapability::BluetoothChannelSoundingPhaseTiming;
        assert_eq!(
            mismatched.validate(),
            Err(EvidenceError::CapabilityPayloadMismatch)
        );

        let sounding = SensingEvidence {
            source_id: SourceId::from("cs-node"),
            source_capability: SourceCapability::BluetoothChannelSoundingPhaseTiming,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.9,
            quality: EvidenceQuality::Usable,
            privacy_class: PrivacyClass::P0,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: SensingEvidencePayload::BluetoothChannelSounding {
                procedure_id: "17".into(),
                source_session_id: 44,
                procedure_step_count: 4,
                local_role: ChannelSoundingRole::Initiator,
                antenna_path: 0,
                calibration_id: "fixture.ble_cs_calibration.v1".into(),
                gateway_envelope: gateway_receipt(2),
                steps: vec![
                    ChannelSoundingStep {
                        channel_index: 5,
                        phase_radians: 0.2,
                        round_trip_time_ns: 12.1,
                        quality: 0.9,
                    },
                    ChannelSoundingStep {
                        channel_index: 21,
                        phase_radians: 0.4,
                        round_trip_time_ns: 12.2,
                        quality: 0.9,
                    },
                    ChannelSoundingStep {
                        channel_index: 37,
                        phase_radians: 0.6,
                        round_trip_time_ns: 12.3,
                        quality: 0.9,
                    },
                    ChannelSoundingStep {
                        channel_index: 61,
                        phase_radians: 0.8,
                        round_trip_time_ns: 12.4,
                        quality: 0.9,
                    },
                ],
            },
        };
        assert!(sounding.validate().is_ok());
        assert_ne!(
            serde_json::to_value(&adv).unwrap()["payload"]["kind"],
            serde_json::to_value(&sounding).unwrap()["payload"]["kind"]
        );
        let sounding_json = serde_json::to_value(&sounding).unwrap();
        assert_eq!(sounding_json["payload"]["source_session_id"], "44");
        assert_eq!(sounding_json["payload"]["procedure_step_count"], 4);
        assert!(sounding_json["payload"].get("pseudonymous_token").is_none());
        assert_eq!(
            sounding_json["payload"]["gateway_envelope"]["contract"],
            "RuView/GW/v1"
        );
        assert_eq!(
            sounding.validate_for_export(EvidenceExportScope::External),
            Err(EvidenceError::P0ExportRequiresEdgeOnly)
        );
        assert!(sounding
            .validate_for_export(EvidenceExportScope::EdgeOnly)
            .is_ok());

        let mut missing_receipt = adv.clone();
        let SensingEvidencePayload::BleAdvertisementRssi {
            gateway_envelope, ..
        } = &mut missing_receipt.payload
        else {
            unreachable!();
        };
        *gateway_envelope = None;
        assert_eq!(
            missing_receipt.validate(),
            Err(EvidenceError::MissingVerifiedGatewayEnvelope)
        );

        let mut invalid_receipt = sounding.clone();
        let SensingEvidencePayload::BluetoothChannelSounding {
            gateway_envelope, ..
        } = &mut invalid_receipt.payload
        else {
            unreachable!();
        };
        gateway_envelope.gateway_boot_nonce = 0;
        assert_eq!(
            invalid_receipt.validate(),
            Err(EvidenceError::InvalidGatewayEnvelopeReceipt)
        );

        let mut misclassified = sounding;
        misclassified.privacy_class = PrivacyClass::P4;
        assert_eq!(
            misclassified.validate(),
            Err(EvidenceError::PrivacyClassMismatch)
        );
    }

    #[test]
    fn rvcs_conversion_is_bounded_and_signed() {
        let positive_endpoint =
            ChannelSoundingStep::from_rvcs_v1(78, 3_142, 250_000, 1_000).unwrap();
        assert_eq!(positive_endpoint.channel_index, 78);
        assert_eq!(positive_endpoint.round_trip_time_ns, 250.0);
        assert!((-core::f32::consts::PI..core::f32::consts::PI)
            .contains(&positive_endpoint.phase_radians));
        assert!(positive_endpoint.phase_radians.is_sign_negative());

        let negative_endpoint = ChannelSoundingStep::from_rvcs_v1(0, -3_142, 0, 0).unwrap();
        assert!((-core::f32::consts::PI..core::f32::consts::PI)
            .contains(&negative_endpoint.phase_radians));
        assert!(negative_endpoint.phase_radians.is_sign_positive());

        for invalid in [
            ChannelSoundingStep::from_rvcs_v1(79, 0, 0, 0),
            ChannelSoundingStep::from_rvcs_v1(0, 3_143, 0, 0),
            ChannelSoundingStep::from_rvcs_v1(0, 0, -1, 0),
            ChannelSoundingStep::from_rvcs_v1(0, 0, 250_001, 0),
            ChannelSoundingStep::from_rvcs_v1(0, 0, 0, 1_001),
        ] {
            assert_eq!(invalid, Err(EvidenceError::InvalidRvcsPrimitive));
        }
    }

    #[test]
    fn abstention_requires_a_reason() {
        let evidence = SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.0,
            quality: EvidenceQuality::Abstained,
            privacy_class: PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token(),
                rssi_dbm: -60,
                token_expires_at_ns: 9,
                token_epoch: 1,
                source_sequence: 1,
                token_status: TokenStatus::Expired,
                authentication: TokenAuthentication::Authenticated,
                gateway_envelope: Some(gateway_receipt(1)),
            },
        };
        assert_eq!(
            evidence.validate(),
            Err(EvidenceError::MissingAbstentionReason)
        );
    }

    #[test]
    fn expiry_is_fail_closed_at_the_exact_deadline() {
        let mut evidence = SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.8,
            quality: EvidenceQuality::Usable,
            privacy_class: PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token(),
                rssi_dbm: -60,
                token_expires_at_ns: 20,
                token_epoch: 1,
                source_sequence: 1,
                token_status: TokenStatus::Valid,
                authentication: TokenAuthentication::Authenticated,
                gateway_envelope: Some(gateway_receipt(1)),
            },
        };
        assert!(!evidence.is_expired_at(19));
        assert!(evidence.is_expired_at(20));
        assert!(evidence.is_expired_at(21));

        evidence.expires_at_ns = evidence.timestamp_ns;
        assert_eq!(
            evidence.validate(),
            Err(EvidenceError::ExpiryBeforeMeasurement)
        );
    }

    #[test]
    fn unauthenticated_advertisement_cannot_be_usable() {
        let mut evidence = SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.8,
            quality: EvidenceQuality::Usable,
            privacy_class: PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token(),
                rssi_dbm: -60,
                token_expires_at_ns: 20,
                token_epoch: 1,
                source_sequence: 1,
                token_status: TokenStatus::Valid,
                authentication: TokenAuthentication::Unauthenticated,
                gateway_envelope: None,
            },
        };
        assert_eq!(
            evidence.validate(),
            Err(EvidenceError::UnauthenticatedEvidencePromoted)
        );
        evidence.quality = EvidenceQuality::Degraded;
        evidence
            .quality_reasons
            .push(QualityReason::UnauthenticatedSource);
        assert!(evidence.validate().is_ok());
        let SensingEvidencePayload::BleAdvertisementRssi {
            gateway_envelope, ..
        } = &mut evidence.payload
        else {
            unreachable!();
        };
        *gateway_envelope = Some(gateway_receipt(1));
        assert_eq!(
            evidence.validate(),
            Err(EvidenceError::UnexpectedVerifiedGatewayEnvelope)
        );
    }

    #[test]
    fn expired_token_cannot_be_published_as_usable() {
        let evidence = SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.8,
            quality: EvidenceQuality::Usable,
            privacy_class: PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token(),
                rssi_dbm: -60,
                token_expires_at_ns: 10,
                token_epoch: 1,
                source_sequence: 1,
                token_status: TokenStatus::Expired,
                authentication: TokenAuthentication::Authenticated,
                gateway_envelope: Some(gateway_receipt(1)),
            },
        };
        assert_eq!(
            evidence.validate(),
            Err(EvidenceError::InvalidTokenDisposition)
        );
    }

    #[test]
    fn valid_advertisement_cannot_outlive_token_or_max_ttl() {
        let mut evidence = SensingEvidence {
            source_id: SourceId::from("ble-anchor"),
            source_capability: SourceCapability::BleAdvertisementRssi,
            timestamp_ns: 10,
            expires_at_ns: 30,
            confidence: 0.8,
            quality: EvidenceQuality::Usable,
            privacy_class: PrivacyClass::P5,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: SensingEvidencePayload::BleAdvertisementRssi {
                pseudonymous_token: token(),
                rssi_dbm: -60,
                token_expires_at_ns: 20,
                token_epoch: 1,
                source_sequence: 1,
                token_status: TokenStatus::Valid,
                authentication: TokenAuthentication::Authenticated,
                gateway_envelope: Some(gateway_receipt(1)),
            },
        };
        assert_eq!(
            evidence.validate(),
            Err(EvidenceError::EvidenceOutlivesToken)
        );
        evidence.expires_at_ns = 20;
        assert!(evidence.validate().is_ok());
        evidence.expires_at_ns = evidence.timestamp_ns + MAX_EVIDENCE_TTL_NS + 1;
        assert_eq!(
            evidence.validate(),
            Err(EvidenceError::EvidenceLifetimeTooLong)
        );

        evidence.expires_at_ns = 20;
        let SensingEvidencePayload::BleAdvertisementRssi {
            token_expires_at_ns,
            ..
        } = &mut evidence.payload
        else {
            unreachable!();
        };
        *token_expires_at_ns = evidence.timestamp_ns + MAX_TOKEN_TTL_NS + 1;
        assert_eq!(
            evidence.validate(),
            Err(EvidenceError::TokenLifetimeTooLong)
        );
    }

    #[test]
    fn channel_sounding_requires_unique_grouped_steps() {
        let mut sounding = SensingEvidence {
            source_id: SourceId::from("cs-node"),
            source_capability: SourceCapability::BluetoothChannelSoundingPhaseTiming,
            timestamp_ns: 10,
            expires_at_ns: 20,
            confidence: 0.9,
            quality: EvidenceQuality::Usable,
            privacy_class: PrivacyClass::P0,
            quality_reasons: vec![],
            synthetic_label: None,
            payload: SensingEvidencePayload::BluetoothChannelSounding {
                procedure_id: "23".into(),
                source_session_id: 44,
                procedure_step_count: 4,
                local_role: ChannelSoundingRole::Initiator,
                antenna_path: 0,
                calibration_id: "cal_test_01".into(),
                gateway_envelope: gateway_receipt(2),
                steps: (0_u8..4)
                    .map(|index| ChannelSoundingStep {
                        channel_index: index,
                        phase_radians: 0.2 + f32::from(index) * 0.1,
                        round_trip_time_ns: 12.0,
                        quality: 0.9,
                    })
                    .collect(),
            },
        };
        assert!(sounding.validate().is_ok());
        for (channel_index, phase_radians, round_trip_time_ns) in [
            (79, 0.2, 12.0),
            (0, core::f32::consts::PI, 12.0),
            (0, 0.2, 250.01),
        ] {
            let mut invalid = sounding.clone();
            let SensingEvidencePayload::BluetoothChannelSounding { steps, .. } =
                &mut invalid.payload
            else {
                unreachable!();
            };
            steps[0].channel_index = channel_index;
            steps[0].phase_radians = phase_radians;
            steps[0].round_trip_time_ns = round_trip_time_ns;
            assert_eq!(invalid.validate(), Err(EvidenceError::InvalidMeasurement));
        }
        {
            let SensingEvidencePayload::BluetoothChannelSounding { steps, .. } =
                &mut sounding.payload
            else {
                unreachable!();
            };
            steps.truncate(3);
        }
        assert_eq!(
            sounding.validate(),
            Err(EvidenceError::ChannelSoundingStepCountMismatch {
                declared: 4,
                actual: 3,
            })
        );
        {
            let SensingEvidencePayload::BluetoothChannelSounding {
                procedure_step_count,
                ..
            } = &mut sounding.payload
            else {
                unreachable!();
            };
            *procedure_step_count = 3;
        }
        assert_eq!(
            sounding.validate(),
            Err(EvidenceError::InvalidChannelSoundingStepCount)
        );

        {
            let SensingEvidencePayload::BluetoothChannelSounding {
                steps,
                procedure_step_count,
                ..
            } = &mut sounding.payload
            else {
                unreachable!();
            };
            steps.push(ChannelSoundingStep {
                channel_index: 0,
                phase_radians: 0.9,
                round_trip_time_ns: 12.0,
                quality: 0.9,
            });
            *procedure_step_count = 4;
        }
        assert_eq!(
            sounding.validate(),
            Err(EvidenceError::DuplicateChannelSoundingStep)
        );

        {
            let SensingEvidencePayload::BluetoothChannelSounding {
                source_session_id, ..
            } = &mut sounding.payload
            else {
                unreachable!();
            };
            *source_session_id = 0;
        }
        assert_eq!(
            sounding.validate(),
            Err(EvidenceError::InvalidChannelSoundingSession)
        );
        {
            let SensingEvidencePayload::BluetoothChannelSounding {
                source_session_id, ..
            } = &mut sounding.payload
            else {
                unreachable!();
            };
            *source_session_id = 44;
        }

        for invalid_id in ["023", "0", "4294967296", "+23"] {
            {
                let SensingEvidencePayload::BluetoothChannelSounding { procedure_id, .. } =
                    &mut sounding.payload
                else {
                    unreachable!();
                };
                *procedure_id = invalid_id.into();
            }
            assert_eq!(
                sounding.validate(),
                Err(EvidenceError::InvalidChannelSoundingProcedure)
            );
        }
    }
}

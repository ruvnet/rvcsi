//! The validation pipeline (ADR-095 D6/D13).
//!
//! [`validate_frame`] is the only door between raw adapter output and anything
//! downstream (DSP, events, the napi boundary, RuVector). It mutates a frame in
//! place: on success it sets `validation` to `Accepted` or `Degraded` and fills
//! `quality_score`; on a hard failure it returns a [`ValidationError`] and the
//! caller quarantines the frame (when quarantine is enabled) or drops it.

use serde::{Deserialize, Serialize};

use crate::adapter::AdapterProfile;
use crate::frame::{CsiFrame, ValidationStatus};

/// Tunable bounds for the validation pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationPolicy {
    /// Minimum acceptable subcarrier count.
    pub min_subcarriers: u16,
    /// Maximum acceptable subcarrier count.
    pub max_subcarriers: u16,
    /// Plausible RSSI range, dBm (inclusive).
    pub rssi_dbm_bounds: (i16, i16),
    /// If `true`, a non-monotonic timestamp is a hard reject; if `false`, the
    /// frame is marked [`ValidationStatus::Recovered`] and accepted.
    pub strict_monotonic_time: bool,
    /// If `true`, frames that fail a soft check become `Degraded` instead of
    /// being rejected; if `false`, soft failures are rejected too.
    pub degrade_instead_of_reject: bool,
    /// Frames whose computed quality is below this become `Degraded`
    /// (or rejected if `degrade_instead_of_reject` is false).
    pub min_quality: f32,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        ValidationPolicy {
            min_subcarriers: 1,
            max_subcarriers: 4096,
            rssi_dbm_bounds: (-110, 0),
            strict_monotonic_time: false,
            degrade_instead_of_reject: true,
            min_quality: 0.25,
        }
    }
}

/// Computed usability confidence for a frame, in `[0.0, 1.0]`.
///
/// Starts at `1.0` and accrues multiplicative penalties for: out-of-range
/// (but non-fatal) RSSI, near-zero amplitude (dead subcarriers), excessive
/// amplitude spikes, and missing optional metadata that the profile implies
/// should be present.
#[derive(Debug, Clone, PartialEq)]
pub struct QualityScore {
    /// The final score.
    pub value: f32,
    /// Human-readable reasons it was reduced (empty when `value == 1.0`).
    pub reasons: Vec<String>,
}

impl QualityScore {
    fn full() -> Self {
        QualityScore {
            value: 1.0,
            reasons: Vec::new(),
        }
    }

    fn penalize(&mut self, factor: f32, reason: impl Into<String>) {
        self.value = (self.value * factor).clamp(0.0, 1.0);
        self.reasons.push(reason.into());
    }
}

/// Why a frame was rejected (a hard failure).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// The four parallel vectors disagree in length, or none match `subcarrier_count`.
    #[error("vector length mismatch: i={i}, q={q}, amp={amp}, phase={phase}, subcarrier_count={sc}")]
    LengthMismatch {
        /// i_values length
        i: usize,
        /// q_values length
        q: usize,
        /// amplitude length
        amp: usize,
        /// phase length
        phase: usize,
        /// declared subcarrier_count
        sc: usize,
    },
    /// Subcarrier count is outside `[policy.min, policy.max]` or not in the profile.
    #[error("subcarrier count {count} not allowed (policy {min}..={max}, profile-allowed: {profile_ok})")]
    SubcarrierCount {
        /// the count
        count: u16,
        /// policy minimum
        min: u16,
        /// policy maximum
        max: u16,
        /// whether the profile's expected list allowed it
        profile_ok: bool,
    },
    /// A non-finite (NaN / inf) value in one of the vectors.
    #[error("non-finite value in '{vector}' at index {index}")]
    NonFinite {
        /// which vector
        vector: &'static str,
        /// index of the offending element
        index: usize,
    },
    /// RSSI is so far out of range it's implausible (hard reject).
    #[error("implausible RSSI {rssi} dBm (bounds {min}..={max})")]
    ImplausibleRssi {
        /// reported rssi
        rssi: i16,
        /// lower bound
        min: i16,
        /// upper bound
        max: i16,
    },
    /// Timestamp went backwards and `strict_monotonic_time` is set.
    #[error("non-monotonic timestamp: {ts} <= previous {prev}")]
    NonMonotonicTime {
        /// this frame's timestamp
        ts: u64,
        /// previous frame's timestamp
        prev: u64,
    },
    /// Channel is not supported by the source profile.
    #[error("channel {channel} not in source profile")]
    UnsupportedChannel {
        /// the channel
        channel: u16,
    },
    /// Computed quality fell below `policy.min_quality` and degradation is disabled.
    #[error("quality {quality} below minimum {min}")]
    BelowMinQuality {
        /// computed quality
        quality: f32,
        /// configured minimum
        min: f32,
    },
}

/// How implausibly far outside the bounds an RSSI must be before it's a hard
/// reject rather than a quality penalty.
const RSSI_HARD_MARGIN: i16 = 30;

/// Validate `frame` against `profile` and `policy`, mutating it in place.
///
/// `prev_timestamp_ns` is the timestamp of the previous accepted frame in the
/// same session (or `None` for the first frame); it is used for the
/// monotonicity check.
///
/// On `Ok(())` the frame's `validation` is `Accepted` / `Degraded` /
/// `Recovered` and `quality_score` is set. On `Err`, the frame's `validation`
/// has been set to `Rejected` (so a caller that ignores the error still won't
/// expose it) and the error explains why.
pub fn validate_frame(
    frame: &mut CsiFrame,
    profile: &AdapterProfile,
    policy: &ValidationPolicy,
    prev_timestamp_ns: Option<u64>,
) -> Result<(), ValidationError> {
    // -- hard checks ---------------------------------------------------------
    let sc = frame.subcarrier_count as usize;
    if frame.i_values.len() != sc
        || frame.q_values.len() != sc
        || frame.amplitude.len() != sc
        || frame.phase.len() != sc
    {
        frame.validation = ValidationStatus::Rejected;
        return Err(ValidationError::LengthMismatch {
            i: frame.i_values.len(),
            q: frame.q_values.len(),
            amp: frame.amplitude.len(),
            phase: frame.phase.len(),
            sc,
        });
    }

    let profile_ok = profile.accepts_subcarrier_count(frame.subcarrier_count);
    if frame.subcarrier_count < policy.min_subcarriers
        || frame.subcarrier_count > policy.max_subcarriers
        || !profile_ok
    {
        frame.validation = ValidationStatus::Rejected;
        return Err(ValidationError::SubcarrierCount {
            count: frame.subcarrier_count,
            min: policy.min_subcarriers,
            max: policy.max_subcarriers,
            profile_ok,
        });
    }

    for (name, v) in [
        ("i_values", &frame.i_values),
        ("q_values", &frame.q_values),
        ("amplitude", &frame.amplitude),
        ("phase", &frame.phase),
    ] {
        if let Some(idx) = v.iter().position(|x| !x.is_finite()) {
            frame.validation = ValidationStatus::Rejected;
            return Err(ValidationError::NonFinite {
                vector: name,
                index: idx,
            });
        }
    }

    if !profile.accepts_channel(frame.channel) {
        frame.validation = ValidationStatus::Rejected;
        return Err(ValidationError::UnsupportedChannel {
            channel: frame.channel,
        });
    }

    let (rssi_lo, rssi_hi) = policy.rssi_dbm_bounds;
    if let Some(rssi) = frame.rssi_dbm {
        if rssi < rssi_lo - RSSI_HARD_MARGIN || rssi > rssi_hi + RSSI_HARD_MARGIN {
            frame.validation = ValidationStatus::Rejected;
            return Err(ValidationError::ImplausibleRssi {
                rssi,
                min: rssi_lo,
                max: rssi_hi,
            });
        }
    }

    let mut recovered_time = false;
    if let Some(prev) = prev_timestamp_ns {
        if frame.timestamp_ns <= prev {
            if policy.strict_monotonic_time {
                frame.validation = ValidationStatus::Rejected;
                return Err(ValidationError::NonMonotonicTime {
                    ts: frame.timestamp_ns,
                    prev,
                });
            }
            recovered_time = true;
        }
    }

    // -- quality scoring (soft) ---------------------------------------------
    let mut q = QualityScore::full();

    if let Some(rssi) = frame.rssi_dbm {
        if rssi < rssi_lo || rssi > rssi_hi {
            q.penalize(0.6, format!("rssi {rssi} dBm outside [{rssi_lo},{rssi_hi}]"));
        }
    }

    // dead subcarriers (amplitude ~ 0)
    let dead = frame.amplitude.iter().filter(|a| **a < 1e-6).count();
    if dead > 0 {
        let frac = dead as f32 / sc.max(1) as f32;
        q.penalize((1.0 - frac).max(0.05), format!("{dead}/{sc} dead subcarriers"));
    }

    // amplitude spikes (a single subcarrier >> the median magnitude)
    if sc >= 3 {
        let mut sorted: Vec<f32> = frame.amplitude.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));
        let median = sorted[sc / 2].max(1e-9);
        let max = *sorted.last().unwrap();
        if max > median * 50.0 {
            q.penalize(0.7, format!("amplitude spike: max {max:.3} vs median {median:.3}"));
        }
    }

    // implied-but-missing metadata
    if frame.rssi_dbm.is_none() {
        q.penalize(0.95, "missing rssi");
    }

    let status = if recovered_time {
        ValidationStatus::Recovered
    } else if q.value < policy.min_quality {
        if policy.degrade_instead_of_reject {
            ValidationStatus::Degraded
        } else {
            frame.validation = ValidationStatus::Rejected;
            return Err(ValidationError::BelowMinQuality {
                quality: q.value,
                min: policy.min_quality,
            });
        }
    } else if q.reasons.is_empty() {
        ValidationStatus::Accepted
    } else if policy.degrade_instead_of_reject {
        // soft penalties but above the floor → still acceptable, just note them
        ValidationStatus::Accepted
    } else {
        ValidationStatus::Accepted
    };

    frame.validation = status;
    frame.quality_score = q.value;
    frame.quality_reasons = q.reasons;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::AdapterKind;
    use crate::ids::{FrameId, SessionId, SourceId};

    fn raw(sc: usize) -> CsiFrame {
        CsiFrame::from_iq(
            FrameId(0),
            SessionId(0),
            SourceId::from("t"),
            AdapterKind::File,
            1_000,
            6,
            20,
            vec![1.0; sc],
            vec![1.0; sc],
        )
    }

    #[test]
    fn clean_frame_is_accepted_with_perfect_quality() {
        let mut f = raw(56).with_rssi(-55);
        validate_frame(&mut f, &AdapterProfile::offline(AdapterKind::File), &ValidationPolicy::default(), None).unwrap();
        assert_eq!(f.validation, ValidationStatus::Accepted);
        assert_eq!(f.quality_score, 1.0);
        assert!(f.quality_reasons.is_empty());
        assert!(f.is_exposable());
    }

    #[test]
    fn missing_rssi_is_a_minor_penalty_not_a_reject() {
        let mut f = raw(56);
        validate_frame(&mut f, &AdapterProfile::offline(AdapterKind::File), &ValidationPolicy::default(), None).unwrap();
        assert_eq!(f.validation, ValidationStatus::Accepted);
        assert!(f.quality_score < 1.0);
        assert!(f.quality_reasons.iter().any(|r| r.contains("rssi")));
    }

    #[test]
    fn length_mismatch_is_rejected() {
        let mut f = raw(56);
        f.q_values.pop();
        let err = validate_frame(&mut f, &AdapterProfile::offline(AdapterKind::File), &ValidationPolicy::default(), None).unwrap_err();
        assert!(matches!(err, ValidationError::LengthMismatch { .. }));
        assert_eq!(f.validation, ValidationStatus::Rejected);
        assert!(!f.is_exposable());
    }

    #[test]
    fn non_finite_is_rejected() {
        let mut f = raw(4);
        f.amplitude[2] = f32::NAN;
        let err = validate_frame(&mut f, &AdapterProfile::offline(AdapterKind::File), &ValidationPolicy::default(), None).unwrap_err();
        assert!(matches!(err, ValidationError::NonFinite { vector: "amplitude", index: 2 }));
    }

    #[test]
    fn subcarrier_count_must_match_profile() {
        let mut f = raw(57); // ESP32 expects 64/128/192
        let err = validate_frame(&mut f, &AdapterProfile::esp32_default(), &ValidationPolicy::default(), None).unwrap_err();
        assert!(matches!(err, ValidationError::SubcarrierCount { count: 57, .. }));
    }

    #[test]
    fn non_monotonic_time_is_recovered_when_lenient_rejected_when_strict() {
        let mut f = raw(56).with_rssi(-50);
        // lenient
        validate_frame(&mut f, &AdapterProfile::offline(AdapterKind::File), &ValidationPolicy::default(), Some(2_000)).unwrap();
        assert_eq!(f.validation, ValidationStatus::Recovered);
        // strict
        let mut g = raw(56).with_rssi(-50);
        let policy = ValidationPolicy { strict_monotonic_time: true, ..Default::default() };
        let err = validate_frame(&mut g, &AdapterProfile::offline(AdapterKind::File), &policy, Some(2_000)).unwrap_err();
        assert!(matches!(err, ValidationError::NonMonotonicTime { .. }));
    }

    #[test]
    fn dead_subcarriers_degrade_quality() {
        let mut f = raw(10).with_rssi(-50);
        for a in f.amplitude.iter_mut().take(8) {
            *a = 0.0;
        }
        validate_frame(&mut f, &AdapterProfile::offline(AdapterKind::File), &ValidationPolicy::default(), None).unwrap();
        assert!(f.quality_score < 0.5);
        assert!(f.quality_reasons.iter().any(|r| r.contains("dead subcarriers")));
    }

    #[test]
    fn very_low_quality_can_be_degraded_or_rejected() {
        // 9/10 dead → quality ~0.1 < min_quality 0.25
        let mk = || {
            let mut f = raw(10).with_rssi(-50);
            for a in f.amplitude.iter_mut().take(9) {
                *a = 0.0;
            }
            f
        };
        let mut f = mk();
        validate_frame(&mut f, &AdapterProfile::offline(AdapterKind::File), &ValidationPolicy::default(), None).unwrap();
        assert_eq!(f.validation, ValidationStatus::Degraded);

        let mut g = mk();
        let policy = ValidationPolicy { degrade_instead_of_reject: false, ..Default::default() };
        let err = validate_frame(&mut g, &AdapterProfile::offline(AdapterKind::File), &policy, None).unwrap_err();
        assert!(matches!(err, ValidationError::BelowMinQuality { .. }));
        assert_eq!(g.validation, ValidationStatus::Rejected);
    }

    #[test]
    fn implausible_rssi_is_hard_reject() {
        let mut f = raw(56).with_rssi(50); // way above 0 + margin
        let err = validate_frame(&mut f, &AdapterProfile::offline(AdapterKind::File), &ValidationPolicy::default(), None).unwrap_err();
        assert!(matches!(err, ValidationError::ImplausibleRssi { .. }));
    }
}

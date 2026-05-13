//! The normalized [`CsiFrame`] — the FFI-safe boundary object (ADR-095 D5/D6).

use serde::{Deserialize, Serialize};

use crate::adapter::AdapterKind;
use crate::ids::{FrameId, SessionId, SourceId};

/// Outcome of the validation pipeline for a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStatus {
    /// Not yet validated — set by adapters before [`crate::validate_frame`] runs.
    /// A `Pending` frame must never cross a language boundary.
    Pending,
    /// Passed all checks.
    Accepted,
    /// Usable but with reduced confidence; carries a reason in `quality_reasons`.
    Degraded,
    /// Failed a hard check; quarantined when quarantine is enabled, otherwise dropped.
    Rejected,
    /// Reconstructed during replay or gap-recovery; timestamp monotonicity is waived.
    Recovered,
}

impl ValidationStatus {
    /// Whether a frame with this status may be exposed to SDK/DSP/memory/agents.
    #[inline]
    pub fn is_exposable(self) -> bool {
        matches!(
            self,
            ValidationStatus::Accepted | ValidationStatus::Degraded | ValidationStatus::Recovered
        )
    }
}

/// One CSI observation at a timestamp, normalized across all sources.
///
/// Invariants enforced by [`crate::validate_frame`]:
/// * `i_values.len() == q_values.len() == amplitude.len() == phase.len() == subcarrier_count`
/// * all of `i_values`/`q_values`/`amplitude`/`phase` are finite
/// * `subcarrier_count` is within the source's [`crate::AdapterProfile`]
/// * `rssi_dbm`, when present, is within plausible device bounds
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CsiFrame {
    /// Monotonic id within the session.
    pub frame_id: FrameId,
    /// Owning capture session.
    pub session_id: SessionId,
    /// Human-readable source id.
    pub source_id: SourceId,
    /// Which adapter produced this frame.
    pub adapter_kind: AdapterKind,
    /// Source timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// WiFi channel number.
    pub channel: u16,
    /// Channel bandwidth in MHz (20, 40, 80, 160).
    pub bandwidth_mhz: u16,
    /// Received signal strength, dBm, if reported.
    pub rssi_dbm: Option<i16>,
    /// Noise floor, dBm, if reported.
    pub noise_floor_dbm: Option<i16>,
    /// Receive-antenna index, if reported.
    pub antenna_index: Option<u8>,
    /// Transmit chain index, if reported.
    pub tx_chain: Option<u8>,
    /// Receive chain index, if reported.
    pub rx_chain: Option<u8>,
    /// Number of subcarriers (== length of the four vectors below).
    pub subcarrier_count: u16,
    /// In-phase components, one per subcarrier.
    pub i_values: Vec<f32>,
    /// Quadrature components, one per subcarrier.
    pub q_values: Vec<f32>,
    /// Magnitude `sqrt(i^2 + q^2)`, one per subcarrier.
    pub amplitude: Vec<f32>,
    /// Phase `atan2(q, i)` in radians, one per subcarrier (unwrapped by DSP later).
    pub phase: Vec<f32>,
    /// Validation outcome.
    pub validation: ValidationStatus,
    /// Quality / usability confidence in `[0.0, 1.0]`.
    pub quality_score: f32,
    /// Reasons a frame was degraded (empty when `Accepted`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quality_reasons: Vec<String>,
    /// Calibration version this frame was processed against, if any.
    pub calibration_version: Option<String>,
}

impl CsiFrame {
    /// Build a raw (un-validated) frame from interleaved-free I/Q vectors.
    ///
    /// `amplitude` and `phase` are derived from `i_values`/`q_values`. The
    /// frame is returned with `validation = Pending` and `quality_score = 0.0`;
    /// run [`crate::validate_frame`] before exposing it.
    #[allow(clippy::too_many_arguments)]
    pub fn from_iq(
        frame_id: FrameId,
        session_id: SessionId,
        source_id: SourceId,
        adapter_kind: AdapterKind,
        timestamp_ns: u64,
        channel: u16,
        bandwidth_mhz: u16,
        i_values: Vec<f32>,
        q_values: Vec<f32>,
    ) -> Self {
        let n = i_values.len();
        let mut amplitude = Vec::with_capacity(n);
        let mut phase = Vec::with_capacity(n);
        for (i, q) in i_values.iter().zip(q_values.iter()) {
            amplitude.push((i * i + q * q).sqrt());
            phase.push(q.atan2(*i));
        }
        CsiFrame {
            frame_id,
            session_id,
            source_id,
            adapter_kind,
            timestamp_ns,
            channel,
            bandwidth_mhz,
            rssi_dbm: None,
            noise_floor_dbm: None,
            antenna_index: None,
            tx_chain: None,
            rx_chain: None,
            subcarrier_count: n as u16,
            i_values,
            q_values,
            amplitude,
            phase,
            validation: ValidationStatus::Pending,
            quality_score: 0.0,
            quality_reasons: Vec::new(),
            calibration_version: None,
        }
    }

    /// Builder-style setter for RSSI.
    pub fn with_rssi(mut self, rssi_dbm: i16) -> Self {
        self.rssi_dbm = Some(rssi_dbm);
        self
    }

    /// Builder-style setter for noise floor.
    pub fn with_noise_floor(mut self, noise_floor_dbm: i16) -> Self {
        self.noise_floor_dbm = Some(noise_floor_dbm);
        self
    }

    /// Builder-style setter for antenna / chain metadata.
    pub fn with_chains(mut self, antenna: Option<u8>, tx: Option<u8>, rx: Option<u8>) -> Self {
        self.antenna_index = antenna;
        self.tx_chain = tx;
        self.rx_chain = rx;
        self
    }

    /// Mean amplitude across subcarriers (0.0 for an empty frame).
    pub fn mean_amplitude(&self) -> f32 {
        if self.amplitude.is_empty() {
            0.0
        } else {
            self.amplitude.iter().sum::<f32>() / self.amplitude.len() as f32
        }
    }

    /// Whether this frame may be exposed across a language boundary.
    pub fn is_exposable(&self) -> bool {
        self.validation.is_exposable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CsiFrame {
        CsiFrame::from_iq(
            FrameId(0),
            SessionId(0),
            SourceId::from("test"),
            AdapterKind::File,
            1_000,
            6,
            20,
            vec![3.0, 0.0, -1.0],
            vec![4.0, 2.0, 0.0],
        )
    }

    #[test]
    fn derives_amplitude_and_phase() {
        let f = sample();
        assert_eq!(f.subcarrier_count, 3);
        assert!((f.amplitude[0] - 5.0).abs() < 1e-6); // 3-4-5 triangle
        assert!((f.amplitude[1] - 2.0).abs() < 1e-6);
        assert!((f.phase[0] - (4.0f32).atan2(3.0)).abs() < 1e-6);
        assert_eq!(f.validation, ValidationStatus::Pending);
        assert_eq!(f.quality_score, 0.0);
    }

    #[test]
    fn builder_setters_and_mean() {
        let f = sample().with_rssi(-55).with_noise_floor(-92).with_chains(Some(0), None, Some(1));
        assert_eq!(f.rssi_dbm, Some(-55));
        assert_eq!(f.noise_floor_dbm, Some(-92));
        assert_eq!(f.antenna_index, Some(0));
        assert_eq!(f.rx_chain, Some(1));
        assert!((f.mean_amplitude() - (5.0 + 2.0 + 1.0) / 3.0).abs() < 1e-6);
    }

    #[test]
    fn exposability_rules() {
        assert!(!ValidationStatus::Pending.is_exposable());
        assert!(!ValidationStatus::Rejected.is_exposable());
        assert!(ValidationStatus::Accepted.is_exposable());
        assert!(ValidationStatus::Degraded.is_exposable());
        assert!(ValidationStatus::Recovered.is_exposable());
    }

    #[test]
    fn frame_json_roundtrips() {
        let f = sample().with_rssi(-60);
        let json = serde_json::to_string(&f).unwrap();
        let back: CsiFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}

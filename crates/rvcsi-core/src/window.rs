//! The [`CsiWindow`] aggregate — a bounded sequence of frames from one source.

use serde::{Deserialize, Serialize};

use crate::ids::{SessionId, SourceId, WindowId};

/// A bounded window of frames, summarized into per-subcarrier statistics plus
/// scalar motion / presence / quality scores.
///
/// Invariants (enforced by the DSP windowing stage, [`CsiWindow::validate`]):
/// * all frames came from one `source_id` and one `session_id`
/// * `start_ns < end_ns`
/// * `0.0 <= presence_score <= 1.0` and `0.0 <= quality_score <= 1.0`
/// * `mean_amplitude.len() == phase_variance.len()`
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CsiWindow {
    /// Window id.
    pub window_id: WindowId,
    /// Owning session.
    pub session_id: SessionId,
    /// Source the frames came from.
    pub source_id: SourceId,
    /// Timestamp of the first frame, ns.
    pub start_ns: u64,
    /// Timestamp of the last frame, ns.
    pub end_ns: u64,
    /// Number of frames aggregated.
    pub frame_count: u32,
    /// Mean amplitude per subcarrier.
    pub mean_amplitude: Vec<f32>,
    /// Phase variance per subcarrier.
    pub phase_variance: Vec<f32>,
    /// Scalar motion energy (>= 0).
    pub motion_energy: f32,
    /// Presence score in `[0.0, 1.0]`.
    pub presence_score: f32,
    /// Window quality in `[0.0, 1.0]`.
    pub quality_score: f32,
}

/// Reasons a [`CsiWindow`] failed its invariants.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum WindowError {
    /// `start_ns >= end_ns`.
    #[error("window start {start_ns} not before end {end_ns}")]
    BadTimeOrder {
        /// start
        start_ns: u64,
        /// end
        end_ns: u64,
    },
    /// A score escaped `[0, 1]`.
    #[error("score '{name}' = {value} out of [0,1]")]
    ScoreOutOfRange {
        /// which score
        name: &'static str,
        /// the value
        value: f32,
    },
    /// `mean_amplitude` and `phase_variance` disagree in length.
    #[error("stat length mismatch: mean_amplitude={a}, phase_variance={b}")]
    StatLengthMismatch {
        /// mean_amplitude length
        a: usize,
        /// phase_variance length
        b: usize,
    },
    /// Zero frames in the window.
    #[error("empty window")]
    Empty,
}

impl CsiWindow {
    /// Duration covered by the window, ns.
    pub fn duration_ns(&self) -> u64 {
        self.end_ns.saturating_sub(self.start_ns)
    }

    /// Number of subcarriers summarized.
    pub fn subcarrier_count(&self) -> usize {
        self.mean_amplitude.len()
    }

    /// Check the aggregate invariants.
    pub fn validate(&self) -> Result<(), WindowError> {
        if self.frame_count == 0 {
            return Err(WindowError::Empty);
        }
        if self.start_ns >= self.end_ns {
            return Err(WindowError::BadTimeOrder {
                start_ns: self.start_ns,
                end_ns: self.end_ns,
            });
        }
        if self.mean_amplitude.len() != self.phase_variance.len() {
            return Err(WindowError::StatLengthMismatch {
                a: self.mean_amplitude.len(),
                b: self.phase_variance.len(),
            });
        }
        for (name, v) in [
            ("presence_score", self.presence_score),
            ("quality_score", self.quality_score),
        ] {
            if !(0.0..=1.0).contains(&v) || !v.is_finite() {
                return Err(WindowError::ScoreOutOfRange { name, value: v });
            }
        }
        if !self.motion_energy.is_finite() || self.motion_energy < 0.0 {
            return Err(WindowError::ScoreOutOfRange {
                name: "motion_energy",
                value: self.motion_energy,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> CsiWindow {
        CsiWindow {
            window_id: WindowId(0),
            session_id: SessionId(0),
            source_id: SourceId::from("test"),
            start_ns: 1_000,
            end_ns: 2_000,
            frame_count: 10,
            mean_amplitude: vec![1.0, 2.0, 3.0],
            phase_variance: vec![0.1, 0.1, 0.2],
            motion_energy: 0.5,
            presence_score: 0.8,
            quality_score: 0.9,
        }
    }

    #[test]
    fn valid_window_passes() {
        let w = good();
        assert!(w.validate().is_ok());
        assert_eq!(w.duration_ns(), 1_000);
        assert_eq!(w.subcarrier_count(), 3);
    }

    #[test]
    fn rejects_bad_time_order() {
        let mut w = good();
        w.end_ns = w.start_ns;
        assert!(matches!(w.validate(), Err(WindowError::BadTimeOrder { .. })));
    }

    #[test]
    fn rejects_out_of_range_score() {
        let mut w = good();
        w.presence_score = 1.5;
        assert!(matches!(w.validate(), Err(WindowError::ScoreOutOfRange { name: "presence_score", .. })));
        let mut w = good();
        w.motion_energy = -0.1;
        assert!(matches!(w.validate(), Err(WindowError::ScoreOutOfRange { name: "motion_energy", .. })));
    }

    #[test]
    fn rejects_stat_mismatch_and_empty() {
        let mut w = good();
        w.phase_variance.push(0.3);
        assert!(matches!(w.validate(), Err(WindowError::StatLengthMismatch { .. })));
        let mut w = good();
        w.frame_count = 0;
        assert!(matches!(w.validate(), Err(WindowError::Empty)));
    }
}

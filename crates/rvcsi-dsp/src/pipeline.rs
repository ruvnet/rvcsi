//! The composable [`SignalPipeline`] (ADR-095 FR4).
//!
//! A pipeline is a small bag of configuration plus a non-destructive
//! `process_frame` step that cleans a [`CsiFrame`]'s `amplitude` / `phase`
//! vectors *after* `rvcsi_core::validate_frame` has run. It deliberately never
//! mutates `validation`, `quality_score`, or `quality_reasons` — those belong to
//! the validation stage, and a DSP cleanup pass must not silently "upgrade" or
//! "downgrade" a frame's trust state.

use rvcsi_core::CsiFrame;

use crate::stages::{hampel_filter, moving_average, remove_dc_offset, unwrap_phase};

/// Configurable signal-cleaning pipeline applied per frame.
///
/// The processing order in [`SignalPipeline::process_frame`] is fixed:
/// 1. Hampel outlier filter on `amplitude`
/// 2. centered moving-average smoothing on `amplitude`
/// 3. DC-offset removal on `amplitude` (if [`remove_dc`](Self::remove_dc))
/// 4. baseline subtraction on `amplitude` (if a learned baseline of matching
///    length is present)
/// 5. phase unwrap on `phase` (if [`unwrap_phase`](Self::unwrap_phase))
#[derive(Debug, Clone, PartialEq)]
pub struct SignalPipeline {
    /// Window length for the moving-average smoothing of amplitude
    /// (`0`/`1` disables smoothing).
    pub smoothing_window: usize,
    /// Half-window for the Hampel outlier filter on amplitude.
    pub hampel_half_window: usize,
    /// Outlier threshold (in robust sigmas) for the Hampel filter.
    pub hampel_n_sigmas: f32,
    /// Whether to unwrap the phase vector.
    pub unwrap_phase: bool,
    /// Whether to subtract the DC offset (mean) from the amplitude vector.
    pub remove_dc: bool,
    /// Optional learned per-subcarrier baseline amplitude; subtracted from
    /// `amplitude` when its length matches the frame's subcarrier count.
    pub baseline_amplitude: Option<Vec<f32>>,
}

impl Default for SignalPipeline {
    fn default() -> Self {
        SignalPipeline {
            smoothing_window: 3,
            hampel_half_window: 3,
            hampel_n_sigmas: 3.0,
            unwrap_phase: true,
            remove_dc: true,
            baseline_amplitude: None,
        }
    }
}

impl SignalPipeline {
    /// Construct a pipeline with the [default](Self::default) configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style setter for [`smoothing_window`](Self::smoothing_window).
    pub fn with_smoothing_window(mut self, window: usize) -> Self {
        self.smoothing_window = window;
        self
    }

    /// Builder-style setter for the Hampel half-window.
    pub fn with_hampel_half_window(mut self, half_window: usize) -> Self {
        self.hampel_half_window = half_window;
        self
    }

    /// Builder-style setter for the Hampel sigma threshold.
    pub fn with_hampel_n_sigmas(mut self, n_sigmas: f32) -> Self {
        self.hampel_n_sigmas = n_sigmas;
        self
    }

    /// Builder-style setter for [`unwrap_phase`](Self::unwrap_phase).
    pub fn with_unwrap_phase(mut self, on: bool) -> Self {
        self.unwrap_phase = on;
        self
    }

    /// Builder-style setter for [`remove_dc`](Self::remove_dc).
    pub fn with_remove_dc(mut self, on: bool) -> Self {
        self.remove_dc = on;
        self
    }

    /// Builder-style setter for an explicit baseline amplitude vector.
    pub fn with_baseline_amplitude(mut self, baseline: Option<Vec<f32>>) -> Self {
        self.baseline_amplitude = baseline;
        self
    }

    /// Clean a frame's `amplitude` and `phase` vectors in place.
    ///
    /// See the [type docs](SignalPipeline) for the fixed processing order. This
    /// method does **not** read or write `frame.validation`,
    /// `frame.quality_score`, or `frame.quality_reasons`, and is a no-op for a
    /// frame with `subcarrier_count == 0`. The lengths of `amplitude` and
    /// `phase` are preserved.
    pub fn process_frame(&self, frame: &mut CsiFrame) {
        if frame.subcarrier_count == 0 || frame.amplitude.is_empty() {
            return;
        }

        // 1. Hampel outlier rejection on amplitude.
        if self.hampel_half_window > 0 {
            frame.amplitude =
                hampel_filter(&frame.amplitude, self.hampel_half_window, self.hampel_n_sigmas);
        }

        // 2. Moving-average smoothing on amplitude.
        if self.smoothing_window > 1 {
            frame.amplitude = moving_average(&frame.amplitude, self.smoothing_window);
        }

        // 3. DC-offset removal on amplitude.
        if self.remove_dc {
            remove_dc_offset(&mut frame.amplitude);
        }

        // 4. Baseline subtraction (only when lengths match).
        if let Some(baseline) = &self.baseline_amplitude {
            if baseline.len() == frame.amplitude.len() {
                for (a, b) in frame.amplitude.iter_mut().zip(baseline.iter()) {
                    *a -= *b;
                }
            }
        }

        // 5. Phase unwrap.
        if self.unwrap_phase {
            unwrap_phase(&mut frame.phase);
        }
    }

    /// Learn a per-subcarrier baseline amplitude from a batch of frames.
    ///
    /// Sets [`baseline_amplitude`](Self::baseline_amplitude) to the element-wise
    /// mean amplitude over the supplied frames, considering only frames whose
    /// `subcarrier_count` equals the first frame's and whose `amplitude` vector
    /// is non-empty. A no-op when `frames` is empty (or yields no usable frame).
    pub fn learn_baseline(&mut self, frames: &[CsiFrame]) {
        let Some(first) = frames.iter().find(|f| !f.amplitude.is_empty()) else {
            return;
        };
        let n = first.amplitude.len();
        let reference_count = first.subcarrier_count;
        let mut acc = vec![0.0f32; n];
        let mut used = 0usize;
        for f in frames {
            if f.subcarrier_count != reference_count || f.amplitude.len() != n {
                continue;
            }
            for (a, &v) in acc.iter_mut().zip(f.amplitude.iter()) {
                *a += v;
            }
            used += 1;
        }
        if used == 0 {
            return;
        }
        let used_f = used as f32;
        for a in acc.iter_mut() {
            *a /= used_f;
        }
        self.baseline_amplitude = Some(acc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{AdapterKind, FrameId, SessionId, SourceId, ValidationStatus};

    fn frame_with_amplitude(amp: Vec<f32>) -> CsiFrame {
        let n = amp.len();
        // Build a frame from I/Q so phase/amplitude are consistent, then
        // overwrite amplitude with the test fixture.
        let i: Vec<f32> = amp.clone();
        let q: Vec<f32> = vec![0.0; n];
        let mut f = CsiFrame::from_iq(
            FrameId(1),
            SessionId(1),
            SourceId::from("pipe-test"),
            AdapterKind::Synthetic,
            10_000,
            6,
            20,
            i,
            q,
        );
        f.amplitude = amp;
        f.phase = vec![0.0; n];
        // Pretend validation already ran.
        f.validation = ValidationStatus::Accepted;
        f.quality_score = 0.77;
        f.quality_reasons = vec!["fixture".to_string()];
        f
    }

    #[test]
    fn process_frame_removes_spike_and_preserves_validation() {
        let mut f = frame_with_amplitude(vec![5.0, 5.0, 5.0, 200.0, 5.0, 5.0, 5.0]);
        let n_before = f.amplitude.len();
        let pipe = SignalPipeline::default();
        pipe.process_frame(&mut f);
        assert_eq!(f.amplitude.len(), n_before);
        assert_eq!(f.phase.len(), n_before);
        // The huge spike must be gone: after hampel+smoothing+DC removal the
        // amplitude should be near zero everywhere (constant signal -> ~0 mean).
        for v in &f.amplitude {
            assert!(v.abs() < 1.0, "spike not removed, residual {v}");
        }
        // Validation state untouched.
        assert_eq!(f.validation, ValidationStatus::Accepted);
        assert!((f.quality_score - 0.77).abs() < 1e-6);
        assert_eq!(f.quality_reasons, vec!["fixture".to_string()]);
    }

    #[test]
    fn process_frame_is_noop_on_empty_frame() {
        let mut f = CsiFrame::from_iq(
            FrameId(2),
            SessionId(1),
            SourceId::from("empty"),
            AdapterKind::Synthetic,
            1,
            6,
            20,
            Vec::new(),
            Vec::new(),
        );
        f.validation = ValidationStatus::Degraded;
        let pipe = SignalPipeline::default();
        pipe.process_frame(&mut f);
        assert!(f.amplitude.is_empty());
        assert!(f.phase.is_empty());
        assert_eq!(f.validation, ValidationStatus::Degraded);
    }

    #[test]
    fn unwrap_phase_can_be_disabled() {
        let mut f = frame_with_amplitude(vec![1.0, 1.0, 1.0, 1.0]);
        f.phase = vec![0.0, 3.0, -3.0, 0.0];
        let pipe = SignalPipeline::default()
            .with_unwrap_phase(false)
            .with_hampel_half_window(0)
            .with_smoothing_window(0)
            .with_remove_dc(false);
        pipe.process_frame(&mut f);
        // phase left exactly as-is
        assert_eq!(f.phase, vec![0.0, 3.0, -3.0, 0.0]);
        // amplitude untouched too
        assert_eq!(f.amplitude, vec![1.0, 1.0, 1.0, 1.0]);
    }

    #[test]
    fn learn_baseline_then_process_subtracts_it() {
        // Three frames whose mean amplitude is [2, 4, 6, 8].
        let frames = vec![
            frame_with_amplitude(vec![1.0, 3.0, 5.0, 7.0]),
            frame_with_amplitude(vec![2.0, 4.0, 6.0, 8.0]),
            frame_with_amplitude(vec![3.0, 5.0, 7.0, 9.0]),
        ];
        let mut pipe = SignalPipeline::default()
            .with_hampel_half_window(0)
            .with_smoothing_window(0);
        pipe.learn_baseline(&frames);
        assert_eq!(pipe.baseline_amplitude, Some(vec![2.0, 4.0, 6.0, 8.0]));

        // Process a frame equal to the baseline. After DC removal (mean 5 ->
        // [-3,-1,1,3]) then baseline subtraction ([-3-2,-1-4,1-6,3-8] =
        // [-5,-5,-5,-5]) — the point is just that it's "small" and bounded.
        let mut f = frame_with_amplitude(vec![2.0, 4.0, 6.0, 8.0]);
        pipe.process_frame(&mut f);
        assert_eq!(f.amplitude.len(), 4);
        for v in &f.amplitude {
            assert!(v.abs() < 10.0, "baseline-subtracted residual too large: {v}");
        }
        // With DC removal turned off, a frame equal to the baseline goes to
        // exactly zero.
        let mut pipe2 = pipe.clone();
        pipe2.remove_dc = false;
        let mut f2 = frame_with_amplitude(vec![2.0, 4.0, 6.0, 8.0]);
        pipe2.process_frame(&mut f2);
        for v in &f2.amplitude {
            assert!(v.abs() < 1e-5, "expected ~0, got {v}");
        }
    }

    #[test]
    fn learn_baseline_ignores_mismatched_and_empty() {
        let frames = vec![
            frame_with_amplitude(vec![2.0, 2.0, 2.0]),
            frame_with_amplitude(vec![1.0, 2.0]), // wrong length -> ignored
            frame_with_amplitude(vec![4.0, 4.0, 4.0]),
        ];
        let mut pipe = SignalPipeline::default();
        pipe.learn_baseline(&frames);
        assert_eq!(pipe.baseline_amplitude, Some(vec![3.0, 3.0, 3.0]));

        // empty input -> no change
        let mut pipe2 = SignalPipeline::default();
        pipe2.learn_baseline(&[]);
        assert_eq!(pipe2.baseline_amplitude, None);
    }

    #[test]
    fn pipeline_is_deterministic() {
        let make = || frame_with_amplitude(vec![5.0, 6.0, 7.0, 50.0, 7.0, 6.0, 5.0]);
        let pipe = SignalPipeline::default();
        let mut a = make();
        let mut b = make();
        pipe.process_frame(&mut a);
        pipe.process_frame(&mut b);
        assert_eq!(a.amplitude, b.amplitude);
        assert_eq!(a.phase, b.phase);
    }
}

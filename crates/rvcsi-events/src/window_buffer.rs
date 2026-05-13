//! [`WindowBuffer`] — aggregates exposable [`CsiFrame`]s into [`CsiWindow`]s.

use rvcsi_core::{CsiFrame, CsiWindow, IdGenerator, SessionId, SourceId};

/// Tunables for a [`WindowBuffer`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowBufferConfig {
    /// Close the window once this many frames have been buffered. Must be `>= 2`.
    pub max_frames: usize,
    /// Close the window once `last_ts - first_ts >= max_duration_ns`.
    pub max_duration_ns: u64,
    /// Centre of the logistic that maps `motion_energy` to `presence_score`.
    pub presence_threshold: f32,
}

impl WindowBufferConfig {
    /// Build a config with a default `presence_threshold` of `0.05`.
    ///
    /// # Panics
    /// Panics if `max_frames < 2`.
    pub fn new(max_frames: usize, max_duration_ns: u64) -> Self {
        assert!(max_frames >= 2, "WindowBuffer max_frames must be >= 2");
        WindowBufferConfig {
            max_frames,
            max_duration_ns,
            presence_threshold: 0.05,
        }
    }

    /// Builder-style setter for [`WindowBufferConfig::presence_threshold`].
    pub fn with_presence_threshold(mut self, t: f32) -> Self {
        self.presence_threshold = t;
        self
    }
}

/// Buffers frames from one `(session_id, source_id)` and emits windows.
///
/// Use [`WindowBuffer::push`] for each incoming frame; it returns `Some(window)`
/// on the frame that closes a window (that frame being the last in the window).
/// Call [`WindowBuffer::flush`] at end-of-stream to drain whatever is buffered.
#[derive(Debug, Clone)]
pub struct WindowBuffer {
    session_id: SessionId,
    source_id: SourceId,
    cfg: WindowBufferConfig,
    /// Subcarrier count fixed by the first buffered frame of the current window.
    subcarrier_count: Option<u16>,
    /// Buffered `amplitude` vectors (one per accepted frame).
    amplitudes: Vec<Vec<f32>>,
    /// Buffered `phase` vectors (one per accepted frame).
    phases: Vec<Vec<f32>>,
    /// Buffered `quality_score`s.
    qualities: Vec<f32>,
    /// Buffered timestamps (ns).
    timestamps: Vec<u64>,
}

impl WindowBuffer {
    /// Create a buffer for `session_id` / `source_id` with the given thresholds.
    ///
    /// # Panics
    /// Panics if `max_frames < 2`.
    pub fn new(
        session_id: SessionId,
        source_id: SourceId,
        max_frames: usize,
        max_duration_ns: u64,
    ) -> Self {
        Self::with_config(
            session_id,
            source_id,
            WindowBufferConfig::new(max_frames, max_duration_ns),
        )
    }

    /// Create a buffer from a [`WindowBufferConfig`].
    ///
    /// # Panics
    /// Panics if `cfg.max_frames < 2`.
    pub fn with_config(session_id: SessionId, source_id: SourceId, cfg: WindowBufferConfig) -> Self {
        assert!(cfg.max_frames >= 2, "WindowBuffer max_frames must be >= 2");
        WindowBuffer {
            session_id,
            source_id,
            cfg,
            subcarrier_count: None,
            amplitudes: Vec::new(),
            phases: Vec::new(),
            qualities: Vec::new(),
            timestamps: Vec::new(),
        }
    }

    /// Number of frames currently buffered (not yet emitted as a window).
    pub fn pending_frame_count(&self) -> usize {
        self.amplitudes.len()
    }

    /// Add a frame; returns `Some(window)` if this frame closed a window.
    ///
    /// Frames are skipped (returning `None`, not buffered) when:
    /// * `!frame.is_exposable()`,
    /// * the frame's `session_id` / `source_id` don't match the buffer's, or
    /// * the frame's `subcarrier_count` differs from the first buffered frame's.
    pub fn push(&mut self, frame: &CsiFrame, ids: &IdGenerator) -> Option<CsiWindow> {
        if !frame.is_exposable() {
            return None;
        }
        if frame.session_id != self.session_id || frame.source_id != self.source_id {
            return None;
        }
        match self.subcarrier_count {
            None => self.subcarrier_count = Some(frame.subcarrier_count),
            Some(n) if n != frame.subcarrier_count => return None,
            Some(_) => {}
        }

        self.amplitudes.push(frame.amplitude.clone());
        self.phases.push(frame.phase.clone());
        self.qualities.push(frame.quality_score);
        self.timestamps.push(frame.timestamp_ns);

        let reached_count = self.amplitudes.len() >= self.cfg.max_frames;
        let reached_duration = match (self.timestamps.first(), self.timestamps.last()) {
            (Some(&first), Some(&last)) => last.saturating_sub(first) >= self.cfg.max_duration_ns,
            _ => false,
        };
        if reached_count || reached_duration {
            Some(self.close(ids))
        } else {
            None
        }
    }

    /// Drain whatever is buffered (>= 1 frame) into a final window.
    ///
    /// Returns `None` when the buffer is empty.
    pub fn flush(&mut self, ids: &IdGenerator) -> Option<CsiWindow> {
        if self.amplitudes.is_empty() {
            None
        } else {
            Some(self.close(ids))
        }
    }

    /// Build the [`CsiWindow`] from the buffered frames and reset the buffer.
    fn close(&mut self, ids: &IdGenerator) -> CsiWindow {
        let frame_count = self.amplitudes.len();
        debug_assert!(frame_count >= 1, "close() called on an empty buffer");
        let n = self.subcarrier_count.unwrap_or(0) as usize;

        // Per-subcarrier mean amplitude.
        let mut mean_amplitude = vec![0.0f32; n];
        for amp in &self.amplitudes {
            for (slot, a) in mean_amplitude.iter_mut().zip(amp.iter()) {
                *slot += *a;
            }
        }
        for v in &mut mean_amplitude {
            *v /= frame_count as f32;
        }

        // Per-subcarrier population variance of the phase.
        let mut phase_mean = vec![0.0f32; n];
        for ph in &self.phases {
            for (slot, p) in phase_mean.iter_mut().zip(ph.iter()) {
                *slot += *p;
            }
        }
        for v in &mut phase_mean {
            *v /= frame_count as f32;
        }
        let mut phase_variance = vec![0.0f32; n];
        for ph in &self.phases {
            for k in 0..n {
                let d = ph.get(k).copied().unwrap_or(0.0) - phase_mean[k];
                phase_variance[k] += d * d;
            }
        }
        for v in &mut phase_variance {
            *v /= frame_count as f32;
        }

        // Motion energy: mean over consecutive pairs of ||amp_b - amp_a||_2 / sqrt(n).
        let motion_energy = if frame_count < 2 || n == 0 {
            0.0
        } else {
            let mut acc = 0.0f64;
            for w in self.amplitudes.windows(2) {
                let (a, b) = (&w[0], &w[1]);
                let mut sq = 0.0f64;
                for k in 0..n {
                    let d = (b.get(k).copied().unwrap_or(0.0) - a.get(k).copied().unwrap_or(0.0))
                        as f64;
                    sq += d * d;
                }
                acc += sq.sqrt() / (n as f64).sqrt();
            }
            (acc / (frame_count - 1) as f64) as f32
        };
        let motion_energy = if motion_energy.is_finite() && motion_energy >= 0.0 {
            motion_energy
        } else {
            0.0
        };

        // Presence score: logistic of (motion_energy - threshold).
        let z = (motion_energy - self.cfg.presence_threshold) * 8.0;
        let presence_score = (1.0 / (1.0 + (-z).exp())).clamp(0.0, 1.0);

        // Quality score: mean of frame quality scores.
        let quality_sum: f32 = self.qualities.iter().sum();
        let quality_score = (quality_sum / frame_count as f32).clamp(0.0, 1.0);

        let start_ns = *self.timestamps.first().unwrap();
        let raw_end = *self.timestamps.last().unwrap();
        // Edge case: a single-frame window would have start_ns == end_ns, which
        // CsiWindow::validate() rejects. Bump the end by 1 ns so it stays valid.
        let end_ns = if raw_end > start_ns { raw_end } else { start_ns + 1 };

        let window = CsiWindow {
            window_id: ids.next_window(),
            session_id: self.session_id,
            source_id: self.source_id.clone(),
            start_ns,
            end_ns,
            frame_count: frame_count as u32,
            mean_amplitude,
            phase_variance,
            motion_energy,
            presence_score,
            quality_score,
        };
        debug_assert!(
            window.validate().is_ok(),
            "WindowBuffer produced an invalid CsiWindow: {:?}",
            window.validate()
        );

        // Reset for the next window.
        self.subcarrier_count = None;
        self.amplitudes.clear();
        self.phases.clear();
        self.qualities.clear();
        self.timestamps.clear();

        window
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{AdapterKind, FrameId, ValidationStatus};

    fn frame(
        session: u64,
        source: &str,
        frame_id: u64,
        ts: u64,
        amp: &[f32],
        quality: f32,
    ) -> CsiFrame {
        // Build I/Q so that amplitude == amp and phase == 0.
        let i: Vec<f32> = amp.to_vec();
        let q: Vec<f32> = vec![0.0; amp.len()];
        let mut f = CsiFrame::from_iq(
            FrameId(frame_id),
            SessionId(session),
            SourceId::from(source),
            AdapterKind::Synthetic,
            ts,
            6,
            20,
            i,
            q,
        );
        f.validation = ValidationStatus::Accepted;
        f.quality_score = quality;
        f
    }

    #[test]
    fn closes_after_exactly_max_frames() {
        let g = IdGenerator::new();
        let mut buf = WindowBuffer::new(SessionId(0), SourceId::from("s"), 4, u64::MAX);
        let amp = [1.0f32, 1.0, 1.0];
        assert!(buf.push(&frame(0, "s", 0, 0, &amp, 0.9), &g).is_none());
        assert!(buf.push(&frame(0, "s", 1, 10, &amp, 0.9), &g).is_none());
        assert!(buf.push(&frame(0, "s", 2, 20, &amp, 0.9), &g).is_none());
        assert_eq!(buf.pending_frame_count(), 3);
        let w = buf.push(&frame(0, "s", 3, 30, &amp, 0.9), &g).expect("window");
        assert_eq!(w.frame_count, 4);
        assert_eq!(buf.pending_frame_count(), 0);
        assert!(w.validate().is_ok());
    }

    #[test]
    fn closes_on_duration_with_fewer_frames() {
        let g = IdGenerator::new();
        let mut buf = WindowBuffer::new(SessionId(0), SourceId::from("s"), 100, 1_000);
        let amp = [1.0f32, 2.0];
        assert!(buf.push(&frame(0, "s", 0, 0, &amp, 0.8), &g).is_none());
        assert!(buf.push(&frame(0, "s", 1, 500, &amp, 0.8), &g).is_none());
        let w = buf
            .push(&frame(0, "s", 2, 1_000, &amp, 0.8), &g)
            .expect("window closed on duration");
        assert_eq!(w.frame_count, 3);
        assert_eq!(w.start_ns, 0);
        assert_eq!(w.end_ns, 1_000);
        assert!(w.validate().is_ok());
    }

    #[test]
    fn flush_returns_remainder_and_handles_single_frame() {
        let g = IdGenerator::new();
        let mut buf = WindowBuffer::new(SessionId(0), SourceId::from("s"), 10, u64::MAX);
        let amp = [1.0f32, 1.0];
        assert!(buf.push(&frame(0, "s", 0, 100, &amp, 0.7), &g).is_none());
        let w = buf.flush(&g).expect("flush returns the single buffered frame");
        assert_eq!(w.frame_count, 1);
        assert_eq!(w.start_ns, 100);
        assert_eq!(w.end_ns, 101); // bumped so validate() passes
        assert_eq!(w.motion_energy, 0.0);
        assert!(w.validate().is_ok());
        assert!(buf.flush(&g).is_none());
    }

    #[test]
    fn skips_mismatched_session_and_source() {
        let g = IdGenerator::new();
        let mut buf = WindowBuffer::new(SessionId(7), SourceId::from("good"), 4, u64::MAX);
        let amp = [1.0f32, 1.0];
        assert!(buf.push(&frame(7, "good", 0, 0, &amp, 0.9), &g).is_none());
        // Wrong session.
        assert!(buf.push(&frame(8, "good", 1, 10, &amp, 0.9), &g).is_none());
        // Wrong source.
        assert!(buf.push(&frame(7, "bad", 2, 20, &amp, 0.9), &g).is_none());
        assert_eq!(buf.pending_frame_count(), 1);
    }

    #[test]
    fn skips_non_exposable_and_mismatched_subcarrier_count() {
        let g = IdGenerator::new();
        let mut buf = WindowBuffer::new(SessionId(0), SourceId::from("s"), 4, u64::MAX);
        // Non-exposable frame is dropped.
        let mut bad = frame(0, "s", 0, 0, &[1.0, 1.0], 0.9);
        bad.validation = ValidationStatus::Pending;
        assert!(buf.push(&bad, &g).is_none());
        assert_eq!(buf.pending_frame_count(), 0);
        // First good frame fixes subcarrier count = 2.
        assert!(buf.push(&frame(0, "s", 1, 10, &[1.0, 1.0], 0.9), &g).is_none());
        // Different subcarrier count is dropped.
        assert!(buf
            .push(&frame(0, "s", 2, 20, &[1.0, 1.0, 1.0], 0.9), &g)
            .is_none());
        assert_eq!(buf.pending_frame_count(), 1);
    }

    #[test]
    fn identical_frames_have_zero_motion_low_presence() {
        let g = IdGenerator::new();
        let mut buf = WindowBuffer::new(SessionId(0), SourceId::from("s"), 8, u64::MAX);
        let amp = [1.0f32; 32];
        let mut last = None;
        for k in 0..8u64 {
            last = buf.push(&frame(0, "s", k, k * 10, &amp, 0.9), &g);
        }
        let w = last.expect("window");
        assert_eq!(w.motion_energy, 0.0);
        assert!(w.presence_score < 0.5, "presence_score = {}", w.presence_score);
        assert!(w.validate().is_ok());
    }

    #[test]
    fn growing_jitter_raises_motion_and_presence() {
        let g = IdGenerator::new();
        let mut buf = WindowBuffer::new(SessionId(0), SourceId::from("s"), 16, u64::MAX);
        // Large alternating jitter -> high motion energy.
        let mut last = None;
        for k in 0..16u64 {
            let bump = if k % 2 == 0 { 0.0 } else { 1.0 };
            let amp: Vec<f32> = (0..32).map(|_| 1.0 + bump).collect();
            last = buf.push(&frame(0, "s", k, k * 10, &amp, 0.9), &g);
        }
        let w = last.expect("window");
        assert!(w.motion_energy > 0.1, "motion_energy = {}", w.motion_energy);
        assert!(w.presence_score > 0.5, "presence_score = {}", w.presence_score);
        assert!(w.validate().is_ok());
    }
}

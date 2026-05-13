//! [`EventPipeline`] — wires a [`WindowBuffer`] to a set of [`EventDetector`]s.
//!
//! A pipeline owns its own [`IdGenerator`] so window/event ids are minted in a
//! deterministic order. Feed it frames with [`EventPipeline::process_frame`]
//! and drain the tail with [`EventPipeline::flush`].

use rvcsi_core::{CsiEvent, CsiFrame, CsiWindow, IdGenerator, SessionId, SourceId};

use crate::detectors::{
    BaselineDriftDetector, EventDetector, MotionDetector, PresenceDetector, QualityDetector,
};
use crate::window_buffer::{WindowBuffer, WindowBufferConfig};

/// How many recently-closed windows the pipeline keeps for inspection.
const RECENT_WINDOW_CAP: usize = 32;

/// Aggregates frames into windows and runs detectors over them.
pub struct EventPipeline {
    buffer: WindowBuffer,
    detectors: Vec<Box<dyn EventDetector>>,
    ids: IdGenerator,
    recent: Vec<CsiWindow>,
}

impl core::fmt::Debug for EventPipeline {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventPipeline")
            .field("detectors", &self.detectors.iter().map(|d| d.name()).collect::<Vec<_>>())
            .field("pending_frame_count", &self.buffer.pending_frame_count())
            .field("recent_windows", &self.recent.len())
            .finish()
    }
}

impl EventPipeline {
    /// New pipeline with the given window-buffer config and no detectors.
    ///
    /// Add detectors with [`EventPipeline::add_detector`].
    pub fn new(session_id: SessionId, source_id: SourceId, buffer_cfg: WindowBufferConfig) -> Self {
        EventPipeline {
            buffer: WindowBuffer::with_config(session_id, source_id, buffer_cfg),
            detectors: Vec::new(),
            ids: IdGenerator::new(),
            recent: Vec::new(),
        }
    }

    /// New pipeline with the four default detectors and a 16-frame / 1-second
    /// window buffer.
    pub fn with_defaults(session_id: SessionId, source_id: SourceId) -> Self {
        let mut p = Self::new(
            session_id,
            source_id,
            WindowBufferConfig::new(16, 1_000_000_000),
        );
        p.add_detector(Box::new(PresenceDetector::new()));
        p.add_detector(Box::new(MotionDetector::new()));
        p.add_detector(Box::new(QualityDetector::new()));
        p.add_detector(Box::new(BaselineDriftDetector::new()));
        p
    }

    /// Append a detector. Detectors run in insertion order on every window.
    pub fn add_detector(&mut self, detector: Box<dyn EventDetector>) {
        self.detectors.push(detector);
    }

    /// Names of the registered detectors, in order.
    pub fn detector_names(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.name()).collect()
    }

    /// The most-recently-closed windows (newest last), capped at 32.
    pub fn recent_windows(&self) -> &[CsiWindow] {
        &self.recent
    }

    /// Frames buffered but not yet emitted as a window.
    pub fn pending_frame_count(&self) -> usize {
        self.buffer.pending_frame_count()
    }

    /// Push one frame; if it closes a window, run every detector on that window
    /// and return their concatenated events. Otherwise return an empty `Vec`.
    pub fn process_frame(&mut self, frame: &CsiFrame) -> Vec<CsiEvent> {
        match self.buffer.push(frame, &self.ids) {
            Some(window) => self.run_detectors(window),
            None => Vec::new(),
        }
    }

    /// Close whatever frames remain in the buffer into a final window and run
    /// detectors on it. Returns an empty `Vec` if the buffer was empty.
    pub fn flush(&mut self) -> Vec<CsiEvent> {
        match self.buffer.flush(&self.ids) {
            Some(window) => self.run_detectors(window),
            None => Vec::new(),
        }
    }

    fn run_detectors(&mut self, window: CsiWindow) -> Vec<CsiEvent> {
        let mut events = Vec::new();
        for d in &mut self.detectors {
            events.extend(d.on_window(&window, &self.ids));
        }
        debug_assert!(events.iter().all(|e| e.validate().is_ok()));
        self.recent.push(window);
        if self.recent.len() > RECENT_WINDOW_CAP {
            let overflow = self.recent.len() - RECENT_WINDOW_CAP;
            self.recent.drain(0..overflow);
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{AdapterKind, CsiEventKind, FrameId, ValidationStatus};

    /// Deterministic LCG (Numerical Recipes constants) -> `[0.0, 1.0)`.
    struct Lcg(u64);
    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed)
        }
        fn next_unit(&mut self) -> f32 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            // top 24 bits -> [0,1)
            ((self.0 >> 40) as f32) / (1u64 << 24) as f32
        }
    }

    fn accepted_frame(frame_id: u64, ts: u64, amp: &[f32], quality: f32) -> CsiFrame {
        let i: Vec<f32> = amp.to_vec();
        let q: Vec<f32> = vec![0.0; amp.len()];
        let mut f = CsiFrame::from_iq(
            FrameId(frame_id),
            SessionId(1),
            SourceId::from("dev"),
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

    /// Build a quiet / active / quiet frame stream with monotonic 50 ms
    /// timestamps. Long enough that the default 16-frame window buffer yields
    /// enough windows for the detectors' debounce / hysteresis chains.
    fn synthetic_stream() -> Vec<CsiFrame> {
        let mut rng = Lcg::new(0xC0FFEE);
        let mut frames = Vec::new();
        let dt = 50_000_000u64; // 50 ms
        let quiet_a = 30u64;
        let active = 60u64;
        let quiet_b = 60u64;
        let total = quiet_a + active + quiet_b;
        for k in 0..total {
            let ts = k * dt;
            let is_active = (quiet_a..quiet_a + active).contains(&k);
            let amp: Vec<f32> = (0..32)
                .map(|_| {
                    if is_active {
                        // Large per-frame jitter.
                        1.0 + (rng.next_unit() - 0.5) * 4.0
                    } else {
                        // Tiny deterministic noise around 1.0.
                        1.0 + (rng.next_unit() - 0.5) * 0.001
                    }
                })
                .collect();
            frames.push(accepted_frame(k, ts, &amp, 0.9));
        }
        frames
    }

    fn run_stream(frames: &[CsiFrame]) -> Vec<CsiEvent> {
        let mut p = EventPipeline::with_defaults(SessionId(1), SourceId::from("dev"));
        let mut events = Vec::new();
        for f in frames {
            events.extend(p.process_frame(f));
        }
        events.extend(p.flush());
        events
    }

    #[test]
    fn pipeline_detects_motion_and_presence_and_settles() {
        let frames = synthetic_stream();
        let events = run_stream(&frames);
        assert!(!events.is_empty(), "expected some events");
        for e in &events {
            assert!(e.validate().is_ok(), "invalid event: {e:?}");
        }
        let kinds: Vec<CsiEventKind> = events.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&CsiEventKind::MotionDetected), "kinds = {kinds:?}");
        assert!(kinds.contains(&CsiEventKind::PresenceStarted), "kinds = {kinds:?}");
        assert!(kinds.contains(&CsiEventKind::MotionSettled), "kinds = {kinds:?}");
        assert!(kinds.contains(&CsiEventKind::PresenceEnded), "kinds = {kinds:?}");

        // MotionDetected should come before MotionSettled.
        let det = events.iter().position(|e| e.kind == CsiEventKind::MotionDetected).unwrap();
        let set = events.iter().position(|e| e.kind == CsiEventKind::MotionSettled).unwrap();
        assert!(det < set);
        let start = events.iter().position(|e| e.kind == CsiEventKind::PresenceStarted).unwrap();
        let end = events.iter().position(|e| e.kind == CsiEventKind::PresenceEnded).unwrap();
        assert!(start < end);
    }

    #[test]
    fn pipeline_is_deterministic() {
        let frames = synthetic_stream();
        let a = run_stream(&frames);
        let b = run_stream(&frames);
        assert_eq!(a, b, "same stream must yield identical events");
    }

    #[test]
    fn pipeline_recent_windows_and_pending_count() {
        let mut p = EventPipeline::with_defaults(SessionId(1), SourceId::from("dev"));
        let amp = vec![1.0f32; 32];
        // Two windows worth of frames (16 each at the 16-frame cap).
        for k in 0..16u64 {
            p.process_frame(&accepted_frame(k, k * 10_000, &amp, 0.9));
        }
        assert_eq!(p.recent_windows().len(), 1);
        assert_eq!(p.pending_frame_count(), 0);
        p.process_frame(&accepted_frame(16, 200_000, &amp, 0.9));
        assert_eq!(p.pending_frame_count(), 1);
        let leftover = p.flush();
        let _ = leftover;
        assert_eq!(p.recent_windows().len(), 2);
        assert_eq!(p.pending_frame_count(), 0);
    }

    #[test]
    fn pipeline_skips_foreign_frames() {
        let mut p = EventPipeline::with_defaults(SessionId(1), SourceId::from("dev"));
        let amp = vec![1.0f32; 8];
        let mut foreign = accepted_frame(0, 0, &amp, 0.9);
        foreign.session_id = SessionId(99);
        assert!(p.process_frame(&foreign).is_empty());
        assert_eq!(p.pending_frame_count(), 0);
    }

    #[test]
    fn detector_names_in_order() {
        let p = EventPipeline::with_defaults(SessionId(1), SourceId::from("dev"));
        assert_eq!(
            p.detector_names(),
            vec!["presence", "motion", "quality", "baseline_drift"]
        );
    }
}

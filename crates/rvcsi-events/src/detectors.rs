//! Event detectors — small deterministic state machines over [`CsiWindow`]s.
//!
//! Every detector implements [`EventDetector`]; an [`crate::EventPipeline`]
//! runs each in turn on every closed window and concatenates the emitted
//! [`CsiEvent`]s. Detectors are intentionally tiny and side-effect-free: the
//! only state they keep is the bare minimum to debounce / hysteresis-gate, so
//! replaying the same window stream is fully deterministic.

use rvcsi_core::{CsiEvent, CsiEventKind, CsiWindow, IdGenerator, WindowId};

/// Consumes [`CsiWindow`]s and emits [`CsiEvent`]s.
pub trait EventDetector {
    /// Process one window; return any events it triggers (possibly empty).
    fn on_window(&mut self, window: &CsiWindow, ids: &IdGenerator) -> Vec<CsiEvent>;

    /// Stable name for logging / inspection.
    fn name(&self) -> &'static str;
}

/// Build a single-window-evidence [`CsiEvent`] (validated in debug builds).
fn make_event(
    ids: &IdGenerator,
    kind: CsiEventKind,
    window: &CsiWindow,
    timestamp_ns: u64,
    confidence: f32,
) -> CsiEvent {
    let evidence: Vec<WindowId> = vec![window.window_id];
    let confidence = confidence.clamp(0.0, 1.0);
    let event = CsiEvent::new(
        ids.next_event(),
        kind,
        window.session_id,
        window.source_id.clone(),
        timestamp_ns,
        confidence,
        evidence,
    );
    debug_assert!(
        event.validate().is_ok(),
        "detector produced an invalid CsiEvent: {:?}",
        event.validate()
    );
    event
}

// ---------------------------------------------------------------------------
// PresenceDetector
// ---------------------------------------------------------------------------

/// Tunables for [`PresenceDetector`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PresenceConfig {
    /// Enter `Present` when `presence_score >= on_threshold` for `enter_windows` windows.
    pub on_threshold: f32,
    /// Exit to `Absent` when `presence_score <= off_threshold` for `exit_windows` windows.
    pub off_threshold: f32,
    /// Consecutive high windows required to declare presence.
    pub enter_windows: u32,
    /// Consecutive low windows required to declare absence.
    pub exit_windows: u32,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        // A truly quiet window has `presence_score ≈ 0.40` (the
        // `WindowBuffer` logistic floor at zero motion), so `off_threshold`
        // sits just above that and `on_threshold` well above it.
        PresenceConfig {
            on_threshold: 0.7,
            off_threshold: 0.45,
            enter_windows: 2,
            exit_windows: 3,
        }
    }
}

impl PresenceConfig {
    /// Validate the relationship `on_threshold > off_threshold` and positivity.
    fn checked(self) -> Self {
        assert!(
            self.on_threshold > self.off_threshold,
            "PresenceConfig requires on_threshold > off_threshold"
        );
        assert!(self.enter_windows >= 1 && self.exit_windows >= 1);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PresenceState {
    Absent,
    Present,
}

/// Hysteresis state machine over [`CsiWindow::presence_score`].
///
/// Emits a single [`CsiEventKind::PresenceStarted`] when the score has been
/// high for `enter_windows` consecutive windows, and a single
/// [`CsiEventKind::PresenceEnded`] when it has been low for `exit_windows`
/// consecutive windows. A window that breaks the streak resets the counter.
#[derive(Debug, Clone)]
pub struct PresenceDetector {
    cfg: PresenceConfig,
    state: PresenceState,
    streak: u32,
}

impl Default for PresenceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceDetector {
    /// New detector with default thresholds.
    pub fn new() -> Self {
        Self::with_config(PresenceConfig::default())
    }

    /// New detector with explicit config.
    ///
    /// # Panics
    /// Panics if `on_threshold <= off_threshold` or a window count is zero.
    pub fn with_config(cfg: PresenceConfig) -> Self {
        PresenceDetector {
            cfg: cfg.checked(),
            state: PresenceState::Absent,
            streak: 0,
        }
    }
}

impl EventDetector for PresenceDetector {
    fn on_window(&mut self, window: &CsiWindow, ids: &IdGenerator) -> Vec<CsiEvent> {
        let p = window.presence_score;
        match self.state {
            PresenceState::Absent => {
                if p >= self.cfg.on_threshold {
                    self.streak += 1;
                    if self.streak >= self.cfg.enter_windows {
                        self.state = PresenceState::Present;
                        self.streak = 0;
                        return vec![make_event(
                            ids,
                            CsiEventKind::PresenceStarted,
                            window,
                            window.end_ns,
                            p,
                        )];
                    }
                } else {
                    self.streak = 0;
                }
            }
            PresenceState::Present => {
                if p <= self.cfg.off_threshold {
                    self.streak += 1;
                    if self.streak >= self.cfg.exit_windows {
                        self.state = PresenceState::Absent;
                        self.streak = 0;
                        return vec![make_event(
                            ids,
                            CsiEventKind::PresenceEnded,
                            window,
                            window.end_ns,
                            (1.0 - p).clamp(0.0, 1.0),
                        )];
                    }
                } else {
                    self.streak = 0;
                }
            }
        }
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "presence"
    }
}

// ---------------------------------------------------------------------------
// MotionDetector
// ---------------------------------------------------------------------------

/// Tunables for [`MotionDetector`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MotionConfig {
    /// Rising-edge threshold on `motion_energy`.
    pub on_threshold: f32,
    /// Falling-edge threshold on `motion_energy` (`< on_threshold`).
    pub off_threshold: f32,
    /// Consecutive windows above/below the relevant threshold before firing.
    pub debounce_windows: u32,
}

impl Default for MotionConfig {
    fn default() -> Self {
        MotionConfig {
            on_threshold: 0.05,
            off_threshold: 0.02,
            debounce_windows: 2,
        }
    }
}

impl MotionConfig {
    fn checked(self) -> Self {
        assert!(
            self.on_threshold > self.off_threshold,
            "MotionConfig requires on_threshold > off_threshold"
        );
        assert!(self.debounce_windows >= 1);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MotionState {
    Settled,
    Moving,
}

/// State machine over [`CsiWindow::motion_energy`].
///
/// Emits [`CsiEventKind::MotionDetected`] on a debounced rising edge and
/// [`CsiEventKind::MotionSettled`] on a debounced falling edge.
#[derive(Debug, Clone)]
pub struct MotionDetector {
    cfg: MotionConfig,
    state: MotionState,
    streak: u32,
}

impl Default for MotionDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MotionDetector {
    /// New detector with default thresholds.
    pub fn new() -> Self {
        Self::with_config(MotionConfig::default())
    }

    /// New detector with explicit config.
    ///
    /// # Panics
    /// Panics if `on_threshold <= off_threshold` or `debounce_windows == 0`.
    pub fn with_config(cfg: MotionConfig) -> Self {
        MotionDetector {
            cfg: cfg.checked(),
            state: MotionState::Settled,
            streak: 0,
        }
    }
}

impl EventDetector for MotionDetector {
    fn on_window(&mut self, window: &CsiWindow, ids: &IdGenerator) -> Vec<CsiEvent> {
        let m = window.motion_energy;
        match self.state {
            MotionState::Settled => {
                if m > self.cfg.on_threshold {
                    self.streak += 1;
                    if self.streak >= self.cfg.debounce_windows {
                        self.state = MotionState::Moving;
                        self.streak = 0;
                        let conf = (m / (2.0 * self.cfg.on_threshold)).clamp(0.0, 1.0);
                        return vec![make_event(
                            ids,
                            CsiEventKind::MotionDetected,
                            window,
                            window.end_ns,
                            conf,
                        )];
                    }
                } else {
                    self.streak = 0;
                }
            }
            MotionState::Moving => {
                if m < self.cfg.off_threshold {
                    self.streak += 1;
                    if self.streak >= self.cfg.debounce_windows {
                        self.state = MotionState::Settled;
                        self.streak = 0;
                        let rise = (m / (2.0 * self.cfg.on_threshold)).clamp(0.0, 1.0);
                        return vec![make_event(
                            ids,
                            CsiEventKind::MotionSettled,
                            window,
                            window.end_ns,
                            (1.0 - rise).clamp(0.0, 1.0),
                        )];
                    }
                } else {
                    self.streak = 0;
                }
            }
        }
        Vec::new()
    }

    fn name(&self) -> &'static str {
        "motion"
    }
}

// ---------------------------------------------------------------------------
// QualityDetector
// ---------------------------------------------------------------------------

/// Tunables for [`QualityDetector`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QualityConfig {
    /// `quality_score` below this (debounced) raises [`CsiEventKind::SignalQualityDropped`].
    pub drop_threshold: f32,
    /// Consecutive low windows before [`CsiEventKind::SignalQualityDropped`] fires.
    pub debounce_windows: u32,
    /// Consecutive low windows (counting from the first low one) before
    /// [`CsiEventKind::CalibrationRequired`] also fires — once per low stretch.
    pub calib_windows: u32,
}

impl Default for QualityConfig {
    fn default() -> Self {
        QualityConfig {
            drop_threshold: 0.4,
            debounce_windows: 2,
            calib_windows: 4,
        }
    }
}

impl QualityConfig {
    fn checked(self) -> Self {
        assert!(self.debounce_windows >= 1 && self.calib_windows >= 1);
        self
    }
}

/// State machine over [`CsiWindow::quality_score`].
///
/// While `quality_score` stays below `drop_threshold` it counts a low streak.
/// At `debounce_windows` it emits [`CsiEventKind::SignalQualityDropped`]; at
/// `calib_windows` it additionally emits [`CsiEventKind::CalibrationRequired`]
/// (only once until quality recovers). Any window at or above `drop_threshold`
/// resets the streak and re-arms both events.
#[derive(Debug, Clone)]
pub struct QualityDetector {
    cfg: QualityConfig,
    low_streak: u32,
    dropped_emitted: bool,
    calib_emitted: bool,
}

impl Default for QualityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl QualityDetector {
    /// New detector with default thresholds.
    pub fn new() -> Self {
        Self::with_config(QualityConfig::default())
    }

    /// New detector with explicit config.
    pub fn with_config(cfg: QualityConfig) -> Self {
        QualityDetector {
            cfg: cfg.checked(),
            low_streak: 0,
            dropped_emitted: false,
            calib_emitted: false,
        }
    }
}

impl EventDetector for QualityDetector {
    fn on_window(&mut self, window: &CsiWindow, ids: &IdGenerator) -> Vec<CsiEvent> {
        let q = window.quality_score;
        if q < self.cfg.drop_threshold {
            self.low_streak += 1;
            let mut out = Vec::new();
            if !self.dropped_emitted && self.low_streak >= self.cfg.debounce_windows {
                self.dropped_emitted = true;
                out.push(make_event(
                    ids,
                    CsiEventKind::SignalQualityDropped,
                    window,
                    window.end_ns,
                    (1.0 - q).clamp(0.0, 1.0),
                ));
            }
            if !self.calib_emitted && self.low_streak >= self.cfg.calib_windows {
                self.calib_emitted = true;
                out.push(make_event(
                    ids,
                    CsiEventKind::CalibrationRequired,
                    window,
                    window.end_ns,
                    (1.0 - q).clamp(0.0, 1.0),
                ));
            }
            out
        } else {
            self.low_streak = 0;
            self.dropped_emitted = false;
            self.calib_emitted = false;
            Vec::new()
        }
    }

    fn name(&self) -> &'static str {
        "quality"
    }
}

// ---------------------------------------------------------------------------
// BaselineDriftDetector
// ---------------------------------------------------------------------------

/// Tunables for [`BaselineDriftDetector`].
///
/// `drift_threshold` and `anomaly_threshold` are **relative** — they are
/// fractions of the running baseline's RMS magnitude, not absolute amplitude
/// units. This keeps the detector source-agnostic: ESP32 emits raw `int8` I/Q
/// (amplitudes up to ~128), Nexmon emits `int16`-scaled CSI, and a
/// baseline-subtracted pipeline emits values near zero — an *absolute* threshold
/// can only ever be right for one of them, a *relative* one is right for all.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BaselineDriftConfig {
    /// Relative per-window drift `||mean_amplitude - baseline||_2 / ||baseline||_2`
    /// above this for `drift_windows` windows in a row triggers
    /// [`CsiEventKind::BaselineChanged`]. `0.15` ≈ "the room moved ~15 %".
    pub drift_threshold: f32,
    /// Consecutive drifting windows before [`CsiEventKind::BaselineChanged`] fires.
    pub drift_windows: u32,
    /// A single window whose relative drift exceeds this (much larger) value
    /// triggers [`CsiEventKind::AnomalyDetected`]. `1.0` ≈ "this window differs
    /// from the baseline by as much as the baseline's own magnitude".
    pub anomaly_threshold: f32,
    /// EWMA smoothing factor for the running baseline (`baseline = a*current + (1-a)*baseline`).
    pub ewma_alpha: f32,
}

impl Default for BaselineDriftConfig {
    fn default() -> Self {
        BaselineDriftConfig {
            drift_threshold: 0.15,
            drift_windows: 3,
            anomaly_threshold: 1.0,
            ewma_alpha: 0.1,
        }
    }
}

impl BaselineDriftConfig {
    fn checked(self) -> Self {
        assert!(self.drift_windows >= 1);
        assert!(self.anomaly_threshold > self.drift_threshold);
        assert!(self.ewma_alpha > 0.0 && self.ewma_alpha <= 1.0);
        self
    }
}

/// Tracks an EWMA baseline of `mean_amplitude` and flags sustained drift /
/// single-window anomalies.
#[derive(Debug, Clone)]
pub struct BaselineDriftDetector {
    cfg: BaselineDriftConfig,
    baseline: Option<Vec<f32>>,
    drift_streak: u32,
}

impl Default for BaselineDriftDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BaselineDriftDetector {
    /// New detector with default thresholds.
    pub fn new() -> Self {
        Self::with_config(BaselineDriftConfig::default())
    }

    /// New detector with explicit config.
    pub fn with_config(cfg: BaselineDriftConfig) -> Self {
        BaselineDriftDetector {
            cfg: cfg.checked(),
            baseline: None,
            drift_streak: 0,
        }
    }

    /// L2 distance between two equal-length vectors, normalized by `sqrt(len)`.
    fn rms_distance(a: &[f32], b: &[f32]) -> f32 {
        let n = a.len();
        if n == 0 {
            return 0.0;
        }
        let mut sq = 0.0f64;
        for k in 0..n {
            let d = (a[k] - b[k]) as f64;
            sq += d * d;
        }
        (sq.sqrt() / (n as f64).sqrt()) as f32
    }

    /// Root-mean-square magnitude of a vector (`0.0` for an empty one).
    fn rms(v: &[f32]) -> f32 {
        let n = v.len();
        if n == 0 {
            return 0.0;
        }
        let sq: f64 = v.iter().map(|&x| (x as f64) * (x as f64)).sum();
        (sq.sqrt() / (n as f64).sqrt()) as f32
    }

    /// Drift of `current` from `baseline` as a fraction of the baseline's RMS
    /// magnitude. Source-agnostic (see [`BaselineDriftConfig`]). The `eps` floor
    /// keeps a near-zero baseline (e.g. just after a baseline-subtraction stage)
    /// from blowing the ratio up to infinity — when the baseline carries
    /// essentially no energy there is nothing to drift *relative to*, so the
    /// detector treats it as quiet.
    fn relative_drift(current: &[f32], baseline: &[f32]) -> f32 {
        let abs_drift = Self::rms_distance(current, baseline);
        let baseline_rms = Self::rms(baseline);
        // 1e-3 is well below any real CSI amplitude scale (ESP32 int8 ⇒ O(10),
        // Nexmon int16 ⇒ O(100s)) yet above f32 noise.
        const EPS: f32 = 1e-3;
        if baseline_rms <= EPS {
            // Degenerate baseline: fall back to an absolute reading so a sudden
            // jump away from a flat-zero baseline still registers.
            abs_drift
        } else {
            abs_drift / baseline_rms
        }
    }

    fn update_ewma(&mut self, current: &[f32]) {
        match &mut self.baseline {
            None => self.baseline = Some(current.to_vec()),
            Some(b) if b.len() != current.len() => {
                self.baseline = Some(current.to_vec());
            }
            Some(b) => {
                let a = self.cfg.ewma_alpha;
                for k in 0..b.len() {
                    b[k] = a * current[k] + (1.0 - a) * b[k];
                }
            }
        }
    }
}

impl EventDetector for BaselineDriftDetector {
    fn on_window(&mut self, window: &CsiWindow, ids: &IdGenerator) -> Vec<CsiEvent> {
        let current = &window.mean_amplitude;
        let baseline = match &self.baseline {
            None => {
                // First window establishes the baseline; no drift possible yet.
                self.baseline = Some(current.clone());
                return Vec::new();
            }
            Some(b) if b.len() != current.len() => {
                // Subcarrier count changed — reset and skip this window.
                self.baseline = Some(current.clone());
                self.drift_streak = 0;
                return Vec::new();
            }
            Some(b) => b.clone(),
        };

        let drift = Self::relative_drift(current, &baseline);
        let mut out = Vec::new();

        if drift > self.cfg.anomaly_threshold {
            out.push(make_event(
                ids,
                CsiEventKind::AnomalyDetected,
                window,
                window.end_ns,
                (drift / (2.0 * self.cfg.anomaly_threshold)).clamp(0.0, 1.0),
            ));
        }

        if drift > self.cfg.drift_threshold {
            self.drift_streak += 1;
            if self.drift_streak >= self.cfg.drift_windows {
                out.push(make_event(
                    ids,
                    CsiEventKind::BaselineChanged,
                    window,
                    window.end_ns,
                    (drift / (2.0 * self.cfg.drift_threshold)).clamp(0.0, 1.0),
                ));
                self.drift_streak = 0;
                // Hard-reset the baseline to the new operating point.
                self.baseline = Some(current.clone());
                return out;
            }
        } else {
            self.drift_streak = 0;
        }

        self.update_ewma(current);
        out
    }

    fn name(&self) -> &'static str {
        "baseline_drift"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{SessionId, SourceId};

    fn window(window_id: u64, end_ns: u64, motion: f32, presence: f32, quality: f32) -> CsiWindow {
        let end_ns = end_ns.max(1);
        CsiWindow {
            window_id: WindowId(window_id),
            session_id: SessionId(0),
            source_id: SourceId::from("s"),
            start_ns: end_ns.saturating_sub(1_000),
            end_ns,
            frame_count: 8,
            mean_amplitude: vec![1.0; 8],
            phase_variance: vec![0.0; 8],
            motion_energy: motion,
            presence_score: presence,
            quality_score: quality,
        }
    }

    fn window_amp(window_id: u64, end_ns: u64, amp: Vec<f32>) -> CsiWindow {
        let n = amp.len();
        CsiWindow {
            window_id: WindowId(window_id),
            session_id: SessionId(0),
            source_id: SourceId::from("s"),
            start_ns: 0,
            end_ns: end_ns.max(1),
            frame_count: 8,
            mean_amplitude: amp,
            phase_variance: vec![0.0; n],
            motion_energy: 0.0,
            presence_score: 0.0,
            quality_score: 0.9,
        }
    }

    #[test]
    fn presence_detector_emits_started_then_ended() {
        let g = IdGenerator::new();
        let mut d = PresenceDetector::with_config(PresenceConfig {
            on_threshold: 0.6,
            off_threshold: 0.35,
            enter_windows: 2,
            exit_windows: 3,
        });
        let mut events = Vec::new();
        // Low windows.
        for k in 0..3u64 {
            events.extend(d.on_window(&window(k, (k + 1) * 1_000, 0.0, 0.05, 0.9), &g));
        }
        assert!(events.is_empty());
        // High run -> PresenceStarted after the 2nd one.
        for k in 3..8u64 {
            events.extend(d.on_window(&window(k, (k + 1) * 1_000, 0.5, 0.95, 0.9), &g));
        }
        // Low run -> PresenceEnded after the 3rd low one.
        for k in 8..13u64 {
            events.extend(d.on_window(&window(k, (k + 1) * 1_000, 0.0, 0.05, 0.9), &g));
        }
        assert_eq!(events.len(), 2, "events = {events:?}");
        assert_eq!(events[0].kind, CsiEventKind::PresenceStarted);
        assert_eq!(events[1].kind, CsiEventKind::PresenceEnded);
        for e in &events {
            assert!(e.validate().is_ok());
            assert!(!e.evidence_window_ids.is_empty());
            assert!((0.0..=1.0).contains(&e.confidence));
        }
    }

    #[test]
    fn presence_detector_streak_reset() {
        let g = IdGenerator::new();
        let mut d = PresenceDetector::new();
        // 1 high, 1 low (resets), then enough highs.
        assert!(d.on_window(&window(0, 1_000, 0.0, 0.95, 0.9), &g).is_empty());
        assert!(d.on_window(&window(1, 2_000, 0.0, 0.05, 0.9), &g).is_empty());
        assert!(d.on_window(&window(2, 3_000, 0.0, 0.95, 0.9), &g).is_empty());
        let e = d.on_window(&window(3, 4_000, 0.0, 0.95, 0.9), &g);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].kind, CsiEventKind::PresenceStarted);
    }

    #[test]
    fn motion_detector_emits_detected_then_settled() {
        let g = IdGenerator::new();
        let mut d = MotionDetector::with_config(MotionConfig {
            on_threshold: 0.05,
            off_threshold: 0.02,
            debounce_windows: 2,
        });
        let mut events = Vec::new();
        for k in 0..2u64 {
            events.extend(d.on_window(&window(k, (k + 1) * 1_000, 0.001, 0.0, 0.9), &g));
        }
        for k in 2..6u64 {
            events.extend(d.on_window(&window(k, (k + 1) * 1_000, 0.3, 0.0, 0.9), &g));
        }
        for k in 6..10u64 {
            events.extend(d.on_window(&window(k, (k + 1) * 1_000, 0.0, 0.0, 0.9), &g));
        }
        assert_eq!(events.len(), 2, "events = {events:?}");
        assert_eq!(events[0].kind, CsiEventKind::MotionDetected);
        assert_eq!(events[1].kind, CsiEventKind::MotionSettled);
        for e in &events {
            assert!(e.validate().is_ok());
        }
    }

    #[test]
    fn quality_detector_drop_then_calibration_once() {
        let g = IdGenerator::new();
        let mut d = QualityDetector::with_config(QualityConfig {
            drop_threshold: 0.4,
            debounce_windows: 2,
            calib_windows: 4,
        });
        let mut events = Vec::new();
        // Good window first.
        events.extend(d.on_window(&window(0, 1_000, 0.0, 0.0, 0.9), &g));
        // Low run.
        for k in 1..8u64 {
            events.extend(d.on_window(&window(k, (k + 1) * 1_000, 0.0, 0.0, 0.1), &g));
        }
        let dropped = events
            .iter()
            .filter(|e| e.kind == CsiEventKind::SignalQualityDropped)
            .count();
        let calib = events
            .iter()
            .filter(|e| e.kind == CsiEventKind::CalibrationRequired)
            .count();
        assert_eq!(dropped, 1, "events = {events:?}");
        assert_eq!(calib, 1, "events = {events:?}");
        for e in &events {
            assert!(e.validate().is_ok());
        }
        // Recover and drop again -> re-armed.
        events.clear();
        events.extend(d.on_window(&window(8, 9_000, 0.0, 0.0, 0.95), &g));
        for k in 9..14u64 {
            events.extend(d.on_window(&window(k, (k + 1) * 1_000, 0.0, 0.0, 0.1), &g));
        }
        assert_eq!(
            events
                .iter()
                .filter(|e| e.kind == CsiEventKind::SignalQualityDropped)
                .count(),
            1
        );
    }

    #[test]
    fn baseline_drift_stable_then_shift_then_anomaly() {
        let g = IdGenerator::new();
        let mut d = BaselineDriftDetector::with_config(BaselineDriftConfig {
            drift_threshold: 0.15,
            drift_windows: 3,
            anomaly_threshold: 1.0,
            ewma_alpha: 0.1,
        });
        // Stable baseline -> no events.
        let mut events = Vec::new();
        for k in 0..5u64 {
            events.extend(d.on_window(&window_amp(k, (k + 1) * 1_000, vec![1.0; 8]), &g));
        }
        assert!(events.is_empty(), "events = {events:?}");
        // Sustained shift -> BaselineChanged.
        for k in 5..10u64 {
            events.extend(d.on_window(&window_amp(k, (k + 1) * 1_000, vec![1.5; 8]), &g));
        }
        assert!(
            events.iter().any(|e| e.kind == CsiEventKind::BaselineChanged),
            "events = {events:?}"
        );
        // Single huge spike -> AnomalyDetected.
        events.clear();
        events.extend(d.on_window(&window_amp(10, 11_000, vec![50.0; 8]), &g));
        assert!(
            events.iter().any(|e| e.kind == CsiEventKind::AnomalyDetected),
            "events = {events:?}"
        );
        for e in &events {
            assert!(e.validate().is_ok());
        }
    }

    #[test]
    fn baseline_drift_is_scale_invariant_no_anomaly_storm() {
        // Regression for the ESP32 live-capture finding: raw int8 CSI amplitudes
        // are O(10–128), so an *absolute* anomaly_threshold of 1.0 fired on
        // essentially every window. With a *relative* threshold a few-percent
        // wobble around a large baseline must stay quiet.
        let g = IdGenerator::new();
        let mut d = BaselineDriftDetector::new(); // defaults: drift 0.15, anomaly 1.0
        // A realistic ESP32-ish window: two big "DC/pilot" subcarriers plus a
        // band of small data subcarriers; ±3 % jitter window to window.
        let base: Vec<f32> = {
            let mut v = vec![128.0, 110.0];
            v.extend(std::iter::repeat(15.0).take(68));
            v
        };
        let mut events = Vec::new();
        for k in 0..40u64 {
            // deterministic small wobble in [-0.03, +0.03] * value
            let f = 1.0 + 0.03 * (((k * 2654435761) % 7) as f32 / 3.0 - 1.0);
            let w: Vec<f32> = base.iter().map(|x| x * f).collect();
            events.extend(d.on_window(&window_amp(k, (k + 1) * 1_000, w), &g));
        }
        assert!(
            !events.iter().any(|e| e.kind == CsiEventKind::AnomalyDetected),
            "a ±3% wobble around a large baseline must not be an anomaly; got {events:?}"
        );
        // A 5x jump on the data subcarriers (a person walks in) *is* an anomaly.
        let spike: Vec<f32> = {
            let mut v = vec![128.0, 110.0];
            v.extend(std::iter::repeat(75.0).take(68));
            v
        };
        let ev = d.on_window(&window_amp(99, 100_000, spike), &g);
        assert!(
            ev.iter().any(|e| e.kind == CsiEventKind::AnomalyDetected),
            "a 5x jump on the data band should register; got {ev:?}"
        );
    }

    #[test]
    fn baseline_drift_resets_on_subcarrier_change() {
        let g = IdGenerator::new();
        let mut d = BaselineDriftDetector::new();
        assert!(d.on_window(&window_amp(0, 1_000, vec![1.0; 8]), &g).is_empty());
        // Different length -> reset, no event.
        assert!(d.on_window(&window_amp(1, 2_000, vec![1.0; 16]), &g).is_empty());
        assert!(d.on_window(&window_amp(2, 3_000, vec![1.0; 16]), &g).is_empty());
    }
}

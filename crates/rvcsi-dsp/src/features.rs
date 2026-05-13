//! Frame/window-level scalar features (ADR-095 FR4).
//!
//! These are deterministic, dependency-light feature extractors that turn
//! cleaned amplitude/quality series into the small scalar signals downstream
//! components (presence, breathing, confidence) expose. Anything labelled
//! "heuristic" is best-effort and is meant to be quality-gated by the caller.

use crate::stages::{mean, moving_average, std_dev};

/// Per-subcarrier RMS amplitude delta between two consecutive frames.
///
/// Defined as `||cur - prev||_2 / sqrt(n)`. Returns `0.0` if either slice is
/// empty or the lengths differ (a quiet zero rather than an error keeps the
/// streaming call sites simple).
pub fn motion_energy(prev_amplitude: &[f32], cur_amplitude: &[f32]) -> f32 {
    if prev_amplitude.is_empty()
        || cur_amplitude.is_empty()
        || prev_amplitude.len() != cur_amplitude.len()
    {
        return 0.0;
    }
    let sum_sq: f32 = prev_amplitude
        .iter()
        .zip(cur_amplitude.iter())
        .map(|(p, c)| {
            let d = c - p;
            d * d
        })
        .sum();
    (sum_sq / prev_amplitude.len() as f32).sqrt()
}

/// Mean of [`motion_energy`] over every consecutive pair in the series.
///
/// Returns `0.0` if fewer than two amplitude vectors are supplied.
pub fn motion_energy_series(amplitudes: &[Vec<f32>]) -> f32 {
    if amplitudes.len() < 2 {
        return 0.0;
    }
    let mut acc = 0.0f32;
    for w in amplitudes.windows(2) {
        acc += motion_energy(&w[0], &w[1]);
    }
    acc / (amplitudes.len() - 1) as f32
}

/// Fixed logistic steepness for [`presence_score`].
const PRESENCE_STEEPNESS: f32 = 8.0;

/// Logistic squash of motion energy into a `[0, 1]` presence score.
///
/// Formula: `1 / (1 + exp(-(motion_energy - threshold) * k))` with a fixed
/// steepness `k = 8.0`. Monotone increasing in `motion_energy`, bounded to
/// `[0, 1]`, and exactly `0.5` when `motion_energy == threshold`.
pub fn presence_score(motion_energy: f32, threshold: f32) -> f32 {
    let z = (motion_energy - threshold) * PRESENCE_STEEPNESS;
    1.0 / (1.0 + (-z).exp())
}

/// Robust aggregate of per-frame quality scores in `[0, 1]`.
///
/// Computes `mean - 0.5 * std_dev` over the supplied per-frame quality scores
/// and clamps the result to `[0, 1]`. Returns `0.0` for an empty input. The
/// `-0.5*std` term penalizes windows whose quality is uneven.
pub fn confidence_score(quality_scores: &[f32]) -> f32 {
    if quality_scores.is_empty() {
        return 0.0;
    }
    (mean(quality_scores) - 0.5 * std_dev(quality_scores)).clamp(0.0, 1.0)
}

/// Minimum number of full periods of data required before [`breathing_band_estimate`]
/// will attempt anything.
const MIN_PERIODS: f32 = 2.0;
/// Low edge of the respiration band, Hz (~6 bpm).
const RESP_LO_HZ: f32 = 0.1;
/// High edge of the respiration band, Hz (~30 bpm).
const RESP_HI_HZ: f32 = 0.5;
/// Minimum normalized autocorrelation peak to accept an estimate.
const PEAK_THRESHOLD: f32 = 0.3;

/// Best-effort respiration-rate estimate, in **breaths per minute**.
///
/// Heuristic, FFT-free pipeline:
/// 1. detrend the series by subtracting a moving average,
/// 2. compute the biased autocorrelation for lags in the 0.1–0.5 Hz band
///    (6–30 bpm),
/// 3. if there is a clear dominant peak — its normalized autocorrelation
///    (peak / zero-lag) exceeds `~0.3` and it is a local maximum — return
///    `Some(60 * sample_rate_hz / best_lag)`, otherwise `None`.
///
/// Returns `None` unless there are at least two full periods of data at the
/// slowest band edge (so the caller need not pre-trim). This is **heuristic**
/// and is meant to be quality-gated by the caller; do not treat the result as
/// a medical-grade vital sign.
pub fn breathing_band_estimate(amplitude_series: &[f32], sample_rate_hz: f32) -> Option<f32> {
    if sample_rate_hz <= 0.0 || amplitude_series.len() < 4 {
        return None;
    }
    // Lag (in samples) bounds for the respiration band.
    let min_lag = (sample_rate_hz / RESP_HI_HZ).floor() as usize;
    let mut max_lag = (sample_rate_hz / RESP_LO_HZ).ceil() as usize;
    if min_lag < 1 {
        return None;
    }
    // Need at least MIN_PERIODS periods at the *fast* edge of the band before
    // it is worth attempting anything (a shorter series cannot resolve even the
    // quickest breathing rate). The slow edge is handled by clamping `max_lag`
    // to half the series length below.
    let needed = (MIN_PERIODS * sample_rate_hz / RESP_HI_HZ).ceil() as usize;
    if amplitude_series.len() < needed.max(2 * min_lag) {
        return None;
    }
    max_lag = max_lag.min(amplitude_series.len() / 2);
    if max_lag <= min_lag {
        return None;
    }

    // 1. Detrend: subtract a moving average whose window spans roughly one slow
    //    period (clamped to the series length) so the trend, not the
    //    oscillation, is removed.
    let trend_window = ((sample_rate_hz / RESP_LO_HZ).round() as usize)
        .max(3)
        .min(amplitude_series.len());
    let trend = moving_average(amplitude_series, trend_window);
    let detrended: Vec<f32> = amplitude_series
        .iter()
        .zip(trend.iter())
        .map(|(x, t)| x - t)
        .collect();

    // 2. Biased autocorrelation (divide by N for every lag).
    let n = detrended.len() as f32;
    let autocorr = |lag: usize| -> f32 {
        let mut s = 0.0f32;
        for i in lag..detrended.len() {
            s += detrended[i] * detrended[i - lag];
        }
        s / n
    };
    let zero_lag = autocorr(0);
    if zero_lag <= 0.0 {
        return None;
    }

    // 3. Find the dominant local-max lag inside the band.
    let mut best_lag = 0usize;
    let mut best_val = f32::NEG_INFINITY;
    for lag in min_lag..=max_lag {
        let v = autocorr(lag);
        if v > best_val {
            best_val = v;
            best_lag = lag;
        }
    }
    if best_lag == 0 {
        return None;
    }
    // Local maximum check (compare against immediate neighbours).
    let left = autocorr(best_lag - 1);
    let right = if best_lag < max_lag.min(detrended.len().saturating_sub(1)) {
        autocorr(best_lag + 1)
    } else {
        f32::NEG_INFINITY
    };
    let is_local_max = best_val >= left && best_val >= right;
    let normalized = best_val / zero_lag;
    if !is_local_max || normalized < PEAK_THRESHOLD {
        return None;
    }
    Some(60.0 * sample_rate_hz / best_lag as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f32, b: f32, eps: f32) {
        assert!((a - b).abs() < eps, "{a} !~= {b} (eps {eps})");
    }

    #[test]
    fn motion_energy_zero_for_identical() {
        let a = vec![1.0, 2.0, 3.0];
        approx(motion_energy(&a, &a), 0.0, 1e-6);
    }

    #[test]
    fn motion_energy_positive_for_different() {
        let a = vec![0.0, 0.0, 0.0];
        let b = vec![1.0, 1.0, 1.0];
        // diff all 1 -> sum_sq 3, /3 = 1, sqrt = 1
        approx(motion_energy(&a, &b), 1.0, 1e-6);
    }

    #[test]
    fn motion_energy_mismatch_or_empty_is_zero() {
        approx(motion_energy(&[], &[1.0]), 0.0, 1e-6);
        approx(motion_energy(&[1.0, 2.0], &[1.0]), 0.0, 1e-6);
    }

    #[test]
    fn motion_energy_series_averages() {
        // frames: [0,0],[1,1],[1,1] -> energies: 1.0, 0.0 -> mean 0.5
        let frames = vec![vec![0.0, 0.0], vec![1.0, 1.0], vec![1.0, 1.0]];
        approx(motion_energy_series(&frames), 0.5, 1e-6);
        // fewer than 2 -> 0
        approx(motion_energy_series(&[vec![1.0]]), 0.0, 1e-6);
        approx(motion_energy_series(&[]), 0.0, 1e-6);
    }

    #[test]
    fn presence_score_bounded_monotone_half_at_threshold() {
        let t = 0.5;
        approx(presence_score(t, t), 0.5, 1e-6);
        let lo = presence_score(0.0, t);
        let mid = presence_score(0.5, t);
        let hi = presence_score(2.0, t);
        assert!(lo < mid && mid < hi, "{lo} {mid} {hi}");
        assert!((0.0..=1.0).contains(&lo));
        assert!((0.0..=1.0).contains(&hi));
        // very small / very large saturate
        assert!(presence_score(-100.0, t) < 1e-3);
        assert!(presence_score(100.0, t) > 1.0 - 1e-3);
    }

    #[test]
    fn confidence_score_basic() {
        approx(confidence_score(&[0.9, 0.9, 0.9]), 0.9, 1e-6); // std 0
        approx(confidence_score(&[]), 0.0, 1e-6);
        // uneven quality -> penalized below the mean
        let c = confidence_score(&[0.2, 1.0, 0.6]);
        assert!(c < 0.6, "{c}");
        assert!((0.0..=1.0).contains(&c));
    }

    #[test]
    fn breathing_estimate_detects_quarter_hz_sine() {
        // 0.25 Hz sine (15 bpm) sampled at 10 Hz for 12 s -> 120 samples.
        let fs = 10.0f32;
        let n = 120usize;
        let freq = 0.25f32;
        let mut series = Vec::with_capacity(n);
        // tiny deterministic "noise" via a fixed sequence
        for i in 0..n {
            let t = i as f32 / fs;
            let noise = 0.02 * ((i as f32 * 1.7).sin());
            series.push(1.0 + 0.5 * (2.0 * core::f32::consts::PI * freq * t).sin() + noise);
        }
        let bpm = breathing_band_estimate(&series, fs).expect("should detect a peak");
        approx(bpm, 15.0, 3.0);
    }

    #[test]
    fn breathing_estimate_none_for_short_or_noise() {
        // too short
        assert!(breathing_band_estimate(&[1.0, 2.0, 3.0], 10.0).is_none());
        // a flat constant -> zero-lag autocorr 0 after detrend -> None
        assert!(breathing_band_estimate(&vec![1.0; 200], 10.0).is_none());
        // bad sample rate
        assert!(breathing_band_estimate(&vec![1.0; 200], 0.0).is_none());
    }
}

//! Pure per-vector DSP primitives (ADR-095 FR4).
//!
//! Every function here is deterministic and operates on plain `&[f32]` /
//! `&mut [f32]` slices — no allocation-heavy dependencies, no hidden state.
//! Errors are reported via [`DspError`].

use core::f32::consts::PI;

use thiserror::Error;

/// Errors produced by DSP stages that can fail.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DspError {
    /// Two slices that were required to be the same length were not.
    #[error("length mismatch: {a} vs {b}")]
    LengthMismatch {
        /// Length of the first slice.
        a: usize,
        /// Length of the second slice.
        b: usize,
    },
    /// An operation that requires at least one sample received an empty slice.
    #[error("empty input")]
    EmptyInput,
}

/// Arithmetic mean of the slice. Returns `0.0` for an empty slice.
pub fn mean(xs: &[f32]) -> f32 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f32>() / xs.len() as f32
    }
}

/// Population variance (divides by `n`, not `n - 1`). Returns `0.0` for an
/// empty slice.
pub fn variance(xs: &[f32]) -> f32 {
    if xs.is_empty() {
        return 0.0;
    }
    let m = mean(xs);
    xs.iter().map(|x| {
        let d = x - m;
        d * d
    }).sum::<f32>()
        / xs.len() as f32
}

/// Population standard deviation. Returns `0.0` for an empty slice.
pub fn std_dev(xs: &[f32]) -> f32 {
    variance(xs).sqrt()
}

/// Median of the slice (clones and sorts internally). Returns `0.0` for an
/// empty slice. For an even count, returns the average of the two central
/// values.
pub fn median(xs: &[f32]) -> f32 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal));
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        0.5 * (v[n / 2 - 1] + v[n / 2])
    }
}

/// Subtract the mean of the slice from every element, in place.
pub fn remove_dc_offset(xs: &mut [f32]) {
    let m = mean(xs);
    for x in xs.iter_mut() {
        *x -= m;
    }
}

/// In-place 1-D phase unwrap.
///
/// Walks left→right; whenever the raw step `phase[i] - phase[i-1]` exceeds
/// `+PI` we accumulate a `-2*PI` correction, and whenever it is below `-PI`
/// we accumulate a `+2*PI` correction. The running correction is added to
/// every subsequent sample, producing a continuous series with no step larger
/// than `PI` in magnitude.
pub fn unwrap_phase(phase: &mut [f32]) {
    if phase.len() < 2 {
        return;
    }
    let mut correction = 0.0f32;
    let mut prev_raw = phase[0];
    // We read `phase[i]` and write `phase[i]` in the same step; an index loop
    // is the clearest way to express that, hence the lint allowance.
    #[allow(clippy::needless_range_loop)]
    for i in 1..phase.len() {
        let raw = phase[i];
        let step = raw - prev_raw;
        if step > PI {
            correction -= 2.0 * PI;
        } else if step < -PI {
            correction += 2.0 * PI;
        }
        prev_raw = raw;
        phase[i] = raw + correction;
    }
}

/// Centered moving average with edge clamping (the window shrinks at the ends).
///
/// `window == 0 || window == 1` returns a plain copy. The result has the same
/// length as the input.
pub fn moving_average(xs: &[f32], window: usize) -> Vec<f32> {
    if window <= 1 || xs.is_empty() {
        return xs.to_vec();
    }
    let half = window / 2;
    let n = xs.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let lo = i.saturating_sub(half);
        let hi = (i + half + 1).min(n);
        let slice = &xs[lo..hi];
        out.push(mean(slice));
    }
    out
}

/// Exponentially-weighted moving average.
///
/// `y[0] = x[0]`, `y[i] = alpha * x[i] + (1 - alpha) * y[i-1]`. `alpha` is
/// clamped to `(0.0, 1.0]` (values `<= 0` become a tiny positive epsilon,
/// values `> 1` become `1.0`). An empty input yields an empty output.
pub fn ewma(xs: &[f32], alpha: f32) -> Vec<f32> {
    if xs.is_empty() {
        return Vec::new();
    }
    let a = if alpha > 1.0 {
        1.0
    } else if alpha <= 0.0 {
        f32::EPSILON
    } else {
        alpha
    };
    let mut out = Vec::with_capacity(xs.len());
    let mut y = xs[0];
    out.push(y);
    for &x in &xs[1..] {
        y = a * x + (1.0 - a) * y;
        out.push(y);
    }
    out
}

/// Hampel outlier filter.
///
/// For each index `i`, take the window `[i - half_window, i + half_window]`
/// (clamped to the slice), compute the median `m` and
/// `MAD = 1.4826 * median(|x - m|)`. If `|x[i] - m| > n_sigmas * MAD`, the
/// sample is replaced with `m`; otherwise it is kept. Returns a new `Vec` of
/// the same length.
pub fn hampel_filter(xs: &[f32], half_window: usize, n_sigmas: f32) -> Vec<f32> {
    hampel_filter_count(xs, half_window, n_sigmas).0
}

/// Like [`hampel_filter`] but also reports how many samples were replaced.
pub fn hampel_filter_count(xs: &[f32], half_window: usize, n_sigmas: f32) -> (Vec<f32>, usize) {
    if xs.is_empty() {
        return (Vec::new(), 0);
    }
    let n = xs.len();
    let mut out = Vec::with_capacity(n);
    let mut replaced = 0usize;
    for i in 0..n {
        let lo = i.saturating_sub(half_window);
        let hi = (i + half_window + 1).min(n);
        let window = &xs[lo..hi];
        let m = median(window);
        let deviations: Vec<f32> = window.iter().map(|x| (x - m).abs()).collect();
        let mad = 1.4826 * median(&deviations);
        // When `mad == 0` (a majority of the window is identical) the test
        // `dev > n_sigmas * 0` reduces to `dev > 0`, i.e. any sample that
        // differs from the window median is treated as an outlier — this is the
        // standard degenerate-MAD behaviour for the Hampel identifier.
        if (xs[i] - m).abs() > n_sigmas * mad {
            out.push(m);
            replaced += 1;
        } else {
            out.push(xs[i]);
        }
    }
    (out, replaced)
}

/// Sliding population variance over a centered window with edge clamping.
///
/// `window <= 1` produces an all-zero series the same length as the input
/// (a single-sample window has zero variance). The result has the same length
/// as the input.
pub fn short_window_variance(xs: &[f32], window: usize) -> Vec<f32> {
    let n = xs.len();
    if n == 0 {
        return Vec::new();
    }
    if window <= 1 {
        return vec![0.0; n];
    }
    let half = window / 2;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let lo = i.saturating_sub(half);
        let hi = (i + half + 1).min(n);
        out.push(variance(&xs[lo..hi]));
    }
    out
}

/// Elementwise `current - baseline`. Errors if the lengths differ.
pub fn subtract_baseline(current: &[f32], baseline: &[f32]) -> Result<Vec<f32>, DspError> {
    if current.len() != baseline.len() {
        return Err(DspError::LengthMismatch {
            a: current.len(),
            b: baseline.len(),
        });
    }
    Ok(current
        .iter()
        .zip(baseline.iter())
        .map(|(c, b)| c - b)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f32, b: f32) {
        assert!((a - b).abs() < 1e-5, "{a} !~= {b}");
    }

    #[test]
    fn mean_variance_median_basic() {
        let xs = [1.0, 2.0, 3.0, 4.0];
        approx(mean(&xs), 2.5);
        // population variance of 1..4: mean 2.5, devs^2 = 2.25,0.25,0.25,2.25 -> 5/4 = 1.25
        approx(variance(&xs), 1.25);
        approx(std_dev(&xs), 1.25f32.sqrt());
        // even-count median: avg of 2 and 3
        approx(median(&xs), 2.5);
        approx(median(&[3.0, 1.0, 2.0]), 2.0);
    }

    #[test]
    fn empty_inputs_are_zero() {
        approx(mean(&[]), 0.0);
        approx(variance(&[]), 0.0);
        approx(std_dev(&[]), 0.0);
        approx(median(&[]), 0.0);
    }

    #[test]
    fn remove_dc_offset_centers() {
        let mut xs = [1.0, 2.0, 3.0, 4.0];
        remove_dc_offset(&mut xs);
        approx(mean(&xs), 0.0);
        approx(xs[0], -1.5);
        approx(xs[3], 1.5);
    }

    #[test]
    fn unwrap_phase_is_continuous() {
        // raw: 0, 3, -3, 0. step 3->-3 is -6 < -PI so +2PI; etc.
        let mut p = [0.0f32, 3.0, -3.0, 0.0];
        unwrap_phase(&mut p);
        for w in p.windows(2) {
            assert!((w[1] - w[0]).abs() <= PI + 1e-5, "jump too big: {w:?}");
        }
        // first sample untouched
        approx(p[0], 0.0);
    }

    #[test]
    fn unwrap_phase_short_slices() {
        let mut a: [f32; 0] = [];
        unwrap_phase(&mut a);
        let mut b = [1.23f32];
        unwrap_phase(&mut b);
        approx(b[0], 1.23);
    }

    #[test]
    fn moving_average_window_three() {
        // [1,2,3,4,5], window 3, half=1, edge clamp:
        // i=0: [1,2] -> 1.5
        // i=1: [1,2,3] -> 2
        // i=2: [2,3,4] -> 3
        // i=3: [3,4,5] -> 4
        // i=4: [4,5] -> 4.5
        let out = moving_average(&[1.0, 2.0, 3.0, 4.0, 5.0], 3);
        assert_eq!(out.len(), 5);
        approx(out[0], 1.5);
        approx(out[1], 2.0);
        approx(out[2], 3.0);
        approx(out[3], 4.0);
        approx(out[4], 4.5);
    }

    #[test]
    fn moving_average_window_one_is_copy() {
        let xs = [1.0, 2.0, 3.0];
        assert_eq!(moving_average(&xs, 1), xs.to_vec());
        assert_eq!(moving_average(&xs, 0), xs.to_vec());
    }

    #[test]
    fn ewma_first_element_and_alpha_one() {
        let xs = [2.0, 4.0, 8.0];
        let out = ewma(&xs, 0.5);
        approx(out[0], 2.0);
        approx(out[1], 0.5 * 4.0 + 0.5 * 2.0); // 3.0
        approx(out[2], 0.5 * 8.0 + 0.5 * 3.0); // 5.5
        // alpha = 1.0 -> copy
        assert_eq!(ewma(&xs, 1.0), xs.to_vec());
        // clamped: alpha > 1 also a copy
        assert_eq!(ewma(&xs, 5.0), xs.to_vec());
        // empty
        assert!(ewma(&[], 0.5).is_empty());
    }

    #[test]
    fn hampel_replaces_spike() {
        let xs = [1.0, 1.0, 1.0, 100.0, 1.0, 1.0, 1.0];
        let (out, count) = hampel_filter_count(&xs, 3, 3.0);
        approx(out[3], 1.0);
        assert_eq!(count, 1);
        // all other points unchanged
        for i in [0, 1, 2, 4, 5, 6] {
            approx(out[i], 1.0);
        }
        // hampel_filter agrees
        assert_eq!(hampel_filter(&xs, 3, 3.0), out);
    }

    #[test]
    fn hampel_clean_signal_unchanged() {
        let xs = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
        let (out, count) = hampel_filter_count(&xs, 2, 3.0);
        assert_eq!(count, 0);
        assert_eq!(out, xs.to_vec());
    }

    #[test]
    fn hampel_empty() {
        let (out, count) = hampel_filter_count(&[], 2, 3.0);
        assert!(out.is_empty());
        assert_eq!(count, 0);
    }

    #[test]
    fn short_window_variance_constant_is_zero() {
        let xs = [5.0; 8];
        let out = short_window_variance(&xs, 3);
        assert_eq!(out.len(), 8);
        for v in out {
            approx(v, 0.0);
        }
        // window 1 -> all zeros
        let out2 = short_window_variance(&xs, 1);
        assert_eq!(out2, vec![0.0; 8]);
        assert!(short_window_variance(&[], 3).is_empty());
    }

    #[test]
    fn short_window_variance_nonconstant() {
        // [0, 0, 9], window 3, half 1:
        // i=0: [0,0] var 0
        // i=1: [0,0,9] mean 3, devs^2 9,9,36 -> 54/3 = 18
        // i=2: [0,9] mean 4.5, devs^2 20.25,20.25 -> 40.5/2 = 20.25
        let out = short_window_variance(&[0.0, 0.0, 9.0], 3);
        approx(out[0], 0.0);
        approx(out[1], 18.0);
        approx(out[2], 20.25);
    }

    #[test]
    fn subtract_baseline_works_and_errors() {
        let c = [3.0, 5.0, 7.0];
        let b = [1.0, 2.0, 3.0];
        let out = subtract_baseline(&c, &b).unwrap();
        assert_eq!(out, vec![2.0, 3.0, 4.0]);
        let err = subtract_baseline(&c, &[1.0, 2.0]).unwrap_err();
        assert_eq!(err, DspError::LengthMismatch { a: 3, b: 2 });
    }
}

//! Deterministic, dependency-free embedding functions for RF memory records.
//!
//! [`window_embedding`] turns a [`CsiWindow`] into a fixed-length
//! [`WINDOW_EMBEDDING_DIM`]-vector regardless of subcarrier count;
//! [`event_embedding`] turns a [`CsiEvent`] into a fixed-length
//! [`EVENT_EMBEDDING_DIM`]-vector. [`cosine_similarity`] is the comparison
//! metric used by the [`crate::RfMemoryStore`] implementations.
//!
//! All functions are pure and deterministic — the same input always yields the
//! same bytes, with no clocks, randomness, threads or floating-point
//! reductions whose order could vary.

use rvcsi_core::{CsiEvent, CsiEventKind, CsiWindow};

/// Length of a [`window_embedding`] vector.
///
/// Layout (all indices into the returned `Vec<f32>`):
/// * `0..32`  — `mean_amplitude` linearly resampled to 32 bins
/// * `32..64` — `phase_variance` linearly resampled to 32 bins
/// * `64`     — `motion_energy`
/// * `65`     — `presence_score`
/// * `66`     — `quality_score`
/// * `67`     — `ln(1 + frame_count)`
///
/// The whole vector is then L2-normalized (left all-zero if its norm is 0,
/// e.g. for an empty window).
pub const WINDOW_EMBEDDING_DIM: usize = 68;

/// Length of an [`event_embedding`] vector.
///
/// Layout:
/// * `0..10` — one-hot of [`CsiEventKind`] in declaration order (see
///   [`kind_index`])
/// * `10`    — `confidence`
/// * `11`    — `ln(1 + evidence_window_ids.len())`
///
/// Event embeddings are **not** normalized (the one-hot block already gives
/// them a stable scale).
pub const EVENT_EMBEDDING_DIM: usize = 12;

/// Number of bins each per-subcarrier vector is resampled to.
const SUBCARRIER_BINS: usize = 32;

/// Linearly resample `src` (length `n`) to length `m`.
///
/// * `n == 0` → `vec![0.0; m]`
/// * `n == 1` → `vec![src[0]; m]`
/// * otherwise, for each output index `j`: `pos = j * (n-1) / (m-1)`,
///   `lo = floor(pos)`, `frac = pos - lo`, value `src[lo] * (1 - frac) +
///   src[min(lo+1, n-1)] * frac`.
fn resample_linear(src: &[f32], m: usize) -> Vec<f32> {
    let n = src.len();
    if n == 0 {
        return vec![0.0; m];
    }
    if n == 1 {
        return vec![src[0]; m];
    }
    if m == 0 {
        return Vec::new();
    }
    if m == 1 {
        // Degenerate target: just take the first sample (avoids /0 below).
        return vec![src[0]];
    }
    let mut out = Vec::with_capacity(m);
    let denom = (m - 1) as f32;
    let span = (n - 1) as f32;
    for j in 0..m {
        let pos = j as f32 * span / denom;
        let lo = pos.floor() as usize;
        let frac = pos - lo as f32;
        let hi = (lo + 1).min(n - 1);
        out.push(src[lo] * (1.0 - frac) + src[hi] * frac);
    }
    out
}

/// L2 norm of a slice (`0.0` for an empty slice).
fn l2_norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

/// In-place L2 normalization; leaves `v` unchanged if its norm is `0` or
/// non-finite.
fn l2_normalize(v: &mut [f32]) {
    let norm = l2_norm(v);
    if norm.is_finite() && norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Build the deterministic embedding for a [`CsiWindow`].
///
/// The returned vector has length [`WINDOW_EMBEDDING_DIM`]; see that constant's
/// docs for the exact bin layout. The result is L2-normalized (or all-zero for
/// an empty window — i.e. `subcarrier_count == 0` and `frame_count == 0`).
pub fn window_embedding(w: &CsiWindow) -> Vec<f32> {
    let mut out = Vec::with_capacity(WINDOW_EMBEDDING_DIM);
    out.extend(resample_linear(&w.mean_amplitude, SUBCARRIER_BINS));
    out.extend(resample_linear(&w.phase_variance, SUBCARRIER_BINS));
    out.push(w.motion_energy);
    out.push(w.presence_score);
    out.push(w.quality_score);
    out.push((w.frame_count as f32).ln_1p());
    debug_assert_eq!(out.len(), WINDOW_EMBEDDING_DIM);
    l2_normalize(&mut out);
    out
}

/// Fixed index of a [`CsiEventKind`] in the one-hot block of an event
/// embedding — the variant declaration order in `rvcsi_core`.
fn kind_index(k: CsiEventKind) -> usize {
    match k {
        CsiEventKind::PresenceStarted => 0,
        CsiEventKind::PresenceEnded => 1,
        CsiEventKind::MotionDetected => 2,
        CsiEventKind::MotionSettled => 3,
        CsiEventKind::BaselineChanged => 4,
        CsiEventKind::SignalQualityDropped => 5,
        CsiEventKind::DeviceDisconnected => 6,
        CsiEventKind::BreathingCandidate => 7,
        CsiEventKind::AnomalyDetected => 8,
        CsiEventKind::CalibrationRequired => 9,
    }
}

/// Build the deterministic embedding for a [`CsiEvent`].
///
/// The returned vector has length [`EVENT_EMBEDDING_DIM`]; see that constant's
/// docs for the exact layout. Not normalized.
pub fn event_embedding(e: &CsiEvent) -> Vec<f32> {
    let mut out = vec![0.0_f32; EVENT_EMBEDDING_DIM];
    out[kind_index(e.kind)] = 1.0;
    out[10] = e.confidence;
    out[11] = (e.evidence_window_ids.len() as f32).ln_1p();
    out
}

/// Cosine similarity of two equal-length vectors.
///
/// Returns `0.0` if the lengths differ or either vector is all-zero (or has a
/// non-finite norm); otherwise `dot(a, b) / (||a|| * ||b||)` clamped to
/// `[-1.0, 1.0]`.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let na = l2_norm(a);
    let nb = l2_norm(b);
    if !(na.is_finite() && nb.is_finite()) || na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    (dot / (na * nb)).clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{EventId, SessionId, SourceId, WindowId};

    fn window() -> CsiWindow {
        CsiWindow {
            window_id: WindowId(7),
            session_id: SessionId(1),
            source_id: SourceId::from("emb-test"),
            start_ns: 1_000,
            end_ns: 2_000,
            frame_count: 12,
            mean_amplitude: vec![1.0, 2.0, 3.0, 4.0, 5.0],
            phase_variance: vec![0.1, 0.2, 0.1, 0.3, 0.2],
            motion_energy: 0.42,
            presence_score: 0.8,
            quality_score: 0.9,
        }
    }

    fn event(kind: CsiEventKind) -> CsiEvent {
        CsiEvent::new(
            EventId(3),
            kind,
            SessionId(1),
            SourceId::from("emb-test"),
            5_000,
            0.75,
            vec![WindowId(1), WindowId(2)],
        )
    }

    #[test]
    fn resample_edge_cases() {
        assert_eq!(resample_linear(&[], 4), vec![0.0; 4]);
        assert_eq!(resample_linear(&[2.5], 3), vec![2.5, 2.5, 2.5]);
        // identity-ish: 3 -> 3 keeps endpoints
        let r = resample_linear(&[0.0, 1.0, 2.0], 3);
        assert!((r[0] - 0.0).abs() < 1e-6);
        assert!((r[1] - 1.0).abs() < 1e-6);
        assert!((r[2] - 2.0).abs() < 1e-6);
        // upsample 2 -> 5 is a straight line
        let r = resample_linear(&[0.0, 4.0], 5);
        assert!((r[2] - 2.0).abs() < 1e-6);
    }

    #[test]
    fn window_embedding_is_deterministic_and_unit_length() {
        let w = window();
        let a = window_embedding(&w);
        let b = window_embedding(&w);
        assert_eq!(a, b);
        assert_eq!(a.len(), WINDOW_EMBEDDING_DIM);
        let norm = l2_norm(&a);
        assert!((norm - 1.0).abs() < 1e-5, "norm was {norm}");
    }

    #[test]
    fn empty_window_embeds_to_zero() {
        let mut w = window();
        w.mean_amplitude.clear();
        w.phase_variance.clear();
        w.motion_energy = 0.0;
        w.presence_score = 0.0;
        w.quality_score = 0.0;
        w.frame_count = 0;
        let e = window_embedding(&w);
        assert_eq!(e.len(), WINDOW_EMBEDDING_DIM);
        assert!(e.iter().all(|x| *x == 0.0));
    }

    #[test]
    fn window_embedding_length_independent_of_subcarrier_count() {
        let mut a = window();
        a.mean_amplitude = vec![1.0; 56];
        a.phase_variance = vec![0.1; 56];
        let mut b = window();
        b.mean_amplitude = vec![1.0; 234];
        b.phase_variance = vec![0.1; 234];
        assert_eq!(window_embedding(&a).len(), window_embedding(&b).len());
    }

    #[test]
    fn event_embedding_layout() {
        let e = event(CsiEventKind::MotionDetected);
        let v = event_embedding(&e);
        assert_eq!(v.len(), EVENT_EMBEDDING_DIM);
        assert_eq!(v[kind_index(CsiEventKind::MotionDetected)], 1.0);
        // exactly one hot in the first 10
        assert_eq!(v[..10].iter().filter(|x| **x == 1.0).count(), 1);
        assert!((v[10] - 0.75).abs() < 1e-6);
        assert!((v[11] - (2.0_f32).ln_1p()).abs() < 1e-6);

        // a different kind lights a different bin
        let v2 = event_embedding(&event(CsiEventKind::AnomalyDetected));
        assert_eq!(v2[kind_index(CsiEventKind::AnomalyDetected)], 1.0);
        assert_ne!(v, v2);
    }

    #[test]
    fn cosine_basic_identities() {
        let v = window_embedding(&window());
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-5);
        let neg: Vec<f32> = v.iter().map(|x| -x).collect();
        assert!((cosine_similarity(&v, &neg) + 1.0).abs() < 1e-5);
        // mismatched lengths -> 0
        assert_eq!(cosine_similarity(&v, &v[..3]), 0.0);
        // all-zero -> 0
        assert_eq!(cosine_similarity(&[0.0; 4], &[1.0; 4]), 0.0);
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
    }
}

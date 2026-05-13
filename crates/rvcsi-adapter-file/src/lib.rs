//! # rvCSI file/replay adapter
//!
//! The `.rvcsi` capture container, its [`FileRecorder`], and the
//! [`FileReplayAdapter`] [`CsiSource`](rvcsi_core::CsiSource) (ADR-095 FR1/FR10,
//! D9).
//!
//! A `.rvcsi` file is plain [JSONL]: the first line is a [`CaptureHeader`]
//! describing the session; every subsequent line is one
//! [`rvcsi_core::CsiFrame`] serialized as compact JSON. The format is simple,
//! deterministic, append-friendly and trivially inspectable with `head` / `jq`.
//!
//! Typical use:
//!
//! ```no_run
//! use rvcsi_adapter_file::{CaptureHeader, FileRecorder, FileReplayAdapter};
//! use rvcsi_core::{AdapterKind, AdapterProfile, CsiSource, SessionId, SourceId};
//!
//! # fn demo() -> rvcsi_core::Result<()> {
//! let header = CaptureHeader::new(
//!     SessionId(1),
//!     SourceId::from("file:lab.rvcsi"),
//!     AdapterProfile::offline(AdapterKind::File),
//! );
//! let mut rec = FileRecorder::create("lab.rvcsi", &header)?;
//! // rec.write_frame(&frame)?; ...
//! rec.finish()?;
//!
//! let mut replay = FileReplayAdapter::open("lab.rvcsi")?;
//! while let Some(frame) = replay.next_frame()? {
//!     // hand `frame` downstream — its ValidationStatus is preserved as recorded
//!     let _ = frame;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [JSONL]: https://jsonlines.org/

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod format;
mod recorder;
mod replay;

pub use format::{CaptureHeader, CAPTURE_VERSION};
pub use recorder::FileRecorder;
pub use replay::FileReplayAdapter;

use std::path::Path;

use rvcsi_core::{CsiFrame, Result};

/// Read an entire `.rvcsi` capture into memory: its [`CaptureHeader`] and every
/// [`CsiFrame`] it contains, in recording order.
///
/// This is a convenience wrapper over [`FileReplayAdapter`]; for large captures
/// or streaming use, prefer iterating [`FileReplayAdapter`] directly. Errors are
/// the same as [`FileReplayAdapter::open`] / [`FileReplayAdapter::next_frame`]:
/// an [`rvcsi_core::RvcsiError::Io`] for a missing/unreadable file, an
/// [`rvcsi_core::RvcsiError::Parse`] (offset `0`) for a bad header, or an
/// [`rvcsi_core::RvcsiError::Parse`] carrying the 1-based line number for a
/// malformed frame line.
pub fn read_all(path: impl AsRef<Path>) -> Result<(CaptureHeader, Vec<CsiFrame>)> {
    use rvcsi_core::CsiSource;
    let mut adapter = FileReplayAdapter::open(path)?;
    let header = adapter.header().clone();
    let mut frames = Vec::new();
    while let Some(frame) = adapter.next_frame()? {
        frames.push(frame);
    }
    Ok((header, frames))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{
        AdapterKind, AdapterProfile, CsiSource, FrameId, RvcsiError, SessionId, SourceId,
        ValidationStatus,
    };
    use std::fs::File;
    use std::io::{Read, Write};

    fn header() -> CaptureHeader {
        CaptureHeader::new(
            SessionId(1),
            SourceId::from("it-test"),
            AdapterProfile::offline(AdapterKind::File),
        )
        .with_created_unix_ns(0)
        .with_calibration_version("room@v1")
        .with_runtime_config_json(r#"{"window_ms":500}"#)
    }

    /// A small varied set of frames: two accepted (quality 0.9), two degraded
    /// with reasons, one recovered — varying timestamps / channels / subcarrier
    /// counts.
    fn sample_frames() -> Vec<CsiFrame> {
        let mut frames = Vec::new();

        let mut f0 = CsiFrame::from_iq(
            FrameId(0),
            SessionId(1),
            SourceId::from("it-test"),
            AdapterKind::File,
            1_000,
            1,
            20,
            vec![1.0, 2.0, 3.0, 4.0],
            vec![0.5, 0.5, 0.5, 0.5],
        )
        .with_rssi(-55);
        f0.validation = ValidationStatus::Accepted;
        f0.quality_score = 0.9;
        frames.push(f0);

        let mut f1 = CsiFrame::from_iq(
            FrameId(1),
            SessionId(1),
            SourceId::from("it-test"),
            AdapterKind::File,
            2_000,
            6,
            40,
            vec![0.1; 8],
            vec![0.2; 8],
        );
        f1.validation = ValidationStatus::Degraded;
        f1.quality_score = 0.4;
        f1.quality_reasons = vec!["missing rssi".to_string(), "low snr".to_string()];
        frames.push(f1);

        let mut f2 = CsiFrame::from_iq(
            FrameId(2),
            SessionId(1),
            SourceId::from("it-test"),
            AdapterKind::File,
            3_000,
            11,
            20,
            vec![5.0, 6.0],
            vec![1.0, -1.0],
        )
        .with_rssi(-70)
        .with_noise_floor(-95);
        f2.validation = ValidationStatus::Accepted;
        f2.quality_score = 0.9;
        frames.push(f2);

        let mut f3 = CsiFrame::from_iq(
            FrameId(3),
            SessionId(1),
            SourceId::from("it-test"),
            AdapterKind::File,
            2_500, // deliberately out of order — replay preserves it verbatim
            6,
            20,
            vec![0.0; 3],
            vec![0.0; 3],
        );
        f3.validation = ValidationStatus::Recovered;
        f3.quality_score = 0.3;
        frames.push(f3);

        let mut f4 = CsiFrame::from_iq(
            FrameId(4),
            SessionId(1),
            SourceId::from("it-test"),
            AdapterKind::File,
            4_000,
            36,
            80,
            vec![2.0; 6],
            vec![0.0; 6],
        );
        f4.validation = ValidationStatus::Degraded;
        f4.quality_score = 0.5;
        f4.quality_reasons = vec!["amplitude spike".to_string()];
        frames.push(f4);

        frames
    }

    #[test]
    fn record_then_replay_roundtrips_exactly() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = header();
        let frames = sample_frames();

        let mut rec = FileRecorder::create(tmp.path(), &header).unwrap();
        for f in &frames {
            rec.write_frame(f).unwrap();
        }
        assert_eq!(rec.frames_written(), frames.len() as u64);
        rec.finish().unwrap();

        let mut adapter = FileReplayAdapter::open(tmp.path()).unwrap();
        assert_eq!(adapter.header(), &header);
        let mut got = Vec::new();
        while let Some(f) = adapter.next_frame().unwrap() {
            got.push(f);
        }
        assert_eq!(got, frames);
        assert_eq!(adapter.health().frames_delivered, frames.len() as u64);
        assert!(!adapter.health().connected);
    }

    #[test]
    fn re_serializing_replayed_frames_is_byte_identical() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = header();
        let frames = sample_frames();
        let mut rec = FileRecorder::create(tmp.path(), &header).unwrap();
        for f in &frames {
            rec.write_frame(f).unwrap();
        }
        rec.finish().unwrap();

        let mut original = String::new();
        File::open(tmp.path()).unwrap().read_to_string(&mut original).unwrap();

        // Round-trip the whole capture and re-emit it; bytes must match.
        let (h, fs) = read_all(tmp.path()).unwrap();
        let tmp2 = tempfile::NamedTempFile::new().unwrap();
        let mut rec2 = FileRecorder::create(tmp2.path(), &h).unwrap();
        for f in &fs {
            rec2.write_frame(f).unwrap();
        }
        rec2.finish().unwrap();
        let mut reemitted = String::new();
        File::open(tmp2.path()).unwrap().read_to_string(&mut reemitted).unwrap();

        assert_eq!(original, reemitted);
    }

    #[test]
    fn read_all_matches_replay() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = header();
        let frames = sample_frames();
        let mut rec = FileRecorder::create(tmp.path(), &header).unwrap();
        for f in &frames {
            rec.write_frame(f).unwrap();
        }
        rec.finish().unwrap();

        let (h, fs) = read_all(tmp.path()).unwrap();
        assert_eq!(h, header);
        assert_eq!(fs, frames);
    }

    #[test]
    fn header_only_capture_has_no_frames() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = header();
        FileRecorder::create(tmp.path(), &header).unwrap().finish().unwrap();

        let mut adapter = FileReplayAdapter::open(tmp.path()).unwrap();
        assert!(adapter.next_frame().unwrap().is_none());

        let (h, fs) = read_all(tmp.path()).unwrap();
        assert_eq!(h, header);
        assert!(fs.is_empty());
    }

    #[test]
    fn bad_header_line_is_parse_error_at_offset_zero() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let mut f = File::create(tmp.path()).unwrap();
            f.write_all(b"not json\n").unwrap();
        }
        match FileReplayAdapter::open(tmp.path()) {
            Err(RvcsiError::Parse { offset, .. }) => assert_eq!(offset, 0),
            other => panic!("expected Parse at offset 0, got {other:?}"),
        }
        match read_all(tmp.path()) {
            Err(RvcsiError::Parse { offset, .. }) => assert_eq!(offset, 0),
            other => panic!("expected Parse at offset 0, got {other:?}"),
        }
    }

    #[test]
    fn garbage_frame_after_good_frames_reports_line_number() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = header();
        {
            let mut f = File::create(tmp.path()).unwrap();
            serde_json::to_writer(&mut f, &header).unwrap();
            f.write_all(b"\n").unwrap();
            // lines 2 + 3: good frames
            let frames = sample_frames();
            serde_json::to_writer(&mut f, &frames[0]).unwrap();
            f.write_all(b"\n").unwrap();
            serde_json::to_writer(&mut f, &frames[1]).unwrap();
            f.write_all(b"\n").unwrap();
            // line 4: garbage
            f.write_all(b"{ not a frame }\n").unwrap();
        }
        let mut adapter = FileReplayAdapter::open(tmp.path()).unwrap();
        assert!(adapter.next_frame().unwrap().is_some()); // line 2
        assert!(adapter.next_frame().unwrap().is_some()); // line 3
        match adapter.next_frame() {
            Err(RvcsiError::Parse { offset, .. }) => assert_eq!(offset, 4),
            other => panic!("expected Parse at line 4, got {other:?}"),
        }
    }

    #[test]
    fn nonexistent_path_is_io_error() {
        match FileReplayAdapter::open("/no/such/file/at/all.rvcsi") {
            Err(RvcsiError::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
        match read_all("/no/such/file/at/all.rvcsi") {
            Err(RvcsiError::Io(_)) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[test]
    fn counters_are_consistent() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = header();
        let frames = sample_frames();
        let mut rec = FileRecorder::create(tmp.path(), &header).unwrap();
        for (i, f) in frames.iter().enumerate() {
            rec.write_frame(f).unwrap();
            assert_eq!(rec.frames_written(), (i + 1) as u64);
        }
        rec.finish().unwrap();

        let mut adapter = FileReplayAdapter::open(tmp.path()).unwrap();
        let mut n = 0u64;
        while adapter.next_frame().unwrap().is_some() {
            n += 1;
            assert_eq!(adapter.health().frames_delivered, n);
        }
        assert_eq!(n, frames.len() as u64);
    }
}

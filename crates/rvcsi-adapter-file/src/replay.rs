//! [`FileReplayAdapter`] — a [`CsiSource`] that replays a `.rvcsi` capture
//! file, frame by frame, exactly as it was recorded.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use rvcsi_core::{
    AdapterProfile, CsiFrame, CsiSource, Result, RvcsiError, SessionId, SourceHealth, SourceId,
};

use crate::format::{CaptureHeader, CAPTURE_VERSION};

/// Deterministic replay source backed by a `.rvcsi` capture file.
///
/// The header is parsed eagerly on [`FileReplayAdapter::open`]; frames are
/// parsed lazily, one line at a time, on each [`CsiSource::next_frame`] call.
/// Timestamps, ordering and per-frame [`rvcsi_core::ValidationStatus`] are
/// preserved verbatim — replay does not re-validate or re-order anything, it
/// only deserializes what was stored.
///
/// `replay_speed` is carried for the daemon/CLI to pace playback with; the
/// adapter itself never sleeps.
#[derive(Debug)]
pub struct FileReplayAdapter {
    header: CaptureHeader,
    profile: AdapterProfile,
    source_id: SourceId,
    reader: BufReader<File>,
    /// 1-based line number of the line a subsequent `next_frame` will read.
    next_line: usize,
    frames_delivered: u64,
    at_eof: bool,
    replay_speed: f32,
    last_status: Option<String>,
}

impl FileReplayAdapter {
    /// Open `path` for replay at real-time speed (`replay_speed == 1.0`).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_speed(path, 1.0)
    }

    /// Open `path` for replay, carrying `replay_speed` for downstream pacing.
    pub fn open_with_speed(path: impl AsRef<Path>, replay_speed: f32) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let mut reader = BufReader::new(file);

        let mut first = String::new();
        let n = reader.read_line(&mut first)?;
        if n == 0 {
            return Err(RvcsiError::parse(0, "empty capture file: missing header line"));
        }
        let header: CaptureHeader = serde_json::from_str(first.trim_end_matches(['\n', '\r']))
            .map_err(|e| RvcsiError::parse(0, format!("invalid .rvcsi header line: {e}")))?;
        if header.rvcsi_capture_version != CAPTURE_VERSION {
            return Err(RvcsiError::parse(
                0,
                format!(
                    "unsupported .rvcsi capture version {} (this build supports {})",
                    header.rvcsi_capture_version, CAPTURE_VERSION
                ),
            ));
        }

        let profile = header.adapter_profile.clone();
        let source_id = header.source_id.clone();
        Ok(FileReplayAdapter {
            header,
            profile,
            source_id,
            reader,
            next_line: 2,
            frames_delivered: 0,
            at_eof: false,
            replay_speed,
            last_status: None,
        })
    }

    /// The capture header parsed from the file.
    pub fn header(&self) -> &CaptureHeader {
        &self.header
    }

    /// Playback speed multiplier carried for the daemon/CLI (the adapter itself
    /// does not sleep).
    pub fn replay_speed(&self) -> f32 {
        self.replay_speed
    }

    /// Whether the underlying file has been fully consumed.
    pub fn is_at_eof(&self) -> bool {
        self.at_eof
    }
}

impl CsiSource for FileReplayAdapter {
    fn profile(&self) -> &AdapterProfile {
        &self.profile
    }

    fn session_id(&self) -> SessionId {
        self.header.session_id
    }

    fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    fn next_frame(&mut self) -> core::result::Result<Option<CsiFrame>, RvcsiError> {
        if self.at_eof {
            return Ok(None);
        }
        loop {
            let mut line = String::new();
            let read = self.reader.read_line(&mut line)?;
            if read == 0 {
                self.at_eof = true;
                return Ok(None);
            }
            let line_no = self.next_line;
            self.next_line += 1;
            let trimmed = line.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                // Tolerate blank lines (e.g. a trailing newline at EOF).
                continue;
            }
            let frame: CsiFrame = serde_json::from_str(trimmed).map_err(|e| {
                self.last_status = Some(format!("parse error at line {line_no}"));
                RvcsiError::parse(line_no, format!("invalid frame line {line_no}: {e}"))
            })?;
            self.frames_delivered += 1;
            return Ok(Some(frame));
        }
    }

    fn health(&self) -> SourceHealth {
        SourceHealth {
            connected: !self.at_eof,
            frames_delivered: self.frames_delivered,
            frames_rejected: 0,
            status: self.last_status.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::FileRecorder;
    use rvcsi_core::{AdapterKind, FrameId, ValidationStatus};
    use std::io::Write;

    fn frame(id: u64, ts: u64) -> CsiFrame {
        CsiFrame::from_iq(
            FrameId(id),
            SessionId(1),
            SourceId::from("rep-test"),
            AdapterKind::File,
            ts,
            6,
            20,
            vec![1.0, 2.0],
            vec![0.0, 1.0],
        )
    }

    fn write_capture(path: &Path, frames: &[CsiFrame]) -> CaptureHeader {
        let header = CaptureHeader::new(
            SessionId(1),
            SourceId::from("rep-test"),
            AdapterProfile::offline(AdapterKind::File),
        )
        .with_created_unix_ns(0);
        let mut rec = FileRecorder::create(path, &header).unwrap();
        for f in frames {
            rec.write_frame(f).unwrap();
        }
        rec.finish().unwrap();
        header
    }

    #[test]
    fn open_speed_default_is_one() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), &[]);
        let a = FileReplayAdapter::open(tmp.path()).unwrap();
        assert_eq!(a.replay_speed(), 1.0);
        let b = FileReplayAdapter::open_with_speed(tmp.path(), 4.0).unwrap();
        assert_eq!(b.replay_speed(), 4.0);
    }

    #[test]
    fn replays_frames_in_order() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let frames = vec![frame(0, 10), frame(1, 20), frame(2, 30)];
        let header = write_capture(tmp.path(), &frames);
        let mut a = FileReplayAdapter::open(tmp.path()).unwrap();
        assert_eq!(a.header(), &header);
        assert_eq!(a.session_id(), SessionId(1));
        assert_eq!(a.source_id(), &SourceId::from("rep-test"));
        let mut got = Vec::new();
        while let Some(f) = a.next_frame().unwrap() {
            got.push(f);
        }
        assert_eq!(got, frames);
        assert!(a.is_at_eof());
        assert!(!a.health().connected);
        assert_eq!(a.health().frames_delivered, 3);
        // Repeated calls after EOF stay at None.
        assert!(a.next_frame().unwrap().is_none());
    }

    #[test]
    fn header_only_file_yields_no_frames() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), &[]);
        let mut a = FileReplayAdapter::open(tmp.path()).unwrap();
        assert!(a.next_frame().unwrap().is_none());
        assert_eq!(a.health().frames_delivered, 0);
    }

    #[test]
    fn validation_status_preserved() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut f = frame(0, 1);
        f.validation = ValidationStatus::Degraded;
        f.quality_score = 0.42;
        f.quality_reasons = vec!["missing rssi".to_string()];
        write_capture(tmp.path(), &[f.clone()]);
        let mut a = FileReplayAdapter::open(tmp.path()).unwrap();
        let back = a.next_frame().unwrap().unwrap();
        assert_eq!(back, f);
        assert_eq!(back.validation, ValidationStatus::Degraded);
        assert_eq!(back.quality_reasons, vec!["missing rssi".to_string()]);
    }

    #[test]
    fn bad_header_is_parse_error_at_offset_zero() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let mut f = File::create(tmp.path()).unwrap();
            f.write_all(b"not json\n").unwrap();
        }
        let err = FileReplayAdapter::open(tmp.path()).unwrap_err();
        match err {
            RvcsiError::Parse { offset, .. } => assert_eq!(offset, 0),
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn garbage_frame_line_is_parse_error_with_line_number() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = CaptureHeader::new(
            SessionId(1),
            SourceId::from("rep-test"),
            AdapterProfile::offline(AdapterKind::File),
        )
        .with_created_unix_ns(0);
        {
            let mut f = File::create(tmp.path()).unwrap();
            serde_json::to_writer(&mut f, &header).unwrap();
            f.write_all(b"\n").unwrap();
            // line 2: a good frame
            serde_json::to_writer(&mut f, &frame(0, 1)).unwrap();
            f.write_all(b"\n").unwrap();
            // line 3: garbage
            f.write_all(b"{not a frame}\n").unwrap();
        }
        let mut a = FileReplayAdapter::open(tmp.path()).unwrap();
        assert!(a.next_frame().unwrap().is_some()); // line 2 ok
        let err = a.next_frame().unwrap_err(); // line 3
        match err {
            RvcsiError::Parse { offset, .. } => assert_eq!(offset, 3),
            other => panic!("expected Parse at line 3, got {other:?}"),
        }
    }

    #[test]
    fn nonexistent_path_is_io_error() {
        let err = FileReplayAdapter::open("/no/such/rvcsi/file.rvcsi").unwrap_err();
        assert!(matches!(err, RvcsiError::Io(_)), "expected Io, got {err:?}");
    }

    #[test]
    fn wrong_version_rejected() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut header = CaptureHeader::new(
            SessionId(1),
            SourceId::from("x"),
            AdapterProfile::offline(AdapterKind::File),
        );
        header.rvcsi_capture_version = 999;
        {
            let mut f = File::create(tmp.path()).unwrap();
            serde_json::to_writer(&mut f, &header).unwrap();
            f.write_all(b"\n").unwrap();
        }
        let err = FileReplayAdapter::open(tmp.path()).unwrap_err();
        assert!(matches!(err, RvcsiError::Parse { offset: 0, .. }));
    }
}

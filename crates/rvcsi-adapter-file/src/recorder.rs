//! [`FileRecorder`] — writes a `.rvcsi` capture: a header line followed by one
//! JSON line per [`CsiFrame`].

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use rvcsi_core::{CsiFrame, Result};

use crate::format::CaptureHeader;

/// Append-only writer for a `.rvcsi` capture file.
///
/// Create one with [`FileRecorder::create`] (which writes the header line),
/// push frames with [`FileRecorder::write_frame`], and call
/// [`FileRecorder::finish`] (or just drop it after [`FileRecorder::flush`]) to
/// be sure everything reached disk.
pub struct FileRecorder {
    writer: BufWriter<File>,
    frames_written: u64,
}

impl FileRecorder {
    /// Create `path` (truncating any existing file) and write `header` as the
    /// first line.
    pub fn create(path: impl AsRef<Path>, header: &CaptureHeader) -> Result<Self> {
        let file = File::create(path.as_ref())?;
        let mut writer = BufWriter::new(file);
        write_json_line(&mut writer, header)?;
        Ok(FileRecorder {
            writer,
            frames_written: 0,
        })
    }

    /// Append one frame as a JSON line.
    pub fn write_frame(&mut self, frame: &CsiFrame) -> Result<()> {
        write_json_line(&mut self.writer, frame)?;
        self.frames_written += 1;
        Ok(())
    }

    /// Flush buffered bytes to the underlying file.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    /// Number of frames written so far (the header line is not counted).
    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    /// Flush and close the file, consuming the recorder.
    pub fn finish(mut self) -> Result<()> {
        self.flush()
    }
}

/// Serialize `value` as a single JSON line (no embedded newlines — `serde_json`
/// compact form never produces them) followed by `\n`.
fn write_json_line<W: Write, T: serde::Serialize>(writer: &mut W, value: &T) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_core::{AdapterKind, AdapterProfile, FrameId, SessionId, SourceId};
    use std::io::Read;

    fn frame(id: u64, ts: u64) -> CsiFrame {
        CsiFrame::from_iq(
            FrameId(id),
            SessionId(1),
            SourceId::from("rec-test"),
            AdapterKind::File,
            ts,
            6,
            20,
            vec![1.0, 2.0, 3.0],
            vec![0.5, 0.5, 0.5],
        )
    }

    #[test]
    fn writes_header_then_frames_and_counts() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let header = CaptureHeader::new(
            SessionId(1),
            SourceId::from("rec-test"),
            AdapterProfile::offline(AdapterKind::File),
        )
        .with_created_unix_ns(0);
        let mut rec = FileRecorder::create(tmp.path(), &header).unwrap();
        assert_eq!(rec.frames_written(), 0);
        rec.write_frame(&frame(0, 100)).unwrap();
        rec.write_frame(&frame(1, 200)).unwrap();
        assert_eq!(rec.frames_written(), 2);
        rec.finish().unwrap();

        let mut contents = String::new();
        File::open(tmp.path()).unwrap().read_to_string(&mut contents).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        let parsed_header: CaptureHeader = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed_header, header);
        let f0: CsiFrame = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(f0, frame(0, 100));
    }
}

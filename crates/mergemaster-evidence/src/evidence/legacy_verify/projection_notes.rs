//! CLI batch-check rows: bounded headers, never whole-output retention.
use super::*;
use crate::evidence::legacy_verify::{crate_manifest_ops::exception, utf8_stream::Utf8};
const HEADER_LIMIT: usize = 138;
struct Notes<'a> {
    capture: ProjectionCapture<'a>,
    decoder: Utf8,
    row: String,
    row_bytes: usize,
    after_cr: bool,
    overflow: bool,
    present: Vec<bool>,
    max_rows: usize,
}
impl Notes<'_> {
    fn character(&mut self, c: char) {
        if self.overflow {
            return;
        }
        if self.after_cr && c == '\n' {
            self.after_cr = false;
            return;
        }
        self.after_cr = c == '\r';
        self.row_bytes += c.len_utf8();
        if self.row_bytes > HEADER_LIMIT {
            self.overflow = true;
            return;
        }
        if matches!(
            c,
            '\n' | '\r'
                | '\u{b}'
                | '\u{c}'
                | '\u{1c}'
                | '\u{1d}'
                | '\u{1e}'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            self.end_row();
        } else {
            self.row.push(c);
        }
    }
    fn end_row(&mut self) {
        if self.present.len() < self.max_rows {
            self.present.push(!self.row.ends_with(" missing"));
        }
        self.row.clear();
        self.row_bytes = 0;
    }
}
impl CaptureSink for Notes<'_> {
    type Error = ProcessError;
    type Output = Result<Vec<bool>, PolicyError>;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), ProcessError> {
        match stream {
            Stream::Stderr => self.capture.push(stream, bytes)?,
            Stream::Stdout => {
                // Temporarily move the decoder to keep row mutation disjoint.
                let mut decoder = std::mem::take(&mut self.decoder);
                decoder.push(bytes, |c| self.character(c));
                self.decoder = decoder;
                if self.overflow {
                    return Err(ProcessError::Policy(Box::new(failure(
                        "note Git header exceeds 138 bytes",
                    ))));
                }
            }
        }
        Ok(())
    }
    fn finish(mut self, status: ExitStatus) -> Self::Output {
        self.capture.finish(status)?;
        self.decoder
            .finish()
            .map_err(|e| exception("UnicodeDecodeError", e))?;
        if !self.row.is_empty() && self.present.len() < self.max_rows {
            self.present.push(!self.row.ends_with(" missing"));
        }
        Ok(self.present)
    }
    fn context(self, error: ProcessError) -> ProcessError {
        self.capture.context(error)
    }
}
pub(crate) fn read(
    command: &mut Command,
    input: &[u8],
    max_rows: usize,
) -> Result<Vec<bool>, PolicyError> {
    collect(
        command,
        input,
        "cat-file",
        Duration::from_secs(60),
        Notes {
            capture: ProjectionCapture::new("cat-file", ExpectedOutput::Discard),
            decoder: Utf8::default(),
            row: String::new(),
            row_bytes: 0,
            after_cr: false,
            overflow: false,
            present: Vec::new(),
            max_rows,
        },
    )?
}
#[cfg(test)]
#[path = "note_presence_tests.rs"]
mod tests;

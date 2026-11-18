//! Incremental strict ref parsing: only potentially matching records are retained.
use super::*;
use crate::evidence::legacy_verify::{crate_manifest_ops::exception, log_lines, utf8_stream::Utf8};
struct Rows<'a, C> {
    prefix: &'a str,
    line: String,
    discarded: bool,
    found: C,
}
impl<C: Extend<String>> Rows<'_, C> {
    fn character(&mut self, character: char) {
        if matches!(
            character,
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
            self.end_line();
        } else if !self.discarded {
            // A matching row is OID + space + prefix + the identical OID.
            if self.line.len() + character.len_utf8() > self.prefix.len() + 129 {
                self.discarded = true;
                self.line.clear();
            } else {
                self.line.push(character);
            }
        }
    }
    fn end_line(&mut self) {
        if !self.discarded
            && let Some((id, name)) = self.line.split_once(' ')
            && log_lines::oid(id)
            && name.strip_prefix(self.prefix) == Some(id)
        {
            self.found.extend(std::iter::once(id.to_owned()));
        }
        self.discarded = false;
        self.line.clear();
    }
}
struct References<'a, C> {
    capture: ProjectionCapture<'a>,
    decoder: Utf8,
    rows: Rows<'a, C>,
}
impl<C: Extend<String>> CaptureSink for References<'_, C> {
    type Error = ProcessError;
    type Output = Result<C, PolicyError>;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), ProcessError> {
        match stream {
            Stream::Stdout => self
                .decoder
                .push(bytes, |character| self.rows.character(character)),
            Stream::Stderr => self.capture.push(stream, bytes)?,
        }
        Ok(())
    }
    fn finish(mut self, status: ExitStatus) -> Self::Output {
        self.capture.finish(status)?;
        self.decoder
            .finish()
            .map_err(|e| exception("UnicodeDecodeError", e))?;
        self.rows.end_line();
        Ok(self.rows.found)
    }
    fn context(self, error: ProcessError) -> ProcessError {
        self.capture.context(error)
    }
}
pub(crate) fn read<C: Default + Extend<String>>(
    command: &mut Command,
    prefix: &str,
    timeout: Duration,
) -> Result<C, PolicyError> {
    let capture = ProjectionCapture::new("for-each-ref", ExpectedOutput::Discard);
    collect(
        command,
        b"",
        "for-each-ref",
        timeout,
        References {
            capture,
            decoder: Utf8::default(),
            rows: Rows {
                prefix,
                line: String::new(),
                discarded: false,
                found: C::default(),
            },
        },
    )?
}

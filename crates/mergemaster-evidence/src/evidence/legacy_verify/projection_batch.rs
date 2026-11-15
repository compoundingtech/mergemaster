//! One oracle batch invocation, bounded per frame rather than whole stdout.
use super::*;
use crate::evidence::legacy_verify::raw_batch::header_size;
struct Batch<'a, F> {
    capture: ProjectionCapture<'a>,
    requests: &'a [String],
    index: usize,
    header: Vec<u8>,
    body: Vec<u8>,
    remaining: Option<u64>,
    retain: bool,
    consume: F,
}
impl<F: FnMut(&[u8]) -> Result<bool, PolicyError>> Batch<'_, F> {
    fn stdout(&mut self, mut bytes: &[u8]) -> Result<(), PolicyError> {
        while !bytes.is_empty() {
            if let Some(remaining) = self.remaining {
                if remaining > 0 {
                    let count = remaining.min(bytes.len() as u64) as usize;
                    if self.retain {
                        self.body.extend_from_slice(&bytes[..count]);
                    }
                    self.remaining = Some(remaining - count as u64);
                    bytes = &bytes[count..];
                } else {
                    if bytes[0] != b'\n' {
                        return Err(failure("invalid raw Git body terminator"));
                    }
                    if self.retain {
                        self.retain = (self.consume)(&self.body)?;
                    }
                    self.body.clear();
                    self.remaining = None;
                    self.index += 1;
                    bytes = &bytes[1..];
                }
            } else {
                let request = self
                    .requests
                    .get(self.index)
                    .ok_or_else(|| failure("unexpected raw Git output"))?;
                self.header.push(bytes[0]);
                bytes = &bytes[1..];
                if self.header.len() > 128 || self.header.last() == Some(&b'\n') {
                    self.remaining = header_size(&self.header, request, self.retain)?;
                    if self.remaining.is_none() {
                        self.index += 1;
                    }
                    self.header.clear();
                }
            }
        }
        Ok(())
    }
}
impl<F: FnMut(&[u8]) -> Result<bool, PolicyError>> CaptureSink for Batch<'_, F> {
    type Error = ProcessError;
    type Output = Result<(), PolicyError>;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), ProcessError> {
        match stream {
            Stream::Stdout => self
                .stdout(bytes)
                .map_err(|e| ProcessError::Policy(Box::new(e))),
            Stream::Stderr => self.capture.push(stream, bytes),
        }
    }
    fn finish(self, status: ExitStatus) -> Self::Output {
        self.capture.finish(status)?;
        if !self.header.is_empty() || self.remaining.is_some() || self.index != self.requests.len()
        {
            return Err(failure("unterminated raw Git header"));
        }
        Ok(())
    }
    fn context(self, error: ProcessError) -> ProcessError {
        self.capture.context(error)
    }
}
/// Consume bounded frames; returning false discards all later bodies while still
/// draining under the same owned deadline and validating exit status/stderr.
pub fn read(
    command: &mut Command,
    requests: &[String],
    consume: impl FnMut(&[u8]) -> Result<bool, PolicyError>,
) -> Result<(), PolicyError> {
    let mut input = Vec::new();
    for request in requests {
        crate::evidence::oid(request.strip_suffix("^{tree}").unwrap_or(request))
            .map_err(|e| failure(e.to_string()))?;
        input.extend_from_slice(request.as_bytes());
        input.push(b'\n');
    }
    collect(
        command,
        &input,
        "cat-file",
        Duration::from_secs(60),
        Batch {
            capture: ProjectionCapture::new("cat-file", ExpectedOutput::Discard),
            requests,
            index: 0,
            header: Vec::new(),
            body: Vec::new(),
            remaining: None,
            retain: true,
            consume,
        },
    )?
}
#[cfg(test)]
#[path = "batch_capture_tests.rs"]
mod tests;

//! Bounded retention does not turn successful verbose Git into a refusal.
use super::crate_inputs::failure;
use crate::{
    evidence::legacy_policy::PolicyError,
    gate::git::deadline::{CaptureSink, GitChild, Stream},
};
use std::{
    collections::VecDeque,
    io,
    process::{Command, ExitStatus},
    time::Duration,
};
const STDERR_LIMIT: usize = 1024 * 1024;
#[derive(Clone, Copy)]
pub enum ExpectedOutput {
    Sha1,
    Sha256,
    Discard,
}
use super::projection_oid::{ObjectId, space};
struct ProjectionCapture<'a> {
    operation: &'a str,
    expected: ExpectedOutput,
    stdout: ObjectId,
    stderr: VecDeque<u8>,
    overflow: bool,
}
struct ProcessError(io::Error, bool);
impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self(error, false)
    }
}
impl CaptureSink for ProjectionCapture<'_> {
    type Error = ProcessError;
    type Output = Result<Vec<u8>, PolicyError>;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), ProcessError> {
        match stream {
            Stream::Stdout => {
                if !matches!(self.expected, ExpectedOutput::Discard) {
                    self.stdout.push(bytes);
                }
            }
            Stream::Stderr => {
                let excess = self
                    .stderr
                    .len()
                    .saturating_add(bytes.len())
                    .saturating_sub(STDERR_LIMIT);
                self.overflow |= excess != 0;
                if bytes.len() >= STDERR_LIMIT {
                    self.stderr.clear();
                    self.stderr.extend(&bytes[bytes.len() - STDERR_LIMIT..]);
                } else {
                    self.stderr.drain(..excess.min(self.stderr.len()));
                    self.stderr.extend(bytes);
                }
            }
        }
        Ok(())
    }
    fn finish(mut self, status: ExitStatus) -> Self::Output {
        if !status.success() {
            if self.overflow {
                return Err(failure("Git projection stderr exceeds 1048576 bytes"));
            }
            return Err(failure(format!(
                "git {}: {}",
                self.operation,
                String::from_utf8_lossy(self.stderr.make_contiguous()).trim_matches(space)
            )));
        }
        let width = match self.expected {
            ExpectedOutput::Sha1 => 40,
            ExpectedOutput::Sha256 => 64,
            ExpectedOutput::Discard => return Ok(Vec::new()),
        };
        self.stdout.finish(width).ok_or_else(|| {
            failure(format!(
                "Git {} returned a malformed object id",
                self.operation
            ))
        })
    }

    fn context(self, mut error: ProcessError) -> ProcessError {
        error.1 = true;
        error
    }
}
pub fn exchange(
    command: &mut Command,
    bytes: &[u8],
    operation: &str,
    expected: ExpectedOutput,
    timeout: Duration,
) -> Result<Vec<u8>, PolicyError> {
    let sink = ProjectionCapture {
        operation,
        expected,
        stdout: ObjectId::default(),
        stderr: VecDeque::new(),
        overflow: false,
    };
    GitChild::capture_with_sink(command, Some(bytes), timeout, sink).map_err(|error| {
        failure(format!(
            "git {operation}: {}",
            super::projection_process_error::diagnostic(command, &error.0, error.1, timeout)
        ))
    })?
}
#[cfg(test)]
#[path = "projection_capture_tests.rs"]
mod tests;

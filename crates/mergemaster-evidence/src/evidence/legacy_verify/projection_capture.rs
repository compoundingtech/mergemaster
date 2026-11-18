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
#[derive(Clone)]
pub enum ExpectedOutput {
    Sha1,
    Sha256,
    Discard,
    Bytes(usize),
    Source(super::source_resource::SourceResource),
}
use super::projection_oid::{ObjectId, space};
struct ProjectionCapture<'a> {
    operation: &'a str,
    expected: ExpectedOutput,
    stdout: ObjectId,
    bytes: Vec<u8>,
    stderr: VecDeque<u8>,
    overflow: bool,
}
impl<'a> ProjectionCapture<'a> {
    fn new(operation: &'a str, expected: ExpectedOutput) -> Self {
        Self {
            operation,
            expected,
            stdout: ObjectId::default(),
            bytes: Vec::new(),
            stderr: VecDeque::new(),
            overflow: false,
        }
    }
}
enum ProcessError {
    Io(io::Error, bool),
    Resource(super::source_resource::SourceResource),
    Bytes(usize),
    Policy(Box<PolicyError>),
}
impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self::Io(error, false)
    }
}
impl CaptureSink for ProjectionCapture<'_> {
    type Error = ProcessError;
    type Output = Result<Vec<u8>, PolicyError>;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), ProcessError> {
        match stream {
            Stream::Stdout => match &self.expected {
                ExpectedOutput::Bytes(limit) => {
                    let bound = limit.saturating_add(1);
                    let retained = bytes.len().min(bound.saturating_sub(self.bytes.len()));
                    self.bytes.extend_from_slice(&bytes[..retained]);
                    if self.bytes.len() > *limit {
                        return Err(ProcessError::Bytes(*limit));
                    }
                }
                ExpectedOutput::Source(resource) => {
                    let limit = resource.byte_limit();
                    let bound = limit + 1;
                    let retained = bytes.len().min(bound.saturating_sub(self.bytes.len()));
                    self.bytes.extend_from_slice(&bytes[..retained]);
                    if self.bytes.len() > limit {
                        return Err(ProcessError::Resource(resource.clone()));
                    }
                }
                ExpectedOutput::Discard => {}
                ExpectedOutput::Sha1 | ExpectedOutput::Sha256 => self.stdout.push(bytes),
            },
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
            ExpectedOutput::Source(_) => return Ok(self.bytes),
            ExpectedOutput::Bytes(_) => return Ok(self.bytes),
        };
        self.stdout.finish(width).ok_or_else(|| {
            failure(format!(
                "Git {} returned a malformed object id",
                self.operation
            ))
        })
    }

    fn context(self, mut error: ProcessError) -> ProcessError {
        if let ProcessError::Io(_, spawned) = &mut error {
            *spawned = true;
        }
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
    collect(
        command,
        bytes,
        operation,
        timeout,
        ProjectionCapture::new(operation, expected),
    )?
}
fn collect<S: CaptureSink<Error = ProcessError>>(
    command: &mut Command,
    bytes: &[u8],
    operation: &str,
    timeout: Duration,
    sink: S,
) -> Result<S::Output, PolicyError> {
    GitChild::capture_with_sink(command, Some(bytes), timeout, sink)
        .map_err(|error| process_error(command, operation, timeout, error))
}
fn process_error(
    command: &Command,
    operation: &str,
    timeout: Duration,
    error: ProcessError,
) -> PolicyError {
    match error {
        ProcessError::Policy(error) => *error,
        ProcessError::Resource(resource) => resource.into_error(),
        ProcessError::Bytes(limit) => failure(format!("Git output exceeds {limit} bytes")),
        ProcessError::Io(error, spawned) => failure(format!(
            "git {operation}: {}",
            super::projection_process_error::diagnostic(command, &error, spawned, timeout)
        )),
    }
}
pub(super) fn record_blob(command: &mut Command) -> Result<Vec<u8>, PolicyError> {
    let timeout = Duration::from_secs(60);
    let sink = ProjectionCapture::new(
        "cat-file",
        ExpectedOutput::Bytes(super::statement::MAX_STATEMENT_BYTES),
    );
    GitChild::capture_with_sink(command, Some(b""), timeout, sink).map_err(|error| match error {
        ProcessError::Bytes(_) => PolicyError {
            reason: "statement-too-large",
            ..failure("record statement exceeds 1048576 bytes")
        },
        other => process_error(command, "cat-file", timeout, other),
    })?
}
/// Only ordinary Git/process failures mean an absent subject; cap failures abort.
pub(super) fn record_subject(command: &mut Command) -> Result<Option<Vec<u8>>, PolicyError> {
    let timeout = Duration::from_secs(60);
    let sink = ProjectionCapture::new("rev-parse", ExpectedOutput::Bytes(128));
    match GitChild::capture_with_sink(command, Some(b""), timeout, sink) {
        Ok(result) => Ok(result.ok()),
        Err(error @ ProcessError::Bytes(_)) => {
            Err(process_error(command, "rev-parse", timeout, error))
        }
        Err(_) => Ok(None),
    }
}
#[path = "projection_refs.rs"]
mod refs;
pub(super) use refs::read as reference_ids;
#[path = "projection_notes.rs"]
mod notes;
pub(super) use notes::read as note_presence;
#[path = "projection_batch.rs"]
mod batch;
pub use batch::read as raw_batch;
#[cfg(test)]
#[path = "projection_capture_tests.rs"]
mod tests;

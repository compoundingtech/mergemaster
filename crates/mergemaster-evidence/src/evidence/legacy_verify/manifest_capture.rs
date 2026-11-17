//! Bare inherited, no-timeout bounded capture for rust-test-keys sources.
use super::{
    source_io,
    source_resource::{SOURCE_BYTES, SourceResource},
};
use crate::{
    evidence::legacy_policy::PolicyError,
    gate::git::deadline::{CaptureSink, GitChild, Stream},
};
use std::process::{Command, ExitStatus, Output};
struct Capture {
    stdout: Vec<u8>,
    stderr: Option<Vec<u8>>,
    resource: SourceResource,
}
enum Error {
    Io(std::io::Error),
    Resource(SourceResource),
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl CaptureSink for Capture {
    type Error = Error;
    type Output = Output;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), Error> {
        let retained = match stream {
            Stream::Stdout => Some(&mut self.stdout),
            Stream::Stderr => self.stderr.as_mut(),
        };
        if let Some(retained) = retained {
            let length = bytes
                .len()
                .min((SOURCE_BYTES + 1).saturating_sub(retained.len()));
            retained.extend_from_slice(&bytes[..length]);
            if retained.len() > SOURCE_BYTES {
                return Err(Error::Resource(self.resource.clone()));
            }
        }
        Ok(())
    }
    fn finish(self, status: ExitStatus) -> Self::Output {
        Output {
            status,
            stdout: self.stdout,
            stderr: self.stderr.unwrap_or_default(),
        }
    }
    fn context(self, error: Error) -> Error {
        error
    }
}
pub(super) fn read(
    command: &mut Command,
    resource: SourceResource,
) -> Result<Option<Vec<u8>>, PolicyError> {
    metadata(command, resource, false).map(|out| out.status.success().then_some(out.stdout))
}
pub(super) fn metadata(
    command: &mut Command,
    resource: SourceResource,
    stderr: bool,
) -> Result<Output, PolicyError> {
    GitChild::capture_without_timeout(
        command,
        None,
        Capture {
            stdout: Vec::new(),
            stderr: stderr.then(Vec::new),
            resource,
        },
    )
    .map_err(|error| match error {
        Error::Io(error) => source_io::error(command.get_program(), &error),
        Error::Resource(resource) => resource.into_error(),
    })
}

//! Bare inherited, no-timeout bounded capture for rust-test-keys sources.
use super::{
    source_io,
    source_resource::{SOURCE_BYTES, SourceResource},
};
use crate::{
    evidence::legacy_policy::PolicyError,
    gate::git::deadline::{CaptureSink, GitChild, Stream},
};
use std::process::{Command, ExitStatus};
struct Capture {
    stdout: Vec<u8>,
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
    type Output = Option<Vec<u8>>;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), Error> {
        // The oracle captures stderr but show() never consumes it.
        if matches!(stream, Stream::Stdout) {
            let retained = bytes
                .len()
                .min((SOURCE_BYTES + 1).saturating_sub(self.stdout.len()));
            self.stdout.extend_from_slice(&bytes[..retained]);
            if self.stdout.len() > SOURCE_BYTES {
                return Err(Error::Resource(self.resource.clone()));
            }
        }
        Ok(())
    }
    fn finish(self, status: ExitStatus) -> Self::Output {
        status.success().then_some(self.stdout)
    }
    fn context(self, error: Error) -> Error {
        error
    }
}
pub(super) fn read(
    command: &mut Command,
    resource: SourceResource,
) -> Result<Option<Vec<u8>>, PolicyError> {
    GitChild::capture_without_timeout(
        command,
        None,
        Capture {
            stdout: Vec::new(),
            resource,
        },
    )
    .map_err(|error| match error {
        Error::Io(error) => source_io::error(command.get_program(), &error),
        Error::Resource(resource) => resource.into_error(),
    })
}

//! Exact inherited no_lazy subprocess boundary for shadow-log reads.
use super::source_resource::{SOURCE_BYTES, SourceResource};
use super::{crate_manifest_ops::exception, projection_process_error, source_io};
use crate::{
    evidence::legacy_policy::PolicyError,
    gate::git::deadline::{CaptureSink, GitChild, Stream},
};
use std::{
    ffi::OsStr,
    io,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::{Command, ExitStatus},
    time::Duration,
};
enum ProcessError {
    Io(io::Error, bool),
    Resource(SourceResource),
}
impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self::Io(error, false)
    }
}
pub struct Read {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
}
/// Stdout is an in-memory source; stderr is drained without retention.
struct Capture {
    stdout: Vec<u8>,
    resource: SourceResource,
}
impl CaptureSink for Capture {
    type Error = ProcessError;
    type Output = Read;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), ProcessError> {
        if matches!(stream, Stream::Stdout) {
            let retained = bytes
                .len()
                .min((SOURCE_BYTES + 1).saturating_sub(self.stdout.len()));
            self.stdout.extend_from_slice(&bytes[..retained]);
            if self.stdout.len() > SOURCE_BYTES {
                return Err(ProcessError::Resource(self.resource.clone()));
            }
        }
        Ok(())
    }
    fn finish(self, status: ExitStatus) -> Read {
        Read {
            status,
            stdout: self.stdout,
        }
    }
    fn context(self, mut error: ProcessError) -> ProcessError {
        if let ProcessError::Io(_, spawned) = &mut error {
            *spawned = true;
        }
        error
    }
}
/// Nonzero Git status remains ordinary data, except source overflow.
pub fn read(repo: &Path, args: &[&OsStr], resource: SourceResource) -> Result<Read, PolicyError> {
    read_with(repo, args, Duration::from_secs(60), None, resource)
}
fn read_with(
    repo: &Path,
    args: &[&OsStr],
    timeout: Duration,
    path: Option<&OsStr>,
    resource: SourceResource,
) -> Result<Read, PolicyError> {
    // Inspect original bytes: Command::get_args omits rejected NUL arguments.
    if std::iter::once(repo.as_os_str())
        .chain(args.iter().copied())
        .any(|arg| arg.as_bytes().contains(&0))
    {
        return Err(exception("ValueError", "embedded null byte"));
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args(["-c", "gpg.format=ssh", "-c", "gpg.ssh.program=ssh-keygen"])
        .args(args)
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("LC_ALL", "C");
    if let Some(path) = path {
        command.env("PATH", path);
    }
    GitChild::capture_with_sink(
        &mut command,
        None,
        timeout,
        Capture {
            stdout: Vec::new(),
            resource,
        },
    )
    .map_err(|error| {
        let (error, spawned) = match error {
            ProcessError::Resource(resource) => return resource.into_error(),
            ProcessError::Io(error, spawned) => (error, spawned),
        };
        if error.kind() == io::ErrorKind::TimedOut {
            exception(
                "TimeoutExpired",
                projection_process_error::diagnostic(&command, &error, spawned, timeout),
            )
        } else if !spawned {
            source_io::error(command.get_program(), &error)
        } else {
            exception(
                "OSError",
                projection_process_error::diagnostic(&command, &error, true, timeout),
            )
        }
    })
}
#[cfg(test)]
#[path = "log_transport_tests.rs"]
mod tests;

//! Exact inherited no_lazy subprocess boundary for shadow-log reads.
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
struct ProcessError {
    error: io::Error,
    spawned: bool,
}
impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            spawned: false,
        }
    }
}
pub struct Read {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
}
#[derive(Default)]
struct Capture {
    stdout: Vec<u8>,
}
impl CaptureSink for Capture {
    type Error = ProcessError;
    type Output = Read;
    fn push(&mut self, stream: Stream, bytes: &[u8]) -> Result<(), ProcessError> {
        if matches!(stream, Stream::Stdout) {
            self.stdout.extend_from_slice(bytes);
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
        error.spawned = true;
        error
    }
}
/// Nonzero Git status remains ordinary data. No native sanitizer or byte cap.
pub fn read(repo: &Path, args: &[&OsStr]) -> Result<Read, PolicyError> {
    read_with(repo, args, Duration::from_secs(60), None)
}
fn read_with(
    repo: &Path,
    args: &[&OsStr],
    timeout: Duration,
    path: Option<&OsStr>,
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
    GitChild::capture_with_sink(&mut command, None, timeout, Capture::default()).map_err(|error| {
        if error.error.kind() == io::ErrorKind::TimedOut {
            exception(
                "TimeoutExpired",
                projection_process_error::diagnostic(
                    &command,
                    &error.error,
                    error.spawned,
                    timeout,
                ),
            )
        } else if !error.spawned {
            source_io::error(command.get_program(), &error.error)
        } else {
            exception(
                "OSError",
                projection_process_error::diagnostic(&command, &error.error, true, timeout),
            )
        }
    })
}
#[cfg(test)]
#[path = "log_transport_tests.rs"]
mod tests;

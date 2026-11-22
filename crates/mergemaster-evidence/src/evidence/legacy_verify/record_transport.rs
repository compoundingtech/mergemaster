//! Explicit record-reader transport; native hardening stays the default.
use super::{
    projection,
    projection_capture::{self, ExpectedOutput},
};
use crate::evidence::legacy_policy::PolicyError;
use std::{
    ffi::OsStr,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Transport {
    Native,
    Cli,
}
impl Transport {
    fn command(repo: &Path, args: &[&str]) -> Result<Command, PolicyError> {
        let mut command = projection::projection_command(repo, &[] as &[&str])?;
        if args.iter().any(|arg| arg.contains('\0')) {
            return Err(super::crate_manifest_ops::exception(
                "ValueError",
                "embedded null byte",
            ));
        }
        command.args(
            args.iter()
                .copied()
                .filter(|arg| args[0] == "rev-parse" || *arg != "--end-of-options"),
        );
        Ok(command)
    }
    pub(super) fn read(
        self,
        repo: &Path,
        args: &[&str],
        limit: usize,
    ) -> Result<Vec<u8>, PolicyError> {
        if self == Self::Native {
            return crate::gate::git::git_bounded(repo, args, limit).map_err(super::records::error);
        }
        let mut command = Self::command(repo, args)?;
        if args.starts_with(&["cat-file", "blob"]) {
            projection_capture::record_blob(&mut command)
        } else {
            projection_capture::exchange(
                &mut command,
                b"",
                args[0],
                ExpectedOutput::Bytes(limit),
                Duration::from_secs(60),
            )
        }
    }
    /// CLI-only record arguments retain Python's surrogateescaped argv bytes.
    pub(super) fn read_record(
        repo: &Path,
        args: &[&str],
        record: &OsStr,
        limit: usize,
    ) -> Result<Vec<u8>, PolicyError> {
        if record.as_encoded_bytes().contains(&0) {
            return Err(super::crate_manifest_ops::exception(
                "ValueError",
                "embedded null byte",
            ));
        }
        let mut command = Self::command(repo, args)?;
        command.arg(record);
        projection_capture::exchange(
            &mut command,
            b"",
            args[0],
            ExpectedOutput::Bytes(limit),
            Duration::from_secs(60),
        )
    }
    pub(super) fn subject(
        self,
        repo: &Path,
        subject: &str,
    ) -> Result<Option<Vec<u8>>, PolicyError> {
        let command = |args: &[&str]| {
            let mut command = if self == Self::Native {
                let mut command = crate::gate::git::command(repo);
                command.args(args);
                command
            } else {
                Self::command(repo, args)?
            };
            command.env("GIT_NO_LAZY_FETCH", "1").stdin(Stdio::piped());
            Ok::<_, PolicyError>(command)
        };
        // Probe the literal subject first: rev-parse also fails for present but
        // corrupt or wrong-type objects, so its status cannot establish absence.
        let mut probe = command(&["cat-file", "--batch-check=%(objectname)"])?;
        if !projection_capture::record_subject(&mut probe, subject)? {
            return Ok(None);
        }
        let object = format!("{subject}^{{tree}}");
        let mut tree = command(&[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &object,
        ])?;
        projection_capture::exchange(
            &mut tree,
            b"",
            "rev-parse",
            ExpectedOutput::Bytes(128),
            Duration::from_secs(60),
        )
        .map(Some)
        .map_err(projection_capture::subject_error)
    }
}

//! Python subprocess diagnostics for the legacy projection transport.
use super::python_repr::Repr;
use crate::evidence::legacy_policy::normalized_text::NormalizedText;
use std::{ffi::OsStr, io, os::unix::ffi::OsStrExt, process::Command, time::Duration};

/// POSIX filesystem decoding, shared by process diagnostics and CLI ingress.
pub fn decode(value: &OsStr) -> NormalizedText {
    if let Some(value) = value.to_str() {
        return value.into();
    }
    let mut bytes = value.as_bytes();
    let mut points = Vec::new();
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                points.extend(text.chars().map(u32::from));
                break;
            }
            Err(error) => {
                let (valid, tail) = bytes.split_at(error.valid_up_to());
                points.extend(String::from_utf8_lossy(valid).chars().map(u32::from));
                let count = error.error_len().unwrap_or(tail.len());
                points.extend(tail[..count].iter().map(|b| 0xdc00 + u32::from(*b)));
                bytes = &tail[count..];
            }
        }
    }
    NormalizedText::from_points(&points)
}
fn repr(value: &OsStr) -> String {
    Repr(decode(value).borrowed()).to_string()
}
pub fn diagnostic(
    command: &Command,
    error: &io::Error,
    spawned: bool,
    timeout: Duration,
) -> String {
    if error.kind() == io::ErrorKind::TimedOut {
        let argv = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(repr)
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "Command '[{argv}]' timed out after {} seconds",
            timeout.as_secs_f64()
        );
    }
    os_diagnostic(error, (!spawned).then(|| command.get_program()))
}
pub(super) fn os_diagnostic(error: &io::Error, filename: Option<&OsStr>) -> String {
    if let Some(errno) = error.raw_os_error() {
        let text = error.to_string();
        let suffix = format!(" (os error {errno})");
        let message = text.strip_suffix(&suffix).unwrap_or(&text);
        let filename = filename.map_or_else(String::new, |name| format!(": {}", repr(name)));
        return format!("[Errno {errno}] {message}{filename}");
    }
    error.to_string()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::git::deadline::GitChild;
    use std::{os::unix::ffi::OsStringExt, process::Stdio};
    #[test]
    fn process_errors_match_python() {
        let args = [
            std::ffi::OsString::from("a'b"),
            std::ffi::OsString::from_vec(b"raw\xff".to_vec()),
            "ü".into(),
        ];
        let mut command = Command::new("git");
        command.args(&args);
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "deadline");
        let oracle = crate::pinned_python::command().args(["-c", r#"import subprocess,sys; assert sys.version_info[:3]==(3,14,7); print(str(subprocess.TimeoutExpired(['git', "a'b", 'raw'+chr(0xdcff), 'ü'],60))); print(str(FileNotFoundError(2,'No such file or directory','git')))"#]).output().unwrap();
        assert!(oracle.status.success());
        let expected = String::from_utf8(oracle.stdout).unwrap();
        let lines: Vec<_> = expected.lines().collect();
        assert_eq!(
            diagnostic(&command, &timeout, true, Duration::from_secs(60)),
            lines[0]
        );
        assert_eq!(
            diagnostic(
                &command,
                &io::Error::from_raw_os_error(2),
                false,
                Duration::ZERO
            ),
            lines[1]
        );
        let mut missing = Command::new("/definitely-missing-projection-git");
        let error = missing.output().unwrap_err();
        assert_eq!(
            diagnostic(&missing, &error, false, Duration::ZERO),
            "[Errno 2] No such file or directory: '/definitely-missing-projection-git'"
        );
        let mut expired = Command::new("python3");
        expired
            .args(["-c", "import signal;signal.pause()"])
            .stdin(Stdio::piped());
        let error = GitChild::capture(&mut expired, Some(b""), Duration::ZERO).unwrap_err();
        assert_eq!(
            diagnostic(&expired, &error, true, Duration::ZERO),
            "Command '['python3', '-c', 'import signal;signal.pause()']' timed out after 0 seconds"
        );
    }
}

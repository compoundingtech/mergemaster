//! Uncaught Python filesystem/subprocess OS exceptions at legacy source boundaries.
use super::{crate_manifest_ops::exception, projection_process_error::os_diagnostic};
use crate::evidence::legacy_policy::PolicyError;
use std::{ffi::OsStr, io, os::unix::ffi::OsStrExt};

pub fn error(filename: &OsStr, error: &io::Error) -> PolicyError {
    if filename.as_bytes().contains(&0) {
        return exception("ValueError", "embedded null byte");
    }
    exception(
        class(error.raw_os_error()),
        os_diagnostic(error, Some(filename)),
    )
}
fn class(errno: Option<i32>) -> &'static str {
    use libc::{
        EACCES, EAGAIN, EALREADY, ECHILD, ECONNABORTED, ECONNREFUSED, ECONNRESET, EEXIST,
        EINPROGRESS, EINTR, EISDIR, ENOENT, ENOTDIR, EPERM, EPIPE, ESHUTDOWN, ESRCH, ETIMEDOUT,
        EWOULDBLOCK,
    };
    // libc 0.2.191 defines ENOTCAPABLE on FreeBSD, Apple platforms and WASI.
    #[cfg(any(target_os = "freebsd", target_vendor = "apple", target_os = "wasi"))]
    if errno == Some(libc::ENOTCAPABLE) {
        return "PermissionError";
    }
    match errno {
        Some(n) if [EAGAIN, EALREADY, EWOULDBLOCK, EINPROGRESS].contains(&n) => "BlockingIOError",
        Some(ECHILD) => "ChildProcessError",
        Some(EPIPE | ESHUTDOWN) => "BrokenPipeError",
        Some(ECONNABORTED) => "ConnectionAbortedError",
        Some(ECONNREFUSED) => "ConnectionRefusedError",
        Some(ECONNRESET) => "ConnectionResetError",
        Some(EEXIST) => "FileExistsError",
        Some(ENOENT) => "FileNotFoundError",
        Some(EISDIR) => "IsADirectoryError",
        Some(ENOTDIR) => "NotADirectoryError",
        Some(EINTR) => "InterruptedError",
        Some(EACCES | EPERM) => "PermissionError",
        Some(ESRCH) => "ProcessLookupError",
        Some(ETIMEDOUT) => "TimeoutError",
        _ => "OSError",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    #[cfg(any(target_os = "freebsd", target_vendor = "apple", target_os = "wasi"))]
    #[test]
    fn not_capable_is_permission_error() {
        let actual = error(
            OsStr::new("source"),
            &io::Error::from_raw_os_error(libc::ENOTCAPABLE),
        );
        assert_eq!(
            actual.origin,
            crate::evidence::legacy_policy::ErrorOrigin::Exception {
                class: "PermissionError"
            }
        );
    }
    #[test]
    fn errno_subclasses_and_filename_repr_match_pinned_python() {
        let script = r#"
import errno,json,os,sys
assert sys.version_info[:3]==(3,14,7)
numbers=sorted(set(range(256))|set(errno.errorcode))
print(json.dumps([[n,list(os.fsencode(path)),type(OSError(n,os.strerror(n),path)).__name__,str(OSError(n,os.strerror(n),path))] for n in numbers for path in ["plain", "both'\"quotes", 'raw'+chr(0xdcff), 'é🦀\n']]))
"#;
        let out = std::process::Command::new("python3")
            .args(["-c", script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let cases: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
        for case in cases {
            let errno = i32::try_from(case[0].as_i64().unwrap()).unwrap();
            let name: Vec<u8> = serde_json::from_value(case[1].clone()).unwrap();
            let actual = error(
                OsStr::from_bytes(&name),
                &io::Error::from_raw_os_error(errno),
            );
            let crate::evidence::legacy_policy::ErrorOrigin::Exception { class } = actual.origin
            else {
                panic!("unexpected Failure")
            };
            assert_eq!(class, case[2], "{errno}");
            assert_eq!(actual.detail.to_string(), case[3], "{errno}");
        }
        let actual = error(
            OsStr::from_bytes(b"null\0path"),
            &io::Error::from(io::ErrorKind::InvalidInput),
        );
        assert_eq!(
            actual.origin,
            crate::evidence::legacy_policy::ErrorOrigin::Exception {
                class: "ValueError"
            }
        );
        assert_eq!(actual.detail.to_string(), "embedded null byte");
    }
}

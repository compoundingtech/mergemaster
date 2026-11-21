//! st-test accepted-base input selection for native crate keying.
use super::{
    crate_inputs::failure, crate_manifest_ops::exception, json_bytes, projection_oid::space,
    source_io,
};
use crate::evidence::legacy_policy::PolicyError;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
use std::{
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, process::CommandExt},
    },
    path::Path,
    process::Command,
};
pub struct SelectedSources {
    pub inputs_from: String,
}
/// AcceptedSource must be bounded before any production caller is added.
pub struct AcceptedSource<'a> {
    pub repo: &'a Path,
    pub base: &'a str,
}
fn git_failure(operation: &str, stderr: &[u8]) -> PolicyError {
    let text = String::from_utf8_lossy(stderr);
    let text = text.trim_matches(space);
    let start = text.char_indices().rev().nth(399).map_or(0, |(i, _)| i);
    failure(format!("git {operation} failed: {}", &text[start..]))
}
impl AcceptedSource<'_> {
    fn git(&self, args: &[&str]) -> Result<Vec<u8>, PolicyError> {
        if self.repo.as_os_str().as_bytes().contains(&0) || args.iter().any(|s| s.contains('\0')) {
            return Err(exception("ValueError", "embedded null byte"));
        }
        // Attribute directory resolution errors to cwd, never to the executable.
        // O_PATH avoids requiring read permission on Linux directories.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let access = Some(libc::O_PATH);
        #[cfg(any(
            target_vendor = "apple",
            target_os = "aix",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "cygwin",
            target_os = "emscripten",
            target_os = "solaris",
            target_os = "illumos"
        ))]
        let access = Some(libc::O_SEARCH);
        #[cfg(any(target_os = "hurd", target_os = "nto"))]
        let access = Some(libc::O_EXEC);
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "aix",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "cygwin",
            target_os = "emscripten",
            target_os = "solaris",
            target_os = "illumos",
            target_os = "hurd",
            target_os = "nto"
        )))]
        let access: Option<i32> = None;
        let directory = access
            .map(|access| {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_DIRECTORY | access)
                        .open(self.repo)
                }
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                {
                    use std::os::fd::FromRawFd;
                    let path = std::ffi::CString::new(self.repo.as_os_str().as_bytes()).map_err(
                        |error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error),
                    )?;
                    // OpenOptions masks O_ACCMODE, which includes O_SEARCH on
                    // some targets. Preserve the search-only access mode.
                    // SAFETY: path is NUL-terminated; no creation mode is used.
                    let fd = unsafe {
                        libc::open(path.as_ptr(), access | libc::O_DIRECTORY | libc::O_CLOEXEC)
                    };
                    if fd == -1 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        // SAFETY: open returned a new, uniquely owned descriptor.
                        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
                    }
                }
            })
            .transpose()
            .or_else(|error| {
                // Never require directory read permission just to enter cwd.
                if !cfg!(any(target_os = "linux", target_os = "android"))
                    && error.raw_os_error() == Some(libc::EACCES)
                {
                    return Ok(None);
                }
                Err(source_io::error(self.repo.as_os_str(), &error))
            })?;
        let mut command = Command::new("git");
        command.args(args);
        if let Some(directory) = directory {
            // SAFETY: the captured file owns the descriptor until after spawn.
            // fchdir and errno inspection are async-signal-safe; no allocation or
            // locks occur in the child. The parent's cwd is never changed.
            unsafe {
                command.pre_exec(move || {
                    if libc::fchdir(directory.as_raw_fd()) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        } else {
            // No search-only open flag, or non-Linux open denied permission:
            // retain legacy chdir semantics rather than requiring readable cwd.
            command.current_dir(self.repo);
        }
        // A late fchdir search-permission failure is indistinguishable from an
        // exec failure here; unlike Python it carries 'git' (see commit body).
        let out = command
            .output()
            .map_err(|error| source_io::error(std::ffi::OsStr::new("git"), &error))?;
        if !out.status.success() {
            return Err(git_failure(args[0], &out.stderr));
        }
        Ok(out.stdout)
    }
    fn present(&self, path: &str) -> Result<bool, PolicyError> {
        Ok(!self
            .git(&["ls-tree", "--full-tree", "-z", self.base, "--", path])?
            .is_empty())
    }
    fn show(&self, path: &str) -> Result<Vec<u8>, PolicyError> {
        self.git(&["show", &format!("{}:{path}", self.base)])
    }
    pub fn resolve(
        &self,
        candidate_tree: &str,
        judged_by_policy: impl FnOnce() -> Result<bool, PolicyError>,
    ) -> Result<SelectedSources, PolicyError> {
        let mut inputs = None;
        for path in [
            ".fractal/rust-test-inputs.json",
            ".st/rust-test-inputs.json",
        ] {
            if self.present(path)? {
                inputs = Some(self.show(path)?);
                break;
            }
        }
        if let Some(bytes) = &inputs {
            json_bytes::parse(bytes)?;
        }
        let inputs_from = match inputs {
            Some(_) => self.base,
            None if judged_by_policy()? => {
                return Err(failure(
                    "the accepted base judges rust-tests but has no rust-test-inputs.json: only the base's inputs may key a note",
                ));
            }
            None => candidate_tree,
        };
        Ok(SelectedSources {
            inputs_from: inputs_from.into(),
        })
    }
}
#[cfg(test)]
#[path = "crate_sources_tests.rs"]
mod tests;

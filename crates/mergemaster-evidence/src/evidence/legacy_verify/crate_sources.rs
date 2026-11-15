//! st-test accepted-base tool/input selection, before executing or keying anything.
use super::{
    crate_inputs::failure, crate_manifest_ops::exception, json_bytes, projection_oid::space,
    source_io,
};
use crate::evidence::legacy_policy::PolicyError;
use std::{
    fs::OpenOptions,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt, process::CommandExt},
    },
    path::Path,
    process::Command,
};
const TOOL: &str = "scripts/rust-test-keys";
const VERIFIER: &str = "scripts/evidence-verify";
pub struct SelectedSources {
    pub tool: Vec<u8>,
    pub verifier: Vec<u8>,
    pub inputs_from: String,
}
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
        let access = libc::O_PATH;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let access = 0;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | access)
            .open(self.repo)
            .map_err(|error| source_io::error(self.repo.as_os_str(), &error))?;
        let mut command = Command::new("git");
        command.args(args);
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
        candidate_directory: &Path,
        candidate_tree: &str,
        judged_by_policy: impl FnOnce() -> Result<bool, PolicyError>,
    ) -> Result<SelectedSources, PolicyError> {
        let shown = if self.present(TOOL)? {
            Some(self.show(TOOL)?)
        } else {
            None
        };
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
        let (tool, inputs_from) = match (shown, inputs) {
            (Some(tool), Some(_)) => (tool, self.base),
            _ if judged_by_policy()? => {
                return Err(failure(
                    "the accepted base judges rust-tests but has no scripts/rust-test-keys and rust-test-inputs.json: only the base's tool and inputs may key a note",
                ));
            }
            _ => {
                let path = candidate_directory.join(TOOL);
                let tool = std::fs::read(&path)
                    .map_err(|error| source_io::error(path.as_os_str(), &error))?;
                (tool, candidate_tree)
            }
        };
        let verifier = self.show(VERIFIER)?;
        Ok(SelectedSources {
            tool,
            verifier,
            inputs_from: inputs_from.into(),
        })
    }
}
#[cfg(test)]
#[path = "crate_sources_tests.rs"]
mod tests;

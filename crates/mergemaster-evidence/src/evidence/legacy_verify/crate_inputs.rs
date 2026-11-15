//! Committed sources for the pinned rust-test-keys projection.
use super::toml::{self, Table};
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError, normalized_text::NormalizedText};
use std::{
    path::Path,
    process::{Command, Output},
};
pub const INPUTS_PATH: &str = ".st/rust-test-inputs.json";
pub(super) fn failure(detail: impl Into<NormalizedText>) -> PolicyError {
    PolicyError {
        resource: None,
        origin: ErrorOrigin::Failure,
        reason: "error",
        detail: detail.into(),
    }
}
pub use super::crate_inputs_text::{joined, normpath, utf8};
pub struct TreeSource<'a> {
    pub repo: &'a Path,
    pub tree: &'a str,
    pub no_lazy_fetch: bool,
}
impl TreeSource<'_> {
    pub(super) fn git(&self, args: &[&str]) -> Result<Output, PolicyError> {
        let mut command = Command::new("git");
        command.arg("-C").arg(self.repo).args(args);
        if self.no_lazy_fetch {
            command.env("GIT_NO_LAZY_FETCH", "1");
        }
        command.output().map_err(|error| failure(error.to_string()))
    }
    pub fn resolve(&self) -> Result<String, PolicyError> {
        let expression = format!("{}^{{tree}}", self.tree);
        let out = self.git(&["rev-parse", "--verify", "--end-of-options", &expression])?;
        if !out.status.success() {
            return Err(failure(format!("{} is not a tree", self.tree)));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().into())
    }
    pub fn show(&self, path: &str) -> Result<Option<Vec<u8>>, PolicyError> {
        let arg = format!("{}:{path}", self.tree);
        let out = self.git(&["cat-file", "blob", &arg])?;
        Ok(out.status.success().then_some(out.stdout))
    }
    pub fn config_path(&self, legacy: &str) -> Result<Option<String>, PolicyError> {
        let preferred = legacy.replacen(".st/", ".fractal/", 1);
        let out = self.git(&[
            "ls-tree",
            "-z",
            "--full-tree",
            self.tree,
            "--",
            &preferred,
            legacy,
        ])?;
        if !out.status.success() {
            return Err(failure(format!(
                "cannot resolve configuration at {}: {}",
                self.tree,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let mut old = false;
        for row in out.stdout.split(|b| *b == 0).filter(|row| !row.is_empty()) {
            let name = row.splitn(2, |b| *b == b'\t').nth(1).unwrap_or_default();
            if name == preferred.as_bytes() {
                return Ok(Some(preferred));
            }
            old |= name == legacy.as_bytes();
        }
        Ok(old.then(|| legacy.into()))
    }
    pub fn manifest(&self, directory: &str) -> Result<Table, PolicyError> {
        let path = joined(directory, "Cargo.toml");
        let bytes = self
            .show(&path)?
            .ok_or_else(|| failure(format!("{}:{path} is not readable", self.tree)))?;
        let text = utf8(&bytes).map_err(|e| failure(format!("{path}: {e}")))?;
        toml::parse(text).map_err(|e| {
            if matches!(
                e.kind,
                toml::ErrorKind::Decode | toml::ErrorKind::Resource(_)
            ) {
                failure(format!("{path}: {e}"))
            } else {
                PolicyError {
                    resource: None,
                    reason: "error",
                    origin: ErrorOrigin::Exception {
                        class: e.kind.class(),
                    },
                    detail: e.to_string().into(),
                }
            }
        })
    }
}
#[cfg(test)]
#[path = "crate_inputs_tests.rs"]
mod tests;

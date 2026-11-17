//! Committed sources for the pinned rust-test-keys projection.
use super::source_resource::SourceResource;
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
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new("git");
        command.arg("-C").arg(self.repo).args(args);
        if self.no_lazy_fetch {
            command.env("GIT_NO_LAZY_FETCH", "1");
        }
        command
    }
    pub(super) fn git(&self, args: &[&str]) -> Result<Output, PolicyError> {
        self.command(args)
            .output()
            .map_err(|error| super::source_io::error(std::ffi::OsStr::new("git"), &error))
    }
    pub fn resolve(&self) -> Result<String, PolicyError> {
        let expression = format!("{}^{{tree}}", self.tree);
        let mut command = self.command(&["rev-parse", "--verify", "--end-of-options", &expression]);
        let bytes = super::manifest_capture::read(
            &mut command,
            SourceResource::RawBlob(expression.into()),
        )?
        .ok_or_else(|| failure(format!("{} is not a tree", self.tree)))?;
        Ok(String::from_utf8_lossy(&bytes).trim().into())
    }
    pub fn show(&self, path: &str) -> Result<Option<Vec<u8>>, PolicyError> {
        let arg = format!("{}:{path}", self.tree);
        let mut command = self.command(&["cat-file", "blob", &arg]);
        super::manifest_capture::read(&mut command, SourceResource::RawBlob(arg.into()))
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
        let arg = format!("{}:{path}", self.tree);
        let mut command = self.command(&["cat-file", "blob", &arg]);
        let bytes = super::manifest_capture::read(
            &mut command,
            SourceResource::Toml(toml::Resource::SourceBytes),
        )
        .map_err(|mut error| {
            if error.resource.is_some() {
                error.detail =
                    NormalizedText::around(&format!("{path}: "), error.detail.borrowed(), "");
            }
            error
        })?
        .ok_or_else(|| failure(format!("{}:{path} is not readable", self.tree)))?;
        let text = utf8(&bytes).map_err(|e| failure(format!("{path}: {e}")))?;
        toml::parse(text).map_err(|e| {
            if matches!(
                e.kind,
                toml::ErrorKind::Decode | toml::ErrorKind::Resource(_)
            ) {
                let mut error = failure(format!("{path}: {e}"));
                if let toml::ErrorKind::Resource(resource) = e.kind {
                    error.resource = Some(SourceResource::Toml(resource));
                }
                error
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
#[path = "manifest_capture_tests.rs"]
mod capture_tests;
#[cfg(test)]
#[path = "crate_inputs_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "tree_read_capture_tests.rs"]
mod tree_capture_tests;

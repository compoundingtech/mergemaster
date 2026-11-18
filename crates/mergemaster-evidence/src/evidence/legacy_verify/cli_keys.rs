//! Main's separately ordered signer and shadow-log key preparation.
use super::{
    binding_path::encode,
    cli_adapter::decode,
    cli_config,
    cli_tempfile::{TemporaryFile, abspath},
    crate_inputs::failure,
    projection::read_git_source,
    source_io,
    source_resource::SourceResource,
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
};

pub enum Keys {
    Existing(PathBuf),
    Temporary(TemporaryFile),
}
impl Keys {
    pub fn path(&self) -> &Path {
        match self {
            Self::Existing(path) => path,
            Self::Temporary(file) => file.path(),
        }
    }
    /// Call after the verification result is captured, including on refusal.
    /// Python's explicit keyfile finally-close can override that result.
    pub fn close(self) -> Result<(), PolicyError> {
        match self {
            Self::Existing(_) => Ok(()),
            Self::Temporary(file) => file.close(),
        }
    }
}
fn absolute(path: &Path) -> Result<PathBuf, PolicyError> {
    abspath(path).map_err(|e| {
        let mut error = source_io::error(path.as_os_str(), &e);
        error.detail = super::projection_process_error::os_diagnostic(&e, None).into();
        error
    })
}
pub fn signers(repo: &Path, keys: &Path, from: Option<TextRef<'_>>) -> Result<Keys, PolicyError> {
    if let Some(from) = from.filter(|v| !v.equals("")) {
        // Unlike log keys, Python creates this file BEFORE lookup/read.
        let mut file = TemporaryFile::new(".keys")?;
        let result = cli_config::blob(repo, from, ".st/evidence-keys")
            .and_then(|bytes| file.write_and_flush(&bytes));
        if let Err(error) = result {
            file.close()?;
            return Err(error);
        }
        Ok(Keys::Temporary(file))
    } else {
        let path = absolute(keys)?;
        if !path.is_file() {
            return Err(failure(NormalizedText::around(
                "key list ",
                decode(keys.as_os_str()).borrowed(),
                " not found",
            )));
        }
        Ok(Keys::Existing(path))
    }
}
pub fn log_keys(
    repo: &Path,
    explicit: Option<&Path>,
    from: Option<TextRef<'_>>,
) -> Result<Option<Keys>, PolicyError> {
    let earlier = explicit
        .filter(|p| !p.as_os_str().is_empty())
        .map(absolute)
        .transpose()?
        .map(Keys::Existing);
    let Some(from) = from.filter(|v| !v.equals("")) else {
        return Ok(earlier);
    };
    let Some(path) = cli_config::path(repo, from, ".st/evidence-log-key")? else {
        return Ok(earlier);
    };
    let spec = NormalizedText::concat([from, TextRef::Str(":"), TextRef::Str(&path)].into_iter());
    let object = OsString::from_vec(encode(spec.borrowed(), 0, true)?.into_owned());
    let bytes = read_git_source(
        repo,
        &[OsStr::new("show"), OsStr::new("--end-of-options"), &object],
        SourceResource::RawBlob(spec),
    )?;
    // The blob read completes BEFORE this file is created.
    let mut file = TemporaryFile::new(".log-keys")?;
    file.write_and_flush(&bytes)?;
    Ok(Some(Keys::Temporary(file)))
}

#[cfg(test)]
#[path = "cli_keys_tests.rs"]
mod tests;

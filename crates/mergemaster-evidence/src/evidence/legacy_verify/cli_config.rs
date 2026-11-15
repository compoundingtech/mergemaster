//! Oracle config lookup for CLI reads, without native OID validation.
use super::{
    binding_path::encode, crate_inputs_text::utf8, crate_manifest_ops::exception,
    projection::read_git, value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError, normalized_text::NormalizedText};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
};

pub fn path(
    repo: &Path,
    revision: TextRef<'_>,
    legacy: &str,
) -> Result<Option<String>, PolicyError> {
    if repo.as_os_str().as_bytes().contains(&0) {
        return Err(exception("ValueError", "embedded null byte"));
    }
    let revision = encode(revision, 0, true)?;
    let preferred = legacy.replacen(".st/", ".fractal/", 1);
    let listing = read_git(
        repo,
        &[
            OsStr::new("ls-tree"),
            OsStr::new("-z"),
            OsStr::new("--full-tree"),
            OsStr::from_bytes(&revision),
            OsStr::new("--"),
            OsStr::new(&preferred),
            OsStr::new(legacy),
        ],
        usize::MAX,
    )?;
    let mut has_preferred = false;
    let mut has_legacy = false;
    for row in listing.split(|b| *b == 0).filter(|row| !row.is_empty()) {
        let name = row.splitn(2, |b| *b == b'\t').nth(1).unwrap_or_default();
        let name = utf8(name).map_err(|message| exception("UnicodeDecodeError", message))?;
        has_preferred |= name == preferred;
        has_legacy |= name == legacy;
    }
    Ok(if has_preferred {
        Some(preferred)
    } else if has_legacy {
        Some(legacy.into())
    } else {
        None
    })
}
pub fn blob(repo: &Path, revision: TextRef<'_>, legacy: &str) -> Result<Vec<u8>, PolicyError> {
    let path = path(repo, revision, legacy)?;
    let mut object = OsString::from_vec(encode(revision, 0, true)?.into_owned());
    object.push(":");
    object.push(path.as_deref().unwrap_or(legacy));
    read_git(
        repo,
        &[OsStr::new("show"), OsStr::new("--end-of-options"), &object],
        usize::MAX,
    )
}
pub fn lanes(repo: &Path, revision: TextRef<'_>) -> Result<String, PolicyError> {
    let result = blob(repo, revision, ".st/required-lanes.json").and_then(|bytes| {
        utf8(&bytes)
            .map(str::to_owned)
            .map_err(|m| exception("UnicodeDecodeError", m))
    });
    result.map_err(|e| {
        if e.origin == ErrorOrigin::Failure
            || e.origin
                == (ErrorOrigin::Exception {
                    class: "UnicodeDecodeError",
                })
        {
            PolicyError {
                resource: None,
                origin: ErrorOrigin::Failure,
                reason: "error",
                detail: NormalizedText::around(
                    "no readable lane file at ",
                    revision,
                    ":.st/required-lanes.json",
                ),
            }
        } else {
            e
        }
    })
}

#[cfg(test)]
#[path = "cli_config_tests.rs"]
mod tests;

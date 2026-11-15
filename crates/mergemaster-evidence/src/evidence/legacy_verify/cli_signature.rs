//! Oracle signature transport; native signature hardening remains independent.
use super::{
    binding_path::encode,
    crate_manifest_ops::exception,
    projection,
    projection_capture::{self, ExpectedOutput},
    source_resource::SourceResource,
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::Path,
    time::Duration,
};

/// No revocation prevalidation, native sanitizer, or extra program overrides.
/// Key paths are raw filesystem bytes; commit identity retains original points.
pub fn signature(
    repo: &Path,
    commit: TextRef<'_>,
    keys: &Path,
    revocations: &Path,
) -> Result<(String, String), PolicyError> {
    if [repo, keys, revocations]
        .iter()
        .any(|p| p.as_os_str().as_bytes().contains(&0))
    {
        return Err(exception("ValueError", "embedded null byte"));
    }
    let encoded = encode(commit, 0, true)?;
    let mut allowed = OsString::from("gpg.ssh.allowedSignersFile=");
    allowed.push(keys);
    let mut revoked = OsString::from("gpg.ssh.revocationFile=");
    revoked.push(revocations);
    let mut command = projection::projection_command(
        repo,
        &[
            OsStr::new("-c"),
            &allowed,
            OsStr::new("-c"),
            &revoked,
            OsStr::new("show"),
            OsStr::new("-s"),
            OsStr::new("--format=%G?%x00%GS"),
            OsStr::from_bytes(&encoded),
        ],
    )?;
    let bytes = projection_capture::exchange(
        &mut command,
        b"",
        "show",
        ExpectedOutput::Source(SourceResource::RawBlob(NormalizedText::concat(
            std::iter::once(commit),
        ))),
        Duration::from_secs(60),
    )?;
    let shown = super::crate_inputs_text::utf8(&bytes)
        .map_err(|e| exception("UnicodeDecodeError", e))?
        .trim_matches('\n');
    let (status, principal) = shown.split_once('\0').unwrap_or((shown, ""));
    Ok((status.to_owned(), principal.to_owned()))
}

#[cfg(test)]
#[path = "cli_signature_tests.rs"]
mod tests;

//! C1 policy ingress: inherited Git transport, then strict UTF-8, then JSON.
use super::{
    binding_path::encode, crate_manifest_ops::exception, projection::read_git,
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{
    ErrorOrigin, PolicyDocument, PolicyError, check_names::CheckName,
    normalized_text::NormalizedText,
};
use std::{
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
};
const LEGACY: &str = ".st/evidence-skip-policy.json";
const PREFERRED: &str = ".fractal/evidence-skip-policy.json";

/// Read the exact caller revision, including unresolved names and abbreviations.
/// A present preferred file never falls back after a read/decode failure.
pub fn read_policy<'a>(repo: &Path, commit: impl Into<TextRef<'a>>) -> Result<String, PolicyError> {
    let commit = commit.into();
    let read = || {
        // Python validates each earlier argument before encoding the next.
        if repo.as_os_str().as_bytes().contains(&0) {
            return Err(exception("ValueError", "embedded null byte"));
        }
        let encoded = encode(commit, 0, true)?;
        let revision = OsStr::from_bytes(&encoded);
        let listing = read_git(
            repo,
            &[
                OsStr::new("ls-tree"),
                OsStr::new("-z"),
                OsStr::new("--full-tree"),
                revision,
                OsStr::new("--"),
                OsStr::new(PREFERRED),
                OsStr::new(LEGACY),
            ],
            usize::MAX,
        )?;
        let mut preferred = false;
        for row in listing.split(|b| *b == 0).filter(|row| !row.is_empty()) {
            let name = row.splitn(2, |b| *b == b'\t').nth(1).unwrap_or_default();
            // Python decodes every listed name before choosing either path.
            let name = std::str::from_utf8(name).map_err(|_| unreadable(commit))?;
            preferred |= name == PREFERRED;
        }
        let path = if preferred { PREFERRED } else { LEGACY };
        let mut object = OsString::from_vec(encoded.into_owned());
        object.push(":");
        object.push(path);
        let bytes = read_git(
            repo,
            &[
                OsStr::new("show"),
                OsStr::new("--end-of-options"),
                object.as_os_str(),
            ],
            usize::MAX,
        )?;
        String::from_utf8(bytes).map_err(|_| unreadable(commit))
    };
    read().map_err(|e| {
        if e.origin == ErrorOrigin::Failure {
            unreadable(commit)
        } else {
            e
        }
    })
}
fn unreadable(commit: TextRef<'_>) -> PolicyError {
    PolicyError {
        resource: None,
        origin: ErrorOrigin::Failure,
        reason: "no_policy",
        detail: NormalizedText::around(
            "no readable skip policy at ",
            commit,
            ":.st/evidence-skip-policy.json",
        ),
    }
}
/// The first production PolicyDocument caller: decoding must precede parsing.
/// In particular BOM is JSON syntax, not a UTF-8 read refusal.
pub fn load<'a, 'c>(
    repo: &Path,
    commit: impl Into<TextRef<'c>>,
    check: impl Into<CheckName<'a>>,
) -> Result<PolicyDocument<'a>, PolicyError> {
    PolicyDocument::parse(&read_policy(repo, commit)?, check)
}
#[cfg(all(test, unix))]
#[path = "policy_loader_tests.rs"]
mod tests;

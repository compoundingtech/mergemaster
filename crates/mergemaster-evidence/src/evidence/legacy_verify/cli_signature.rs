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
use indexmap::{Equivalent, IndexMap};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    ffi::{OsStr, OsString},
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Hash, PartialEq, Eq)]
struct Key<R, C> {
    repo: R,
    commit: C,
    allowed: [u8; 32],
    revoked: [u8; 32],
}
type OwnedKey = Key<PathBuf, Vec<u8>>;
impl Equivalent<OwnedKey> for Key<&Path, &[u8]> {
    fn equivalent(&self, other: &OwnedKey) -> bool {
        self.repo == other.repo
            && self.commit == other.commit
            && self.allowed == other.allowed
            && self.revoked == other.revoked
    }
}
thread_local! {
    static SIGNED: RefCell<Option<IndexMap<OwnedKey, (String, String)>>> = const { RefCell::new(None) };
}
pub(super) fn batch_memo(active: bool) {
    SIGNED.with(|memo| *memo.borrow_mut() = active.then(IndexMap::new));
}
fn digest(path: &Path) -> Option<[u8; 32]> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let size = file.read(&mut buffer).ok()?;
        if size == 0 {
            return Some(digest.finalize().into());
        }
        digest.update(&buffer[..size]);
    }
}
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
    // Contents, not tempfile paths, identify trust. Unreadable lists still go
    // through Git, preserving the single-run error/status contract.
    let key = SIGNED.with(|memo| {
        if memo.borrow().is_none() {
            return None;
        }
        Some(Key {
            repo,
            commit: encoded.as_ref(),
            allowed: digest(keys)?,
            revoked: digest(revocations)?,
        })
    });
    if let Some(answer) = key.as_ref().and_then(|key| {
        SIGNED.with(|memo| {
            memo.borrow()
                .as_ref()
                .and_then(|values| values.get(key).cloned())
        })
    }) {
        return Ok(answer);
    }
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
    let answer = (status.to_owned(), principal.to_owned());
    if let Some(key) = key {
        let Key {
            allowed, revoked, ..
        } = key;
        SIGNED.with(|memo| {
            if let Some(values) = memo.borrow_mut().as_mut() {
                values.insert(
                    Key {
                        repo: repo.to_owned(),
                        commit: encoded.into_owned(),
                        allowed,
                        revoked,
                    },
                    answer.clone(),
                );
            }
        });
    }
    Ok(answer)
}

#[cfg(test)]
#[path = "cli_signature_tests.rs"]
mod tests;

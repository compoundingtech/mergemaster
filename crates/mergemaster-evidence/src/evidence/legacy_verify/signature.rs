//! Git's SSH signature status and principal; callers must still enforce trust policy.
use crate::{
    evidence::{legacy_policy::PolicyError, oid},
    gate::git::git,
};
use std::{
    fs::File,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

fn revocation_path(repo: &Path, supplied: &Path) -> anyhow::Result<PathBuf> {
    if supplied.is_absolute() {
        return Ok(supplied.to_owned());
    }
    // Git show moves to the worktree root, but bare repositories retain -C's cwd.
    let bare = git(repo, &["rev-parse", "--is-bare-repository"])?;
    let root = match bare.as_slice() {
        b"true\n" => std::path::absolute(repo)?,
        b"false\n" => {
            let output = String::from_utf8(git(repo, &["rev-parse", "--show-toplevel"])?)?;
            PathBuf::from(
                output
                    .strip_suffix('\n')
                    .ok_or_else(|| anyhow::anyhow!("unterminated Git root"))?,
            )
        }
        _ => anyhow::bail!("invalid Git repository kind"),
    };
    let path = root.join(supplied);
    anyhow::ensure!(path.is_absolute(), "Git root is not absolute");
    Ok(path)
}

/// Inspect one record using the supplied signer and revocation files, not repo overrides.
/// A successful Git invocation can return an untrusted status (including `N`).
/// Revocations must be a readable regular file; symlinks to such files are allowed.
pub fn signature(
    repo: &Path,
    commit: &str,
    keys: &str,
    revocations: &str,
) -> Result<(String, String), PolicyError> {
    let error = |detail: String| PolicyError {
        reason: "error",
        detail: detail.into(),
    };
    let path = revocation_path(repo, Path::new(revocations))
        .map_err(|e| error(format!("revocation path resolution failed: {e}")))?;
    let checked = path
        .to_str()
        .ok_or_else(|| error("revocation path is not UTF-8".into()))?;
    let metadata = std::fs::metadata(&path)
        .map_err(|e| error(format!("revocation file is unavailable: {e}")))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o444 == 0 {
        return Err(error(
            "revocation path is not a readable regular file".into(),
        ));
    }
    File::open(&path).map_err(|e| error(format!("revocation file is unreadable: {e}")))?;
    oid(commit).map_err(|e| error(e.to_string()))?;
    let shown = git(
        repo,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            "gpg.ssh.program=ssh-keygen",
            // Git dispatches by signature header, not only gpg.format.
            "-c",
            "gpg.program=/bin/false",
            "-c",
            "gpg.openpgp.program=/bin/false",
            "-c",
            "gpg.x509.program=/bin/false",
            "-c",
            &format!("gpg.ssh.allowedSignersFile={keys}"),
            "-c",
            &format!("gpg.ssh.revocationFile={checked}"),
            "show",
            "-s",
            "--format=%G?%x00%GS",
            "--end-of-options",
            commit,
        ],
    );
    let shown = shown.map_err(|e| error(e.to_string()))?;
    let shown = String::from_utf8(shown).map_err(|e| error(e.to_string()))?;
    let shown = shown.trim_matches('\n');
    let (status, principal) = shown.split_once('\0').unwrap_or((shown, ""));
    Ok((status.to_owned(), principal.to_owned()))
}

#[cfg(test)]
#[path = "signature_tests.rs"]
mod tests;

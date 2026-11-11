//! Git's SSH signature status and principal; callers must still enforce trust policy.
use crate::{
    evidence::{legacy_policy::PolicyError, oid},
    gate::git::git,
};
use std::path::Path;

/// Inspect one record using the supplied signer and revocation files, not repo overrides.
/// A successful Git invocation can return an untrusted status (including `N`).
pub fn signature(
    repo: &Path,
    commit: &str,
    keys: &str,
    revocations: &str,
) -> Result<(String, String), PolicyError> {
    let error = |detail: String| PolicyError {
        reason: "error",
        detail,
    };
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
            &format!("gpg.ssh.revocationFile={revocations}"),
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

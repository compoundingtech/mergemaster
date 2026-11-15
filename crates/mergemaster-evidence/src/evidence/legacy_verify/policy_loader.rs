//! C1 policy ingress: inherited Git transport, then strict UTF-8, then JSON.
use super::{cli_config, value_inputs::TextRef};
use crate::evidence::legacy_policy::{
    ErrorOrigin, PolicyDocument, PolicyError, check_names::CheckName,
    normalized_text::NormalizedText,
};
use std::path::Path;

/// Read the exact caller revision, including unresolved names and abbreviations.
/// A present preferred file never falls back after a read/decode failure.
pub fn read_policy<'a>(repo: &Path, commit: impl Into<TextRef<'a>>) -> Result<String, PolicyError> {
    let commit = commit.into();
    cli_config::blob(repo, commit, ".st/evidence-skip-policy.json")
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| unreadable(commit)))
        .map_err(|e| {
            if e.origin == ErrorOrigin::Failure
                || e.origin
                    == (ErrorOrigin::Exception {
                        class: "UnicodeDecodeError",
                    })
            {
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

//! Signature partition only; check membership and miss precedence are separate.
use super::{
    collection::Candidate,
    signature::signature,
    statement::{field, string},
};
use crate::evidence::legacy_policy::PolicyError;
use std::path::Path;

pub struct TrustedCandidate {
    pub candidate: Candidate,
    pub principal: String,
}
pub struct UntrustedCandidate {
    pub reason: &'static str,
    pub commit: String,
}
pub struct TrustGroups {
    pub trusted: Vec<TrustedCandidate>,
    pub untrusted: Vec<UntrustedCandidate>,
    pub degraded: Vec<Candidate>,
}
/// Consume structurally validated candidates in order. No error becomes a status
/// or a partial group result; callers must propagate collection/cache errors too.
/// `revocations` is the caller-owned file, kept alive for the entire partition.
pub fn partition(
    repo: &Path,
    candidates: Vec<Candidate>,
    keys: &str,
    revocations: &str,
) -> Result<TrustGroups, PolicyError> {
    let mut groups = TrustGroups {
        trusted: Vec::new(),
        untrusted: Vec::new(),
        degraded: Vec::new(),
    };
    for candidate in candidates {
        let doc = &candidate.statement;
        let predicate = field(doc, doc.root(), "predicate").expect("validated predicate");
        let is = |node, expected: &str| {
            string(node).is_some_and(|s| s.iter().copied().eq(expected.chars().map(u32::from)))
        };
        if is(
            field(doc, predicate, "tier").expect("validated tier"),
            "degraded",
        ) {
            groups.degraded.push(candidate);
            continue;
        }
        let (status, principal) = signature(repo, &candidate.commit, keys, revocations)?;
        if status == "G"
            && !principal.is_empty()
            && is(
                field(doc, predicate, "signer").expect("validated signer"),
                &principal,
            )
        {
            groups.trusted.push(TrustedCandidate {
                candidate,
                principal,
            });
        } else {
            groups.untrusted.push(UntrustedCandidate {
                reason: if status == "B" || status == "N" {
                    "bad_signature"
                } else {
                    "untrusted_signer"
                },
                commit: candidate.commit,
            });
        }
    }
    Ok(groups)
}
#[cfg(test)]
#[path = "trust_tests.rs"]
mod tests;

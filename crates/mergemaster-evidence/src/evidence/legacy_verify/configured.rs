//! The configured verification call used by require_all, not its lane/error aggregation.
use super::{
    Failure,
    candidates::{Candidate, LaneOnce, Levels, Prepared},
    collection::CandidateCollector,
    facts::DocumentFacts,
    inputs::CurrentTime,
    judgment::{LaneDefinition, Provider},
    ordering::CheckJudgment,
    prefix::{Request, candidates},
    trust::TrustedCandidate,
};
use crate::{
    evidence::legacy_policy::{PolicyError, PolicyRules},
    gate::git::deadline::GitChild,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path};

// require_all supplies an eager lane, but never a level_lane callback.
struct RequiredProvider<P>(P);
impl<P: Provider> Provider for RequiredProvider<P> {
    fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
        Ok(None)
    }
    fn blob_sha256(&mut self, path: &Path) -> Result<Option<String>, PolicyError> {
        self.0.blob_sha256(path)
    }
}
/// Select the actual trusted record for one configured required check.
/// Projection inputs come from rules, not q.inputs; crate binding, run inputs and
/// preferred levels are absent, matching require_all's verify invocation.
/// Each call owns a fresh collector budget and lazy-lane state. Every failure
/// propagates unchanged: the caller, not this helper, chooses the per-lane refusal.
/// The prefix intentionally uses Python's empty owned revocation tempfile.
/// This is not an API promising external revocation enforcement or a CLI result.
pub fn required(
    q: &Request<'_>,
    rules: &PolicyRules,
    lane: Option<&LaneDefinition>,
    clock: &mut dyn CurrentTime,
    provider: impl Provider,
) -> Result<TrustedCandidate, Failure> {
    let mut records = candidates(
        &mut CandidateCollector::for_check(),
        &Request {
            inputs: rules.header.inputs.as_deref(),
            crate_key: None,
            ..*q
        },
    )?;
    let check = q.check.codepoints();
    let prepared = Prepared::new(
        rules,
        records
            .iter()
            .map(|record| Candidate {
                commit: &record.candidate.commit,
                facts: DocumentFacts::for_check(
                    &record.candidate.statement,
                    &check,
                    &record.principal,
                )
                .expect("prefix supplied validated trusted check"),
            })
            .collect(),
        q.check,
    )?;
    let decision = CheckJudgment {
        clock,
        run_inputs: &BTreeMap::new(),
        lane,
        provider: LaneOnce::new(RequiredProvider(provider)),
    }
    .select(&prepared, q.check, Levels::Utf8(&[]));
    let (index, _) = decision.result?;
    let commit = prepared.candidates[index].commit;
    // Prepared may remove shard parts: its index is not an index into records.
    let original = records
        .iter()
        .position(|record| record.candidate.commit == commit)
        .expect("prepared candidate belongs to collected records");
    Ok(records.swap_remove(original))
}

/// Configured required-check selection with bound-file reads from the candidate tree.
pub fn required_git(
    q: &Request<'_>,
    rules: &PolicyRules,
    lane: Option<&LaneDefinition>,
    clock: &mut dyn CurrentTime,
) -> Result<TrustedCandidate, Failure> {
    required(
        q,
        rules,
        lane,
        clock,
        GitProvider {
            repo: q.repo,
            tree: q.tree,
        },
    )
}

/// Required checks have no level-lane callback; bound files come from this tree.
pub(super) struct GitProvider<'a> {
    pub repo: &'a Path,
    pub tree: &'a str,
}
impl Provider for GitProvider<'_> {
    fn level_lane(&mut self) -> Result<Option<&LaneDefinition>, PolicyError> {
        Ok(None)
    }
    fn blob_sha256(&mut self, path: &Path) -> Result<Option<String>, PolicyError> {
        // Python maps Git OSError/nonzero/60s timeout to None. Hash stdout without
        // buffering the blob; discarded stderr and one deadline cover its lifetime.
        let mut object = std::ffi::OsString::from(self.tree);
        object.push(":");
        object.push(path);
        Ok(GitChild::spawn(
            crate::gate::git::command(self.repo)
                .args(["cat-file", "blob"])
                .arg(object),
        )
        .ok()
        .and_then(blob_hash))
    }
}
fn blob_hash(mut child: GitChild) -> Option<String> {
    let mut output = child.stdout().ok()?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        match output.read(&mut buffer).ok()? {
            0 => break,
            n => hash.update(&buffer[..n]),
        }
    }
    drop(output);
    child
        .wait()
        .ok()?
        .success()
        .then(|| hex::encode(hash.finalize()))
}

#[cfg(all(test, unix))]
#[path = "required_git_tests.rs"]
mod git_tests;

#[cfg(all(test, unix))]
#[path = "configured_tests.rs"]
mod tests;

//! The configured verification call used by require_all, not its lane/error aggregation.
use super::{
    Failure,
    candidates::{Candidate, LaneOnce, Levels, Prepared},
    collection::CandidateCollector,
    facts::DocumentFacts,
    judgment::{LaneDefinition, Provider},
    ordering::CheckJudgment,
    prefix::{Request, candidates},
    trust::TrustedCandidate,
};
use crate::evidence::legacy_policy::{PolicyError, PolicyRules};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, path::Path, process::Stdio};

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
    now_micros: i64,
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
        now_micros,
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
    now_micros: i64,
) -> Result<TrustedCandidate, Failure> {
    required(
        q,
        rules,
        lane,
        now_micros,
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
        // Python maps Git OSError/nonzero/60s timeout to None. Rust currently has
        // no subprocess deadline, like the other Git helpers; cross-cutting
        // deadline parity is required before CLI cutover. Do not buffer a blob
        // or Git diagnostics while waiting: stdout is hashed, stderr discarded.
        let mut object = std::ffi::OsString::from(self.tree);
        object.push(":");
        object.push(path);
        let Ok(mut child) = crate::gate::git::command(self.repo)
            .args(["cat-file", "blob"])
            .arg(object)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return Ok(None);
        };
        let mut output = child.stdout.take().expect("piped Git stdout");
        let mut hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let read_ok = loop {
            match output.read(&mut buffer) {
                Ok(0) => break true,
                Ok(n) => hash.update(&buffer[..n]),
                Err(_) => break false,
            }
        };
        drop(output);
        if !read_ok {
            let _ = child.kill();
        }
        let status = match child.wait() {
            Ok(status) => status,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(None);
            }
        };
        Ok((read_ok && status.success()).then(|| hex::encode(hash.finalize())))
    }
}

#[cfg(all(test, unix))]
#[path = "required_git_tests.rs"]
mod git_tests;

#[cfg(all(test, unix))]
#[path = "configured_tests.rs"]
mod tests;

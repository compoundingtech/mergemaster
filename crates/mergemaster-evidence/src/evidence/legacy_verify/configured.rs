//! Joined legacy verification; require_all retains its deliberately narrower call.
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
    fn blob_sha256(
        &mut self,
        path: super::judgment::BindingPath<'_>,
    ) -> Result<Option<String>, PolicyError> {
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
    )?
    .records;
    let check = q.check.codepoints();
    let prepared = prepare_records(&records, rules, &check)?;
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
    let original = record_position(&records, commit)?;
    Ok(records.swap_remove(original))
}

fn prepare_records<'a>(
    records: &'a [TrustedCandidate],
    rules: &'a PolicyRules,
    check: &'a [u32],
) -> Result<Prepared<'a>, Failure> {
    Prepared::new(rules, document_candidates(records, check)?, check)
}

fn document_candidates<'a>(
    records: &'a [TrustedCandidate],
    check: &'a [u32],
) -> Result<Vec<Candidate<'a>>, Failure> {
    records
        .iter()
        .map(|record| {
            Ok(Candidate {
                commit: &record.candidate.commit,
                facts: DocumentFacts::for_check(
                    &record.candidate.statement,
                    check,
                    &record.principal,
                )
                .ok_or_else(super::invalid_statement_failure)?,
            })
        })
        .collect()
}

fn record_position(records: &[TrustedCandidate], commit: &str) -> Result<usize, Failure> {
    records
        .iter()
        .position(|record| record.candidate.commit == commit)
        .ok_or_else(super::invalid_statement_failure)
}

#[derive(Clone, Copy)]
pub enum Settings<'a> {
    Policy(&'a PolicyRules),
    Unconfigured(&'a super::judgment::Unconfigured<'a>),
}

/// The general verified() join, retaining crate/run-input/preferred-level behavior.
/// Reuse `judgment` across members to memoize the accepted-base lane once.
/// The callback borrows original documents and complete selection metadata; it
/// may emit wire output or retain owned fields without a serialize/reparse bridge.
/// Prefix uses Python's empty revocation file, not external revocation policy.
pub fn verified<T, P: Provider>(
    q: &Request<'_>,
    settings: Settings<'_>,
    judgment: &mut CheckJudgment<'_, P>,
    prefer: Levels<'_>,
    emit: impl FnOnce(&super::result::Satisfied<'_>, &TrustedCandidate) -> T,
) -> Result<T, Failure> {
    selected_record(q, settings, judgment, prefer, emit).map(|(value, _)| value)
}

/// Retain the selected original document and typed metadata for aggregation.
/// Ownership moves after the borrowed view is consumed; no JSON bridge or
/// duplicate statement/principal allocation is needed.
pub fn retained<P: Provider>(
    q: &Request<'_>,
    settings: Settings<'_>,
    judgment: &mut CheckJudgment<'_, P>,
    prefer: Levels<'_>,
) -> Result<super::result::Retained, Failure> {
    selected_record(q, settings, judgment, prefer, |view, _| {
        super::result::Selection::capture(view)
    })
    .map(|(selection, record)| super::result::Retained::new(record, selection))
}

fn selected_record<T, P: Provider>(
    q: &Request<'_>,
    settings: Settings<'_>,
    judgment: &mut CheckJudgment<'_, P>,
    prefer: Levels<'_>,
    emit: impl FnOnce(&super::result::Satisfied<'_>, &TrustedCandidate) -> T,
) -> Result<(T, TrustedCandidate), Failure> {
    let inputs = match settings {
        Settings::Policy(rules) => rules.header.inputs.as_deref(),
        Settings::Unconfigured(_) => None,
    };
    let mut gathered = candidates(
        &mut CandidateCollector::for_check(),
        &Request { inputs, ..*q },
    )?;
    let check = q.check.codepoints();
    let records = document_candidates(&gathered.records, &check)?;
    let prepared = match settings {
        Settings::Policy(rules) => Prepared::new(rules, records, &*check)?,
        Settings::Unconfigured(options) => Prepared::unconfigured(options, records),
    };
    let decision = judgment.select(&prepared, q.check, prefer);
    let selected = decision.result?;
    let original = record_position(&gathered.records, prepared.candidates[selected.0].commit)?;
    let decision = super::ordering::Decision {
        result: Ok(selected),
        walk: decision.walk,
    };
    let view = super::result::Satisfied::from_decision(
        &prepared,
        &decision,
        q.tree,
        q.check,
        gathered.input_key.as_deref(),
    )
    .map_err(|_| super::invalid_statement_failure())?;
    let value = emit(&view, &gathered.records[original]);
    Ok((value, gathered.records.swap_remove(original)))
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
    fn blob_sha256(
        &mut self,
        path: super::judgment::BindingPath<'_>,
    ) -> Result<Option<String>, PolicyError> {
        // Python maps Git OSError/nonzero/60s timeout to None. Hash stdout without
        // buffering the blob; discarded stderr and one deadline cover its lifetime.
        let path = path.native(Some(self.tree))?;
        let mut object = std::ffi::OsString::from(self.tree);
        object.push(":");
        object.push(path.as_ref());
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

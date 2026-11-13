//! Candidate walks only; sorting/preferences and final decisions are separate.
use super::{
    Failure,
    candidates::{LaneOnce, Prepared},
    judgment::{LaneDefinition, Provider, judge_document},
    routing::Routing,
};
use std::{cmp::Reverse, collections::BTreeMap};
#[derive(Default)]
pub struct Walk {
    pub decided_by: Option<usize>,
    pub skipped_newer: Vec<String>,
}
pub struct CheckJudgment<'a, P> {
    pub now_micros: i64,
    pub run_inputs: &'a BTreeMap<String, String>,
    pub lane: Option<&'a LaneDefinition>,
    pub provider: LaneOnce<P>,
}
impl<P: Provider> CheckJudgment<'_, P> {
    /// Judge in caller-supplied order; only foreign levels/definitions are skipped.
    /// # Panics
    /// Indices must belong to this already validated, trusted prepared candidate set.
    pub fn first_valid<'r>(
        &mut self,
        prepared: &Prepared<'r>,
        indices: &[usize],
        walk: &mut Walk,
    ) -> Result<Option<(usize, Routing<'r>)>, Failure> {
        for &i in indices {
            let candidate = &prepared.candidates[i];
            let reason = if !prepared.accepted.contains(candidate.facts.level()) {
                "level_not_accepted"
            } else {
                match judge_document(
                    prepared.policy,
                    &candidate.facts,
                    self.now_micros,
                    self.run_inputs,
                    self.lane,
                    &mut self.provider,
                    prepared.attempts(),
                ) {
                    Ok(routing) => return Ok(Some((i, routing))),
                    Err(failure) if failure.reason == "wrong_definition" => "wrong_definition",
                    Err(failure) => {
                        walk.decided_by = Some(i);
                        return Err(failure);
                    }
                }
            };
            let note = format!("{} {} {reason}", candidate.commit, candidate.facts.level());
            if !walk.skipped_newer.contains(&note) {
                walk.skipped_newer.push(note);
            }
        }
        Ok(None)
    }
}
/// Latest failure within the inclusive skew margin; first input wins equal instants.
/// No failures means no datetime subtraction, matching Python's lazy comprehension.
/// # Panics
/// `index` must belong to the validated prepared set whenever failures are present.
pub fn latest_failure_after(
    prepared: &Prepared<'_>,
    index: usize,
) -> Result<Option<usize>, Failure> {
    let candidates = &prepared.candidates;
    let mut failures = (0..prepared.attempts())
        .filter(|i| candidates[*i].facts.failed())
        .peekable();
    if failures.peek().is_none() {
        return Ok(None);
    }
    let facts = &candidates[index].facts;
    if facts.local_micros < -62_135_596_680_000_000 {
        return Err(Failure {
            reason: "error",
            detail: "datetime subtraction overflow".into(),
            attempts: prepared.attempts(),
        });
    }
    Ok(failures
        .filter(|i| candidates[*i].facts.moment_micros >= facts.moment_micros - 120_000_000)
        .min_by_key(|i| Reverse(candidates[*i].facts.moment_micros)))
}
#[cfg(test)]
#[path = "ordering_tests.rs"]
mod tests;

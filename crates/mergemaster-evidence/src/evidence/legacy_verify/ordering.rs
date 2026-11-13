//! Candidate walks and conservative final selection, with or without policy.
use super::{
    Failure,
    candidates::{LaneOnce, Levels, Prepared, Rules},
    inputs::CurrentTime,
    judgment::{LaneDefinition, Provider, judge_document, judge_unconfigured},
    routing::Routing,
};
use std::{cmp::Reverse, collections::BTreeMap};
#[derive(Default)]
pub struct Walk {
    pub decided_by: Option<usize>,
    pub skipped_newer: Vec<String>,
}
/// A judged candidate index; routing is absent exactly when no policy applies.
pub type JudgedCandidate<'a> = (usize, Option<Routing<'a>>);
pub struct Decision<'a> {
    pub result: Result<JudgedCandidate<'a>, Failure>,
    pub walk: Walk,
}
pub struct CheckJudgment<'a, P> {
    pub clock: &'a mut dyn CurrentTime,
    pub run_inputs: &'a BTreeMap<String, String>,
    pub lane: Option<&'a LaneDefinition>,
    pub provider: LaneOnce<P>,
}
impl<P: Provider> CheckJudgment<'_, P> {
    fn judge<'r>(
        &mut self,
        prepared: &Prepared<'r>,
        index: usize,
    ) -> Result<Option<Routing<'r>>, Failure> {
        let facts = &prepared.candidates[index].facts;
        match &prepared.rules {
            Rules::Policy { policy, .. } => judge_document(
                policy,
                facts,
                self.clock,
                self.run_inputs,
                self.lane,
                &mut self.provider,
                prepared.attempts(),
            )
            .map(Some),
            Rules::Unconfigured(options) => judge_unconfigured(
                options,
                facts,
                self.clock,
                self.lane,
                &mut self.provider,
                prepared.attempts(),
            )
            .map(|()| None),
        }
    }
    /// Select within one prepared check, retaining lazy lane state across judgments.
    /// Metadata indices refer to `prepared`; this is not CLI result serialization.
    pub fn select<'r>(
        &mut self,
        prepared: &Prepared<'r>,
        check: impl std::fmt::Display,
        prefer: Levels<'_>,
    ) -> Decision<'r> {
        let candidates = &prepared.candidates;
        let attempts = prepared.attempts();
        let mut walk = Walk::default();
        let result = (|| {
            let mut order: Vec<_> = (0..attempts)
                .filter(|i| !candidates[*i].facts.failed())
                .collect();
            order.sort_by_key(|i| Reverse(candidates[*i].facts.moment_micros));
            // Build the whole preferred list before any judgment, as Python does.
            let mut preferred = Vec::new();
            for &i in &order {
                if prefer.contains(candidates[i].facts.level())
                    && latest_failure_after(prepared, i)?.is_none()
                {
                    preferred.push(i);
                }
            }
            let found = match self.first_valid(prepared, &preferred, &mut walk)? {
                Some(found) => Some(found),
                None => self.first_valid(prepared, &order, &mut walk)?,
            };
            if let Some((i, routing)) = found {
                if let Some(failed) = latest_failure_after(prepared, i)? {
                    walk.decided_by = Some(failed);
                    let failure = &candidates[failed];
                    return Err(Failure { origin: crate::evidence::legacy_policy::ErrorOrigin::Failure, reason: "check_failed", detail: format!("record {} ({}) for check {check} failed, dated after the pass that would decide ({})",
                    failure.commit,
                    failure.facts.level(),
                    candidates[i].commit).into(), attempts, });
                }
                walk.decided_by = Some(i);
                return Ok((i, routing));
            }
            let mut chosen = (0..attempts)
                .min_by_key(|i| {
                    Reverse((
                        candidates[*i].facts.moment_micros,
                        candidates[*i].facts.failed(),
                    ))
                })
                .ok_or_else(|| Failure {
                    origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                    reason: "error",
                    detail: "empty candidate list".into(),
                    attempts,
                })?;
            if !candidates[chosen].facts.failed() {
                chosen = latest_failure_after(prepared, chosen)?.unwrap_or(chosen);
            }
            let routing = self
                .judge(prepared, chosen)
                .inspect_err(|_| walk.decided_by = Some(chosen))?;
            Ok((chosen, routing))
        })();
        Decision { result, walk }
    }
    /// Judge in caller-supplied order; only foreign levels/definitions are skipped.
    /// # Panics
    /// Indices must belong to this already validated, trusted prepared candidate set.
    pub fn first_valid<'r>(
        &mut self,
        prepared: &Prepared<'r>,
        indices: &[usize],
        walk: &mut Walk,
    ) -> Result<Option<JudgedCandidate<'r>>, Failure> {
        for &i in indices {
            let candidate = &prepared.candidates[i];
            let reason = if !prepared.accepted_levels().contains(candidate.facts.level()) {
                "level_not_accepted"
            } else {
                match self.judge(prepared, i) {
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
        return Err(Failure::exception(
            "OverflowError",
            "datetime subtraction overflow",
            prepared.attempts(),
        ));
    }
    Ok(failures
        .filter(|i| candidates[*i].facts.moment_micros >= facts.moment_micros - 120_000_000)
        .min_by_key(|i| Reverse(candidates[*i].facts.moment_micros)))
}
#[cfg(test)]
#[path = "ordering_tests.rs"]
mod tests;

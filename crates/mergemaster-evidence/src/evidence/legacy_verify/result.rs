//! Lossless borrowed successful-result dictionary; JSON output lives in result_json.
use super::{
    Failure,
    candidates::{Prepared, Rules},
    events::{kind_of_text, narrowed_event_iter},
    facts::DocumentFacts,
    ordering::Decision,
    statement::{array, field, string},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::check_names::CheckName;
use crate::evidence::legacy_policy::seconds::Seconds;
use std::borrow::Cow;

#[derive(Debug)]
pub enum ViewError<'a> {
    Judgment(&'a Failure),
    InvalidDecision,
}
pub struct Satisfied<'a> {
    pub satisfied: bool,
    pub tree: &'a str,
    pub check: CheckName<'a>,
    pub record: &'a str,
    pub kind: &'static str,
    pub signer: &'a str,
    pub trust_level: &'a str,
    pub tier: &'a [u32],
    pub observed_at: &'a [u32],
    pub attempts: usize,
    pub policy: bool,
    pub max_age_s: Option<Cow<'a, Seconds>>,
    pub enforce: bool,
    pub r#match: &'static str,
    pub matched_tree: &'a [u32],
    pub source_inputs: Option<&'a str>,
    pub sample_one_in: u64,
    pub decided_by: Option<&'a str>,
    pub skipped_newer: Option<&'a [String]>,
    facts: &'a DocumentFacts<'a>,
    check_events: Option<&'a [String]>,
    level_events: Option<&'a [String]>,
}
impl<'a> Satisfied<'a> {
    /// View of a successful selection in either mode; failures are returned unchanged.
    /// `source_inputs` is the exact prefix input key, not recomputed from a record.
    /// Malformed manually constructed selections return InvalidDecision, without text.
    pub fn from_decision(
        prepared: &'a Prepared<'a>,
        decision: &'a Decision<'a>,
        tree: &'a str,
        check: impl Into<CheckName<'a>>,
        source_inputs: Option<&'a str>,
    ) -> Result<Self, ViewError<'a>> {
        let invalid = || ViewError::InvalidDecision;
        let (index, routing) = decision.result.as_ref().map_err(ViewError::Judgment)?;
        let candidate = prepared.candidates.get(*index).ok_or_else(invalid)?;
        let facts = &candidate.facts;
        let doc = facts.document;
        let matched_tree = (|| {
            let subject = array(field(doc, doc.root(), "subject")?)?;
            let digest = field(doc, doc.try_node(*subject.first()?)?, "digest")?;
            string(field(doc, digest, "gitTree")?)
        })()
        .ok_or_else(invalid)?;
        let decided_by = match decision.walk.decided_by {
            Some(index) => Some(prepared.candidates.get(index).ok_or_else(invalid)?.commit),
            None => None,
        };
        let (policy, max_age_s, enforce, sample_one_in, check_events) = match &prepared.rules {
            Rules::Policy { policy, .. } => {
                let header = &policy.header;
                (
                    true,
                    header.max_age_s.as_ref().map(Cow::Borrowed),
                    header.enforce,
                    header.sample_one_in,
                    header.events.as_deref(),
                )
            }
            Rules::Unconfigured(options) => (
                false,
                match options.max_age {
                    Some(super::inputs::AgeLimit::Seconds(seconds)) => {
                        Some(Cow::Owned(Seconds::from(seconds)))
                    }
                    Some(super::inputs::AgeLimit::Overflow) => return Err(invalid()),
                    None => None,
                },
                false,
                1,
                None,
            ),
        };
        Ok(Self {
            satisfied: true,
            tree,
            check: check.into(),
            record: candidate.commit,
            kind: kind_of_text(TextRef::Points(facts.runner)).ok_or_else(invalid)?,
            signer: facts.principal,
            trust_level: facts.level(),
            tier: facts.tier,
            observed_at: facts.observed_at,
            attempts: prepared.attempts(),
            policy,
            max_age_s,
            enforce,
            r#match: if TextRef::Points(matched_tree).equals(tree) {
                "tree"
            } else {
                "inputs"
            },
            matched_tree,
            source_inputs,
            sample_one_in,
            decided_by,
            skipped_newer: decision
                .walk
                .decided_by
                .map(|_| decision.walk.skipped_newer.as_slice()),
            facts,
            check_events,
            level_events: routing
                .as_ref()
                .and_then(|routing| routing.level)
                .map(|level| level.events.as_slice()),
        })
    }
    pub fn command(&self) -> impl ExactSizeIterator<Item = &[u32]> {
        self.facts.command()
    }
    /// Omitted inputs and an empty object both produce the result dictionary's empty map.
    pub fn inputs(&self) -> impl Iterator<Item = (&[u32], &[u32])> {
        self.facts
            .inputs
            .into_iter()
            .flat_map(super::value_inputs::ValidatedInputs::iter)
    }
    pub fn events(&self) -> Option<impl Iterator<Item = &str>> {
        narrowed_event_iter(self.check_events, self.level_events)
    }
}
#[cfg(test)]
#[path = "result_tests.rs"]
mod tests;

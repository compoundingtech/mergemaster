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
    pub(super) fn with_events<'b>(self, events: Option<&'b [String]>) -> Satisfied<'b>
    where
        'a: 'b,
    {
        let mut view: Satisfied<'b> = self;
        view.check_events = events;
        view.level_events = None;
        view
    }
}

/// Only selection metadata is owned separately; signed fields stay in the
/// original Arc<Document> and are borrowed again when an aggregate is emitted.
pub struct Retained {
    record: super::trust::TrustedCandidate,
    selection: Selection,
}
pub(super) struct Selection {
    attempts: usize,
    policy: bool,
    max_age_s: Option<Seconds>,
    enforce: bool,
    r#match: &'static str,
    source_inputs: Option<String>,
    sample_one_in: u64,
    events: Option<Vec<String>>,
    decided_by: Option<String>,
    skipped_newer: Option<Vec<String>>,
}
impl Selection {
    pub(super) fn capture(view: &Satisfied<'_>) -> Self {
        Self {
            attempts: view.attempts,
            policy: view.policy,
            max_age_s: view.max_age_s.as_deref().cloned(),
            enforce: view.enforce,
            r#match: view.r#match,
            source_inputs: view.source_inputs.map(str::to_owned),
            sample_one_in: view.sample_one_in,
            events: view
                .events()
                .map(|events| events.map(str::to_owned).collect()),
            decided_by: view.decided_by.map(str::to_owned),
            skipped_newer: view.skipped_newer.map(<[String]>::to_vec),
        }
    }
}
impl Retained {
    pub(super) fn new(record: super::trust::TrustedCandidate, selection: Selection) -> Self {
        Self { record, selection }
    }
    pub fn record(&self) -> &super::trust::TrustedCandidate {
        &self.record
    }
    pub(super) fn aggregation(&self) -> (usize, bool, Option<&[String]>) {
        (
            self.selection.attempts,
            self.selection.r#match == "inputs",
            self.selection.events.as_deref(),
        )
    }
    pub fn facts(&self, check: CheckName<'_>) -> Result<DocumentFacts<'_>, Failure> {
        DocumentFacts::for_check(
            &self.record.candidate.statement,
            &check.codepoints(),
            &self.record.principal,
        )
        .ok_or_else(super::invalid_statement_failure)
    }
    /// Reborrow a complete successful dictionary without serializing/reparsing.
    /// The caller supplies the same target/check used to select this record.
    pub fn with_view<T>(
        &self,
        tree: &str,
        check: CheckName<'_>,
        emit: impl FnOnce(&Satisfied<'_>) -> T,
    ) -> Result<T, Failure> {
        self.with_owned_view(tree, check, |view| emit(&view))
    }
    pub(super) fn with_owned_view<T>(
        &self,
        tree: &str,
        check: CheckName<'_>,
        emit: impl FnOnce(Satisfied<'_>) -> T,
    ) -> Result<T, Failure> {
        let facts = self.facts(check)?;
        let doc = &*self.record.candidate.statement;
        let matched_tree = (|| {
            let subject = array(field(doc, doc.root(), "subject")?)?;
            let digest = field(doc, doc.try_node(*subject.first()?)?, "digest")?;
            string(field(doc, digest, "gitTree")?)
        })()
        .ok_or_else(super::invalid_statement_failure)?;
        let selection = &self.selection;
        Ok(emit(Satisfied {
            satisfied: true,
            tree,
            check,
            record: &self.record.candidate.commit,
            kind: kind_of_text(TextRef::Points(facts.runner))
                .ok_or_else(super::invalid_statement_failure)?,
            signer: &self.record.principal,
            trust_level: facts.level(),
            tier: facts.tier,
            observed_at: facts.observed_at,
            attempts: selection.attempts,
            policy: selection.policy,
            max_age_s: selection.max_age_s.as_ref().map(Cow::Borrowed),
            enforce: selection.enforce,
            r#match: selection.r#match,
            matched_tree,
            source_inputs: selection.source_inputs.as_deref(),
            sample_one_in: selection.sample_one_in,
            decided_by: selection.decided_by.as_deref(),
            skipped_newer: selection.skipped_newer.as_deref(),
            facts: &facts,
            check_events: selection.events.as_deref(),
            level_events: None,
        }))
    }
}
#[cfg(test)]
#[path = "result_tests.rs"]
mod tests;

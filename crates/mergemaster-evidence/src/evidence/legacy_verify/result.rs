//! Lossless borrowed successful-result dictionary; no JSON/CLI serialization.
use super::{
    Failure,
    candidates::Prepared,
    events::{kind_of_text, narrowed_event_iter},
    facts::DocumentFacts,
    ordering::Decision,
    statement::{array, field, string},
    statement_document::Node,
    value_inputs::TextRef,
};
pub struct Satisfied<'a> {
    pub satisfied: bool,
    pub tree: &'a str,
    pub check: &'a str,
    pub record: &'a str,
    pub kind: &'static str,
    pub signer: &'a str,
    pub trust_level: &'a str,
    pub tier: &'a [u32],
    pub observed_at: &'a [u32],
    pub attempts: usize,
    pub policy: bool,
    pub max_age_s: Option<u64>,
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
    /// Policy-mode view of a successful selection; failures are returned unchanged.
    /// `source_inputs` is the exact prefix input key, not recomputed from a record.
    /// # Panics
    /// Requires the same prepared set as the decision, with fully validated statements.
    /// Invalid indices/shapes are caller errors; this is not an untrusted-input entrypoint.
    pub fn from_decision(
        prepared: &'a Prepared<'a>,
        decision: &'a Decision<'a>,
        tree: &'a str,
        check: &'a str,
        source_inputs: Option<&'a str>,
    ) -> Result<Self, &'a Failure> {
        let (index, routing) = decision.result.as_ref()?;
        let candidate = &prepared.candidates[*index];
        let facts = &candidate.facts;
        let doc = facts.document;
        let subject = array(field(doc, doc.root(), "subject").expect("validated subject"))
            .expect("subject array");
        let digest = field(doc, doc.node(subject[0]), "digest").expect("validated digest");
        let matched_tree =
            string(field(doc, digest, "gitTree").expect("validated tree")).expect("tree string");
        let header = &prepared.policy.header;
        Ok(Self {
            satisfied: true,
            tree,
            check,
            record: candidate.commit,
            kind: kind_of_text(TextRef::Points(facts.runner)).expect("successful kind"),
            signer: facts.principal,
            trust_level: facts.level(),
            tier: facts.tier,
            observed_at: facts.observed_at,
            attempts: prepared.attempts(),
            policy: true,
            max_age_s: header.max_age_s,
            enforce: header.enforce,
            r#match: if TextRef::Points(matched_tree).equals(tree) {
                "tree"
            } else {
                "inputs"
            },
            matched_tree,
            source_inputs,
            sample_one_in: header.sample_one_in,
            decided_by: decision
                .walk
                .decided_by
                .map(|i| prepared.candidates[i].commit),
            skipped_newer: decision
                .walk
                .decided_by
                .map(|_| decision.walk.skipped_newer.as_slice()),
            facts,
            check_events: header.events.as_deref(),
            level_events: routing.level.map(|level| level.events.as_slice()),
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
            .flat_map(|node| {
                let Node::Object(entries) = node else {
                    unreachable!("validated input object")
                };
                entries.iter()
            })
            .map(|(key, id)| {
                (
                    key.as_slice(),
                    string(self.facts.document.node(*id)).expect("validated input string"),
                )
            })
    }
    pub fn events(&self) -> Option<impl Iterator<Item = &str>> {
        narrowed_event_iter(self.check_events, self.level_events)
    }
}
#[cfg(test)]
#[path = "result_tests.rs"]
mod tests;

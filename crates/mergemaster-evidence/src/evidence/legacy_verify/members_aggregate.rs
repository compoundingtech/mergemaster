use super::{Covered, Failure, Retained};
use crate::evidence::{
    legacy_output::{ValueWriter, Written},
    legacy_policy::check_names::CheckName,
};
use std::fmt::{self, Write};

/// Owned aggregate retains the original records, not copied statement dictionaries.
pub struct Aggregate {
    covered: Covered,
    oldest: usize,
    weakest: usize,
    attempts: usize,
    inputs_match: bool,
    combined: String,
    events: Option<Vec<String>>,
}
pub struct View<'a, 'b> {
    oldest: &'a super::super::result::Satisfied<'b>,
    aggregate: &'a Aggregate,
}
fn level(note: &Retained) -> &str {
    note.record().principal.split('/').next().unwrap_or("")
}
fn rank(note: &Retained) -> u8 {
    match level(note) {
        "host" => 1,
        "agent" => 2,
        _ => 0,
    }
}
impl Covered {
    /// Use the same check and configured event list used in member selection.
    pub fn aggregate(
        self,
        check: CheckName<'_>,
        policy_events: Option<&[String]>,
    ) -> Result<Aggregate, Failure> {
        let first = self
            .entries
            .first()
            .ok_or_else(super::super::invalid_statement_failure)?;
        let mut oldest_time = first.2.facts(check)?.moment_micros;
        let (mut oldest, mut weakest, mut attempts, mut inputs_match) = (0, 0, 0, false);
        let mut last_events = policy_events;
        for (index, (_, _, note)) in self.entries.iter().enumerate() {
            let time = if index == 0 {
                oldest_time
            } else {
                note.facts(check)?.moment_micros
            };
            if time < oldest_time {
                oldest_time = time;
                oldest = index;
            }
            if rank(note) > rank(&self.entries[weakest].2) {
                weakest = index;
            }
            let (count, matched, events) = note.aggregation();
            attempts = attempts.max(count);
            inputs_match |= matched;
            if events.is_some() {
                last_events = events;
            }
        }
        // The last constrained list supplies order and duplicates. Every earlier
        // constraint only supplies membership, exactly like repeated intersections.
        let events = last_events.map(|events| {
            events
                .iter()
                .filter(|event| {
                    policy_events.is_none_or(|allowed| allowed.contains(event))
                        && self.entries.iter().all(|(_, _, note)| {
                            note.aggregation()
                                .2
                                .is_none_or(|allowed| allowed.contains(event))
                        })
                })
                .cloned()
                .collect()
        });
        let combined = super::super::member_digest::combined_sorted_key(
            self.iter().map(|(name, key, _)| (name, key)),
        );
        Ok(Aggregate {
            covered: self,
            oldest,
            weakest,
            attempts,
            inputs_match,
            combined,
            events,
        })
    }
}
impl Aggregate {
    /// Reconstruct the oldest dictionary and overlay only oracle aggregate fields.
    pub fn with_view<T>(
        &self,
        tree: &str,
        check: CheckName<'_>,
        emit: impl FnOnce(&View<'_, '_>) -> T,
    ) -> Result<T, Failure> {
        self.covered.entries[self.oldest]
            .2
            .with_owned_view(tree, check, |oldest| {
                let mut oldest = oldest.with_events(self.events.as_deref());
                oldest.trust_level = level(&self.covered.entries[self.weakest].2);
                oldest.attempts = self.attempts;
                oldest.r#match = if self.inputs_match { "inputs" } else { "tree" };
                oldest.source_inputs = Some(&self.combined);
                emit(&View {
                    oldest: &oldest,
                    aggregate: self,
                })
            })
    }
}
impl View<'_, '_> {
    pub fn write_json<'s, W: Write>(
        &self,
        writer: ValueWriter<'s, '_, W>,
    ) -> Result<Written<'s>, fmt::Error> {
        self.oldest.write_extended_json(writer, |o| {
            o.field_text("members", |w| {
                w.integer(self.aggregate.covered.entries.len() as i128)
            })?;
            o.field_text("crates", |w| {
                w.object(|o| {
                    for (name, _, note) in self.aggregate.covered.iter() {
                        o.field_text(name, |w| w.text(&note.record().candidate.commit))?;
                    }
                    Ok(())
                })
            })?;
            o.field_text("missing", |w| w.object(|_| Ok(())))
        })
    }
}

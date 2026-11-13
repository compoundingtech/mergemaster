//! Successful single-check wire dictionary; no failure envelope or CLI dispatch.
use super::{result::Satisfied, value_inputs::TextRef};
use crate::evidence::legacy_output::{ValueWriter, Written};
use std::fmt::{self, Write};

impl Satisfied<'_> {
    /// Python's successful dictionary, including optional selection metadata.
    /// No trailing newline. On error, discard the partially written output.
    pub fn write_json<'s>(
        &self,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        writer.object(|o| {
            o.field_text("satisfied", |w| w.boolean(self.satisfied))?;
            o.field_text("tree", |w| w.text(self.tree))?;
            o.field_text("check", |w| match self.check.text() {
                TextRef::Str(text) => w.text(text),
                TextRef::Points(points) => w.string(points),
            })?;
            o.field_text("record", |w| w.text(self.record))?;
            o.field_text("kind", |w| w.text(self.kind))?;
            o.field_text("signer", |w| w.text(self.signer))?;
            o.field_text("trust_level", |w| w.text(self.trust_level))?;
            o.field_text("tier", |w| w.string(self.tier))?;
            o.field_text("observed_at", |w| w.string(self.observed_at))?;
            o.field_text("command", |w| {
                w.array(|a| {
                    for arg in self.command() {
                        a.item(|w| w.string(arg))?;
                    }
                    Ok(())
                })
            })?;
            o.field_text("inputs", |w| {
                w.object(|o| {
                    for (key, value) in self.inputs() {
                        o.field(key, |w| w.string(value))?;
                    }
                    Ok(())
                })
            })?;
            o.field_text("attempts", |w| w.integer(self.attempts as i128))?;
            o.field_text("policy", |w| w.boolean(self.policy))?;
            o.field_text("max_age_s", |w| match self.max_age_s {
                Some(age) => w.integer(i128::from(age)),
                None => w.null(),
            })?;
            o.field_text("enforce", |w| w.boolean(self.enforce))?;
            o.field_text("match", |w| w.text(self.r#match))?;
            o.field_text("matched_tree", |w| w.string(self.matched_tree))?;
            o.field_text("source_inputs", |w| match self.source_inputs {
                Some(key) => w.text(key),
                None => w.null(),
            })?;
            o.field_text("sample_one_in", |w| {
                w.integer(i128::from(self.sample_one_in))
            })?;
            o.field_text("events", |w| match self.events() {
                Some(events) => w.array(|a| {
                    for event in events {
                        a.item(|w| w.text(event))?;
                    }
                    Ok(())
                }),
                None => w.null(),
            })?;
            if let Some(commit) = self.decided_by {
                o.field_text("decided_by", |w| w.text(commit))?;
            }
            if let Some(skipped) = self.skipped_newer {
                o.field_text("skipped_newer", |w| {
                    w.array(|a| {
                        for note in skipped {
                            a.item(|w| w.text(note))?;
                        }
                        Ok(())
                    })
                })?;
            }
            Ok(())
        })
    }
}

//! Wire-only require-all dictionaries; no judgment or exception classification.
use super::require_all::{All, Decision};
use crate::evidence::{
    legacy_output::{ValueWriter, Written},
    legacy_policy::{PolicyError, RequireMode},
};
use std::fmt::{self, Write};

fn decision(value: Decision) -> &'static str {
    match value {
        Decision::Ok => "ok",
        Decision::WouldReject => "would-reject",
        Decision::Reject => "reject",
    }
}
impl All<'_> {
    /// Preserve dictionary order and lossless lane/tier text; no trailing LF.
    /// Discard partial output on error. This does not normalize diagnostic text.
    pub fn write_json<'s>(
        &self,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        writer.object(|o| {
            o.field_text("mode", |w| w.text("require-all"))?;
            o.field_text("tree", |w| w.text(self.tree))?;
            o.field_text("satisfied", |w| w.boolean(self.satisfied))?;
            o.field_text("decision", |w| w.text(decision(self.decision)))?;
            o.field_text("lanes", |w| {
                w.object(|o| {
                    for (check, lane) in &self.lanes {
                        o.field(check, |w| {
                            w.object(|o| {
                                o.field_text("require", |w| {
                                    w.text(match lane.require {
                                        RequireMode::Off => "off",
                                        RequireMode::Shadow => "shadow",
                                        RequireMode::Reject => "reject",
                                    })
                                })?;
                                o.field_text("satisfied", |w| w.boolean(lane.outcome.is_ok()))?;
                                match &lane.outcome {
                                    Ok(record) => {
                                        o.field_text("decision", |w| {
                                            w.text(decision(lane.decision))
                                        })?;
                                        o.field_text("record", |w| w.text(&record.record))?;
                                        o.field_text("signer", |w| w.text(&record.signer))?;
                                        o.field_text("tier", |w| w.string(&record.tier))?;
                                    }
                                    Err(error) => {
                                        o.field_text("reason", |w| w.text(error.reason))?;
                                        o.field_text("detail", |w| {
                                            w.codepoints(error.detail.borrowed().points())
                                        })?;
                                        o.field_text("decision", |w| {
                                            w.text(decision(lane.decision))
                                        })?;
                                    }
                                }
                                Ok(())
                            })
                        })?;
                    }
                    Ok(())
                })
            })
        })
    }
}
/// Global CLI error envelope, preserving reason/detail verbatim. Exception class
/// formatting requires explicit caller provenance; this adapter never infers it.
/// No exit-code policy or trailing LF; discard partial output on error.
pub fn write_error<'s>(
    error: &PolicyError,
    writer: ValueWriter<'s, '_, impl Write>,
) -> Result<Written<'s>, fmt::Error> {
    writer.object(|o| {
        o.field_text("mode", |w| w.text("require-all"))?;
        o.field_text("decision", |w| w.text("error"))?;
        o.field_text("satisfied", |w| w.boolean(false))?;
        o.field_text("reason", |w| w.text(error.reason))?;
        o.field_text("detail", |w| w.codepoints(error.detail.borrowed().points()))
    })
}
#[cfg(test)]
#[path = "require_all_json_tests.rs"]
mod tests;

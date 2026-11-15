//! Complete ordinary verification wire outcomes, without reparsing signed documents.
use super::{
    Failure, configured, failure_json::WireError, log_view, members, members::Aggregate,
    result::Retained, value_inputs::TextRef,
};
use crate::evidence::{legacy_output, legacy_policy::check_names::CheckName};
use std::fmt;

pub enum Outcome {
    Single(Result<(Retained, Option<log_view::View>), Box<configured::Refusal>>),
    Members(Result<Aggregate, members::Refusal>),
}
impl Outcome {
    pub fn satisfied(&self) -> bool {
        matches!(self, Self::Single(Ok(_)) | Self::Members(Ok(_)))
    }
    /// Outer errors are record-view invariant refusals; inner errors belong to the sink.
    pub fn write(
        &self,
        tree: &str,
        check: CheckName<'_>,
        output: &mut String,
    ) -> Result<fmt::Result, Failure> {
        Ok(match self {
            Self::Single(Ok((record, log))) => record.with_view(tree, check, |view| {
                legacy_output::write(output, |w| {
                    view.write_extended_json(w, |o| {
                        if let Some(log) = log {
                            log.write_fields(o)?;
                        }
                        Ok(())
                    })
                })
            })?,
            Self::Members(Ok(aggregate)) => aggregate.with_view(tree, check, |view| {
                legacy_output::write(output, |w| view.write_json(w))
            })?,
            Self::Single(Err(refusal)) => {
                let skipped: Option<Vec<_>> = refusal
                    .skipped_newer
                    .as_ref()
                    .map(|v| v.iter().map(|s| TextRef::Str(s)).collect());
                legacy_output::write(output, |w| {
                    WireError::from_failure(
                        &refusal.failure,
                        refusal.decided_by.as_deref().map(TextRef::Str),
                        skipped.as_deref(),
                    )
                    .write_extended_json(check, w, |o| {
                        if let Some(log) = &refusal.log {
                            log.write_fields(o)?;
                        }
                        Ok(())
                    })
                })
            }
            Self::Members(Err(members::Refusal::Verification(failure))) => {
                legacy_output::write(output, |w| {
                    WireError::from_failure(failure, None, None).write_json(check, w)
                })
            }
            Self::Members(Err(members::Refusal::Uncovered(refusal))) => {
                legacy_output::write(output, |w| {
                    WireError::from_failure(&refusal.failure, None, None).write_extended_json(
                        check,
                        w,
                        |o| {
                            o.field_text("missing", |w| {
                                w.object(|o| {
                                    for (name, reason) in &refusal.missing {
                                        o.field_text(name, |w| w.text(reason))?;
                                    }
                                    Ok(())
                                })
                            })?;
                            o.field_text("members", |w| w.integer(refusal.members as i128))?;
                            if let Some(log) = &refusal.log {
                                log.write_fields(o)?;
                            }
                            Ok(())
                        },
                    )
                })
            }
        })
    }
}

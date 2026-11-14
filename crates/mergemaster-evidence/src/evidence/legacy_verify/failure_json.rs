//! Emitter-only Python CLI error view. Construct from explicit source provenance;
//! never recover lost text, infer an exception class, or classify a core Failure.
pub use super::value_inputs::TextRef;
use crate::evidence::{
    legacy_output::{ValueWriter, Written},
    legacy_policy::check_names::CheckName,
};
use std::fmt::{self, Write};

#[derive(Default)]
pub struct Extras<'a> {
    pub attempts: Option<usize>,
    pub decided_by: Option<TextRef<'a>>,
    pub skipped_newer: Option<&'a [TextRef<'a>]>,
}
/// Failure metadata is absent for non-Failure exceptions by construction.
/// Members/log overlays are separate, not silently accepted as unknown extras.
pub enum WireError<'a> {
    Failure {
        reason: TextRef<'a>,
        detail: TextRef<'a>,
        extras: Extras<'a>,
    },
    Exception {
        class: TextRef<'a>,
        detail: TextRef<'a>,
    },
}
impl WireError<'_> {
    /// Single-check handler dictionary; no exit policy or final LF. Discard
    /// partial output on error. This is not wired to normalized core diagnostics.
    pub fn write_json<'s>(
        &self,
        check: CheckName<'_>,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        writer.object(|o| {
            o.field_text("satisfied", |w| w.boolean(false))?;
            o.field_text("reason", |w| match self {
                Self::Failure { reason, .. } => w.codepoints(reason.points()),
                Self::Exception { .. } => w.text("error"),
            })?;
            o.field_text("check", |w| w.codepoints(check.text().points()))?;
            o.field_text("detail", |w| match self {
                Self::Failure { detail, .. } => w.codepoints(detail.points()),
                Self::Exception { class, detail } => {
                    w.codepoints(class.points().chain([58, 32]).chain(detail.points()))
                }
            })?;
            if let Self::Failure { extras, .. } = self {
                if let Some(attempts) = extras.attempts {
                    o.field_text("attempts", |w| w.integer(attempts as i128))?;
                }
                if let Some(commit) = extras.decided_by {
                    o.field_text("decided_by", |w| w.codepoints(commit.points()))?;
                }
                if let Some(skipped) = extras.skipped_newer {
                    o.field_text("skipped_newer", |w| {
                        w.array(|a| {
                            for note in skipped {
                                a.item(|w| w.codepoints(note.points()))?;
                            }
                            Ok(())
                        })
                    })?;
                }
            }
            Ok(())
        })
    }
}
#[cfg(test)]
#[path = "failure_json_tests.rs"]
mod tests;

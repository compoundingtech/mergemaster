//! Python CLI error views borrowed from explicit source provenance.
//! Never recover lost text or infer an exception class from diagnostic content.
pub use super::value_inputs::TextRef;
use crate::evidence::{
    legacy_output::{ValueWriter, Written},
    legacy_policy::{ErrorOrigin, PolicyError, check_names::CheckName},
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
impl<'a> WireError<'a> {
    /// Preserve source metadata; selection extras apply only to ordinary failures.
    pub fn from_failure(
        failure: &'a super::Failure,
        decided_by: Option<TextRef<'a>>,
        skipped_newer: Option<&'a [TextRef<'a>]>,
    ) -> Self {
        Self::from_parts(
            failure.origin,
            failure.reason,
            failure.detail.borrowed(),
            Extras {
                attempts: failure.attempts,
                decided_by,
                skipped_newer,
            },
        )
    }
    pub fn from_policy(error: &'a PolicyError) -> Self {
        Self::from_parts(
            error.origin,
            error.reason,
            error.detail.borrowed(),
            Extras::default(),
        )
    }
    fn from_parts(
        origin: ErrorOrigin,
        reason: &'a str,
        detail: TextRef<'a>,
        extras: Extras<'a>,
    ) -> Self {
        match origin {
            ErrorOrigin::Failure => Self::Failure {
                reason: TextRef::Str(reason),
                detail,
                extras,
            },
            ErrorOrigin::Exception { class } => Self::Exception {
                class: TextRef::Str(class),
                detail,
            },
        }
    }
    fn write_reason<'s>(
        &self,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        match self {
            Self::Failure { reason, .. } => writer.codepoints(reason.points()),
            Self::Exception { .. } => writer.text("error"),
        }
    }
    fn write_detail<'s>(
        &self,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        match self {
            Self::Failure { detail, .. } => writer.codepoints(detail.points()),
            Self::Exception { class, detail } => {
                writer.codepoints(class.points().chain([58, 32]).chain(detail.points()))
            }
        }
    }
    /// Global require-all handler; no per-check or selection metadata.
    pub fn write_global<'s>(
        &self,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        writer.object(|o| {
            o.field_text("mode", |w| w.text("require-all"))?;
            o.field_text("decision", |w| w.text("error"))?;
            o.field_text("satisfied", |w| w.boolean(false))?;
            o.field_text("reason", |w| self.write_reason(w))?;
            o.field_text("detail", |w| self.write_detail(w))
        })
    }
    /// Single-check handler dictionary; no exit policy or final LF.
    /// Discard partial output on error.
    pub fn write_json<'s>(
        &self,
        check: CheckName<'_>,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        writer.object(|o| {
            o.field_text("satisfied", |w| w.boolean(false))?;
            o.field_text("reason", |w| self.write_reason(w))?;
            o.field_text("check", |w| w.codepoints(check.text().points()))?;
            o.field_text("detail", |w| self.write_detail(w))?;
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

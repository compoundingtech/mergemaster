//! Uncolored argparse stream/exit rendering, preserving interpolation provenance.
use super::{
    argparse_help,
    argparse_options::OPTIONS,
    argparse_parse::{ParseError, ParseOutcome, parse},
    argparse_usage::{RenderedHelp, usage},
    python_repr::Repr,
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::normalized_text::NormalizedText;

pub struct Streams {
    pub stdout: RenderedHelp,
    pub stderr: RenderedHelp,
    pub exit: i32,
}
#[derive(Default)]
struct Message {
    points: Vec<u32>,
    interpolations: Vec<std::ops::Range<usize>>,
}
impl Message {
    fn literal(&mut self, value: &str) {
        self.points.extend(value.chars().map(u32::from));
    }
    fn value(&mut self, value: TextRef<'_>) {
        let start = self.points.len();
        self.points.extend(value.points());
        self.interpolations.push(start..self.points.len());
    }
    fn finish(self) -> RenderedHelp {
        RenderedHelp {
            text: NormalizedText::from_points(&self.points),
            interpolations: self.interpolations,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidOption;
fn name(id: usize) -> Result<&'static str, InvalidOption> {
    let spec = OPTIONS.get(id).ok_or(InvalidOption)?;
    Ok(if id == 0 { "-h/--help" } else { spec.name })
}
impl ParseError<'_> {
    pub fn message(&self) -> Result<RenderedHelp, InvalidOption> {
        let mut out = Message::default();
        match self {
            Self::Ambiguous(value, ids) => {
                out.literal("ambiguous option: ");
                out.value(*value);
                out.literal(" could match ");
                for (at, id) in ids.iter().enumerate() {
                    if at > 0 {
                        out.literal(", ");
                    }
                    out.literal(OPTIONS.get(*id).ok_or(InvalidOption)?.name);
                }
            }
            Self::RequiredGroup(group) => {
                out.literal("one of the arguments ");
                let mut first = true;
                for spec in OPTIONS.iter().filter(|s| s.group == Some(*group)) {
                    if !first {
                        out.literal(" ");
                    }
                    first = false;
                    out.literal(spec.name);
                }
                out.literal(" is required");
            }
            Self::Unrecognized(values) => {
                out.literal("unrecognized arguments: ");
                for (at, value) in values.iter().enumerate() {
                    if at > 0 {
                        out.literal(" ");
                    }
                    out.value(*value);
                }
            }
            Self::ExpectedArgument(id) => {
                out.literal(&format!("argument {}: expected one argument", name(*id)?));
            }
            Self::Conflict(id, prior) => {
                out.literal(&format!(
                    "argument {}: not allowed with argument {}",
                    name(*id)?,
                    name(*prior)?
                ));
            }
            Self::IgnoredExplicit(id, value) => {
                out.literal(&format!(
                    "argument {}: ignored explicit argument ",
                    name(*id)?
                ));
                out.value(TextRef::Str(&format!("{}", Repr(*value))));
            }
            Self::InvalidInteger(id, value, error) => {
                out.literal(&format!("argument {}: ", name(*id)?));
                out.value(error.diagnostic(*value).borrowed());
            }
        }
        Ok(out.finish())
    }
}
/// No production dispatch: successful namespaces are returned by the parser itself.
pub fn streams(
    argv: &[TextRef<'_>],
    prog: TextRef<'_>,
    width: usize,
) -> Result<Option<Streams>, InvalidOption> {
    let empty = || Message::default().finish();
    let outcome = match parse(argv) {
        Ok(ParseOutcome::Parsed(_)) => None,
        Ok(ParseOutcome::Help) => Some(Streams {
            stdout: argparse_help::help(prog, width),
            stderr: empty(),
            exit: 0,
        }),
        Err(error) => {
            let mut rendered = usage(prog, width);
            let mut suffix = Message::default();
            suffix.value(prog);
            suffix.literal(": error: ");
            let message = error.message()?;
            let offset = suffix.points.len();
            suffix.points.extend(message.text.borrowed().points());
            suffix.interpolations.extend(
                message
                    .interpolations
                    .into_iter()
                    .map(|r| r.start + offset..r.end + offset),
            );
            suffix.literal("\n");
            let offset = rendered.text.borrowed().points().count();
            let points: Vec<_> = rendered
                .text
                .borrowed()
                .points()
                .chain(suffix.points)
                .collect();
            rendered.text = NormalizedText::from_points(&points);
            rendered.interpolations.extend(
                suffix
                    .interpolations
                    .into_iter()
                    .map(|r| r.start + offset..r.end + offset),
            );
            Some(Streams {
                stdout: empty(),
                stderr: rendered,
                exit: 2,
            })
        }
    };
    Ok(outcome)
}
#[cfg(test)]
#[path = "argparse_diagnostic_tests.rs"]
mod tests;

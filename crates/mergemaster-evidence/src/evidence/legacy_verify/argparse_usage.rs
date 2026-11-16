//! Python 3.14.7 usage rendering; width is terminal columns minus two.
use super::{
    argparse_options::{Action, OPTIONS, OptionSpec},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::normalized_text::NormalizedText;
use std::ops::Range;
/// Code-point ranges identify user program text, not formatter-generated LF.
/// A later terminal sink must escape only these ranges, never the whole result.
#[derive(Debug, Clone)]
pub struct RenderedHelp {
    pub text: NormalizedText,
    pub interpolations: Vec<Range<usize>>,
}
#[derive(Default)]
pub(super) struct Output {
    points: Vec<u32>,
    interpolations: Vec<Range<usize>>,
}
impl Output {
    pub(super) fn literal(&mut self, text: &str) {
        self.points.extend(text.chars().map(u32::from));
    }
    pub(super) fn spaces(&mut self, count: usize) {
        self.points.extend(std::iter::repeat_n(32, count));
    }
    fn program(&mut self, prog: TextRef<'_>) {
        let start = self.points.len();
        self.points.extend(prog.points());
        if start < self.points.len() {
            self.interpolations.push(start..self.points.len());
        }
    }
    pub(super) fn finish(self) -> RenderedHelp {
        // HelpFormatter.format_help collapses 3+ LF and strips outer LF even
        // when those LF originated in prog. Keep provenance through that pass.
        let start = self
            .points
            .iter()
            .position(|p| *p != 10)
            .unwrap_or(self.points.len());
        let end = self
            .points
            .iter()
            .rposition(|p| *p != 10)
            .map_or(start, |i| i + 1);
        let mut result = Self::default();
        let mut newlines = 0;
        let mut user_start = None;
        for at in start..end {
            let point = self.points[at];
            newlines = if point == 10 { newlines + 1 } else { 0 };
            if newlines > 2 {
                continue;
            }
            let user = self.interpolations.iter().any(|range| range.contains(&at));
            if user && user_start.is_none() {
                user_start = Some(result.points.len());
            }
            if !user && let Some(start) = user_start.take() {
                result.interpolations.push(start..result.points.len());
            }
            result.points.push(point);
        }
        if let Some(start) = user_start {
            result.interpolations.push(start..result.points.len());
        }
        if !result.points.is_empty() {
            result.points.push(10);
        }
        RenderedHelp {
            text: NormalizedText::from_points(&result.points),
            interpolations: result.interpolations,
        }
    }
}
pub(super) fn invocation(spec: &OptionSpec, summary: bool) -> String {
    let name = if spec.action == Action::Help {
        if summary { "-h" } else { "-h, --help" }
    } else {
        spec.name
    };
    spec.metavar
        .map_or_else(|| name.to_owned(), |label| format!("{name} {label}"))
}
fn usage_parts() -> Vec<String> {
    let mut parts = Vec::with_capacity(OPTIONS.len());
    for (index, spec) in OPTIONS.iter().enumerate() {
        let mut part = invocation(spec, true);
        if let Some(group) = spec.group {
            let first = index == 0 || OPTIONS[index - 1].group != Some(group);
            let last = OPTIONS
                .get(index + 1)
                .is_none_or(|s| s.group != Some(group));
            if first {
                part.insert(0, if group == 0 { '(' } else { '[' });
            }
            if last {
                part.push(if group == 0 { ')' } else { ']' });
            } else {
                part.push_str(" |");
            }
        } else {
            part.insert(0, '[');
            part.push(']');
        }
        parts.push(part);
    }
    parts
}
// The program is a separate piece so no search/replacement can mistake option
// text for a matching program string, including empty or newline-bearing prog.
#[derive(Clone, Copy)]
enum Piece<'a> {
    Program,
    Literal(&'a str),
}
fn piece_len(piece: Piece<'_>, prog_len: usize) -> usize {
    match piece {
        Piece::Program => prog_len,
        Piece::Literal(text) => text.len(),
    }
}
fn wrapped_usage(out: &mut Output, prog: TextRef<'_>, width: usize, parts: &[String]) {
    let prog_len = prog.points().count();
    let short = (7 + prog_len) as f64 <= 0.75 * width as f64;
    let indent = if short { 8 + prog_len } else { 7 };
    if !short {
        out.program(prog);
        out.literal("\n");
    }
    let mut line: Vec<Piece<'_>> = Vec::new();
    let mut length = if short { 6 } else { indent - 1 };
    let mut first = true;
    let pieces = short
        .then_some(Piece::Program)
        .into_iter()
        .chain(parts.iter().map(|part| Piece::Literal(part)));
    for piece in pieces {
        let size = piece_len(piece, prog_len);
        if length + 1 + size > width && !line.is_empty() {
            write_line(out, prog, &line, if short && first { 0 } else { indent });
            out.literal("\n");
            first = false;
            line.clear();
            length = indent - 1;
        }
        line.push(piece);
        length += size + 1;
    }
    if !line.is_empty() {
        write_line(out, prog, &line, if short && first { 0 } else { indent });
    }
}
fn write_line(out: &mut Output, prog: TextRef<'_>, pieces: &[Piece<'_>], indent: usize) {
    out.spaces(indent);
    for (index, piece) in pieces.iter().enumerate() {
        if index > 0 {
            out.literal(" ");
        }
        match piece {
            Piece::Program => out.program(prog),
            Piece::Literal(text) => out.literal(text),
        }
    }
}
pub(super) fn add_usage(out: &mut Output, prog: TextRef<'_>, width: usize) {
    let parts = usage_parts();
    let prog_len = prog.points().count();
    let length = 7
        + prog_len
        + usize::from(prog_len > 0)
        + parts.iter().map(String::len).sum::<usize>()
        + parts.len().saturating_sub(1);
    out.literal("usage: ");
    if length > width {
        wrapped_usage(out, prog, width, &parts);
    } else {
        out.program(prog);
        if prog_len > 0 {
            out.literal(" ");
        }
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                out.literal(" ");
            }
            out.literal(part);
        }
    }
    out.literal("\n\n");
}
/// Equivalent to ArgumentParser.format_usage(), with interpolation provenance.
pub fn usage(prog: TextRef<'_>, width: usize) -> RenderedHelp {
    let mut out = Output::default();
    add_usage(&mut out, prog, width);
    out.finish()
}
#[cfg(test)]
#[path = "argparse_usage_tests.rs"]
mod tests;

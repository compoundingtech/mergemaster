//! Python 3.14.7's uncolored formatter for the fixed evidence-verify options.
//! `width` is the effective formatter width (terminal columns minus two).
use super::{
    argparse_options::{DESCRIPTION, OPTIONS},
    argparse_usage::{Output, RenderedHelp, add_usage, invocation},
    value_inputs::TextRef,
};
#[path = "argparse_textwrap.rs"]
mod textwrap;

/// Equivalent to ArgumentParser.format_help(), with interpolation provenance.
pub fn help(prog: TextRef<'_>, width: usize) -> RenderedHelp {
    let mut out = Output::default();
    add_usage(&mut out, prog, width);
    for line in textwrap::wrap(DESCRIPTION, width.max(11)) {
        out.literal(&line);
        out.literal("\n");
    }
    out.literal("\noptions:\n");
    let headers: Vec<String> = OPTIONS.iter().map(|s| invocation(s, false)).collect();
    let action_max = headers.iter().map(|s| s.len() + 2).max().unwrap_or(0);
    let max_help_position = 24.min(width.saturating_sub(20).max(4));
    let help_position = (action_max + 2).min(max_help_position);
    let action_width = help_position - 4;
    let help_width = width.saturating_sub(help_position).max(11);
    for (spec, header) in OPTIONS.iter().zip(&headers) {
        out.spaces(2);
        out.literal(header);
        if spec.help.is_empty() {
            out.literal("\n");
            continue;
        }
        let first_indent = if header.len() <= action_width {
            out.spaces(action_width - header.len() + 2);
            0
        } else {
            out.literal("\n");
            help_position
        };
        for (index, line) in textwrap::wrap(spec.help, help_width).iter().enumerate() {
            out.spaces(if index == 0 {
                first_indent
            } else {
                help_position
            });
            out.literal(line);
            out.literal("\n");
        }
    }
    out.finish()
}
#[cfg(test)]
#[path = "argparse_help_tests.rs"]
mod tests;

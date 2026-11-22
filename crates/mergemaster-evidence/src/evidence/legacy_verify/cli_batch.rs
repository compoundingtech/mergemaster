//! Post-oracle #5552 batch transport; each question retains ordinary CLI ownership.
use super::{
    cli_adapter::Exit,
    statement_document::{Document, Node},
    value_inputs::TextRef,
};
use crate::evidence::{legacy_json, legacy_policy::normalized_text::NormalizedText};
use std::{ffi::OsStr, fmt::Write, os::unix::ffi::OsStrExt};

pub(super) fn usage(message: &str) -> Exit {
    Exit {
        stdout: String::new(),
        stderr: format!("{message}\n"),
        code: 2,
    }
}

/// Thread-local because library tests/callers can verify independent repositories
/// concurrently. Only immutable statements/signatures survive between questions;
/// per-check budgets, clocks, policy, lanes and judgments are always reconstructed.
pub(super) struct Memo;
impl Memo {
    pub(super) fn new() -> Self {
        super::cli_signature::batch_memo(true);
        super::records::batch_memo(true);
        Self
    }
}
impl Drop for Memo {
    fn drop(&mut self) {
        super::cli_signature::batch_memo(false);
        super::records::batch_memo(false);
    }
}

pub(super) fn run(bytes: &[u8]) -> anyhow::Result<Exit> {
    const INVALID: &str = "--batch reads a JSON array of argument vectors, each an array of strings, on standard input";
    // CPython's isolated stdin uses UTF-8/surrogateescape, not strict UTF-8.
    // Keep the valid-text fast path and reuse CLI ingress decoding otherwise.
    let document = match std::str::from_utf8(bytes) {
        Ok(text) => Document::from_text(text),
        Err(_) => match super::cli_adapter::decode(OsStr::from_bytes(bytes)) {
            NormalizedText::Codepoints(points) => Document::from_points(points),
            NormalizedText::Scalar(text) => Document::from_text(&text),
        },
    };
    let Ok(document) = document else {
        return Ok(usage(INVALID));
    };
    let Node::Array(runs) = document.root() else {
        return Ok(usage(INVALID));
    };
    // Validate the entire batch before executing anything, including earlier rows.
    if !runs.iter().all(|id| {
        matches!(document.node(*id), Node::Array(args)
        if args.iter().all(|id| matches!(document.node(*id), Node::String(_))))
    }) {
        return Ok(usage(INVALID));
    }
    let _memo = Memo::new();
    let mut stdout = String::from("[");
    for (index, id) in runs.iter().enumerate() {
        let Node::Array(args) = document.node(*id) else {
            return Ok(usage(INVALID));
        };
        let argv: Vec<_> = args
            .iter()
            .filter_map(|id| match document.node(*id) {
                Node::String(points) => Some(TextRef::Points(points)),
                _ => None,
            })
            .collect();
        let answer = if argv.first().is_some_and(|arg| arg.equals("--batch")) {
            usage("--batch cannot be nested")
        } else {
            super::cli_dispatch::run_arguments(&argv).unwrap_or_else(|error| Exit {
                stdout: String::new(),
                stderr: format!("{error:#}\n"),
                code: 1,
            })
        };
        if index != 0 {
            stdout.push_str(", ");
        }
        write!(stdout, "{{\"exit\": {}, \"stdout\": ", answer.code)?;
        legacy_json::string(&answer.stdout, &mut stdout)?;
        stdout.push_str(", \"stderr\": ");
        legacy_json::string(&answer.stderr, &mut stdout)?;
        stdout.push('}');
    }
    stdout.push_str("]\n");
    Ok(Exit {
        stdout,
        stderr: String::new(),
        code: 0,
    })
}

#[cfg(test)]
#[path = "cli_batch_tests.rs"]
mod tests;

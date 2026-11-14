//! Borrowed selected-check facts; neither extraction nor a principal grants trust.
use super::{
    statement::{field, string, zoned_time_components},
    statement_document::{Document, Node},
    value_inputs::{InputSource, StringNodes, ValidatedInputs},
};

/// Numeric source used only to spell a refusal; document integers are never narrowed.
#[derive(Clone, Copy)]
pub(super) enum ExitCode<'a> {
    Native(i32),
    Decimal(&'a str),
}
impl std::fmt::Display for ExitCode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(code) => std::fmt::Display::fmt(code, f),
            Self::Decimal(code) => f.write_str(code),
        }
    }
}

/// Lossless counterpart of native routing facts, not an authorization decision.
/// Construct from a validated statement and an independently verified principal.
/// Missing or ill-shaped viewed fields return None; unrelated fields are not validated.
pub struct DocumentFacts<'a> {
    pub check_name: &'a [u32],
    pub tier: &'a [u32],
    pub runner: &'a [u32],
    pub principal: &'a str,
    /// Canonical signed decimal, without narrowing Python's arbitrary-size integer.
    pub exit_code: &'a str,
    pub observed_at: &'a [u32],
    pub moment_micros: i64,
    pub(super) local_micros: i64,
    /// None represents Python's omitted inputs, equivalent to an empty object.
    pub inputs: Option<ValidatedInputs<'a>>,
    pub(super) document: &'a Document,
    command: StringNodes<'a>,
}
impl<'a> DocumentFacts<'a> {
    pub(super) fn input_source(&self) -> InputSource<'a> {
        self.inputs
            .map_or(InputSource::Empty, InputSource::Document)
    }
    /// Check names are Python code points, including lone surrogates; no key allocation.
    pub fn for_check(document: &'a Document, check: &[u32], principal: &'a str) -> Option<Self> {
        let predicate = field(document, document.root(), "predicate")?;
        let observed = field(document, predicate, "observed")?;
        let Node::Object(checks) = field(document, observed, "checks")? else {
            return None;
        };
        let (check_name, result) = checks.get_key_value(check)?;
        let result = document.node(*result);
        let Node::Integer(exit_code) = field(document, result, "exit_code")? else {
            return None;
        };
        let command = StringNodes::new(document, field(document, result, "command")?)?;
        let inputs = match field(document, observed, "inputs") {
            Some(node) => Some(ValidatedInputs::new(document, node)?),
            None => None,
        };
        let observed_at = string(field(document, predicate, "observed_at")?)?;
        let (moment_micros, local_micros) = zoned_time_components(observed_at)?;
        Some(Self {
            check_name,
            tier: string(field(document, predicate, "tier")?)?,
            runner: string(field(document, observed, "runner")?)?,
            principal,
            exit_code,
            observed_at,
            moment_micros,
            local_micros,
            inputs,
            document,
            command,
        })
    }
    pub fn failed(&self) -> bool {
        self.exit_code != "0"
    }
    pub fn level(&self) -> &str {
        self.principal.split('/').next().unwrap_or("")
    }
    pub fn command(&self) -> impl ExactSizeIterator<Item = &'a [u32]> + '_ {
        self.command.clone()
    }
}

#[cfg(test)]
#[path = "facts_tests.rs"]
mod tests;

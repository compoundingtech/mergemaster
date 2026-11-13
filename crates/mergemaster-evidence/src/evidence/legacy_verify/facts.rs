//! Borrowed selected-check facts; neither extraction nor a principal grants trust.
use super::{
    statement::{array, field, string, zoned_time_components},
    statement_document::{Document, Node},
};

/// Lossless counterpart of native routing facts, not an authorization decision.
/// Construct from a validated statement and an independently verified principal.
/// Missing or ill-shaped viewed fields return None; unrelated fields are not validated.
pub struct DocumentFacts<'a> {
    pub tier: &'a [u32],
    pub runner: &'a [u32],
    pub principal: &'a str,
    /// Canonical signed decimal, without narrowing Python's arbitrary-size integer.
    pub exit_code: &'a str,
    pub observed_at: &'a [u32],
    pub moment_micros: i64,
    pub(super) local_micros: i64,
    /// None represents Python's omitted inputs, equivalent to an empty object.
    pub inputs: Option<&'a Node>,
    pub(super) document: &'a Document,
    command: &'a [usize],
}
impl<'a> DocumentFacts<'a> {
    pub(super) fn input_source(&self) -> super::value_inputs::InputSource<'a> {
        match self.inputs {
            None => super::value_inputs::InputSource::Empty,
            Some(Node::Object(inputs)) => {
                super::value_inputs::InputSource::Document(self.document, inputs)
            }
            _ => unreachable!("validated fact inputs"),
        }
    }
    /// Check names are Python code points, including lone surrogates; no key allocation.
    pub fn for_check(document: &'a Document, check: &[u32], principal: &'a str) -> Option<Self> {
        let predicate = field(document, document.root(), "predicate")?;
        let observed = field(document, predicate, "observed")?;
        let Node::Object(checks) = field(document, observed, "checks")? else {
            return None;
        };
        let result = document.node(*checks.get(check)?);
        let Node::Integer(exit_code) = field(document, result, "exit_code")? else {
            return None;
        };
        let command = array(field(document, result, "command")?)?;
        if !command
            .iter()
            .all(|id| string(document.node(*id)).is_some())
        {
            return None;
        }
        let inputs = field(document, observed, "inputs");
        if let Some(node) = inputs {
            let Node::Object(entries) = node else {
                return None;
            };
            if !entries
                .values()
                .all(|id| string(document.node(*id)).is_some())
            {
                return None;
            }
        }
        let observed_at = string(field(document, predicate, "observed_at")?)?;
        let (moment_micros, local_micros) = zoned_time_components(observed_at)?;
        Some(Self {
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
        self.command
            .iter()
            .map(|id| string(self.document.node(*id)).expect("checked command string"))
    }
}

#[cfg(test)]
#[path = "facts_tests.rs"]
mod tests;

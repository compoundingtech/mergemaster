//! Python 3.14.7 argparse consumption for evidence-verify's optional-only parser.
use super::super::argparse_compat::consumption;
use super::argparse_int::{self, Integer, IntegerError};
use super::argparse_options::{Action, DefaultValue, OPTIONS};
use super::value_inputs::TextRef;
pub struct ParsedArguments<'a> {
    /// Indexed by OPTIONS: stores retain the last value, appends all values;
    /// present flags contain one empty-string sentinel, absent flags are empty.
    pub values: Vec<Vec<TextRef<'a>>>,
    pub max_age: Option<Integer>,
}
pub enum ParseOutcome<'a> {
    Help,
    Parsed(ParsedArguments<'a>),
}
pub enum ParseError<'a> {
    Ambiguous(TextRef<'a>, Vec<usize>),
    ExpectedArgument(usize),
    IgnoredExplicit(usize, TextRef<'a>),
    InvalidInteger(usize, TextRef<'a>, IntegerError),
    /// Conflicting option, followed by the earlier option in its group.
    Conflict(usize, usize),
    RequiredGroup(u8),
    Unrecognized(Vec<TextRef<'a>>),
}
impl consumption::Options for [super::argparse_options::OptionSpec] {
    fn count(&self) -> usize {
        self.len()
    }
    fn option(&self, id: usize) -> consumption::OptionView {
        let spec = &self[id];
        consumption::OptionView {
            long: spec.name,
            short: spec
                .aliases
                .iter()
                .copied()
                .find(|alias| !alias.starts_with("--")),
            hidden: false,
            takes_value: !matches!(spec.action, Action::Flag | Action::Help),
            help: matches!(spec.action, Action::Help),
        }
    }
}
pub fn parse<'a>(argv: &[TextRef<'a>]) -> Result<ParseOutcome<'a>, ParseError<'a>> {
    let mut values: Vec<Vec<TextRef<'a>>> = OPTIONS
        .iter()
        .map(|spec| match spec.default {
            DefaultValue::Text(text) if spec.action != Action::Help => vec![TextRef::Str(text)],
            _ => Vec::new(),
        })
        .collect();
    let mut max_age = None;
    let consumed = consumption::consume(argv.iter().copied(), OPTIONS, false, |id, value| {
        let spec = &OPTIONS[id];
        if matches!(spec.action, Action::Integer) {
            let integer = argparse_int::parse(value)
                .map_err(|error| ParseError::InvalidInteger(id, value, error))?;
            max_age = Some(integer);
        }
        if let Some(group) = spec.group
            && let Some(previous) = OPTIONS.iter().enumerate().position(|(other, candidate)| {
                other != id && candidate.group == Some(group) && !values[other].is_empty()
            })
        {
            return Err(ParseError::Conflict(id, previous));
        }
        if !matches!(spec.action, Action::Append) {
            values[id].clear();
        }
        values[id].push(value);
        Ok(())
    })
    .map_err(|error| match error {
        consumption::Error::Ambiguous(value, ids) => ParseError::Ambiguous(value, ids),
        consumption::Error::ExpectedArgument(id) => ParseError::ExpectedArgument(id),
        consumption::Error::IgnoredExplicit(id, value) => ParseError::IgnoredExplicit(id, value),
        consumption::Error::Conversion(error) => error,
    })?;
    let consumption::Outcome::Arguments { extras, .. } = consumed else {
        return Ok(ParseOutcome::Help);
    };
    if !OPTIONS
        .iter()
        .zip(&values)
        .any(|(spec, values)| spec.group == Some(0) && !values.is_empty())
    {
        return Err(ParseError::RequiredGroup(0));
    }
    if !extras.is_empty() {
        return Err(ParseError::Unrecognized(extras));
    }
    Ok(ParseOutcome::Parsed(ParsedArguments { values, max_age }))
}
#[cfg(test)]
#[path = "argparse_parse_tests.rs"]
mod tests;

//! Python 3.14.7 argparse consumption for evidence-verify's optional-only parser.
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
enum Token<'a> {
    Value,
    Separator,
    Unknown,
    Option(usize, Option<TextRef<'a>>),
    Ambiguous,
    ShortHelp(TextRef<'a>),
}

const HELP: usize = 0;

fn matching_options(name: TextRef<'_>) -> impl Iterator<Item = usize> + '_ {
    OPTIONS.iter().enumerate().filter_map(move |(id, spec)| {
        let mut points = spec.name.chars().map(u32::from);
        name.points()
            .all(|point| points.next() == Some(point))
            .then_some(id)
    })
}
fn token(argument: TextRef<'_>) -> Token<'_> {
    if argument.equals("--") {
        return Token::Separator;
    }
    if !argument.starts_with("-") || argument.equals("-") {
        return Token::Value;
    }
    let (name, explicit) = argument
        .split_once("=")
        .map_or((argument, None), |(name, value)| (name, Some(value)));
    if name.equals("-h") {
        return Token::Option(HELP, explicit);
    }
    if let Some(id) = OPTIONS.iter().position(|spec| name.equals(spec.name)) {
        return Token::Option(id, explicit);
    }
    if argument.starts_with("--") {
        let mut candidates = matching_options(name);
        if let Some(id) = candidates.next() {
            return if candidates.next().is_some() {
                Token::Ambiguous
            } else {
                Token::Option(id, explicit)
            };
        }
    } else if let Some(tail) = argument.strip_prefix("-h") {
        return Token::ShortHelp(tail);
    }
    if negative_number(argument) || argument.points().any(|point| point == 32) {
        Token::Value
    } else {
        Token::Unknown
    }
}
fn negative_number(argument: TextRef<'_>) -> bool {
    let mut points = argument.points();
    if points.next() != Some(45) {
        return false;
    }
    let first = points.next();
    let digit = if first == Some(46) {
        points.next()
    } else {
        first
    };
    digit.is_some_and(|point| super::python_digits::decimal(point).is_some())
}
fn short_help(mut tail: TextRef<'_>) -> Result<(), ParseError<'_>> {
    loop {
        if let Some(value) = tail.strip_prefix("=") {
            return Err(ParseError::IgnoredExplicit(HELP, value));
        }
        if tail.starts_with("-") {
            return Err(ParseError::IgnoredExplicit(HELP, tail));
        }
        if let Some(rest) = tail.strip_prefix("h") {
            tail = rest;
        } else {
            return Ok(());
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
    let mut extras = Vec::new();
    let mut at = 0;
    while at < argv.len() {
        let argument = argv[at];
        let (id, explicit) = match token(argument) {
            Token::Value | Token::Unknown => {
                extras.push(argument);
                at += 1;
                continue;
            }
            Token::Separator => {
                extras.extend_from_slice(&argv[at..]);
                break;
            }
            Token::Ambiguous => {
                let name = argument.split_once("=").map_or(argument, |(name, _)| name);
                let matches = matching_options(name).collect();
                return Err(ParseError::Ambiguous(argument, matches));
            }
            Token::ShortHelp(tail) => {
                short_help(tail)?;
                return Ok(ParseOutcome::Help);
            }
            Token::Option(id, explicit) => (id, explicit),
        };
        let spec = &OPTIONS[id];
        let no_value = matches!(spec.action, Action::Flag | Action::Help);
        let value = if no_value {
            if let Some(value) = explicit {
                return Err(ParseError::IgnoredExplicit(id, value));
            }
            TextRef::Str("")
        } else if let Some(value) = explicit {
            value
        } else {
            let Some(value) = argv.get(at + 1).copied() else {
                return Err(ParseError::ExpectedArgument(id));
            };
            if !matches!(token(value), Token::Value) {
                return Err(ParseError::ExpectedArgument(id));
            }
            at += 1;
            value
        };
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
        if matches!(spec.action, Action::Help) {
            return Ok(ParseOutcome::Help);
        }
        if !matches!(spec.action, Action::Append) {
            values[id].clear();
        }
        values[id].push(value);
        at += 1;
    }
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

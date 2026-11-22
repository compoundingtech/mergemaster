//! Borrowed, option-indexed argparse consumption; callers own conversion and policy.
use super::super::legacy_verify::{python_digits::decimal, value_inputs::TextRef};

pub(in crate::evidence) struct OptionView {
    pub long: &'static str,
    pub short: Option<&'static str>,
    pub hidden: bool,
    pub takes_value: bool,
    pub help: bool,
}
pub(in crate::evidence) trait Options {
    fn count(&self) -> usize;
    fn option(&self, id: usize) -> OptionView;
}
pub(in crate::evidence) enum Error<'a, E> {
    Ambiguous(TextRef<'a>, Vec<usize>),
    ExpectedArgument(usize),
    IgnoredExplicit(usize, TextRef<'a>),
    Conversion(E),
}
pub(in crate::evidence) enum Outcome<'a> {
    Help,
    Arguments {
        extras: Vec<TextRef<'a>>,
        positionals: Vec<TextRef<'a>>,
    },
}
enum Token<'a> {
    Value,
    Separator,
    Unknown,
    Option(usize, Option<TextRef<'a>>, bool),
    Ambiguous(Vec<usize>),
}
fn prefix(name: TextRef<'_>, long: &str) -> bool {
    let mut points = long.chars().map(u32::from);
    name.points().all(|point| points.next() == Some(point))
}
fn token<'a>(argument: TextRef<'a>, options: &(impl Options + ?Sized)) -> Token<'a> {
    if argument.equals("--") {
        return Token::Separator;
    }
    if !argument.starts_with("-") || argument.equals("-") {
        return Token::Value;
    }
    let (name, explicit) = argument
        .split_once("=")
        .map_or((argument, None), |(name, value)| (name, Some(value)));
    for id in 0..options.count() {
        let spec = options.option(id);
        if name.equals(spec.long) || spec.short.is_some_and(|short| name.equals(short)) {
            return Token::Option(id, explicit, false);
        }
    }
    if argument.starts_with("--") {
        let mut matches = (0..options.count()).filter(|id| {
            let spec = options.option(*id);
            !spec.hidden && prefix(name, spec.long)
        });
        if let Some(first) = matches.next() {
            if let Some(second) = matches.next() {
                let mut ids = vec![first, second];
                ids.extend(matches);
                return Token::Ambiguous(ids);
            }
            return Token::Option(first, explicit, false);
        }
    } else {
        for id in 0..options.count() {
            if let Some(tail) = options
                .option(id)
                .short
                .and_then(|short| argument.strip_prefix(short))
            {
                return Token::Option(id, Some(tail), true);
            }
        }
    }
    // CPython 3.14 uses a prefix match of -\.?\d, not numeric validation.
    let mut points = argument.points();
    let negative = if points.next() == Some(45) {
        let first = points.next();
        let digit = if first == Some(46) {
            points.next()
        } else {
            first
        };
        digit.is_some_and(|point| decimal(point).is_some())
    } else {
        false
    };
    if negative || argument.points().any(|point| point == 32) {
        Token::Value
    } else {
        Token::Unknown
    }
}

pub(in crate::evidence) fn consume<'a, E>(
    argv: impl Iterator<Item = TextRef<'a>>,
    options: &(impl Options + ?Sized),
    accept_positionals: bool,
    mut convert: impl FnMut(usize, TextRef<'a>) -> Result<(), E>,
) -> Result<Outcome<'a>, Error<'a, E>> {
    let mut argv = argv.peekable();
    let mut extras = Vec::new();
    let mut positionals = Vec::new();
    let mut positional_closed = false;
    while let Some(argument) = argv.next() {
        let (id, explicit, attached) = match token(argument, options) {
            Token::Separator => {
                if accept_positionals && !positional_closed {
                    positionals.extend(argv);
                } else {
                    extras.push(argument);
                    extras.extend(argv);
                }
                break;
            }
            Token::Value if accept_positionals && !positional_closed => {
                positionals.push(argument);
                continue;
            }
            Token::Value | Token::Unknown => {
                if !positionals.is_empty() {
                    positional_closed = true;
                }
                extras.push(argument);
                continue;
            }
            Token::Ambiguous(ids) => return Err(Error::Ambiguous(argument, ids)),
            Token::Option(id, explicit, attached) => (id, explicit, attached),
        };
        if !positionals.is_empty() {
            positional_closed = true;
        }
        let spec = options.option(id);
        let value = if !spec.takes_value {
            if let Some(mut value) = explicit {
                if attached && spec.help {
                    let short = spec.short.unwrap_or("").trim_start_matches('-');
                    loop {
                        if value.equals("") {
                            return Ok(Outcome::Help);
                        }
                        if let Some(rest) = value.strip_prefix("=") {
                            value = rest;
                            break;
                        }
                        if value.starts_with("-") {
                            break;
                        }
                        if let Some(rest) = value.strip_prefix(short) {
                            value = rest;
                        } else {
                            return Ok(Outcome::Help);
                        }
                    }
                }
                return Err(Error::IgnoredExplicit(id, value));
            }
            if spec.help {
                return Ok(Outcome::Help);
            }
            TextRef::Str("")
        } else if let Some(value) = explicit {
            value
        } else {
            let Some(value) = argv
                .peek()
                .copied()
                .filter(|value| matches!(token(*value, options), Token::Value))
            else {
                return Err(Error::ExpectedArgument(id));
            };
            argv.next();
            value
        };
        convert(id, value).map_err(Error::Conversion)?;
    }
    Ok(Outcome::Arguments {
        extras,
        positionals,
    })
}

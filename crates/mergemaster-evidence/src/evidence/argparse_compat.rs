//! Small optional-only argparse compatibility parser; command policy lives in callers.
use super::legacy_verify::{python_digits::decimal, python_repr::Repr, value_inputs::TextRef};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub(super) enum Value {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<Value>),
}

#[derive(Clone, Copy)]
pub(super) enum DefaultValue {
    None,
    Bool(bool),
    Int(i64),
    #[allow(dead_code)] // These commands do not use float defaults, but the schema supports them.
    Float(f64),
    String(&'static str),
    List(&'static [DefaultValue]),
    Factory(fn() -> Value),
}
impl DefaultValue {
    fn value(self) -> Value {
        match self {
            Self::None => Value::None,
            Self::Bool(v) => Value::Bool(v),
            Self::Int(v) => Value::Int(v),
            Self::Float(v) => Value::Float(v),
            Self::String(v) => Value::String(v.to_owned()),
            Self::List(v) => Value::List(v.iter().map(|v| v.value()).collect()),
            Self::Factory(f) => f(),
        }
    }
}

pub(super) struct Parsed {
    pub values: BTreeMap<&'static str, Value>,
    pub provided: BTreeSet<&'static str>,
}

pub(super) struct Exit {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}
#[derive(Clone, Copy)]
pub(super) enum Action {
    Help,
    Flag,
    Store,
    Append,
    Convert {
        name: &'static str,
        parse: fn(&str) -> Option<Value>,
    },
}
pub(super) struct OptionSpec {
    pub long: &'static str,
    pub short: Option<&'static str>,
    pub metavar: Option<&'static str>,
    pub action: Action,
    pub choices: &'static [&'static str],
    pub help: &'static str,
    pub hidden: bool,
    pub default: DefaultValue,
}
pub(super) struct Parser {
    pub program: &'static str,
    pub description: &'static str,
    pub options: &'static [OptionSpec],
}
impl OptionSpec {
    fn takes_value(&self) -> bool {
        !matches!(self.action, Action::Help | Action::Flag)
    }
    fn label(&self) -> String {
        let value = self
            .metavar
            .map(|value| format!(" {value}"))
            .unwrap_or_default();
        if let Some(short) = self.short {
            format!("{short}{value}, {}{value}", self.long)
        } else {
            format!("{}{value}", self.long)
        }
    }
    fn diagnostic(&self) -> String {
        if let Some(short) = self.short {
            format!("{short}/{}", self.long)
        } else {
            self.long.to_owned()
        }
    }
}
fn repr(text: &str) -> Repr<'_> {
    Repr(TextRef::Str(text))
}
enum Token<'a> {
    Value,
    Separator,
    Unknown,
    Option(usize, Option<&'a str>, bool),
    Ambiguous(Vec<&'static str>),
}
impl Parser {
    pub fn usage(&self) -> String {
        let mut out = format!("usage: {}", self.program);
        let indent = " ".repeat(out.len() + 1);
        let mut column = out.len();
        for spec in self.options.iter().filter(|spec| !spec.hidden) {
            let flag = spec.short.unwrap_or(spec.long);
            let part = if let Some(value) = spec.metavar {
                format!("[{flag} {value}]")
            } else {
                format!("[{flag}]")
            };
            if column + 1 + part.len() > 78 {
                out.push('\n');
                out.push_str(&indent);
                column = indent.len();
            } else {
                out.push(' ');
                column += 1;
            }
            out.push_str(&part);
            column += part.len();
        }
        out.push('\n');
        out
    }
    pub fn error(&self, message: impl std::fmt::Display) -> Exit {
        Exit {
            code: 2,
            stdout: String::new(),
            stderr: format!("{}{}: error: {message}\n", self.usage(), self.program),
        }
    }
    fn helped(&self) -> Exit {
        let mut out = self.usage();
        out.push('\n');
        wrap(self.description, 78, "", &mut out);
        out.push_str("\noptions:\n");
        let help_column = self
            .options
            .iter()
            .filter(|s| !s.hidden)
            .map(|s| s.label().len() + 4)
            .max()
            .unwrap_or(4)
            .min(24);
        for spec in self.options.iter().filter(|s| !s.hidden) {
            let label = spec.label();
            out.push_str("  ");
            out.push_str(&label);
            if spec.help.is_empty() {
                out.push('\n');
                continue;
            }
            if label.len() + 2 > help_column - 2 {
                out.push('\n');
                out.push_str(&" ".repeat(help_column));
            } else {
                out.push_str(&" ".repeat(help_column - label.len() - 2));
            }
            wrap(
                spec.help,
                78 - help_column,
                &" ".repeat(help_column),
                &mut out,
            );
        }
        Exit {
            code: 0,
            stdout: out,
            stderr: String::new(),
        }
    }
    fn token<'a>(&self, text: &'a str) -> Token<'a> {
        if text == "--" {
            return Token::Separator;
        }
        if !text.starts_with('-') || text == "-" {
            return Token::Value;
        }
        let (key, explicit) = text
            .split_once('=')
            .map_or((text, None), |(a, b)| (a, Some(b)));
        if let Some((id, _)) = self
            .options
            .iter()
            .enumerate()
            .find(|(_, s)| s.long == key || s.short == Some(key))
        {
            return Token::Option(id, explicit, false);
        }
        if text.starts_with("--") {
            let mut matches = self
                .options
                .iter()
                .enumerate()
                .filter(|(_, s)| !s.hidden && s.long.starts_with(key));
            if let Some((id, first)) = matches.next() {
                if let Some((_, second)) = matches.next() {
                    let mut names = vec![first.long, second.long];
                    names.extend(matches.map(|(_, s)| s.long));
                    return Token::Ambiguous(names);
                }
                return Token::Option(id, explicit, false);
            }
        } else if let Some((id, tail)) = self.options.iter().enumerate().find_map(|(id, s)| {
            s.short
                .and_then(|short| text.strip_prefix(short))
                .map(|tail| (id, tail))
        }) {
            return Token::Option(id, Some(tail), true);
        }
        let negative = text.strip_prefix('-').is_some_and(|body| {
            body.strip_prefix('.')
                .unwrap_or(body)
                .chars()
                .next()
                .is_some_and(|c| decimal(u32::from(c)).is_some())
        });
        if negative || text.contains(' ') {
            Token::Value
        } else {
            Token::Unknown
        }
    }
    /// Preserve Python default types; conversion applies only to supplied values
    /// and to string defaults, never to integer/float/list/bool/None defaults.
    pub fn parse(&self, argv: &[String]) -> Result<Parsed, Exit> {
        let mut stored: Vec<(usize, Value)> = Vec::new();
        let mut provided = BTreeSet::new();
        let mut extras = Vec::new();
        let mut index = 0;
        while let Some(arg) = argv.get(index) {
            match self.token(arg) {
                Token::Separator => {
                    extras.extend_from_slice(&argv[index..]);
                    break;
                }
                Token::Value | Token::Unknown => extras.push(arg.clone()),
                Token::Ambiguous(names) => {
                    return Err(self.error(format!(
                        "ambiguous option: {arg} could match {}",
                        names.join(", ")
                    )));
                }
                Token::Option(id, explicit, attached) => {
                    let spec = &self.options[id];
                    provided.insert(spec.long);
                    if !spec.takes_value() {
                        if let Some(mut value) = explicit {
                            // Short help clusters queue their actions before the
                            // unknown suffix; help exits before extras are reported.
                            if attached && matches!(spec.action, Action::Help) {
                                let short = spec.short.unwrap_or("").trim_start_matches('-');
                                loop {
                                    if value.is_empty() {
                                        return Err(self.helped());
                                    }
                                    if let Some(rest) = value.strip_prefix('=') {
                                        value = rest;
                                        break;
                                    }
                                    if value.starts_with('-') {
                                        break;
                                    }
                                    if let Some(rest) = value.strip_prefix(short) {
                                        value = rest;
                                    } else {
                                        return Err(self.helped());
                                    }
                                }
                            }
                            return Err(self.error(format!(
                                "argument {}: ignored explicit argument {}",
                                spec.diagnostic(),
                                repr(value)
                            )));
                        }
                        if matches!(spec.action, Action::Help) {
                            return Err(self.helped());
                        }
                        stored.retain(|(key, _)| *key != id);
                        stored.push((id, Value::Bool(true)));
                    } else {
                        let value = if let Some(value) = explicit {
                            value
                        } else {
                            index += 1;
                            let Some(value) = argv
                                .get(index)
                                .filter(|v| matches!(self.token(v), Token::Value))
                            else {
                                return Err(self.error(format!(
                                    "argument {}: expected one argument",
                                    spec.diagnostic()
                                )));
                            };
                            value
                        };
                        let converted = if let Action::Convert { name, parse } = spec.action {
                            let Some(converted) = parse(value) else {
                                return Err(self.error(format!(
                                    "argument {}: invalid {name} value: {}",
                                    spec.diagnostic(),
                                    repr(value)
                                )));
                            };
                            converted
                        } else {
                            Value::String(value.to_owned())
                        };
                        if !spec.choices.is_empty()
                            && !matches!(&converted, Value::String(v) if spec.choices.contains(&v.as_str()))
                        {
                            return Err(self.error(format!(
                                "argument {}: invalid choice: {} (choose from {})",
                                spec.diagnostic(),
                                repr(value),
                                spec.choices
                                    .iter()
                                    .map(|choice| repr(choice).to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )));
                        }
                        if !matches!(spec.action, Action::Append) {
                            stored.retain(|(key, _)| *key != id);
                        }
                        stored.push((id, converted));
                    }
                }
            }
            index += 1;
        }
        let mut values = BTreeMap::new();
        for spec in self.options {
            if matches!(spec.action, Action::Help) {
                continue;
            }
            let supplied = provided.contains(spec.long);
            if supplied && !matches!(spec.action, Action::Append) {
                continue;
            }
            let mut value = spec.default.value();
            if !supplied {
                if let (Action::Convert { name, parse }, Value::String(text)) =
                    (spec.action, &value)
                {
                    value = parse(text).ok_or_else(|| {
                        self.error(format!(
                            "argument {}: invalid {name} value: {}",
                            spec.diagnostic(),
                            repr(text)
                        ))
                    })?;
                }
            }
            values.insert(spec.long, value);
        }
        for (id, value) in stored {
            let spec = &self.options[id];
            if matches!(spec.action, Action::Append) {
                if let Some(Value::List(items)) = values.get_mut(spec.long) {
                    items.push(value);
                } else {
                    values.insert(spec.long, Value::List(vec![value]));
                }
            } else {
                values.insert(spec.long, value);
            }
        }
        if !extras.is_empty() {
            return Err(self.error(format!("unrecognized arguments: {}", extras.join(" "))));
        }
        Ok(Parsed { values, provided })
    }
}
/// Append wrapped text after a caller-supplied first-line prefix.
fn wrap(text: &str, width: usize, continuation: &str, out: &mut String) {
    let mut column = 0;
    for word in text.split_whitespace() {
        if column != 0 && column + 1 + word.len() > width {
            out.push('\n');
            out.push_str(continuation);
            column = 0;
        }
        if column != 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += word.len();
    }
    out.push('\n');
}

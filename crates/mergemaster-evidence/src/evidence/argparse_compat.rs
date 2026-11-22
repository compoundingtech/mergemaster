//! Small optional-only argparse compatibility parser; command policy lives in callers.
use super::legacy_verify::{python_digits::decimal, python_repr::Repr, value_inputs::TextRef};
use std::collections::{BTreeMap, BTreeSet};

pub(super) mod consumption;

impl consumption::Options for [OptionSpec] {
    fn count(&self) -> usize {
        self.len()
    }
    fn option(&self, id: usize) -> consumption::OptionView {
        let spec = &self[id];
        consumption::OptionView {
            long: spec.long,
            short: spec.short,
            hidden: spec.hidden,
            takes_value: spec.takes_value(),
            help: matches!(spec.action, Action::Help),
        }
    }
}

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
pub(super) fn float(text: &str) -> Option<Value> {
    // Python float accepts Unicode decimal digits and digit-separated underscores,
    // but not Rust's broader trim set (notably U+001C through U+001F).
    let text = text.trim_matches(|c: char| c.is_whitespace() && !matches!(c, '\u{1c}'..='\u{1f}'));
    let mut normalized = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut previous_digit = false;
    while let Some(ch) = chars.next() {
        if ch == '_' {
            if !previous_digit
                || !chars
                    .peek()
                    .is_some_and(|c| decimal(u32::from(*c)).is_some())
            {
                return None;
            }
            previous_digit = false;
        } else if let Some(digit) = decimal(u32::from(ch)) {
            normalized.push(char::from(b'0' + digit));
            previous_digit = true;
        } else {
            normalized.push(ch);
            previous_digit = false;
        }
    }
    let number = match normalized.to_ascii_lowercase().as_str() {
        "inf" | "+inf" | "infinity" | "+infinity" => Some(f64::INFINITY),
        "-inf" | "-infinity" => Some(f64::NEG_INFINITY),
        "nan" | "+nan" | "-nan" => Some(f64::NAN),
        _ => normalized.parse().ok(),
    }?;
    Some(Value::Float(number))
}
pub(super) fn integer(text: &str) -> Option<Value> {
    let number = super::legacy_verify::argparse_int::parse(TextRef::Str(text)).ok()?;
    let magnitude = number.digits.parse::<u64>().ok()?;
    let signed = if number.negative {
        i64::try_from(i128::from(magnitude).checked_neg()?).ok()?
    } else {
        i64::try_from(magnitude).ok()?
    };
    Some(Value::Int(signed))
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
    /// Preserve Python default types; conversion applies only to supplied values
    /// and to string defaults, never to integer/float/list/bool/None defaults.
    pub fn parse(&self, argv: &[String]) -> Result<Parsed, Exit> {
        self.parse_required(argv, &[])
    }
    pub fn parse_required(&self, argv: &[String], required: &[&str]) -> Result<Parsed, Exit> {
        self.parse_inner(argv, required, false)
            .map(|(parsed, _)| parsed)
    }
    pub fn parse_positionals(&self, argv: &[String]) -> Result<(Parsed, Vec<String>), Exit> {
        self.parse_inner(argv, &[], true)
    }
    fn parse_inner(
        &self,
        argv: &[String],
        required: &[&str],
        accept_positionals: bool,
    ) -> Result<(Parsed, Vec<String>), Exit> {
        let mut stored: Vec<(usize, Value)> = Vec::new();
        let mut provided = BTreeSet::new();
        let consumed = consumption::consume(
            argv.iter().map(TextRef::from),
            self.options,
            accept_positionals,
            |id, value| {
                let spec = &self.options[id];
                provided.insert(spec.long);
                let TextRef::Str(value) = value else {
                    return Err(self.error("non-string input at string parser boundary"));
                };
                let converted = if !spec.takes_value() {
                    Value::Bool(true)
                } else if let Action::Convert { name, parse } = spec.action {
                    parse(value).ok_or_else(|| {
                        self.error(format!(
                            "argument {}: invalid {name} value: {}",
                            spec.diagnostic(),
                            repr(value)
                        ))
                    })?
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
                Ok(())
            },
        )
        .map_err(|error| match error {
            consumption::Error::Ambiguous(argument, ids) => self.error(format!(
                "ambiguous option: {argument} could match {}",
                ids.iter()
                    .map(|id| self.options[*id].long)
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            consumption::Error::ExpectedArgument(id) => self.error(format!(
                "argument {}: expected one argument",
                self.options[id].diagnostic()
            )),
            consumption::Error::IgnoredExplicit(id, value) => self.error(format!(
                "argument {}: ignored explicit argument {}",
                self.options[id].diagnostic(),
                Repr(value)
            )),
            consumption::Error::Conversion(exit) => exit,
        })?;
        let consumption::Outcome::Arguments {
            extras,
            positionals,
        } = consumed
        else {
            return Err(self.helped());
        };
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
            if !supplied
                && let (Action::Convert { name, parse }, Value::String(text)) =
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
        let missing: Vec<_> = required
            .iter()
            .filter(|name| !provided.contains(**name))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(self.error(format!(
                "the following arguments are required: {}",
                missing.join(", ")
            )));
        }
        if !extras.is_empty() {
            return Err(self.error(format!(
                "unrecognized arguments: {}",
                extras
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            )));
        }
        Ok((
            Parsed { values, provided },
            positionals
                .into_iter()
                .map(|value| value.to_string())
                .collect(),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;

    const fn option(long: &'static str, action: Action) -> OptionSpec {
        OptionSpec {
            long,
            short: None,
            metavar: Some("VALUE"),
            action,
            choices: &[],
            help: "",
            hidden: false,
            default: DefaultValue::None,
        }
    }
    const PARSER: Parser = Parser {
        program: "test",
        description: "",
        options: &[
            option("--repo", Action::Store),
            option("--repository", Action::Store),
            option(
                "--integer",
                Action::Convert {
                    name: "int",
                    parse: integer,
                },
            ),
            option(
                "--float",
                Action::Convert {
                    name: "float",
                    parse: float,
                },
            ),
        ],
    };
    fn argv(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }
    #[test]
    fn exact_prefix_inline_and_repetition() {
        let parsed = PARSER
            .parse(&argv(&["--repo=first", "--repo", "-2", "--repos=last"]))
            .ok()
            .unwrap();
        assert_eq!(
            parsed.values.get("--repo"),
            Some(&Value::String("-2".into()))
        );
        assert_eq!(
            parsed.values.get("--repository"),
            Some(&Value::String("last".into()))
        );
        let exit = PARSER.parse(&argv(&["--rep=x"])).err().unwrap();
        assert_eq!(exit.code, 2);
        assert!(
            exit.stderr
                .ends_with("ambiguous option: --rep=x could match --repo, --repository\n")
        );
    }
    #[test]
    fn python_numeric_spellings() {
        for value in ["  +1_024\t", "١_٠٢٤"] {
            assert_eq!(integer(value), Some(Value::Int(1024)));
        }
        for value in ["  +1_024.5\t", "١_٠٢٤.٥"] {
            assert_eq!(float(value), Some(Value::Float(1024.5)));
        }
        for value in ["nan", "+NaN", "-nan"] {
            assert!(matches!(float(value), Some(Value::Float(number)) if number.is_nan()));
        }
        assert_eq!(float("inf"), Some(Value::Float(f64::INFINITY)));
        assert_eq!(float("-infinity"), Some(Value::Float(f64::NEG_INFINITY)));
        for value in ["1__0", "_10", "10_", "\u{1c}10", "1e_2"] {
            assert!(float(value).is_none());
        }
        assert!(PARSER.parse(&argv(&["--float", "-infinity"])).is_err());
        assert!(PARSER.parse(&argv(&["--float=-infinity"])).is_ok());
        assert!(PARSER.parse(&argv(&["--float", "-1e2"])).is_ok());
        assert!(PARSER.parse(&argv(&["--float", "-.5"])).is_ok());
    }
    #[test]
    fn required_and_positional_ordering() {
        let exit = PARSER
            .parse_required(&argv(&["unknown"]), &["--repo"])
            .err()
            .unwrap();
        assert!(
            exit.stderr
                .contains("the following arguments are required: --repo")
        );
        let (_, files) = PARSER
            .parse_positionals(&argv(&["--repo=x", "--", "-file"]))
            .ok()
            .unwrap();
        assert_eq!(files, ["-file"]);
        assert!(
            PARSER
                .parse_positionals(&argv(&["first", "--repo=x", "last"]))
                .is_err()
        );
    }
}

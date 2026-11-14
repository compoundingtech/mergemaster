//! CPython 3.14.7 tomllib lexical primitives; positions count Unicode code points.
//! Ported from Lib/tomllib/_parser.py (MIT, Taneli Hukkinen, PSF contribution).
use super::{python_repr::Repr, value_inputs::TextRef};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub message: String,
    pub position: usize,
    pub line: usize,
    pub column: u128,
    pub at_end: bool,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.at_end {
            write!(f, "{} (at end of document)", self.message)
        } else {
            write!(
                f,
                "{} (at line {}, column {})",
                self.message, self.line, self.column
            )
        }
    }
}
impl std::error::Error for Error {}

/// The CRLF-normalized source used by every TOML parser stage.
#[derive(Debug)]
pub struct Source {
    pub chars: Vec<char>,
}
impl Source {
    pub fn new(text: &str) -> Self {
        let mut chars = Vec::with_capacity(text.len());
        let mut input = text.chars().peekable();
        while let Some(c) = input.next() {
            if c == '\r' && input.peek() == Some(&'\n') {
                input.next();
                chars.push('\n');
            } else {
                chars.push(c);
            }
        }
        Self { chars }
    }
    pub fn error(&self, message: impl Into<String>, position: usize) -> Error {
        let prefix = &self.chars[..position.min(self.chars.len())];
        Error {
            message: message.into(),
            position,
            line: prefix.iter().filter(|c| **c == '\n').count() + 1,
            column: prefix
                .iter()
                .rposition(|c| *c == '\n')
                .map_or(position as u128 + 1, |p| (position - p) as u128),
            at_end: position >= self.chars.len(),
        }
    }
    pub fn at(&self, position: usize) -> Option<char> {
        self.chars.get(position).copied()
    }
    pub fn skip(&self, mut position: usize, allowed: impl Fn(char) -> bool) -> usize {
        while self.at(position).is_some_and(&allowed) {
            position += 1;
        }
        position
    }
    pub fn skip_until(
        &self,
        position: usize,
        expect: char,
        error_on: impl Fn(char) -> bool,
        error_on_eof: bool,
    ) -> Result<usize, Error> {
        let end = self
            .chars
            .get(position..)
            .unwrap_or_default()
            .iter()
            .position(|c| *c == expect)
            .map(|p| position + p);
        // CPython reports the missing terminator before illegal characters.
        if end.is_none() && error_on_eof {
            return Err(self.error(format!("Expected {}", repr(expect)), self.chars.len()));
        }
        let end = end.unwrap_or(self.chars.len());
        if let Some(offset) = self
            .chars
            .get(position..end)
            .unwrap_or_default()
            .iter()
            .position(|c| error_on(*c))
        {
            let pos = position + offset;
            return Err(self.error(
                format!("Found invalid character {}", repr(self.chars[pos])),
                pos,
            ));
        }
        Ok(end)
    }
    pub fn skip_comment(&self, position: usize) -> Result<usize, Error> {
        if self.at(position) == Some('#') {
            self.skip_until(position + 1, '\n', illegal_single, false)
        } else {
            Ok(position)
        }
    }
    pub fn skip_array_ws(&self, mut position: usize) -> Result<usize, Error> {
        loop {
            let before = position;
            position = self.skip_comment(self.skip(position, |c| whitespace(c) || c == '\n'))?;
            if position == before {
                return Ok(position);
            }
        }
    }
}
pub fn whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t')
}
pub fn bare_key(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_')
}
pub fn illegal_single(c: char) -> bool {
    (c < ' ' || c == '\u{7f}') && c != '\t'
}
pub fn illegal_multiline(c: char) -> bool {
    illegal_single(c) && c != '\n'
}
fn repr(c: char) -> String {
    Repr(TextRef::Points(&[u32::from(c)])).to_string()
}

#[path = "toml_strings.rs"]
mod strings;

#[cfg(test)]
#[path = "toml_lexing_tests.rs"]
mod tests;

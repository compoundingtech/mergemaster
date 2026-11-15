//! Lossless Python JSON primitive tokens; container grammar belongs to the loader.
//! Syntax diagnostics follow CPython 3.14.7's accelerated `_json` scanner.
//! Numbers consume the longest valid prefix; document grammar rejects leftover text.
use super::statement_bytes::decode_json_bytes;
#[derive(Debug)]
pub enum Token {
    Null,
    Bool(bool),
    /// Original integer lexeme, including -0; numeric conversion is deferred.
    Integer(String),
    Float(f64),
    /// Python code points, including lone surrogates that cannot inhabit Rust String.
    String(Vec<u32>),
    Punctuation(u8),
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Syntax(SyntaxError),
    IntegerLimit { digits: usize },
}

/// CPython 3.14.7 `Modules/_json.c` and `Lib/json/decoder.py` diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntaxKind {
    ExpectingValue,
    PropertyName,
    ColonDelimiter,
    CommaDelimiter,
    TrailingArrayComma,
    TrailingObjectComma,
    UnterminatedString,
    InvalidControlCharacter,
    InvalidEscape,
    InvalidUnicodeEscape,
    ExtraData,
    UnexpectedUtf8Bom,
}
impl SyntaxKind {
    pub const fn message(self) -> &'static str {
        match self {
            Self::ExpectingValue => "Expecting value",
            Self::PropertyName => "Expecting property name enclosed in double quotes",
            Self::ColonDelimiter => "Expecting ':' delimiter",
            Self::CommaDelimiter => "Expecting ',' delimiter",
            Self::TrailingArrayComma => "Illegal trailing comma before end of array",
            Self::TrailingObjectComma => "Illegal trailing comma before end of object",
            Self::UnterminatedString => "Unterminated string starting at",
            Self::InvalidControlCharacter => "Invalid control character at",
            Self::InvalidEscape => "Invalid \\escape",
            Self::InvalidUnicodeEscape => "Invalid \\uXXXX escape",
            Self::ExtraData => "Extra data",
            Self::UnexpectedUtf8Bom => "Unexpected UTF-8 BOM (decode using utf-8-sig)",
        }
    }
}
/// Zero-based character position and one-based line/column, all in codepoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub kind: SyntaxKind,
    pub pos: usize,
    pub lineno: usize,
    pub colno: usize,
}
impl std::fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: line {} column {} (char {})",
            self.kind.message(),
            self.lineno,
            self.colno,
            self.pos
        )
    }
}
pub struct Tokens {
    text: Vec<u32>,
    at: usize,
}
impl Tokens {
    pub(super) fn from_points(text: Vec<u32>) -> Self {
        Self { text, at: 0 }
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            text: decode_json_bytes(bytes)?,
            at: 0,
        })
    }
    /// JSON str semantics: preserve BOM and NUL codepoints, with no byte sniffing.
    pub fn from_text(text: &str) -> Self {
        Self {
            text: text.chars().map(u32::from).collect(),
            at: 0,
        }
    }
    pub fn syntax_error(&self, kind: SyntaxKind, pos: usize) -> SyntaxError {
        let prefix = &self.text[..pos];
        SyntaxError {
            kind,
            pos,
            lineno: prefix.iter().filter(|p| **p == 10).count() + 1,
            colno: prefix
                .iter()
                .rposition(|p| *p == 10)
                .map_or(pos + 1, |n| pos - n),
        }
    }
    pub fn position(&self) -> usize {
        self.at
    }
    pub fn peek(&mut self) -> Option<u32> {
        while matches!(self.text.get(self.at), Some(9 | 10 | 13 | 32)) {
            self.at += 1;
        }
        self.text.get(self.at).copied()
    }
    fn invalid(&self, kind: SyntaxKind, pos: usize) -> Error {
        Error::Syntax(self.syntax_error(kind, pos))
    }
    fn eat(&mut self, point: u32) -> bool {
        if self.text.get(self.at) == Some(&point) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn word(&mut self, word: &str) -> bool {
        let prefix = self.text.get(self.at..self.at + word.len());
        let matches = prefix.is_some_and(|p| p.iter().copied().eq(word.bytes().map(u32::from)));
        if matches {
            self.at += word.len();
        }
        matches
    }
    fn hex(&self, at: usize) -> Option<u32> {
        self.text.get(at..at + 4)?.iter().try_fold(0, |n, p| {
            let digit = match p {
                48..=57 => p - 48,
                65..=70 => p - 55,
                97..=102 => p - 87,
                _ => return None,
            };
            Some((n << 4) | digit)
        })
    }
    fn string(&mut self) -> Result<Vec<u32>, Error> {
        let begin = self.at - 1;
        let mut result = Vec::new();
        loop {
            let Some(mut point) = self.text.get(self.at).copied() else {
                return Err(self.invalid(SyntaxKind::UnterminatedString, begin));
            };
            self.at += 1;
            match point {
                34 => return Ok(result),
                0..=31 => {
                    return Err(self.invalid(SyntaxKind::InvalidControlCharacter, self.at - 1));
                }
                92 => {
                    let Some(escaped) = self.text.get(self.at).copied() else {
                        return Err(self.invalid(SyntaxKind::UnterminatedString, begin));
                    };
                    point = escaped;
                    self.at += 1;
                    point = match point {
                        34 | 47 | 92 => point,
                        98 => 8,
                        102 => 12,
                        110 => 10,
                        114 => 13,
                        116 => 9,
                        117 => {
                            let mut high = self.hex(self.at).ok_or_else(|| {
                                self.invalid(SyntaxKind::InvalidUnicodeEscape, self.at - 1)
                            })?;
                            self.at += 4;
                            if (0xd800..=0xdbff).contains(&high)
                                && self.text.get(self.at..self.at + 2) == Some(&[92, 117])
                                && let Some(low @ 0xdc00..=0xdfff) = self.hex(self.at + 2)
                            {
                                high = 0x10000 + ((high - 0xd800) << 10) + low - 0xdc00;
                                self.at += 6;
                            }
                            high
                        }
                        _ => return Err(self.invalid(SyntaxKind::InvalidEscape, self.at - 2)),
                    };
                }
                _ => {}
            }
            result.push(point);
        }
    }
    fn digits(&mut self) -> bool {
        let start = self.at;
        while matches!(self.text.get(self.at), Some(48..=57)) {
            self.at += 1;
        }
        self.at != start
    }
    fn number(&mut self) -> Result<Token, Error> {
        let start = self.at;
        self.eat(45);
        let digits = self.at;
        if !self.eat(48) && !self.digits() {
            return Err(self.invalid(SyntaxKind::ExpectingValue, start));
        }
        let mut float = false;
        let fraction = self.at;
        if self.eat(46) {
            if self.digits() {
                float = true;
            } else {
                self.at = fraction;
            }
        }
        let exponent = self.at;
        if self.eat(101) || self.eat(69) {
            if !self.eat(43) {
                self.eat(45);
            }
            if self.digits() {
                float = true;
            } else {
                self.at = exponent;
            }
        }
        if !float && self.at - digits > 4300 {
            return Err(Error::IntegerLimit {
                digits: self.at - digits,
            });
        }
        let text: String = self.text[start..self.at]
            .iter()
            .map(|p| char::from(p.to_le_bytes()[0]))
            .collect();
        if float {
            Ok(Token::Float(text.parse().map_err(|_| {
                self.invalid(SyntaxKind::ExpectingValue, start)
            })?))
        } else {
            Ok(Token::Integer(text))
        }
    }
    fn token(&mut self) -> Result<Token, Error> {
        let point = self.text[self.at];
        for (word, token) in [
            ("NaN", Token::Float(f64::NAN)),
            ("Infinity", Token::Float(f64::INFINITY)),
            ("-Infinity", Token::Float(f64::NEG_INFINITY)),
            ("null", Token::Null),
            ("true", Token::Bool(true)),
            ("false", Token::Bool(false)),
        ] {
            if self.word(word) {
                return Ok(token);
            }
        }
        match point {
            34 => {
                self.at += 1;
                self.string().map(Token::String)
            }
            45 | 48..=57 => self.number(),
            44 | 58 | 91 | 93 | 123 | 125 => {
                self.at += 1;
                Ok(Token::Punctuation(point.to_le_bytes()[0]))
            }
            _ => Err(self.invalid(SyntaxKind::ExpectingValue, self.at)),
        }
    }
}
impl Iterator for Tokens {
    type Item = Result<Token, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        self.peek()?;
        let token = self.token();
        if token.is_err() {
            self.at = self.text.len();
        }
        Some(token)
    }
}
#[cfg(test)]
#[path = "statement_tokens_tests.rs"]
mod tests;

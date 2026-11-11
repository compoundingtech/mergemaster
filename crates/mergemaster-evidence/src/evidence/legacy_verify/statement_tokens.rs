//! Lossless Python JSON primitive tokens; container grammar belongs to the loader.
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
    Invalid,
    IntegerLimit,
}
pub struct Tokens {
    text: Vec<u32>,
    at: usize,
}
impl Tokens {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            text: decode_json_bytes(bytes)?,
            at: 0,
        })
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
    fn string(&mut self) -> Option<Vec<u32>> {
        let mut result = Vec::new();
        loop {
            let mut point = *self.text.get(self.at)?;
            self.at += 1;
            match point {
                34 => return Some(result),
                0..=31 => return None,
                92 => {
                    point = *self.text.get(self.at)?;
                    self.at += 1;
                    point = match point {
                        34 | 47 | 92 => point,
                        98 => 8,
                        102 => 12,
                        110 => 10,
                        114 => 13,
                        116 => 9,
                        117 => {
                            let mut high = self.hex(self.at)?;
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
                        _ => return None,
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
            return Err(Error::Invalid);
        }
        let mut float = false;
        if self.eat(46) {
            float = true;
            if !self.digits() {
                return Err(Error::Invalid);
            }
        }
        if self.eat(101) || self.eat(69) {
            float = true;
            if !self.eat(43) {
                self.eat(45);
            }
            if !self.digits() {
                return Err(Error::Invalid);
            }
        }
        if !float && self.at - digits > 4300 {
            return Err(Error::IntegerLimit);
        }
        let text: String = self.text[start..self.at]
            .iter()
            .map(|p| char::from_u32(*p).unwrap())
            .collect();
        if float {
            Ok(Token::Float(text.parse().map_err(|_| Error::Invalid)?))
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
                self.string().map(Token::String).ok_or(Error::Invalid)
            }
            45 | 48..=57 => self.number(),
            44 | 58 | 91 | 93 | 123 | 125 => {
                self.at += 1;
                Ok(Token::Punctuation(u8::try_from(point).unwrap()))
            }
            _ => Err(Error::Invalid),
        }
    }
}
impl Iterator for Tokens {
    type Item = Result<Token, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        while matches!(self.text.get(self.at), Some(9 | 10 | 13 | 32)) {
            self.at += 1;
        }
        if self.at == self.text.len() {
            return None;
        }
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

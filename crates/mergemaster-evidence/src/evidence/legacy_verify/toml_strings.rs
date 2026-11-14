//! CPython 3.14.7 tomllib strings and escape rules (MIT, Taneli Hukkinen).
use super::{Error, Source, illegal_multiline, illegal_single, repr, whitespace};

impl Source {
    pub fn literal_string(&self, position: usize) -> Result<(usize, String), Error> {
        let start = position.saturating_add(1);
        let end = self.skip_until(start, '\'', illegal_single, true)?;
        Ok((end + 1, self.chars[start..end].iter().collect()))
    }
    pub fn basic_escape(&self, position: usize, multiline: bool) -> Result<(usize, String), Error> {
        let id = self.at(position.saturating_add(1));
        let mut pos = position.saturating_add(2);
        if self.at(position) != Some('\\') {
            return Err(self.error("Unescaped '\\' in a string", pos));
        }
        if multiline && matches!(id, Some(' ' | '\t' | '\n')) {
            if id != Some('\n') {
                pos = self.skip(pos, whitespace);
                let Some(c) = self.at(pos) else {
                    return Ok((pos, String::new()));
                };
                if c != '\n' {
                    return Err(self.error("Unescaped '\\' in a string", pos));
                }
                pos += 1;
            }
            return Ok((
                self.skip(pos, |c| whitespace(c) || c == '\n'),
                String::new(),
            ));
        }
        if matches!(id, Some('u' | 'U')) {
            return self.hex_char(pos, if id == Some('u') { 4 } else { 8 });
        }
        let replacement = match id {
            Some('b') => '\u{8}',
            Some('t') => '\t',
            Some('n') => '\n',
            Some('f') => '\u{c}',
            Some('r') => '\r',
            Some('"') => '"',
            Some('\\') => '\\',
            _ => return Err(self.error("Unescaped '\\' in a string", pos)),
        };
        Ok((pos, replacement.to_string()))
    }
    fn hex_char(&self, position: usize, length: usize) -> Result<(usize, String), Error> {
        let Some(end) = position.checked_add(length) else {
            return Err(self.error("Invalid hex value", position));
        };
        let Some(chars) = self.chars.get(position..end) else {
            return Err(self.error("Invalid hex value", position));
        };
        let mut number = Some(0_u32);
        for c in chars {
            if !c.is_ascii_hexdigit() {
                return Err(self.error("Invalid hex value", position));
            }
            let Some(digit) = c.to_digit(16) else {
                return Err(self.error("Invalid hex value", position));
            };
            number = number.and_then(|value| value.checked_mul(16)?.checked_add(digit));
        }
        let c = number
            .and_then(char::from_u32)
            .ok_or_else(|| self.error("Escaped character is not a Unicode scalar value", end))?;
        Ok((end, c.to_string()))
    }
    /// Starts after the opening delimiter (or after the trimmed multiline newline).
    pub fn basic_string(&self, mut pos: usize, multiline: bool) -> Result<(usize, String), Error> {
        let mut result = String::new();
        loop {
            let Some(c) = self.at(pos) else {
                return Err(self.error("Unterminated string", pos));
            };
            if c == '"' {
                if !multiline {
                    return Ok((pos + 1, result));
                }
                if self.at(pos + 1) == Some('"') && self.at(pos + 2) == Some('"') {
                    return Ok((pos + 3, result));
                }
            }
            if c == '\\' {
                let (next, escape) = self.basic_escape(pos, multiline)?;
                result.push_str(&escape);
                pos = next;
                continue;
            }
            if if multiline {
                illegal_multiline(c)
            } else {
                illegal_single(c)
            } {
                return Err(self.error(format!("Illegal character {}", repr(c)), pos));
            }
            result.push(c);
            pos += 1;
        }
    }
}

#[cfg(test)]
#[path = "toml_strings_tests.rs"]
mod tests;

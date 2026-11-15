//! CPython 3.14.7 tomllib keys and multiline delimiters (MIT, Taneli Hukkinen).
use super::{Error, ErrorKind, Source, bare_key, illegal_multiline, repr, whitespace};
/// CPython 3.14.7's default sys.getrecursionlimit(), captured by tomllib at import.
pub const MAX_KEY_PARTS: usize = 1000;
impl Source {
    fn starts(&self, position: usize, text: &str) -> bool {
        self.chars.get(position..).is_some_and(|tail| {
            let mut chars = tail.iter();
            text.chars().all(|c| chars.next() == Some(&c))
        })
    }
    pub fn key_part(&self, position: usize) -> Result<(usize, String), Error> {
        match self.at(position) {
            Some(c) if bare_key(c) => {
                let end = self.skip(position, bare_key);
                Ok((end, self.chars[position..end].iter().collect()))
            }
            Some('\'') => self.literal_string(position),
            Some('"') => self.basic_string(position + 1, false),
            _ => Err(self.error("Invalid initial character for a key part", position)),
        }
    }
    pub fn key(&self, position: usize) -> Result<(usize, Vec<String>), Error> {
        let (mut pos, first) = self.key_part(position)?;
        let mut key = vec![first];
        pos = self.skip(pos, whitespace);
        while self.at(pos) == Some('.') {
            pos = self.skip(pos + 1, whitespace);
            let (end, part) = self.key_part(pos)?;
            pos = end;
            key.push(part);
            if key.len() > MAX_KEY_PARTS {
                let mut error = self.error(
                    format!("TOML key has more than the allowed {MAX_KEY_PARTS} parts"),
                    pos,
                );
                error.kind = ErrorKind::Recursion;
                return Err(error);
            }
            pos = self.skip(pos, whitespace);
        }
        Ok((pos, key))
    }
    pub fn multiline_string(
        &self,
        position: usize,
        literal: bool,
    ) -> Result<(usize, String), Error> {
        let mut pos = position.saturating_add(3);
        if self.at(pos) == Some('\n') {
            pos += 1;
        }
        let delimiter = if literal { '\'' } else { '"' };
        let (mut pos, mut result) = if literal {
            let end = self
                .chars
                .get(pos..)
                .unwrap_or_default()
                .windows(3)
                .position(|chars| chars == ['\'', '\'', '\''])
                .map(|offset| pos + offset)
                .ok_or_else(|| self.error("Expected \"'''\"", self.chars.len()))?;
            if let Some(offset) = self.chars[pos..end]
                .iter()
                .position(|c| illegal_multiline(*c))
            {
                let at = pos + offset;
                return Err(self.error(
                    format!("Found invalid character {}", repr(self.chars[at])),
                    at,
                ));
            }
            (end + 3, self.chars[pos..end].iter().collect::<String>())
        } else {
            self.basic_string(pos, true)?
        };
        for _ in 0..2 {
            if self.at(pos) != Some(delimiter) {
                break;
            }
            result.push(delimiter);
            pos += 1;
        }
        Ok((pos, result))
    }
    /// String branch of parse_value, preserving single versus triple delimiters.
    pub fn string(&self, position: usize) -> Result<(usize, String), Error> {
        match self.at(position) {
            Some('"') if self.starts(position, "\"\"\"") => self.multiline_string(position, false),
            Some('"') => self.basic_string(position + 1, false),
            Some('\'') if self.starts(position, "'''") => self.multiline_string(position, true),
            Some('\'') => self.literal_string(position),
            _ => Err(self.error("Invalid value", position)),
        }
    }
}
#[cfg(test)]
#[path = "toml_keys_tests.rs"]
mod tests;

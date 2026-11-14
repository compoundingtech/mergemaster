//! Prefix scanners for CPython 3.14.7 tomllib RE_NUMBER and special floats.
use super::{Error, ErrorKind, Source, Value};
impl Source {
    fn digits(&self, position: usize, radix: u32) -> Option<usize> {
        let digit = |c: char| c.is_ascii() && c.is_digit(radix);
        if !self.at(position).is_some_and(digit) {
            return None;
        }
        let mut end = position + 1;
        loop {
            if self.at(end).is_some_and(digit) {
                end += 1;
            } else if self.at(end) == Some('_') && self.at(end + 1).is_some_and(digit) {
                end += 2;
            } else {
                return Some(end);
            }
        }
    }
    fn numeric_token(
        &self,
        start: usize,
        end: usize,
        float: bool,
        decimal: bool,
    ) -> Result<Value, Error> {
        if float {
            let token: String = self.chars[start..end]
                .iter()
                .filter(|c| **c != '_')
                .collect();
            return token
                .parse()
                .map(Value::Float)
                .map_err(|_| self.error("Invalid value", start));
        }
        if decimal {
            let digits = self.chars[start..end]
                .iter()
                .filter(|c| c.is_ascii_digit())
                .count();
            if digits > 4300 {
                let mut error = self.error(format!("Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"), start);
                error.kind = ErrorKind::Value;
                return Err(error);
            }
        }
        Ok(Value::Integer(self.chars[start..end].iter().collect()))
    }
    /// Only numeric alternatives; the full parser tries dates and times first.
    pub fn number(&self, position: usize) -> Result<Option<(usize, Value)>, Error> {
        if self.at(position) == Some('0') {
            let radix = match self.at(position + 1) {
                Some('x') => Some(16),
                Some('b') => Some(2),
                Some('o') => Some(8),
                _ => None,
            };
            if let Some(radix) = radix
                && let Some(end) = self.digits(position + 2, radix)
            {
                return Ok(Some((
                    end,
                    self.numeric_token(position, end, false, false)?,
                )));
            }
        }
        let start = position + usize::from(matches!(self.at(position), Some('+' | '-')));
        let integer_end = if self.at(start) == Some('0') {
            Some(start + 1)
        } else {
            self.digits(start, 10)
        };
        if let Some(mut end) = integer_end {
            let mut float = false;
            if self.at(end) == Some('.')
                && let Some(next) = self.digits(end + 1, 10)
            {
                end = next;
                float = true;
            }
            if matches!(self.at(end), Some('e' | 'E')) {
                let start = end + 1 + usize::from(matches!(self.at(end + 1), Some('+' | '-')));
                if let Some(next) = self.digits(start, 10) {
                    end = next;
                    float = true;
                }
            }
            return Ok(Some((end, self.numeric_token(position, end, float, true)?)));
        }
        for token in ["inf", "nan", "-inf", "+inf", "-nan", "+nan"] {
            if self.starts(position, token) {
                let value = if token.ends_with("inf") {
                    f64::INFINITY
                } else {
                    f64::NAN
                };
                return Ok(Some((
                    position + token.len(),
                    Value::Float(if token.starts_with('-') {
                        -value
                    } else {
                        value
                    }),
                )));
            }
        }
        Ok(None)
    }
}
#[cfg(test)]
#[path = "toml_numbers_tests.rs"]
mod tests;

//! Python 3.14.7 `int(text)` at argparse's default decimal digit limit.
use super::{python_digits::decimal, python_repr::Repr, value_inputs::TextRef};
use crate::evidence::legacy_policy::normalized_text::NormalizedText;

/// Unbounded signed integer; magnitude is canonical ASCII decimal, including zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integer {
    pub negative: bool,
    pub digits: String,
}
impl Integer {
    pub fn is_positive(&self) -> bool {
        !self.negative && self.digits != "0"
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerError {
    InvalidLiteral,
    DigitLimit { digits: usize },
}

impl IntegerError {
    /// Argparse wraps either int() ValueError in the same unbounded argument repr.
    pub fn diagnostic(self, value: TextRef<'_>) -> NormalizedText {
        match self {
            Self::InvalidLiteral | Self::DigitLimit { .. } => {
                format!("invalid int value: {}", Repr(value)).into()
            }
        }
    }
}

// ASCII control separators U+001C..U+001F are str.isspace(), but int() rejects
// them: the Unicode-to-ASCII transform deliberately leaves ASCII untouched.
fn whitespace(point: u32) -> bool {
    matches!(point, 9..=13 | 32 | 0x85 | 0xa0 | 0x1680 | 0x2000..=0x200a | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
}

pub fn parse(value: TextRef<'_>) -> Result<Integer, IntegerError> {
    let mut points = value.points().peekable();
    while points.peek().is_some_and(|p| whitespace(*p)) {
        points.next();
    }
    let negative = points.peek() == Some(&45);
    if matches!(points.peek(), Some(43 | 45)) {
        points.next();
    }
    let mut digits = String::new();
    let mut count = 0;
    let mut previous_digit = false;
    while let Some(point) = points.next() {
        if let Some(digit) = decimal(point) {
            count += 1;
            previous_digit = true;
            if count <= 4300 && (digit != 0 || !digits.is_empty()) {
                digits.push(char::from(b'0' + digit));
            }
        } else if point == 95 && previous_digit {
            previous_digit = false;
        } else if whitespace(point) && previous_digit {
            if points.any(|p| !whitespace(p)) {
                return Err(IntegerError::InvalidLiteral);
            }
            break;
        } else {
            return Err(IntegerError::InvalidLiteral);
        }
    }
    if !previous_digit {
        return Err(IntegerError::InvalidLiteral);
    }
    if count > 4300 {
        return Err(IntegerError::DigitLimit { digits: count });
    }
    if digits.is_empty() {
        digits.push('0');
    }
    Ok(Integer {
        negative: negative && digits != "0",
        digits,
    })
}
#[cfg(test)]
#[path = "argparse_int_tests.rs"]
mod tests;

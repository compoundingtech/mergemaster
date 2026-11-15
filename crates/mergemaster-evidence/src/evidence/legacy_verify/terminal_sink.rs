//! Approved terminal/log divergence: escape interpolated values, not structure.
use super::{argparse_usage::RenderedHelp, value_inputs::TextRef};
use std::fmt::{self, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRange,
    InvalidCodepoint,
    UnsafeLiteral,
    Write(fmt::Error),
}
impl From<fmt::Error> for Error {
    fn from(e: fmt::Error) -> Self {
        Self::Write(e)
    }
}
fn escaped(point: u32, out: &mut impl Write) -> Result<(), Error> {
    match point {
        9 => out.write_str("\\t")?,
        10 => out.write_str("\\n")?,
        13 => out.write_str("\\r")?,
        92 => out.write_str("\\\\")?,
        0..=31 | 127..=159 => write!(out, "\\x{point:02x}")?,
        0xd800..=0xdfff => write!(out, "\\u{point:04x}")?,
        _ => out.write_char(char::from_u32(point).ok_or(Error::InvalidCodepoint)?)?,
    }
    Ok(())
}
/// Unbounded Python-repr-style escaping of one value, without repr quotes.
/// Printable text stays exact; every backslash is escaped, even an existing escape.
pub fn value(text: TextRef<'_>, out: &mut impl Write) -> Result<(), Error> {
    for point in text.points() {
        escaped(point, out)?;
    }
    Ok(())
}
impl RenderedHelp {
    /// Write safe terminal/log text while preserving formatter-generated LF.
    /// Publicly constructible invalid provenance returns a typed error, never panics.
    /// Discard partial output on error; the original lossless library text is unchanged.
    pub fn write_terminal(&self, out: &mut impl Write) -> Result<(), Error> {
        let text = self.text.borrowed();
        let length = text.points().count();
        let mut end = 0;
        for range in &self.interpolations {
            if range.start < end || range.start > range.end || range.end > length {
                return Err(Error::InvalidRange);
            }
            end = range.end;
        }
        let mut ranges = self.interpolations.iter().peekable();
        for (at, point) in text.points().enumerate() {
            while ranges.peek().is_some_and(|range| range.end <= at) {
                ranges.next();
            }
            if ranges.peek().is_some_and(|range| range.contains(&at)) {
                escaped(point, out)?;
            } else {
                if matches!(point, 0..=9 | 11..=31 | 127..=159 | 0xd800..=0xdfff) {
                    return Err(Error::UnsafeLiteral);
                }
                out.write_char(char::from_u32(point).ok_or(Error::InvalidCodepoint)?)?;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "terminal_sink_tests.rs"]
mod tests;

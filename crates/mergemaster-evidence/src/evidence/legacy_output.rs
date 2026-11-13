//! Streaming legacy CLI JSON, matching Python `json.dumps(..., indent=2)`.
//! Object order is caller order; codepoints preserve lone surrogates. No final LF
//! is added (the CLI's print operation owns it). This is not an input decoder.
use std::fmt::{self, Write};

/// A single JSON value written without allocating an intermediate JSON tree.
pub struct Writer<'a, W: Write> {
    out: &'a mut W,
    depth: usize,
}
impl<'a, W: Write> Writer<'a, W> {
    pub fn new(out: &'a mut W) -> Self {
        Self { out, depth: 0 }
    }
    pub fn string(&mut self, points: &[u32]) -> fmt::Result {
        super::legacy_json::codepoints(points.iter().copied(), self.out)
    }
    pub fn text(&mut self, text: &str) -> fmt::Result {
        super::legacy_json::string(text, self.out)
    }
    pub fn boolean(&mut self, value: bool) -> fmt::Result {
        self.out.write_str(if value { "true" } else { "false" })
    }
    pub fn null(&mut self) -> fmt::Result {
        self.out.write_str("null")
    }
    /// Output metadata integers; this does not decode or narrow policy inputs.
    pub fn integer(&mut self, value: i128) -> fmt::Result {
        write!(self.out, "{value}")
    }
    pub fn object(
        &mut self,
        fields: impl FnOnce(&mut Object<'_, '_, W>) -> fmt::Result,
    ) -> fmt::Result {
        self.out.write_char('{')?;
        let mut object = Object(Sequence {
            writer: self,
            populated: false,
        });
        fields(&mut object)?;
        object.0.finish('}')
    }
    pub fn array(
        &mut self,
        items: impl FnOnce(&mut Array<'_, '_, W>) -> fmt::Result,
    ) -> fmt::Result {
        self.out.write_char('[')?;
        let mut array = Array(Sequence {
            writer: self,
            populated: false,
        });
        items(&mut array)?;
        array.0.finish(']')
    }
}
struct Sequence<'a, 'b, W: Write> {
    writer: &'a mut Writer<'b, W>,
    populated: bool,
}
impl<W: Write> Sequence<'_, '_, W> {
    fn next(&mut self) -> fmt::Result {
        if self.populated {
            self.writer.out.write_char(',')?;
        }
        self.populated = true;
        writeln!(self.writer.out)?;
        write!(
            self.writer.out,
            "{:width$}",
            "",
            width = (self.writer.depth + 1) * 2
        )
    }
    fn value(&mut self, value: impl FnOnce(&mut Writer<'_, W>) -> fmt::Result) -> fmt::Result {
        value(&mut Writer {
            out: self.writer.out,
            depth: self.writer.depth + 1,
        })
    }
    fn finish(&mut self, end: char) -> fmt::Result {
        if self.populated {
            writeln!(self.writer.out)?;
            write!(
                self.writer.out,
                "{:width$}",
                "",
                width = self.writer.depth * 2
            )?;
        }
        self.writer.out.write_char(end)
    }
}
/// Fields are emitted in insertion order; callers supply unique keys.
pub struct Object<'a, 'b, W: Write>(Sequence<'a, 'b, W>);
impl<W: Write> Object<'_, '_, W> {
    pub fn field(
        &mut self,
        key: &[u32],
        value: impl FnOnce(&mut Writer<'_, W>) -> fmt::Result,
    ) -> fmt::Result {
        self.0.next()?;
        self.0.writer.string(key)?;
        self.0.writer.out.write_str(": ")?;
        self.0.value(value)
    }
    pub fn field_text(
        &mut self,
        key: &str,
        value: impl FnOnce(&mut Writer<'_, W>) -> fmt::Result,
    ) -> fmt::Result {
        self.0.next()?;
        self.0.writer.text(key)?;
        self.0.writer.out.write_str(": ")?;
        self.0.value(value)
    }
}
pub struct Array<'a, 'b, W: Write>(Sequence<'a, 'b, W>);
impl<W: Write> Array<'_, '_, W> {
    pub fn item(&mut self, value: impl FnOnce(&mut Writer<'_, W>) -> fmt::Result) -> fmt::Result {
        self.0.next()?;
        self.0.value(value)
    }
}

#[cfg(test)]
#[path = "legacy_output_tests.rs"]
mod tests;

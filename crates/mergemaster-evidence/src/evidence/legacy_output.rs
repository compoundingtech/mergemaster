//! Streaming legacy CLI JSON matching Python `json.dumps(..., indent=2)`.
//! Object order is caller order; codepoints preserve lone surrogates. No final LF.
use std::{
    fmt::{self, Write},
    marker::PhantomData,
};

/// Proof of exactly one value, scoped to its writer; cannot be forged or reused.
pub struct Written<'scope>(PhantomData<fn(&'scope mut ()) -> &'scope mut ()>);
/// A consuming capability for one JSON value, not an input decoder.
pub struct ValueWriter<'scope, 'out, W: Write> {
    out: &'out mut W,
    depth: usize,
    scope: PhantomData<Written<'scope>>,
}
/// Write exactly one root value. Discard partial output on error.
/// ```compile_fail
/// use mergemaster_evidence::evidence::legacy_output::write;
/// write(&mut String::new(), |_| Ok(())); // no value
/// ```
/// ```compile_fail
/// use mergemaster_evidence::evidence::legacy_output::write;
/// write(&mut String::new(), |w| { w.null()?; w.null() }); // consumed
/// ```
/// ```compile_fail
/// use mergemaster_evidence::evidence::legacy_output::write;
/// write(&mut String::new(), |w| { let token = w.null()?;
///     write(&mut String::new(), |_| Ok(token))?; Err(std::fmt::Error) }); // foreign scope
/// ```
pub fn write<W: Write>(
    out: &mut W,
    value: impl for<'s> FnOnce(ValueWriter<'s, '_, W>) -> Result<Written<'s>, fmt::Error>,
) -> fmt::Result {
    value(ValueWriter {
        out,
        depth: 0,
        scope: PhantomData,
    })
    .map(|_| ())
}
impl<'s, W: Write> ValueWriter<'s, '_, W> {
    fn done(self) -> Written<'s> {
        Written(PhantomData)
    }
    pub fn string(self, points: &[u32]) -> Result<Written<'s>, fmt::Error> {
        self.codepoints(points.iter().copied())
    }
    /// Stream composed Python text without allocating a concatenated string.
    pub fn codepoints(
        self,
        points: impl IntoIterator<Item = u32>,
    ) -> Result<Written<'s>, fmt::Error> {
        super::legacy_json::codepoints(points, self.out)?;
        Ok(self.done())
    }
    pub fn text(self, text: &str) -> Result<Written<'s>, fmt::Error> {
        super::legacy_json::string(text, self.out)?;
        Ok(self.done())
    }
    pub fn boolean(self, value: bool) -> Result<Written<'s>, fmt::Error> {
        self.out.write_str(if value { "true" } else { "false" })?;
        Ok(self.done())
    }
    pub fn null(self) -> Result<Written<'s>, fmt::Error> {
        self.out.write_str("null")?;
        Ok(self.done())
    }
    /// Output metadata integers; does not decode or narrow policy inputs.
    pub fn integer(self, value: i128) -> Result<Written<'s>, fmt::Error> {
        write!(self.out, "{value}")?;
        Ok(self.done())
    }
    pub fn object(
        self,
        fields: impl FnOnce(&mut Object<'_, W>) -> fmt::Result,
    ) -> Result<Written<'s>, fmt::Error> {
        self.out.write_char('{')?;
        let mut object = Object(Sequence {
            out: &mut *self.out,
            depth: self.depth,
            populated: false,
            pending: false,
        });
        fields(&mut object)?;
        object.0.finish('}')?;
        Ok(self.done())
    }
    pub fn array(
        self,
        items: impl FnOnce(&mut Array<'_, W>) -> fmt::Result,
    ) -> Result<Written<'s>, fmt::Error> {
        self.out.write_char('[')?;
        let mut array = Array(Sequence {
            out: &mut *self.out,
            depth: self.depth,
            populated: false,
            pending: false,
        });
        items(&mut array)?;
        array.0.finish(']')?;
        Ok(self.done())
    }
}
struct Sequence<'out, W: Write> {
    out: &'out mut W,
    depth: usize,
    populated: bool,
    pending: bool,
}
impl<W: Write> Sequence<'_, W> {
    fn next(&mut self) -> fmt::Result {
        if std::mem::replace(&mut self.pending, true) {
            return Err(fmt::Error);
        }
        if self.populated {
            self.out.write_char(',')?;
        }
        self.populated = true;
        writeln!(self.out)?;
        write!(self.out, "{:width$}", "", width = (self.depth + 1) * 2)
    }
    fn value(
        &mut self,
        value: impl for<'s> FnOnce(ValueWriter<'s, '_, W>) -> Result<Written<'s>, fmt::Error>,
    ) -> fmt::Result {
        value(ValueWriter {
            out: self.out,
            depth: self.depth + 1,
            scope: PhantomData,
        })?;
        self.pending = false;
        Ok(())
    }
    fn finish(&mut self, end: char) -> fmt::Result {
        if self.pending {
            return Err(fmt::Error);
        }
        if self.populated {
            writeln!(self.out)?;
            write!(self.out, "{:width$}", "", width = self.depth * 2)?;
        }
        self.out.write_char(end)
    }
}
/// Fields are emitted in insertion order; callers supply unique keys.
pub struct Object<'out, W: Write>(Sequence<'out, W>);
impl<W: Write> Object<'_, W> {
    pub fn field(
        &mut self,
        key: &[u32],
        value: impl for<'s> FnOnce(ValueWriter<'s, '_, W>) -> Result<Written<'s>, fmt::Error>,
    ) -> fmt::Result {
        self.0.next()?;
        super::legacy_json::codepoints(key.iter().copied(), self.0.out)?;
        self.0.out.write_str(": ")?;
        self.0.value(value)
    }
    pub fn field_text(
        &mut self,
        key: &str,
        value: impl for<'s> FnOnce(ValueWriter<'s, '_, W>) -> Result<Written<'s>, fmt::Error>,
    ) -> fmt::Result {
        self.0.next()?;
        super::legacy_json::string(key, self.0.out)?;
        self.0.out.write_str(": ")?;
        self.0.value(value)
    }
}
pub struct Array<'out, W: Write>(Sequence<'out, W>);
impl<W: Write> Array<'_, W> {
    pub fn item(
        &mut self,
        value: impl for<'s> FnOnce(ValueWriter<'s, '_, W>) -> Result<Written<'s>, fmt::Error>,
    ) -> fmt::Result {
        self.0.next()?;
        self.0.value(value)
    }
}
#[cfg(test)]
#[path = "legacy_output_tests.rs"]
mod tests;

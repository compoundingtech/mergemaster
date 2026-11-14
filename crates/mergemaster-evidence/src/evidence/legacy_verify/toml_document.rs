use super::{
    Error, Source, Table, Value, bare_key,
    containers::KeyRepr,
    nested::NestedDict,
    tables::{Flag, Flags},
    whitespace,
};

/// CPython tomllib grammar with iterative, resource-bounded-by-memory values.
pub fn parse(text: &str) -> Result<Table, Error> {
    let source = Source::new(text);
    let mut out = NestedDict::default();
    let mut flags = Flags::default();
    let mut header = Vec::new();
    let mut pos = 0;
    loop {
        pos = source.skip(pos, whitespace);
        match source.at(pos) {
            None => return Ok(out.data),
            Some('\n') => {
                pos += 1;
                continue;
            }
            Some(c) if bare_key(c) || matches!(c, '\'' | '"') => {
                pos = source.assignment(pos, &mut out, &mut flags, &header)?;
                pos = source.skip(pos, whitespace);
            }
            Some('[') => {
                flags.finalize_pending();
                (pos, header) = source.header(pos, &mut out, &mut flags)?;
                pos = source.skip(pos, whitespace);
            }
            Some('#') => {}
            _ => return Err(source.error("Invalid statement", pos)),
        }
        pos = source.skip_comment(pos)?;
        match source.at(pos) {
            None => return Ok(out.data),
            Some('\n') => pos += 1,
            _ => {
                return Err(
                    source.error("Expected newline or end of document after a statement", pos)
                );
            }
        }
    }
}
impl Source {
    fn header(
        &self,
        position: usize,
        out: &mut NestedDict,
        flags: &mut Flags,
    ) -> Result<(usize, Vec<String>), Error> {
        let array = self.at(position + 1) == Some('[');
        let width = if array { 2 } else { 1 };
        let (pos, key) = self.key(self.skip(position + width, whitespace))?;
        if array {
            if flags.is(&key, Flag::Frozen) {
                return Err(self.error(
                    format!("Cannot mutate immutable namespace {}", KeyRepr(&key)),
                    pos,
                ));
            }
            flags.unset_all(&key);
            flags.set(&key, Flag::ExplicitNest, false);
            out.append_nest(&key)
                .ok_or_else(|| self.error("Cannot overwrite a value", pos))?;
        } else {
            if flags.is(&key, Flag::ExplicitNest) || flags.is(&key, Flag::Frozen) {
                return Err(self.error(format!("Cannot declare {} twice", KeyRepr(&key)), pos));
            }
            flags.set(&key, Flag::ExplicitNest, false);
            out.nest(&key, true)
                .ok_or_else(|| self.error("Cannot overwrite a value", pos))?;
        }
        let close = if array { "]]" } else { "]" };
        if !self.starts(pos, close) {
            let message = if array {
                "Expected ']]' at the end of an array declaration"
            } else {
                "Expected ']' at the end of a table declaration"
            };
            return Err(self.error(message, pos));
        }
        Ok((pos + width, key))
    }
    fn assignment(
        &self,
        position: usize,
        out: &mut NestedDict,
        flags: &mut Flags,
        header: &[String],
    ) -> Result<usize, Error> {
        let (start, key) = self.pair_start(position)?;
        let (pos, value) = self.value(start)?;
        let mut absolute = Vec::with_capacity(header.len() + key.len());
        absolute.extend_from_slice(header);
        absolute.extend(key);
        let parent_len = absolute.len().saturating_sub(1);
        for length in header.len() + 1..=parent_len {
            let prefix = &absolute[..length];
            if flags.is(prefix, Flag::ExplicitNest) {
                return Err(self.error(
                    format!("Cannot redefine namespace {}", KeyRepr(prefix)),
                    pos,
                ));
            }
            flags.add_pending(prefix, Flag::ExplicitNest);
        }
        let parent = &absolute[..parent_len];
        if flags.is(parent, Flag::Frozen) {
            return Err(self.error(
                format!("Cannot mutate immutable namespace {}", KeyRepr(parent)),
                pos,
            ));
        }
        let nest = out
            .nest(parent, true)
            .ok_or_else(|| self.error("Cannot overwrite a value", pos))?;
        if absolute.last().is_some_and(|stem| nest.contains_key(stem)) {
            return Err(self.error("Cannot overwrite a value", pos));
        }
        if matches!(value, Value::Array(_) | Value::Table(_)) {
            flags.set(&absolute, Flag::Frozen, true);
        }
        if let Some(stem) = absolute.pop() {
            nest.insert(stem, value);
        }
        Ok(pos)
    }
}

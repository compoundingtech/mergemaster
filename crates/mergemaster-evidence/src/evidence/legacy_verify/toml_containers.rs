//! Array and inline-table nesting is iterative and unbounded (subject to memory).
//! Approved, labelled resource-dependent divergence: CPython 3.14.7 tomllib raises
//! RecursionError at nesting depths that depend on the interpreter stack; Rust
//! does not emulate a fixed recursion boundary. MAX_KEY_PARTS=1000 remains exact
//! (see toml_keys.rs) and is not part of this divergence.
use super::{
    Error, Repr, Source, TextRef, Value,
    nested::NestedDict,
    tables::{Flag, Flags},
    whitespace,
};
use std::fmt;

pub(super) struct KeyRepr<'a>(pub &'a [String]);
impl fmt::Display for KeyRepr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(")?;
        for (i, part) in self.0.iter().enumerate() {
            if i != 0 {
                f.write_str(", ")?;
            }
            write!(f, "{}", Repr(TextRef::Str(part)))?;
        }
        if self.0.len() == 1 {
            f.write_str(",")?;
        }
        f.write_str(")")
    }
}

enum Frame {
    Array(Vec<Value>),
    Inline {
        out: NestedDict,
        flags: Flags,
        key: Vec<String>,
    },
}
impl Source {
    pub(super) fn pair_start(&self, position: usize) -> Result<(usize, Vec<String>), Error> {
        let (pos, key) = self.key(position)?;
        if self.at(pos) != Some('=') {
            return Err(self.error("Expected '=' after a key in a key/value pair", pos));
        }
        Ok((self.skip(pos + 1, whitespace), key))
    }
    /// Parses all TOML values with an explicit container stack.
    pub fn value(&self, position: usize) -> Result<(usize, Value), Error> {
        let mut pos = position;
        let mut stack = Vec::new();
        loop {
            let mut value = match self.at(pos) {
                Some('\'' | '"') => {
                    let (end, text) = self.string(pos)?;
                    pos = end;
                    Value::String(text)
                }
                Some('[') => {
                    pos = self.skip_array_ws(pos + 1)?;
                    if self.at(pos) != Some(']') {
                        stack.push(Frame::Array(Vec::new()));
                        continue;
                    }
                    pos += 1;
                    Value::Array(Vec::new())
                }
                Some('{') => {
                    pos = self.skip(pos + 1, whitespace);
                    if self.at(pos) != Some('}') {
                        let (end, key) = self.pair_start(pos)?;
                        pos = end;
                        stack.push(Frame::Inline {
                            out: NestedDict::default(),
                            flags: Flags::default(),
                            key,
                        });
                        continue;
                    }
                    pos += 1;
                    Value::Table(Default::default())
                }
                _ => {
                    if self.starts(pos, "true") {
                        pos += 4;
                        Value::Bool(true)
                    } else if self.starts(pos, "false") {
                        pos += 5;
                        Value::Bool(false)
                    } else if let Some((end, value)) = self.temporal(pos)? {
                        pos = end;
                        value
                    } else if let Some((end, value)) = self.number(pos)? {
                        pos = end;
                        value
                    } else {
                        return Err(self.error("Invalid value", pos));
                    }
                }
            };
            loop {
                let Some(frame) = stack.pop() else {
                    return Ok((pos, value));
                };
                match frame {
                    Frame::Array(mut items) => {
                        items.push(value);
                        pos = self.skip_array_ws(pos)?;
                        if self.at(pos) == Some(']') {
                            pos += 1;
                            value = Value::Array(items);
                            continue;
                        }
                        if self.at(pos) != Some(',') {
                            return Err(self.error("Unclosed array", pos));
                        }
                        pos = self.skip_array_ws(pos + 1)?;
                        if self.at(pos) == Some(']') {
                            pos += 1;
                            value = Value::Array(items);
                            continue;
                        }
                        stack.push(Frame::Array(items));
                        break;
                    }
                    Frame::Inline {
                        mut out,
                        mut flags,
                        mut key,
                    } => {
                        if flags.is(&key, Flag::Frozen) {
                            return Err(self.error(
                                format!("Cannot mutate immutable namespace {}", KeyRepr(&key)),
                                pos,
                            ));
                        }
                        // Source::key always returns a nonempty key; split at its final part.
                        let parent_len = key.len().saturating_sub(1);
                        let nest = out
                            .nest(&key[..parent_len], false)
                            .ok_or_else(|| self.error("Cannot overwrite a value", pos))?;
                        if let Some(stem) = key.last()
                            && nest.contains_key(stem)
                        {
                            return Err(self.error(
                                format!("Duplicate inline table key {}", Repr(TextRef::Str(stem))),
                                pos,
                            ));
                        }
                        let next = self.skip(pos, whitespace);
                        if self.at(next) == Some(',')
                            && matches!(value, Value::Array(_) | Value::Table(_))
                        {
                            flags.set(&key, Flag::Frozen, true);
                        }
                        if let Some(stem) = key.pop() {
                            nest.insert(stem, value);
                        }
                        pos = next;
                        if self.at(pos) == Some('}') {
                            pos += 1;
                            value = Value::Table(out.data);
                            continue;
                        }
                        if self.at(pos) != Some(',') {
                            return Err(self.error("Unclosed inline table", pos));
                        }
                        let (end, key) = self.pair_start(self.skip(pos + 1, whitespace))?;
                        pos = end;
                        stack.push(Frame::Inline { out, flags, key });
                        break;
                    }
                }
            }
        }
    }
}

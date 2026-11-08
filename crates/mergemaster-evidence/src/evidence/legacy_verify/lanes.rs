//! Legacy lane declarations and definition bytes; no Git reads or native hashing.
use crate::evidence::legacy_policy::{PolicyError, declared_paths, selected_entry};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::{self, Write};

#[derive(Debug, Serialize)]
pub struct LaneRules {
    pub argv: Vec<String>,
    pub definition_paths: Vec<String>,
    pub tree_inputs: Vec<String>,
    pub absent_paths: Vec<String>,
    pub ci_inputs: Option<Vec<String>>,
}
impl LaneRules {
    pub fn parse(text: &str, lane: &str) -> Result<Self, PolicyError> {
        let error = || PolicyError {
            reason: "error",
            detail: format!("invalid lane {lane}"),
        };
        let entry = selected_entry(text, lane, "lanes")?.ok_or_else(|| PolicyError {
            reason: "no_lane",
            detail: format!("lane {lane} is absent"),
        })?;
        let Value::Object(mut entry) = entry else {
            return Err(error());
        };
        if entry.keys().any(|k| {
            ![
                "argv",
                "definition_paths",
                "tree_inputs",
                "absent_paths",
                "ci_inputs",
            ]
            .contains(&k.as_str())
        }) {
            return Err(error());
        }
        let argv: Vec<String> =
            serde_json::from_value(entry.remove("argv").ok_or_else(error)?).map_err(|_| error())?;
        if argv.is_empty() || argv.iter().any(String::is_empty) {
            return Err(error());
        }
        let paths = |key: &str, optional: bool| -> Result<Vec<String>, PolicyError> {
            let Some(value) = entry.get(key) else {
                return if optional {
                    Ok(Vec::new())
                } else {
                    Err(error())
                };
            };
            if optional
                && (matches!(value, Value::String(s) if s.is_empty())
                    || matches!(value, Value::Object(m) if m.is_empty())
                    || matches!(value, Value::Array(a) if a.is_empty()))
            {
                return Ok(Vec::new());
            }
            let paths = declared_paths(value, lane, false)?;
            if key != "tree_inputs" && paths.iter().any(|p| p == ".") {
                return Err(error());
            }
            Ok(paths)
        };
        Ok(Self {
            argv,
            definition_paths: paths("definition_paths", false)?,
            tree_inputs: paths("tree_inputs", true)?,
            absent_paths: paths("absent_paths", true)?,
            ci_inputs: entry
                .get("ci_inputs")
                .filter(|v| !v.is_null())
                .map(|v| declared_paths(v, lane, true))
                .transpose()?,
        })
    }
}

#[derive(Deserialize)]
pub struct DefinitionEntry {
    pub mode: String,
    pub oid: String,
    pub path: Vec<u8>,
}
fn codepoints(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes.utf8_chunks().flat_map(|part| {
        part.valid()
            .chars()
            .map(u32::from)
            .chain(part.invalid().iter().map(|b| 0xdc00 + u32::from(*b)))
    })
}
pub(super) fn string(value: &str, out: &mut impl Write) -> fmt::Result {
    out.write_char('"')?;
    for ch in value.chars() {
        match ch {
            '"' => out.write_str("\\\"")?,
            '\\' => out.write_str("\\\\")?,
            '\x08' => out.write_str("\\b")?,
            '\x0c' => out.write_str("\\f")?,
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_str("\\t")?,
            ' '..='~' => out.write_char(ch)?,
            _ => {
                for unit in ch.encode_utf16(&mut [0; 2]) {
                    write!(out, "\\u{unit:04x}")?;
                }
            }
        }
    }
    out.write_char('"')
}
fn strings(values: &[String], out: &mut impl Write) -> fmt::Result {
    out.write_char('[')?;
    for (i, value) in values.iter().enumerate() {
        if i != 0 {
            out.write_str(", ")?;
        }
        string(value, out)?;
    }
    out.write_char(']')
}
/// Sort in place, as Python sorts surrogateescaped names; emit the exact preimage.
pub fn definition_bytes(
    entries: &mut [DefinitionEntry],
    argv: &[String],
    absent: &mut [String],
    mut emit: impl FnMut(&[u8]),
) {
    struct Sink<'a, F>(&'a mut F);
    impl<F: FnMut(&[u8])> Write for Sink<'_, F> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.0(s.as_bytes());
            Ok(())
        }
    }
    entries.sort_unstable_by(|a, b| codepoints(&a.path).cmp(codepoints(&b.path)));
    for entry in entries {
        for part in [
            entry.mode.as_bytes(),
            b" ",
            entry.oid.as_bytes(),
            b" ",
            &entry.path,
            b"\n",
        ] {
            emit(part);
        }
    }
    emit(b"argv:");
    strings(argv, &mut Sink(&mut emit)).expect("infallible byte sink");
    if !absent.is_empty() {
        absent.sort_unstable();
        emit(b"\nabsent:");
        strings(absent, &mut Sink(&mut emit)).expect("infallible byte sink");
    }
}
pub fn definition_digest(
    entries: &mut [DefinitionEntry],
    argv: &[String],
    absent: &mut [String],
) -> String {
    let mut hash = Sha256::new();
    definition_bytes(entries, argv, absent, |bytes| hash.update(bytes));
    hex::encode(hash.finalize())
}

#[cfg(test)]
#[path = "lanes_tests.rs"]
mod tests;

//! Legacy lane declarations and definition bytes; no Git reads or native hashing.
use super::failure_json::TextRef;
use crate::evidence::legacy_json::string;
use crate::evidence::legacy_policy::{
    PolicyError, check_names::CheckName, declared_paths, normalized_text::NormalizedText,
};
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
    pub fn parse<'a>(text: &str, lane: impl Into<CheckName<'a>>) -> Result<Self, PolicyError> {
        let lane = lane.into();
        let error = |suffix: &str| PolicyError {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "error",
            detail: NormalizedText::around("lane ", lane.text(), suffix),
        };
        let shape = || error(" needs argv and definition_paths, and nothing unknown");
        let entry = lane.entry(text, "lanes")?.ok_or_else(|| PolicyError {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "no_lane",
            detail: NormalizedText::around("the lane file has no entry for ", lane.text(), ""),
        })?;
        let Value::Object(mut entry) = entry else {
            return Err(shape());
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
        }) || !entry.contains_key("argv")
            || !entry.contains_key("definition_paths")
        {
            return Err(shape());
        }
        let argv_error = || error(": argv must be a nonempty list of strings");
        let argv: Vec<String> = serde_json::from_value(entry.remove("argv").ok_or_else(shape)?)
            .map_err(|_| argv_error())?;
        if argv.is_empty() || argv.iter().any(String::is_empty) {
            return Err(argv_error());
        }
        let paths = |key: &str, optional: bool| -> Result<Vec<String>, PolicyError> {
            let Some(value) = entry.get(key) else {
                return if optional {
                    Ok(Vec::new())
                } else {
                    Err(shape())
                };
            };
            if optional
                && (matches!(value, Value::String(s) if s.is_empty())
                    || matches!(value, Value::Object(m) if m.is_empty())
                    || matches!(value, Value::Array(a) if a.is_empty()))
            {
                return Ok(Vec::new());
            }
            let paths = declared_paths(
                value,
                &[
                    TextRef::Str("lane "),
                    lane.text(),
                    TextRef::Str(" "),
                    TextRef::Str(key),
                ],
                false,
            )?;
            if key != "tree_inputs" && paths.iter().any(|p| p == ".") {
                return Err(error(&format!(
                    ": {key} must name files or directories, not the whole tree"
                )));
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
                .map(|v| {
                    declared_paths(
                        v,
                        &[
                            TextRef::Str("lane "),
                            lane.text(),
                            TextRef::Str(" ci_inputs"),
                        ],
                        true,
                    )
                })
                .transpose()?,
        })
    }
}

#[derive(Deserialize, PartialEq, Eq)]
pub struct DefinitionEntry {
    pub mode: String,
    pub oid: String,
    pub path: Vec<u8>,
}
impl Ord for DefinitionEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.mode
            .cmp(&other.mode)
            .then_with(|| self.oid.cmp(&other.oid))
            .then_with(|| codepoints(&self.path).cmp(codepoints(&other.path)))
    }
}
impl PartialOrd for DefinitionEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
pub(super) fn codepoints(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes.utf8_chunks().flat_map(|part| {
        part.valid()
            .chars()
            .map(u32::from)
            .chain(part.invalid().iter().map(|b| 0xdc00 + u32::from(*b)))
    })
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

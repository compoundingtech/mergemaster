//! Local JSON values retain number lexemes without enabling serde_json extension features.
use super::{legacy_policy::check_names::CheckKey, legacy_verify::value_inputs::TextRef};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    fmt::{self, Write},
    ops::Index,
};

#[derive(Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}
impl Value {
    pub fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_number(&self) -> Option<&str> {
        if let Self::Number(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Self>> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        if let Self::Object(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn is_string(&self) -> bool {
        self.as_str().is_some()
    }
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_object()?.get(key)
    }
}
impl Index<&str> for Value {
    type Output = Self;
    fn index(&self, key: &str) -> &Self {
        static NULL: Value = Value::Null;
        self.get(key).unwrap_or(&NULL)
    }
}
impl PartialEq<&str> for Value {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Some(*other)
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    // IgnoredAny checks JSON grammar without converting numbers to bounded machine types.
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes)?;
    Scanner { bytes, position: 0 }.value(0)
}
// serde's byte-string decoder preserves surrogates but permits raw controls.
pub(super) fn strict_strings(text: &str) -> bool {
    let (mut quoted, mut escaped) = (false, false);
    for byte in text.bytes() {
        if quoted && byte < 0x20 {
            return false;
        }
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        }
    }
    true
}
/// Select only the two outer lane-name maps losslessly; values use the same scanner.
pub(super) fn selected_lane(text: &str, lane: TextRef<'_>) -> Result<Option<Value>> {
    ensure!(strict_strings(text), "unescaped JSON control");
    serde_json::from_str::<serde::de::IgnoredAny>(text)?;
    Scanner {
        bytes: text.as_bytes(),
        position: 0,
    }
    .lane_member(lane, true)
}
struct Scanner<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Scanner<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(|c| b" \t\r\n".contains(c))
        {
            self.position += 1;
        }
    }
    fn string_bytes(&mut self) -> &[u8] {
        let start = self.position;
        self.position += 1;
        loop {
            match self.bytes[self.position] {
                b'"' => {
                    self.position += 1;
                    break;
                }
                b'\\' => self.position += 2,
                _ => self.position += 1,
            }
        }
        &self.bytes[start..self.position]
    }
    fn string(&mut self) -> Result<String> {
        serde_json::from_slice(self.string_bytes()).context("JSON string")
    }
    fn lane_member(&mut self, lane: TextRef<'_>, outer: bool) -> Result<Option<Value>> {
        self.whitespace();
        let depth = usize::from(!outer);
        if self.bytes[self.position] != b'{' {
            self.value(depth)?;
            return Ok(None);
        }
        self.position += 1;
        self.whitespace();
        let mut selected = None;
        while self.bytes[self.position] != b'}' {
            let CheckKey(key) = serde_json::from_slice(self.string_bytes())?;
            self.whitespace();
            self.position += 1; // Colon, already validated by IgnoredAny.
            let matches = if outer {
                key.iter().copied().eq("lanes".chars().map(u32::from))
            } else {
                key.iter().copied().eq(lane.points())
            };
            if matches {
                selected = if outer {
                    self.lane_member(lane, false)?
                } else {
                    Some(self.value(depth + 1)?)
                };
            } else {
                self.value(depth + 1)?;
            }
            self.whitespace();
            if self.bytes[self.position] != b',' {
                break;
            }
            self.position += 1;
            self.whitespace();
        }
        self.position += 1;
        Ok(selected)
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        ensure!(depth < 128, "JSON nesting limit");
        self.whitespace();
        Ok(
            match self
                .bytes
                .get(self.position)
                .context("missing JSON value")?
            {
                b'n' => {
                    self.position += 4;
                    Value::Null
                }
                b't' => {
                    self.position += 4;
                    Value::Bool(true)
                }
                b'f' => {
                    self.position += 5;
                    Value::Bool(false)
                }
                b'"' => Value::String(self.string()?),
                b'[' => {
                    self.position += 1;
                    self.whitespace();
                    let mut values = Vec::new();
                    while self.bytes[self.position] != b']' {
                        values.push(self.value(depth + 1)?);
                        self.whitespace();
                        if self.bytes[self.position] != b',' {
                            break;
                        }
                        self.position += 1;
                    }
                    self.position += 1;
                    Value::Array(values)
                }
                b'{' => {
                    self.position += 1;
                    self.whitespace();
                    let mut values = BTreeMap::new();
                    while self.bytes[self.position] != b'}' {
                        let key = self.string()?;
                        self.whitespace();
                        self.position += 1; // Colon, already checked by IgnoredAny.
                        values.insert(key, self.value(depth + 1)?);
                        self.whitespace();
                        if self.bytes[self.position] != b',' {
                            break;
                        }
                        self.position += 1;
                        self.whitespace();
                    }
                    self.position += 1;
                    Value::Object(values)
                }
                b'-' | b'0'..=b'9' => {
                    let start = self.position;
                    while self
                        .bytes
                        .get(self.position)
                        .is_some_and(|c| b"0123456789.eE+-".contains(c))
                    {
                        self.position += 1;
                    }
                    Value::Number(
                        std::str::from_utf8(&self.bytes[start..self.position])?.to_owned(),
                    )
                }
                _ => bail!("unexpected JSON token"),
            },
        )
    }
}
pub(super) fn extension_syntax(text: &str) -> bool {
    let bytes = text.as_bytes();
    let (mut i, mut quoted, mut escaped) = (0, false, false);
    let mut probe = Vec::with_capacity(bytes.len());
    while i < bytes.len() {
        let token = ["-Infinity", "Infinity", "NaN"]
            .into_iter()
            .find(|t| !quoted && bytes[i..].starts_with(t.as_bytes()));
        if let Some(token) = token {
            probe.extend_from_slice(b"null");
            i += token.len();
            continue;
        }
        let b = bytes[i];
        probe.push(b);
        if escaped {
            escaped = false;
        } else if quoted && b == b'\\' {
            escaped = true;
        } else if b == b'"' {
            quoted = !quoted;
        }
        i += 1;
    }
    serde_json::from_slice::<serde::de::IgnoredAny>(&probe).is_ok()
}
pub(super) fn limits(text: &str) -> (usize, bool) {
    let bytes = text.as_bytes();
    let (mut i, mut quoted, mut depth, mut maximum, mut long_integer) =
        (0, false, 0usize, 0, false);
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if quoted => {
                i += 2;
                continue;
            }
            b'"' => quoted = !quoted,
            b'[' | b'{' if !quoted => {
                depth += 1;
                maximum = maximum.max(depth);
            }
            b']' | b'}' if !quoted => depth = depth.saturating_sub(1),
            b'-' | b'0'..=b'9' if !quoted => {
                let start = i;
                while i < bytes.len() && b"0123456789.eE+-".contains(&bytes[i]) {
                    i += 1;
                }
                let number = &text[start..i];
                long_integer |= !number.contains(['.', 'e', 'E'])
                    && number.trim_start_matches('-').len() > 4300;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    (maximum, long_integer)
}
pub(super) fn has_float(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.contains(['.', 'e', 'E']),
        Value::Array(a) => a.iter().any(has_float),
        Value::Object(m) => m.values().any(has_float),
        _ => false,
    }
}
/// Encode guarded values whose number lexemes are integers, with Python ASCII JSON.
pub(super) fn encode_integer(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(if n == "-0" { "0" } else { n }),
        Value::String(s) => string(s, out).expect("infallible string sink"),
        Value::Array(a) => {
            out.push('[');
            for (i, value) in a.iter().enumerate() {
                if i != 0 {
                    out.push(',');
                }
                encode_integer(value, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (key, value)) in m.iter().enumerate() {
                if i != 0 {
                    out.push(',');
                }
                string(key, out).expect("infallible string sink");
                out.push(':');
                encode_integer(value, out);
            }
            out.push('}');
        }
    }
}
pub(super) fn string(value: &str, out: &mut impl Write) -> fmt::Result {
    codepoints(value.chars().map(u32::from), out)
}

/// Python ensure_ascii escaping, including lone surrogates; no input decoding.
/// Scalar string callers retain their existing encoding and sink-error behavior.
pub(super) fn codepoints(
    value: impl IntoIterator<Item = u32>,
    out: &mut impl Write,
) -> fmt::Result {
    out.write_char('"')?;
    for point in value {
        match point {
            0x22 => out.write_str("\\\"")?,
            0x5c => out.write_str("\\\\")?,
            8 => out.write_str("\\b")?,
            12 => out.write_str("\\f")?,
            10 => out.write_str("\\n")?,
            13 => out.write_str("\\r")?,
            9 => out.write_str("\\t")?,
            0x20..=0x7e => out.write_char(char::from_u32(point).ok_or(fmt::Error)?)?,
            0..=0xffff => write!(out, "\\u{point:04x}")?,
            0x10000..=0x10ffff => {
                let offset = point - 0x10000;
                write!(
                    out,
                    "\\u{:04x}\\u{:04x}",
                    0xd800 + (offset >> 10),
                    0xdc00 + (offset & 0x3ff)
                )?;
            }
            _ => return Err(fmt::Error),
        }
    }
    out.write_char('"')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codepoint_encoder_matches_pinned_python_bytes() {
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle");
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                r"
import runpy,sys
json=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')['json']
print(json.dumps(''.join(map(chr,range(0x110000)))))
print(json.dumps(''.join(chr(p) for p in range(0x110000) if not 0xd800<=p<=0xdfff)))
",
                &root,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut actual = String::new();
        codepoints(0..=0x10ffff, &mut actual).unwrap();
        actual.push('\n');
        let scalars: String = (0..=0x10ffff).filter_map(char::from_u32).collect();
        string(&scalars, &mut actual).unwrap();
        actual.push('\n');
        assert_eq!(actual.as_bytes(), output.stdout);
        assert!(codepoints([0x110000], &mut String::new()).is_err());
        struct Refuse;
        impl Write for Refuse {
            fn write_str(&mut self, _: &str) -> fmt::Result {
                Err(fmt::Error)
            }
        }
        assert!(string("scalar", &mut Refuse).is_err());
        assert!(codepoints([0xd800], &mut Refuse).is_err());
    }

    #[test]
    fn ordinary_json_objects_remain_objects_in_both_parsers() {
        for key in [
            "$serde_json::private::Number",
            "$serde_json::private::RawValue",
            r"\u0024serde_json::private::RawValue",
        ] {
            let bytes = format!(r#"{{"value":{{"{key}":"0"}}}}"#);
            let ordinary: serde_json::Value = serde_json::from_str(&bytes).unwrap();
            assert!(
                ordinary["value"].is_object(),
                "crate-wide features changed {key}"
            );
            assert!(
                parse(bytes.as_bytes()).unwrap()["value"]
                    .as_object()
                    .is_some()
            );
        }
    }

    #[test]
    fn scanner_preserves_numbers_duplicates_and_standard_json_refusals() {
        let value = parse(
            br#"{"n":1,"n":1234567890123456789012345678901234567890,"a":[-0,1e1000],"s":"x\"y"}"#,
        )
        .unwrap();
        assert_eq!(
            value["n"].as_number(),
            Some("1234567890123456789012345678901234567890")
        );
        assert_eq!(value["a"].as_array().unwrap()[0].as_number(), Some("-0"));
        assert_eq!(
            value["a"].as_array().unwrap()[1].as_number(),
            Some("1e1000")
        );
        assert_eq!(value["s"].as_str(), Some("x\"y"));
        for invalid in [
            "",
            "[1,]",
            "{\"a\":}",
            "\"unterminated",
            "01",
            "[true false]",
        ] {
            assert!(parse(invalid.as_bytes()).is_err(), "{invalid}");
        }
    }
}

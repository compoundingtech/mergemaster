//! Local JSON values retain number lexemes without enabling serde_json extension features.
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeMap, ops::Index};

#[derive(Debug)]
pub enum Value {
    Null, Bool(bool), Number(String), String(String), Array(Vec<Value>), Object(BTreeMap<String, Value>),
}
impl Value {
    pub fn as_str(&self) -> Option<&str> { if let Self::String(s) = self { Some(s) } else { None } }
    pub fn as_number(&self) -> Option<&str> { if let Self::Number(s) = self { Some(s) } else { None } }
    pub fn as_array(&self) -> Option<&Vec<Self>> { if let Self::Array(v) = self { Some(v) } else { None } }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Self>> { if let Self::Object(v) = self { Some(v) } else { None } }
    pub fn is_string(&self) -> bool { self.as_str().is_some() }
    pub fn get(&self, key: &str) -> Option<&Self> { self.as_object()?.get(key) }
}
impl Index<&str> for Value {
    type Output = Self;
    fn index(&self, key: &str) -> &Self { static NULL: Value = Value::Null; self.get(key).unwrap_or(&NULL) }
}
impl PartialEq<&str> for Value {
    fn eq(&self, other: &&str) -> bool { self.as_str() == Some(*other) }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    // IgnoredAny checks JSON grammar without converting numbers to bounded machine types.
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes)?;
    Scanner { bytes, position: 0 }.value(0)
}
struct Scanner<'a> { bytes: &'a [u8], position: usize }
impl Scanner<'_> {
    fn whitespace(&mut self) {
        while self.bytes.get(self.position).is_some_and(|c| b" \t\r\n".contains(c)) { self.position += 1; }
    }
    fn string(&mut self) -> Result<String> {
        let start = self.position;
        self.position += 1;
        loop {
            match self.bytes[self.position] {
                b'"' => { self.position += 1; break; }
                b'\\' => self.position += 2,
                _ => self.position += 1,
            }
        }
        serde_json::from_slice(&self.bytes[start..self.position]).context("JSON string")
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        ensure!(depth < 128, "JSON nesting limit");
        self.whitespace();
        Ok(match self.bytes.get(self.position).context("missing JSON value")? {
            b'n' => { self.position += 4; Value::Null }
            b't' => { self.position += 4; Value::Bool(true) }
            b'f' => { self.position += 5; Value::Bool(false) }
            b'"' => Value::String(self.string()?),
            b'[' => {
                self.position += 1;
                self.whitespace();
                let mut values = Vec::new();
                while self.bytes[self.position] != b']' {
                    values.push(self.value(depth + 1)?);
                    self.whitespace();
                    if self.bytes[self.position] != b',' { break; }
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
                    if self.bytes[self.position] != b',' { break; }
                    self.position += 1;
                    self.whitespace();
                }
                self.position += 1;
                Value::Object(values)
            }
            b'-' | b'0'..=b'9' => {
                let start = self.position;
                while self.bytes.get(self.position).is_some_and(|c| b"0123456789.eE+-".contains(c)) { self.position += 1; }
                Value::Number(std::str::from_utf8(&self.bytes[start..self.position])?.to_owned())
            }
            _ => bail!("unexpected JSON token"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_json_objects_remain_objects_in_both_parsers() {
        for key in ["$serde_json::private::Number", "$serde_json::private::RawValue", r"\u0024serde_json::private::RawValue"] {
            let bytes = format!(r#"{{"value":{{"{key}":"0"}}}}"#);
            let ordinary: serde_json::Value = serde_json::from_str(&bytes).unwrap();
            assert!(ordinary["value"].is_object(), "crate-wide features changed {key}");
            assert!(parse(bytes.as_bytes()).unwrap()["value"].as_object().is_some());
        }
    }

    #[test]
    fn scanner_preserves_numbers_duplicates_and_standard_json_refusals() {
        let value = parse(br#"{"n":1,"n":1234567890123456789012345678901234567890,"a":[-0,1e1000],"s":"x\"y"}"#).unwrap();
        assert_eq!(value["n"].as_number(), Some("1234567890123456789012345678901234567890"));
        assert_eq!(value["a"].as_array().unwrap()[0].as_number(), Some("-0"));
        assert_eq!(value["a"].as_array().unwrap()[1].as_number(), Some("1e1000"));
        assert_eq!(value["s"].as_str(), Some("x\"y"));
        for invalid in ["", "[1,]", "{\"a\":}", "\"unterminated", "01", "[true false]"] {
            assert!(parse(invalid.as_bytes()).is_err(), "{invalid}");
        }
    }
}

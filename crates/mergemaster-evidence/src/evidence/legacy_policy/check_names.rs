//! Policy-name enumeration/selection only; rule normalization remains a separate boundary.
use super::{PolicyDocument, PolicyError, invalid, policy_document, value_source::Source};
use crate::evidence::legacy_verify::value_inputs::TextRef;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;

/// Borrowed policy identity; never convert a Python name through lossy UTF-8.
#[derive(Clone, Copy)]
pub struct CheckName<'a>(TextRef<'a>);
impl<'a> From<&'a str> for CheckName<'a> {
    fn from(name: &'a str) -> Self {
        Self(TextRef::Str(name))
    }
}
impl<'a> From<&'a [u32]> for CheckName<'a> {
    fn from(name: &'a [u32]) -> Self {
        Self(TextRef::Points(name))
    }
}
impl<'a> CheckName<'a> {
    pub(crate) fn text(self) -> TextRef<'a> {
        self.0
    }
    /// Borrow code-point names; scalar text allocates the equivalent lookup sequence.
    pub fn codepoints(self) -> std::borrow::Cow<'a, [u32]> {
        match self.0 {
            TextRef::Str(text) => text.chars().map(u32::from).collect::<Vec<_>>().into(),
            TextRef::Points(points) => points.into(),
        }
    }
    pub(super) fn matches(self, points: &[u32]) -> bool {
        match self.0 {
            TextRef::Str(name) => name.chars().map(u32::from).eq(points.iter().copied()),
            TextRef::Points(name) => name == points,
        }
    }
    /// The lane domain retains its existing serde value API.
    pub(crate) fn lane_entry(self, text: &str) -> Result<Option<Value>, PolicyError> {
        if !crate::evidence::legacy_json::strict_strings(text) {
            return Err(invalid("unescaped control character in JSON string"));
        }
        let mut decoder = serde_json::Deserializer::from_str(text);
        let entry = LaneDocument(self)
            .deserialize(&mut decoder)
            .map_err(|error| invalid(error.to_string()))?;
        decoder.end().map_err(|error| invalid(error.to_string()))?;
        Ok(entry)
    }
}
impl std::fmt::Display for CheckName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl std::fmt::Debug for CheckName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Sorted Python code-point names, including lone surrogates; duplicate keys collapse.
/// Entries are syntax-checked, not policy-validated or filtered by `require`.
pub fn sorted(text: &str) -> Result<Vec<Vec<u32>>, PolicyError> {
    let document = policy_document(text)?;
    let mut names: Vec<_> = Source::root(&document)
        .get("checks")
        .and_then(Source::object)
        .into_iter()
        .flat_map(|entries| entries.keys().cloned())
        .collect();
    names.sort_unstable();
    Ok(names)
}
/// Select by borrowed code points without converting the name through Rust String.
/// The selected entry stays owned by its original lossless Document.
pub fn selected<'a>(
    text: &str,
    name: &'a [u32],
) -> Result<Option<PolicyDocument<'a>>, PolicyError> {
    let policy = PolicyDocument::parse(text, name)?;
    Ok(policy.entry.is_some().then_some(policy))
}
struct LaneDocument<'a>(CheckName<'a>);
impl<'de> DeserializeSeed<'de> for LaneDocument<'_> {
    type Value = Option<Value>;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for LaneDocument<'_> {
    type Value = Option<Value>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a legacy skip policy object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let (mut version, mut entry, mut present, mut unknown) = (None, None, false, false);
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "version" => version = Some(map.next_value::<Value>()?),
                "lanes" => {
                    entry = map.next_value_seed(LaneEntries(self.0))?;
                    present = true;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    unknown = true;
                }
            }
        }
        if unknown
            || !present
            || !(version.as_ref().and_then(Value::as_f64) == Some(1.0)
                || version == Some(Value::Bool(true)))
        {
            return Err(de::Error::custom(
                "document must contain version 1 and a lanes object",
            ));
        }
        Ok(entry)
    }
}
struct LaneEntries<'a>(CheckName<'a>);
impl<'de> DeserializeSeed<'de> for LaneEntries<'_> {
    type Value = Option<Value>;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for LaneEntries<'_> {
    type Value = Option<Value>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a map of legacy check entries")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut entry = None;
        while let Some(CheckKey(key)) = map.next_key::<CheckKey>()? {
            if self.0.matches(&key) {
                entry = Some(map.next_value::<Value>()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(entry)
    }
}
pub(crate) struct CheckKey(pub Vec<u32>);
impl<'de> serde::Deserialize<'de> for CheckKey {
    fn deserialize<D: de::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        decoder.deserialize_bytes(KeyVisitor)
    }
}
struct KeyVisitor;
impl<'de> Visitor<'de> for KeyVisitor {
    type Value = CheckKey;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object key")
    }
    fn visit_bytes<E: de::Error>(self, mut bytes: &[u8]) -> Result<CheckKey, E> {
        // serde's byte-string decoder preserves lone surrogates as WTF-8.
        // Do not encoding-sniff: NUL/BOM are ordinary characters inside a key.
        let mut points = Vec::new();
        loop {
            match std::str::from_utf8(bytes) {
                Ok(text) => {
                    points.extend(text.chars().map(u32::from));
                    return Ok(CheckKey(points));
                }
                Err(error) => {
                    let (valid, rest) = bytes.split_at(error.valid_up_to());
                    let text = std::str::from_utf8(valid).map_err(E::custom)?;
                    points.extend(text.chars().map(u32::from));
                    match rest {
                        [0xed, second @ 0xa0..=0xbf, third @ 0x80..=0xbf, tail @ ..] => {
                            points.push(
                                0xd000
                                    | (u32::from(*second & 0x3f) << 6)
                                    | u32::from(*third & 0x3f),
                            );
                            bytes = tail;
                        }
                        _ => return Err(E::custom("invalid JSON key encoding")),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    // Tagged values preserve every JSON type and lone-surrogate key/string point.
    fn lossless(source: super::super::value_source::Source<'_>) -> Value {
        use crate::evidence::legacy_verify::statement_document::Node;
        match source.node() {
            Node::Null => json!(["null"]),
            Node::Bool(value) => json!(["bool", value]),
            Node::Integer(decimal) => json!(["int", decimal]),
            Node::Float(value) if value.is_nan() => json!(["nan"]),
            Node::Float(value) => json!(["float", value.to_bits()]),
            Node::String(points) => json!(["str", points]),
            Node::Array(_) => json!([
                "list",
                source.array().unwrap().map(lossless).collect::<Vec<_>>()
            ]),
            Node::Object(_) => json!([
                "dict",
                source
                    .entries()
                    .unwrap()
                    .map(|(key, value)| json!([key, lossless(value)]))
                    .collect::<Vec<_>>()
            ]),
        }
    }
    #[test]
    fn policy_names_match_python_codepoints_and_selection() {
        let mut cases: Vec<String> = [
            r#"{"version":1,"checks":{}}"#,
            r#"{"version":true,"checks":{"\ud800":1,"\udfff":2,"\ud83d\ude00":3,"😀":4,"z":5}}"#,
            r#"{"version":1.0,"checks":{"\u0000x":1,"\ufeffx":2,"":3,"\u0000\u0000":4,"é":5}}"#,
            r#"{"version":1,"checks":{"b":1,"a":2,"b":3}}"#,
            r#"{"version":1,"checks":{"old":1},"checks":{"\ud800":2}}"#,
            r#"{"version":1,"checks":{"ignored":1e1000,"unit":2}}"#,
            r#"{"version":1,"checks":{"\ud800":{"kinds":{"wrapper":{"command":["test"]}},"trust_levels":["agent"],"require":"off"}}}"#,
            r#"{"version":2,"checks":{}}"#,
            r#"{"version":1,"checks":[],"extra":0}"#,
            r#"{"version":1,"checks":{"x":1,}}"#,
            r#"{"version":1,"checks":{"\ud800":1}} trailing"#,
            r#"{"version":1,"checks":{"a\\":1,"a\"b":2}}"#,
            r#"{"version":1,"checks":{"selected":{"\ud800":["\udfff","\ud83d\ude00",null,true,false,123456789012345678901234567890,-0.0,1.5],"\u0000":{"duplicate":1,"duplicate":2},"empty":{}}}}"#,
            r#"{"version":1,"checks":{"negative_zero":-0.0,"zero":0.0,"finite":1.5,"rounded":0.1,"positive_infinity":Infinity,"negative_infinity":-Infinity}}"#,
            r#"{"version":1,"checks":{"nan":NaN}}"#,
        ].into_iter().map(str::to_owned).collect();
        for point in 0..0x20 {
            cases.push(format!(
                "{{\"version\":1,\"checks\":{{\"a{}\":1}}}}",
                char::from_u32(point).unwrap()
            ));
            cases.push(format!(
                r#"{{"version":1,"checks":{{"a\u{point:04x}":1}}}}"#
            ));
        }
        let frozen_cases: Vec<String> = serde_json::from_slice(include_bytes!(
            "../../../../../tests/fixtures/oracle/scalar/check-names/stdin.json"
        ))
        .unwrap();
        assert_eq!(cases, frozen_cases, "complete input matrix changed");
        let expected: Vec<Value> = serde_json::from_slice(include_bytes!(
            "../../../../../tests/fixtures/oracle/scalar/check-names/stdout.bin"
        ))
        .unwrap();
        assert_eq!(
            cases.len(),
            expected.len(),
            "complete output matrix changed"
        );
        for (text, expected) in cases.iter().zip(expected) {
            let actual = sorted(text);
            if expected.is_null() {
                assert!(actual.is_err(), "{text}");
                assert!(selected(text, &[97]).is_err(), "{text}");
                assert!(
                    CheckName::from("a")
                        .lane_entry(&text.replace("\"checks\"", "\"lanes\""))
                        .is_err(),
                    "{text}"
                );
                continue;
            }
            let names = actual.unwrap();
            assert_eq!(json!(names), expected["names"], "{text}");
            for (index, name) in names.iter().enumerate() {
                if expected["values"][index].is_null() {
                    continue;
                }
                let policy = selected(text, name).unwrap().unwrap();
                assert_eq!(
                    lossless(policy.source().unwrap()),
                    expected["values"][index],
                    "{text}"
                );
            }
            assert!(selected(text, &[0x10ffff]).unwrap().is_none());
        }
        assert_eq!(
            CheckName::from("unit")
                .lane_entry(&cases[5].replace("\"checks\"", "\"lanes\""))
                .unwrap(),
            Some(json!(2))
        );
        assert_eq!(
            CheckName::from("😀")
                .lane_entry(&cases[1].replace("\"checks\"", "\"lanes\""))
                .unwrap(),
            Some(json!(4))
        );
    }
}

#[cfg(test)]
#[path = "name_rules_tests.rs"]
mod normalization_tests;

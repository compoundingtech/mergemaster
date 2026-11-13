//! Policy-name enumeration/selection only; rule normalization remains a separate boundary.
use super::{PolicyError, entries};
use serde::de::{self, Visitor};
use serde_json::Value;

/// Sorted Python code-point names, including lone surrogates; duplicate keys collapse.
/// Entries are syntax-checked, not policy-validated or filtered by `require`.
pub fn sorted(text: &str) -> Result<Vec<Vec<u32>>, PolicyError> {
    Ok(entries(text, Selection::Names, "checks")?
        .names
        .into_iter()
        .collect())
}
/// Select by borrowed code points without converting the name through Rust String.
/// Selected values retain the existing serde-value validation domain.
pub fn selected(text: &str, name: &[u32]) -> Result<Option<Value>, PolicyError> {
    Ok(entries(text, Selection::Points(name), "checks")?.entry)
}
#[derive(Clone, Copy)]
pub(super) enum Selection<'a> {
    Scalar(&'a str),
    Points(&'a [u32]),
    Names,
}
pub(super) struct CheckKey(pub Vec<u32>);
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
                    points.extend(std::str::from_utf8(valid).unwrap().chars().map(u32::from));
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
        let script = r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
out=[]
for text in json.load(sys.stdin):
 try:
  d=json.loads(text)
  if not isinstance(d,dict) or set(d)!={'version','checks'} or d['version']!=1 or not isinstance(d['checks'],dict): raise ValueError()
  names=sorted(d['checks']); values=[]
  if names==['\ud800'] and isinstance(d['checks'][names[0]],dict):
   assert v['require_all']('/not-a-repo','tree','/absent',text,'org/repo')=={'mode':'require-all','tree':'tree','satisfied':True,'decision':'ok','lanes':{}}
  for k in names:
   value=d['checks'][k]
   # Unselected huge floats are syntax-checked only by the Rust parser.
   values.append(None if isinstance(value,float) else value)
  out.append({'names':[[ord(c) for c in k] for k in names],'values':values})
 except ValueError: out.append(None)
print(json.dumps(out))
"#;
        let mut child = std::process::Command::new("python3")
            .args([
                "-c",
                script,
                &std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle"),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        serde_json::to_writer(child.stdin.take().unwrap(), &cases).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        for (text, expected) in cases.iter().zip(expected) {
            let actual = sorted(text);
            if expected.is_null() {
                assert!(actual.is_err(), "{text}");
                assert!(selected(text, &[97]).is_err(), "{text}");
                assert!(
                    super::super::selected_entry(text, "a", "checks").is_err(),
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
                assert_eq!(
                    selected(text, name).unwrap(),
                    Some(expected["values"][index].clone()),
                    "{text}"
                );
            }
            assert_eq!(selected(text, &[0x10ffff]).unwrap(), None);
        }
        assert_eq!(
            super::super::selected_entry(&cases[5], "unit", "checks").unwrap(),
            Some(json!(2))
        );
        assert_eq!(
            super::super::selected_entry(&cases[1], "😀", "checks").unwrap(),
            Some(json!(4))
        );
    }
}

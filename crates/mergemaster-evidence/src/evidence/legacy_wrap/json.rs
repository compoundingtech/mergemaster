//! Legacy Python JSON separators and lossless aggregate values.
use super::super::{
    flip_skip_python, legacy_json,
    legacy_verify::statement_document::{Document, Error, Node},
};
use anyhow::{Context, Result, bail};
use indexmap::IndexMap;

pub(super) type Fields = IndexMap<String, String>;
pub(super) type Inputs = IndexMap<Vec<u32>, String>;

pub(super) fn parse(text: &str) -> Result<Document> {
    Document::from_text_with_depth_limit(text, None).map_err(decode_error)
}

pub(super) fn parse_bytes(bytes: &[u8]) -> Result<Document> {
    Document::from_bytes_with_depth_limit(bytes, None).map_err(decode_error)
}

fn decode_error(error: Error) -> anyhow::Error {
    match error {
        Error::Syntax(error) => anyhow::anyhow!("{error}"),
        Error::IntegerLimit { digits } => anyhow::anyhow!(
            "Exceeds the limit (4300 digits) for integer string conversion: value has {digits} digits; use sys.set_int_max_str_digits() to increase the limit"
        ),
        Error::Encoding => anyhow::anyhow!("invalid JSON encoding"),
        Error::NestingLimit => {
            anyhow::anyhow!("maximum recursion depth exceeded while decoding a JSON object")
        }
    }
}

pub(super) fn get<'a>(document: &'a Document, node: &'a Node, key: &str) -> Option<&'a Node> {
    let Node::Object(fields) = node else {
        return None;
    };
    fields
        .iter()
        .find(|(name, _)| name.iter().copied().eq(key.chars().map(u32::from)))
        .map(|(_, id)| document.node(*id))
}

pub(super) fn text(node: &Node) -> Result<String> {
    let Node::String(points) = node else {
        bail!("expected a JSON string");
    };
    points
        .iter()
        .map(|point| {
            char::from_u32(*point)
                .ok_or_else(|| anyhow::anyhow!("text contains an unpaired surrogate"))
        })
        .collect()
}

pub(super) fn quote(text: &str) -> String {
    let mut out = String::new();
    legacy_json::emit_string(text, |part| out.push_str(part));
    out
}

pub(super) fn encoded(
    document: &Document,
    node: &Node,
    sorted: bool,
    compact: bool,
) -> Result<String> {
    let mut out = String::new();
    encode(document, node, sorted, compact, &mut out)?;
    Ok(out)
}

fn encode(
    document: &Document,
    node: &Node,
    sorted: bool,
    compact: bool,
    out: &mut String,
) -> Result<()> {
    enum Emit<'a> {
        Node(&'a Node),
        Key(&'a [u32]),
        Literal(&'static str),
    }
    let separator = if compact { "," } else { ", " };
    let colon = if compact { ":" } else { ": " };
    let mut stack = vec![Emit::Node(node)];
    while let Some(next) = stack.pop() {
        match next {
            Emit::Key(key) => legacy_json::codepoints(key.iter().copied(), out)?,
            Emit::Literal(text) => out.push_str(text),
            Emit::Node(Node::Array(values)) => {
                out.push('[');
                stack.push(Emit::Literal("]"));
                for (index, id) in values.iter().enumerate().rev() {
                    stack.push(Emit::Node(document.node(*id)));
                    if index != 0 {
                        stack.push(Emit::Literal(separator));
                    }
                }
            }
            Emit::Node(Node::Object(fields)) => {
                out.push('{');
                stack.push(Emit::Literal("}"));
                if sorted {
                    let mut ordered: Vec<_> = fields.iter().collect();
                    ordered.sort_unstable_by(|a, b| a.0.cmp(b.0));
                    for (index, (key, id)) in ordered.into_iter().enumerate().rev() {
                        stack.push(Emit::Node(document.node(*id)));
                        stack.push(Emit::Literal(colon));
                        stack.push(Emit::Key(key));
                        if index != 0 {
                            stack.push(Emit::Literal(separator));
                        }
                    }
                } else {
                    for (index, (key, id)) in fields.iter().enumerate().rev() {
                        stack.push(Emit::Node(document.node(*id)));
                        stack.push(Emit::Literal(colon));
                        stack.push(Emit::Key(key));
                        if index != 0 {
                            stack.push(Emit::Literal(separator));
                        }
                    }
                }
            }
            Emit::Node(value) => flip_skip_python::node_json(document, value, 0, out)?,
        }
    }
    Ok(())
}

pub(super) fn object(fields: &Fields, pretty: bool) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index != 0 {
            out.push_str(if pretty { ",\n" } else { ", " });
        } else if pretty {
            out.push('\n');
        }
        if pretty {
            out.push_str("  ");
        }
        legacy_json::emit_string(key, |part| out.push_str(part));
        out.push_str(": ");
        out.push_str(value);
    }
    if pretty && !fields.is_empty() {
        out.push('\n');
    }
    out.push('}');
    out
}

pub(super) fn inputs(fields: &Inputs) -> Result<String> {
    let mut out = String::from("{");
    for (index, (key, value)) in fields.iter().enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        legacy_json::codepoints(key.iter().copied(), &mut out)?;
        out.push_str(": ");
        out.push_str(value);
    }
    out.push('}');
    Ok(out)
}

pub(super) fn set(inputs: &mut Inputs, key: &str, value: &str) {
    inputs.insert(key.chars().map(u32::from).collect(), quote(value));
}

pub(super) fn input<'a>(inputs: &'a Inputs, key: &str) -> Option<&'a str> {
    inputs
        .iter()
        .find(|(name, _)| name.iter().copied().eq(key.chars().map(u32::from)))
        .map(|(_, value)| value.as_str())
}

fn type_name(node: &Node) -> &'static str {
    match node {
        Node::Null => "NoneType",
        Node::Bool(_) => "bool",
        Node::Integer(_) => "int",
        Node::Float(_) => "float",
        Node::String(_) => "str",
        Node::Array(_) => "list",
        Node::Object(_) => "dict",
    }
}

fn points_string(points: &[u32]) -> Result<String> {
    let mut value = String::new();
    legacy_json::codepoints(points.iter().copied(), &mut value)?;
    Ok(value)
}

#[derive(Hash, PartialEq, Eq)]
enum UpdateKey {
    String(Vec<u32>),
    Null,
    Number(String),
}
type Updates = IndexMap<UpdateKey, (Option<Vec<u32>>, String)>;

fn update_key(document: &Document, node: &Node) -> Result<(UpdateKey, Option<Vec<u32>>)> {
    let identity = match node {
        Node::String(points) => return Ok((UpdateKey::String(points.clone()), None)),
        Node::Null => return Ok((UpdateKey::Null, None)),
        Node::Bool(value) => if *value { "1" } else { "0" }.to_owned(),
        Node::Integer(value) => {
            if value == "-0" {
                "0".to_owned()
            } else {
                value.clone()
            }
        }
        Node::Float(value) if *value == 0.0 => "0".to_owned(),
        Node::Float(value) if value.is_finite() && value.fract() == 0.0 => format!("{value:.0}"),
        Node::Float(value) if value.is_nan() => "NaN".to_owned(),
        Node::Float(value) => format!("float:{}", value.to_bits()),
        _ => bail!("unhashable type: '{}'", type_name(node)),
    };
    Ok((
        UpdateKey::Number(identity),
        Some(
            encoded(document, node, false, false)?
                .chars()
                .map(u32::from)
                .collect(),
        ),
    ))
}

fn update_entry(updates: &mut Updates, key: UpdateKey, spelling: Option<Vec<u32>>, value: String) {
    match updates.entry(key) {
        indexmap::map::Entry::Occupied(mut entry) => entry.get_mut().1 = value,
        indexmap::map::Entry::Vacant(entry) => {
            entry.insert((spelling, value));
        }
    }
}

/// `dict.update` accepts mappings or iterables whose elements have two items.
pub(super) fn update_inputs(inputs: &mut Inputs, document: &Document, node: &Node) -> Result<()> {
    if let Node::Object(fields) = node {
        for (key, id) in fields {
            inputs.insert(
                key.clone(),
                encoded(document, document.node(*id), false, false)?,
            );
        }
        return Ok(());
    }
    let mut updates: Updates = std::mem::take(inputs)
        .into_iter()
        .map(|(key, value)| (UpdateKey::String(key), (None, value)))
        .collect();
    match node {
        Node::Array(rows) => {
            for (index, id) in rows.iter().enumerate() {
                let row = document.node(*id);
                let length = match row {
                    Node::Array(values) => values.len(),
                    Node::String(points) => points.len(),
                    Node::Object(fields) => fields.len(),
                    _ => bail!(
                        "cannot convert dictionary update sequence element #{index} to a sequence"
                    ),
                };
                anyhow::ensure!(
                    length == 2,
                    "dictionary update sequence element #{index} has length {length}; 2 is required"
                );
                let (key, spelling, value) = match row {
                    Node::Array(values) => {
                        let (key, spelling) = update_key(document, document.node(values[0]))?;
                        (
                            key,
                            spelling,
                            encoded(document, document.node(values[1]), false, false)?,
                        )
                    }
                    Node::String(points) => (
                        UpdateKey::String(vec![points[0]]),
                        None,
                        points_string(&points[1..])?,
                    ),
                    Node::Object(fields) => {
                        let mut keys = fields.keys();
                        let first = keys.next().context("missing first update key")?.clone();
                        let second = keys.next().context("missing second update key")?;
                        (UpdateKey::String(first), None, points_string(second)?)
                    }
                    _ => bail!(
                        "cannot convert dictionary update sequence element #{index} to a sequence"
                    ),
                };
                update_entry(&mut updates, key, spelling, value);
            }
        }
        Node::String(points) => {
            anyhow::ensure!(
                points.is_empty(),
                "dictionary update sequence element #0 has length 1; 2 is required"
            );
        }
        _ => bail!("'{}' object is not iterable", type_name(node)),
    }
    for (key, (spelling, value)) in updates {
        let key = match key {
            UpdateKey::String(points) => points,
            UpdateKey::Null => "null".chars().map(u32::from).collect(),
            UpdateKey::Number(_) => spelling.context("missing numeric update key spelling")?,
        };
        inputs.insert(key, value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn byte_signer_responses_accept_bom_and_utf16_utf32() {
        let raw = r#"{"record":"a","tier":"full"}"#;
        let mut cases = vec![
            raw.as_bytes().to_vec(),
            [b"\xef\xbb\xbf".as_slice(), raw.as_bytes()].concat(),
        ];
        for little in [false, true] {
            let utf16: Vec<_> = raw
                .encode_utf16()
                .flat_map(|n| {
                    if little {
                        n.to_le_bytes()
                    } else {
                        n.to_be_bytes()
                    }
                })
                .collect();
            let utf32: Vec<_> = raw
                .chars()
                .flat_map(|c| {
                    if little {
                        u32::from(c).to_le_bytes()
                    } else {
                        u32::from(c).to_be_bytes()
                    }
                })
                .collect();
            cases.push(utf16.clone());
            cases.push(
                [
                    if little {
                        b"\xff\xfe".as_slice()
                    } else {
                        b"\xfe\xff".as_slice()
                    },
                    &utf16,
                ]
                .concat(),
            );
            cases.push(utf32.clone());
            cases.push(
                [
                    if little {
                        b"\xff\xfe\0\0".as_slice()
                    } else {
                        b"\0\0\xfe\xff".as_slice()
                    },
                    &utf32,
                ]
                .concat(),
            );
        }
        for bytes in cases {
            let document = parse_bytes(&bytes).unwrap();
            assert_eq!(
                encoded(&document, document.root(), false, false).unwrap(),
                r#"{"record": "a", "tier": "full"}"#
            );
        }
    }

    #[test]
    fn aggregate_input_updates_match_python_mapping_iterable_and_refusal_semantics() {
        let raw = r#"[{},[],[["run_id","42"]],["ab"],"",[["base","changed"]],[["x"]],[["x","y","z"]],[false],null,42,true,"ab",[[[],"x"]],[[{},"x"]],[{"a":0,"b":1}],[[true,"a"],["true","b"],[1,"c"]],[["true","a"],[true,"b"],["true","c"]],[[1.0,"x"],[true,"y"]],[[null,"x"],["null","y"]]]"#;
        let mut child = crate::pinned_python::command()
            .args([
                "-B",
                "-c",
                r#"
import json,sys
for extra in json.load(sys.stdin):
    base={'base':'x'}
    try:
        base.update(extra)
        print('OK '+json.dumps(json.loads(json.dumps(base))))
    except (ValueError,TypeError) as error:
        print('ERROR '+str(error))
"#,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), raw.as_bytes()).unwrap();
        let reference = child.wait_with_output().unwrap();
        assert!(reference.status.success());
        let document = parse(raw).unwrap();
        let Node::Array(cases) = document.root() else {
            panic!("array fixture");
        };
        let mut actual = String::new();
        for id in cases {
            let mut values = Inputs::new();
            set(&mut values, "base", "x");
            match update_inputs(&mut values, &document, document.node(*id)) {
                Ok(()) => {
                    actual.push_str("OK ");
                    actual.push_str(&inputs(&values).unwrap());
                }
                Err(error) => {
                    actual.push_str("ERROR ");
                    actual.push_str(&error.to_string());
                }
            }
            actual.push('\n');
        }
        assert_eq!(actual.as_bytes(), reference.stdout);
    }

    #[test]
    fn aggregate_json_bytes_match_python_for_numbers_unicode_and_duplicate_keys() {
        let raw = r#"[{"z":[1.0,1e-5,-0.0,1e1000,NaN],"a":"é🌍\ud800","y":[1e23,1.2345678901234567]}, {"b":2,"a":1,"b":3}, 123456789012345678901234567890123456789, -0]"#;
        let doc = parse(raw).unwrap();
        let Node::Array(values) = doc.root() else {
            panic!("array fixture");
        };
        for (sorted, compact) in [(true, true), (false, false)] {
            let mut child = crate::pinned_python::command()
                .args(["-B", "-c", "import json,sys; values=json.load(sys.stdin); print('\\n'.join(json.dumps(v,sort_keys=sys.argv[1]=='true',separators=(',',':') if sys.argv[2]=='true' else None) for v in values))", if sorted { "true" } else { "false" }, if compact { "true" } else { "false" }])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            std::io::Write::write_all(&mut child.stdin.take().unwrap(), raw.as_bytes()).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            let mut actual = String::new();
            for id in values {
                actual.push_str(&encoded(&doc, doc.node(*id), sorted, compact).unwrap());
                actual.push('\n');
            }
            assert_eq!(actual.as_bytes(), output.stdout);
        }
    }
}

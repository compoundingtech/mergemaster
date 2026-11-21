//! Persist Python JSON values without narrowing numbers or losing unknown fields.
use super::super::legacy_verify::statement_document::{Document, Error, Node};
use anyhow::{Context, Result, bail, ensure};
use indexmap::IndexMap;
use std::sync::Arc;

/// Inclusive container count, including the root object; an explicit native bound.
pub const MAX_STATE_DEPTH: usize = 256;

#[derive(Clone)]
enum Field {
    Original(usize),
    Number(f64),
    Text(Arc<str>),
}
#[derive(Clone, Default)]
pub struct State {
    document: Option<Arc<Document>>,
    fields: IndexMap<Arc<[u32]>, Field>,
}
impl State {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // json.load(open(path)) parses decoded UTF-8 text without byte-encoding sniffing.
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Ok(Self::default());
        };
        let document = match Document::from_text_with_depth_limit(text, Some(MAX_STATE_DEPTH)) {
            Ok(document) => document,
            Err(Error::NestingLimit) => {
                bail!("watch state JSON exceeds {MAX_STATE_DEPTH} container levels")
            }
            Err(_) => return Ok(Self::default()),
        };
        let Node::Object(fields) = document.root() else {
            return Ok(Self::default());
        };
        let fields = fields
            .iter()
            .map(|(key, id)| (Arc::from(key.as_slice()), Field::Original(*id)))
            .collect();
        Ok(Self {
            document: Some(Arc::new(document)),
            fields,
        })
    }
    fn key(name: &str) -> ([u32; 32], usize) {
        let mut points = [0; 32];
        for (out, byte) in points.iter_mut().zip(name.bytes()) {
            *out = u32::from(byte);
        }
        (points, name.len())
    }
    pub(super) fn contains(&self, name: &str) -> bool {
        let (points, len) = Self::key(name);
        self.fields.contains_key(&points[..len])
    }
    fn set(&mut self, name: &str, field: Field) {
        let (points, len) = Self::key(name);
        if let Some(previous) = self.fields.get_mut(&points[..len]) {
            *previous = field;
        } else {
            self.fields.insert(Arc::from(&points[..len]), field);
        }
    }
    pub(super) fn insert_number(&mut self, name: &str, number: f64) {
        self.set(name, Field::Number(number));
    }
    pub(super) fn insert_text(&mut self, name: &str, text: &str) {
        self.set(name, Field::Text(Arc::from(text)));
    }
    pub(super) fn remove(&mut self, name: &str) {
        let (points, len) = Self::key(name);
        self.fields.shift_remove(&points[..len]);
    }
    pub(super) fn restore(&mut self, name: &str, before: &Self) {
        self.remove(name);
        let (points, len) = Self::key(name);
        if let Some(field) = before.fields.get(&points[..len]) {
            self.set(name, field.clone());
        }
    }
    pub(super) fn number(&self, name: &str) -> Result<f64> {
        let (points, len) = Self::key(name);
        let Some(field) = self.fields.get(&points[..len]) else {
            return Ok(0.0);
        };
        match field {
            Field::Number(value) => Ok(*value),
            Field::Original(id) => match self
                .document
                .as_ref()
                .context("missing state document")?
                .node(*id)
            {
                Node::Bool(value) => Ok(if *value { 1.0 } else { 0.0 }),
                Node::Float(value) => Ok(*value),
                Node::Integer(decimal) => {
                    let value: f64 = decimal.parse()?;
                    ensure!(value.is_finite(), "integer too large to convert to float");
                    Ok(value)
                }
                _ => bail!("state {name} is not a number"),
            },
            Field::Text(_) => bail!("state {name} is not a number"),
        }
    }
    pub fn json(&self) -> Result<String> {
        let mut out = String::from("{");
        for (index, (key, field)) in self.fields.iter().enumerate() {
            if index != 0 {
                out.push_str(", ");
            }
            super::super::legacy_json::codepoints(key.iter().copied(), &mut out)?;
            out.push_str(": ");
            match field {
                Field::Number(value) => float(*value, &mut out)?,
                Field::Text(text) => super::super::legacy_json::string(text, &mut out)?,
                Field::Original(id) => node(
                    self.document.as_ref().context("missing state document")?,
                    *id,
                    &mut out,
                )?,
            }
        }
        out.push('}');
        Ok(out)
    }
}
fn float(value: f64, out: &mut String) -> Result<()> {
    if value.is_nan() {
        out.push_str("NaN");
    } else if value == f64::INFINITY {
        out.push_str("Infinity");
    } else if value == f64::NEG_INFINITY {
        out.push_str("-Infinity");
    } else {
        out.push_str(&super::super::legacy_request::float_token(value)?);
    }
    Ok(())
}
fn node(document: &Document, root: usize, out: &mut String) -> Result<()> {
    enum Emit<'a> {
        Node(usize),
        Text(&'static str),
        Key(&'a [u32]),
    }
    let mut stack = vec![Emit::Node(root)];
    while let Some(action) = stack.pop() {
        match action {
            Emit::Text(text) => out.push_str(text),
            Emit::Key(points) => {
                super::super::legacy_json::codepoints(points.iter().copied(), out)?
            }
            Emit::Node(id) => match document.node(id) {
                Node::Null => out.push_str("null"),
                Node::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
                Node::Integer(decimal) => out.push_str(if decimal == "-0" { "0" } else { decimal }),
                Node::Float(value) => float(*value, out)?,
                Node::String(points) => {
                    super::super::legacy_json::codepoints(points.iter().copied(), out)?
                }
                Node::Array(items) => {
                    out.push('[');
                    stack.push(Emit::Text("]"));
                    for (index, id) in items.iter().enumerate().rev() {
                        stack.push(Emit::Node(*id));
                        if index != 0 {
                            stack.push(Emit::Text(", "));
                        }
                    }
                }
                Node::Object(fields) => {
                    out.push('{');
                    stack.push(Emit::Text("}"));
                    for (index, (key, id)) in fields.iter().enumerate().rev() {
                        stack.push(Emit::Node(*id));
                        stack.push(Emit::Text(": "));
                        stack.push(Emit::Key(key));
                        if index != 0 {
                            stack.push(Emit::Text(", "));
                        }
                    }
                }
            },
        }
    }
    Ok(())
}

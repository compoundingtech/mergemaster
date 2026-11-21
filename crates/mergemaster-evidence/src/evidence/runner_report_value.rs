//! Borrowed access to the shared Python JSON arena, and lossless report output.
use super::{
    legacy_json,
    legacy_verify::{
        python_repr::Repr,
        statement_document::{Document, Node},
        value_inputs::TextRef,
    },
    runner_report_numbers::float_repr,
};
use anyhow::{Context, Result};
use std::{borrow::Cow, fmt::Write};
static NULL_NODE: Node = Node::Null;

#[derive(Clone, Copy)]
pub(super) struct Input<'a> {
    pub document: &'a Document,
    pub node: &'a Node,
}
impl<'a> Input<'a> {
    pub fn root(document: &'a Document) -> Self {
        Self {
            document,
            node: document.root(),
        }
    }
    pub fn field(self, key: &str) -> Self {
        let id = if let Node::Object(fields) = self.node {
            fields
                .iter()
                .find(|(points, _)| points.iter().copied().eq(key.chars().map(u32::from)))
                .map(|(_, id)| *id)
        } else {
            None
        };
        Self {
            document: self.document,
            node: id.map_or(&NULL_NODE, |id| self.document.node(id)),
        }
    }
    pub fn array(self) -> impl Iterator<Item = Self> {
        let items: &[usize] = if let Node::Array(items) = self.node {
            items
        } else {
            &[]
        };
        items.iter().map(move |id| Self {
            document: self.document,
            node: self.document.node(*id),
        })
    }
    pub fn numeric(self) -> bool {
        matches!(self.node, Node::Integer(_) | Node::Float(_) | Node::Bool(_))
    }
    pub fn truth(self) -> bool {
        match self.node {
            Node::Null => false,
            Node::Bool(v) => *v,
            Node::Integer(s) => s != "0" && s != "-0",
            Node::Float(v) => *v != 0.0,
            Node::String(s) => !s.is_empty(),
            Node::Array(v) => !v.is_empty(),
            Node::Object(v) => !v.is_empty(),
        }
    }
    pub fn points(self) -> Option<&'a [u32]> {
        if let Node::String(s) = self.node {
            Some(s)
        } else {
            None
        }
    }
    pub fn text(self) -> Result<Cow<'a, [u32]>> {
        if let Some(points) = self.points() {
            return Ok(Cow::Borrowed(points));
        }
        let mut out = String::new();
        self.repr(&mut out)?;
        Ok(Cow::Owned(out.chars().map(u32::from).collect()))
    }
    fn repr(self, out: &mut String) -> Result<()> {
        match self.node {
            Node::Null => out.push_str("None"),
            Node::Bool(v) => out.push_str(if *v { "True" } else { "False" }),
            Node::Integer(s) => out.push_str(if s == "-0" { "0" } else { s }),
            Node::Float(v) => out.push_str(&float_repr(*v)?),
            Node::String(s) => write!(out, "{}", Repr(TextRef::Points(s)))?,
            Node::Array(_) => {
                out.push('[');
                for (index, value) in self.array().enumerate() {
                    if index != 0 {
                        out.push_str(", ");
                    }
                    value.repr(out)?;
                }
                out.push(']');
            }
            Node::Object(fields) => {
                out.push('{');
                for (index, (key, id)) in fields.iter().enumerate() {
                    if index != 0 {
                        out.push_str(", ");
                    }
                    write!(out, "{}: ", Repr(TextRef::Points(key)))?;
                    Self {
                        document: self.document,
                        node: self.document.node(*id),
                    }
                    .repr(out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }
}

type Field<'a> = (Cow<'a, [u32]>, Output<'a>);

pub(super) enum Output<'a> {
    Null,
    Bool(bool),
    Integer(i128),
    Float(f64),
    Text(Cow<'a, [u32]>),
    Raw(Input<'a>),
    Array(Vec<Self>),
    Object(Vec<Field<'a>>),
}
impl<'a> Output<'a> {
    pub fn text(value: impl AsRef<str>) -> Self {
        Self::Text(Cow::Owned(value.as_ref().chars().map(u32::from).collect()))
    }
    pub fn object<const N: usize>(fields: [(&str, Self); N]) -> Self {
        Self::Object(
            fields
                .into_iter()
                .map(|(k, v)| (Cow::Owned(k.chars().map(u32::from).collect()), v))
                .collect(),
        )
    }
    pub fn field(&self, key: &str) -> &Self {
        if let Self::Object(fields) = self
            && let Some((_, v)) = fields
                .iter()
                .find(|(k, _)| k.iter().copied().eq(key.chars().map(u32::from)))
        {
            return v;
        }
        static NULL: Output<'static> = Output::Null;
        &NULL
    }
    pub fn array(&self) -> Result<&[Self]> {
        if let Self::Array(v) = self {
            Ok(v)
        } else {
            anyhow::bail!("invalid report array")
        }
    }
    pub fn fields(&self) -> Result<&[Field<'a>]> {
        if let Self::Object(v) = self {
            Ok(v)
        } else {
            anyhow::bail!("invalid report object")
        }
    }
    pub fn scalar(&self) -> Result<String> {
        match self {
            Self::Null => Ok("None".into()),
            Self::Bool(v) => Ok(if *v { "True" } else { "False" }.into()),
            Self::Integer(v) => Ok(v.to_string()),
            Self::Float(v) => float_repr(*v),
            Self::Text(v) => scalar_text(v),
            Self::Raw(v) => scalar_text(&v.text()?),
            _ => anyhow::bail!("invalid report scalar"),
        }
    }
    pub fn pretty(&self, depth: usize, out: &mut String) -> Result<()> {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Self::Integer(v) => write!(out, "{v}")?,
            Self::Float(v) => json_float(*v, out)?,
            Self::Text(v) => legacy_json::codepoints(v.iter().copied(), out)?,
            Self::Raw(value) => raw_json(*value, depth, out)?,
            Self::Array(values) => {
                out.push('[');
                for (i, v) in values.iter().enumerate() {
                    line(i, depth + 1, out);
                    v.pretty(depth + 1, out)?;
                }
                close(values.is_empty(), depth, ']', out);
            }
            Self::Object(fields) => {
                out.push('{');
                for (i, (key, v)) in fields.iter().enumerate() {
                    line(i, depth + 1, out);
                    legacy_json::codepoints(key.iter().copied(), out)?;
                    out.push_str(": ");
                    v.pretty(depth + 1, out)?;
                }
                close(fields.is_empty(), depth, '}', out);
            }
        }
        Ok(())
    }
}
pub(super) fn scalar_text(points: &[u32]) -> Result<String> {
    points
        .iter()
        .map(|p| char::from_u32(*p).context("cannot encode lone surrogate in Markdown"))
        .collect()
}
fn json_float(value: f64, out: &mut String) -> Result<()> {
    if value.is_nan() {
        out.push_str("NaN");
    } else if value == f64::INFINITY {
        out.push_str("Infinity");
    } else if value == f64::NEG_INFINITY {
        out.push_str("-Infinity");
    } else {
        out.push_str(&float_repr(value)?);
    }
    Ok(())
}
fn line(index: usize, depth: usize, out: &mut String) {
    if index != 0 {
        out.push(',');
    }
    out.push('\n');
    out.extend(std::iter::repeat_n(' ', depth * 2));
}
fn close(empty: bool, depth: usize, end: char, out: &mut String) {
    if !empty {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', depth * 2));
    }
    out.push(end);
}
fn raw_json(value: Input<'_>, depth: usize, out: &mut String) -> Result<()> {
    match value.node {
        Node::Null => out.push_str("null"),
        Node::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Node::Integer(v) => out.push_str(if v == "-0" { "0" } else { v }),
        Node::Float(v) => json_float(*v, out)?,
        Node::String(v) => legacy_json::codepoints(v.iter().copied(), out)?,
        Node::Array(items) => {
            out.push('[');
            for (i, v) in value.array().enumerate() {
                line(i, depth + 1, out);
                raw_json(v, depth + 1, out)?;
            }
            close(items.is_empty(), depth, ']', out);
        }
        Node::Object(fields) => {
            out.push('{');
            for (i, (key, id)) in fields.iter().enumerate() {
                line(i, depth + 1, out);
                legacy_json::codepoints(key.iter().copied(), out)?;
                out.push_str(": ");
                raw_json(
                    Input {
                        document: value.document,
                        node: value.document.node(*id),
                    },
                    depth + 1,
                    out,
                )?;
            }
            close(fields.is_empty(), depth, '}', out);
        }
    }
    Ok(())
}

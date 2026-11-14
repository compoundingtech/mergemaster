//! Borrowed policy value facade over a parsed statement Document; the
//! temporary bridge below is removed by the step-5 PolicyDocument ingress
//! cutover slice, which feeds the Document from the original policy text.
use super::normalized_text::NormalizedText;
use super::{PolicyError, invalid};
use crate::evidence::legacy_verify::statement_document::{Document, Node};
use indexmap::IndexMap;

#[derive(Clone, Copy)]
pub(super) struct Source<'a> {
    document: &'a Document,
    node: &'a Node,
}
impl<'a> Source<'a> {
    pub(super) fn root(document: &'a Document) -> Self {
        Self {
            document,
            node: document.root(),
        }
    }
    fn at(self, id: usize) -> Self {
        Self {
            document: self.document,
            node: self.document.node(id),
        }
    }
    pub(super) fn is_null(self) -> bool {
        matches!(self.node, Node::Null)
    }
    pub(super) fn object(self) -> Option<&'a IndexMap<Vec<u32>, usize>> {
        match self.node {
            Node::Object(entries) => Some(entries),
            _ => None,
        }
    }
    pub(super) fn get(self, key: &str) -> Option<Self> {
        let entries = self.object()?;
        entries
            .iter()
            .find(|(k, _)| key_is(k, key))
            .map(|(_, id)| self.at(*id))
    }
    pub(super) fn array(self) -> Option<impl Iterator<Item = Self> + 'a> {
        match self.node {
            Node::Array(items) => Some(items.iter().map(move |id| self.at(*id))),
            _ => None,
        }
    }
    pub(super) fn as_bool(self) -> Option<bool> {
        match self.node {
            Node::Bool(value) => Some(*value),
            _ => None,
        }
    }
    /// Integer-only u64 view, matching the retained serde numeric bound.
    pub(super) fn as_u64(self) -> Option<u64> {
        match self.node {
            Node::Integer(text) => text.parse().ok(),
            _ => None,
        }
    }
    pub(super) fn as_f64(self) -> Option<f64> {
        match self.node {
            Node::Integer(text) => text.parse::<f64>().ok(),
            Node::Float(value) => Some(*value),
            _ => None,
        }
    }
    pub(super) fn string_points(self) -> Option<&'a [u32]> {
        match self.node {
            Node::String(points) => Some(points.as_slice()),
            _ => None,
        }
    }
    pub(super) fn str_is(self, text: &str) -> bool {
        self.string_points()
            .is_some_and(|points| key_is(points, text))
    }
    /// Scalar storage for bridge-sourced names; lone surrogates stay code points.
    pub(super) fn normalized(self) -> Option<NormalizedText> {
        self.string_points().map(NormalizedText::from_points)
    }
}
pub(super) fn key_is(points: &[u32], key: &str) -> bool {
    points.iter().copied().eq(key.chars().map(u32::from))
}
/// Nonempty name list over code points; None rejects any non-name member.
pub(super) fn names(source: Source) -> Option<Vec<NormalizedText>> {
    let names: Option<Vec<_>> = source
        .array()?
        .map(|item| {
            item.normalized()
                .filter(|name| name.borrowed().points().next().is_some())
        })
        .collect();
    names.filter(|names| !names.is_empty())
}
/// Re-encode the retained serde entry into a lossless Document (the bridge).
pub(super) fn bridge(entry: &serde_json::Value) -> Result<Document, PolicyError> {
    let text = serde_json::to_string(entry).map_err(|e| invalid(e.to_string()))?;
    Document::from_bytes(text.as_bytes()).map_err(|error| invalid(format!("{error:?}")))
}
/// Transcode a bridged subtree back to serde values for modules that still
/// consume them; removed with the bridge in the step-5 cutover slice.
pub(super) fn to_value(source: Source) -> serde_json::Value {
    fn text(points: &[u32]) -> String {
        String::from_iter(
            points
                .iter()
                .map(|&p| char::from_u32(p).unwrap_or(char::REPLACEMENT_CHARACTER)),
        )
    }
    match source.node {
        Node::Null => serde_json::Value::Null,
        Node::Bool(value) => serde_json::Value::Bool(*value),
        Node::Integer(text) => match text.parse::<i64>() {
            Ok(value) => serde_json::Value::Number(value.into()),
            Err(_) => match text.parse::<u64>() {
                Ok(value) => serde_json::Value::Number(value.into()),
                Err(_) => parse_float(text),
            },
        },
        Node::Float(value) => serde_json::Number::from_f64(*value)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Node::String(points) => serde_json::Value::String(text(points)),
        Node::Array(items) => {
            serde_json::Value::Array(items.iter().map(|id| to_value(source.at(*id))).collect())
        }
        Node::Object(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(key, id)| (text(key), to_value(source.at(*id))))
                .collect(),
        ),
    }
}
fn parse_float(text: &str) -> serde_json::Value {
    text.parse::<f64>()
        .ok()
        .and_then(serde_json::Number::from_f64)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null)
}

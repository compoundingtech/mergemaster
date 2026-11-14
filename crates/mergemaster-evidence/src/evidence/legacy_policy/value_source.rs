//! Borrowed views of the sole, lossless policy Document.
use super::normalized_text::NormalizedText;
use crate::evidence::legacy_verify::statement_document::{Document, Node};
use indexmap::IndexMap;

#[derive(Clone, Copy, Debug)]
pub struct Source<'a> {
    document: &'a Document,
    node: &'a Node,
}
impl<'a> Source<'a> {
    pub fn root(document: &'a Document) -> Self {
        Self {
            document,
            node: document.root(),
        }
    }
    pub(super) fn at(self, id: usize) -> Self {
        Self {
            document: self.document,
            node: self.document.node(id),
        }
    }
    pub(super) fn node(self) -> &'a Node {
        self.node
    }
    pub(super) fn entries(self) -> Option<impl Iterator<Item = (&'a [u32], Self)>> {
        self.object().map(|entries| {
            entries
                .iter()
                .map(move |(key, id)| (key.as_slice(), self.at(*id)))
        })
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
    pub(super) fn array(self) -> Option<impl ExactSizeIterator<Item = Self> + 'a> {
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
    /// Integer-only u64 view for bounded policy fields.
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
    /// Lone surrogates remain code points, never replacement characters.
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

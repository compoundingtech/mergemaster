use super::statement_document::{Document, Node};
use std::collections::BTreeMap;

/// Lossless borrowed Python text; Display is diagnostic, not a wire encoder.
#[derive(Clone, Copy)]
pub enum TextRef<'a> {
    Str(&'a str),
    Points(&'a [u32]),
}
impl<'a> TextRef<'a> {
    pub(in crate::evidence) fn split_once(self, separator: &str) -> Option<(Self, Self)> {
        match self {
            Self::Str(text) => text
                .split_once(separator)
                .map(|(head, tail)| (Self::Str(head), Self::Str(tail))),
            Self::Points(points) => {
                let width = separator.chars().count();
                let at = if width == 0 {
                    0
                } else {
                    points.windows(width).position(|window| {
                        window.iter().copied().eq(separator.chars().map(u32::from))
                    })?
                };
                Some((
                    Self::Points(&points[..at]),
                    Self::Points(&points[at + width..]),
                ))
            }
        }
    }
    pub(in crate::evidence) fn strip_prefix(self, prefix: &str) -> Option<Self> {
        match self {
            Self::Str(text) => text.strip_prefix(prefix).map(Self::Str),
            Self::Points(points) => self
                .starts_with(prefix)
                .then(|| Self::Points(&points[prefix.chars().count()..])),
        }
    }
    pub(in crate::evidence) fn starts_with(self, prefix: &str) -> bool {
        match self {
            Self::Str(text) => text.starts_with(prefix),
            Self::Points(_) => {
                let mut points = self.points();
                prefix.chars().all(|c| points.next() == Some(u32::from(c)))
            }
        }
    }
    pub(crate) fn points(self) -> impl Iterator<Item = u32> {
        let (text, points) = match self {
            Self::Str(text) => (text, &[][..]),
            Self::Points(points) => ("", points),
        };
        text.chars().map(u32::from).chain(points.iter().copied())
    }
    pub(super) fn len(self) -> usize {
        match self {
            Self::Str(text) => text.len(),
            Self::Points(points) => points.len(),
        }
    }
    pub(crate) fn equals(self, text: &str) -> bool {
        match self {
            Self::Str(value) => value == text,
            Self::Points(points) => points.iter().copied().eq(text.chars().map(u32::from)),
        }
    }
    pub(super) fn complete_shards(self, count: u8) -> bool {
        let mut points = self.points();
        for index in 0..count {
            if index > 0 && points.next() != Some(44) {
                return false;
            }
            if index >= 10 && points.next() != Some(49) {
                return false;
            }
            if points.next() != Some(48 + u32::from(index % 10)) {
                return false;
            }
            for byte in b"=success" {
                if points.next() != Some(u32::from(*byte)) {
                    return false;
                }
            }
        }
        points.next().is_none()
    }
}
impl<'a> From<&'a str> for TextRef<'a> {
    fn from(text: &'a str) -> Self {
        Self::Str(text)
    }
}
impl<'a> From<&'a String> for TextRef<'a> {
    fn from(text: &'a String) -> Self {
        Self::Str(text)
    }
}
impl<'a> From<&'a crate::evidence::legacy_policy::normalized_text::NormalizedText> for TextRef<'a> {
    fn from(text: &'a crate::evidence::legacy_policy::normalized_text::NormalizedText) -> Self {
        text.borrowed()
    }
}
impl std::fmt::Display for TextRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Self::Str(text) = self {
            return f.write_str(text);
        }
        for point in self.points() {
            if let Some(c) = char::from_u32(point) {
                write!(f, "{c}")?;
            } else {
                write!(f, "\\u{point:04x}")?;
            }
        }
        Ok(())
    }
}
/// A borrowed object whose IDs resolve to string nodes in this immutable document.
#[derive(Clone, Copy)]
pub struct ValidatedInputs<'a> {
    document: &'a Document,
    entries: &'a indexmap::IndexMap<Vec<u32>, usize>,
}
impl<'a> ValidatedInputs<'a> {
    pub fn new(document: &'a Document, node: &'a Node) -> Option<Self> {
        let Node::Object(entries) = node else {
            return None;
        };
        entries
            .values()
            .all(|id| matches!(document.try_node(*id), Some(Node::String(_))))
            .then_some(Self { document, entries })
    }
    fn get(self, key: &[u32]) -> Option<&'a [u32]> {
        match self.document.try_node(*self.entries.get(key)?)? {
            Node::String(value) => Some(value),
            _ => None, // Constructor proves this cannot occur; no mutable arena access.
        }
    }
    pub(super) fn iter(self) -> impl Iterator<Item = (&'a [u32], &'a [u32])> {
        self.entries
            .iter()
            .filter_map(move |(key, id)| match self.document.try_node(*id)? {
                Node::String(value) => Some((key.as_slice(), value.as_slice())),
                _ => None,
            })
    }
}

/// Borrowed run-input lookup without narrowing Python string codepoints.
pub trait InputMap {
    fn get_text(&self, key: TextRef<'_>) -> Option<TextRef<'_>>;
}
impl InputMap for BTreeMap<String, String> {
    fn get_text(&self, key: TextRef<'_>) -> Option<TextRef<'_>> {
        InputSource::Native(self).get_text(key)
    }
}
impl InputMap for ValidatedInputs<'_> {
    fn get_text(&self, key: TextRef<'_>) -> Option<TextRef<'_>> {
        InputSource::Document(*self).get_text(key)
    }
}

/// Validation and iteration share the same immutable arena, with no copied strings.
#[derive(Clone)]
pub(super) struct StringNodes<'a> {
    document: &'a Document,
    ids: std::slice::Iter<'a, usize>,
}
impl<'a> StringNodes<'a> {
    pub(super) fn new(document: &'a Document, node: &'a Node) -> Option<Self> {
        let Node::Array(ids) = node else { return None };
        ids.iter()
            .all(|id| matches!(document.try_node(*id), Some(Node::String(_))))
            .then_some(Self {
                document,
                ids: ids.iter(),
            })
    }
}
impl<'a> Iterator for StringNodes<'a> {
    type Item = &'a [u32];
    fn next(&mut self) -> Option<Self::Item> {
        match self.document.try_node(*self.ids.next()?)? {
            Node::String(value) => Some(value),
            _ => None, // Only the validating constructor creates this view.
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ids.size_hint()
    }
}
impl ExactSizeIterator for StringNodes<'_> {}

#[derive(Clone, Copy)]
pub(super) enum InputSource<'a> {
    Empty,
    Native(&'a BTreeMap<String, String>),
    Document(ValidatedInputs<'a>),
}
impl<'a> InputSource<'a> {
    pub(super) fn get_text(&self, key: TextRef<'_>) -> Option<TextRef<'a>> {
        let key = match key {
            TextRef::Str(key) => return self.get(key),
            TextRef::Points(key) => key,
        };
        match self {
            Self::Empty => None,
            Self::Native(inputs) => inputs
                .iter()
                .find(|(name, _)| TextRef::Points(key).equals(name))
                .map(|(_, value)| TextRef::Str(value)),
            Self::Document(inputs) => inputs.get(key).map(TextRef::Points),
        }
    }
    pub(super) fn get(&self, key: &str) -> Option<TextRef<'a>> {
        match self {
            Self::Empty => None,
            Self::Native(inputs) => inputs.get(key).map(|value| TextRef::Str(value)),
            Self::Document(inputs) => {
                let mut small = [0; 32];
                let mut chars = key.chars();
                let mut length = 0;
                for point in &mut small {
                    let Some(c) = chars.next() else { break };
                    *point = u32::from(c);
                    length += 1;
                }
                let large;
                let key = if let Some(next) = chars.next() {
                    large = small
                        .into_iter()
                        .chain(std::iter::once(u32::from(next)))
                        .chain(chars.map(u32::from))
                        .collect::<Vec<_>>();
                    &large[..]
                } else {
                    &small[..length]
                };
                inputs.get(key).map(TextRef::Points)
            }
        }
    }
}
#[cfg(test)]
#[path = "run_inputs_tests.rs"]
mod run_tests;
#[cfg(test)]
#[path = "value_inputs_tests.rs"]
mod tests;

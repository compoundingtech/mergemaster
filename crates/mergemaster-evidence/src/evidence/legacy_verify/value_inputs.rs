use super::statement_document::{Document, Node};
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub(super) enum TextRef<'a> {
    Str(&'a str),
    Points(&'a [u32]),
}
impl TextRef<'_> {
    pub(super) fn points(self) -> impl Iterator<Item = u32> {
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
    pub(super) fn equals(self, text: &str) -> bool {
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
pub(super) enum InputSource<'a> {
    Native(&'a BTreeMap<String, String>),
    Document(&'a Document, &'a indexmap::IndexMap<Vec<u32>, usize>),
}
impl<'a> InputSource<'a> {
    pub(super) fn get(&self, key: &str) -> Option<TextRef<'a>> {
        match self {
            Self::Native(inputs) => inputs.get(key).map(|value| TextRef::Str(value)),
            Self::Document(doc, inputs) => {
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
                let Node::String(value) = doc.node(*inputs.get(key)?) else {
                    unreachable!("validated input values are strings")
                };
                Some(TextRef::Points(value))
            }
        }
    }
}
#[cfg(test)]
#[path = "value_inputs_tests.rs"]
mod tests;

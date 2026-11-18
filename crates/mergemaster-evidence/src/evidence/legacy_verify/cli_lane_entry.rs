//! Compare the canonical JSON of CLI lane entries without serializing either.
use super::{
    statement_document::{Document, Node, PolicyTextError},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{PolicyError, SourceResource};

fn document(text: &str) -> Result<Option<Document>, PolicyError> {
    match Document::from_policy_text(text) {
        Ok(doc) => Ok(Some(doc)),
        Err(PolicyTextError::Text(_)) => Ok(None),
        Err(PolicyTextError::Resource(resource)) => {
            Err(SourceResource::LaneJson(resource).into_error())
        }
    }
}
fn get<'a>(doc: &'a Document, node: &'a Node, key: TextRef<'_>) -> Option<&'a Node> {
    let Node::Object(entries) = node else {
        return None;
    };
    entries
        .iter()
        .find(|(name, _)| name.iter().copied().eq(key.points()))
        .map(|(_, id)| doc.node(*id))
}
fn entry<'a>(doc: &'a Document, lane: TextRef<'_>) -> Option<&'a Node> {
    let lanes = get(doc, doc.root(), TextRef::Str("lanes"))?;
    get(doc, lanes, lane)
}
/// Equivalent to `here is not None and here == lane_entry(text, check)`.
/// Canonical JSON distinguishes bool/int/float and signed float zero; object
/// order and integer -0 do not matter. NaN always serializes to the same token.
/// Missing/malformed left entries short-circuit before parsing the right text.
pub fn matches(here: &str, accepted: &str, lane: TextRef<'_>) -> Result<bool, PolicyError> {
    let Some(left) = document(here)? else {
        return Ok(false);
    };
    let Some(a) = entry(&left, lane) else {
        return Ok(false);
    };
    let Some(right) = document(accepted)? else {
        return Ok(false);
    };
    let Some(b) = entry(&right, lane) else {
        return Ok(false);
    };
    let mut pending = vec![(a, b)];
    while let Some((a, b)) = pending.pop() {
        let equal = match (a, b) {
            (Node::Null, Node::Null) => true,
            (Node::Bool(a), Node::Bool(b)) => a == b,
            (Node::Integer(a), Node::Integer(b)) => {
                a == b || (a == "-0" && b == "0") || (a == "0" && b == "-0")
            }
            (Node::Float(a), Node::Float(b)) => {
                a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
            }
            (Node::String(a), Node::String(b)) => a == b,
            (Node::Array(a), Node::Array(b)) if a.len() == b.len() => {
                pending.extend(
                    a.iter()
                        .zip(b)
                        .map(|(a, b)| (left.node(*a), right.node(*b))),
                );
                true
            }
            (Node::Object(a), Node::Object(b)) if a.len() == b.len() => {
                for (key, value) in a {
                    let Some(other) = b.get(key) else {
                        return Ok(false);
                    };
                    pending.push((left.node(*value), right.node(*other)));
                }
                true
            }
            _ => false,
        };
        if !equal {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
#[path = "cli_lane_entry_tests.rs"]
mod tests;

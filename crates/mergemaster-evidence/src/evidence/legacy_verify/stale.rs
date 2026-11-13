//! Raw diagnostic discovery only: no statement validation or signature trust.
use super::{
    raw_batch::RawBatch,
    statement::field,
    statement_document::{Document, Error, Node},
};
use crate::evidence::{
    legacy_policy::{PolicyError, check_names::CheckName},
    oid,
};
use std::path::Path;
fn error(detail: &str) -> PolicyError {
    PolicyError {
        reason: "error",
        detail: detail.into(),
    }
}
fn other_blobs(body: &[u8], tree: &str, blobs: &mut Vec<String>) -> Result<(), PolicyError> {
    let mut tail = body;
    let width = tree.len() / 2;
    while !tail.is_empty() {
        let nul = tail
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| error("unterminated raw tree entry"))?;
        let space = tail[..nul]
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| error("invalid raw tree entry"))?;
        let name = &tail[space + 1..nul];
        let end = nul + 1 + width;
        if end > tail.len() {
            return Err(error("truncated raw tree object ID"));
        }
        if name != tree.as_bytes() && std::str::from_utf8(name).is_ok_and(|n| oid(n).is_ok()) {
            blobs.push(hex::encode(&tail[nul + 1..end]));
        }
        tail = &tail[end..];
    }
    Ok(())
}
fn has_check(doc: &Document, check: &[u32]) -> bool {
    let Some(checks) = field(doc, doc.root(), "predicate")
        .and_then(|p| field(doc, p, "observed"))
        .and_then(|o| field(doc, o, "checks"))
    else {
        return false;
    };
    match checks {
        Node::Object(values) => values.contains_key(check),
        Node::Array(values) => values
            .iter()
            .any(|id| matches!(doc.node(*id),Node::String(s) if s.as_slice()==check)),
        Node::String(value) => check.is_empty() || value.windows(check.len()).any(|s| s == check),
        _ => false,
    }
}
pub(super) fn bodies_have<'a>(
    mut batch: RawBatch,
    blobs: &[String],
    check: impl Into<CheckName<'a>>,
) -> Result<bool, PolicyError> {
    let check = check.into().codepoints();
    for blob in blobs {
        let Some(body) = batch.read(blob)? else {
            continue;
        };
        match Document::from_bytes(&body) {
            Ok(doc) if has_check(&doc, &check) => return Ok(true), // Drop cancels/reaps, no later request/read.
            Err(Error::NestingLimit) => {
                return Err(PolicyError {
                    reason: "stale-scan-too-deep",
                    detail: "raw JSON exceeds 256 containers".into(),
                });
            }
            Ok(_)
            | Err(Error::Encoding | Error::Invalid | Error::IntegerLimit | Error::ExtraData) => {}
        }
    }
    batch.finish()?;
    Ok(false)
}
/// Python's raw stale-tree diagnostic, not a trusted-record lookup.
/// Aggregate object count/runtime remain unbounded; each body/depth is bounded.
pub fn other_trees_have<'a>(
    repo: &Path,
    commits: &[String],
    tree: &str,
    check: impl Into<CheckName<'a>>,
) -> Result<bool, PolicyError> {
    if commits.is_empty() {
        return Ok(false);
    }
    oid(tree).map_err(|e| error(&e.to_string()))?;
    let mut listing = RawBatch::open(repo)?;
    let mut blobs = Vec::new();
    for commit in commits {
        if let Some(body) = listing.read(&format!("{commit}^{{tree}}"))? {
            other_blobs(&body, tree, &mut blobs)?;
        }
    }
    listing.finish()?; // Python enumerates all trees before testing any JSON body.
    if blobs.is_empty() {
        return Ok(false);
    }
    bodies_have(RawBatch::open(repo)?, &blobs, check)
}
#[cfg(test)]
#[path = "stale_tests.rs"]
mod tests;

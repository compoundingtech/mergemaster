use super::{
    Failure,
    collection::CandidateCollector,
    stale::other_trees_have,
    statement::field,
    statement_document::{Document, Node},
    trust::{TrustedCandidate, partition},
};
use crate::evidence::legacy_policy::{PolicyError, check_names::CheckName};
use std::path::Path;
pub struct Request<'a> {
    pub repo: &'a Path,
    pub tree: &'a str,
    pub check: CheckName<'a>,
    pub keys: &'a str,
    pub inputs: Option<&'a [String]>,
    pub crate_key: Option<(&'a str, &'a str)>,
}
fn failure(reason: &'static str, detail: String, attempts: usize) -> Failure {
    Failure {
        reason,
        detail,
        attempts,
    }
}
fn phase_error(e: PolicyError) -> Failure {
    failure(e.reason, e.detail, 0)
}
fn includes(doc: &Document, check: &[u32]) -> bool {
    matches!(field(doc,doc.root(),"predicate").and_then(|p| field(doc,p,"observed")).and_then(|o| field(doc,o,"checks")),Some(Node::Object(v)) if v.contains_key(check))
}
/// Reproduce Python's EMPTY owned revocation file, not external revocation policy.
/// Do not reuse for an API promising caller-supplied revocation enforcement.
/// attempts=0 normalizes absent Python metadata; it is not CLI wire parity.
pub fn candidates(
    collector: &mut CandidateCollector,
    q: &Request<'_>,
) -> Result<Vec<TrustedCandidate>, Failure> {
    let (groups, legacy) = {
        let file =
            tempfile::NamedTempFile::new().map_err(|e| failure("error", e.to_string(), 0))?;
        let path = file
            .path()
            .canonicalize()
            .map_err(|e| failure("error", e.to_string(), 0))?;
        let revocations = path
            .to_str()
            .ok_or_else(|| failure("error", "temporary revocation path is not UTF-8".into(), 0))?;
        let collected = collector
            .collect(q.repo, q.tree, q.check, q.inputs, q.crate_key)
            .map_err(phase_error)?;
        let groups =
            partition(q.repo, collected.records, q.keys, revocations).map_err(phase_error)?;
        (groups, collected.legacy)
    }; // Match957-995: revocation file lives through partition, not the miss scan.
    let check = q.check.codepoints();
    let had_trusted = !groups.trusted.is_empty();
    let with_check: Vec<_> = groups
        .trusted
        .into_iter()
        .filter(|c| includes(&c.candidate.statement, &check))
        .collect();
    if !with_check.is_empty() {
        return Ok(with_check);
    }
    let degraded = groups
        .degraded
        .iter()
        .filter(|c| includes(&c.statement, &check))
        .count();
    if degraded > 0 && groups.untrusted.is_empty() {
        return Err(failure(
            "degraded",
            format!("only unsigned degraded records exist for check {}", q.check),
            degraded,
        ));
    }
    if !groups.untrusted.is_empty() && !had_trusted {
        return Err(failure(
            groups.untrusted[0].reason,
            format!("no record for check {} is signed by a trusted key", q.check),
            0,
        ));
    }
    if had_trusted {
        return Err(failure(
            "wrong_check",
            format!(
                "trusted records for this tree do not include check {}",
                q.check
            ),
            0,
        ));
    }
    let stale = other_trees_have(q.repo, &legacy, q.tree, q.check).map_err(phase_error)?;
    Err(if stale {
        failure(
            "stale_tree",
            format!("check {} has records only for other trees", q.check),
            0,
        )
    } else {
        failure("no_record", format!("no record for check {}", q.check), 0)
    })
}
#[cfg(all(test, unix))]
#[path = "joined_tests.rs"]
mod joined_tests;
#[cfg(test)]
#[path = "prefix_tests.rs"]
mod tests;

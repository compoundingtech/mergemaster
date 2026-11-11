//! Record structure and subject binding only; signature trust is a separate gate.
use super::{
    statement::{MAX_STATEMENT_BYTES, array, field, statement_of, string},
    statement_document::Document,
};
use crate::{
    evidence::{legacy_policy::PolicyError, oid},
    gate::git::git_bounded,
};
use indexmap::{Equivalent, IndexMap};
use std::{
    ffi::{OsStr, OsString},
    path::Path,
};
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        reason: "error",
        detail: detail.to_string(),
    }
}
/// Read one immutable record. Malformed records refuse; Git failures remain errors.
pub fn read_statement(
    repo: &Path,
    commit: &str,
    tree: Option<&str>,
) -> Result<Option<Document>, PolicyError> {
    oid(commit).map_err(error)?;
    let listing = git_bounded(
        repo,
        &["ls-tree", "-r", "-z", "--end-of-options", commit],
        MAX_STATEMENT_BYTES,
    )
    .map_err(error)?;
    let mut rows = listing.split(|b| *b == 0).filter(|v| !v.is_empty());
    let Some(row) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Ok(None);
    }
    let entry = std::str::from_utf8(row).map_err(error)?;
    let Some((meta, path)) = entry.split_once('\t') else {
        return Ok(None);
    };
    let mut parts = meta.split_whitespace();
    let (Some("100644"), Some("blob"), Some(blob_id), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Ok(None);
    };
    if oid(blob_id).is_err() || oid(path).is_err() || tree.is_some_and(|t| t != path) {
        return Ok(None);
    }
    let size =
        git_bounded(repo, &["cat-file", "-s", "--end-of-options", blob_id], 64).map_err(error)?;
    let size: u64 = std::str::from_utf8(&size)
        .map_err(error)?
        .trim()
        .parse()
        .map_err(error)?;
    if size > MAX_STATEMENT_BYTES as u64 {
        return Err(PolicyError {
            reason: "statement-too-large",
            detail: format!("record statement exceeds {MAX_STATEMENT_BYTES} bytes"),
        });
    }
    // Check object size first for a distinct diagnostic; bound capture independently.
    let blob = git_bounded(
        repo,
        &["cat-file", "blob", "--end-of-options", blob_id],
        MAX_STATEMENT_BYTES,
    )
    .map_err(error)?;
    let Some(doc) = statement_of(&blob, path)? else {
        return Ok(None);
    };
    let subjects = array(field(&doc, doc.root(), "subject").expect("validated subject")).unwrap();
    let name = string(field(&doc, doc.node(subjects[0]), "name").expect("validated name")).unwrap();
    let subject: String = name.iter().map(|p| char::from_u32(*p).unwrap()).collect();
    let raw = git_bounded(
        repo,
        &["cat-file", "commit", "--end-of-options", commit],
        MAX_STATEMENT_BYTES,
    )
    .map_err(error)?;
    let end = raw
        .windows(2)
        .position(|p| p == b"\n\n")
        .unwrap_or(raw.len());
    let header = String::from_utf8_lossy(&raw[..end]);
    let mut parents = header
        .split([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ])
        .filter_map(|line| line.strip_prefix("parent "));
    if parents.next() != Some(subject.as_str()) || parents.next().is_some() {
        return Ok(None);
    }
    // A missing subject is allowed in shallow/partial stores, never lazily fetched.
    // Oracle parity (evidence-verify:758-762): every probe failure counts as absent,
    // not only missing objects. Tighten Python and Rust together after cutover.
    let present = git_bounded(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &format!("{subject}^{{tree}}"),
        ],
        128,
    )
    .ok();
    if present.is_some_and(|v| v.strip_suffix(b"\n").unwrap_or(&v) != path.as_bytes()) {
        return Ok(None);
    }
    Ok(Some(doc))
}

#[derive(Hash, PartialEq, Eq)]
struct Key<R, C, T> {
    repo: R,
    commit: C,
    tree: T,
}
type OwnedKey = Key<OsString, String, Option<String>>;
impl Equivalent<OwnedKey> for Key<&OsStr, &str, Option<&str>> {
    fn equivalent(&self, key: &OwnedKey) -> bool {
        self.repo == key.repo.as_os_str()
            && self.commit == key.commit.as_str()
            && self.tree == key.tree.as_deref()
    }
}
/// Invocation-owned cache of immutable records, including structural refusals.
/// Keys retain exact repository spelling; hits allocate only the returned copy.
#[derive(Default)]
pub struct RecordCache {
    values: IndexMap<OwnedKey, Option<Document>>,
}
impl RecordCache {
    /// Any error, including a cap refusal, must abort the caller's whole check.
    pub fn load(
        &mut self,
        repo: &Path,
        commit: &str,
        tree: Option<&str>,
    ) -> Result<Option<Document>, PolicyError> {
        let key = Key {
            repo: repo.as_os_str(),
            commit,
            tree,
        };
        if let Some(value) = self.values.get(&key) {
            return Ok(value.clone());
        }
        // Failed reads are not inserted, matching assignment only after Python returns.
        let value = read_statement(repo, commit, tree)?;
        self.values.insert(
            Key {
                repo: key.repo.to_owned(),
                commit: commit.to_owned(),
                tree: tree.map(str::to_owned),
            },
            value.clone(),
        );
        Ok(value)
    }
}
#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;

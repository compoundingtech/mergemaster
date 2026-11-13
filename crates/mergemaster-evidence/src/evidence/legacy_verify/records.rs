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
    sync::Arc,
};
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: detail.to_string().into(),
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
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "statement-too-large",
            detail: format!("record statement exceeds {MAX_STATEMENT_BYTES} bytes").into(),
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
const _: () = assert!(std::mem::size_of::<(OwnedKey, Option<Arc<Document>>, usize)>() <= 88);
type OwnedKey = Key<OsString, String, Option<String>>;
impl Equivalent<OwnedKey> for Key<&OsStr, &str, Option<&str>> {
    fn equivalent(&self, key: &OwnedKey) -> bool {
        self.repo == key.repo.as_os_str()
            && self.commit == key.commit.as_str()
            && self.tree == key.tree.as_deref()
    }
}
/// Per candidate/check, never a process-global budget.
pub const MAX_RECORD_UNITS: usize = 4 * 1024 * 1024;
pub const MAX_RECORD_ENTRIES: usize = 8192;
/// Check-owned cache of shared immutable records; hits allocate no document data.
/// Logical units bound ownership, not RSS; refusals latch and abort the whole check.
pub struct RecordCache {
    values: IndexMap<OwnedKey, Option<Arc<Document>>>,
    documents: IndexMap<OwnedKey, Arc<Document>>,
    remaining_units: usize,
    exhausted: bool,
}
impl RecordCache {
    /// Construct once for one candidate/check, shared across its member crates.
    pub fn for_check() -> Self {
        Self {
            values: IndexMap::new(),
            documents: IndexMap::new(),
            remaining_units: MAX_RECORD_UNITS,
            exhausted: false,
        }
    }
    pub(super) fn check_budget(&mut self) -> Result<(), PolicyError> {
        self.charge(0, false)
    }
    fn key_units(key: &Key<&OsStr, &str, Option<&str>>) -> usize {
        key.repo
            .len()
            .saturating_add(key.commit.len())
            .saturating_add(key.tree.map_or(0, str::len))
            .saturating_add(2)
    }
    fn charge(&mut self, units: usize, entry: bool) -> Result<(), PolicyError> {
        if self.exhausted
            || units > self.remaining_units
            || (entry && self.values.len() >= MAX_RECORD_ENTRIES)
        {
            self.exhausted = true;
            return Err(PolicyError {
                origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
                reason: "record-budget-exceeded",
                detail: "check record ownership or cache entry limit exceeded".into(),
            });
        }
        self.remaining_units -= units;
        Ok(())
    }
    /// Any error, including a cap refusal, must abort the caller's whole check.
    pub fn load(
        &mut self,
        repo: &Path,
        commit: &str,
        tree: Option<&str>,
    ) -> Result<Option<Arc<Document>>, PolicyError> {
        let key = Key {
            repo: repo.as_os_str(),
            commit,
            tree,
        };
        if let Some(index) = self.values.get_index_of(&key) {
            self.charge(0, false)?;
            return Ok(self.values[index].clone());
        }
        // Refuse an exhausted invocation/entry limit before reading another record.
        self.charge(0, true)?;
        // Failed reads are not inserted, matching assignment only after Python returns.
        let parsed = read_statement(repo, commit, tree)?;
        let identity = Key {
            repo: key.repo,
            commit,
            tree: None,
        };
        let retained = self.documents.get(&identity).cloned();
        let extra = if parsed.is_some() && retained.is_none() {
            parsed
                .as_ref()
                .map_or(0, Document::ownership_units)
                .saturating_add(Self::key_units(&identity))
        } else {
            0
        };
        self.charge(Self::key_units(&key).saturating_add(extra), true)?;
        let value = parsed.map(|document| {
            retained.unwrap_or_else(|| {
                let document = Arc::new(document);
                self.documents.insert(
                    OwnedKey {
                        repo: key.repo.to_owned(),
                        commit: commit.to_owned(),
                        tree: None,
                    },
                    Arc::clone(&document),
                );
                document
            })
        });
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

//! Candidate indexes and structural statements confer no signature trust.
use super::{
    discovery, projection,
    records::RecordCache,
    statement::{field, string},
    statement_document::Document,
};
use crate::evidence::legacy_policy::PolicyError;
use indexmap::{IndexMap, IndexSet};
use std::{path::Path, sync::Arc};

pub struct Candidate {
    pub commit: String,
    pub statement: Arc<Document>,
}
fn input<'a>(doc: &'a Document, key: &str) -> Option<&'a [u32]> {
    let predicate = field(doc, doc.root(), "predicate")?;
    let observed = field(doc, predicate, "observed")?;
    string(field(doc, field(doc, observed, "inputs")?, key)?)
}
fn equals(points: Option<&[u32]>, value: &str) -> bool {
    points.is_some_and(|p| p.iter().copied().eq(value.chars().map(u32::from)))
}
/// Python's default needs_tests=False contract only; no test-count policy yet.
pub fn signed_for_crate(doc: &Document, name: &str, key: &str) -> bool {
    equals(input(doc, "crate"), name) && equals(input(doc, "source_inputs"), key)
}
/// One owner per candidate check; reuse across that check's member crates.
pub struct CandidateCollector {
    cache: RecordCache,
}
impl CandidateCollector {
    pub fn for_check() -> Self {
        Self {
            cache: RecordCache::for_check(),
        }
    }
    /// Return the entire ordered structural candidate set, or abort on any error.
    /// `inputs` is rules.inputs, not an authorization decision. Crate binding wins.
    pub fn collect(
        &mut self,
        repo: &Path,
        tree: &str,
        check: &str,
        inputs: Option<&[String]>,
        crate_key: Option<(&str, &str)>,
    ) -> Result<Vec<Candidate>, PolicyError> {
        self.cache.check_budget()?;
        let legacy = discovery::legacy_refs(repo, tree.len())?;
        let commits: Vec<_> = discovery::tree_refs(repo, tree)?
            .into_iter()
            .chain(legacy)
            .collect::<IndexSet<_>>()
            .into_iter()
            .collect();
        let mut mine = IndexMap::new();
        for commit in discovery::with_note_for(repo, &commits, tree)? {
            if let Some(statement) = self.cache.load(repo, commit, Some(tree))? {
                mine.insert(commit.to_owned(), statement);
            }
        }
        let input_key = if let Some((name, key)) = crate_key {
            mine.retain(|_, statement| signed_for_crate(statement, name, key));
            Some(key.to_owned())
        } else if let Some(paths) = inputs {
            projection::project(repo, tree, paths)?
        } else {
            None
        };
        if let Some(key) = input_key {
            for commit in discovery::input_refs(repo, check, &key)? {
                if mine.contains_key(&commit) {
                    continue;
                }
                if let Some(statement) = self.cache.load(repo, &commit, None)?
                    && equals(input(&statement, "source_inputs"), &key)
                    && crate_key.is_none_or(|(name, k)| signed_for_crate(&statement, name, k))
                {
                    mine.insert(commit, statement);
                }
            }
        }
        Ok(mine
            .into_iter()
            .map(|(commit, statement)| Candidate { commit, statement })
            .collect())
    }
}
#[cfg(test)]
#[path = "collection_tests.rs"]
mod tests;

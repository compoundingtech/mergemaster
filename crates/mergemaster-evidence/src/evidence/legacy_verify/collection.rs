//! Candidate indexes and structural statements confer no signature trust.
use super::{
    discovery, projection, python_digits,
    records::RecordCache,
    statement::{field, string},
    statement_document::{Document, Node},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{
    PolicyError, check_names::CheckName, normalized_text::NormalizedText,
};
use indexmap::{IndexMap, IndexSet};
use std::{path::Path, sync::Arc};

pub struct Candidate {
    pub commit: String,
    pub statement: Arc<Document>,
}
pub struct Collected {
    pub records: Vec<Candidate>,
    pub legacy: Vec<String>,
    pub input_key: Option<String>,
}
fn input_node<'a>(doc: &'a Document, key: &str) -> Option<&'a Node> {
    let predicate = field(doc, doc.root(), "predicate")?;
    let observed = field(doc, predicate, "observed")?;
    field(doc, field(doc, observed, "inputs")?, key)
}
fn input<'a>(doc: &'a Document, key: &str) -> Option<&'a [u32]> {
    string(input_node(doc, key)?)
}
fn equals(points: Option<&[u32]>, value: &str) -> bool {
    points.is_some_and(|p| p.iter().copied().eq(value.chars().map(u32::from)))
}
#[derive(Clone, Copy)]
pub struct CrateBinding<'a> {
    pub name: TextRef<'a>,
    pub key: &'a str,
    pub needs_tests: bool,
}
/// Exact signed crate/key binding and optional positive Python test count.
pub fn signed_for_crate(doc: &Document, binding: CrateBinding<'_>) -> Result<bool, PolicyError> {
    if !input(doc, "crate").is_some_and(|name| name.iter().copied().eq(binding.name.points()))
        || !equals(input(doc, "source_inputs"), binding.key)
    {
        return Ok(false);
    }
    if !binding.needs_tests {
        return Ok(true);
    }
    let ran = match input_node(doc, "tests_run") {
        Some(Node::String(ran)) => ran,
        // All other Python str(value) spellings contain nondigits. Integers alone
        // can spell a positive decimal; avoid allocating their identical str().
        Some(Node::Integer(ran)) => {
            return Ok(!ran.starts_with('-') && ran.bytes().any(|b| b != b'0'));
        }
        _ => return Ok(false),
    };
    if ran.is_empty() || !ran.iter().all(|p| python_digits::is_digit(*p)) {
        return Ok(false);
    }
    let positive = ran.iter().try_fold(false, |positive, point| {
        python_digits::decimal(*point).map(|digit| positive || digit != 0)
    });
    let Some(positive) = positive else {
        // Every isdigit character is printable and quote-free. Bound the input
        // before formatting, then retain int()'s first 200 repr codepoints.
        let mut detail = format!(
            "invalid literal for int() with base 10: {}",
            super::python_repr::Repr(TextRef::Points(&ran[..ran.len().min(199)]))
        );
        if let Some((end, _)) = detail.char_indices().nth(240) {
            detail.truncate(end);
        }
        return Err(test_count_error(detail));
    };
    if ran.len() > 4300 {
        return Err(test_count_error(format!(
            "Exceeds the limit (4300 digits) for integer string conversion: value has {} digits; use sys.set_int_max_str_digits() to increase the limit",
            ran.len()
        )));
    }
    Ok(positive)
}
fn test_count_error(detail: String) -> PolicyError {
    PolicyError {
        resource: None,
        origin: crate::evidence::legacy_policy::ErrorOrigin::Exception {
            class: "ValueError",
        },
        reason: "error",
        detail: detail.into(),
    }
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
    pub fn collect<'a>(
        &mut self,
        repo: &Path,
        tree: &str,
        check: impl Into<CheckName<'a>>,
        inputs: Option<&[NormalizedText]>,
        crate_key: Option<CrateBinding<'_>>,
    ) -> Result<Collected, PolicyError> {
        self.cache.check_budget()?;
        let legacy = discovery::legacy_refs(repo, tree.len())?;
        let mut commits: IndexSet<_> = discovery::tree_refs(repo, tree)?.into_iter().collect();
        for commit in &legacy {
            if !commits.contains(commit) {
                commits.insert(commit.clone());
            }
        }
        let commits: Vec<_> = commits.into_iter().collect();
        let mut mine = IndexMap::new();
        for commit in discovery::with_note_for(repo, &commits, tree)? {
            if let Some(statement) = self.cache.load(repo, commit, Some(tree))? {
                mine.insert(commit.to_owned(), statement);
            }
        }
        let input_key = if let Some(binding) = crate_key {
            let mut failure = None;
            mine.retain(|_, statement| {
                if failure.is_some() {
                    return true;
                }
                match signed_for_crate(statement, binding) {
                    Ok(keep) => keep,
                    Err(error) => {
                        failure = Some(error);
                        false
                    }
                }
            });
            if let Some(error) = failure {
                return Err(error);
            }
            Some(binding.key.to_owned())
        } else if let Some(paths) = inputs {
            projection::project(repo, tree, paths)?
        } else {
            None
        };
        if let Some(key) = input_key.as_deref() {
            for commit in discovery::input_refs(repo, check, key)? {
                if mine.contains_key(&commit) {
                    continue;
                }
                if let Some(statement) = self.cache.load(repo, &commit, None)?
                    && equals(input(&statement, "source_inputs"), key)
                    && match crate_key {
                        Some(binding) => signed_for_crate(&statement, binding)?,
                        None => true,
                    }
                {
                    mine.insert(commit, statement);
                }
            }
        }
        Ok(Collected {
            records: mine
                .into_iter()
                .map(|(commit, statement)| Candidate { commit, statement })
                .collect(),
            legacy,
            input_key,
        })
    }
}
#[cfg(test)]
#[path = "collection_tests.rs"]
mod tests;

//! Per-crate source-input keys composed from declared paths and legacy projection.
use super::{
    crate_input_document::Inputs,
    crate_inputs::{TreeSource, failure},
    projection::project_with_fetch,
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use indexmap::IndexMap;

pub struct CrateKey {
    pub key: Option<String>,
    pub paths: Vec<NormalizedText>,
}
type KeyPaths = IndexMap<String, Vec<NormalizedText>>;
impl TreeSource<'_> {
    /// Like rust-test-keys main: resolve the candidate before reading selected inputs.
    pub fn keys_from(
        &self,
        inputs_from: Option<&str>,
        only: &[String],
    ) -> Result<IndexMap<String, CrateKey>, PolicyError> {
        let tree = self.resolve()?;
        let inputs = TreeSource {
            repo: self.repo,
            tree: inputs_from.filter(|s| !s.is_empty()).unwrap_or(&tree),
            no_lazy_fetch: self.no_lazy_fetch,
        }
        .read_inputs()?;
        TreeSource {
            repo: self.repo,
            tree: &tree,
            no_lazy_fetch: self.no_lazy_fetch,
        }
        .keys(&inputs, only)
    }
    pub fn keys(
        &self,
        inputs: &Inputs,
        only: &[String],
    ) -> Result<IndexMap<String, CrateKey>, PolicyError> {
        let (tree, paths) = self.key_paths(inputs, only)?;
        project_keys(self.repo, &tree, paths, self.no_lazy_fetch)
    }
    fn key_paths(
        &self,
        inputs: &Inputs,
        only: &[String],
    ) -> Result<(String, KeyPaths), PolicyError> {
        let tree = self.resolve()?;
        let paths = TreeSource {
            repo: self.repo,
            tree: &tree,
            no_lazy_fetch: self.no_lazy_fetch,
        }
        .declared_paths(inputs)?;
        let unknown: Vec<_> = only
            .iter()
            .filter(|name| !paths.contains_key(*name))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            return Err(failure(format!(
                "not a workspace crate of this tree: {}",
                unknown.join(", ")
            )));
        }
        Ok((
            tree,
            paths
                .into_iter()
                .filter(|(name, _)| only.is_empty() || only.contains(name))
                .collect(),
        ))
    }
}
fn project_keys(
    repo: &std::path::Path,
    tree: &str,
    paths: KeyPaths,
    no_lazy_fetch: bool,
) -> Result<IndexMap<String, CrateKey>, PolicyError> {
    paths
        .into_iter()
        .map(|(name, paths)| {
            let key = project_with_fetch(repo, tree, &paths, no_lazy_fetch)?;
            Ok((name, CrateKey { key, paths }))
        })
        .collect()
}
/// Verifier member mode reads accepted-base inputs before resolving the candidate.
/// Each subprocess disables lazy fetching without changing inherited process state.
pub fn member_keys(
    repo: &std::path::Path,
    tree: &str,
    policy_base: Option<TextRef<'_>>,
) -> Result<IndexMap<String, Option<String>>, PolicyError> {
    let base = policy_base.filter(|base| !base.equals("")).ok_or_else(|| {
        failure("--members needs --policy-from: the keys are defined by the accepted base")
    })?;
    let load = || {
        let inputs = Inputs::read_from(repo, base, true)?;
        TreeSource {
            repo,
            tree,
            no_lazy_fetch: true,
        }
        .key_paths(&inputs, &[])
    };
    // Python catches only rust-test-keys failures, not verifier projection failures.
    let (resolved, paths) = load().map_err(|mut error| {
        if error.origin == crate::evidence::legacy_policy::ErrorOrigin::Failure {
            error.detail = NormalizedText::around("per-crate keys: ", error.detail.borrowed(), "");
        }
        error
    })?;
    let members: IndexMap<_, _> = project_keys(repo, &resolved, paths, true)?
        .into_iter()
        .map(|(name, value)| (name, value.key))
        .collect();
    if members.is_empty() {
        return Err(failure(
            "the tree has no workspace member: nothing to cover is not a pass",
        ));
    }
    Ok(members)
}
#[cfg(test)]
#[path = "crate_keys_tests.rs"]
mod tests;

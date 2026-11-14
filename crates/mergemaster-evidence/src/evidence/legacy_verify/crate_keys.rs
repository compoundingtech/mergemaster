//! Per-crate source-input keys composed from declared paths and legacy projection.
use super::{
    crate_input_document::Inputs,
    crate_inputs::{TreeSource, failure},
    projection::project_with_fetch,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use indexmap::IndexMap;

pub struct CrateKey {
    pub key: Option<String>,
    pub paths: Vec<NormalizedText>,
}
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
        paths
            .into_iter()
            .filter(|(name, _)| only.is_empty() || only.contains(name))
            .map(|(name, paths)| {
                let key = project_with_fetch(self.repo, &tree, &paths, self.no_lazy_fetch)?;
                Ok((name, CrateKey { key, paths }))
            })
            .collect()
    }
}
#[cfg(test)]
#[path = "crate_keys_tests.rs"]
mod tests;

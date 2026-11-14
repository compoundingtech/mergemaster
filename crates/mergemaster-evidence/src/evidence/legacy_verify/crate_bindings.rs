//! Construct actual member/explicit bindings from the accepted base's allowance.
use super::{
    collection::CrateBinding, crate_key_argument::ParsedCrateKey, crate_keys::member_keys,
    value_inputs::TextRef, zero_test_crates::zero_test_crates,
};
use crate::evidence::legacy_policy::PolicyError;
use indexmap::IndexMap;
use std::{collections::BTreeSet, path::Path};

/// Member keys are read first; only then read the standalone no-tests allowance.
/// This is verification preparation, not `--project` (which stops after keys).
pub struct Members {
    pub keys: IndexMap<String, Option<String>>,
    no_tests: BTreeSet<Vec<u32>>,
}
impl Members {
    pub fn read(repo: &Path, tree: &str, policy_base: Option<&str>) -> Result<Self, PolicyError> {
        let keys = member_keys(repo, tree, policy_base)?;
        let no_tests = match policy_base {
            Some(base) => zero_test_crates(repo, base)?,
            // member_keys has already refused an absent or empty base.
            None => BTreeSet::new(),
        };
        Ok(Self { keys, no_tests })
    }
    /// A missing key is retained, not silently dropped or treated as satisfied.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Option<CrateBinding<'_>>)> {
        self.keys.iter().map(|(name, key)| {
            let name_ref = TextRef::Str(name);
            (
                name.as_str(),
                key.as_deref().map(|key| CrateBinding {
                    name: name_ref,
                    key,
                    needs_tests: !listed(&self.no_tests, name_ref),
                }),
            )
        })
    }
}
fn listed(names: &BTreeSet<Vec<u32>>, name: TextRef<'_>) -> bool {
    match name {
        TextRef::Points(points) => names.contains(points),
        TextRef::Str(_) => names
            .iter()
            .any(|points| points.iter().copied().eq(name.points())),
    }
}
impl ParsedCrateKey<'_> {
    /// No accepted base means no count requirement and no allowance read.
    /// Otherwise preserve the standalone reader's error source unchanged.
    pub fn binding(
        &self,
        repo: &Path,
        policy_base: Option<&str>,
    ) -> Result<CrateBinding<'_>, PolicyError> {
        let needs_tests = if let Some(base) = policy_base.filter(|base| !base.is_empty()) {
            !listed(&zero_test_crates(repo, base)?, self.name)
        } else {
            false
        };
        Ok(CrateBinding {
            name: self.name,
            key: &self.key,
            needs_tests,
        })
    }
}

#[cfg(test)]
#[path = "crate_bindings_tests.rs"]
mod tests;

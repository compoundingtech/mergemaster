//! Order-preserving port of rust-test-keys' memoized dependency walk.
use super::{
    crate_inputs::TreeSource,
    crate_manifest_ops::{dependency_paths, object},
    toml::Value,
};
use crate::evidence::legacy_policy::PolicyError;
use indexmap::IndexMap;
use std::collections::BTreeSet;
const DEP_TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
#[derive(Default)]
pub struct ClosureCache {
    entries: IndexMap<String, BTreeSet<String>>,
}
struct Frame {
    index: usize,
    tables: std::vec::IntoIter<Option<Value>>,
    children: std::vec::IntoIter<String>,
}
impl ClosureCache {
    pub fn paths(&self, directory: &str) -> Option<&BTreeSet<String>> {
        self.entries.get(directory)
    }
    fn insert(&mut self, directory: String) -> usize {
        let set = BTreeSet::from([directory.clone()]);
        self.entries.insert_full(directory, set).0
    }
    fn union_existing(&mut self, parent: usize, child: usize) {
        if parent == child {
            return;
        }
        if let Ok([(_, parent), (_, child)]) = self
            .entries
            .as_mut_slice()
            .get_disjoint_mut([parent, child])
        {
            for path in child.iter() {
                if !parent.contains(path) {
                    parent.insert(path.clone());
                }
            }
        }
    }
}
impl TreeSource<'_> {
    fn dependency_tables(&self, directory: &str) -> Result<Vec<Option<Value>>, PolicyError> {
        let mut parsed = self.manifest(directory)?;
        // Match Python's eager target lookup, but keep each dependency table lazy.
        let mut tables: Vec<_> = DEP_TABLES
            .iter()
            .map(|kind| parsed.shift_remove(*kind))
            .collect();
        let mut targets = parsed.shift_remove("target");
        object(targets.as_ref(), true, "values")?;
        if let Some(Value::Table(targets)) = targets.as_mut() {
            for target in targets.values_mut() {
                object(Some(target), false, "get")?;
                if let Value::Table(target) = target {
                    tables.extend(DEP_TABLES.iter().map(|kind| target.shift_remove(*kind)));
                }
            }
        }
        Ok(tables)
    }
    fn start_frame(
        &self,
        directory: String,
        cache: &mut ClosureCache,
    ) -> Result<Frame, PolicyError> {
        let tables = self.dependency_tables(&directory);
        // Preserve the installed singleton even when manifest evaluation refuses.
        let index = cache.insert(directory);
        Ok(Frame {
            index,
            tables: tables?.into_iter(),
            children: Vec::new().into_iter(),
        })
    }
    /// Populate the cache without recursively using the native thread stack.
    pub fn closure(
        &self,
        directory: &str,
        workspace: Option<&Value>,
        cache: &mut ClosureCache,
    ) -> Result<(), PolicyError> {
        if cache.entries.contains_key(directory) {
            return Ok(());
        }
        let mut stack = vec![self.start_frame(directory.into(), cache)?];
        while let Some(frame) = stack.last_mut() {
            if let Some(child) = frame.children.next() {
                if let Some(index) = cache.entries.get_index_of(&child) {
                    cache.union_existing(frame.index, index);
                } else {
                    stack.push(self.start_frame(child, cache)?);
                }
            } else if let Some(table) = frame.tables.next()
                && let Some((directory, _)) = cache.entries.get_index(frame.index)
            {
                frame.children =
                    dependency_paths(table.as_ref(), directory, workspace)?.into_iter();
            } else if let Some(completed) = stack.pop()
                && let Some(parent) = stack.last()
            {
                cache.union_existing(parent.index, completed.index);
            }
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "crate_closure_tests.rs"]
mod tests;

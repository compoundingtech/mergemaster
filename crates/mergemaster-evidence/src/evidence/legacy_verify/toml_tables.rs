//! Namespace bookkeeping ported from CPython 3.14.7 `tomllib._parser`.
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Flag {
    Frozen,
    ExplicitNest,
}

impl Flag {
    const fn bit(self) -> u8 {
        match self {
            Self::Frozen => 1,
            Self::ExplicitNest => 2,
        }
    }
}

#[derive(Default)]
struct Node {
    flags: u8,
    recursive: u8,
    nested: BTreeMap<String, Node>,
}

impl Drop for Node {
    fn drop(&mut self) {
        let mut pending: Vec<_> = std::mem::take(&mut self.nested).into_values().collect();
        while let Some(mut node) = pending.pop() {
            pending.extend(std::mem::take(&mut node.nested).into_values());
        }
    }
}

#[derive(Default)]
pub struct Flags {
    flags: BTreeMap<String, Node>,
    pending: BTreeSet<(Vec<String>, Flag)>,
}

impl Flags {
    pub fn add_pending(&mut self, key: &[String], flag: Flag) {
        self.pending.insert((key.to_vec(), flag));
    }

    pub fn finalize_pending(&mut self) {
        for (key, flag) in std::mem::take(&mut self.pending) {
            self.set(&key, flag, false);
        }
    }

    /// Remove every flag in the subtree at `key`.
    ///
    /// An empty path deliberately does nothing. Python raises `IndexError`,
    /// but the parser never produces an empty key.
    pub fn unset_all(&mut self, key: &[String]) {
        let Some((stem, parent)) = key.split_last() else {
            return;
        };
        let mut cont = &mut self.flags;
        for part in parent {
            let Some(node) = cont.get_mut(part) else {
                return;
            };
            cont = &mut node.nested;
        }
        cont.remove(stem);
    }

    /// Set a flag at `key`, optionally applying it recursively.
    ///
    /// An empty path deliberately does nothing. Python raises `IndexError`,
    /// but the parser never produces an empty key.
    pub fn set(&mut self, key: &[String], flag: Flag, recursive: bool) {
        let Some((stem, parent)) = key.split_last() else {
            return;
        };
        let mut cont = &mut self.flags;
        for part in parent {
            cont = &mut cont.entry(part.clone()).or_default().nested;
        }
        let node = cont.entry(stem.clone()).or_default();
        if recursive {
            node.recursive |= flag.bit();
        } else {
            node.flags |= flag.bit();
        }
    }

    pub fn is(&self, key: &[String], flag: Flag) -> bool {
        let Some((stem, parent)) = key.split_last() else {
            return false;
        };
        let mut cont = &self.flags;
        for part in parent {
            let Some(node) = cont.get(part) else {
                return false;
            };
            if node.recursive & flag.bit() != 0 {
                return true;
            }
            cont = &node.nested;
        }
        cont.get(stem)
            .is_some_and(|node| (node.flags | node.recursive) & flag.bit() != 0)
    }
}

#[cfg(test)]
#[path = "toml_tables_tests.rs"]
mod tests;

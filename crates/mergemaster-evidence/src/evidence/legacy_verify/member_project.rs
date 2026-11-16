//! `--project --members` result, stopping before allowance/policy/record reads.
use super::{crate_keys::member_keys, value_inputs::TextRef};
use crate::evidence::{
    legacy_output::{ValueWriter, Written},
    legacy_policy::{PolicyError, check_names::CheckName},
};
use indexmap::IndexMap;
use std::{
    fmt::{self, Write},
    path::Path,
};

pub struct MemberProject<'a> {
    pub tree: &'a str,
    pub check: CheckName<'a>,
    keys: IndexMap<String, Option<String>>,
}
impl<'a> MemberProject<'a> {
    pub fn read(
        repo: &Path,
        tree: &'a str,
        check: CheckName<'a>,
        policy_base: Option<&str>,
    ) -> Result<Self, PolicyError> {
        if !matches!(tree.len(), 40 | 64)
            || !tree
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(super::crate_inputs::failure(
                "expected a full lowercase Git tree ID",
            ));
        }
        let mut keys = member_keys(repo, tree, policy_base)?;
        keys.sort_keys();
        Ok(Self { tree, check, keys })
    }
    /// Exactly the project dictionary, with sorted crate keys and both fetch
    /// namespaces. A missing projected key emits null and an empty refspec list.
    /// JSON escapes controls/surrogates; no raw terminal sink is installed here.
    pub fn write_json<'s>(
        &self,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        writer.object(|o| {
            o.field_text("crates", |w| {
                w.object(|o| {
                    for (name, key) in &self.keys {
                        o.field_text(name, |w| {
                            w.object(|o| {
                                o.field_text("key", |w| match key {
                                    Some(key) => w.text(key),
                                    None => w.null(),
                                })?;
                                o.field_text("refspecs", |w| {
                                    w.array(|a| {
                                        if let Some(key) =
                                            key.as_deref().filter(|key| !key.is_empty())
                                        {
                                            for namespace in [
                                                "refs/tags/evidence/input/",
                                                "refs/notes/evidence-input/",
                                            ] {
                                                a.item(|w| {
                                                    w.codepoints(
                                                        [
                                                            TextRef::Str("+"),
                                                            TextRef::Str(namespace),
                                                            self.check.text(),
                                                            TextRef::Str("/"),
                                                            TextRef::Str(key),
                                                            TextRef::Str("/*:"),
                                                            TextRef::Str(namespace),
                                                            self.check.text(),
                                                            TextRef::Str("/"),
                                                            TextRef::Str(key),
                                                            TextRef::Str("/*"),
                                                        ]
                                                        .into_iter()
                                                        .flat_map(TextRef::points),
                                                    )
                                                })?;
                                            }
                                        }
                                        Ok(())
                                    })
                                })?;
                                Ok(())
                            })
                        })?;
                    }
                    Ok(())
                })
            })?;
            o.field_text("members", |w| w.integer(self.keys.len() as i128))?;
            o.field_text("tree", |w| w.text(self.tree))?;
            o.field_text("check", |w| w.codepoints(self.check.text().points()))?;
            Ok(())
        })
    }
}
#[cfg(test)]
#[path = "member_project_tests.rs"]
mod tests;

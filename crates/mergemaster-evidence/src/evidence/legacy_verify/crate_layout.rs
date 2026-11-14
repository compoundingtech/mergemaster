//! Workspace discovery from committed manifests, without Cargo execution.
use super::{
    crate_inputs::{TreeSource, failure, joined, normpath, utf8},
    crate_manifest_ops::{self as ops, object, truthy},
    python_repr::Repr,
    toml::{Table, Value},
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::PolicyError;
use indexmap::IndexMap;
use std::collections::BTreeSet;
pub struct Layout {
    pub members: IndexMap<String, String>,
    pub patched: Vec<String>,
    pub root: Table,
}
impl TreeSource<'_> {
    fn member(&self, value: &Value, out: &mut Vec<String>) -> Result<(), PolicyError> {
        if let Value::String(s) = value {
            return self.member_str(s, out);
        }
        if ops::contains_star(value)? {
            return Err(ops::attribute(value, "endswith"));
        }
        out.push(ops::path(value, None)?);
        Ok(())
    }
    fn member_str(&self, member: &str, out: &mut Vec<String>) -> Result<(), PolicyError> {
        if !member.contains('*') {
            out.push(normpath(member));
            return Ok(());
        }
        if !member.ends_with("/*") || member[..member.len() - 2].contains('*') {
            return Err(failure(format!(
                "workspace member glob {} is not supported",
                Repr(TextRef::Str(member))
            )));
        }
        let listing = self.git(&[
            "ls-tree",
            "-d",
            "--name-only",
            self.tree,
            &member[..member.len() - 1],
        ])?;
        let text = utf8(&listing.stdout).map_err(|e| ops::exception("UnicodeDecodeError", e))?;
        let mut names: Vec<_> = text
            .split([
                '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
                '\u{2029}',
            ])
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        names.sort();
        out.extend(names);
        Ok(())
    }
    pub fn expand_members(&self, value: Option<&Value>) -> Result<Vec<String>, PolicyError> {
        let mut out = Vec::new();
        match value.filter(|v| truthy(v)) {
            None => {}
            Some(Value::Array(a)) => {
                for v in a {
                    self.member(v, &mut out)?;
                }
            }
            Some(Value::Table(t)) => {
                for key in t.keys() {
                    self.member_str(key, &mut out)?;
                }
            }
            Some(Value::String(s)) => {
                for c in s.chars() {
                    let mut bytes = [0; 4];
                    self.member_str(c.encode_utf8(&mut bytes), &mut out)?;
                }
            }
            Some(v) => {
                return Err(ops::exception(
                    "TypeError",
                    format!("'{}' object is not iterable", ops::type_name(v)),
                ));
            }
        }
        Ok(out)
    }
    pub fn layout(&self) -> Result<Layout, PolicyError> {
        let root = self.manifest(".")?;
        let workspace = object(root.get("workspace"), true, "get")?;
        let mut directories = self.expand_members(workspace.and_then(|t| t.get("members")))?;
        if root.contains_key("package") {
            directories.insert(0, ".".into());
        }
        let mut patched = BTreeSet::new();
        for table in object(root.get("patch"), true, "values")?
            .into_iter()
            .flat_map(|t| t.values())
        {
            for spec in object(Some(table), false, "values")?
                .into_iter()
                .flat_map(|t| t.values())
            {
                if let Value::Table(t) = spec
                    && let Some(path) = t.get("path")
                {
                    patched.insert(ops::path(path, None)?);
                }
            }
        }
        let mut members = IndexMap::new();
        for directory in directories {
            let manifest = self.manifest(&directory)?;
            if let Some(name) =
                object(manifest.get("package"), false, "get")?.and_then(|t| t.get("name"))
            {
                let Value::String(name) = name else {
                    return Err(failure(format!(
                        "{}: package.name is not a string",
                        joined(&directory, "Cargo.toml")
                    )));
                };
                if !name.is_empty() {
                    members.insert(name.clone(), directory);
                }
            }
        }
        Ok(Layout {
            members,
            patched: patched.into_iter().collect(),
            root,
        })
    }
}
#[cfg(test)]
#[path = "crate_layout_tests.rs"]
mod tests;

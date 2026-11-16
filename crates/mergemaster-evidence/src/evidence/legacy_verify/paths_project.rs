//! Paths-only `--project`, without policy loading or production CLI dispatch.
use super::{projection, value_inputs::TextRef};
use crate::evidence::{
    legacy_output::{ValueWriter, Written},
    legacy_policy::{
        PolicyError, check_names::CheckName, declared_path_items, normalized_text::NormalizedText,
    },
};
use std::{
    fmt::{self, Write},
    path::Path,
};

pub struct PathsProject<'a> {
    pub tree: &'a str,
    pub check: CheckName<'a>,
    pub paths: Option<Vec<NormalizedText>>,
    pub source_inputs: Option<String>,
}
pub(super) fn validate_tree(tree: &str) -> Result<(), PolicyError> {
    if !matches!(tree.len(), 40 | 64)
        || !tree
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(super::crate_inputs::failure(
            "expected a full lowercase Git tree ID",
        ));
    }
    Ok(())
}
impl<'a> PathsProject<'a> {
    /// With no --paths, both paths and source_inputs are null. A supplied empty
    /// list refuses instead; comma filtering precedes declared-path validation.
    pub fn read(
        repo: &Path,
        tree: &'a str,
        check: CheckName<'a>,
        argument: Option<TextRef<'_>>,
    ) -> Result<Self, PolicyError> {
        validate_tree(tree)?;
        let paths = argument
            .map(|argument| {
                let parts: Vec<_> = match argument {
                    TextRef::Str(s) => s
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(TextRef::Str)
                        .collect(),
                    TextRef::Points(p) => p
                        .split(|p| *p == 44)
                        .filter(|p| !p.is_empty())
                        .map(TextRef::Points)
                        .collect(),
                };
                declared_path_items(
                    Some(parts.into_iter().map(Some)),
                    &[TextRef::Str("--paths")],
                    false,
                )
                .map(|paths| {
                    paths
                        .into_iter()
                        .map(NormalizedText::from)
                        .collect::<Vec<_>>()
                })
            })
            .transpose()?;
        let source_inputs = paths
            .as_deref()
            .map(|paths| projection::project(repo, tree, paths))
            .transpose()?
            .flatten();
        Ok(Self {
            tree,
            check,
            paths,
            source_inputs,
        })
    }
    /// JSON escapes controls/surrogates and preserves unbounded output length.
    /// This proves only the wire sink; #245 still governs terminal diagnostics.
    pub fn write_json<'s>(
        &self,
        writer: ValueWriter<'s, '_, impl Write>,
    ) -> Result<Written<'s>, fmt::Error> {
        writer.object(|o| {
            o.field_text("source_inputs", |w| match &self.source_inputs {
                Some(key) => w.text(key),
                None => w.null(),
            })?;
            o.field_text("paths", |w| match &self.paths {
                Some(paths) => w.array(|a| {
                    for path in paths {
                        a.item(|w| w.codepoints(path.borrowed().points()))?;
                    }
                    Ok(())
                }),
                None => w.null(),
            })?;
            o.field_text("tree", |w| w.text(self.tree))?;
            o.field_text("check", |w| w.codepoints(self.check.text().points()))?;
            o.field_text("base_inputs", |w| w.object(|_| Ok(())))?;
            Ok(())
        })
    }
}
#[cfg(test)]
#[path = "paths_project_tests.rs"]
mod tests;

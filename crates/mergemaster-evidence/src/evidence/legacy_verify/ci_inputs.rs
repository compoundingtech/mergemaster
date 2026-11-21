//! CI input existence is checked before equality: two missing inputs never agree.
use super::{
    binding_path::encode, crate_inputs_text::utf8, crate_manifest_ops::exception,
    projection::read_git_source, projection_oid::space, source_resource::SourceResource,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

/// Preserve declaration order, including duplicate unresolved entries. Exclusions
/// and the whole-tree marker do not need to resolve. Selector errors propagate.
pub fn unresolved_ci_inputs<'a>(
    repo: &Path,
    tree: &OsStr,
    inputs: &'a [NormalizedText],
) -> Result<Vec<&'a NormalizedText>, PolicyError> {
    let mut unresolved = Vec::new();
    for input in inputs {
        let item = input.borrowed();
        if item.starts_with("!") || item.equals(".") {
            continue;
        }
        let found = if item.split_once("::").is_some() {
            super::helper_selection::selected(repo, tree, item)?
                .is_some_and(|part| !part.is_empty())
        } else {
            let encoded = encode(item, 0, true)?;
            let listing = read_git_source(
                repo,
                &[
                    OsStr::new("ls-tree"),
                    OsStr::new("--full-tree"),
                    tree,
                    OsStr::new("--"),
                    OsStr::from_bytes(&encoded),
                ],
                SourceResource::TreeListing(super::cli_adapter::decode(tree)),
            )?;
            listing.iter().any(|byte| !byte.is_ascii_whitespace())
        };
        if !found {
            unresolved.push(input);
        }
    }
    Ok(unresolved)
}

/// Resolve every revision first, then every declaration, and only then project.
/// In particular an invalid later revision must not be hidden by an earlier
/// unresolved input. An empty revision list is false, as in the Python set test.
pub fn ci_inputs_unchanged(
    repo: &Path,
    inputs: &[NormalizedText],
    revisions: &[NormalizedText],
) -> Result<bool, PolicyError> {
    let trees = revisions
        .iter()
        .map(|revision| {
            let expression = NormalizedText::around("", revision.borrowed(), "^{tree}");
            let encoded = encode(expression.borrowed(), 0, true)?.into_owned();
            let shown = read_git_source(
                repo,
                &[
                    OsStr::new("rev-parse"),
                    OsStr::new("--verify"),
                    OsStr::new("--end-of-options"),
                    OsStr::from_bytes(&encoded),
                ],
                SourceResource::RawBlob(expression),
            )?;
            Ok(utf8(&shown)
                .map_err(|detail| exception("UnicodeDecodeError", detail))?
                .trim_matches(space)
                .to_owned())
        })
        .collect::<Result<Vec<_>, PolicyError>>()?;
    for tree in &trees {
        if !unresolved_ci_inputs(repo, OsStr::new(tree), inputs)?.is_empty() {
            return Ok(false);
        }
    }
    let Some((first, rest)) = trees.split_first() else {
        return Ok(false);
    };
    let first = super::projection::project_for_helper(repo, first, inputs)?;
    let mut equal = true;
    for tree in rest {
        // Do not short-circuit: Python projects every revision before comparing.
        equal &= super::projection::project_for_helper(repo, tree, inputs)? == first;
    }
    Ok(equal)
}

#[cfg(test)]
#[path = "ci_inputs_tests.rs"]
mod tests;

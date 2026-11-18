//! CLI lane Git reads use oracle transport, independently of native lane APIs.
use super::{
    binding_path::encode, crate_manifest_ops::exception, lanes::DefinitionEntry,
    projection::read_git_source, source_resource::SourceResource, value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use std::{collections::BTreeSet, ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};

/// Recursive listings retain the original revision in the approved 64MiB refusal.
pub fn definition_entries(
    repo: &Path,
    tree: TextRef<'_>,
    paths: &[String],
) -> Result<BTreeSet<DefinitionEntry>, PolicyError> {
    let mut entries = BTreeSet::new();
    for path in paths {
        if repo.as_os_str().as_bytes().contains(&0) {
            return Err(exception("ValueError", "embedded null byte"));
        }
        let encoded = encode(tree, 0, true)?;
        let listing = read_git_source(
            repo,
            &[
                OsStr::new("ls-tree"),
                OsStr::new("-r"),
                OsStr::new("-z"),
                OsStr::new("--full-tree"),
                OsStr::new("--end-of-options"),
                OsStr::from_bytes(&encoded),
                OsStr::new("--"),
                OsStr::new(path),
            ],
            SourceResource::TreeListing(NormalizedText::concat(std::iter::once(tree))),
        )?;
        super::lane_git::parse_entries(&listing, &mut entries)?;
    }
    Ok(entries)
}

#[cfg(test)]
#[path = "cli_definition_entries_tests.rs"]
mod tests;

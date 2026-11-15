//! Resolve configuration layout and select content from the supplied Git tree only.
use super::{
    binding_path::encode, lane_git::config_path_with, projection::read_git,
    selection_json::select_json, value_inputs::TextRef, workflow::workflow_job,
};
use crate::evidence::legacy_policy::PolicyError;
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: detail.to_string().into(),
    }
}
pub fn selector_item(repo: &Path, tree: &str, item: &str) -> Result<Option<String>, PolicyError> {
    if let Some((path, selector)) = item.split_once("::")
        && (path.starts_with(".st/") || path.starts_with(".fractal/"))
    {
        let legacy = path.replacen(".fractal/", ".st/", 1);
        return Ok(config_path_with(tree, &legacy, |preferred, legacy| {
            read_git(
                repo,
                &[
                    "ls-tree",
                    "-z",
                    "--full-tree",
                    tree,
                    "--",
                    preferred,
                    legacy,
                ],
                usize::MAX,
            )
        })?
        .map(|path| format!("{path}::{selector}")));
    }
    Ok(Some(item.to_owned()))
}
pub fn selected(repo: &Path, tree: &str, item: &str) -> Result<Option<Vec<u8>>, PolicyError> {
    match selector_item(repo, tree, item)? {
        Some(item) => selected_content(repo, tree, &item),
        None => Ok(None),
    }
}
pub fn selected_content<'a>(
    repo: &Path,
    tree: &str,
    item: impl Into<TextRef<'a>>,
) -> Result<Option<Vec<u8>>, PolicyError> {
    // Generous configuration/workflow cap; enforce before decoding or either selector.
    selected_content_limit(repo, tree, item.into(), 16 * 1024 * 1024)
}
fn selected_content_limit<'a>(
    repo: &Path,
    tree: &str,
    item: impl Into<TextRef<'a>>,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, PolicyError> {
    crate::evidence::oid(tree).map_err(error)?;
    let item = item.into();
    let (path, selector) = item.split_once("::").unwrap_or((item, TextRef::Str("")));
    let encoded = encode(path, 0, true)?;
    if read_git(
        repo,
        &[
            OsStr::new("ls-tree"),
            OsStr::new("--full-tree"),
            OsStr::new(tree),
            OsStr::new("--"),
            OsStr::from_bytes(&encoded),
        ],
        usize::MAX,
    )?
    .is_empty()
    {
        return Ok(None);
    }
    let shown_path = [tree.as_bytes(), b":", &encoded].concat();
    let shown = read_git(
        repo,
        &[
            OsStr::new("show"),
            OsStr::new("--end-of-options"),
            OsStr::from_bytes(&shown_path),
        ],
        max_bytes,
    )?;
    let text = std::str::from_utf8(&shown).map_err(error)?;
    if let Some(job) = selector.strip_prefix("jobs.") {
        workflow_job(text, job)
    } else {
        select_json(text, selector)
    }
}
#[cfg(test)]
#[path = "selection_tests.rs"]
mod tests;

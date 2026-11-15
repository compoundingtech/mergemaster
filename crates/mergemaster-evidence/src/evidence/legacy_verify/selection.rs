//! Resolve configuration layout and select content from the supplied Git tree only.
use super::{
    binding_path::encode, crate_inputs_text::utf8, projection::read_selection,
    selection_json::select_json, source_resource::LISTING_BYTES, value_inputs::TextRef,
    workflow::workflow_job,
};
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError, normalized_text::NormalizedText};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        resource: None,
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: detail.to_string().into(),
    }
}
fn replace_first(text: TextRef<'_>, needle: &str, replacement: &str) -> NormalizedText {
    if let Some((head, tail)) = text.split_once(needle) {
        NormalizedText::concat([head, TextRef::Str(replacement), tail].into_iter())
    } else {
        NormalizedText::around("", text, "")
    }
}
pub fn selector_item<'a>(
    repo: &Path,
    tree: &str,
    item: impl Into<TextRef<'a>>,
) -> Result<Option<NormalizedText>, PolicyError> {
    selector_item_with(tree, item, |args, limit| {
        read_selection(repo, tree, args, limit)
    })
}
pub(super) fn selector_item_with<'a>(
    tree: &str,
    item: impl Into<TextRef<'a>>,
    read: impl Fn(&[&OsStr], usize) -> Result<Vec<u8>, PolicyError>,
) -> Result<Option<NormalizedText>, PolicyError> {
    let item = item.into();
    if let Some((path, selector)) = item.split_once("::")
        && (path.starts_with(".st/") || path.starts_with(".fractal/"))
    {
        crate::evidence::oid(tree).map_err(error)?;
        let legacy = replace_first(path, ".fractal/", ".st/");
        let preferred = replace_first(legacy.borrowed(), ".st/", ".fractal/");
        let preferred_bytes = encode(preferred.borrowed(), 0, true)?;
        let legacy_bytes = encode(legacy.borrowed(), 0, true)?;
        let listing = read(
            &[
                OsStr::new("ls-tree"),
                OsStr::new("-z"),
                OsStr::new("--full-tree"),
                OsStr::new(tree),
                OsStr::new("--"),
                OsStr::from_bytes(&preferred_bytes),
                OsStr::from_bytes(&legacy_bytes),
            ],
            LISTING_BYTES,
        )?;
        let (mut has_preferred, mut has_legacy) = (false, false);
        for row in listing
            .split(|byte| *byte == 0)
            .filter(|row| !row.is_empty())
        {
            let name = row
                .iter()
                .position(|byte| *byte == b'\t')
                .map_or(&[][..], |tab| &row[tab + 1..]);
            utf8(name).map_err(|detail| PolicyError {
                resource: None,
                origin: ErrorOrigin::Exception {
                    class: "UnicodeDecodeError",
                },
                reason: "error",
                detail: detail.into(),
            })?;
            has_preferred |= name == preferred_bytes.as_ref();
            has_legacy |= name == legacy_bytes.as_ref();
        }
        let resolved = if has_preferred {
            Some(&preferred)
        } else if has_legacy {
            Some(&legacy)
        } else {
            None
        };
        return Ok(resolved.map(|path| {
            NormalizedText::concat([path.borrowed(), TextRef::Str("::"), selector].into_iter())
        }));
    }
    Ok(Some(NormalizedText::around("", item, "")))
}
pub fn selected<'a>(
    repo: &Path,
    tree: &str,
    item: impl Into<TextRef<'a>>,
) -> Result<Option<Vec<u8>>, PolicyError> {
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
    selected_content_with(tree, item, max_bytes, |args, limit| {
        read_selection(repo, tree, args, limit)
    })
}
pub(super) fn selected_content_with<'a>(
    tree: &str,
    item: impl Into<TextRef<'a>>,
    max_bytes: usize,
    read: impl Fn(&[&OsStr], usize) -> Result<Vec<u8>, PolicyError>,
) -> Result<Option<Vec<u8>>, PolicyError> {
    crate::evidence::oid(tree).map_err(error)?;
    let item = item.into();
    let (path, selector) = item.split_once("::").unwrap_or((item, TextRef::Str("")));
    let encoded = encode(path, 0, true)?;
    if read(
        &[
            OsStr::new("ls-tree"),
            OsStr::new("--full-tree"),
            OsStr::new(tree),
            OsStr::new("--"),
            OsStr::from_bytes(&encoded),
        ],
        LISTING_BYTES,
    )?
    .is_empty()
    {
        return Ok(None);
    }
    let shown_path = [tree.as_bytes(), b":", &encoded].concat();
    let shown = read(
        &[
            OsStr::new("show"),
            OsStr::new("--end-of-options"),
            OsStr::from_bytes(&shown_path),
        ],
        max_bytes,
    )?;
    let text = std::str::from_utf8(&shown).map_err(|_| PolicyError {
        resource: None,
        origin: ErrorOrigin::Failure,
        reason: "error",
        detail: NormalizedText::around("", path, " is not text"),
    })?;
    if let Some(job) = selector.strip_prefix("jobs.") {
        workflow_job(text, job)
    } else {
        select_json(text, path, selector)
    }
}
#[cfg(test)]
#[path = "selection_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "selector_stress_tests.rs"]
mod stress_tests;

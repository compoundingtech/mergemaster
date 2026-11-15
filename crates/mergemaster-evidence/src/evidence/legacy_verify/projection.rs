//! Legacy input tree projection, preserving raw Git names and modes.
use super::{
    lane_git::parse_entries,
    projection_capture::{self, ExpectedOutput},
    selection::{selected_content_with, selector_item_with},
};
use crate::evidence::{
    legacy_policy::{PolicyError, normalized_text::NormalizedText},
    oid,
};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    io::Write,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        resource: None,
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: detail.to_string().into(),
    }
}
fn projection_command(repo: &Path, args: &[impl AsRef<OsStr>]) -> Result<Command, PolicyError> {
    if repo.as_os_str().as_bytes().contains(&0)
        || args.iter().any(|arg| arg.as_ref().as_bytes().contains(&0))
    {
        return Err(PolicyError {
            resource: None,
            origin: crate::evidence::legacy_policy::ErrorOrigin::Exception {
                class: "ValueError",
            },
            reason: "error",
            detail: "embedded null byte".into(),
        });
    }
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .args([
            "-c",
            "gpg.format=ssh",
            "-c",
            "gpg.ssh.program=ssh-keygen",
            "-c",
            "commit.gpgSign=false",
        ])
        .args(args)
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped());
    Ok(cmd)
}
#[cfg(test)]
thread_local! {
    static EXCHANGE_TIMEOUT: std::cell::Cell<Duration> = const {
        std::cell::Cell::new(Duration::from_secs(60))
    };
}
fn input_git(
    repo: &Path,
    args: &[impl AsRef<OsStr>],
    bytes: &[u8],
    index: Option<&Path>,
    expected: ExpectedOutput,
) -> Result<Vec<u8>, PolicyError> {
    input_git_with_fetch(repo, args, bytes, index, expected, false)
}
fn input_git_with_fetch(
    repo: &Path,
    args: &[impl AsRef<OsStr>],
    bytes: &[u8],
    index: Option<&Path>,
    expected: ExpectedOutput,
    no_lazy_fetch: bool,
) -> Result<Vec<u8>, PolicyError> {
    let mut cmd = projection_command(repo, args)?;
    if no_lazy_fetch {
        cmd.env("GIT_NO_LAZY_FETCH", "1");
    }
    if let Some(index) = index {
        cmd.env("GIT_INDEX_FILE", index);
    }
    #[cfg(not(test))]
    let timeout = Duration::from_secs(60);
    #[cfg(test)]
    let timeout = EXCHANGE_TIMEOUT.get();
    projection_capture::exchange(
        &mut cmd,
        bytes,
        args.first()
            .and_then(|arg| arg.as_ref().to_str())
            .unwrap_or(""),
        expected,
        timeout,
    )
}
pub(super) fn read_git(
    repo: &Path,
    args: &[impl AsRef<OsStr>],
    limit: usize,
) -> Result<Vec<u8>, PolicyError> {
    input_git(repo, args, &[], None, ExpectedOutput::Bytes(limit))
}
pub(super) fn read_git_source(
    repo: &Path,
    args: &[impl AsRef<OsStr>],
    resource: super::source_resource::SourceResource,
) -> Result<Vec<u8>, PolicyError> {
    input_git(repo, args, &[], None, ExpectedOutput::Source(resource))
}
pub(super) fn read_selection(
    repo: &Path,
    tree: &str,
    args: &[&OsStr],
    limit: usize,
) -> Result<Vec<u8>, PolicyError> {
    input_git(repo, args, &[], None, selection_output(tree, limit))
}
fn selection_output(tree: &str, limit: usize) -> ExpectedOutput {
    if limit == super::source_resource::LISTING_BYTES {
        ExpectedOutput::Source(super::source_resource::SourceResource::TreeListing(
            tree.into(),
        ))
    } else {
        ExpectedOutput::Bytes(limit)
    }
}
pub fn project(
    repo: &Path,
    tree: &str,
    paths: &[NormalizedText],
) -> Result<Option<String>, PolicyError> {
    project_with_fetch(repo, tree, paths, false)
}
pub(super) fn project_with_fetch(
    repo: &Path,
    tree: &str,
    paths: &[NormalizedText],
    no_lazy_fetch: bool,
) -> Result<Option<String>, PolicyError> {
    let read = |args: &[&OsStr], limit| {
        input_git_with_fetch(
            repo,
            args,
            &[],
            None,
            selection_output(tree, limit),
            no_lazy_fetch,
        )
    };
    if oid(tree).is_err() {
        return Err(error("invalid tree object ID"));
    }
    let expected = if tree.len() == 40 {
        ExpectedOutput::Sha1
    } else {
        ExpectedOutput::Sha256
    };
    let plain: Vec<_> = paths
        .iter()
        .map(NormalizedText::borrowed)
        .filter(|p| !p.starts_with("!") && p.split_once("::").is_none())
        .collect();
    let excluded: Vec<_> = paths
        .iter()
        .filter_map(|p| p.borrowed().strip_prefix("!"))
        .map(|p| super::binding_path::encode(p, 0, false))
        .collect::<Result<_, _>>()?;
    let mut chosen = BTreeSet::new();
    for path in paths
        .iter()
        .filter(|p| p.borrowed().split_once("::").is_some())
    {
        if let Some(item) = selector_item_with(tree, path, read)? {
            chosen.insert(item);
        }
    }
    let whole = plain.iter().any(|p| p.equals("."));
    if whole && excluded.is_empty() && chosen.is_empty() {
        return Ok(Some(tree.into()));
    }
    let mut entries = BTreeSet::new();
    if !plain.is_empty() {
        let encoded = if whole {
            Vec::new()
        } else {
            plain
                .iter()
                .map(|p| super::binding_path::encode(*p, 0, true))
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut args: Vec<&OsStr> = ["ls-tree", "-r", "-z", "--full-tree", tree]
            .into_iter()
            .map(OsStr::new)
            .collect();
        if !whole {
            args.push(OsStr::new("--"));
            args.extend(encoded.iter().map(|p| OsStr::from_bytes(p)));
        }
        parse_entries(
            &read(&args, super::source_resource::LISTING_BYTES)?,
            &mut entries,
        )?;
    }
    let mut index_bytes = Vec::new();
    for entry in entries {
        if excluded.iter().any(|out| {
            let end = out.iter().rposition(|b| *b != b'/').map_or(0, |i| i + 1);
            entry.path == out.as_ref()
                || entry
                    .path
                    .strip_prefix(&out[..end])
                    .is_some_and(|tail| tail.starts_with(b"/"))
        }) {
            continue;
        }
        write!(index_bytes, "{} {} 0\t", entry.mode, entry.oid).map_err(error)?;
        index_bytes.extend_from_slice(&entry.path);
        index_bytes.push(0);
    }
    for item in chosen {
        if let Some(bytes) = selected_content_with(tree, &item, 16 * 1024 * 1024, read)? {
            let blob = String::from_utf8(input_git_with_fetch(
                repo,
                &["hash-object", "--stdin"],
                &bytes,
                None,
                expected.clone(),
                no_lazy_fetch,
            )?)
            .map_err(error)?;
            write!(index_bytes, "100644 {} 0\t", blob.trim()).map_err(error)?;
            index_bytes.extend_from_slice(&super::binding_path::encode(item.borrowed(), 0, false)?);
            index_bytes.push(0);
        }
    }
    if index_bytes.is_empty() {
        return Ok(None);
    }
    let scratch = tempfile::tempdir().map_err(error)?;
    let index = scratch.path().join("index");
    input_git_with_fetch(
        repo,
        &["update-index", "-z", "--index-info"],
        &index_bytes,
        Some(&index),
        ExpectedOutput::Discard,
        no_lazy_fetch,
    )?;
    let output = input_git_with_fetch(
        repo,
        &["write-tree", "--missing-ok"],
        &[],
        Some(&index),
        expected,
        no_lazy_fetch,
    )?;
    Ok(Some(
        String::from_utf8(output).map_err(error)?.trim().to_owned(),
    ))
}
#[cfg(test)]
#[path = "listing_capture_tests.rs"]
mod listing_capture_tests;
#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;

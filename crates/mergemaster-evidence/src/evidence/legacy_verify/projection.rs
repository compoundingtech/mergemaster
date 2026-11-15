//! Legacy input tree projection, preserving raw Git names and modes.
use super::{
    lane_git::parse_entries,
    projection_capture::{self, ExpectedOutput},
    selection::{selected_content, selector_item},
};
use crate::evidence::{legacy_policy::PolicyError, oid};
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
    let mut cmd = projection_command(repo, args)?;
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
pub fn project(repo: &Path, tree: &str, paths: &[String]) -> Result<Option<String>, PolicyError> {
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
        .filter(|p| !p.starts_with('!') && !p.contains("::"))
        .map(String::as_str)
        .collect();
    let excluded: Vec<_> = paths
        .iter()
        .filter_map(|p| p.strip_prefix('!'))
        .map(str::as_bytes)
        .collect();
    let mut chosen = BTreeSet::new();
    for path in paths.iter().filter(|p| p.contains("::")) {
        if let Some(item) = selector_item(repo, tree, path)? {
            chosen.insert(item);
        }
    }
    let whole = plain.contains(&".");
    if whole && excluded.is_empty() && chosen.is_empty() {
        return Ok(Some(tree.into()));
    }
    let mut entries = BTreeSet::new();
    if !plain.is_empty() {
        let mut args = vec!["ls-tree", "-r", "-z", "--full-tree", tree];
        if !whole {
            args.push("--");
            args.extend(plain);
        }
        parse_entries(&read_git(repo, &args, usize::MAX)?, &mut entries)?;
    }
    let mut index_bytes = Vec::new();
    for entry in entries {
        if excluded.iter().any(|out| {
            let end = out.iter().rposition(|b| *b != b'/').map_or(0, |i| i + 1);
            entry.path == *out
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
        if let Some(bytes) = selected_content(repo, tree, &item)? {
            let blob = String::from_utf8(input_git(
                repo,
                &["hash-object", "--stdin"],
                &bytes,
                None,
                expected,
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
    input_git(
        repo,
        &["update-index", "-z", "--index-info"],
        &index_bytes,
        Some(&index),
        ExpectedOutput::Discard,
    )?;
    let output = input_git(
        repo,
        &["write-tree", "--missing-ok"],
        &[],
        Some(&index),
        expected,
    )?;
    Ok(Some(
        String::from_utf8(output).map_err(error)?.trim().to_owned(),
    ))
}
#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;

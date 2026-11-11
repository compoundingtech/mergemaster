//! Legacy input tree projection, preserving raw Git names and modes.
use super::{
    lane_git::parse_entries,
    selection::{selected_content, selector_item},
};
use crate::{
    evidence::{legacy_policy::PolicyError, oid},
    gate::git::{command, git, git_bounded},
};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::Path,
    process::Stdio,
};
// hash-object/write-tree emit one full SHA-1/SHA-256 OID and newline;
// update-index emits nothing. Read one extra byte to distinguish overflow.
const MAX_PROJECTION_OUTPUT: usize = 65;
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        reason: "error",
        detail: detail.to_string(),
    }
}
fn valid_output(output: &[u8], width: usize) -> bool {
    output.len() == width + 1
        && output.last() == Some(&b'\n')
        && output[..width].iter().all(u8::is_ascii_hexdigit)
}
// Bounded stdout and suppressed stderr avoid pipe deadlock; reap on stdin failure.
fn input_git(
    repo: &Path,
    args: &[&str],
    bytes: &[u8],
    index: Option<&Path>,
) -> Result<Vec<u8>, PolicyError> {
    let mut cmd = command(repo);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(index) = index {
        cmd.env("GIT_INDEX_FILE", index);
    }
    let mut child = cmd.spawn().map_err(error)?;
    let written = child.stdin.take().unwrap().write_all(bytes);
    if let Err(e) = written {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error(e));
    }
    let result = (|| {
        let mut output = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .take((MAX_PROJECTION_OUTPUT + 1) as u64)
            .read_to_end(&mut output)
            .map_err(error)?;
        if output.len() > MAX_PROJECTION_OUTPUT {
            return Err(PolicyError {
                reason: "projection-output-too-large",
                detail: "Git projection output exceeds 65 bytes".into(),
            });
        }
        Ok(output)
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(error)?;
    if result.is_ok() && !status.success() {
        return Err(error("Git projection plumbing failed"));
    }
    let output = result?;
    match args.first().copied() {
        Some("hash-object" | "write-tree") => {
            let format =
                git_bounded(repo, &["rev-parse", "--show-object-format"], 7).map_err(error)?;
            let width = match format.as_slice() {
                b"sha1\n" => 40,
                b"sha256\n" => 64,
                _ => return Err(error("invalid Git object format")),
            };
            if !valid_output(&output, width) {
                return Err(error("invalid Git projection object ID output"));
            }
        }
        Some("update-index") if output.is_empty() => {}
        _ => return Err(error("unexpected Git projection output")),
    }
    Ok(output)
}
pub fn project(repo: &Path, tree: &str, paths: &[String]) -> Result<Option<String>, PolicyError> {
    if oid(tree).is_err() {
        return Err(error("invalid tree object ID"));
    }
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
        let mut args = vec![
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            "--end-of-options",
            tree,
        ];
        if !whole {
            args.push("--");
            args.extend(plain);
        }
        parse_entries(&git(repo, &args).map_err(error)?, &mut entries)?;
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
            let blob =
                String::from_utf8(input_git(repo, &["hash-object", "--stdin"], &bytes, None)?)
                    .map_err(error)?;
            write!(index_bytes, "100644 {} 0\t{item}\0", blob.trim()).map_err(error)?;
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
    )?;
    let output = input_git(repo, &["write-tree", "--missing-ok"], &[], Some(&index))?;
    Ok(Some(
        String::from_utf8(output).map_err(error)?.trim().to_owned(),
    ))
}
#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;

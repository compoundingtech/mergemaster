//! Legacy input-ref indexes discover candidates, never signature or statement trust.
use crate::{
    evidence::{legacy_policy::PolicyError, oid},
    gate::git::{command, text},
};
use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Write},
    path::Path,
    process::Stdio,
};
fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        reason: "error",
        detail: detail.to_string(),
    }
}
/// Prefix order is significant; duplicate IDs are returned once at first occurrence.
pub fn records_under(repo: &Path, prefixes: &[String]) -> Result<Vec<String>, PolicyError> {
    let listings = prefixes
        .iter()
        .map(|prefix| {
            text(
                repo,
                &[
                    "for-each-ref",
                    "--format=%(objectname) %(refname)",
                    prefix.trim_end_matches('/'),
                ],
            )
            .map_err(error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    for (prefix, listing) in prefixes.iter().zip(&listings) {
        for line in listing.lines() {
            let Some((id, name)) = line.split_once(' ') else {
                continue;
            };
            if oid(id).is_ok() && name.strip_prefix(prefix.as_str()) == Some(id) && seen.insert(id)
            {
                found.push(id.to_owned());
            }
        }
    }
    Ok(found)
}
pub fn input_refs(repo: &Path, check: &str, key: &str) -> Result<Vec<String>, PolicyError> {
    if !(1..=100).contains(&check.len())
        || !check.as_bytes()[0].is_ascii_alphanumeric()
        || !check
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || oid(key).is_err()
    {
        return Ok(Vec::new());
    }
    records_under(
        repo,
        &[
            format!("refs/tags/evidence/input/{check}/{key}/"),
            format!("refs/notes/evidence-input/{check}/{key}/"),
        ],
    )
}
/// One batch request, preserving duplicates/order; entry presence alone grants no trust.
pub fn with_note_for<'a>(
    repo: &Path,
    commits: &'a [String],
    tree: &str,
) -> Result<Vec<&'a str>, PolicyError> {
    if commits.is_empty() {
        return Ok(Vec::new());
    }
    let mut child = command(repo)
        .args(["cat-file", "--batch-check"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(error)?;
    let result = (|| {
        let mut input = child.stdin.take().expect("piped Git stdin");
        let mut output = BufReader::new(child.stdout.take().expect("piped Git stdout"));
        let mut found = Vec::new();
        let mut answer = String::new();
        // One query/answer at a time avoids pipe-capacity deadlock without another Git process.
        for commit in commits {
            writeln!(input, "{commit}:{tree}").map_err(error)?;
            input.flush().map_err(error)?;
            answer.clear();
            output.read_line(&mut answer).map_err(error)?;
            if !answer.ends_with('\n') {
                return Err(error("truncated Git batch answer"));
            }
            if !answer.trim_end_matches('\n').ends_with(" missing") {
                found.push(commit.as_str());
            }
        }
        Ok(found)
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(error)?;
    if !status.success() && result.is_ok() {
        return Err(error("Git note discovery failed"));
    }
    result
}

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
    for prefix in prefixes {
        if !prefix.starts_with("refs/") {
            return Err(error("invalid record prefix"));
        }
        let name = prefix.strip_suffix('/').unwrap_or(prefix);
        text(repo, &["check-ref-format", name]).map_err(error)?;
    }
    let listings = prefixes
        .iter()
        .map(|prefix| {
            text(
                repo,
                &[
                    "for-each-ref",
                    "--format=%(objectname) %(refname)",
                    "--end-of-options",
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
/// First-layout notes only: the complete suffix must equal the object it names.
pub fn legacy_refs(repo: &Path, width: usize) -> Result<Vec<String>, PolicyError> {
    if !matches!(width, 40 | 64) {
        return Err(error("invalid record object-id width"));
    }
    let listing = text(
        repo,
        &[
            "for-each-ref",
            "--format=%(objectname) %(refname)",
            "--end-of-options",
            &format!("refs/notes/evidence/{}", "?".repeat(width)),
        ],
    )
    .map_err(error)?;
    Ok(listing
        .lines()
        .filter_map(|line| {
            let (id, name) = line.split_once(' ')?;
            (oid(id).is_ok() && name.strip_prefix("refs/notes/evidence/") == Some(id))
                .then(|| id.to_owned())
        })
        .collect())
}
/// Tags precede notes; these are candidates, not validated records.
pub fn tree_refs(repo: &Path, tree: &str) -> Result<Vec<String>, PolicyError> {
    oid(tree).map_err(error)?;
    records_under(
        repo,
        &[
            format!("refs/tags/evidence/{tree}/"),
            format!("refs/notes/evidence/{tree}/"),
        ],
    )
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
    for commit in commits {
        oid(commit).map_err(error)?;
    }
    if tree.contains(['\n', '\r', '\0']) {
        return Err(error("invalid note path"));
    }
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
        for commit in commits {
            writeln!(input, "{commit}:{tree}").map_err(error)?;
            input.flush().map_err(error)?;
            answer.clear();
            output.read_line(&mut answer).map_err(error)?;
            if !answer.ends_with('\n') {
                return Err(error("truncated Git batch answer"));
            }
            if answer
                .strip_suffix(" missing\n")
                .is_some_and(|q| q.split_once(':') == Some((commit.as_str(), tree)))
            {
                continue;
            }
            let mut fields = answer.trim_end_matches('\n').split(' ');
            let (Some(id), Some(kind), Some(size), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(error("malformed Git batch answer"));
            };
            if oid(id).is_err()
                || !matches!(kind, "blob" | "tree" | "commit" | "tag")
                || !size.bytes().all(|b| b.is_ascii_digit())
                || size.parse::<u64>().is_err()
            {
                return Err(error("malformed Git batch object"));
            }
            found.push(commit.as_str());
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

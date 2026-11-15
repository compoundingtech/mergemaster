//! Record IDs after the last shadow-log GC marker (oracle log_lines).
use super::{log_transport, projection_oid::space};
use crate::evidence::legacy_policy::PolicyError;
use std::{collections::BTreeSet, ffi::OsStr, path::Path};

pub(super) fn oid(text: &str) -> bool {
    matches!(text.len(), 40 | 64)
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn read(
    repo: &Path,
    head: &str,
    path: &str,
    check: &str,
) -> Result<BTreeSet<String>, PolicyError> {
    let name = format!("{head}:{path}");
    let out = log_transport::read(
        repo,
        &[
            OsStr::new("cat-file"),
            OsStr::new("blob"),
            OsStr::new(&name),
        ],
    )?;
    if !out.status.success() {
        return Ok(BTreeSet::new());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut found = BTreeSet::new();
    // CRLF's empty second fragment is immaterial to both GC and record parsing.
    for line in text.split([
        '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
    ]) {
        if line.starts_with("gc ") {
            found.clear();
            continue;
        }
        let mut parts = line.split(space).filter(|p| !p.is_empty());
        if parts.next() != Some("record") {
            continue;
        }
        let Some(id) = parts.next().filter(|id| oid(id)) else {
            continue;
        };
        if parts.next() == Some(check)
            && parts.by_ref().take(3).count() == 3
            && parts.next().is_none()
        {
            found.insert(id.to_owned());
        }
    }
    Ok(found)
}

#[cfg(test)]
#[path = "log_lines_tests.rs"]
mod tests;

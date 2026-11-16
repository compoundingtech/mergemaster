//! Record IDs after the last shadow-log GC marker (oracle log_lines).
use super::{binding_path::encode, log_transport, projection_oid::space, value_inputs::TextRef};
use crate::evidence::legacy_policy::PolicyError;
use std::os::unix::ffi::OsStrExt;
use std::{collections::BTreeSet, ffi::OsStr, path::Path};

pub(super) fn oid(text: &str) -> bool {
    matches!(text.len(), 40 | 64)
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn read<'a>(
    repo: &Path,
    head: &str,
    path: impl Into<TextRef<'a>>,
    check: impl Into<TextRef<'a>>,
) -> Result<BTreeSet<String>, PolicyError> {
    // CPython converts/checks the earlier repo argv before the head:path argv.
    if repo.as_os_str().as_bytes().contains(&0) {
        return Err(super::crate_manifest_ops::exception(
            "ValueError",
            "embedded null byte",
        ));
    }
    let path = path.into();
    let check = check.into();
    let path = encode(path, head.chars().count() + 1, true)?;
    let mut name = Vec::with_capacity(head.len() + 1 + path.len());
    name.extend_from_slice(head.as_bytes());
    name.push(b':');
    name.extend_from_slice(&path);
    let out = log_transport::read(
        repo,
        &[
            OsStr::new("cat-file"),
            OsStr::new("blob"),
            OsStr::from_bytes(&name),
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
        if parts.next().is_some_and(|part| check.equals(part))
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

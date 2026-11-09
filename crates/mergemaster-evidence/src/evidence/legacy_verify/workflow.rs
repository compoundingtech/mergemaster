//! Generated-workflow text selection, not a general YAML parser.
use crate::evidence::legacy_policy::PolicyError;
use std::collections::{BTreeMap, BTreeSet};
fn space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}
fn lines(text: &str) -> impl Iterator<Item = &str> {
    let mut chars = text.char_indices().peekable();
    let mut start = 0;
    std::iter::from_fn(move || {
        while let Some((at, c)) = chars.next() {
            if matches!(
                c,
                '\n' | '\r'
                    | '\x0b'
                    | '\x0c'
                    | '\x1c'
                    | '\x1d'
                    | '\x1e'
                    | '\u{85}'
                    | '\u{2028}'
                    | '\u{2029}'
            ) {
                let mut end = at + c.len_utf8();
                if c == '\r' && chars.peek().is_some_and(|(_, c)| *c == '\n') {
                    chars.next();
                    end += 1;
                }
                let line = &text[start..end];
                start = end;
                return Some(line);
            }
        }
        if start == text.len() {
            return None;
        }
        let line = &text[start..];
        start = text.len();
        Some(line)
    })
}
fn name(text: &str, quotes: bool) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b"_-".contains(&b) || (quotes && b"\"'".contains(&b))
        })
}
fn needs<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    for (i, line) in lines.iter().enumerate() {
        let Some(value) = line.strip_prefix("    needs:") else {
            continue;
        };
        let value = value.trim_matches(space);
        if value.starts_with('[') {
            return value
                .trim_matches(['[', ']'])
                .split(',')
                .map(|s| s.trim_matches(space))
                .filter(|s| !s.is_empty())
                .map(|s| s.trim_matches(['\"', '\'']))
                .collect();
        }
        if !value.is_empty() {
            return vec![value.trim_matches(['\"', '\''])];
        }
        let mut found = Vec::new();
        for line in &lines[i + 1..] {
            let Some(item) = line
                .strip_prefix("      - ")
                .map(|s| s.trim_end_matches(space))
                .filter(|s| name(s, true))
            else {
                break;
            };
            found.push(item.trim_matches(['\"', '\'']));
        }
        return found;
    }
    Vec::new()
}
pub fn workflow_job(text: &str, job: &str) -> Result<Option<Vec<u8>>, PolicyError> {
    let error = || PolicyError {
        reason: "error",
        detail: "workflow layout or dependency is not understood".into(),
    };
    let mut top = Vec::new();
    let mut jobs: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let (mut current, mut in_jobs) = (None, false);
    for line in lines(text) {
        if line.trim_matches(space).is_empty() || line.starts_with('#') {
            if let Some(name) = current.filter(|_| in_jobs) {
                jobs.get_mut(name).expect("current job").push(line);
            } else {
                top.push(line);
            }
        } else if !line.starts_with(' ') {
            in_jobs = line.trim_end_matches(space) == "jobs:";
            current = None;
            if !in_jobs {
                top.push(line);
            }
        } else if in_jobs {
            if let Some((name, _)) = line
                .strip_prefix("  ")
                .and_then(|s| s.split_once(':'))
                .filter(|(key, rest)| name(key, false) && rest.chars().all(space))
            {
                current = Some(name);
                jobs.insert(name, vec![line]);
            } else {
                let Some(name) = current.filter(|_| line.starts_with("    ")) else {
                    return Err(error());
                };
                jobs.get_mut(name).expect("current job").push(line);
            }
        } else {
            top.push(line);
        }
    }
    if !jobs.contains_key(job) {
        return Ok(None);
    }
    let (mut wanted, mut queue) = (BTreeSet::new(), vec![job]);
    while let Some(name) = queue.pop() {
        if !wanted.insert(name) {
            continue;
        }
        let Some(lines) = jobs.get(name) else {
            return Err(error());
        };
        queue.extend(needs(lines));
    }
    let mut result = Vec::new();
    for line in top {
        result.extend_from_slice(line.as_bytes());
    }
    for name in wanted {
        result.extend_from_slice(b"\0job ");
        result.extend_from_slice(name.as_bytes());
        result.push(b'\n');
        for line in &jobs[name] {
            result.extend_from_slice(line.as_bytes());
        }
    }
    Ok(Some(result))
}

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;

//! Advisory signed-log metadata; never changes a verification decision.
use super::{
    crate_inputs_text::utf8, crate_manifest_ops::exception, log_lines, log_transport, projection,
    projection_oid::space, statement::zoned_time_micros, value_inputs::TextRef,
};
use crate::evidence::legacy_policy::PolicyError;
use std::{collections::BTreeSet, ffi::OsStr, path::Path};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct View {
    pub log: &'static str,
    pub log_head: Option<String>,
    pub log_age_s: Option<i64>,
    pub log_missing: Option<usize>,
}
impl View {
    pub fn write_fields<W: std::fmt::Write>(
        &self,
        o: &mut crate::evidence::legacy_output::Object<'_, W>,
    ) -> std::fmt::Result {
        o.field_text("log", |w| w.text(self.log))?;
        o.field_text("log_head", |w| match &self.log_head {
            Some(s) => w.text(s),
            None => w.null(),
        })?;
        o.field_text("log_age_s", |w| match self.log_age_s {
            Some(n) => w.integer(i128::from(n)),
            None => w.null(),
        })?;
        o.field_text("log_missing", |w| match self.log_missing {
            Some(n) => w.integer(n as i128),
            None => w.null(),
        })?;
        Ok(())
    }
}

pub(super) fn refs(repo: &Path, prefixes: &[String]) -> Result<BTreeSet<String>, PolicyError> {
    let mut found = BTreeSet::new();
    for prefix in prefixes {
        let out = projection::read_git(
            repo,
            &[
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                prefix.trim_end_matches('/'),
            ],
            usize::MAX,
        )?;
        let text = utf8(&out).map_err(|e| exception("UnicodeDecodeError", e))?;
        for line in text.lines() {
            if let Some((id, name)) = line.split_once(' ')
                && log_lines::oid(id)
                && name.strip_prefix(prefix.as_str()) == Some(id)
            {
                found.insert(id.to_owned());
            }
        }
    }
    Ok(found)
}

pub(super) fn input_refs(
    repo: &Path,
    check: TextRef<'_>,
    key: &str,
) -> Result<BTreeSet<String>, PolicyError> {
    let mut points = check.points();
    if !log_lines::oid(key)
        || check.len() > 100
        || !points
            .next()
            .is_some_and(|p| matches!(p, 48..=57 | 65..=90 | 97..=122))
        || !points.all(|p| matches!(p, 48..=57 | 65..=90 | 97..=122 | 46 | 95 | 45))
    {
        return Ok(BTreeSet::new());
    }
    let check: String = check.points().filter_map(char::from_u32).collect();
    refs(
        repo,
        &[
            format!("refs/tags/evidence/input/{check}/{key}/"),
            format!("refs/notes/evidence-input/{check}/{key}/"),
        ],
    )
}

// Keep the oracle's independent decision inputs and explicit deterministic clock.
#[allow(clippy::too_many_arguments)]
pub fn read<'a>(
    repo: &Path,
    keys: &Path,
    tree: &str,
    check: impl Into<TextRef<'a>>,
    input_key: Option<&str>,
    chosen: Option<&str>,
    now_micros: i64,
    max_age: i64,
) -> Result<View, PolicyError> {
    let check = check.into();
    let mut view = View {
        log: "absent",
        log_head: None,
        log_age_s: None,
        log_missing: None,
    };
    let out = log_transport::read(
        repo,
        &[
            OsStr::new("rev-parse"),
            OsStr::new("--verify"),
            OsStr::new("--quiet"),
            OsStr::new("--end-of-options"),
            OsStr::new("refs/evidence-log/main^{commit}"),
        ],
    )?;
    let text = utf8(&out.stdout).map_err(|e| exception("UnicodeDecodeError", e))?;
    let head = text.trim_matches(space);
    if !out.status.success() || !log_lines::oid(head) {
        return Ok(view);
    }
    view.log_head = Some(head.to_owned());
    let revocations =
        tempfile::NamedTempFile::new().map_err(|e| super::source_io::error(OsStr::new(""), &e))?;
    let mut allowed = std::ffi::OsString::from("gpg.ssh.allowedSignersFile=");
    allowed.push(keys);
    let mut revoked = std::ffi::OsString::from("gpg.ssh.revocationFile=");
    revoked.push(revocations.path());
    let out = log_transport::read(
        repo,
        &[
            OsStr::new("-c"),
            &allowed,
            OsStr::new("-c"),
            &revoked,
            OsStr::new("show"),
            OsStr::new("-s"),
            OsStr::new("--format=%G?%x00%GS%x00%s"),
            OsStr::new(head),
        ],
    )?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.trim_matches('\n').splitn(3, '\0');
    let status = parts.next().unwrap_or("");
    let principal = parts.next().unwrap_or("");
    let subject = parts.next().unwrap_or("");
    view.log = "unsigned";
    if !out.status.success() || status != "G" || !principal.starts_with("log/") {
        return Ok(view);
    }
    view.log = "stale";
    let stamp = std::iter::once(0)
        .chain(subject.match_indices(' ').map(|(i, _)| i + 1))
        .find_map(|i| {
            let suffix = subject.get(i..)?.strip_prefix("as_of=")?;
            let end = suffix.find(space).unwrap_or(suffix.len());
            (end != 0).then_some(&suffix[..end])
        });
    let Some(moment) =
        stamp.and_then(|s| zoned_time_micros(&s.chars().map(u32::from).collect::<Vec<_>>()))
    else {
        return Ok(view);
    };
    let age = super::log_age::total_seconds(now_micros, moment) as i64;
    view.log_age_s = Some(age);
    if age > max_age || age < -120 {
        return Ok(view);
    }
    let mut logged = log_lines::read(
        repo,
        head,
        &format!("trees/{}/{tree}", tree.get(..2).unwrap_or(tree)),
        check,
    )?;
    let mut here = refs(
        repo,
        &[
            format!("refs/tags/evidence/{tree}/"),
            format!("refs/notes/evidence/{tree}/"),
        ],
    )?;
    if let Some(key) = input_key.filter(|k| !k.is_empty()) {
        logged.extend(log_lines::read(
            repo,
            head,
            TextRef::Points(&key_path(check, key)),
            check,
        )?);
        here.extend(input_refs(repo, check, key)?);
    }
    let missing = logged.difference(&here).count();
    view.log_missing = Some(missing);
    view.log = if missing != 0 {
        "missing"
    } else if chosen.is_some_and(|c| !c.is_empty() && !logged.contains(c)) {
        "unlogged_pass"
    } else {
        "ok"
    };
    Ok(view)
}

pub(super) fn key_path(check: TextRef<'_>, key: &str) -> Vec<u32> {
    "keys/"
        .chars()
        .map(u32::from)
        .chain(check.points())
        .chain(
            format!("/{}/{key}", key.get(..2).unwrap_or(key))
                .chars()
                .map(u32::from),
        )
        .collect()
}

#[cfg(test)]
#[path = "log_view_tests.rs"]
mod tests;

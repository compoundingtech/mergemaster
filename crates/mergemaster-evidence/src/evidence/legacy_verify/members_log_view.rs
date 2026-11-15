//! Advisory log metadata for the complete sorted per-crate decision.
use super::{
    crate_manifest_ops::exception, log_lines, log_view, statement::zoned_time_micros,
    value_inputs::TextRef,
};
use crate::evidence::legacy_policy::{PolicyError, normalized_text::NormalizedText};
use std::{collections::BTreeMap, path::Path};

pub struct Member<'a> {
    pub key: Option<&'a str>,
    pub chosen: Option<&'a str>,
    pub observed: Option<TextRef<'a>>,
}
#[derive(Debug, serde::Serialize)]
pub struct View {
    #[serde(flatten)]
    pub head: log_view::View,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_unlogged: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_unlogged_crates: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_unlogged_observed_at: Option<Option<NormalizedText>>,
}
impl View {
    pub fn write_fields<W: std::fmt::Write>(
        &self,
        o: &mut crate::evidence::legacy_output::Object<'_, W>,
    ) -> std::fmt::Result {
        self.head.write_fields(o)?;
        if let Some(n) = self.log_unlogged {
            o.field_text("log_unlogged", |w| w.integer(n as i128))?;
        }
        if let Some(s) = &self.log_unlogged_crates {
            o.field_text("log_unlogged_crates", |w| w.text(s))?;
        }
        if let Some(s) = &self.log_unlogged_observed_at {
            o.field_text("log_unlogged_observed_at", |w| match s {
                Some(s) => w.codepoints(s.borrowed().points()),
                None => w.null(),
            })?;
        }
        Ok(())
    }
}
fn time(text: TextRef<'_>) -> Option<(i64, bool)> {
    let points: std::borrow::Cow<'_, [u32]> = match text {
        TextRef::Str(s) => s.chars().map(u32::from).collect::<Vec<_>>().into(),
        TextRef::Points(p) => p.into(),
    };
    if let Some(t) = zoned_time_micros(&points) {
        return Some((t, true));
    }
    let mut naive = Vec::with_capacity(points.len() + 15);
    naive.extend_from_slice(&points);
    naive.extend("+00:00".chars().map(u32::from));
    if let Some(t) = zoned_time_micros(&naive) {
        return Some((t, false));
    }
    naive.truncate(points.len());
    naive.extend("T00:00:00+00:00".chars().map(u32::from));
    zoned_time_micros(&naive).map(|t| (t, false))
}
pub fn read<'a>(
    repo: &Path,
    keys: &Path,
    tree: &str,
    check: impl Into<TextRef<'a>>,
    members: &BTreeMap<String, Member<'_>>,
    now_micros: i64,
    max_age: i64,
) -> Result<View, PolicyError> {
    let check = check.into();
    let head = log_view::read(repo, keys, tree, check, None, None, now_micros, max_age)?;
    let mut view = View {
        head,
        log_unlogged: None,
        log_unlogged_crates: None,
        log_unlogged_observed_at: None,
    };
    if !matches!(view.head.log, "ok" | "missing") {
        return Ok(view);
    }
    let Some(head) = view.head.log_head.as_deref() else {
        return Ok(view);
    };
    let logged_tree = log_lines::read(
        repo,
        head,
        &format!("trees/{}/{tree}", tree.get(..2).unwrap_or(tree)),
        check,
    )?;
    let here = log_view::refs(
        repo,
        &[
            format!("refs/tags/evidence/{tree}/"),
            format!("refs/notes/evidence/{tree}/"),
        ],
    )?;
    let mut missing = logged_tree
        .difference(&here)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let mut unlogged = Vec::new();
    for (name, member) in members {
        let Some(key) = member.key.filter(|k| log_lines::oid(k)) else {
            continue;
        };
        let logged = log_lines::read(
            repo,
            head,
            TextRef::Points(&log_view::key_path(check, key)),
            check,
        )?;
        let here = log_view::input_refs(repo, check, key)?;
        missing.extend(logged.difference(&here).cloned());
        if let Some(chosen) = member
            .chosen
            .filter(|c| !c.is_empty() && !logged.contains(*c) && !logged_tree.contains(*c))
        {
            unlogged.push((name, chosen, member.observed));
        }
    }
    view.head.log_missing = Some(missing.len());
    view.log_unlogged = Some(unlogged.len());
    if !unlogged.is_empty() {
        use std::fmt::Write;
        let mut summary = String::new();
        for (i, (name, chosen, _)) in unlogged.iter().take(5).enumerate() {
            if i != 0 {
                summary.push('+');
            }
            summary.push_str(name);
            summary.push('=');
            summary.extend(chosen.chars().take(12));
        }
        if unlogged.len() > 5 {
            let _ = write!(summary, "+{}_more", unlogged.len() - 5);
        }
        view.log_unlogged_crates = Some(summary);
        // Parse every time before min(): an invalid later time suppresses even a mixed-zone error.
        let times = unlogged
            .iter()
            .map(|(_, _, text)| {
                let text = (*text)?;
                Some((time(text)?, text))
            })
            .collect::<Option<Vec<_>>>();
        let oldest = if let Some(times) = times {
            if times.iter().any(|(t, _)| t.1 != times[0].0.1) {
                return Err(exception(
                    "TypeError",
                    "can't compare offset-naive and offset-aware datetimes",
                ));
            }
            times
                .into_iter()
                .min_by(|a, b| {
                    a.0.0
                        .cmp(&b.0.0)
                        .then_with(|| a.1.points().cmp(b.1.points()))
                })
                .map(|(_, text)| NormalizedText::around("", text, ""))
        } else {
            None
        };
        view.log_unlogged_observed_at = Some(oldest);
    }
    view.head.log = if missing.is_empty() {
        if unlogged.is_empty() {
            "ok"
        } else {
            "unlogged_pass"
        }
    } else {
        "missing"
    };
    Ok(view)
}
#[cfg(test)]
#[path = "members_log_view_tests.rs"]
mod tests;

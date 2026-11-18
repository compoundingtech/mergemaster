//! CLI definition composition retains lossless argv and raw Git filenames.
use super::{
    cli_lane_git::definition_entries,
    cli_lanes::LaneRules,
    judgment::LaneDefinition,
    lanes::{DefinitionEntry, codepoints},
    value_inputs::TextRef,
};
use crate::evidence::{
    legacy_json,
    legacy_policy::{ErrorOrigin, PolicyError, normalized_text::NormalizedText},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, path::Path};

pub(super) fn failure(reason: &'static str, detail: NormalizedText) -> PolicyError {
    PolicyError {
        resource: None,
        origin: ErrorOrigin::Failure,
        reason,
        detail,
    }
}
struct Hash(Sha256);
impl fmt::Write for Hash {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0.update(text.as_bytes());
        Ok(())
    }
}
/// Hash without constructing the preimage or cloning entry paths/argv.
pub fn definition_digest(
    entries: &BTreeSet<DefinitionEntry>,
    argv: &[NormalizedText],
    absent: &[String],
) -> Result<String, PolicyError> {
    let mut hash = Hash(Sha256::new());
    let mut ordered: Vec<_> = entries.iter().collect();
    ordered.sort_unstable_by(|a, b| codepoints(&a.path).cmp(codepoints(&b.path)));
    for entry in ordered {
        for part in [
            entry.mode.as_bytes(),
            b" ",
            entry.oid.as_bytes(),
            b" ",
            &entry.path,
            b"\n",
        ] {
            hash.0.update(part);
        }
    }
    hash.0.update(b"argv:[");
    for (i, arg) in argv.iter().enumerate() {
        if i != 0 {
            hash.0.update(b", ");
        }
        legacy_json::codepoints(arg.borrowed().points(), &mut hash).map_err(|_| {
            failure(
                "error",
                "lane argv contains an invalid Unicode code point".into(),
            )
        })?;
    }
    hash.0.update(b"]");
    if !absent.is_empty() {
        hash.0.update(b"\nabsent:[");
        let mut ordered: Vec<_> = absent.iter().collect();
        ordered.sort_unstable();
        for (i, path) in ordered.into_iter().enumerate() {
            if i != 0 {
                hash.0.update(b", ");
            }
            legacy_json::emit_string(path, |part| hash.0.update(part.as_bytes()));
        }
        hash.0.update(b"]");
    }
    Ok(hex::encode(hash.0.finalize()))
}
fn covers(path: &str, name: &[u8]) -> bool {
    name == path.as_bytes()
        || name
            .strip_prefix(path.as_bytes())
            .is_some_and(|tail| tail.starts_with(b"/"))
}
pub fn lane_definition(
    repo: &Path,
    base_tree: TextRef<'_>,
    tree: TextRef<'_>,
    rules: &LaneRules,
) -> Result<LaneDefinition, PolicyError> {
    let base = definition_entries(repo, base_tree, &rules.definition_paths)?;
    for path in &rules.definition_paths {
        if !base.iter().any(|entry| covers(path, &entry.path)) {
            return Err(failure(
                "error",
                format!("lane definition path {path} does not exist at the accepted base").into(),
            ));
        }
    }
    let absent = definition_entries(repo, base_tree, &rules.absent_paths)?;
    if let Some(first) = absent
        .iter()
        .min_by(|a, b| codepoints(&a.path).cmp(codepoints(&b.path)))
    {
        let path = codepoints(&first.path).collect::<Vec<_>>();
        return Err(failure(
            "error",
            NormalizedText::around(
                "lane absent path ",
                TextRef::Points(&path),
                " exists at the accepted base",
            ),
        ));
    }
    let mut other = definition_entries(repo, tree, &rules.definition_paths)?;
    let present = definition_entries(repo, tree, &rules.absent_paths)?;
    let mut changed: Vec<_> = base
        .symmetric_difference(&other)
        .chain(present.iter())
        .map(|entry| &entry.path)
        .collect();
    changed.sort_unstable_by(|a, b| codepoints(a).cmp(codepoints(b)));
    changed.dedup();
    let changed = changed.into_iter().cloned().collect();
    let sha256 = definition_digest(&base, &rules.argv, &rules.absent_paths)?;
    other.extend(present);
    let tree_sha256 = definition_digest(&other, &rules.argv, &rules.absent_paths)?;
    Ok(LaneDefinition {
        sha256,
        changed,
        tree_sha256,
    })
}

#[cfg(test)]
#[path = "cli_definition_digest_tests.rs"]
mod tests;

//! Legacy Git definition discovery; native hashing and policy loading are separate.
use super::{
    judgment::LaneDefinition,
    lanes::{DefinitionEntry, LaneRules, codepoints, definition_digest},
};
use crate::{
    evidence::{legacy_policy::PolicyError, oid},
    gate::git::git,
};
use std::{collections::BTreeSet, path::Path};

fn error(detail: impl ToString) -> PolicyError {
    PolicyError {
        reason: "error",
        detail: detail.to_string(),
    }
}
/// Preserve raw names: Git paths are not necessarily UTF-8.
pub fn definition_entries(
    repo: &Path,
    tree: &str,
    paths: &[String],
) -> Result<BTreeSet<DefinitionEntry>, PolicyError> {
    let mut entries = BTreeSet::new();
    for path in paths {
        let listing = git(
            repo,
            &[
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                "--end-of-options",
                tree,
                "--",
                path,
            ],
        )
        .map_err(error)?;
        parse_entries(&listing, &mut entries)?;
    }
    Ok(entries)
}
fn parse_entries(
    listing: &[u8],
    entries: &mut BTreeSet<DefinitionEntry>,
) -> Result<(), PolicyError> {
    if listing.is_empty() {
        return Ok(());
    }
    let rows = listing
        .strip_suffix(b"\0")
        .ok_or_else(|| error("unterminated ls-tree output"))?;
    for row in rows.split(|b| *b == 0) {
        let tab = row
            .iter()
            .position(|b| *b == b'\t')
            .ok_or_else(|| error("invalid ls-tree entry"))?;
        let meta = std::str::from_utf8(&row[..tab]).map_err(error)?;
        let mut fields = meta.split(' ');
        let mode = fields.next().unwrap_or("");
        let kind = fields.next().unwrap_or("");
        let id = fields.next().unwrap_or("");
        if fields.next().is_some()
            || row[tab + 1..].is_empty()
            || oid(id).is_err()
            || !matches!(
                (mode, kind),
                ("100644" | "100755" | "120000", "blob")
                    | ("160000", "commit")
                    | ("040000", "tree")
            )
        {
            return Err(error("malformed ls-tree metadata"));
        }
        entries.insert(DefinitionEntry {
            mode: mode.into(),
            oid: id.into(),
            path: row[tab + 1..].to_vec(),
        });
    }
    Ok(())
}
fn covers(path: &str, name: &[u8]) -> bool {
    name == path.as_bytes()
        || name
            .strip_prefix(path.as_bytes())
            .is_some_and(|tail| tail.starts_with(b"/"))
}
/// Accepted-base existence/absence checks precede all candidate-tree reads.
pub fn lane_definition(
    repo: &Path,
    base_tree: &str,
    tree: &str,
    mut rules: LaneRules,
) -> Result<LaneDefinition, PolicyError> {
    let base = definition_entries(repo, base_tree, &rules.definition_paths)?;
    for path in &rules.definition_paths {
        if !base.iter().any(|entry| covers(path, &entry.path)) {
            return Err(error(format!(
                "definition path {path} is absent from accepted base"
            )));
        }
    }
    if !definition_entries(repo, base_tree, &rules.absent_paths)?.is_empty() {
        return Err(error("an absent path exists in the accepted definition"));
    }
    let mut other = definition_entries(repo, tree, &rules.definition_paths)?;
    let present = definition_entries(repo, tree, &rules.absent_paths)?;
    let mut changed: Vec<_> = base
        .symmetric_difference(&other)
        .chain(present.iter())
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    changed.sort_unstable_by(|a, b| codepoints(a).cmp(codepoints(b)));
    let sha256 = definition_digest(
        &mut base.into_iter().collect::<Vec<_>>(),
        &rules.argv,
        &mut rules.absent_paths,
    );
    other.extend(present);
    let tree_sha256 = definition_digest(
        &mut other.into_iter().collect::<Vec<_>>(),
        &rules.argv,
        &mut rules.absent_paths,
    );
    Ok(LaneDefinition {
        sha256,
        changed,
        tree_sha256,
    })
}

const LANES: &str = ".st/required-lanes.json";
const PREFERRED: &str = ".fractal/required-lanes.json";
fn config_path(repo: &Path, commit: &str) -> Result<Option<&'static str>, PolicyError> {
    let listing = git(
        repo,
        &[
            "ls-tree",
            "-z",
            "--full-tree",
            commit,
            "--",
            PREFERRED,
            LANES,
        ],
    )
    .map_err(error)?;
    let mut entries = BTreeSet::new();
    parse_entries(&listing, &mut entries)?;
    Ok([PREFERRED, LANES].into_iter().find(|path| {
        entries
            .iter()
            .any(|entry| entry.path.as_slice() == path.as_bytes())
    }))
}
/// Read the accepted revision, not the checkout; a present preferred file never falls back.
pub fn read_lanes(repo: &Path, commit: &str) -> Result<String, PolicyError> {
    let path = config_path(repo, commit)?.unwrap_or(LANES);
    let shown = git(repo, &["show", &format!("{commit}:{path}")]).map_err(error)?;
    String::from_utf8(shown).map_err(error)
}
pub fn lane_for(
    repo: &Path,
    tree: &str,
    lanes: Option<(&str, &str)>,
    check: &str,
    lane_base: Option<&str>,
) -> Result<Option<LaneDefinition>, PolicyError> {
    let Some((text, accepted)) = lanes else {
        return Ok(None);
    };
    let mut definition_base = accepted;
    if let Some(base) = lane_base {
        crate::evidence::oid(base).map_err(error)?;
        git(repo, &["merge-base", "--is-ancestor", base, accepted]).map_err(error)?;
        let path = config_path(repo, base)?;
        let shown = git(
            repo,
            &["show", &format!("{base}:{}", path.unwrap_or(LANES))],
        );
        let here = match shown {
            Ok(bytes) => super::lane_entry::canonical(&String::from_utf8_lossy(&bytes), check)?,
            Err(e) if path.is_some() => return Err(error(e)),
            Err(_) => None,
        };
        if here.is_none() || here != super::lane_entry::canonical(text, check)? {
            return Err(PolicyError {
                reason: "definition_changed",
                detail: format!("lane {check} differs from the branch point"),
            });
        }
        definition_base = base;
    }
    let base_tree = crate::gate::git::text(
        repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{definition_base}^{{tree}}"),
        ],
    )
    .map_err(error)?;
    lane_definition(repo, &base_tree, tree, LaneRules::parse(text, check)?).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tree_rows_require_complete_valid_metadata() {
        let id = "a".repeat(40);
        for row in [
            format!("100644 blob {id}\tx"),
            format!("100644 blob {id} extra\tx\0"),
            format!("100644 tree {id}\tx\0"),
            format!("160000 blob {id}\tx\0"),
            format!("100644 blob {}\tx\0", "A".repeat(40)),
            format!("100644 blob {}\tx\0", "a".repeat(39)),
            format!("100644 blob {id}\t\0"),
            format!("bad blob {id}\tx\0"),
            format!("100644 blob {id} x\0"),
            format!("100644 blob {id}\tx\0\0"),
        ] {
            assert!(
                parse_entries(row.as_bytes(), &mut BTreeSet::new()).is_err(),
                "{row:?}"
            );
        }
        for (mode, kind) in [
            ("100644", "blob"),
            ("100755", "blob"),
            ("120000", "blob"),
            ("160000", "commit"),
            ("040000", "tree"),
        ] {
            for width in [40, 64] {
                let row = format!("{mode} {kind} {}\tname\t\n\0", "a".repeat(width));
                let mut found = BTreeSet::new();
                parse_entries(row.as_bytes(), &mut found).unwrap();
                assert_eq!(found.len(), 1);
            }
        }
    }
}

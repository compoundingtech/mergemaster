//! BASE-owned immutable materializations and writable scratch, never implicit ignored inputs.
use crate::gate::{
    config::{self, Lane},
    git,
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

fn overlaps(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|s| s.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|s| s.starts_with('/'))
}

fn tracked(repo: &Path, head: &str) -> Result<BTreeSet<String>> {
    git::git(repo, &["ls-tree", "-r", "--name-only", "-z", head])?
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| Ok(std::str::from_utf8(s)?.to_owned()))
        .collect()
}

/// Validate declarations using committed paths, without consulting candidate policy.
pub fn validate(repo: &Path, head: &str, lane: &Lane) -> Result<()> {
    let roots: Vec<_> = lane.inputs.keys().chain(&lane.scratch).collect();
    let files = tracked(repo, head)?;
    for (index, root) in roots.iter().enumerate() {
        config::validate_path(root)?;
        ensure!(
            !root.ends_with('/') && !root.split('/').any(|s| s.eq_ignore_ascii_case(".git")),
            "invalid workspace root"
        );
        ensure!(
            !roots[..index].iter().any(|other| overlaps(root, other)),
            "overlapping workspace declarations"
        );
        ensure!(
            !files.iter().any(|file| overlaps(root, file)),
            "workspace root collides with tracked path"
        );
    }
    for artifact in lane.inputs.values() {
        let hash = artifact
            .identity
            .strip_prefix("sha256:")
            .or_else(|| artifact.identity.strip_prefix("tree-sha256:"))
            .context("workspace input requires sha256: file or tree-sha256: directory identity")?;
        ensure!(
            !artifact.name.is_empty()
                && hash.len() == 64
                && hash
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid workspace artifact"
        );
    }
    Ok(())
}

// Never traverse a symlink, including an ancestor of a declared root.
fn contained(repo: &Path, root: &str) -> Result<()> {
    let mut path = repo.to_path_buf();
    for part in root.split('/') {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) => ensure!(
                !meta.file_type().is_symlink(),
                "workspace symlink: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Hash directory entries in byte-sorted relative path order; include empty directories and modes.
pub fn tree_digest(root: &Path) -> Result<String> {
    fn walk(root: &Path, path: &Path, rows: &mut Vec<(String, String, String)>) -> Result<()> {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            !meta.file_type().is_symlink(),
            "materialized input contains symlink"
        );
        let name = path
            .strip_prefix(root)?
            .to_str()
            .context("non UTF-8 materialization")?
            .to_owned();
        let mode = if meta.is_dir() {
            "directory"
        } else {
            ensure!(meta.is_file(), "unsupported workspace entry");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if meta.permissions().mode() & 0o111 != 0 {
                    "executable"
                } else {
                    "file"
                }
            }
            #[cfg(not(unix))]
            {
                "file"
            }
        };
        let digest = if meta.is_file() {
            super::signing::hash_file(path)?
        } else {
            String::new()
        };
        rows.push((name, mode.into(), digest));
        if meta.is_dir() {
            for entry in fs::read_dir(path)? {
                walk(root, &entry?.path(), rows)?;
            }
        }
        Ok(())
    }
    ensure!(
        fs::symlink_metadata(root)?.is_dir(),
        "tree artifact must be a directory"
    );
    let mut rows = Vec::new();
    walk(root, root, &mut rows)?;
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(1, rows))?)))
}

/// Enumerate filesystem entries too: Git status can omit empty directories and ignored descendants.
pub(super) fn declared_only(repo: &Path, roots: &[&str]) -> Result<bool> {
    fn walk(repo: &Path, path: &Path, files: &BTreeSet<String>, roots: &[&str]) -> Result<bool> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let name = path
                .strip_prefix(repo)?
                .to_str()
                .context("non UTF-8 workspace path")?
                .to_owned();
            if name == ".git" {
                continue;
            }
            if roots.iter().any(|root| {
                name == *root || name.strip_prefix(*root).is_some_and(|s| s.starts_with('/'))
            }) {
                continue;
            }
            if files.contains(&name) {
                continue;
            }
            let prefix = format!("{name}/");
            let ancestor = files.iter().any(|file| file.starts_with(&prefix))
                || roots.iter().any(|root| root.starts_with(&prefix));
            if !ancestor || !entry.file_type()?.is_dir() || !walk(repo, &path, files, roots)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    walk(repo, repo, &tracked(repo, "HEAD")?, roots)
}

fn scratch_tree(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(
            kind.is_file() || kind.is_dir(),
            "scratch contains symlink or special entry"
        );
        if kind.is_dir() {
            scratch_tree(&entry.path())?;
        }
    }
    Ok(())
}

/// Wrapper start creates empty scratch; all later observers independently remeasure inputs.
pub fn verify(repo: &Path, head: &str, lane: &Lane, start: bool) -> Result<()> {
    validate(repo, head, lane)?;
    ensure!(
        git::text(repo, &["rev-parse", "HEAD"])? == head && super::signing::tracked_clean(repo)?,
        "workspace differs from exact committed HEAD"
    );
    for root in lane.inputs.keys().chain(&lane.scratch) {
        contained(repo, root)?;
    }
    for (root, artifact) in &lane.inputs {
        let path = repo.join(root);
        let actual = if artifact.identity.starts_with("tree-sha256:") {
            tree_digest(&path)?
        } else {
            ensure!(
                fs::symlink_metadata(&path)?.is_file(),
                "file artifact must be regular"
            );
            super::signing::hash_file(&path)?
        };
        ensure!(
            artifact.identity.rsplit(':').next() == Some(actual.as_str()),
            "materialized input identity mismatch: {root}"
        );
    }
    let roots: Vec<_> = lane
        .inputs
        .keys()
        .chain(&lane.scratch)
        .map(String::as_str)
        .collect();
    ensure!(
        declared_only(repo, &roots)?,
        "undeclared ignored/untracked workspace entry"
    );
    for root in &lane.scratch {
        let path = repo.join(root);
        if start {
            if path.exists() {
                ensure!(
                    fs::symlink_metadata(&path)?.is_dir() && fs::read_dir(&path)?.next().is_none(),
                    "scratch must start absent or empty"
                );
            }
            fs::create_dir_all(&path)?;
        } else {
            ensure!(
                fs::symlink_metadata(&path)?.is_dir(),
                "scratch root must remain a directory"
            );
        }
        scratch_tree(&path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap_is_component_aware_and_symmetric() {
        for (a, b, expected) in [
            ("modules", "modules", true),
            ("modules", "modules/pkg", true),
            ("modules", "modules-extra", false),
            ("output", "modules", false),
        ] {
            assert_eq!(overlaps(a, b), expected);
            assert_eq!(overlaps(b, a), expected);
        }
    }

    #[test]
    fn absent_workspace_declarations_preserve_legacy_lane_serialization() {
        let legacy = serde_json::json!({"argv":["check"],"definition_paths":["tools"],
            "trust_levels":["agent"],"mode":"required_evidence","events":["pull_request"],
            "environment":{"manifest":"environment.json","paths":["tools"]},
            "protected_edits":"reject","remediation_argv":["check"]});
        let lane: Lane = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(serde_json::to_value(lane).unwrap(), legacy);
    }
}

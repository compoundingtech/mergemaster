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
    declarations(repo, head, lane).map(|_| ())
}

fn declarations(repo: &Path, head: &str, lane: &Lane) -> Result<BTreeSet<String>> {
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
            .or_else(|| artifact.identity.strip_prefix("tree-sha256-v2:"))
            .context(
                "workspace input requires sha256:, tree-sha256: or tree-sha256-v2: identity",
            )?;
        ensure!(
            !artifact.name.is_empty()
                && hash.len() == 64
                && hash
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid workspace artifact"
        );
    }
    Ok(files)
}

// Only a v2 input's final component may be a link; ancestors and scratch stay physical.
fn contained(repo: &Path, root: &str, linked_root: bool) -> Result<()> {
    let mut path = repo.to_path_buf();
    for part in root.split('/') {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) => ensure!(
                !meta.file_type().is_symlink() || (linked_root && path == repo.join(root)),
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
    digest_tree(root, None, None)
}

/// Measure raw link targets and the complete contents of a possibly linked root.
/// Descendant links contribute only their raw targets to the digest, but their
/// complete reachable subtrees must be authorized. Verify also permits clean tracked paths.
pub fn tree_digest_v2(root: &Path, measured_roots: &[std::path::PathBuf]) -> Result<String> {
    digest_tree(root, Some(measured_roots), None)
}

// Validate reachability separately from digest rows: v1 and v2 preimages stay unchanged.
fn reachable(
    path: &Path,
    measured_roots: &[std::path::PathBuf],
    tracked: Option<(&Path, &BTreeSet<String>)>,
    active: &mut BTreeSet<std::path::PathBuf>,
    complete: &mut BTreeSet<std::path::PathBuf>,
) -> Result<()> {
    let resolved = fs::canonicalize(path).context("dangling or cyclic workspace symlink")?;
    let meta = fs::metadata(&resolved)?;
    let authorized = measured_roots.iter().any(|root| resolved.starts_with(root))
        || tracked.is_some_and(|(repo, files)| {
            resolved
                .strip_prefix(repo)
                .ok()
                .and_then(Path::to_str)
                .is_some_and(|name| {
                    files.contains(name)
                        || (meta.is_dir()
                            && files.iter().any(|file| {
                                file.strip_prefix(name)
                                    .is_some_and(|rest| rest.starts_with('/'))
                            }))
                })
        });
    ensure!(
        authorized,
        "workspace symlink escapes measured inputs: {}",
        path.display()
    );
    ensure!(meta.is_dir() || meta.is_file(), "unsupported workspace entry");
    if !meta.is_dir() || complete.contains(&resolved) {
        return Ok(());
    }
    ensure!(active.insert(resolved.clone()), "cyclic workspace symlink");
    // A tracked directory prefix only permits traversal, never its untracked children.
    for entry in fs::read_dir(&resolved)? {
        reachable(&entry?.path(), measured_roots, tracked, active, complete)?;
    }
    active.remove(&resolved);
    complete.insert(resolved);
    Ok(())
}

fn digest_tree(
    root: &Path,
    measured_roots: Option<&[std::path::PathBuf]>,
    tracked: Option<(&Path, &BTreeSet<String>)>,
) -> Result<String> {
    fn walk(
        root: &Path,
        path: &Path,
        measured_roots: Option<&[std::path::PathBuf]>,
        rows: &mut Vec<(String, String, String)>,
    ) -> Result<()> {
        let meta = fs::symlink_metadata(path)?;
        let name = path
            .strip_prefix(root)?
            .to_str()
            .context("non UTF-8 materialization")?
            .to_owned();
        if meta.file_type().is_symlink() {
            let measured_roots = measured_roots.context("materialized input contains symlink")?;
            let target = fs::read_link(path)?;
            let is_root = path == root;
            rows.push((
                name,
                "symlink".into(),
                hex::encode(Sha256::digest(target.as_os_str().as_encoded_bytes())),
            ));
            if is_root {
                ensure!(
                    fs::metadata(path)?.is_dir(),
                    "linked tree root must be a directory"
                );
                for entry in fs::read_dir(path)? {
                    walk(root, &entry?.path(), Some(measured_roots), rows)?;
                }
            }
            return Ok(());
        }
        let kind = if meta.is_dir() {
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
        rows.push((name, kind.into(), digest));
        if meta.is_dir() {
            for entry in fs::read_dir(path)? {
                walk(root, &entry?.path(), measured_roots, rows)?;
            }
        }
        Ok(())
    }
    ensure!(
        if measured_roots.is_some() {
            fs::metadata(root)?.is_dir()
        } else {
            fs::symlink_metadata(root)?.is_dir()
        },
        "tree artifact must be a directory"
    );
    if let Some(roots) = measured_roots {
        reachable(
            root,
            roots,
            tracked,
            &mut BTreeSet::new(),
            &mut BTreeSet::new(),
        )?;
    }
    let mut rows = Vec::new();
    walk(root, root, measured_roots, &mut rows)?;
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let version = if measured_roots.is_some() { 2 } else { 1 };
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        version, rows,
    ))?)))
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
    let files = declarations(repo, head, lane)?;
    ensure!(
        git::text(repo, &["rev-parse", "HEAD"])? == head && super::signing::tracked_clean(repo)?,
        "workspace differs from exact committed HEAD"
    );
    for (root, artifact) in &lane.inputs {
        contained(repo, root, artifact.identity.starts_with("tree-sha256-v2:"))?;
    }
    for root in &lane.scratch {
        contained(repo, root, false)?;
    }
    let measured_roots = lane
        .inputs
        .iter()
        .filter(|(_, artifact)| {
            artifact.identity.starts_with("tree-sha256:")
                || artifact.identity.starts_with("tree-sha256-v2:")
        })
        .map(|(root, _)| fs::canonicalize(repo.join(root)))
        .collect::<std::io::Result<Vec<_>>>()?;
    let canonical_repo = fs::canonicalize(repo)?;
    for (index, root) in measured_roots.iter().enumerate() {
        if let Ok(relative) = root.strip_prefix(&canonical_repo) {
            let relative = relative.to_str().context("non UTF-8 materialization")?;
            ensure!(
                !files.iter().any(|file| overlaps(relative, file)),
                "measured input aliases tracked path"
            );
            ensure!(
                !lane
                    .scratch
                    .iter()
                    .any(|scratch| overlaps(relative, scratch)),
                "measured input aliases scratch"
            );
        }
        ensure!(
            !canonical_repo.starts_with(root)
                && !measured_roots[..index]
                    .iter()
                    .any(|other| root.starts_with(other) || other.starts_with(root)),
            "aliased or overlapping measured workspace roots"
        );
    }
    for (root, artifact) in &lane.inputs {
        let path = repo.join(root);
        let actual = if artifact.identity.starts_with("tree-sha256:") {
            tree_digest(&path)?
        } else if artifact.identity.starts_with("tree-sha256-v2:") {
            digest_tree(
                &path,
                Some(&measured_roots),
                Some((&canonical_repo, &files)),
            )?
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

//! BASE-owned immutable materializations and writable scratch, never implicit ignored inputs.
use crate::gate::{
    config::{self, Lane},
    git,
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

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
    digest_tree(root, None, None, &[])
}

/// Measure raw link targets and the complete contents of a possibly linked root.
/// Descendant links contribute only their raw targets to the digest, but their
/// complete reachable subtrees must be authorized. Verify also permits clean tracked paths.
/// Supply declared root paths without canonicalizing their final components, so
/// their individually measured root links can also authorize cross-root hops.
/// Standalone callers must independently measure every supplied authority root:
/// descendant links bind raw targets, not the contents reached in another root.
/// V2 observation requires Unix directory device/inode identities and is refused
/// explicitly on non-Unix platforms.
pub fn tree_digest_v2(root: &Path, measured_roots: &[std::path::PathBuf]) -> Result<String> {
    digest_tree(root, Some(measured_roots), None, &[])
}

#[derive(Default)]
struct Reachability {
    bound_roots: BTreeSet<std::path::PathBuf>,
    active: [BTreeSet<std::path::PathBuf>; 2],
    // Keep tracked-authority modes separate without allocating a tuple for lookups.
    complete: [BTreeSet<std::path::PathBuf>; 2],
    #[cfg(test)]
    expansions: [std::collections::BTreeMap<std::path::PathBuf, usize>; 2],
    entries: BTreeMap<PathBuf, ObservedEntry>,
    lookup_directories: BTreeMap<PathBuf, DirectoryIdentity>,
    root_lookups: BTreeMap<PathBuf, PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
enum ObservedEntry {
    Directory(Rc<[PathBuf]>),
    File(bool),
    Link(PathBuf),
}

// Lookup ancestors need identity binding, not a listing of unrelated siblings.
#[derive(Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl DirectoryIdentity {
    fn read(metadata: &fs::Metadata) -> Result<Self> {
        require_v2_platform()?;
        ensure!(
            metadata.is_dir(),
            "workspace lookup component is not a directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        unreachable!("non-Unix v2 observation is refused above")
    }
}

fn require_v2_platform() -> Result<()> {
    ensure!(
        cfg!(unix),
        "v2 workspace observation requires Unix directory device/inode identities"
    );
    Ok(())
}

#[cfg(test)]
type EntryObservationHook = (PathBuf, Box<dyn FnOnce()>);

#[cfg(test)]
thread_local! {
    static BEFORE_ENTRY_OBSERVATION: std::cell::RefCell<Option<EntryObservationHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_entry_observation_hook(path: &Path) {
    let hook = BEFORE_ENTRY_OBSERVATION.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.as_ref().is_some_and(|(expected, _)| expected == path) {
            slot.take()
        } else {
            None
        }
    });
    if let Some((_, run)) = hook {
        run();
    }
}

impl Reachability {
    fn bind_root(&mut self, path: &Path) -> Result<()> {
        // Bind the caller's lexical lookup too: canonicalizing its parent would
        // otherwise erase ancestor aliases before reachability validation.
        let requested = std::path::absolute(path)?;
        let resolved = resolve_links(
            &requested,
            &[],
            &mut None,
            &[],
            self,
            LookupPurpose::RootBinding,
        )?;
        if let Some(previous) = self.root_lookups.get(&requested) {
            ensure!(
                previous == &resolved,
                "workspace root lookup changed during observation"
            );
        } else {
            self.root_lookups.insert(requested, resolved);
        }
        let location = root_location(path)?;
        if fs::symlink_metadata(&location)?.file_type().is_symlink() {
            self.bound_roots.insert(location);
        }
        Ok(())
    }

    fn observe(&mut self, path: &Path, entry: ObservedEntry) -> Result<()> {
        if let Some(previous) = self.entries.get(path) {
            ensure!(
                previous == &entry,
                "workspace entry changed during observation: {}",
                path.display()
            );
        } else {
            self.entries.insert(path.to_owned(), entry);
        }
        Ok(())
    }

    fn observe_lookup_directory(&mut self, path: &Path, metadata: &fs::Metadata) -> Result<()> {
        let identity = DirectoryIdentity::read(metadata)?;
        if let Some(previous) = self.lookup_directories.get(path) {
            ensure!(
                previous == &identity,
                "workspace lookup directory changed during observation: {}",
                path.display()
            );
        } else {
            self.lookup_directories.insert(path.to_owned(), identity);
        }
        Ok(())
    }

    fn unchanged(&self) -> Result<()> {
        for (path, identity) in &self.lookup_directories {
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                metadata.is_dir() && DirectoryIdentity::read(&metadata)? == *identity,
                "workspace lookup directory changed during observation: {}",
                path.display()
            );
        }
        for (path, entry) in &self.entries {
            ensure!(
                &observe_entry(path)? == entry,
                "workspace entry changed during observation: {}",
                path.display()
            );
        }
        for (requested, resolved) in &self.root_lookups {
            ensure!(
                fs::canonicalize(requested)? == *resolved,
                "workspace root lookup changed during observation: {}",
                requested.display()
            );
        }
        Ok(())
    }
}

fn observe_entry(path: &Path) -> Result<ObservedEntry> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(ObservedEntry::Link(fs::read_link(path)?));
    }
    if metadata.is_dir() {
        let mut children = fs::read_dir(path)?
            .map(|entry| Ok(entry?.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        children.sort_unstable();
        return Ok(ObservedEntry::Directory(children.into()));
    }
    ensure!(metadata.is_file(), "unsupported workspace entry");
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    Ok(ObservedEntry::File(executable))
}

fn root_location(path: &Path) -> Result<std::path::PathBuf> {
    let Some(name) = path.file_name() else {
        return Ok(fs::canonicalize(path)?);
    };
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let mut location = fs::canonicalize(parent.unwrap_or(Path::new(".")))?;
    location.push(name);
    Ok(location)
}

fn authorized(
    path: &Path,
    measured_roots: &[std::path::PathBuf],
    tracked: Option<(&Path, &BTreeSet<String>)>,
    directory: bool,
) -> bool {
    measured_roots.iter().any(|root| path.starts_with(root))
        || tracked.is_some_and(|(repo, files)| {
            let Some(name) = path.strip_prefix(repo).ok().and_then(Path::to_str) else {
                return false;
            };
            if files.contains(name) {
                return true;
            }
            if !directory {
                return false;
            }
            let prefix = format!("{name}/");
            files
                .range::<str, _>((
                    std::ops::Bound::Included(prefix.as_str()),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .is_some_and(|file| file.starts_with(&prefix))
        })
}

#[derive(Clone, Copy)]
enum LookupPurpose {
    // Capture the caller's original lookup without granting link authority.
    RootBinding,
    Reachability,
}

// Resolve target components explicitly: canonicalize alone hides unmeasured bridge links.
fn resolve_links(
    path: &Path,
    measured_roots: &[std::path::PathBuf],
    tracked: &mut Option<(&Path, &BTreeSet<String>)>,
    closure_roots: &[std::path::PathBuf],
    state: &mut Reachability,
    purpose: LookupPurpose,
) -> Result<std::path::PathBuf> {
    use std::path::{Component, PathBuf};
    let mut pending = match purpose {
        LookupPurpose::RootBinding => std::path::absolute(path)?,
        // Workspace ancestors are constrained by contained(); binding separately
        // preserves the full requested lookup, including standalone root aliases.
        LookupPurpose::Reachability => root_location(path)?,
    };
    let mut hops = 0;
    loop {
        let mut resolved = PathBuf::new();
        let mut components = pending.components();
        let next = loop {
            let Some(component) = components.next() else {
                return Ok(resolved);
            };
            match component {
                Component::ParentDir => {
                    resolved.pop();
                    continue;
                }
                Component::CurDir => continue,
                _ => resolved.push(component.as_os_str()),
            }
            // Once a path enters a closure, every following hop stays within
            // measured inputs and closure members, never checkout-only authority.
            if super::nix::contains(&resolved, closure_roots) {
                *tracked = None;
            }
            let meta =
                fs::symlink_metadata(&resolved).context("dangling or cyclic workspace symlink")?;
            if !meta.file_type().is_symlink() {
                if meta.is_dir() {
                    state.observe_lookup_directory(&resolved, &meta)?;
                }
                continue;
            }
            ensure!(
                matches!(purpose, LookupPurpose::RootBinding)
                    || state.bound_roots.contains(&resolved)
                    || authorized(&resolved, measured_roots, *tracked, false),
                "workspace symlink escapes through unmeasured intermediate link: {}",
                resolved.display()
            );
            hops += 1;
            ensure!(
                hops <= 40,
                "cyclic workspace symlink or excessive link chain"
            );
            let target = fs::read_link(&resolved)?;
            state.observe(&resolved, ObservedEntry::Link(target.clone()))?;
            let mut next = if target.is_absolute() {
                target
            } else {
                resolved
                    .parent()
                    .context("symlink without parent")?
                    .join(target)
            };
            next.push(components.as_path());
            break next;
        };
        pending = next;
    }
}

// Validate reachability separately from digest rows: v1 and v2 preimages stay unchanged.
fn reachable(
    path: &Path,
    measured_roots: &[std::path::PathBuf],
    tracked: Option<(&Path, &BTreeSet<String>)>,
    closure_roots: &[std::path::PathBuf],
    state: &mut Reachability,
) -> Result<PathBuf> {
    let mut tracked = tracked;
    let resolved = resolve_links(
        path,
        measured_roots,
        &mut tracked,
        closure_roots,
        state,
        LookupPurpose::Reachability,
    )?;
    let meta = fs::symlink_metadata(&resolved)?;
    let authorized = authorized(&resolved, measured_roots, tracked, meta.is_dir());
    ensure!(
        authorized,
        "workspace symlink escapes measured inputs: {}",
        path.display()
    );
    ensure!(
        meta.is_dir() || meta.is_file(),
        "unsupported workspace entry"
    );
    let mode = usize::from(tracked.is_some());
    if meta.is_dir() && state.complete[mode].contains(&resolved) {
        return Ok(resolved);
    }
    // Directory dependency cycles are safe co-inductively: this mode is already
    // validating every physical child. Nonterminating link chains fail in resolve_links.
    if meta.is_dir() && !state.active[mode].insert(resolved.clone()) {
        return Ok(resolved);
    }
    #[cfg(test)]
    run_entry_observation_hook(&resolved);
    let entry = observe_entry(&resolved)?;
    // Only resolve_links may record links. A new link here has never had its
    // destination authorized, even if its path was previously a regular entry.
    ensure!(
        match &entry {
            ObservedEntry::Directory(_) => meta.is_dir(),
            ObservedEntry::File(_) => meta.is_file(),
            ObservedEntry::Link(_) => false,
        },
        "workspace entry kind changed during observation: {}",
        resolved.display()
    );
    state.observe(&resolved, entry)?;
    if !meta.is_dir() {
        return Ok(resolved);
    }
    #[cfg(test)]
    {
        *state.expansions[mode].entry(resolved.clone()).or_default() += 1;
    }
    // A tracked directory prefix only permits traversal, never its untracked children.
    let Some(ObservedEntry::Directory(children)) = state.entries.get(&resolved) else {
        anyhow::bail!(
            "workspace entry changed during observation: {}",
            resolved.display()
        );
    };
    // Retain the validated child list while recursion adds other graph entries.
    let children = Rc::clone(children);
    for child in children.iter() {
        reachable(child, measured_roots, tracked, closure_roots, state)?;
    }
    state.active[mode].remove(&resolved);
    state.complete[mode].insert(resolved.clone());
    Ok(resolved)
}

fn digest_tree(
    root: &Path,
    measured_roots: Option<&[std::path::PathBuf]>,
    tracked: Option<(&Path, &BTreeSet<String>)>,
    closure_roots: &[std::path::PathBuf],
) -> Result<String> {
    let Some(roots) = measured_roots else {
        return digest_rows(root);
    };
    require_v2_platform()?;
    let canonical_roots = roots
        .iter()
        .map(fs::canonicalize)
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut state = Reachability::default();
    state.bind_root(root)?;
    for declared_root in roots {
        state.bind_root(declared_root)?;
    }
    let resolved = reachable(root, &canonical_roots, tracked, closure_roots, &mut state)?;
    let digest = digest_validated(root, &resolved, &state)?;
    for (declared, canonical) in roots.iter().zip(&canonical_roots) {
        ensure!(
            fs::canonicalize(declared)? == *canonical,
            "workspace authority root changed during observation"
        );
    }
    state.unchanged()?;
    Ok(digest)
}

// Hash only the recorded graph, never re-discover a link's destination while hashing.
fn digest_validated(root: &Path, resolved: &Path, state: &Reachability) -> Result<String> {
    fn walk(
        path: &Path,
        name: &Path,
        state: &Reachability,
        rows: &mut Vec<(String, String, String)>,
    ) -> Result<()> {
        let entry = state
            .entries
            .get(path)
            .context("unvalidated workspace entry")?;
        // In particular, reread every link target immediately before its digest row.
        ensure!(
            &observe_entry(path)? == entry,
            "workspace entry changed during measurement: {}",
            path.display()
        );
        let relative = name
            .to_str()
            .context("non UTF-8 materialization")?
            .to_owned();
        match entry {
            ObservedEntry::Link(target) => rows.push((
                relative,
                "symlink".into(),
                hex::encode(Sha256::digest(target.as_os_str().as_encoded_bytes())),
            )),
            ObservedEntry::File(executable) => rows.push((
                relative,
                if *executable { "executable" } else { "file" }.into(),
                super::signing::hash_file(path)?,
            )),
            ObservedEntry::Directory(children) => {
                rows.push((relative, "directory".into(), String::new()));
                for child in children.iter() {
                    walk(
                        child,
                        &name.join(child.file_name().context("workspace child without name")?),
                        state,
                        rows,
                    )?;
                }
            }
        }
        Ok(())
    }
    let location = root_location(root)?;
    let entry = state
        .entries
        .get(resolved)
        .context("unvalidated workspace root")?;
    let ObservedEntry::Directory(children) = entry else {
        anyhow::bail!("tree artifact must be a directory");
    };
    let mut rows = Vec::new();
    if matches!(state.entries.get(&location), Some(ObservedEntry::Link(_))) {
        walk(&location, Path::new(""), state, &mut rows)?;
        // A root link binds its target and the resolved directory's children, not
        // an extra directory row. This preserves the existing v2 preimage.
        for child in children.iter() {
            walk(
                child,
                Path::new(child.file_name().context("workspace child without name")?),
                state,
                &mut rows,
            )?;
        }
    } else {
        walk(resolved, Path::new(""), state, &mut rows)?;
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(2, rows))?)))
}

fn digest_rows(root: &Path) -> Result<String> {
    fn walk(root: &Path, path: &Path, rows: &mut Vec<(String, String, String)>) -> Result<()> {
        let meta = fs::symlink_metadata(path)?;
        let name = path
            .strip_prefix(root)?
            .to_str()
            .context("non UTF-8 materialization")?
            .to_owned();
        ensure!(
            !meta.file_type().is_symlink(),
            "materialized input contains symlink"
        );
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
pub fn verify(
    repo: &Path,
    head: &str,
    lane: &Lane,
    start: bool,
    toolchain: Option<&super::signing::ToolchainMeasurement>,
) -> Result<()> {
    let files = declarations(repo, head, lane)?;
    if lane
        .inputs
        .values()
        .any(|artifact| artifact.identity.starts_with("tree-sha256-v2:"))
    {
        require_v2_platform()?;
    }
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
    let declared_tree_roots: Vec<_> = lane
        .inputs
        .iter()
        .filter(|(_, artifact)| {
            artifact.identity.starts_with("tree-sha256:")
                || artifact.identity.starts_with("tree-sha256-v2:")
        })
        .map(|(root, _)| repo.join(root))
        .collect();
    let mut measured_roots = declared_tree_roots
        .iter()
        .map(fs::canonicalize)
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
    if let Some(toolchain) = toolchain {
        measured_roots.extend_from_slice(&toolchain.nix_roots);
    }
    let mut reachability = Reachability::default();
    for (root, artifact) in &lane.inputs {
        if artifact.identity.starts_with("tree-sha256-v2:") {
            reachability.bind_root(&repo.join(root))?;
        }
    }
    for (root, artifact) in &lane.inputs {
        let path = repo.join(root);
        let actual = if artifact.identity.starts_with("tree-sha256:") {
            tree_digest(&path)?
        } else if artifact.identity.starts_with("tree-sha256-v2:") {
            let resolved = reachable(
                &path,
                &measured_roots,
                Some((&canonical_repo, &files)),
                toolchain.map_or(&[], |measurement| measurement.nix_roots.as_slice()),
                &mut reachability,
            )?;
            digest_validated(&path, &resolved, &reachability)?
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
    // Includes bridges and reachable directories omitted from digest rows, and
    // roots cached by an earlier input in this same observation.
    for (declared, canonical) in declared_tree_roots.iter().zip(&measured_roots) {
        ensure!(
            fs::canonicalize(declared)? == *canonical,
            "workspace authority root changed during observation"
        );
    }
    reachability.unchanged()?;
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
    if let Some(toolchain) = toolchain {
        super::nix::require_members(toolchain.nix_roots.iter().map(PathBuf::as_path))?;
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

    #[cfg(unix)]
    fn closure_directory_link(case: &str) -> Result<String> {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir()?;
        let repo = fixture.path().join("repo");
        let modules = repo.join("modules");
        let store = fixture.path().join("store");
        let package = store.join("00000000000000000000000000000000-package");
        let dependency = store.join("11111111111111111111111111111111-dependency");
        fs::create_dir_all(&modules)?;
        fs::create_dir_all(package.join("bin"))?;
        fs::create_dir_all(&dependency)?;
        fs::write(dependency.join("helper"), "authorized")?;
        let outside = fixture.path().join("helper");
        fs::write(&outside, "unmeasured")?;
        fs::write(repo.join("tracked"), "tracked")?;
        let target = match case {
            "authorized" => dependency.join("helper"),
            "authorized-directory" => dependency.clone(),
            "authorized-bridge" => {
                symlink("helper", dependency.join("bridge"))?;
                dependency.join("bridge")
            }
            "outside-bridge" => {
                let bridge = fixture.path().join("bridge");
                symlink(dependency.join("helper"), &bridge)?;
                bridge
            }
            "tracked-bridge" => {
                let bridge = repo.join("bridge");
                symlink(dependency.join("helper"), &bridge)?;
                bridge
            }
            "measured" => {
                fs::write(modules.join("helper"), "measured")?;
                modules.join("helper")
            }
            "tracked" => repo.join("tracked"),
            _ => outside,
        };
        symlink(target, package.join("bin/helper"))?;
        symlink(&package, modules.join("package"))?;
        let closure = vec![package, dependency];
        let mut measured = vec![modules.clone()];
        measured.extend_from_slice(&closure);
        digest_tree(
            &modules,
            Some(&measured),
            Some((&repo, &BTreeSet::from(["tracked".into(), "bridge".into()]))),
            &closure,
        )
    }

    #[cfg(unix)]
    #[test]
    fn closure_directory_link_rejects_nested_unmeasured_helper() {
        for case in ["escape", "tracked", "outside-bridge", "tracked-bridge"] {
            let error = closure_directory_link(case).unwrap_err();
            assert!(
                error.to_string().contains("symlink escapes"),
                "{case}: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn closure_directory_link_accepts_other_authorized_member_and_measured_root() {
        for case in [
            "authorized",
            "authorized-directory",
            "authorized-bridge",
            "measured",
        ] {
            closure_directory_link(case).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn observation_reachability_expands_shared_chained_roots_once_per_authority_mode() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(fixture.path()).unwrap();
        let roots: Vec<_> = (0..8)
            .map(|index| base.join(format!("root{index}")))
            .collect();
        for root in &roots {
            fs::create_dir(root).unwrap();
        }
        for pair in roots.windows(2) {
            symlink(&pair[1], pair[0].join("next")).unwrap();
        }
        for root in &roots[..7] {
            symlink(&roots[7], root.join("shared")).unwrap();
        }
        let files = BTreeSet::new();
        let mut observation = Reachability::default();
        for tracked in [None, Some((base.as_path(), &files))] {
            for root in &roots {
                reachable(root, &roots, tracked, &[], &mut observation).unwrap();
            }
        }
        for mode in 0..2 {
            assert_eq!(observation.expansions[mode].len(), roots.len());
            assert!(
                observation.expansions[mode]
                    .values()
                    .all(|count| *count == 1)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn pnpm_internal_directory_aliases_remain_authorized() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let modules = fs::canonicalize(fixture.path()).unwrap();
        let package = modules.join(".pnpm/pkg/node_modules/pkg");
        fs::create_dir_all(&package).unwrap();
        fs::write(package.join("index.js"), "package").unwrap();
        symlink(".pnpm/pkg/node_modules/pkg", modules.join("pkg")).unwrap();
        symlink("pkg/node_modules/pkg", modules.join(".pnpm/alias")).unwrap();
        tree_digest_v2(&modules, std::slice::from_ref(&modules)).unwrap();
    }

    #[test]
    fn tracked_directory_range_lookup_is_component_aware() {
        let repo = Path::new("/checkout");
        let files = BTreeSet::from([
            "packages/core-extra/index.js".into(),
            "packages/core/index.js".into(),
        ]);
        let tracked = Some((repo, &files));
        assert!(authorized(&repo.join("packages/core"), &[], tracked, true));
        assert!(!authorized(&repo.join("packages/cor"), &[], tracked, true));
        assert!(!authorized(
            &repo.join("packages/core"),
            &[],
            tracked,
            false
        ));
    }

    #[cfg(unix)]
    #[test]
    fn root_retarget_between_validation_and_hashing_is_refused() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(fixture.path()).unwrap();
        let first = base.join("first");
        let second = base.join("second");
        let root = base.join("root");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        fs::write(first.join("file"), "first").unwrap();
        fs::write(second.join("file"), "second").unwrap();
        symlink(&first, &root).unwrap();
        let mut state = Reachability::default();
        state.bind_root(&root).unwrap();
        let resolved = reachable(&root, &[first, second.clone()], None, &[], &mut state).unwrap();
        fs::remove_file(&root).unwrap();
        symlink(second, &root).unwrap();
        let error = digest_validated(&root, &resolved, &state).unwrap_err();
        assert!(
            error.to_string().contains("changed during measurement"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authorized_bridge_retarget_during_observation_is_refused() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(fixture.path()).unwrap();
        let modules = base.join("modules");
        let authority = base.join("authority");
        fs::create_dir(&modules).unwrap();
        fs::create_dir(&authority).unwrap();
        for name in ["first", "second"] {
            fs::write(authority.join(name), name).unwrap();
        }
        let bridge = authority.join("bridge");
        symlink("first", &bridge).unwrap();
        symlink(&bridge, modules.join("dependency")).unwrap();
        let mut state = Reachability::default();
        let resolved = reachable(
            &modules,
            &[modules.clone(), authority],
            None,
            &[],
            &mut state,
        )
        .unwrap();
        // This bridge has no digest row in modules: it must still be bound to
        // the validated graph, even when both old and new endpoints are authorized.
        fs::remove_file(&bridge).unwrap();
        symlink("second", &bridge).unwrap();
        digest_validated(&modules, &resolved, &state).unwrap();
        let error = state.unchanged().unwrap_err();
        assert!(
            error.to_string().contains("changed during observation"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cached_dependency_cycle_mutation_during_observation_is_refused() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(fixture.path()).unwrap();
        let first = base.join("first");
        let second = base.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        symlink(&second, first.join("next")).unwrap();
        symlink(&first, second.join("next")).unwrap();
        let roots = [first.clone(), second.clone()];
        let mut state = Reachability::default();
        let resolved = reachable(&first, &roots, None, &[], &mut state).unwrap();
        fs::remove_file(second.join("next")).unwrap();
        symlink("next", second.join("next")).unwrap();
        // A cache hit is not a new authorization of the mutated graph.
        reachable(&first, &roots, None, &[], &mut state).unwrap();
        digest_validated(&first, &resolved, &state).unwrap();
        assert!(
            state
                .unchanged()
                .unwrap_err()
                .to_string()
                .contains("changed")
        );
        assert!(tree_digest_v2(&first, &roots).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn link_chain_limit_accepts_40_hops_and_refuses_41() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(fixture.path()).unwrap();
        fs::write(root.join("file"), "content").unwrap();
        for index in 0..40 {
            let target = if index == 39 {
                "file".into()
            } else {
                format!("link{}", index + 1)
            };
            symlink(target, root.join(format!("link{index}"))).unwrap();
        }
        tree_digest_v2(&root, std::slice::from_ref(&root)).unwrap();
        fs::remove_file(root.join("link39")).unwrap();
        symlink("link40", root.join("link39")).unwrap();
        symlink("file", root.join("link40")).unwrap();
        let error = tree_digest_v2(&root, std::slice::from_ref(&root)).unwrap_err();
        assert!(
            error.to_string().contains("excessive link chain"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn closure_parent_components_cannot_escape_to_tracked_authority() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(fixture.path()).unwrap();
        let modules = repo.join("modules");
        let member = repo.join("store/member");
        fs::create_dir(&modules).unwrap();
        fs::create_dir_all(member.join("bin")).unwrap();
        fs::write(repo.join("helper"), "tracked but not closure-authorized").unwrap();
        symlink("../../../helper", member.join("bin/helper")).unwrap();
        symlink(&member, modules.join("package")).unwrap();
        let roots = [modules.clone(), member.clone()];
        let files = BTreeSet::from(["helper".into()]);
        let error =
            digest_tree(&modules, Some(&roots), Some((&repo, &files)), &[member]).unwrap_err();
        assert!(error.to_string().contains("symlink escapes"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn alternating_tracked_closure_and_measured_chains_keep_restricted_mode() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(fixture.path()).unwrap();
        let modules = repo.join("modules");
        let measured = repo.join("measured");
        let member = repo.join("store/member");
        fs::create_dir(&modules).unwrap();
        fs::create_dir(&measured).unwrap();
        fs::create_dir_all(&member).unwrap();
        fs::write(member.join("helper"), "authorized").unwrap();
        fs::write(repo.join("helper"), "tracked").unwrap();
        symlink(member.join("next"), repo.join("bridge")).unwrap();
        symlink(measured.join("return"), member.join("next")).unwrap();
        symlink(member.join("helper"), measured.join("return")).unwrap();
        symlink(repo.join("bridge"), modules.join("dependency")).unwrap();
        let files = BTreeSet::from(["bridge".into(), "helper".into()]);
        let roots = [modules.clone(), measured.clone(), member.clone()];
        digest_tree(
            &modules,
            Some(&roots),
            Some((&repo, &files)),
            std::slice::from_ref(&member),
        )
        .unwrap();
        fs::remove_file(measured.join("return")).unwrap();
        symlink(repo.join("helper"), measured.join("return")).unwrap();
        let error =
            digest_tree(&modules, Some(&roots), Some((&repo, &files)), &[member]).unwrap_err();
        assert!(error.to_string().contains("symlink escapes"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn cache_mode_switch_after_closure_does_not_reuse_tracked_authority() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(fixture.path()).unwrap();
        let modules = repo.join("modules");
        let member = repo.join("store/member");
        fs::create_dir(&modules).unwrap();
        fs::create_dir_all(&member).unwrap();
        fs::write(repo.join("helper"), "tracked").unwrap();
        symlink(repo.join("helper"), modules.join("dependency")).unwrap();
        symlink(&modules, member.join("return")).unwrap();
        let roots = [modules.clone(), member.clone()];
        let files = BTreeSet::from(["helper".into()]);
        let mut state = Reachability::default();
        reachable(
            &modules,
            &roots,
            Some((&repo, &files)),
            std::slice::from_ref(&member),
            &mut state,
        )
        .unwrap();
        // Closure traversal must expand modules again without tracked authority.
        let error = reachable(
            &member,
            &roots,
            Some((&repo, &files)),
            std::slice::from_ref(&member),
            &mut state,
        )
        .unwrap_err();
        assert!(error.to_string().contains("symlink escapes"), "{error}");
        assert_eq!(state.expansions[0].get(&modules), Some(&1));
        assert_eq!(state.expansions[1].get(&modules), Some(&1));
    }

    #[cfg(unix)]
    #[test]
    fn validated_graph_preserves_v2_linked_and_physical_root_preimages() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(fixture.path()).unwrap();
        let physical = base.join("physical");
        fs::create_dir(&physical).unwrap();
        fs::write(physical.join("file"), "content").unwrap();
        symlink("file", physical.join("alias")).unwrap();
        let linked = base.join("linked");
        symlink("physical", &linked).unwrap();
        let hash = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        for (root, kind, value) in [
            (&physical, "directory", String::new()),
            (&linked, "symlink", hash(b"physical")),
        ] {
            let rows = [
                ("", kind, value),
                ("alias", "symlink", hash(b"file")),
                ("file", "file", hash(b"content")),
            ];
            let expected = hash(&serde_json::to_vec(&(2, rows)).unwrap());
            assert_eq!(
                tree_digest_v2(root, std::slice::from_ref(&linked)).unwrap(),
                expected
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn entry_kind_swap_after_authorization_cannot_record_an_unresolved_link() {
        use std::os::unix::fs::symlink;
        for directory in [false, true] {
            for destination in ["outside", "dangling", "cycle"] {
                let fixture = tempfile::tempdir().unwrap();
                let base = fs::canonicalize(fixture.path()).unwrap();
                let root = base.join("inputs");
                fs::create_dir(&root).unwrap();
                fs::write(base.join("outside"), "unmeasured").unwrap();
                let entry = root.join("entry");
                if directory {
                    fs::create_dir(&entry).unwrap();
                } else {
                    fs::write(&entry, "authorized regular file").unwrap();
                }
                let target = match destination {
                    "outside" => base.join("outside"),
                    "dangling" => base.join("missing"),
                    _ => entry.clone(),
                };
                let replaced = entry.clone();
                BEFORE_ENTRY_OBSERVATION.with(|slot| {
                    *slot.borrow_mut() = Some((
                        entry,
                        Box::new(move || {
                            if directory {
                                fs::remove_dir(&replaced).unwrap();
                            } else {
                                fs::remove_file(&replaced).unwrap();
                            }
                            symlink(target, replaced).unwrap();
                        }),
                    ));
                });
                let error = tree_digest_v2(&root, std::slice::from_ref(&root)).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("entry kind changed during observation"),
                    "{directory}/{destination}: {error}"
                );
                BEFORE_ENTRY_OBSERVATION.with(|slot| assert!(slot.borrow().is_none()));
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn ancestor_directory_substitution_after_resolution_is_refused() {
        use std::os::unix::fs::symlink;
        for measured_destination in [false, true] {
            let fixture = tempfile::tempdir().unwrap();
            let base = fs::canonicalize(fixture.path()).unwrap();
            let root = base.join("root");
            let authority = base.join("authority");
            let ancestor = authority.join("ancestor");
            let destination = base.join("destination");
            fs::create_dir(&root).unwrap();
            fs::create_dir_all(&ancestor).unwrap();
            fs::create_dir(&destination).unwrap();
            fs::write(ancestor.join("leaf"), "original").unwrap();
            fs::write(destination.join("leaf"), "substituted").unwrap();
            symlink(ancestor.join("leaf"), root.join("link")).unwrap();
            let mut roots = vec![root.clone(), authority];
            if measured_destination {
                roots.push(destination.clone());
            }
            BEFORE_ENTRY_OBSERVATION.with(|slot| {
                *slot.borrow_mut() = Some((
                    ancestor.join("leaf"),
                    Box::new(move || {
                        fs::rename(&ancestor, base.join("original")).unwrap();
                        symlink(destination, ancestor).unwrap();
                    }),
                ));
            });
            let error = tree_digest_v2(&root, &roots).unwrap_err();
            assert!(
                error.to_string().contains("lookup directory changed"),
                "{measured_destination}: {error}"
            );
            BEFORE_ENTRY_OBSERVATION.with(|slot| assert!(slot.borrow().is_none()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn earlier_legacy_tree_cannot_hide_later_v2_ancestor_substitution() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let repo = fs::canonicalize(fixture.path()).unwrap();
        git::git(&repo, &["init", "-q"]).unwrap();
        git::git(
            &repo,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--allow-empty",
                "-qm",
                "base",
            ],
        )
        .unwrap();
        let head = git::text(&repo, &["rev-parse", "HEAD"]).unwrap();
        let legacy = repo.join("a-legacy");
        let ancestor = legacy.join("ancestor");
        let v2 = repo.join("z-v2");
        let destination = repo.join("outside");
        fs::create_dir_all(&ancestor).unwrap();
        fs::create_dir(&v2).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(ancestor.join("leaf"), "original").unwrap();
        fs::write(destination.join("leaf"), "substituted").unwrap();
        symlink(ancestor.join("leaf"), v2.join("link")).unwrap();
        let roots = [legacy.clone(), v2.clone()];
        let legacy_digest = tree_digest(&legacy).unwrap();
        let v2_digest = tree_digest_v2(&v2, &roots).unwrap();
        let lane: Lane = serde_json::from_value(serde_json::json!({
            "argv":["check"], "definition_paths":["tools"],
            "trust_levels":["agent"], "mode":"required_evidence", "events":["pull_request"],
            "environment":{"manifest":"environment.json","paths":["tools"]},
            "protected_edits":"reject", "remediation_argv":["check"],
            "inputs":{
                "a-legacy":{"name":"legacy","identity":format!("tree-sha256:{legacy_digest}")},
                "outside":{"name":"destination","identity":format!("tree-sha256:{}", tree_digest(&destination).unwrap())},
                "z-v2":{"name":"v2","identity":format!("tree-sha256-v2:{v2_digest}")}
            }
        })).unwrap();
        verify(&repo, &head, &lane, false, None).unwrap();
        BEFORE_ENTRY_OBSERVATION.with(|slot| {
            *slot.borrow_mut() = Some((
                ancestor.join("leaf"),
                Box::new(move || {
                    fs::rename(&ancestor, legacy.join("original")).unwrap();
                    symlink(destination, ancestor).unwrap();
                }),
            ));
        });
        let error = verify(&repo, &head, &lane, false, None).unwrap_err();
        assert!(
            error.to_string().contains("lookup directory changed"),
            "{error}"
        );
        BEFORE_ENTRY_OBSERVATION.with(|slot| assert!(slot.borrow().is_none()));
    }

    #[cfg(unix)]
    #[test]
    fn replacing_lookup_directory_with_another_directory_is_refused() {
        let fixture = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(fixture.path()).unwrap();
        let root = base.join("root");
        fs::create_dir(&root).unwrap();
        let mut state = Reachability::default();
        state
            .observe_lookup_directory(&root, &fs::symlink_metadata(&root).unwrap())
            .unwrap();
        fs::rename(&root, base.join("original")).unwrap();
        fs::create_dir(&root).unwrap();
        let error = state.unchanged().unwrap_err();
        assert!(
            error.to_string().contains("lookup directory changed"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn standalone_root_ancestor_alias_retarget_is_refused() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(fixture.path()).unwrap();
        let real = base.join("real");
        let outside = base.join("outside");
        let alias = base.join("alias");
        fs::create_dir_all(real.join("tree")).unwrap();
        fs::create_dir_all(outside.join("tree")).unwrap();
        fs::write(real.join("tree/leaf"), "authorized").unwrap();
        fs::write(outside.join("tree/leaf"), "unmeasured").unwrap();
        symlink(&real, &alias).unwrap();
        let requested = alias.join("tree");
        let roots = [real.clone()];
        tree_digest_v2(&requested, &roots).unwrap();
        BEFORE_ENTRY_OBSERVATION.with(|slot| {
            *slot.borrow_mut() = Some((
                real.join("tree/leaf"),
                Box::new(move || {
                    fs::remove_file(&alias).unwrap();
                    symlink(outside, alias).unwrap();
                }),
            ));
        });
        // The resolved graph remains intact; only the original requested lookup
        // changes. Canonical authority-root and physical-directory checks alone
        // cannot detect this retarget.
        let error = tree_digest_v2(&requested, &roots).unwrap_err();
        assert!(
            error.to_string().contains("changed during observation"),
            "{error}"
        );
        BEFORE_ENTRY_OBSERVATION.with(|slot| assert!(slot.borrow().is_none()));
    }

    #[cfg(not(unix))]
    #[test]
    fn v2_observation_explicitly_refuses_non_unix() {
        let fixture = tempfile::tempdir().unwrap();
        let error = tree_digest_v2(fixture.path(), &[]).unwrap_err();
        assert!(error.to_string().contains("requires Unix"), "{error}");
    }
}

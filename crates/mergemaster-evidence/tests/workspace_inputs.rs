//! The wrapper and signer share this filesystem-byte and index-flag check.
use mergemaster_evidence::evidence::signing::clean;
use std::{fs, path::Path, process::Command};

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn fixture() -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "-q"]);
    fs::create_dir(repo.path().join("tools")).unwrap();
    fs::write(repo.path().join("tools/check"), "printf trusted\\n\n").unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "base"]);
    assert!(clean(repo.path()).unwrap());
    repo
}

#[test]
fn modified_executable_inputs_refuse_even_when_hidden_from_status() {
    for flag in [None, Some("--skip-worktree"), Some("--assume-unchanged")] {
        let repo = fixture();
        if let Some(flag) = flag {
            git(repo.path(), &["update-index", flag, "tools/check"]);
        }
        fs::write(repo.path().join("tools/check"), "printf untrusted\\n\n").unwrap();
        if flag.is_some() {
            assert!(git(repo.path(), &["status", "--porcelain"]).is_empty());
        }
        assert!(
            !clean(repo.path()).unwrap(),
            "accepted modified input with {flag:?}"
        );
    }
}

#[test]
fn hidden_index_flags_refuse_even_without_a_modification() {
    for flag in ["--skip-worktree", "--assume-unchanged"] {
        let repo = fixture();
        git(repo.path(), &["update-index", flag, "tools/check"]);
        assert!(
            !clean(repo.path()).unwrap(),
            "accepted hidden input with {flag}"
        );
    }
}

#[test]
fn actual_bytes_must_match_blobs_even_when_a_clean_filter_hides_the_change() {
    let repo = fixture();
    fs::write(
        repo.path().join(".gitattributes"),
        "tools/check filter=erase\n",
    )
    .unwrap();
    git(
        repo.path(),
        &["config", "filter.erase.clean", "printf canonical"],
    );
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["add", "--renormalize", "tools/check"]);
    git(repo.path(), &["commit", "-q", "-m", "filtered input"]);
    fs::write(repo.path().join("tools/check"), "printf untrusted\\n\n").unwrap();
    // Refresh cached stat data through the filter without changing the canonical blob.
    git(repo.path(), &["add", "tools/check"]);
    assert!(git(repo.path(), &["status", "--porcelain"]).is_empty());
    assert!(
        !clean(repo.path()).unwrap(),
        "accepted bytes different from the committed blob"
    );
}

fn lane() -> mergemaster_evidence::gate::config::Lane {
    serde_json::from_value(
        serde_json::json!({"argv":["check"],"definition_paths":["tools"],
        "trust_levels":["agent"],"mode":"required_evidence","events":["pull_request"],
        "environment":{"manifest":"environment.json","paths":["tools"]},
        "protected_edits":"reject","remediation_argv":["check"],"scratch":["output"]}),
    )
    .unwrap()
}

#[test]
fn workspace_roots_refuse_escape_overlap_tracked_collisions_and_symlinks() {
    use mergemaster_evidence::evidence::workspace::{validate, verify};
    for root in [
        "../escape",
        "/escape",
        ".git/objects",
        "tools",
        "tools/check",
        "tools/check/child",
        "output/nested",
    ] {
        let repo = fixture();
        let head = git(repo.path(), &["rev-parse", "HEAD"]);
        let mut lane = lane();
        lane.scratch.push(root.into());
        assert!(validate(repo.path(), head.trim(), &lane).is_err(), "{root}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        for root in ["output", "parent/output"] {
            let repo = fixture();
            let outside = tempfile::tempdir().unwrap();
            let head = git(repo.path(), &["rev-parse", "HEAD"]);
            let mut lane = lane();
            lane.scratch = vec![root.into()];
            symlink(
                outside.path(),
                repo.path().join(root.split('/').next().unwrap()),
            )
            .unwrap();
            assert!(verify(repo.path(), head.trim(), &lane, true).is_err());
        }
    }
}

#[test]
fn materialized_tree_identity_binds_bytes_modes_paths_and_empty_directories() {
    use mergemaster_evidence::evidence::workspace::tree_digest;
    let tree = tempfile::tempdir().unwrap();
    fs::write(tree.path().join("input"), "bytes").unwrap();
    let original = tree_digest(tree.path()).unwrap();
    fs::create_dir(tree.path().join("empty")).unwrap();
    assert_ne!(tree_digest(tree.path()).unwrap(), original);
    fs::remove_dir(tree.path().join("empty")).unwrap();
    fs::write(tree.path().join("input"), "changed").unwrap();
    assert_ne!(tree_digest(tree.path()).unwrap(), original);
    fs::write(tree.path().join("input"), "bytes").unwrap();
    fs::rename(tree.path().join("input"), tree.path().join("renamed")).unwrap();
    assert_ne!(tree_digest(tree.path()).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::rename(tree.path().join("renamed"), tree.path().join("input")).unwrap();
        fs::set_permissions(tree.path().join("input"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(tree_digest(tree.path()).unwrap(), original);
        symlink("input", tree.path().join("link")).unwrap();
        assert!(tree_digest(tree.path()).is_err());
    }
}

#[cfg(unix)]
#[test]
fn symlink_tree_digest_measures_targets_and_refuses_unmeasured_destinations() {
    use mergemaster_evidence::evidence::workspace::{tree_digest, tree_digest_v2};
    use std::os::unix::fs::symlink;
    let tree = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let roots = vec![fs::canonicalize(tree.path()).unwrap()];
    fs::write(tree.path().join("input"), "bytes").unwrap();
    fs::write(tree.path().join("same-bytes"), "bytes").unwrap();
    symlink("input", tree.path().join("link")).unwrap();
    let original = tree_digest_v2(tree.path(), &roots).unwrap();
    assert!(tree_digest(tree.path()).is_err());
    fs::remove_file(tree.path().join("link")).unwrap();
    symlink("same-bytes", tree.path().join("link")).unwrap();
    assert_ne!(tree_digest_v2(tree.path(), &roots).unwrap(), original);
    fs::remove_file(tree.path().join("link")).unwrap();
    symlink("missing", tree.path().join("link")).unwrap();
    assert!(tree_digest_v2(tree.path(), &roots).is_err());
    fs::remove_file(tree.path().join("link")).unwrap();
    symlink(other.path(), tree.path().join("link")).unwrap();
    assert!(tree_digest_v2(tree.path(), &roots).is_err());
    let mut both = roots;
    both.push(fs::canonicalize(other.path()).unwrap());
    assert!(tree_digest_v2(tree.path(), &both).is_ok());
    fs::remove_file(tree.path().join("link")).unwrap();
    symlink(other.path().join("missing"), tree.path().join("link")).unwrap();
    assert!(tree_digest_v2(tree.path(), &both).is_err());
}

#[cfg(unix)]
#[test]
fn linked_tree_roots_measure_raw_targets_and_complete_resolved_contents() {
    use mergemaster_evidence::evidence::workspace::{tree_digest, tree_digest_v2};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::symlink;

    for absolute in [false, true] {
        let fixture = tempfile::tempdir().unwrap();
        for target in ["first", "second"] {
            fs::create_dir_all(fixture.path().join(target).join("empty")).unwrap();
            fs::write(fixture.path().join(target).join("input"), "bytes").unwrap();
        }
        let root = fixture.path().join("linked");
        let target = if absolute {
            fs::canonicalize(fixture.path().join("first")).unwrap()
        } else {
            "first".into()
        };
        symlink(&target, &root).unwrap();
        let roots = vec![fs::canonicalize(&root).unwrap()];
        let original = tree_digest_v2(&root, &roots).unwrap();
        // The root has one link row, not an additional empty-path directory row.
        // Link bytes are hashed verbatim, not replaced by the canonical destination.
        let preimage = serde_json::json!([
            2,
            [
                [
                    "",
                    "symlink",
                    hex::encode(Sha256::digest(target.as_os_str().as_encoded_bytes()))
                ],
                ["empty", "directory", ""],
                ["input", "file", hex::encode(Sha256::digest(b"bytes"))]
            ]
        ]);
        assert_eq!(
            original,
            hex::encode(Sha256::digest(serde_json::to_vec(&preimage).unwrap()))
        );
        assert!(tree_digest(&root).is_err());
        fs::write(root.join("input"), "changed").unwrap();
        assert_ne!(tree_digest_v2(&root, &roots).unwrap(), original);
        fs::write(root.join("input"), "bytes").unwrap();
        fs::remove_dir(root.join("empty")).unwrap();
        assert_ne!(tree_digest_v2(&root, &roots).unwrap(), original);
        fs::create_dir(root.join("empty")).unwrap();
        assert_eq!(tree_digest_v2(&root, &roots).unwrap(), original);
        fs::remove_file(&root).unwrap();
        let target = if absolute {
            fs::canonicalize(fixture.path().join("second")).unwrap()
        } else {
            "second".into()
        };
        symlink(target, &root).unwrap();
        let roots = vec![fs::canonicalize(&root).unwrap()];
        assert_ne!(tree_digest_v2(&root, &roots).unwrap(), original);
    }
}

#[cfg(unix)]
fn measured_artifact(
    root: &Path,
    roots: &[std::path::PathBuf],
) -> mergemaster_evidence::gate::config::Artifact {
    mergemaster_evidence::gate::config::Artifact {
        name: "measured tree".into(),
        identity: format!(
            "tree-sha256-v2:{}",
            mergemaster_evidence::evidence::workspace::tree_digest_v2(root, roots).unwrap()
        ),
    }
}

#[cfg(unix)]
#[test]
fn pnpm_package_links_verify_through_declared_linked_external_dependency_roots() {
    use mergemaster_evidence::evidence::workspace::verify;
    use std::os::unix::fs::symlink;

    for absolute in [false, true] {
        let repo = fixture();
        let external = tempfile::tempdir().unwrap();
        fs::create_dir_all(external.path().join("pkg")).unwrap();
        fs::write(external.path().join("pkg/index.js"), "package bytes").unwrap();
        let dependency = repo.path().join("dependencies");
        symlink(external.path(), &dependency).unwrap();
        let modules = repo.path().join("node_modules");
        fs::create_dir(&modules).unwrap();
        let target = if absolute {
            fs::canonicalize(external.path().join("pkg")).unwrap()
        } else {
            "../dependencies/pkg".into()
        };
        symlink(target, modules.join("pkg")).unwrap();
        let roots = vec![
            fs::canonicalize(&modules).unwrap(),
            fs::canonicalize(&dependency).unwrap(),
        ];
        let mut lane = lane();
        lane.inputs
            .insert("node_modules".into(), measured_artifact(&modules, &roots));
        lane.inputs.insert(
            "dependencies".into(),
            measured_artifact(&dependency, &roots),
        );
        let head = git(repo.path(), &["rev-parse", "HEAD"]);
        verify(repo.path(), head.trim(), &lane, true).unwrap();
        let modules_before =
            mergemaster_evidence::evidence::workspace::tree_digest_v2(&modules, &roots).unwrap();
        verify(repo.path(), head.trim(), &lane, false).unwrap();
        fs::write(external.path().join("pkg/index.js"), "changed").unwrap();
        // Descendant links are rows, not traversals; the other declared root binds these bytes.
        assert_eq!(
            mergemaster_evidence::evidence::workspace::tree_digest_v2(&modules, &roots).unwrap(),
            modules_before
        );
        assert!(verify(repo.path(), head.trim(), &lane, false).is_err());
        fs::write(external.path().join("pkg/index.js"), "package bytes").unwrap();
        lane.inputs.remove("dependencies");
        assert!(verify(repo.path(), head.trim(), &lane, false).is_err());
    }
}

#[cfg(unix)]
#[test]
fn linked_inputs_refuse_dangling_roots_linked_ancestors_and_aliases() {
    use mergemaster_evidence::evidence::workspace::verify;
    use std::os::unix::fs::symlink;

    for case in [
        "dangling",
        "ancestor",
        "scratch-root",
        "scratch-descendant",
        "aliased-roots",
        "overlapping-roots",
        "tracked-root",
    ] {
        let repo = fixture();
        let external = tempfile::tempdir().unwrap();
        let mut lane = lane();
        let (name, root) = match case {
            "tracked-root" => {
                symlink("tools", repo.path().join("input")).unwrap();
                ("input", repo.path().join("input"))
            }
            "ancestor" => {
                fs::create_dir(external.path().join("input")).unwrap();
                symlink(external.path(), repo.path().join("parent")).unwrap();
                ("parent/input", repo.path().join("parent/input"))
            }
            "scratch-root" => {
                fs::create_dir(repo.path().join("output")).unwrap();
                symlink("output", repo.path().join("input")).unwrap();
                ("input", repo.path().join("input"))
            }
            _ => {
                symlink(external.path(), repo.path().join("input")).unwrap();
                ("input", repo.path().join("input"))
            }
        };
        let roots = vec![fs::canonicalize(&root).unwrap()];
        lane.inputs
            .insert(name.into(), measured_artifact(&root, &roots));
        if case == "dangling" {
            fs::remove_file(&root).unwrap();
            symlink(external.path().join("missing"), &root).unwrap();
        } else if case == "scratch-descendant" {
            fs::create_dir(repo.path().join("output")).unwrap();
            symlink(repo.path().join("output"), root.join("link")).unwrap();
            // Even a matching raw-link preimage must not admit scratch as a measured root.
            let mut with_scratch = roots;
            with_scratch.push(fs::canonicalize(repo.path().join("output")).unwrap());
            lane.inputs
                .insert(name.into(), measured_artifact(&root, &with_scratch));
        }
        if matches!(case, "aliased-roots" | "overlapping-roots") {
            let other = repo.path().join("other");
            let target = if case == "overlapping-roots" {
                let nested = external.path().join("nested");
                fs::create_dir(&nested).unwrap();
                nested
            } else {
                external.path().to_path_buf()
            };
            symlink(target, &other).unwrap();
            let roots = vec![
                fs::canonicalize(&root).unwrap(),
                fs::canonicalize(&other).unwrap(),
            ];
            lane.inputs
                .insert(name.into(), measured_artifact(&root, &roots));
            lane.inputs
                .insert("other".into(), measured_artifact(&other, &roots));
        }
        let head = git(repo.path(), &["rev-parse", "HEAD"]);
        assert!(
            verify(repo.path(), head.trim(), &lane, true).is_err(),
            "{case}"
        );
        assert!(
            verify(repo.path(), head.trim(), &lane, false).is_err(),
            "{case}"
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_inputs_are_remeasured_and_cannot_reach_scratch_or_unmeasured_paths() {
    use mergemaster_evidence::{
        evidence::workspace::{tree_digest_v2, verify},
        gate::config::Artifact,
    };
    use std::os::unix::fs::symlink;
    let repo = fixture();
    let head = git(repo.path(), &["rev-parse", "HEAD"]);
    let modules = repo.path().join("node_modules");
    fs::create_dir(&modules).unwrap();
    fs::write(modules.join("input"), "bytes").unwrap();
    symlink("input", modules.join("link")).unwrap();
    let roots = vec![fs::canonicalize(&modules).unwrap()];
    let mut lane = lane();
    lane.inputs.insert(
        "node_modules".into(),
        Artifact {
            name: "modules".into(),
            identity: format!(
                "tree-sha256-v2:{}",
                tree_digest_v2(&modules, &roots).unwrap()
            ),
        },
    );
    verify(repo.path(), head.trim(), &lane, true).unwrap();
    verify(repo.path(), head.trim(), &lane, false).unwrap();
    fs::write(modules.join("input"), "changed").unwrap();
    assert!(verify(repo.path(), head.trim(), &lane, false).is_err());
    fs::write(modules.join("input"), "bytes").unwrap();
    for target in ["../output", "../../escape"] {
        fs::remove_file(modules.join("link")).unwrap();
        symlink(target, modules.join("link")).unwrap();
        assert!(verify(repo.path(), head.trim(), &lane, false).is_err());
    }
}

#[cfg(unix)]
#[test]
fn workspace_links_may_reach_verified_tracked_siblings_but_not_unmeasured_paths() {
    use mergemaster_evidence::{
        evidence::workspace::{tree_digest_v2, verify},
        gate::config::Artifact,
    };
    use std::os::unix::fs::symlink;
    let repo = fixture();
    for package in ["core", "other"] {
        let directory = repo.path().join("packages").join(package);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("index.js"), "same bytes").unwrap();
    }
    fs::write(
        repo.path().join(".gitignore"),
        "node_modules/\npackages/ignored/\n",
    )
    .unwrap();
    git(repo.path(), &["add", "."]);
    git(
        repo.path(),
        &["commit", "-q", "-m", "tracked workspace packages"],
    );
    let head = git(repo.path(), &["rev-parse", "HEAD"]);
    let modules = repo.path().join("node_modules");
    fs::create_dir_all(modules.join("@workspace")).unwrap();
    let link = modules.join("@workspace/core");
    symlink("../../packages/core", &link).unwrap();
    let module_root = fs::canonicalize(&modules).unwrap();
    let tracked_root = fs::canonicalize(repo.path().join("packages")).unwrap();
    let digest = || tree_digest_v2(&modules, &[module_root.clone(), tracked_root.clone()]).unwrap();
    let original = digest();
    let mut lane = lane();
    lane.inputs.insert(
        "node_modules".into(),
        Artifact {
            name: "workspace modules".into(),
            identity: format!("tree-sha256-v2:{original}"),
        },
    );
    verify(repo.path(), head.trim(), &lane, true).unwrap();
    verify(repo.path(), head.trim(), &lane, false).unwrap();
    fs::remove_file(&link).unwrap();
    symlink("../../packages/other", &link).unwrap();
    assert_ne!(digest(), original);
    assert!(verify(repo.path(), head.trim(), &lane, false).is_err());
    lane.inputs.get_mut("node_modules").unwrap().identity = format!("tree-sha256-v2:{}", digest());
    verify(repo.path(), head.trim(), &lane, false).unwrap();
    // Tracked files, as well as directory prefixes, are valid endpoints.
    fs::remove_file(&link).unwrap();
    symlink("../../packages/core/index.js", &link).unwrap();
    lane.inputs.get_mut("node_modules").unwrap().identity = format!("tree-sha256-v2:{}", digest());
    verify(repo.path(), head.trim(), &lane, false).unwrap();
    fs::write(repo.path().join("packages/core/index.js"), "dirty").unwrap();
    assert!(verify(repo.path(), head.trim(), &lane, false).is_err());
    fs::write(repo.path().join("packages/core/index.js"), "same bytes").unwrap();
    for target in ["packages/untracked", "packages/ignored"] {
        fs::create_dir(repo.path().join(target)).unwrap();
    }
    for target in [
        "packages/untracked",
        "packages/ignored",
        ".git",
        ".git/config",
    ] {
        fs::remove_file(&link).unwrap();
        symlink(format!("../../{target}"), &link).unwrap();
        // Bind the attack link's actual digest, so refusal must be containment,
        // not an incidental identity mismatch.
        let roots = [
            module_root.clone(),
            fs::canonicalize(repo.path().join(target)).unwrap(),
        ];
        lane.inputs.get_mut("node_modules").unwrap().identity = format!(
            "tree-sha256-v2:{}",
            tree_digest_v2(&modules, &roots).unwrap()
        );
        let error = verify(repo.path(), head.trim(), &lane, false).unwrap_err();
        assert!(
            error.to_string().contains("symlink escapes"),
            "{target}: {error}"
        );
    }
}

#[cfg(unix)]
fn assert_tracked_directory_link_rejected(case: &str) {
    use mergemaster_evidence::{
        evidence::workspace::{tree_digest_v2, verify},
        gate::config::Artifact,
    };
    use std::os::unix::fs::symlink;
    let repo = fixture();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("payload"), "outside").unwrap();
    let package = repo.path().join("packages/core");
    fs::create_dir_all(&package).unwrap();
    fs::write(package.join("index.js"), "tracked").unwrap();
    if case == "escape" {
        symlink(outside.path(), package.join("escape")).unwrap();
    } else if case == "cycle" {
        symlink("cycle", package.join("cycle")).unwrap();
    }
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-q", "-m", "tracked package"]);
    let head = git(repo.path(), &["rev-parse", "HEAD"]);
    let modules = repo.path().join("node_modules");
    fs::create_dir(&modules).unwrap();
    let mut lane = lane();
    lane.inputs.insert(
        "node_modules".into(),
        Artifact {
            name: "modules".into(),
            identity: format!(
                "tree-sha256-v2:{}",
                tree_digest_v2(&modules, &[fs::canonicalize(&modules).unwrap()]).unwrap()
            ),
        },
    );
    if case == "scratch" {
        fs::create_dir(package.join("output")).unwrap();
        fs::write(package.join("output/payload"), "scratch").unwrap();
        lane.scratch = vec!["packages/core/output".into()];
    }
    symlink("../packages/core", modules.join("core")).unwrap();
    if case != "cycle" {
        // Use the attack's actual digest, with broader authority only during measurement.
        let roots = [
            fs::canonicalize(&modules).unwrap(),
            fs::canonicalize(&package).unwrap(),
            fs::canonicalize(outside.path()).unwrap(),
        ];
        lane.inputs.get_mut("node_modules").unwrap().identity = format!(
            "tree-sha256-v2:{}",
            tree_digest_v2(&modules, &roots).unwrap()
        );
    }
    for start in [false, true] {
        let error = verify(repo.path(), head.trim(), &lane, start).unwrap_err();
        assert!(
            error.to_string().contains(if case == "cycle" {
                "cyclic workspace symlink"
            } else {
                "symlink escapes"
            }),
            "{case}: {error}"
        );
    }
}

#[cfg(unix)]
#[test]
fn tracked_directory_link_rejects_nested_tracked_escape() {
    assert_tracked_directory_link_rejected("escape");
}

#[cfg(unix)]
#[test]
fn tracked_directory_link_rejects_reachable_scratch_descendant() {
    assert_tracked_directory_link_rejected("scratch");
}

#[cfg(unix)]
#[test]
fn tracked_directory_link_rejects_cycle() {
    assert_tracked_directory_link_rejected("cycle");
}

#[cfg(unix)]
#[test]
fn tracked_directory_links_accept_only_in_tree_nested_links() {
    use mergemaster_evidence::evidence::workspace::{tree_digest_v2, verify};
    use std::os::unix::fs::symlink;
    let repo = fixture();
    let package = repo.path().join("packages/core");
    fs::create_dir_all(package.join("lib")).unwrap();
    fs::write(package.join("lib/index.js"), "tracked").unwrap();
    symlink("lib", package.join("alias")).unwrap();
    symlink("index.js", package.join("lib/entry.js")).unwrap();
    git(repo.path(), &["add", "."]);
    git(
        repo.path(),
        &["commit", "-q", "-m", "in-tree package aliases"],
    );
    let modules = repo.path().join("node_modules");
    fs::create_dir(&modules).unwrap();
    symlink("../packages/core", modules.join("core")).unwrap();
    let roots = [
        fs::canonicalize(&modules).unwrap(),
        fs::canonicalize(&package).unwrap(),
    ];
    let mut lane = lane();
    lane.inputs.insert(
        "node_modules".into(),
        mergemaster_evidence::gate::config::Artifact {
            name: "modules".into(),
            identity: format!(
                "tree-sha256-v2:{}",
                tree_digest_v2(&modules, &roots).unwrap()
            ),
        },
    );
    let head = git(repo.path(), &["rev-parse", "HEAD"]);
    verify(repo.path(), head.trim(), &lane, true).unwrap();
    verify(repo.path(), head.trim(), &lane, false).unwrap();
}

#[cfg(unix)]
#[test]
fn intermediate_bridge_links_must_have_measured_or_tracked_authority() {
    use mergemaster_evidence::evidence::workspace::verify;
    use std::os::unix::fs::symlink;
    for location in ["outside", "untracked", "ignored", "tracked", "measured"] {
        for component in [false, true] {
            let repo = fixture();
            let outside = tempfile::tempdir().unwrap();
            fs::write(repo.path().join(".gitignore"), "ignored/\n").unwrap();
            if location == "ignored" {
                fs::create_dir(repo.path().join("ignored")).unwrap();
            }
            let modules = repo.path().join("node_modules");
            fs::create_dir_all(modules.join("data")).unwrap();
            fs::write(modules.join("data/a"), "a").unwrap();
            fs::write(modules.join("data/b"), "b").unwrap();
            fs::create_dir(modules.join("data-other")).unwrap();
            fs::write(modules.join("data-other/a"), "other").unwrap();
            let bridge = match location {
                "outside" => outside.path().join("bridge"),
                "ignored" => repo.path().join("ignored/bridge"),
                "measured" => modules.join("bridge"),
                _ => repo.path().join("bridge"),
            };
            let destination = modules.join(if component { "data" } else { "data/a" });
            symlink(&destination, &bridge).unwrap();
            git(repo.path(), &["add", ".gitignore"]);
            if location == "tracked" {
                git(repo.path(), &["add", "bridge"]);
            }
            git(repo.path(), &["commit", "-q", "-m", "bridge authority"]);
            let link_target = if component {
                bridge.join("a")
            } else {
                bridge.clone()
            };
            symlink(link_target, modules.join("link")).unwrap();
            let roots = [
                fs::canonicalize(&modules).unwrap(),
                fs::canonicalize(bridge.parent().unwrap()).unwrap(),
            ];
            let mut lane = lane();
            lane.inputs
                .insert("node_modules".into(), measured_artifact(&modules, &roots));
            let head = git(repo.path(), &["rev-parse", "HEAD"]);
            if matches!(location, "tracked" | "measured") {
                verify(repo.path(), head.trim(), &lane, true).unwrap();
            } else {
                let error = verify(repo.path(), head.trim(), &lane, false).unwrap_err();
                assert!(
                    error.to_string().contains("unmeasured intermediate link"),
                    "{location}, component={component}: {error}"
                );
                // Retargeting this bridge must not make the unchanged raw input link admissible.
                fs::remove_file(&bridge).unwrap();
                symlink(
                    modules.join(if component { "data-other" } else { "data/b" }),
                    &bridge,
                )
                .unwrap();
                assert_eq!(
                    measured_artifact(&modules, &roots).identity,
                    lane.inputs["node_modules"].identity
                );
                assert!(verify(repo.path(), head.trim(), &lane, false).is_err());
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn mutual_workspace_dependencies_accept_authorized_directory_cycles() {
    use mergemaster_evidence::evidence::workspace::verify;
    use std::os::unix::fs::symlink;
    let repo = fixture();
    for package in ["a", "b"] {
        fs::create_dir_all(repo.path().join(format!("packages/{package}"))).unwrap();
        fs::write(
            repo.path().join(format!("packages/{package}/index.js")),
            package,
        )
        .unwrap();
    }
    git(repo.path(), &["add", "."]);
    git(
        repo.path(),
        &["commit", "-q", "-m", "mutual workspace packages"],
    );
    for package in ["a", "b"] {
        let modules = repo.path().join(format!("packages/{package}/node_modules"));
        fs::create_dir(modules).unwrap();
    }
    fs::create_dir(repo.path().join("node_modules")).unwrap();
    symlink("../packages/a", repo.path().join("node_modules/a")).unwrap();
    symlink("../../b", repo.path().join("packages/a/node_modules/b")).unwrap();
    symlink("../../a", repo.path().join("packages/b/node_modules/a")).unwrap();
    let names = [
        "node_modules",
        "packages/a/node_modules",
        "packages/b/node_modules",
    ];
    let mut roots = names
        .iter()
        .map(|name| fs::canonicalize(repo.path().join(name)).unwrap())
        .collect::<Vec<_>>();
    roots.push(fs::canonicalize(repo.path()).unwrap());
    let mut lane = lane();
    for name in names {
        lane.inputs.insert(
            name.into(),
            measured_artifact(&repo.path().join(name), &roots),
        );
    }
    let head = git(repo.path(), &["rev-parse", "HEAD"]);
    verify(repo.path(), head.trim(), &lane, true).unwrap();
    verify(repo.path(), head.trim(), &lane, false).unwrap();
}

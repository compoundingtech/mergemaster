//! The wrapper and signer share this filesystem-byte and index-flag check.
use std::{fs, path::Path, process::Command};
use mergemaster_evidence::evidence::signing::clean;

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git").current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
            "-c", "gc.auto=0", "-c", "maintenance.auto=false"])
        .args(args).output().unwrap();
    assert!(output.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&output.stderr));
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
        if let Some(flag) = flag { git(repo.path(), &["update-index", flag, "tools/check"]); }
        fs::write(repo.path().join("tools/check"), "printf untrusted\\n\n").unwrap();
        if flag.is_some() { assert!(git(repo.path(), &["status", "--porcelain"]).is_empty()); }
        assert!(!clean(repo.path()).unwrap(), "accepted modified input with {flag:?}");
    }
}

#[test]
fn hidden_index_flags_refuse_even_without_a_modification() {
    for flag in ["--skip-worktree", "--assume-unchanged"] {
        let repo = fixture();
        git(repo.path(), &["update-index", flag, "tools/check"]);
        assert!(!clean(repo.path()).unwrap(), "accepted hidden input with {flag}");
    }
}

#[test]
fn actual_bytes_must_match_blobs_even_when_a_clean_filter_hides_the_change() {
    let repo = fixture();
    fs::write(repo.path().join(".gitattributes"), "tools/check filter=erase\n").unwrap();
    git(repo.path(), &["config", "filter.erase.clean", "printf canonical"]);
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["add", "--renormalize", "tools/check"]);
    git(repo.path(), &["commit", "-q", "-m", "filtered input"]);
    fs::write(repo.path().join("tools/check"), "printf untrusted\\n\n").unwrap();
    // Refresh cached stat data through the filter without changing the canonical blob.
    git(repo.path(), &["add", "tools/check"]);
    assert!(git(repo.path(), &["status", "--porcelain"]).is_empty());
    assert!(!clean(repo.path()).unwrap(), "accepted bytes different from the committed blob");
}

fn lane() -> mergemaster_evidence::gate::config::Lane {
    serde_json::from_value(serde_json::json!({"argv":["check"],"definition_paths":["tools"],
        "trust_levels":["agent"],"mode":"required_evidence","events":["pull_request"],
        "environment":{"manifest":"environment.json","paths":["tools"]},
        "protected_edits":"reject","remediation_argv":["check"],"scratch":["output"]})).unwrap()
}

#[test]
fn workspace_roots_refuse_escape_overlap_tracked_collisions_and_symlinks() {
    use mergemaster_evidence::evidence::workspace::{validate, verify};
    for root in ["../escape", "/escape", ".git/objects", "tools", "tools/check", "tools/check/child", "output/nested"] {
        let repo = fixture();
        let head = git(repo.path(), &["rev-parse", "HEAD"]);
        let mut lane = lane();
        lane.scratch.push(root.into());
        assert!(validate(repo.path(), head.trim(), &lane).is_err(), "{root}");
    }
    #[cfg(unix)] {
        use std::os::unix::fs::symlink;
        for root in ["output", "parent/output"] {
            let repo = fixture();
            let outside = tempfile::tempdir().unwrap();
            let head = git(repo.path(), &["rev-parse", "HEAD"]);
            let mut lane = lane();
            lane.scratch = vec![root.into()];
            symlink(outside.path(), repo.path().join(root.split('/').next().unwrap())).unwrap();
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
    #[cfg(unix)] {
        use std::os::unix::fs::{PermissionsExt, symlink};
        fs::rename(tree.path().join("renamed"), tree.path().join("input")).unwrap();
        fs::set_permissions(tree.path().join("input"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(tree_digest(tree.path()).unwrap(), original);
        symlink("input", tree.path().join("link")).unwrap();
        assert!(tree_digest(tree.path()).is_err());
    }
}

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
    git(repo.path(), &["commit", "-q", "-m", "filtered input"]);
    fs::write(repo.path().join("tools/check"), "printf untrusted\\n\n").unwrap();
    assert!(git(repo.path(), &["status", "--porcelain"]).is_empty());
    assert!(!clean(repo.path()).unwrap(), "accepted bytes different from the committed blob");
}

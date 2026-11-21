//! Replay independent, frozen Python observations through the native CLI boundary.
#[path = "../src/pinned_python.rs"]
mod pinned_python;
use serde_json::Value;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn presign_notice_frozen_stdout_summary_annotation_and_never_fails() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixture: Value = serde_json::from_slice(
        &fs::read(root.join("tests/fixtures/oracle/presign-notice.json")).unwrap(),
    )
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let temporary = tempfile::tempdir().unwrap();
        let bin = temporary.path().join("bin");
        fs::create_dir(&bin).unwrap();
        for (name, source) in case["executables"].as_object().unwrap() {
            let path = bin.join(name);
            fs::write(&path, source.as_str().unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let summary = temporary.path().join("summary");
        fs::write(&summary, case["summary_initial"].as_str().unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_mergemaster"));
        command
            .args(["evidence", "presign-notice"])
            .current_dir(temporary.path())
            .env(
                "PATH",
                std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(
                    &std::env::var_os("PATH").unwrap_or_default(),
                )))
                .unwrap(),
            )
            .env("GITHUB_STEP_SUMMARY", &summary);
        for name in ["LINES", "BASE_SHA", "REPOSITORY", "PR_NUMBER", "GH_TOKEN"] {
            command.env_remove(name);
        }
        for (name, value) in case["environment"].as_object().unwrap() {
            command.env(name, value.as_str().unwrap());
        }
        let done = command.output().unwrap();
        let expected = &case["expected"];
        let id = case["id"].as_str().unwrap();
        assert_eq!(
            done.status.code(),
            expected["exit_code"].as_i64().map(|code| code as i32),
            "{id}"
        );
        assert_eq!(
            done.stdout,
            expected["stdout"].as_str().unwrap().as_bytes(),
            "{id}: stdout"
        );
        assert_eq!(
            done.stderr,
            expected["stderr"].as_str().unwrap().as_bytes(),
            "{id}: stderr"
        );
        assert_eq!(
            fs::read(summary).unwrap(),
            expected["summary"].as_str().unwrap().as_bytes(),
            "{id}: summary"
        );
    }
}

fn git(repo: &std::path::Path, args: &[&str]) -> String {
    let done = Command::new("git")
        .args(["-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C"])
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .unwrap();
    assert!(done.status.success(), "{args:?}: {:?}", done.stderr);
    String::from_utf8(done.stdout).unwrap().trim().to_owned()
}

fn commit(repo: &std::path::Path, message: &str) -> String {
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", message]);
    git(repo, &["rev-parse", "HEAD"])
}

fn real_git_notice(repo: &std::path::Path, bin: &std::path::Path, revision: &str) -> String {
    let lines = "evidence-decision v1 check=old decision=run outcome=no_note tree_of=head head_tree=used fork=false\nevidence-decision v1 check=new decision=run outcome=no_note tree_of=head head_tree=used fork=false";
    let run = |mut command: Command| {
        let summary = bin.join("summary");
        fs::write(&summary, "").unwrap();
        let done = command
            .current_dir(repo)
            .env("BASE_SHA", revision)
            .env("LINES", lines)
            .env("REPOSITORY", "org/repo")
            .env("PR_NUMBER", "7")
            .env("GITHUB_STEP_SUMMARY", &summary)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env(
                "PATH",
                std::env::join_paths(std::iter::once(bin.to_owned()).chain(std::env::split_paths(
                    &std::env::var_os("PATH").unwrap_or_default(),
                )))
                .unwrap(),
            )
            .output()
            .unwrap();
        assert_eq!(done.status.code(), Some(0));
        assert!(done.stderr.is_empty(), "{:?}", done.stderr);
        (done.stdout, fs::read(summary).unwrap())
    };
    let mut native = Command::new(env!("CARGO_BIN_EXE_mergemaster"));
    native.args(["evidence", "presign-notice"]);
    let observed = run(native);
    let source = std::env::var_os("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must name the pinned Python oracle source");
    let mut python = pinned_python::command();
    python
        .arg("-B")
        .arg(std::path::Path::new(&source).join("scripts/ci-evidence-presign-notice"));
    assert_eq!(observed, run(python), "revision {revision}");
    String::from_utf8(observed.0).unwrap()
}

#[test]
fn presign_notice_real_git_layout_history_and_unreadable_objects() {
    let temporary = tempfile::tempdir().unwrap();
    let repo = temporary.path().join("repo");
    let bin = temporary.path().join("bin");
    fs::create_dir(&repo).unwrap();
    fs::create_dir(&bin).unwrap();
    // Only gh is scripted: every config lookup traverses real Git objects.
    fs::write(bin.join("gh"), "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(bin.join("gh"), fs::Permissions::from_mode(0o755)).unwrap();
    git(&repo, &["init", "-q"]);
    fs::create_dir(repo.join(".st")).unwrap();
    fs::create_dir(repo.join(".fractal")).unwrap();
    let old = repo.join(".st/required-lanes.json");
    let new = repo.join(".fractal/required-lanes.json");
    fs::write(
        &old,
        r#"{"lanes":{"old":{"definition_paths":["scripts"]}}}"#,
    )
    .unwrap();
    let old_revision = commit(&repo, "old");
    assert!(real_git_notice(&repo, &bin, &old_revision).contains("listed=old passed_over=-"));
    fs::write(
        &new,
        r#"{"lanes":{"new":{"definition_paths":["scripts"]}}}"#,
    )
    .unwrap();
    commit(&repo, "both layouts");
    assert!(real_git_notice(&repo, &bin, "HEAD").contains("listed=new passed_over=-"));
    assert!(real_git_notice(&repo, &bin, &old_revision).contains("listed=old passed_over=-"));
    fs::remove_file(&old).unwrap();
    commit(&repo, "new only");
    assert!(real_git_notice(&repo, &bin, "HEAD").contains("listed=new passed_over=-"));
    fs::write(&new, "{malformed").unwrap();
    fs::write(
        &old,
        r#"{"lanes":{"old":{"definition_paths":["scripts"]}}}"#,
    )
    .unwrap();
    commit(&repo, "malformed preferred with valid legacy");
    assert_eq!(
        real_git_notice(&repo, &bin, "HEAD"),
        "evidence-presign-notice: Expecting property name enclosed in double quotes: line 1 column 2 (char 1); nothing to say\n"
    );
    let blob = git(&repo, &["rev-parse", "HEAD:.fractal/required-lanes.json"]);
    fs::remove_file(repo.join(".git/objects").join(&blob[..2]).join(&blob[2..])).unwrap();
    assert_eq!(
        real_git_notice(&repo, &bin, "HEAD"),
        "evidence-presign-notice: cannot read .fractal/required-lanes.json at HEAD; nothing to say\n"
    );
    assert_eq!(
        real_git_notice(&repo, &bin, "missing-revision"),
        "evidence-presign-notice: cannot inspect lane definition at missing-revi; nothing to say\n"
    );
}

use super::*;
use crate::gate::git::git;
use serde_json::{Value, json};
use std::os::unix::{
    ffi::OsStringExt,
    fs::{PermissionsExt, symlink},
};
#[test]
fn projection_matches_oracle_for_raw_modes_layout_and_selectors() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let run = |args: &[&str]| {
        String::from_utf8(git(repo, args).unwrap())
            .unwrap()
            .trim()
            .to_owned()
    };
    run(&["init"]);
    for (name, bytes) in [
        ("src/a", b"a\n".as_slice()),
        ("src/nested/b", b"b\n"),
        ("src-extra", b"extra\n"),
        ("run", b"#!/bin/sh\n"),
        (".st/inputs.json", br#"{"selected":{"ok":1},"other":0}"#),
    ] {
        let path = repo.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    std::fs::set_permissions(repo.join("run"), std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink("src/a", repo.join("link")).unwrap();
    std::fs::write(
        repo.join(std::ffi::OsString::from_vec(b"src/raw\xff\t\n".to_vec())),
        b"raw",
    )
    .unwrap();
    run(&["add", "."]);
    let first = run(&["write-tree"]);
    let commit = run(&[
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit-tree",
        &first,
        "-m",
        "root",
    ]);
    run(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{commit},module"),
    ]);
    let tree = run(&["write-tree"]);
    std::fs::write(
        repo.join(".st/inputs.json"),
        br#"{"selected":{"ok":1},"other":2}"#,
    )
    .unwrap();
    run(&["add", ".st/inputs.json"]);
    let unrelated = run(&["write-tree"]);
    std::fs::create_dir_all(repo.join(".fractal")).unwrap();
    std::fs::write(
        repo.join(".fractal/inputs.json"),
        br#"{"selected":{"preferred":1}}"#,
    )
    .unwrap();
    run(&["add", ".fractal/inputs.json"]);
    let both = run(&["write-tree"]);
    let paths = [
        vec![],
        vec!["."],
        vec!["missing"],
        vec!["src"],
        vec!["src", "src/a"],
        vec!["run", "link", "module"],
        vec![".", "!src"],
        vec![".", "!src/"],
        vec![".", "!src///"],
        vec![".", "!src/nested"],
        vec![".", "!src-extra"],
        vec!["src", "!src"],
        vec!["!src"],
        vec!["src", "!src/a"],
        vec![".", ".st/missing.json::x"],
        vec![".st/inputs.json::selected"],
        vec![".fractal/inputs.json::selected"],
        vec![
            ".st/inputs.json::selected",
            ".fractal/inputs.json::selected",
        ],
        vec![".st/inputs.json::missing"],
        vec![".", ".st/inputs.json::selected"],
        vec!["src", ".st/inputs.json::selected"],
    ];
    let mut cases = Vec::new();
    let mut actual = Vec::new();
    for tree in [&tree, &unrelated, &both] {
        for paths in &paths {
            let paths: Vec<String> = paths.iter().map(|p| (*p).into()).collect();
            cases.push(json!([tree, paths]));
            actual.push(match project(repo, tree, &paths) {
                Ok(key) => json!({"key":key}),
                Err(e) => json!({"reason":e.reason}),
            });
        }
    }
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
    let script = r#"
import json, runpy, sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
results=[]
for tree,paths in json.loads(sys.argv[3]):
    try: results.append(dict(key=o['project'](sys.argv[2],tree,paths)))
    except o['Failure'] as e: results.append(dict(reason=e.reason))
print(json.dumps(results))
"#;
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            script,
            &root,
            repo.to_str().unwrap(),
            &json!(cases).to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(actual.len(), expected.len());
    for (i, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(*actual, expected, "{}", cases[i]);
    }
}

#[test]
fn projection_validates_before_all_fast_paths() {
    for tree in ["--help", "HEAD", "", &"a".repeat(39), &"g".repeat(40)] {
        for paths in [vec![], vec![".".into()], vec!["x::key".into()]] {
            let failure = project(Path::new("/nonexistent"), tree, &paths).unwrap_err();
            assert_eq!(failure.reason, "error");
            assert_eq!(failure.detail, "invalid tree object ID");
        }
    }
    for tree in ["a".repeat(40), "b".repeat(64)] {
        assert_eq!(
            project(Path::new("/nonexistent"), &tree, &[".".into()]).unwrap(),
            Some(tree)
        );
    }
}

#[test]
fn projection_plumbing_output_is_bounded_and_never_truncated() {
    for format in ["sha1", "sha256"] {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        git(repo, &["init", &format!("--object-format={format}")]).unwrap();
        let expected = if format == "sha1" {
            ExpectedOutput::Sha1
        } else {
            ExpectedOutput::Sha256
        };
        let blob = input_git(
            repo,
            &["hash-object", "--stdin"],
            b"fixture",
            None,
            expected,
        )
        .unwrap();
        assert_eq!(blob.len(), if format == "sha1" { 40 } else { 64 });
        for bytes in [0, 64, 65, 32 * 1024] {
            git(repo, &["config", "projection.fixture", &"x".repeat(bytes)]).unwrap();
            let failure = input_git(
                repo,
                &["config", "--get", "projection.fixture"],
                b"",
                None,
                expected,
            )
            .unwrap_err();
            assert_eq!(failure.reason, "error");
            assert_eq!(failure.detail, "Git config returned a malformed object id");
        }
        assert_eq!(
            input_git(
                repo,
                &["update-index", "-z", "--index-info"],
                b"",
                None,
                ExpectedOutput::Discard
            )
            .unwrap(),
            b""
        );
        let tree = input_git(repo, &["write-tree"], b"", None, expected).unwrap();
        assert_eq!(tree.len(), blob.len());
        assert!(input_git(repo, &["not-a-git-command"], b"", None, expected).is_err());
    }
}

#[test]
fn option_terminator_named_entries_do_not_contaminate_projections() {
    for format in ["sha1", "sha256"] {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let run = |args: &[&str]| String::from_utf8(git(repo, args).unwrap()).unwrap();
        run(&["init", &format!("--object-format={format}")]);
        std::fs::write(repo.join("unrelated"), b"wanted").unwrap();
        run(&["add", "--all"]);
        let expected = run(&["write-tree"]).trim().to_owned();
        for directory in [false, true] {
            let path = repo.join("--");
            if directory {
                std::fs::create_dir(&path).unwrap();
                std::fs::write(path.join("child"), b"unwanted").unwrap();
            } else {
                std::fs::write(&path, b"unwanted").unwrap();
            }
            run(&["add", "--all"]);
            let tree = run(&["write-tree"]);
            assert_eq!(
                project(repo, tree.trim(), &["unrelated".into()]).unwrap(),
                Some(expected.clone())
            );
            assert_eq!(
                project(repo, tree.trim(), &["missing".into()]).unwrap(),
                None
            );
            let selected = project(repo, tree.trim(), &["--".into()]).unwrap().unwrap();
            assert_eq!(
                run(&["ls-tree", "-r", "--name-only", &selected]),
                if directory { "--/child\n" } else { "--\n" }
            );
            if !directory {
                std::fs::remove_file(path).unwrap();
            }
        }
    }
}

#[test]
fn projection_deadline_preserves_exchange_refusals() {
    use std::{process::Command, time::Duration};
    for (size, status, reason) in [(40, 0, None), (66, 0, Some("error")), (0, 7, Some("error"))] {
        let mut command = Command::new("python3");
        command.args([
            "-c",
            "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'a'*int(sys.argv[1]));sys.exit(int(sys.argv[2]))",
            &size.to_string(),
            &status.to_string(),
        ]).stdin(Stdio::piped());
        let result = projection_capture::exchange(
            &mut command,
            b"input",
            "fixture",
            ExpectedOutput::Sha1,
            Duration::from_secs(60),
        );
        match reason {
            Some(reason) => assert_eq!(result.unwrap_err().reason, reason),
            None => assert_eq!(result.unwrap(), vec![b'a'; size]),
        }
    }
    for bytes in [b"".as_slice(), b"input"] {
        let mut command = Command::new("python3");
        command
            .args(["-c", "import signal;signal.pause()"])
            .stdin(Stdio::piped());
        let failure = projection_capture::exchange(
            &mut command,
            bytes,
            "fixture",
            ExpectedOutput::Sha1,
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(failure.reason, "error");
        assert!(
            failure
                .detail
                .to_string()
                .contains("timed out after 0 seconds")
        );
    }
}
#[test]
fn successful_noisy_fsmonitor_matches_projection_oracle() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git(repo, &["init"]).unwrap();
    std::fs::write(repo.join("wanted"), b"fixture").unwrap();
    git(repo, &["add", "wanted"]).unwrap();
    let tree = String::from_utf8(git(repo, &["write-tree"]).unwrap()).unwrap();
    let hook = repo.join("monitor.py");
    std::fs::write(&hook, "#!/usr/bin/env python3\nimport pathlib,sys\np=pathlib.Path(__file__).with_suffix('.calls')\nwith p.open('ab') as f:f.write(b'x')\nsys.stderr.buffer.write(b'e'*1048577)\nsys.stderr.buffer.flush()\nsys.stdout.buffer.write(b'token\\0')\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    git(repo, &["config", "core.fsmonitor", hook.to_str().unwrap()]).unwrap();
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let output = Command::new("python3").args([
        "-c", "import runpy,sys; o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify');print(o['project'](sys.argv[2],sys.argv[3],['wanted']))",
        &root, repo.to_str().unwrap(), tree.trim(),
    ]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let before = std::fs::read(hook.with_extension("calls")).unwrap().len();
    let actual = project(repo, tree.trim(), &["wanted".into()])
        .unwrap()
        .unwrap();
    assert_eq!(actual, String::from_utf8(output.stdout).unwrap().trim());
    assert!(std::fs::read(hook.with_extension("calls")).unwrap().len() > before);
}
#[test]
fn projection_timeout_uses_oracle_full_argv_and_caller_cwd() {
    let repo = Path::new("relative-repository");
    let mut command = projection_command(repo, &["hash-object", "--stdin"]);
    assert!(command.get_current_dir().is_none());
    let oracle = Command::new("python3").args(["-c", "import subprocess; print('git hash-object: '+str(subprocess.TimeoutExpired(['git','-C','relative-repository','-c','gpg.format=ssh','-c','gpg.ssh.program=ssh-keygen','-c','commit.gpgSign=false','hash-object','--stdin'],0)))"]).output().unwrap();
    assert!(oracle.status.success());
    let failure = projection_capture::exchange(
        &mut command,
        b"",
        "hash-object",
        ExpectedOutput::Sha1,
        Duration::ZERO,
    )
    .unwrap_err();
    assert_eq!(
        failure.detail,
        String::from_utf8(oracle.stdout).unwrap().trim()
    );
}

#[test]
fn alternate_objects_cover_listing_config_resolution_and_selected_blob() {
    const CHILD: &str = "MERGEMASTER_PROJECTION_ALTERNATE_CHILD";
    if let Ok(repo) = std::env::var(CHILD) {
        let tree = std::env::var("MERGEMASTER_PROJECTION_ALTERNATE_TREE").unwrap();
        let expected = std::env::var("MERGEMASTER_PROJECTION_ALTERNATE_KEY").unwrap();
        assert_eq!(
            project(
                Path::new(&repo),
                &tree,
                &["wanted".into(), ".st/inputs.json::selected".into()]
            )
            .unwrap()
            .unwrap(),
            expected
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let repo = dir.path().join("consumer");
    std::fs::create_dir_all(source.join(".fractal")).unwrap();
    std::fs::create_dir_all(&repo).unwrap();
    git(&source, &["init"]).unwrap();
    git(&repo, &["init"]).unwrap();
    std::fs::write(source.join("wanted"), b"fixture").unwrap();
    std::fs::write(
        source.join(".fractal/inputs.json"),
        br#"{"selected":{"value":1}}"#,
    )
    .unwrap();
    git(&source, &["add", "."]).unwrap();
    let tree = String::from_utf8(git(&source, &["write-tree"]).unwrap()).unwrap();
    let tree = tree.trim();
    let objects = source.join(".git/objects");
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap();
    let oracle = Command::new("python3")
        .args(["-c", "import runpy,sys;o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify');print(o['project'](sys.argv[2],sys.argv[3],['wanted','.st/inputs.json::selected']))",
            &root, repo.to_str().unwrap(), tree])
        .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", &objects)
        .output().unwrap();
    assert!(
        oracle.status.success(),
        "{}",
        String::from_utf8_lossy(&oracle.stderr)
    );
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "evidence::legacy_verify::projection::tests::alternate_objects_cover_listing_config_resolution_and_selected_blob", "--nocapture"])
        .env(CHILD, &repo)
        .env("MERGEMASTER_PROJECTION_ALTERNATE_TREE", tree)
        .env("MERGEMASTER_PROJECTION_ALTERNATE_KEY", String::from_utf8(oracle.stdout).unwrap().trim())
        .env("GIT_ALTERNATE_OBJECT_DIRECTORIES", &objects)
        .output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
fn read_timeouts_preserve_exact_oracle_command_strings() {
    let tree = "a".repeat(40);
    let output = Command::new("python3")
        .args([
            "-c",
            r#"
import json,runpy,subprocess,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
def expired(command,**kwargs): raise subprocess.TimeoutExpired(command,0)
subprocess.run=expired
out=[]; repo='relative-repository'; tree='a'*40
for call in [
 lambda: v['selector_item'](repo,tree,'.st/input.json::value'),
 lambda: v['selected_content'](repo,tree,"quoted'\n.json::value"),
 lambda: v['project'](repo,tree,["quoted'\n"]),
 lambda: v['project'](repo,tree,['.','!excluded'])]:
 try: call(); raise AssertionError('expected timeout')
 except v['Failure'] as e: out.append(str(e))
print(json.dumps(out))
"#,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
    EXCHANGE_TIMEOUT.set(Duration::ZERO);
    let repo = Path::new("relative-repository");
    let actual = [
        selector_item(repo, &tree, ".st/input.json::value").unwrap_err(),
        selected_content(repo, &tree, "quoted'\n.json::value").unwrap_err(),
        project(repo, &tree, &["quoted'\n".into()]).unwrap_err(),
        project(repo, &tree, &[".".into(), "!excluded".into()]).unwrap_err(),
    ];
    EXCHANGE_TIMEOUT.set(Duration::from_secs(60));
    for (error, expected) in actual.into_iter().zip(expected) {
        assert_eq!(error.detail.to_string(), expected);
    }
}

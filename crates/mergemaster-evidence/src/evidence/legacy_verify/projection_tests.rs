use super::*;
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
        let blob = input_git(repo, &["hash-object", "--stdin"], b"fixture", None).unwrap();
        assert_eq!(blob.len(), if format == "sha1" { 41 } else { 65 });
        for bytes in [0, 64, 65, 32 * 1024] {
            git(repo, &["config", "projection.fixture", &"x".repeat(bytes)]).unwrap();
            let result = input_git(repo, &["config", "--get", "projection.fixture"], b"", None);
            if bytes < MAX_PROJECTION_OUTPUT {
                assert_eq!(
                    result.unwrap_err().detail,
                    "unexpected Git projection output"
                );
            } else {
                let failure = result.unwrap_err();
                assert_eq!(failure.reason, "projection-output-too-large");
            }
        }
        assert_eq!(
            input_git(repo, &["update-index", "-z", "--index-info"], b"", None).unwrap(),
            b""
        );
        let tree = input_git(repo, &["write-tree"], b"", None).unwrap();
        assert_eq!(tree.len(), blob.len());
        assert!(input_git(repo, &["not-a-git-command"], b"", None).is_err());
    }
}

#[test]
fn projection_object_output_is_exactly_one_oid_and_newline() {
    for width in [40, 64] {
        let oid = "a".repeat(width);
        assert!(valid_output(format!("{oid}\n").as_bytes(), width));
        for bad in [
            oid.clone(),
            format!("{oid}\n\n"),
            format!("{oid}\0"),
            format!("{}\n", "g".repeat(width)),
        ] {
            assert!(!valid_output(bad.as_bytes(), width));
        }
        assert!(!valid_output(
            format!("{oid}\n").as_bytes(),
            if width == 40 { 64 } else { 40 }
        ));
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
    for (size, status, reason) in [
        (65, 0, None),
        (66, 0, Some("projection-output-too-large")),
        (0, 7, Some("error")),
    ] {
        let mut command = Command::new("python3");
        command.args([
            "-c",
            "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*int(sys.argv[1]));sys.exit(int(sys.argv[2]))",
            &size.to_string(),
            &status.to_string(),
        ]).stdin(Stdio::piped());
        let result = exchange(GitChild::spawn(&mut command).unwrap(), b"input");
        match reason {
            Some(reason) => assert_eq!(result.unwrap_err().reason, reason),
            None => assert_eq!(result.unwrap(), vec![b'x'; size]),
        }
    }
    for bytes in [b"".as_slice(), b"input"] {
        let mut command = Command::new("python3");
        command
            .args(["-c", "import signal;signal.pause()"])
            .stdin(Stdio::piped());
        let child = GitChild::with_timeout(&mut command, Duration::ZERO).unwrap();
        let failure = exchange(child, bytes).unwrap_err();
        assert_eq!(failure.reason, "error");
        assert!(
            failure
                .detail
                .to_string()
                .contains("Git subprocess deadline exceeded")
        );
    }
}

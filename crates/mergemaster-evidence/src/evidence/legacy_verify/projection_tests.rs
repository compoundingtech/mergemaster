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

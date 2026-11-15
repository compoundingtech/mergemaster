use super::*;
use crate::gate::git::git;
use serde_json::{Value, json};
#[test]
fn lossless_config_resolution_matches_oracle_decode_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git(repo, &["init"]).unwrap();
    for name in [
        b".st/legacy.json".as_slice(),
        b".st/both.json",
        b".fractal/both.json",
        b".st/\xff.json",
        b".fractal/\xfe.json",
        b".st/\xfc.json",
        b".fractal/\xfc.json",
        b".st/.st/input.json",
        b".fractal/.st/input.json",
        b".st/.fractal/only-wrong.json",
        b".fractal/.fractal/only-wrong.json",
        b".st/.st/.fractal/input.json",
        b".st/.st/\xff.json",
    ] {
        let path = repo.join(OsStr::from_bytes(name));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"{}").unwrap();
    }
    git(repo, &["add", "."]).unwrap();
    let tree = String::from_utf8(git(repo, &["write-tree"]).unwrap())
        .unwrap()
        .trim()
        .to_owned();
    let cases: Vec<Vec<u32>> = [
        ".st/legacy.json::key",
        ".fractal/legacy.json::key",
        ".st/both.json::key",
        ".fractal/both.json::key",
        ".st/missing.json::key",
        ".st/legacy.json::SURROGATE",
        ".st/ESCAPE.json::key",
        ".fractal/ESCAPE.json::key",
        ".st/ABSENT.json::key",
        ".st/PREFERRED.json::key",
        ".st/BOTH_RAW.json::key",
        ".st/SURROGATE.json::key",
        ".st/\0.json::key",
        "plain.json::SURROGATE",
        ".st/.fractal/input.json::key",
        ".fractal/.st/input.json::key",
        ".st/.fractal/only-wrong.json::key",
        ".st/.fractal/.fractal/input.json::key",
        ".st/.fractal/ESCAPE.json::key",
    ]
    .into_iter()
    .map(|name| {
        NormalizedText::from(name)
            .replace("ESCAPE", TextRef::Points(&[0xdcff]))
            .replace("ABSENT", TextRef::Points(&[0xdcfd]))
            .replace("PREFERRED", TextRef::Points(&[0xdcfe]))
            .replace("BOTH_RAW", TextRef::Points(&[0xdcfc]))
            .replace("SURROGATE", TextRef::Points(&[0xd800]))
            .borrowed()
            .points()
            .collect()
    })
    .collect();
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); result=[]
for points in json.loads(sys.argv[4]):
 try:
  path=v['selector_item'](sys.argv[2],sys.argv[3],''.join(map(chr,points)))
  result.append(dict(path=list(map(ord,path)) if path is not None else None))
 except Exception as e: result.append(dict(class_name=type(e).__name__,detail=str(e)))
print(json.dumps(result))
"#,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
            repo.to_str().unwrap(),
            &tree,
            &serde_json::to_string(&cases).unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(expected.len(), cases.len());
    let evaluate = |item: TextRef<'_>| match selector_item(repo, &tree, item) {
        Ok(path) => json!({"path":path.map(|p| p.borrowed().points().collect::<Vec<_>>())}),
        Err(error) => {
            let ErrorOrigin::Exception { class } = error.origin else {
                panic!("unexpected refusal: {error:?}");
            };
            json!({"class_name":class,"detail":error.detail.to_string()})
        }
    };
    for (points, expected) in cases.into_iter().zip(expected) {
        assert_eq!(evaluate(TextRef::Points(&points)), expected, "{points:?}");
        if let Some(scalar) = points
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
        {
            assert_eq!(evaluate(TextRef::Str(&scalar)), expected, "{points:?}");
        }
    }
}
#[test]
fn lossless_selected_content_matches_real_git_oracle() {
    use crate::evidence::legacy_policy::{ErrorOrigin, normalized_text::NormalizedText};
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git(repo, &["init"]).unwrap();
    for name in [b"plain.json".as_slice(), b"raw-\xff.json"] {
        std::fs::write(
            repo.join(OsStr::from_bytes(name)),
            br#"{"selected":1,"":2,"nested":{"":3}}"#,
        )
        .unwrap();
    }
    std::fs::write(
        repo.join("workflow.yml"),
        "jobs:\n  test:\n    runs-on: linux\n",
    )
    .unwrap();
    git(repo, &["add", "."]).unwrap();
    let tree = String::from_utf8(git(repo, &["write-tree"]).unwrap())
        .unwrap()
        .trim()
        .to_owned();
    let names = [
        "plain.json::selected",
        "plain.json::nested.",
        "plain.json::\u{0}",
        "plain.json::SURROGATE",
        "raw-ESCAPE.json::selected",
        "missing-ESCAPE.json::selected",
        "bad-SURROGATE.json::selected",
        "bad-\u{0}.json::selected",
        "workflow.yml::jobs.test",
        "workflow.yml::jobs.SURROGATE",
        "missing.json::SURROGATE",
    ];
    let cases: Vec<Vec<u32>> = names
        .iter()
        .map(|name| {
            NormalizedText::from(*name)
                .replace("ESCAPE", TextRef::Points(&[0xdcff]))
                .replace("SURROGATE", TextRef::Points(&[0xd800]))
                .borrowed()
                .points()
                .collect()
        })
        .collect();
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); result=[]
for points in json.loads(sys.argv[4]):
 try:
  value=v['selected_content'](sys.argv[2],sys.argv[3],''.join(map(chr,points)))
  result.append(dict(hex=value.hex() if value is not None else None))
 except Exception as e: result.append(dict(class_name=type(e).__name__,detail=str(e)))
print(json.dumps(result))
"#,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
            repo.to_str().unwrap(),
            &tree,
            &serde_json::to_string(&cases).unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(expected.len(), cases.len());
    for (points, expected) in cases.into_iter().zip(expected) {
        let actual = match selected_content(repo, &tree, TextRef::Points(&points)) {
            Ok(bytes) => json!({"hex":bytes.as_ref().map(hex::encode)}),
            Err(error) => {
                let ErrorOrigin::Exception { class } = error.origin else {
                    panic!("unexpected refusal: {error:?}");
                };
                json!({"class_name":class,"detail":error.detail.to_string()})
            }
        };
        assert_eq!(actual, expected, "{points:?}");
    }
}
#[test]
fn content_and_layout_match_oracle_at_each_tree() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    let run = |args: &[&str]| {
        String::from_utf8(git(repo, args).unwrap())
            .unwrap()
            .trim()
            .to_owned()
    };
    run(&["init"]);
    let write = |path: &str, bytes: &[u8]| {
        let path = repo.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    };
    write(".st/inputs.json", br#"{"selected":{"legacy":1},"":2}"#);
    write("plain.json", br#"{"selected":{"z":1,"a":2}}"#);
    write("bad.json", b"not JSON");
    write("invalid.json", b"\xff");
    write("workflow.yml",b"name: CI\njobs:\n  build:\n    runs-on: linux\n  test:\n    needs: build\n    runs-on: linux\n");
    run(&["add", "."]);
    let legacy = run(&["write-tree"]);
    for item in ["plain.json::selected", "workflow.yml::jobs.test"] {
        let path = item.split_once("::").unwrap().0;
        let size = std::fs::read(repo.join(path)).unwrap().len();
        assert_eq!(
            selected_content_limit(repo, &legacy, item, size - 1)
                .unwrap_err()
                .reason,
            "error"
        );
        assert_eq!(
            selected_content_limit(repo, &legacy, item, size).unwrap(),
            selected_content(repo, &legacy, item).unwrap()
        );
    }
    write(".fractal/inputs.json", br#"{"selected":{"preferred":1}}"#);
    run(&["add", "."]);
    let both = run(&["write-tree"]);
    write(".fractal/inputs.json", b"bad preferred JSON");
    run(&["add", "."]);
    let malformed = run(&["write-tree"]);
    write(".fractal/inputs.json", b"\xff");
    run(&["add", "."]);
    let nontext = run(&["write-tree"]);
    write(".fractal/inputs.json", br#"{"selected":{"preferred":1}}"#);
    run(&["add", "."]);
    std::fs::remove_file(repo.join(".st/inputs.json")).unwrap();
    run(&["add", "-u"]);
    let preferred = run(&["write-tree"]);
    // The checkout is now invalid: every selection must still read the exact tree.
    write(".fractal/inputs.json", b"invalid checkout");
    let items = [
        ".st/inputs.json::selected",
        ".fractal/inputs.json::selected",
        ".st/missing.json::selected",
        ".fractal/missing.json::selected",
        "plain.json::selected",
        "plain.json::selected.missing",
        "plain.json::",
        "missing.json::selected",
        "bad.json::selected",
        "invalid.json::selected",
        "workflow.yml::jobs.test",
        "workflow.yml::jobs.absent",
        "plain.json::selected::extra",
        ".st/inputs.json",
    ];
    let mut cases = Vec::new();
    let mut actual = Vec::new();
    for tree in [&legacy, &both, &preferred, &malformed, &nontext] {
        for item in items {
            cases.push(json!([tree, item]));
            let path = match selector_item(repo, tree, item) {
                Ok(path) => json!({"path":path}),
                Err(e) => json!({"reason":e.reason}),
            };
            let encode = |result: Result<Option<Vec<u8>>, PolicyError>| match result {
                Ok(bytes) => json!({"hex":bytes.map(hex::encode)}),
                Err(e) => json!({"reason":e.reason}),
            };
            actual.push(json!([
                path,
                encode(selected(repo, tree, item)),
                encode(selected_content(repo, tree, item))
            ]));
        }
    }
    let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
        .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
    let script = r#"
import json, runpy, sys
o=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify')
results=[]
for tree,item in json.loads(sys.argv[3]):
    row=[]
    for name in ['selector_item','selected','selected_content']:
        try:
            value=o[name](sys.argv[2],tree,item)
            row.append(dict(path=value) if name=='selector_item' else dict(hex=value.hex() if value is not None else None))
        except o['Failure'] as e:
            row.append(dict(reason=e.reason))
    results.append(row)
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

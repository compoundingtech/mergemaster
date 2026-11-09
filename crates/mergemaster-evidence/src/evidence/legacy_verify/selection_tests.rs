use super::*;
use serde_json::{Value, json};
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

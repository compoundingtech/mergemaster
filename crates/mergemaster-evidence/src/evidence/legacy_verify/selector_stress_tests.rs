use super::*;
use crate::gate::git::git;
use serde_json::{Value, json};

#[test]
fn empty_and_duplicate_selectors_match_pinned_identity_and_projection() {
    let directory = tempfile::tempdir().unwrap();
    let repo = directory.path();
    git(repo, &["init"]).unwrap();
    let mut trees = Vec::new();
    for layout in [".st", ".fractal"] {
        std::fs::create_dir_all(repo.join(layout)).unwrap();
        std::fs::write(
            repo.join(layout).join("inputs.json"),
            br#"{"":{"":7},"selected":{"z":1,"a":2}}"#,
        )
        .unwrap();
        std::fs::write(repo.join("plain.json"), br#"{"":3,"selected":4}"#).unwrap();
        git(repo, &["add", "."]).unwrap();
        trees.push(
            String::from_utf8(git(repo, &["write-tree"]).unwrap())
                .unwrap()
                .trim()
                .to_owned(),
        );
    }
    let singles = [
        ".st/inputs.json::",
        ".fractal/inputs.json::",
        ".st/inputs.json::.",
        ".fractal/inputs.json::.",
        ".st/missing.json::",
        "plain.json::",
        "plain.json::.",
        "plain.json::selected::selected",
        "plain.json::::",
        "missing.json::",
    ];
    let mut cases = Vec::new();
    for tree in &trees {
        for item in singles {
            cases.push(json!({"tree":tree,"paths":[item]}));
        }
        for paths in [
            vec![".st/inputs.json::"; 64],
            vec![".fractal/inputs.json::."; 64],
            [
                ".st/inputs.json::selected",
                ".fractal/inputs.json::selected",
            ]
            .repeat(32),
            ["plain.json::", "plain.json::selected", "plain.json::"].repeat(32),
            vec!["missing.json::"; 64],
        ] {
            cases.push(json!({"tree":tree,"paths":paths}));
        }
    }
    let output = crate::pinned_python::command()
        .args([
            "-c",
            r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); rows=[]
for case in json.loads(sys.argv[3]):
 tree,paths=case['tree'],case['paths']; item=paths[0]
 resolved=v['selector_item'](sys.argv[2],tree,item)
 content=v['selected'](sys.argv[2],tree,item)
 key=v['project'](sys.argv[2],tree,paths)
 unique=v['project'](sys.argv[2],tree,sorted(set(paths)))
 assert key==unique
 if item.endswith('inputs.json::'):
  assert content==b'{"":7}',(item,content)
 if item.endswith('inputs.json::.'):
  assert content==b'7',(item,content)
 if len(paths)>1 and 'inputs.json' in item:
  assert key is not None
 rows.append(dict(resolved=resolved,hex=content.hex() if content is not None else None,key=key))
print(json.dumps(rows))
"#,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").unwrap(),
            repo.to_str().unwrap(),
            &serde_json::to_string(&cases).unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(expected.len(), cases.len());
    for (case, expected) in cases.iter().zip(expected) {
        let tree = case["tree"].as_str().unwrap();
        let paths: Vec<NormalizedText> = case["paths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap().into())
            .collect();
        let item = paths[0].borrowed();
        let resolved = selector_item(repo, tree, item).unwrap();
        let content = selected(repo, tree, item).unwrap();
        let key = super::super::projection::project(repo, tree, &paths).unwrap();
        assert_eq!(
            json!({"resolved":resolved.map(|p|p.to_string()),"hex":content.map(hex::encode),"key":key}),
            expected,
            "{case}"
        );
        let points: Vec<u32> = item.points().collect();
        assert_eq!(
            selector_item(repo, tree, TextRef::Points(&points)).unwrap(),
            selector_item(repo, tree, item).unwrap()
        );
    }
}

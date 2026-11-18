use super::*;
use serde_json::{Value, json};
#[test]
fn lossless_definition_digests_and_refusal_order_match_real_oracle() {
    let root = tempfile::tempdir().unwrap();
    let script = r#"
import json,os,pathlib,runpy,subprocess,sys
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p if p.is_dir() else p.parent.parent
m=runpy.run_path(str(p/'scripts/evidence-verify'));root=pathlib.Path(sys.argv[1]);cases=[]
for width in ['sha1','sha256']:
 repo=root/width;repo.mkdir();subprocess.run(['git','init','-q','--object-format='+width,str(repo)],check=True)
 def git(*args):return subprocess.check_output(['git','-C',str(repo),*args]).strip().decode()
 for name in ['src/a','src/b','src/raw-'+chr(0xdcff),'src/'+chr(0x1f600),'old/z','old/a']:
  path=repo/name;path.parent.mkdir(exist_ok=True);path.write_text('base')
 git('add','.');base=git('write-tree')
 (repo/'src/a').write_text('changed');(repo/'src/b').unlink();(repo/'added').write_text('new');git('add','-A');tree=git('write-tree')
 for paths,absent in [(['src'],[]),(['src/a','src'],['added']),(['missing'],['old']),(['src'],['old']),(['src'],['old/z','old/a']),(['src'],['absent']),(['src'],['added','added'])]:
  for argv in [['run'],['run',chr(0xd800),chr(0xdcc3)+chr(0xdca9),'é😀','quote"\\\n\0']]:
   rules=dict(argv=argv,definition_paths=paths,absent_paths=absent)
   rules=m['lane_rules'](json.dumps(dict(version=1,lanes=dict(check=rules))), 'check')
   try:
    result=m['lane_definition'](str(repo),base,tree,rules)
    result['changed']=[list(name.encode(errors='surrogateescape')) for name in result['changed']]
    expected=['ok',result]
   except m['Failure'] as e:expected=['error',e.reason,list(map(ord,e.detail))]
   cases.append([str(repo),base,tree,json.dumps(dict(version=1,lanes=dict(check=rules))),expected])
print(json.dumps(cases))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .arg(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 28);
    for case in cases {
        let rules = LaneRules::parse(case[3].as_str().unwrap(), TextRef::Str("check")).unwrap();
        let result = lane_definition(
            Path::new(case[0].as_str().unwrap()),
            TextRef::Str(case[1].as_str().unwrap()),
            TextRef::Str(case[2].as_str().unwrap()),
            &rules,
        );
        let actual = match result {
            Ok(lane) => {
                json!(["ok", {"sha256":lane.sha256,"tree_sha256":lane.tree_sha256,"changed":lane.changed}])
            }
            Err(e) => {
                assert_eq!(e.origin, ErrorOrigin::Failure);
                json!([
                    "error",
                    e.reason,
                    e.detail.borrowed().points().collect::<Vec<_>>()
                ])
            }
        };
        assert_eq!(actual, case[4]);
    }
    let error = definition_digest(
        &BTreeSet::new(),
        &[NormalizedText::Codepoints(vec![0x110000])],
        &[],
    )
    .unwrap_err();
    assert_eq!(error.origin, ErrorOrigin::Failure);
    assert_eq!(error.reason, "error");
    assert_eq!(
        error.detail.to_string(),
        "lane argv contains an invalid Unicode code point"
    );
}

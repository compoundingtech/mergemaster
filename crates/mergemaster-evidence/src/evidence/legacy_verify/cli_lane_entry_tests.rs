use super::*;
use serde_json::Value;
#[test]
fn canonical_entry_equivalence_matches_pinned_json_without_narrowing() {
    let output = crate::pinned_python::command().args(["-c", r#"
import json,os,pathlib,runpy,sys
sys.setrecursionlimit(10000)
p=pathlib.Path(os.environ['MERGEMASTER_PYTHON_PARITY_ORACLE']);p=p if p.is_dir() else p.parent.parent
m=runpy.run_path(str(p/'scripts/evidence-verify'));cases=[]
values=['null','true','false','0','-0','0.0','-0.0','1','1.0','1e0','1e309','Infinity','-Infinity','NaN','1.0000000000000002',
 '1e-07','0.0000001','1e20','100000000000000000000','"é😀"','"\\ud800"','"\\udcc3\\udca9"',
 '[1,2]','[2,1]','{"b":2,"a":1}','{"a":1,"b":2}','{"a":0,"a":1}','{"a":1}',
 '{"a":NaN}','{"a":Infinity}','{"a":-0.0}', '"'+('x'*1000)+'"', '['*200+'0'+']'*200]
for lane in ['check',chr(0xd800),'é😀','quote"\\\n']:
 docs=['{"lanes":{'+json.dumps(lane)+':'+v+'}}' for v in values]
 docs += ['{','null','[]','{"lanes":[]}','{"lanes":{}}','{"lanes":{'+json.dumps(lane)+':'+'1'*4301+'}}']
 expected=[]
 for a in docs:
  here=m['lane_entry'](a,lane)
  expected.append([here is not None and here==m['lane_entry'](b,lane) for b in docs])
 cases.append([list(map(ord,lane)),docs,expected])
print(json.dumps(cases))
"#]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    let mut count = 0;
    for case in cases {
        let lane: Vec<u32> = serde_json::from_value(case[0].clone()).unwrap();
        let docs: Vec<String> = serde_json::from_value(case[1].clone()).unwrap();
        for (i, a) in docs.iter().enumerate() {
            for (j, b) in docs.iter().enumerate() {
                assert_eq!(
                    matches(a, b, TextRef::Points(&lane)).unwrap(),
                    case[2][i][j].as_bool().unwrap(),
                    "{i}/{j}"
                );
                if let Some(lane) = lane
                    .iter()
                    .copied()
                    .map(char::from_u32)
                    .collect::<Option<String>>()
                {
                    assert_eq!(
                        matches(a, b, TextRef::Str(&lane)).unwrap(),
                        case[2][i][j].as_bool().unwrap()
                    );
                }
                count += 1;
            }
        }
    }
    assert_eq!(count, 6084);
    let huge = " ".repeat(1_048_577);
    assert!(!matches("{", &huge, TextRef::Str("check")).unwrap());
    assert!(!matches(r#"{"lanes":{}}"#, &huge, TextRef::Str("check")).unwrap());
    let error = matches(r#"{"lanes":{"check":null}}"#, &huge, TextRef::Str("check")).unwrap_err();
    assert_eq!(
        error.resource,
        Some(SourceResource::LaneJson(
            super::super::statement_document::PolicyResource::SourceBytes
        ))
    );
    assert_eq!(error.reason, "error");
    assert_eq!(
        error.origin,
        crate::evidence::legacy_policy::ErrorOrigin::Failure
    );
}

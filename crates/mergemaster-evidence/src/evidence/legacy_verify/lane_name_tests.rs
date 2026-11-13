use super::*;
use serde_json::{Value as Json, json};
#[test]
fn lossless_lane_names_preserve_raw_entries_and_refusals() {
    let script = r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
def emit(text,name,reason=None,raw_control=False):
 expected=v['lane_entry'](text,name)
 cases.append(dict(text=text,name=list(map(ord,name)),expected=dict(reason=reason) if reason else dict(canonical=expected),raw_control=raw_control))
for name in ['check','\ud800','\udfff','🦀']:
 key=json.dumps(name)
 doc=lambda value:'{"lanes":{'+key+':'+value+'}}'
 for value in ['null','-0','9'*4300,'{"b":2,"a":[1]}']: emit(doc(value),name)
 emit('{"lanes":{'+key+':1,'+key+':2}}',name)
 emit('{"lanes":{'+key+':1},"lanes":null}',name)
 emit('{"lanes":{"other\\ud800":3,'+key+':{"z":1}}}',name)
 for depth in [127,128]: emit(doc('['*(depth-2)+'null'+']'*(depth-2)),name,'lane-entry-nesting-depth' if depth>127 else None)
 emit(doc('1.0'),name,'lane-entry-float-text')
 emit(doc('NaN'),name,'lane-entry-json-extensions')
 emit('{"lanes":{'+key+':1,"other":"\\ud800"}}',name,'lane-entry-json-extensions')
 emit(doc('9'*4301),name)
 for malformed in ['{','[]','{"lanes":[]}']: emit(malformed,name)
for control in ['\n','\0']:
 name='bad'+control+'key'; emit('{"lanes":{"'+name+'":1}}',name,raw_control=True)
print(json.dumps(cases))
"#;
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            script,
            &std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<Json> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 66);
    for case in cases {
        let name: Vec<u32> = serde_json::from_value(case["name"].clone()).unwrap();
        let text = case["text"].as_str().unwrap();
        let result = canonical(text, name.as_slice());
        if case["raw_control"].as_bool().unwrap() {
            assert!(!matches!(result, Ok(Some(_))), "raw control accepted");
            continue;
        }
        let actual = result
            .map(|canonical| json!({"canonical":canonical}))
            .unwrap_or_else(|e| json!({"reason":e.reason}));
        assert_eq!(actual, case["expected"], "{case}");
        if let Some(scalar) = name
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
        {
            let existing = canonical(text, scalar.as_str())
                .map(|canonical| json!({"canonical":canonical}))
                .unwrap_or_else(|e| json!({"reason":e.reason}));
            assert_eq!(existing, actual);
        }
    }
}

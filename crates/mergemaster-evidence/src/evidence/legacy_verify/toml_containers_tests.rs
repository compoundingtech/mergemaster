use super::*;
use serde_json::json;
fn snapshot(value: &Value) -> serde_json::Value {
    match value {
        Value::String(s) => json!(s),
        Value::Bool(b) => json!(b),
        Value::Integer(i) => json!(i.parse::<i64>().unwrap()),
        Value::Array(a) => a.iter().map(snapshot).collect(),
        Value::Table(t) => t.iter().map(|(k, v)| (k.clone(), snapshot(v))).collect(),
        other => panic!("unexpected fixture value {other:?}"),
    }
}
#[test]
fn containers_match_pinned_tomllib() {
    let script = r#"
import json,sys
from tomllib._parser import parse_value
assert sys.version_info[:3]==(3,14,7)
samples=['0','true','false','"é"',"'x'",'[]','{}','[1,2,]','[\n#hi\n1, #x\n2]','{a=1,b.c=[false,{x="é"}]}','{a.b=1,a.c=2}','{a=1,a=2}','{a=[],a.b=2}','{a.b=1,a=2}','{a={x=1},a.x=2}','{a.b=[],a.b.c=2}']
for token in ['[1, {a=[false]}]','{a.b=[1,{x="é"}],c=true}']:
 samples.extend(token[:i] for i in range(len(token)+1))
samples+=['[1 2]','[1,#x','{a=1,}','{a=1\n}','{a 1}','{a=}','[}','{]','{a.b=1,a.b=2}','{a.b.c=1,a.b={}}']
cases=[]
for token in samples:
 for prefix in ['', '🦀\r\né']:
  raw=prefix+token; src=raw.replace('\r\n','\n'); pos=len(prefix.replace('\r\n','\n'))
  try:
   end,val=parse_value(src,pos,float); expected=dict(end=end,value=val)
  except Exception as e: expected=dict(error=str(e),kind=type(e).__name__)
  cases.append(dict(raw=raw,pos=pos,expected=expected))
print(json.dumps(cases))
"#;
    let output = crate::pinned_python::command()
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for case in &cases {
        let source = Source::new(case["raw"].as_str().unwrap());
        let actual = match source.value(case["pos"].as_u64().unwrap() as usize) {
            Ok((end, value)) => json!({"end":end,"value":snapshot(&value)}),
            Err(e) => json!({"error":e.to_string(),"kind":e.kind.class()}),
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    assert_eq!(cases.len(), 136);
}

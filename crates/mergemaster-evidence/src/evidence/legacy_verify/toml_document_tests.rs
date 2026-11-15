use super::*;
use serde_json::json;
fn snapshot(v: &Value) -> serde_json::Value {
    match v {
        Value::String(s) => json!(s),
        Value::Bool(b) => json!(b),
        Value::Integer(i) => json!(i.parse::<i64>().unwrap()),
        Value::Array(a) => a.iter().map(snapshot).collect(),
        Value::Table(t) => t.iter().map(|(k, v)| (k.clone(), snapshot(v))).collect(),
        other => panic!("unexpected fixture value {other:?}"),
    }
}
#[test]
fn documents_match_pinned_tomllib() {
    let script = r#"
import json,sys,tomllib,itertools
assert sys.version_info[:3]==(3,14,7)
parts=['a=1','a.b=1','a={b=1}','a=[1]','[a]','[a.b]','[[a]]','[[a.b]]','b=2','"é"=true']
samples=['','\ufeffa=1','🦀=1','a=1 b=2','[a','[[a]','[a]\nx={a=1,}','# comment\r\na = [1, #x\r\n2,]\n']
samples += ['\n'.join(p) for p in itertools.product(parts,repeat=2)]
samples += ['[[a]]\nx=1\n[a.b]\ny=2\n[[a]]\nx=3\n[a.b]\ny=4','a.b.c=1\na.b.d=2\n[a]\nx=3','[a.b]\nx=1\n[a]\ny=2']
for token in ['[package]\nname="é"\nversion="1"\n','[[bin]]\nname="x"\npath="src/main.rs"\n']:
 samples.extend(token[:i] for i in range(len(token)+1))
quote_cases=[('a='+quote*3+'text'+quote*count+tail,count) for quote in ['"',"'"] for count in range(3,8) for tail in ['', '\nb=2', ' trailing']]
samples += [raw for raw,count in quote_cases]
six_quotes={raw for raw,count in quote_cases if count==6}
cases=[]
for raw in samples:
 try: expected=dict(value=tomllib.loads(raw))
 except Exception as e: expected=dict(error=str(e),kind=type(e).__name__)
 if raw in six_quotes:
  assert expected==dict(error='Expected newline or end of document after a statement (at line 1, column 15)',kind='TOMLDecodeError')
 cases.append(dict(raw=raw,expected=expected,six_quotes=raw in six_quotes))
print(json.dumps(cases))
"#;
    let output = std::process::Command::new("python3")
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let mut six_quote_rejections = 0;
    for case in &cases {
        let actual = match parse(case["raw"].as_str().unwrap()) {
            Ok(table) => json!({"value":snapshot(&Value::Table(table))}),
            Err(e) => json!({"error":e.to_string(),"kind":e.kind.class()}),
        };
        assert_eq!(actual, case["expected"], "{case}");
        if case["six_quotes"] == true {
            assert_eq!(
                actual,
                json!({"error":"Expected newline or end of document after a statement (at line 1, column 15)","kind":"TOMLDecodeError"})
            );
            six_quote_rejections += 1;
        }
    }
    assert_eq!(cases.len(), 210);
    assert_eq!(six_quote_rejections, 6);
}
#[test]
fn deeply_nested_document_is_iterative() {
    let depth = 100_000;
    let mut text = String::from("selected=");
    for _ in 0..depth {
        text.push_str("[{a=");
    }
    text.push('0');
    for _ in 0..depth {
        text.push_str("}]");
    }
    let table = parse(&text).unwrap();
    let mut value = &table["selected"];
    for _ in 0..depth {
        let Value::Array(items) = value else {
            panic!("array expected")
        };
        let Value::Table(map) = &items[0] else {
            panic!("table expected")
        };
        value = &map["a"];
    }
    assert!(matches!(value,Value::Integer(i) if i=="0"));
    let output=std::process::Command::new("python3").args(["-c","import tomllib; s='x='+('[{a='*100000)+'0'+('}]'*100000)\ntry: tomllib.loads(s)\nexcept RecursionError: pass\nelse: raise AssertionError('expected RecursionError')"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

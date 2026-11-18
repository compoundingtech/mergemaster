use super::super::*;
use serde_json::{Value, json};
#[test]
fn keys_and_delimiters_match_pinned_tomllib() {
    let script = r#"
import json,sys,tomllib._parser as p
assert sys.version_info[:3]==(3,14,7) and p.MAX_KEY_PARTS==1000
cases=[]
def add(text,mode,start=0):
 src=text.replace('\r\n','\n')
 try:
  pos,value=p.parse_key(src,start) if mode=='key' else p.parse_value(src,start,float)
  expected=dict(pos=pos,value=value)
 except (p.TOMLDecodeError,RecursionError) as e:
  expected=dict(error=str(e),kind=type(e).__name__)
  if isinstance(e,p.TOMLDecodeError): expected.update(pos=e.pos,line=e.lineno,column=e.colno)
 cases.append(dict(text=text,mode=mode,start=start,expected=expected))
keys=['','a','a.b',' a','a . "🦀" . '+chr(39)*2,'a..b','"\\ud800"','""','"\\u0000"','é','🦀']+[chr(c) for c in range(128)]+['.'.join(['a']*n) for n in (998,999,1000,1001)]
for text in keys:
 for start in [0,len(text.replace('\r\n','\n'))+1]: add(text,'key',start)
bodies=['','abc','🦀','\n','\r\n','\0','\t','\\n','\\ \n  after','\\ud800','\\U0001F980',chr(34)+chr(39)]+[chr(c) for c in range(128)]
for opener in [chr(34),chr(39),chr(34)*3,chr(39)*3]:
 for body in bodies:
  for extra in range(4): add(opener+body+opener+opener[0]*extra,'string')
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
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 2526);
    for case in cases {
        let src = Source::new(case["text"].as_str().unwrap());
        let start = case["start"].as_u64().unwrap() as usize;
        let actual = if case["mode"] == "key" {
            src.key(start)
                .map(|(pos, value)| json!({"pos":pos,"value":value}))
        } else {
            src.string(start)
                .map(|(pos, value)| json!({"pos":pos,"value":value}))
        };
        let actual = actual.unwrap_or_else(|e| {
            let mut value = json!({"error":e.to_string(),"kind":e.kind.class()});
            if e.kind == ErrorKind::Decode {
                value["pos"] = json!(e.position);
                value["line"] = json!(e.line);
                value["column"] = json!(e.column);
            }
            value
        });
        assert_eq!(actual, case["expected"], "{case}");
    }
}

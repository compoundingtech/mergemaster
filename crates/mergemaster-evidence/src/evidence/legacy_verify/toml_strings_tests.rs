use super::*;
use serde_json::{Value, json};

#[test]
fn string_primitives_match_pinned_tomllib() {
    let script = r#"
import json,sys,tomllib._parser as p
assert sys.version_info[:3]==(3,14,7)
cases=[]
for raw in ['', '🦀', 'line\r\nnext', '\\', '\\u', '\\u0000', '\\uD800', '\\U00110000', '\\uZZZZ', '\\ \\tX', '\\ \t\n  after', '\\ \t', '"""', 'x"y""z"""tail']+[chr(c) for c in range(128)]:
 src=raw.replace('\r\n','\n')
 for mode in ['literal','basic','multiline','escape','escape-multiline','raw-escape','raw-escape-multiline']:
  text="'"+src if mode=='literal' else src
  if mode.startswith('escape') and not text.startswith('\\'): text='\\'+text
  for start in [0,len(text)+1,len(text)+9]:
   try:
    if mode=='literal': pos,value=p.parse_literal_str(text,start)
    elif mode in ['basic','multiline']: pos,value=p.parse_basic_str(text,start,multiline=mode=='multiline')
    else: pos,value=p.parse_basic_str_escape(text,start,multiline=mode.endswith('multiline'))
    expected=dict(pos=pos,value=value)
   except p.TOMLDecodeError as e: expected=dict(error=str(e),pos=e.pos,line=e.lineno,column=e.colno)
   cases.append(dict(text=text,mode=mode,start=start,expected=expected))
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
    let cases: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cases.len(), 2982);
    for case in cases {
        let src = Source::new(case["text"].as_str().unwrap());
        let start = case["start"].as_u64().unwrap() as usize;
        let actual = match case["mode"].as_str().unwrap() {
            "literal" => src.literal_string(start),
            "basic" => src.basic_string(start, false),
            "multiline" => src.basic_string(start, true),
            "escape" | "raw-escape" => src.basic_escape(start, false),
            "escape-multiline" | "raw-escape-multiline" => src.basic_escape(start, true),
            _ => unreachable!(),
        };
        let actual = match actual {
            Ok((pos, value)) => json!({"pos":pos,"value":value}),
            Err(e) => {
                json!({"error":e.to_string(),"pos":e.position,"line":e.line,"column":e.column})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
}

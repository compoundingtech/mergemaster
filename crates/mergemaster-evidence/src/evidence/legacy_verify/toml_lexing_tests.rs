use super::*;
use serde_json::{Value, json};

#[test]
fn lexical_primitives_match_pinned_tomllib() {
    let script = r#"
import json,sys,tomllib._parser as p
assert sys.version_info[:3]==(3,14,7),sys.version
cases=[]
for raw in ['',' ', '#plain', '#🦀\n#after', '#🦀\r\n  #next\n', ' \n#comment\n \tvalue']+[f'#🦀{chr(c)}tail\n' for c in range(128)]:
 src=raw.replace('\r\n','\n')
 for pos in [0,len(src),len(src)+1,len(src)+9]:
  for mode in ['comment','array','until','until-eof','skip','error']:
   try:
    if mode=='comment': value=p.skip_comment(src,pos)
    elif mode=='array': value=p.skip_comments_and_array_ws(src,pos)
    elif mode=='skip': value=p.skip_chars(src,pos,p.TOML_WS)
    elif mode=='error': raise p.TOMLDecodeError('fixture',src,pos)
    else: value=p.skip_until(src,pos,'!',error_on=p.ILLEGAL_BASIC_STR_CHARS,error_on_eof=mode=='until-eof')
    expected=dict(ok=value)
   except p.TOMLDecodeError as e: expected=dict(error=str(e),message=e.msg,pos=e.pos,line=e.lineno,column=e.colno)
   cases.append(dict(raw=raw,mode=mode,pos=pos,expected=expected))
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
    assert_eq!(cases.len(), 3216);
    for case in cases {
        let source = Source::new(case["raw"].as_str().unwrap());
        let pos = case["pos"].as_u64().unwrap() as usize;
        let actual = match case["mode"].as_str().unwrap() {
            "comment" => source.skip_comment(pos),
            "array" => source.skip_array_ws(pos),
            "skip" => Ok(source.skip(pos, whitespace)),
            "error" => Err(source.error("fixture", pos)),
            mode => source.skip_until(pos, '!', illegal_single, mode == "until-eof"),
        };
        let actual = match actual {
            Ok(pos) => json!({"ok":pos}),
            Err(e) => {
                json!({"error":e.to_string(),"message":e.message,"pos":e.position,"line":e.line,"column":e.column})
            }
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
    for c in (0..=127).map(char::from) {
        assert_eq!(
            bare_key(c),
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        );
        assert_eq!(illegal_single(c), (c < ' ' || c == '\u{7f}') && c != '\t');
        assert_eq!(illegal_multiline(c), illegal_single(c) && c != '\n');
    }
    let source = Source::new("");
    assert_eq!(
        source.skip_until(usize::MAX, '!', illegal_single, false),
        Ok(0)
    );
    assert_eq!(
        source.error("fixture", usize::MAX).column,
        usize::MAX as u128 + 1
    );
}

use super::*;
use serde_json::{Value, json};
use std::process::Command;
fn python(script: &str, args: &[&std::ffi::OsStr]) -> Vec<Value> {
    let out = Command::new("python3")
        .args(["-c", script])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}
#[test]
fn decoding_and_paths_match_python() {
    let cases = python(
        r#"
import json,posixpath,itertools
out=[]
for data in [bytes([a,b]) for a in range(256) for b in [0,65,127,128,159,191,192,223,224,239,240,244,245,255]]+[b'\xe1\x80',b'\xf1\x80\x80',b'\xf1\x80\x80A',b'a\xed\xa0\x80']:
 try: result=dict(text=data.decode())
 except UnicodeDecodeError as e: result=dict(error=str(e))
 out.append(dict(bytes=list(data),expected=result))
paths=['','.', '..','../..','a/../../b','//','///','//a/../b','/../a','a///./b','a/..','../../a/../..','//../x','a/']
for p in paths: out.append(dict(path=p,expected=posixpath.normpath(p)))
for a,b in itertools.product(paths,['Cargo.toml','','x/','/x','//x']): out.append(dict(join=[a,b],expected=posixpath.normpath(posixpath.join(a,b))))
print(json.dumps(out))
"#,
        &[],
    );
    assert_eq!(cases.len(), 3672);
    for case in cases {
        let actual = if case["bytes"].is_array() {
            let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
            match utf8(&bytes) {
                Ok(text) => json!({"text":text}),
                Err(e) => json!({"error":e}),
            }
        } else if let Some(p) = case["path"].as_str() {
            json!(normpath(p))
        } else {
            json!(joined(
                case["join"][0].as_str().unwrap(),
                case["join"][1].as_str().unwrap()
            ))
        };
        assert_eq!(actual, case["expected"], "{case}");
    }
}

use super::*;
use serde_json::{Value, json};
#[test]
fn byte_json_preflight_matches_uncaught_python_errors() {
    let script = r#"
import json,sys
assert sys.version_info[:3]==(3,14,7)
samples=['{}','[]','null','true','NaN','Infinity','-Infinity','-0','1e309','"é🦀\\ud800"','{','[1,]','{"é":}','\ufeff{}','9'*4301]
blobs=[]
for text in samples:
 for encoding in ['utf-8','utf-8-sig','utf-16','utf-16-be','utf-32','utf-32-be']:
  blobs.append(text.encode(encoding))
blobs += [b'\xff',b'\xef\xbb\xbf\xff',b'\xff\xfeX',b'\xfe\xffX',b'\0\0\xfe\xffX',b'\xff\xfe\0\0\0\0\x11\0',b'"\xed\xa0\x80"']
cases=[]
for blob in blobs:
 try:
  value=json.loads(blob); expected={'ok':True}
  if isinstance(value,str): expected['points']=list(map(ord,value))
 except Exception as e: expected={'class':type(e).__name__,'detail':str(e)}
 cases.append([list(blob),expected])
print(json.dumps(cases))
"#;
    let out = std::process::Command::new("python3")
        .args(["-c", script])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cases: Vec<(Vec<u8>, Value)> = serde_json::from_slice(&out.stdout).unwrap();
    for (bytes, expected) in &cases {
        let actual = match parse(bytes) {
            Ok(doc) => match doc.root() {
                super::super::statement_document::Node::String(points) => {
                    json!({"ok":true,"points":points})
                }
                _ => json!({"ok":true}),
            },
            Err(error) => {
                let crate::evidence::legacy_policy::ErrorOrigin::Exception { class } = error.origin
                else {
                    panic!("unexpected Failure")
                };
                assert_eq!(error.reason, "error");
                json!({"class":class,"detail":error.detail.to_string()})
            }
        };
        assert_eq!(&actual, expected, "{bytes:?}");
    }
    assert_eq!(cases.len(), 97);
}
#[test]
fn byte_json_keeps_approved_unbounded_depth() {
    let bytes = format!("{}0{}", "[".repeat(100_000), "]".repeat(100_000));
    let doc = parse(bytes.as_bytes()).unwrap();
    assert!(matches!(
        doc.root(),
        super::super::statement_document::Node::Array(_)
    ));
}

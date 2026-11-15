use super::*;
use serde_json::Value;
#[test]
fn normalized_ids_match_python_strip() {
    let oracle=crate::pinned_python::command().args(["-c",r#"
import json,sys
assert sys.version_info[:3]==(3,14,7)
cases=[]
spaces=''.join(chr(c) for c in list(range(128))+[0x85,0xa0,0x1680,0x2000,0x2007,0x2028,0x2029,0x202f,0x205f,0x3000] if chr(c).isspace())
for width in [40,64]:
 oid='a'*width
 for text in [oid,oid+'\n',spaces+oid+spaces,(' '*100000)+oid+(' '*100000),oid+'x',oid+'\n'+oid,oid+' '*10+'a','',spaces,oid[:-1],oid+'a','é'+oid]:
  normalized=text.strip(); valid=len(normalized)==width and all(c in '0123456789abcdefABCDEF' for c in normalized)
  cases.append(dict(bytes=list(text.encode()),width=width,expected=normalized if valid else None))
cases.append(dict(bytes=[255],width=40,expected=None))
print(json.dumps(cases))
"#]).output().unwrap();
    assert!(oracle.status.success());
    let cases: Vec<Value> = serde_json::from_slice(&oracle.stdout).unwrap();
    for case in &cases {
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        let mut oid = ObjectId::default();
        for byte in bytes {
            oid.push(&[byte]);
        }
        let result = oid.finish(case["width"].as_u64().unwrap() as usize);
        assert_eq!(
            result.as_deref(),
            case["expected"].as_str().map(str::as_bytes)
        );
    }
    assert_eq!(cases.len(), 25);
}

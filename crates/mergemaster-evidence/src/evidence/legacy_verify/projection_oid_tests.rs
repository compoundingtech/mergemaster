use super::*;
use serde_json::Value;
#[test]
fn normalized_ids_match_python_strip_across_chunk_partitions() {
    let oracle=crate::pinned_python::command().args(["-c",r#"
import json,sys
assert sys.version_info[:3]==(3,14,7)
cases=[]
spaces=''.join(chr(c) for c in list(range(128))+[0x85,0xa0,0x1680,0x2000,0x2007,0x2028,0x2029,0x202f,0x205f,0x3000] if chr(c).isspace())
for width in [40,64]:
 oid='a'*width
 for text in [oid,oid+'\n',spaces+oid+spaces,(' '*100000)+oid+(' '*100000),oid+'x',oid+'\n'+oid,oid+' '*10+'a','',spaces,oid[:-1],oid+'a','é'+oid,oid.upper(),oid[:width//2]+'\0'+oid[width//2:],'\r\n'+oid+'\r\n']:
  normalized=text.strip(); valid=len(normalized)==width and all(c in '0123456789abcdefABCDEF' for c in normalized)
  cases.append(dict(bytes=list(text.encode()),width=width,expected=normalized if valid else None))
cases.append(dict(bytes=[255],width=40,expected=None))
print(json.dumps(cases))
"#]).output().unwrap();
    assert!(oracle.status.success());
    let cases: Vec<Value> = serde_json::from_slice(&oracle.stdout).unwrap();
    for case in &cases {
        let bytes: Vec<u8> = serde_json::from_value(case["bytes"].clone()).unwrap();
        let width = case["width"].as_u64().unwrap() as usize;
        let expected = case["expected"].as_str().map(str::as_bytes);
        let mut oid = ObjectId::default();
        for &byte in &bytes {
            oid.push(&[byte]);
        }
        assert_eq!(oid.finish(width).as_deref(), expected, "byte-by-byte");
        // Exhaust every two-chunk split, including empty chunks and UTF-8 interiors.
        // The 200k-byte whitespace fixtures use bounded partition sampling below
        // rather than a quadratic rescan of the same long prefixes/suffixes.
        if bytes.len() <= 1024 {
            for split in 0..=bytes.len() {
                let mut oid = ObjectId::default();
                oid.push(&bytes[..split]);
                oid.push(&[]);
                oid.push(&bytes[split..]);
                assert_eq!(oid.finish(width).as_deref(), expected, "split {split}");
            }
        } else {
            for split in [
                0,
                1,
                99_999,
                100_000,
                100_000 + width,
                bytes.len() - 1,
                bytes.len(),
            ] {
                let mut oid = ObjectId::default();
                oid.push(&bytes[..split]);
                oid.push(&[]);
                oid.push(&bytes[split..]);
                assert_eq!(oid.finish(width).as_deref(), expected, "long split {split}");
            }
        }
        // Reproducible partition-invariance property over every oracle fixture.
        for seed in 1..=64_u64 {
            let mut state = seed;
            let mut remaining = bytes.as_slice();
            let mut oid = ObjectId::default();
            oid.push(&[]);
            while !remaining.is_empty() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                let size = (1 + ((state >> 32) as usize % 4096)).min(remaining.len());
                let (chunk, rest) = remaining.split_at(size);
                oid.push(chunk);
                oid.push(&[]);
                remaining = rest;
            }
            assert_eq!(
                oid.finish(width).as_deref(),
                expected,
                "partition seed {seed}"
            );
        }
    }
    assert_eq!(cases.len(), 31);
}

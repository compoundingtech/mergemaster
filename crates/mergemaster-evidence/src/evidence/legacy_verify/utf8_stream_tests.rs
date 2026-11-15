use super::*;
use serde_json::{Value, json};
#[test]
fn strict_streams_match_python_at_every_split_and_error_offset() {
    let script = r#"
import json,sys
assert sys.version_info[:3]==(3,14,7)
samples=[bytes([a,b]) for a in range(256) for b in [0,65,127,128,159,191,192,223,224,239,240,244,245,255]]
samples += [b'', 'aé中😀\r\n\x85\u2028z'.encode(),b'\xe1\x80',b'\xf1\x80\x80',b'\xf1\x80\x80A',b'\xed\xa0\x80',b'\xf4\x90\x80\x80']
rows=[]
for prefix in [b'',b'first record\n', 'é😀\n'.encode()]:
 for data in samples:
  data=prefix+data
  try: result=dict(text=data.decode())
  except UnicodeDecodeError as e: result=dict(error=str(e))
  rows.append(dict(bytes=list(data),expected=result))
print(json.dumps(rows))
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
    let rows: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rows.len(), 10773);
    for row in rows {
        let bytes: Vec<u8> = serde_json::from_value(row["bytes"].clone()).unwrap();
        for split in 0..=bytes.len() {
            let mut decoder = Utf8::default();
            let mut text = String::new();
            decoder.push(&bytes[..split], |c| text.push(c));
            decoder.push(&[], |c| text.push(c));
            for byte in &bytes[split..] {
                decoder.push(std::slice::from_ref(byte), |c| text.push(c));
            }
            let actual = match decoder.finish() {
                Ok(()) => json!({"text":text}),
                Err(error) => json!({"error":error}),
            };
            assert_eq!(actual, row["expected"], "{row}; split={split}");
        }
    }
}

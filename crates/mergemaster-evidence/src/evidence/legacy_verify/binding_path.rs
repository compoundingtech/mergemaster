//! Encode configured binding paths only when judgment reaches the blob read.
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError, normalized_text::NormalizedText};
use std::{borrow::Cow, ffi::OsString, os::unix::ffi::OsStringExt, path::Path};

pub(super) fn native(text: &NormalizedText) -> Result<Cow<'_, Path>, PolicyError> {
    let points = match text {
        NormalizedText::Scalar(text) => return Ok(Cow::Borrowed(Path::new(text))),
        NormalizedText::Codepoints(points) => points,
    };
    let mut bytes = Vec::with_capacity(points.len());
    let mut utf8 = [0; 4];
    for (index, &point) in points.iter().enumerate() {
        if (0xdc80..=0xdcff).contains(&point) {
            bytes.push((point - 0xdc00) as u8);
        } else if let Some(ch) = char::from_u32(point) {
            bytes.extend_from_slice(ch.encode_utf8(&mut utf8).as_bytes());
        } else {
            let end = index
                + points[index..]
                    .iter()
                    .take_while(|p| (0xd800..=0xdfff).contains(*p))
                    .count();
            let span = if end == index + 1 {
                format!("character '\\u{point:04x}' in position {index}")
            } else {
                format!("characters in position {index}-{}", end - 1)
            };
            return Err(PolicyError {
                origin: ErrorOrigin::Exception {
                    class: "UnicodeEncodeError",
                },
                reason: "error",
                detail: format!("'utf-8' codec can't encode {span}: surrogates not allowed").into(),
            });
        }
    }
    Ok(Cow::Owned(OsString::from_vec(bytes).into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    #[test]
    fn binding_paths_match_python_surrogateescape() {
        let cases = vec![
            vec![0xd800],
            vec![97, 0xd800, 98],
            vec![97, 0xd800, 0xd801, 98],
            vec![0xd800, 0xdc80, 0xd801],
            vec![0xdc80, 0xd800],
            vec![0x1f600, 0xd800],
            vec![97, 0xdcff],
            vec![0x1f600],
            vec![97, 0xdc80, 0xd800, 0xdcff, 98],
        ];
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                r#"
import json, sys
out=[]
for points in json.loads(sys.argv[1]):
 try: out.append(dict(bytes=''.join(map(chr,points)).encode('utf-8','surrogateescape').hex()))
 except UnicodeEncodeError as e: out.append(dict(error=str(e)))
print(json.dumps(out))
"#,
                &serde_json::to_string(&cases).unwrap(),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let expected: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        for (points, expected) in cases.into_iter().zip(expected) {
            match native(&NormalizedText::Codepoints(points)) {
                Ok(path) => assert_eq!(hex::encode(path.as_os_str().as_bytes()), expected["bytes"]),
                Err(error) => {
                    assert_eq!(
                        error.origin,
                        ErrorOrigin::Exception {
                            class: "UnicodeEncodeError"
                        }
                    );
                    assert_eq!(error.detail.to_string(), expected["error"]);
                }
            }
        }
    }
}

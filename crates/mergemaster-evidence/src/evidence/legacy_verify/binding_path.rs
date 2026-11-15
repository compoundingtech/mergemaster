//! Shared strict/filesystem UTF-8 encoding, evaluated only at the required boundary.
use super::value_inputs::TextRef;
use crate::evidence::legacy_policy::{ErrorOrigin, PolicyError, normalized_text::NormalizedText};
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
};

impl<'a> super::judgment::BindingPath<'a> {
    /// Encode at the provider boundary, where the full tree:path argv is known.
    pub fn native(self, tree: Option<&str>) -> Result<Cow<'a, Path>, PolicyError> {
        match self {
            Self::Native(path) => Ok(Cow::Borrowed(path)),
            Self::Text(text) => native(text, tree.map_or(0, |tree| tree.chars().count() + 1)),
        }
    }
}
fn native(text: &NormalizedText, offset: usize) -> Result<Cow<'_, Path>, PolicyError> {
    Ok(match encode(text.borrowed(), offset, true)? {
        Cow::Borrowed(bytes) => Cow::Borrowed(Path::new(OsStr::from_bytes(bytes))),
        Cow::Owned(bytes) => Cow::Owned(OsString::from_vec(bytes).into()),
    })
}
/// Scalar storage stays borrowed; filesystem encoding admits DC80..DCFF raw bytes.
pub(super) fn encode(
    text: TextRef<'_>,
    offset: usize,
    surrogateescape: bool,
) -> Result<Cow<'_, [u8]>, PolicyError> {
    let points = match text {
        TextRef::Str(text) => return Ok(Cow::Borrowed(text.as_bytes())),
        TextRef::Points(points) => points,
    };
    let mut bytes = Vec::with_capacity(points.len());
    let mut utf8 = [0; 4];
    for (index, &point) in points.iter().enumerate() {
        if surrogateescape && (0xdc80..=0xdcff).contains(&point) {
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
                format!("character '\\u{point:04x}' in position {}", index + offset)
            } else {
                format!(
                    "characters in position {}-{}",
                    index + offset,
                    end + offset - 1
                )
            };
            return Err(PolicyError {
                resource: None,
                origin: ErrorOrigin::Exception {
                    class: "UnicodeEncodeError",
                },
                reason: "error",
                detail: format!("'utf-8' codec can't encode {span}: surrogates not allowed").into(),
            });
        }
    }
    Ok(Cow::Owned(bytes))
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
        let output = crate::pinned_python::command()
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
            match native(&NormalizedText::Codepoints(points), 0) {
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
    #[test]
    fn binding_error_positions_match_real_git_arguments() {
        use super::super::{
            configured::GitProvider,
            judgment::{BindingPath, Provider},
        };
        let cases = vec![
            ("tree", vec![0xd800]),
            ("tree", vec![97, 0xd800, 0xd801]),
            ("🦀tree", vec![0x1f600, 0xd800]),
            ("", vec![0xdc80, 0xd800, 0xdcff]),
        ];
        let output = crate::pinned_python::command().args(["-c", r#"
import json, subprocess, sys
out=[]
for tree, points in json.loads(sys.argv[1]):
 try: subprocess.run(['git','cat-file','blob',tree+':'+''.join(map(chr,points))], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 except UnicodeEncodeError as error: out.append(str(error))
print(json.dumps(out))
"#, &serde_json::to_string(&cases).unwrap()]).output().unwrap();
        assert!(output.status.success());
        let expected: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(cases.len(), expected.len());
        for ((tree, points), expected) in cases.into_iter().zip(expected) {
            let mut provider = GitProvider {
                repo: Path::new("."),
                tree,
            };
            let text = NormalizedText::Codepoints(points);
            let error = provider.blob_sha256(BindingPath::Text(&text)).unwrap_err();
            assert_eq!(error.detail.to_string(), expected);
            assert_eq!(
                error.origin,
                ErrorOrigin::Exception {
                    class: "UnicodeEncodeError"
                }
            );
        }
    }
    #[test]
    fn shared_strict_and_filesystem_encoding_match_python() {
        let cases = vec![
            vec![],
            vec![97, 0, 98],
            vec![0x1f600, 0xdcff],
            vec![97, 0xd800, 0xd801, 98],
            vec![0xdc80, 0xd800, 0xdcff],
            vec![0xd800, 0xdc80, 0xd801],
            vec![0xdfff],
            vec![0x1f600],
        ];
        let output = crate::pinned_python::command()
            .args([
                "-c",
                r#"
import json,sys
out=[]
for points in json.loads(sys.argv[1]):
 for mode in ['strict','surrogateescape']:
  for prefix in ['', 'tree:', '🦀tree:']:
   try: out.append(dict(bytes=(''.join(map(chr,points))).encode('utf-8',mode).hex()))
   except UnicodeEncodeError:
    try: (prefix+''.join(map(chr,points))).encode('utf-8',mode)
    except UnicodeEncodeError as e: out.append(dict(exception=type(e).__name__,message=str(e)))
print(json.dumps(out))
"#,
                &serde_json::to_string(&cases).unwrap(),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let expected: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        let mut expected = expected.into_iter();
        for points in cases {
            for surrogateescape in [false, true] {
                for offset in [0, 5, 6] {
                    let expected = expected.next().unwrap();
                    match encode(TextRef::Points(&points), offset, surrogateescape) {
                        Ok(bytes) => assert_eq!(hex::encode(bytes), expected["bytes"]),
                        Err(error) => {
                            assert_eq!(
                                error.origin,
                                ErrorOrigin::Exception {
                                    class: "UnicodeEncodeError"
                                }
                            );
                            assert_eq!(error.detail.to_string(), expected["message"]);
                        }
                    }
                }
            }
        }
        assert!(expected.next().is_none());
        assert!(matches!(
            encode(TextRef::Str("scalar"), 0, false).unwrap(),
            Cow::Borrowed(_)
        ));
    }
}

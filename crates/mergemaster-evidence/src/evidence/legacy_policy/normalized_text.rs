//! Owned Python policy/diagnostic text; scalar callers retain their String storage.
use crate::evidence::legacy_verify::value_inputs::TextRef;

#[derive(Debug, Clone)]
pub enum NormalizedText {
    Scalar(String),
    Codepoints(Vec<u32>),
}
impl NormalizedText {
    pub fn borrowed(&self) -> TextRef<'_> {
        match self {
            Self::Scalar(text) => TextRef::Str(text),
            Self::Codepoints(points) => TextRef::Points(points),
        }
    }
    /// Concatenate borrowed diagnostic fragments; allocate only the owned result.
    pub(crate) fn concat<'a>(parts: impl Iterator<Item = TextRef<'a>> + Clone) -> Self {
        let bytes = parts.clone().try_fold(0, |n, part| match part {
            TextRef::Str(text) => Some(n + text.len()),
            TextRef::Points(_) => None,
        });
        if let Some(bytes) = bytes {
            let mut result = String::with_capacity(bytes);
            for part in parts {
                if let TextRef::Str(text) = part {
                    result.push_str(text);
                }
            }
            Self::Scalar(result)
        } else {
            let mut result = Vec::with_capacity(parts.clone().map(|p| p.points().count()).sum());
            for part in parts {
                result.extend(part.points());
            }
            Self::Codepoints(result)
        }
    }
    pub(crate) fn around(prefix: &str, text: TextRef<'_>, suffix: &str) -> Self {
        Self::concat([TextRef::Str(prefix), text, TextRef::Str(suffix)].into_iter())
    }
    /// Lossless owned text from code points; scalars stay scalar storage.
    pub(crate) fn from_points(points: &[u32]) -> Self {
        points
            .iter()
            .copied()
            .map(char::from_u32)
            .collect::<Option<String>>()
            .map_or_else(|| Self::Codepoints(points.to_vec()), Self::Scalar)
    }
    pub(crate) fn replace(self, needle: &str, replacement: TextRef<'_>) -> Self {
        assert!(!needle.is_empty() && needle.is_ascii());
        let matches = |window: &[u32]| window.iter().copied().eq(needle.bytes().map(u32::from));
        let contains = match &self {
            Self::Scalar(text) => text.contains(needle),
            Self::Codepoints(points) => points.windows(needle.len()).any(matches),
        };
        if !contains {
            return self;
        }
        if let (Self::Scalar(text), TextRef::Str(replacement)) = (&self, replacement) {
            return Self::Scalar(text.replace(needle, replacement));
        }
        let points = match self {
            Self::Scalar(text) => text.chars().map(u32::from).collect(),
            Self::Codepoints(points) => points,
        };
        let mut result = Vec::new();
        let mut at = 0;
        while at < points.len() {
            if points.get(at..at + needle.len()).is_some_and(matches) {
                result.extend(replacement.points());
                at += needle.len();
            } else {
                result.push(points[at]);
                at += 1;
            }
        }
        Self::Codepoints(result)
    }
}
impl From<String> for NormalizedText {
    fn from(text: String) -> Self {
        Self::Scalar(text)
    }
}
impl From<&str> for NormalizedText {
    fn from(text: &str) -> Self {
        Self::Scalar(text.into())
    }
}
impl PartialOrd for NormalizedText {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for NormalizedText {
    fn eq(&self, other: &Self) -> bool {
        self.borrowed().points().eq(other.borrowed().points())
    }
}
impl Ord for NormalizedText {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.borrowed().points().cmp(other.borrowed().points())
    }
}
impl Eq for NormalizedText {}
impl PartialEq<&str> for NormalizedText {
    fn eq(&self, other: &&str) -> bool {
        self.borrowed().points().eq(other.chars().map(u32::from))
    }
}
/// Display is diagnostic-only; wire output must use the lossless borrowed view.
impl std::fmt::Display for NormalizedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.borrowed(), f)
    }
}
impl serde::Serialize for NormalizedText {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Scalar(text) => serializer.serialize_str(text),
            Self::Codepoints(_) => Err(serde::ser::Error::custom(
                "code-point text requires the lossless JSON writer",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codepoint_text_refuses_serde_serialization() {
        // Code points without a UTF-8 form (lone surrogates) must refuse serde,
        // never replace them with U+FFFD; wire output uses the lossless writer.
        assert_eq!(
            serde_json::to_string(&NormalizedText::Codepoints(vec![0xd800, 0x1f600]))
                .unwrap_err()
                .to_string(),
            "code-point text requires the lossless JSON writer"
        );
        assert_eq!(
            serde_json::to_string(&NormalizedText::Scalar("text".into())).unwrap(),
            "\"text\""
        );
    }

    #[test]
    fn normalized_policy_text_replacement_matches_python() {
        let script = r#"
import json,runpy,sys
v=runpy.run_path(sys.argv[1]+'/scripts/evidence-verify'); cases=[]
for check in ['check','\ud800','🦀']:
 for repo in ['org/repo','org/{check}']:
  for value in ['{repository}:{check}:{check}','literal','{check}{check}']:
   text=json.dumps(dict(version=1,checks={check:dict(trust_levels=['agent'],kinds=dict(wrapper=dict(command=[value],runner_prefix=value)))}))
   kind=v['policy_rules'](text,check,repo)['kinds']['wrapper']
   cases.append(dict(value=value,repo=repo,check=list(map(ord,check)),expected=list(map(ord,kind['command'][0])),prefix=list(map(ord,kind['runner_prefix']))))
print(json.dumps(cases))
"#;
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                script,
                &std::env::var("MERGEMASTER_PYTHON_ORACLE").expect("pinned oracle"),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cases: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(cases.len(), 18);
        for case in cases {
            let check: Vec<u32> = serde_json::from_value(case["check"].clone()).unwrap();
            let value = case["value"].as_str().unwrap();
            for text in [
                NormalizedText::Scalar(value.into()),
                NormalizedText::Codepoints(value.chars().map(u32::from).collect()),
            ] {
                let result = text
                    .replace("{repository}", TextRef::Str(case["repo"].as_str().unwrap()))
                    .replace("{check}", TextRef::Points(&check));
                let actual: Vec<u32> = result.borrowed().points().collect();
                assert_eq!(serde_json::json!(actual), case["expected"]);
                assert_eq!(case["expected"], case["prefix"]);
            }
        }
        assert_eq!(
            serde_json::to_value(NormalizedText::Scalar("plain".into())).unwrap(),
            "plain"
        );
        assert!(serde_json::to_value(NormalizedText::Codepoints(vec![0xd800])).is_err());
    }
}

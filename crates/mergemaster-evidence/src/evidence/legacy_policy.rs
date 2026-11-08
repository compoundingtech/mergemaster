//! Legacy skip-policy input declarations; unrelated to native gate authorization.
use serde_json::Value;

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub reason: &'static str,
    pub detail: String,
}
impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}
impl std::error::Error for PolicyError {}

/// Parse the legacy literal-path list, optionally allowing exclusions/selectors.
/// Results are deduplicated and sorted; `where_` supplies diagnostic context.
pub fn declared_paths(
    value: &Value,
    where_: &str,
    selectors: bool,
) -> Result<Vec<String>, PolicyError> {
    let error = |message: String| PolicyError {
        reason: "error",
        detail: format!("{where_}: {message}"),
    };
    let values = value
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 300)
        .ok_or_else(|| error("inputs must be a nonempty list of at most 300 paths".into()))?;
    let mut paths = Vec::with_capacity(values.len());
    for value in values {
        let item = value
            .as_str()
            .filter(|s| s.chars().count() <= 300)
            .ok_or_else(|| error("an input path is not a short string".into()))?;
        let valid = if selectors && item.starts_with('!') {
            literal_path(&item[1..])
        } else if selectors && let Some((path, selector)) = item.split_once("::") {
            let selector_valid = selector.split('.').all(|p| {
                !p.is_empty()
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            });
            let workflow = path.ends_with(".yml") || path.ends_with(".yaml");
            literal_path(path)
                && selector_valid
                && workflow == selector.starts_with("jobs.")
                && (workflow || path.ends_with(".json"))
        } else {
            item == "." || literal_path(item)
        };
        if !valid {
            return Err(error(format!("invalid declared input {item:?}")));
        }
        paths.push(item);
    }
    paths.sort_unstable();
    paths.dedup();
    for item in &paths {
        if let Some(excluded) = item.strip_prefix('!')
            && !paths.iter().any(|p| {
                !p.starts_with('!')
                    && !p.contains("::")
                    && (*p == "."
                        || excluded
                            .strip_prefix(*p)
                            .is_some_and(|rest| rest.starts_with('/')))
            })
        {
            return Err(error(format!(
                "excluded path {item:?} is not under a declared path, so it leaves nothing out"
            )));
        }
    }
    Ok(paths.into_iter().map(str::to_owned).collect())
}

fn literal_path(path: &str) -> bool {
    path.split('/').all(|p| {
        !p.is_empty()
            && p != "."
            && p != ".."
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._@+=,~#-".contains(&b))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn input_declarations_match_the_immutable_oracle() {
        let mut values: Vec<Value> = serde_json::from_str(
            r#"[
          null, {}, true, "src", [], [null], [3], [""], ["."], ["src","src","a"],
          ["src","!src/tmp"], ["src","!src"], ["src","!src2/tmp"], [".","!tmp"],
          ["!tmp"], ["src","!src/../tmp"], ["src","!src/."], ["!src/","src"],
          ["x.yml::jobs.test"], ["x.yaml::jobs.test-id"], ["x.json::a.b"],
          ["x.json::jobs.test"], ["x.yml::a"], ["x.yml::jobs.test.more"],
          ["x.txt::a"], ["x.json::a..b"], ["x.json::a::b"], ["x.json::"],
          ["x.yml::jobs.test","!x.yml/foo"], ["x.json::a","x.json","!x.json/sub"],
          ["../x"], ["x/./a"], ["/x"], ["x/"], ["x//a"], ["x\\a"], ["x:y"],
          ["a@+=,~#-._/b"], ["café"], ["x\n"], ["x\u0000"], ["**"]
        ]"#,
        )
        .unwrap();
        values.extend([
            json!(vec!["a"; 300]),
            json!(vec!["a"; 301]),
            json!(["a".repeat(300)]),
            json!(["a".repeat(301)]),
            json!(["é".repeat(300)]),
        ]);
        values.extend((0_u8..=127).map(|b| json!([format!("a{}b", char::from(b))])));
        let cases: Vec<_> = [false, true]
            .into_iter()
            .flat_map(|selectors| {
                values
                    .iter()
                    .map(move |value| json!({"value":value,"selectors":selectors}))
            })
            .collect();
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for case in json.loads(sys.argv[2]):
    try:
        paths = oracle['declared_paths'](case['value'], 'fixture', case['selectors'])
        results.append({'paths': paths})
    except oracle['Failure'] as failure:
        results.append({'reason': failure.reason})
print(json.dumps(results))
"#,
                &root,
                &serde_json::to_string(&cases).unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(expected.len(), cases.len());
        for (case, expected) in cases.iter().zip(expected) {
            let actual = match declared_paths(
                &case["value"],
                "fixture",
                case["selectors"].as_bool().unwrap(),
            ) {
                Ok(paths) => json!({"paths":paths}),
                Err(error) => {
                    assert!(error.detail.starts_with("fixture: "));
                    json!({"reason":error.reason})
                }
            };
            assert_eq!(actual, expected, "{case}");
        }
    }
}

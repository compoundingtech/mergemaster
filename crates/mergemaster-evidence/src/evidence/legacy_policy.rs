//! Legacy skip-policy schemas; unrelated to native gate authorization.
use serde::Serialize;
use serde_json::{Map, Value, value::RawValue};
use std::collections::BTreeMap;

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

#[derive(Debug)]
pub struct PolicyDocument<'a> {
    pub checks: BTreeMap<String, &'a RawValue>,
}
impl<'a> PolicyDocument<'a> {
    pub fn parse(text: &'a str) -> Result<Self, PolicyError> {
        // RawValue validates JSON grammar without converting unrelated numbers.
        let mut object: BTreeMap<String, &RawValue> =
            serde_json::from_str(text).map_err(|e| invalid(e.to_string()))?;
        let shape = || invalid("skip policy must be {\"version\": 1, \"checks\": {...}}");
        // Python equality also accepts true and 1.0 as version one.
        let version: Option<Value> = object
            .remove("version")
            .and_then(|raw| serde_json::from_str(raw.get()).ok());
        if object.len() != 1
            || !(version.as_ref().and_then(Value::as_f64) == Some(1.0)
                || version == Some(Value::Bool(true)))
        {
            return Err(shape());
        }
        let raw = object.remove("checks").ok_or_else(shape)?;
        let checks = serde_json::from_str(raw.get()).map_err(|_| shape())?;
        Ok(Self { checks })
    }
    /// Consume only the selected check; unrelated entries are not validated.
    pub fn into_header(mut self, check: &str) -> Result<CheckHeader, PolicyError> {
        let entry = self.checks.remove(check).ok_or_else(|| PolicyError {
            reason: "no_policy",
            detail: format!("the skip policy has no entry for check {check}"),
        })?;
        let entry = serde_json::from_str(entry.get()).map_err(|e| invalid(e.to_string()))?;
        CheckHeader::parse(entry, check)
    }
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RequireMode {
    Off,
    Shadow,
    Reject,
}

#[derive(Debug, Serialize)]
pub struct CheckHeader {
    /// Unvalidated kind entries: must be parsed before evidence evaluation.
    #[serde(skip_serializing)]
    pub kinds: Map<String, Value>,
    pub trust_levels: Vec<String>,
    pub max_age_s: Option<u64>,
    pub enforce: bool,
    pub inputs: Option<Vec<String>>,
    pub sample_one_in: u64,
    pub require: RequireMode,
    pub events: Option<Vec<String>>,
}
impl CheckHeader {
    pub fn parse(entry: Value, check: &str) -> Result<Self, PolicyError> {
        let error = |message: &str| invalid(format!("skip policy for {check}: {message}"));
        let shape = || error("needs kinds and trust_levels, and nothing unknown");
        let Value::Object(mut entry) = entry else {
            return Err(shape());
        };
        const KEYS: &[&str] = &[
            "kinds",
            "trust_levels",
            "max_age_s",
            "enforce",
            "inputs",
            "sample_one_in",
            "require",
            "events",
        ];
        if entry.keys().any(|k| !KEYS.contains(&k.as_str()))
            || !entry.contains_key("kinds")
            || !entry.contains_key("trust_levels")
        {
            return Err(shape());
        }
        let trust_levels = names(entry.remove("trust_levels").unwrap())
            .ok_or_else(|| error("trust_levels must be a nonempty list of names"))?;
        let max_age_s =
            match entry.remove("max_age_s") {
                None | Some(Value::Null) => None,
                Some(value) => Some(value.as_u64().filter(|v| *v > 0).ok_or_else(|| {
                    error("max_age_s must be null or a positive integer within u64")
                })?),
            };
        let enforce = entry
            .remove("enforce")
            .unwrap_or(Value::Bool(false))
            .as_bool()
            .ok_or_else(|| error("enforce must be true or false"))?;
        let require = entry.remove("require");
        let require = match require.as_ref().map_or(Some("off"), Value::as_str) {
            Some("off") => RequireMode::Off,
            Some("shadow") => RequireMode::Shadow,
            Some("reject") => RequireMode::Reject,
            _ => return Err(error("require must be one of off, shadow, reject")),
        };
        let inputs = match entry.remove("inputs") {
            None | Some(Value::Null) => None,
            Some(value) => Some(declared_paths(
                &value,
                &format!("skip policy for {check}"),
                true,
            )?),
        };
        let sample_one_in = entry
            .remove("sample_one_in")
            .unwrap_or(Value::from(1))
            .as_u64()
            .filter(|v| (1..=1000).contains(v))
            .ok_or_else(|| error("sample_one_in must be an integer from 1 to 1000"))?;
        let kinds = match entry.remove("kinds") {
            Some(Value::Object(kinds)) if !kinds.is_empty() => kinds,
            _ => return Err(error("kinds must name at least one kind")),
        };
        let events = match entry.remove("events") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                names(value)
                    .filter(|events| {
                        events
                            .iter()
                            .all(|e| matches!(e.as_str(), "pull_request" | "merge_group"))
                            && (events.len() == 1 || (events.len() == 2 && events[0] != events[1]))
                    })
                    .ok_or_else(|| {
                        error("events must be a nonempty list of pull_request, merge_group")
                    })?,
            ),
        };
        Ok(Self {
            kinds,
            trust_levels,
            max_age_s,
            enforce,
            inputs,
            sample_one_in,
            require,
            events,
        })
    }
}
fn invalid(detail: impl Into<String>) -> PolicyError {
    PolicyError {
        reason: "error",
        detail: detail.into(),
    }
}
fn names(value: Value) -> Option<Vec<String>> {
    let Value::Array(values) = value else {
        return None;
    };
    if values.is_empty() {
        return None;
    }
    values
        .into_iter()
        .map(|v| match v {
            Value::String(v) if !v.is_empty() => Some(v),
            _ => None,
        })
        .collect()
}

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
    fn document_and_check_headers_match_the_oracle() {
        let base = json!({"version":1,"checks":{"unit":{"trust_levels":["agent"],
            "kinds":{"wrapper":{"command":["test","{repository}","{check}"]}}}}});
        let parse = |text: &str| PolicyDocument::parse(text)?.into_header("unit");
        let mut cases: Vec<String> = [
            "{",
            "[]",
            r#"{"version":1,"checks":{}}"#,
            r#"{"version":2,"checks":{}}"#,
            r#"{"version":1,"checks":[]}"#,
            r#"{"version":1,"checks":{},"extra":true}"#,
            r#"{"checks":{}}"#,
            r#"{"version":false,"checks":{}}"#,
            r#"{"version":1,"checks":{"unit":false}}"#,
            r#"{"version":1,"checks":{"ignored":1e1000}}"#,
            r#"{"version":1,"checks":{"unit":{"kinds":{"wrapper":{"command":1e1000}},"trust_levels":["agent"]}}}"#,
        ]
        .map(str::to_owned)
        .into();
        cases.push(base.to_string());
        cases.push(
            base.to_string()
                .replace(r#"{"unit":"#, r#"{"ignored":1e1000,"unit":"#),
        );
        let changes: Value = serde_json::from_str(r#"{
          "trust_levels": [[], [""], true, [" "], ["agent","agent"]],
          "max_age_s": [null, 1, 18446744073709551615, 0, -1, true, 1.5, 1.0],
          "enforce": [true, false, null, 1],
          "require": ["off", "shadow", "reject", "bad", null],
          "sample_one_in": [1, 1000, 0, 1001, true, 1.0],
          "events": [null, ["pull_request","merge_group"], ["merge_group"], [], ["push"], ["pull_request","pull_request"]],
          "inputs": [null, ["src","!src/tmp","src"], ["x.yml::jobs.test"], ["."], [], ["../x"]],
          "kinds": [{}, []], "unknown": [true]
        }"#).unwrap();
        for (key, values) in changes.as_object().unwrap() {
            for value in values.as_array().unwrap() {
                let mut doc = base.clone();
                doc["checks"]["unit"][key] = value.clone();
                cases.push(doc.to_string());
            }
        }
        for key in ["kinds", "trust_levels"] {
            let mut doc = base.clone();
            doc["checks"]["unit"].as_object_mut().unwrap().remove(key);
            cases.push(doc.to_string());
        }
        let mut other = base.clone();
        other["checks"]["ignored"] = json!(false);
        cases.push(other.to_string());
        cases.push(base.to_string().replace(":1,", ":true,"));
        cases.push(base.to_string().replace(":1,", ":1.0,"));
        let large = base.to_string().replace(
            "\"trust_levels\"",
            "\"max_age_s\":18446744073709551616,\"trust_levels\"",
        );
        cases.push(large);
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for text in json.loads(sys.argv[2]):
    try:
        header = oracle['policy_rules'](text, 'unit', 'fixture/repo')
        del header['kinds']
        results.append(header)
    except oracle['Failure'] as failure:
        results.append({'reason': failure.reason})
print(json.dumps(results))
"#;
        let output = std::process::Command::new("python3")
            .args(["-c", script, &root, &serde_json::to_string(&cases).unwrap()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(expected.len(), cases.len());
        for (index, (text, expected)) in cases.iter().zip(expected).enumerate() {
            let actual = parse(text)
                .map(|header| serde_json::to_value(header).unwrap())
                .unwrap_or_else(|error| {
                    assert!(!error.detail.is_empty());
                    json!({"reason":error.reason})
                });
            if index == cases.len() - 1 {
                assert!(expected["max_age_s"].is_number()); // max-age-above-u64.
                assert_eq!(actual, json!({"reason":"error"}));
            } else {
                assert_eq!(actual, expected, "{text}");
            }
        }
        other["checks"]["unit"]["kinds"] = json!({"raw":false});
        let header = parse(&other.to_string()).unwrap();
        assert_eq!(
            header.kinds,
            json!({"raw":false}).as_object().unwrap().clone()
        );
    }
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

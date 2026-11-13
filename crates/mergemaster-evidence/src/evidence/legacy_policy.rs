//! Legacy skip-policy schemas; unrelated to native gate authorization.
pub mod check_names;
pub mod kind_rules;
pub mod level_rules;
pub mod normalized_text;
pub mod value_rules;
use check_names::{CheckKey, CheckName, Selection};
use serde::{
    Serialize,
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, Visitor},
};
use serde_json::{Map, Value};

/// Python handler provenance; exception classification is never inferred from text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorOrigin {
    Failure,
    Exception { class: &'static str },
}
#[derive(Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub reason: &'static str,
    pub detail: normalized_text::NormalizedText,
    pub origin: ErrorOrigin,
}
impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}
impl std::error::Error for PolicyError {}

#[derive(Debug)]
pub struct PolicyDocument<'a> {
    check: CheckName<'a>,
    entry: Option<Value>,
}
impl<'a> PolicyDocument<'a> {
    pub fn parse(text: &str, check: impl Into<CheckName<'a>>) -> Result<Self, PolicyError> {
        let check = check.into();
        Ok(Self {
            check,
            entry: check.entry(text, "checks")?,
        })
    }
    /// Unrelated entries are syntax-checked without bounded numeric conversion.
    pub fn into_header(self) -> Result<CheckHeader, PolicyError> {
        let entry = self.entry.ok_or_else(|| PolicyError {
            origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
            reason: "no_policy",
            detail: format!("the skip policy has no entry for check {}", self.check).into(),
        })?;
        CheckHeader::parse(entry, self.check)
    }
    /// Validate and normalize every selected kind before evidence evaluation.
    pub fn into_rules(self, repository: &str) -> Result<PolicyRules, PolicyError> {
        let check = self.check;
        let mut header = self.into_header()?;
        let kinds = kind_rules::checked_kinds(
            std::mem::take(&mut header.kinds),
            &header.trust_levels,
            repository,
            check,
        )?;
        Ok(PolicyRules { header, kinds })
    }
}
/// Syntax-check unrelated entries without converting their numeric values.
pub fn selected_entry(text: &str, name: &str, group: &str) -> Result<Option<Value>, PolicyError> {
    CheckName::from(name).entry(text, group)
}
fn entries(text: &str, selection: Selection<'_>, group: &str) -> Result<Entries, PolicyError> {
    if !super::legacy_json::strict_strings(text) {
        return Err(invalid("unescaped control character in JSON string"));
    }
    let mut decoder = serde_json::Deserializer::from_str(text);
    let entry = DocumentSeed(selection, group)
        .deserialize(&mut decoder)
        .map_err(|e| invalid(e.to_string()))?;
    decoder.end().map_err(|e| invalid(e.to_string()))?;
    Ok(entry)
}
#[derive(Default)]
struct Entries {
    entry: Option<Value>,
    names: std::collections::BTreeSet<Vec<u32>>,
}
struct DocumentSeed<'a>(Selection<'a>, &'a str);
impl<'de> DeserializeSeed<'de> for DocumentSeed<'_> {
    type Value = Entries;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for DocumentSeed<'_> {
    type Value = Entries;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a legacy skip policy object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let (mut version, mut entry, mut checks, mut unknown) =
            (None, Entries::default(), false, false);
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "version" => version = Some(map.next_value::<Value>()?),
                name if name == self.1 => {
                    entry = map.next_value_seed(ChecksSeed(self.0))?;
                    checks = true;
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    unknown = true;
                }
            }
        }
        // Match Python's version-one equality, including true and 1.0.
        if unknown
            || !checks
            || !(version.as_ref().and_then(Value::as_f64) == Some(1.0)
                || version == Some(Value::Bool(true)))
        {
            return Err(de::Error::custom(format!(
                "document must contain version 1 and a {} object",
                self.1
            )));
        }
        Ok(entry)
    }
}
struct ChecksSeed<'a>(Selection<'a>);
impl<'de> DeserializeSeed<'de> for ChecksSeed<'_> {
    type Value = Entries;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for ChecksSeed<'_> {
    type Value = Entries;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a map of legacy check entries")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut entry = Entries::default();
        while let Some(CheckKey(key)) = map.next_key::<CheckKey>()? {
            let selected = match self.0 {
                Selection::Scalar(name) => name.chars().map(u32::from).eq(key.iter().copied()),
                Selection::Points(name) => name == key,
                Selection::Names => {
                    entry.names.insert(key);
                    false
                }
            };
            if selected {
                entry.entry = Some(map.next_value::<Value>()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(entry)
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
    #[serde(skip_serializing)]
    kinds: Map<String, Value>,
    pub trust_levels: Vec<String>,
    pub max_age_s: Option<u64>,
    pub enforce: bool,
    pub inputs: Option<Vec<String>>,
    pub sample_one_in: u64,
    pub require: RequireMode,
    pub events: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct PolicyRules {
    #[serde(flatten)]
    pub header: CheckHeader,
    #[serde(serialize_with = "serialize_pairs")]
    pub kinds: Vec<(String, kind_rules::KindRule)>,
}
impl CheckHeader {
    pub fn parse<'a>(entry: Value, check: impl Into<CheckName<'a>>) -> Result<Self, PolicyError> {
        let check = check.into();
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
                format!("skip policy for {check}"),
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
fn invalid(detail: impl Into<normalized_text::NormalizedText>) -> PolicyError {
    PolicyError {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: detail.into(),
    }
}

#[derive(Debug, Serialize)]
pub struct CommandInputs {
    pub command: Vec<normalized_text::NormalizedText>,
    pub required_inputs: Vec<String>,
    #[serde(serialize_with = "serialize_pairs")]
    pub bind_inputs: Vec<(String, String)>,
}
fn serialize_pairs<S: serde::Serializer, T: Serialize>(
    pairs: &[(String, T)],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(pairs.iter().map(|(key, value)| (key, value)))
}
/// Consume only command/input fields; kind/level key validation is separate.
/// Required-input duplicates/order and placeholders remain unnormalized here.
pub fn checked_command_inputs(
    rule: &mut Map<String, Value>,
    where_: &str,
) -> Result<CommandInputs, PolicyError> {
    let error = |message: &str| invalid(format!("skip policy for {where_}: {message}"));
    let command = rule
        .remove("command")
        .and_then(names)
        .ok_or_else(|| error("command must be a nonempty list of strings"))?;
    let malformed = || error("malformed required_inputs or bind_inputs");
    let required_inputs = string_list(
        rule.remove("required_inputs")
            .unwrap_or(Value::Array(Vec::new())),
    )
    .ok_or_else(malformed)?;
    let bind_inputs = string_map(
        rule.remove("bind_inputs")
            .unwrap_or(Value::Object(Map::new())),
    )
    .ok_or_else(malformed)?;
    Ok(CommandInputs {
        command: command
            .into_iter()
            .map(normalized_text::NormalizedText::Scalar)
            .collect(),
        required_inputs,
        bind_inputs,
    })
}

/// Consume and validate accepted-base file bindings without reading any files.
pub fn checked_base_inputs(
    rule: &mut Map<String, Value>,
    where_: &str,
) -> Result<Vec<(String, String)>, PolicyError> {
    let base = string_map(
        rule.remove("base_inputs")
            .unwrap_or(Value::Object(Map::new())),
    )
    .ok_or_else(|| {
        invalid(format!(
            "skip policy for {where_}: base_inputs maps an input name to a path"
        ))
    })?;
    for (_, path) in &base {
        if !short_path(path) || !(path == "." || literal_path(path)) {
            return Err(invalid(format!(
                "skip policy for {where_}: base_inputs: invalid declared input {path:?}"
            )));
        }
    }
    Ok(base)
}

fn string_map(value: Value) -> Option<Vec<(String, String)>> {
    let Value::Object(values) = value else {
        return None;
    };
    values
        .into_iter()
        .map(|(key, value)| match value {
            Value::String(value) if !key.is_empty() && !value.is_empty() => Some((key, value)),
            _ => None,
        })
        .collect()
}
fn names(value: Value) -> Option<Vec<String>> {
    string_list(value).filter(|values| !values.is_empty())
}
fn string_list(value: Value) -> Option<Vec<String>> {
    let Value::Array(values) = value else {
        return None;
    };
    values
        .into_iter()
        .map(|v| match v {
            Value::String(v) if !v.is_empty() => Some(v),
            _ => None,
        })
        .collect()
}
fn short_path(path: &str) -> bool {
    path.chars().nth(300).is_none()
}

/// Parse the legacy literal-path list, optionally allowing exclusions/selectors.
/// Results are deduplicated and sorted; `where_` supplies diagnostic context.
pub fn declared_paths(
    value: &Value,
    where_: impl std::fmt::Display,
    selectors: bool,
) -> Result<Vec<String>, PolicyError> {
    let error = |message: String| PolicyError {
        origin: crate::evidence::legacy_policy::ErrorOrigin::Failure,
        reason: "error",
        detail: format!("{where_}: {message}").into(),
    };
    let values = value
        .as_array()
        .filter(|v| !v.is_empty() && v.len() <= 300)
        .ok_or_else(|| error("inputs must be a nonempty list of at most 300 paths".into()))?;
    let mut paths = Vec::with_capacity(values.len());
    for value in values {
        let item = value
            .as_str()
            .filter(|s| short_path(s))
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
    fn command_and_base_inputs_match_the_oracle() {
        let base = json!({"command":["test","{repository}","{check}"]});
        let mut cases = vec![base.clone(), json!({})];
        let changes: Value = serde_json::from_str(
            r#"{
          "command": [null, [], false, "test", [""], [1], ["test"," "], [["test"]]],
          "required_inputs": [null, [], false, [""], [1], ["b","a","b"], [" "]],
          "bind_inputs": [null, [], false, {"":"x"}, {"x":""}, {"x":1}, {"z":"q","x":"y"}],
          "base_inputs": [null, [], false, {"":"x"}, {"x":""}, {"x":1}, {"x":"."},
                         {"b":"src/b","a":"src/a"}, {"x":"../src"}, {"x":"src/"},
                         {"x":"!src"}, {"x":"x.json::a"}, {"x":"café"}],
          "unrelated": [true]
        }"#,
        )
        .unwrap();
        for (key, values) in changes.as_object().unwrap() {
            for value in values.as_array().unwrap() {
                let mut rule = base.clone();
                rule[key] = value.clone();
                cases.push(rule);
            }
        }
        for length in [300, 301] {
            let mut rule = base.clone();
            rule["base_inputs"] = json!({"input":"a".repeat(length)});
            cases.push(rule);
        }
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for rule in json.loads(sys.argv[2]):
    try:
        command, required, bind = oracle['checked_command_inputs'](rule, 'fixture')
        base = oracle['checked_base_inputs'](rule, 'fixture')
        results.append(dict(command=command, required_inputs=required, bind_inputs=bind, base_inputs=base))
    except (oracle['Failure'], KeyError):  # Missing command reaches the CLI's error handler.
        results.append({'reason': 'error'})
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
        for (rule, expected) in cases.iter().zip(expected) {
            let mut fields = rule.as_object().unwrap().clone();
            let actual = checked_command_inputs(&mut fields, "fixture")
                .and_then(|inputs| {
                    let base = checked_base_inputs(&mut fields, "fixture")?;
                    let mut value = serde_json::to_value(inputs).unwrap();
                    value["base_inputs"] = Value::Object(
                        base.into_iter()
                            .map(|(key, value)| (key, Value::String(value)))
                            .collect(),
                    );
                    Ok(value)
                })
                .unwrap_or_else(|error| {
                    assert!(
                        error
                            .detail
                            .to_string()
                            .starts_with("skip policy for fixture: ")
                    );
                    json!({"reason":error.reason})
                });
            assert_eq!(actual, expected, "{rule}");
            if let Some(bind) = rule.get("bind_inputs").and_then(Value::as_object)
                && let Some(parsed) = actual["bind_inputs"].as_object()
            {
                assert!(bind.keys().eq(parsed.keys()), "{rule}");
            }
        }
    }

    #[test]
    fn base_input_order_preserves_the_oracle_deciding_reason() {
        let rules = json!([
            {"base_inputs":{"z":"src/z","a":"src/a"}},
            {"base_inputs":{"a":"src/a","z":"src/z"}}
        ]);
        let parsed: Vec<_> = rules
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| {
                let mut fields = rule.as_object().unwrap().clone();
                let base = checked_base_inputs(&mut fields, "fixture").unwrap();
                Value::Object(
                    base.into_iter()
                        .map(|(key, value)| (key, Value::String(value)))
                        .collect(),
                )
            })
            .collect();
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
reasons = []
for original, parsed in zip(json.loads(sys.argv[2]), json.loads(sys.argv[3])):
    for base in (original['base_inputs'], parsed):
        try:
            oracle['value_checks']({'base_inputs': base}, {'z': 'wrong'}, {'z': 'expected'}, 1)
        except oracle['Failure'] as failure:
            reasons.append(failure.reason)
print(json.dumps(reasons))
"#;
        let output = std::process::Command::new("python3")
            .args([
                "-c",
                script,
                &root,
                &rules.to_string(),
                &serde_json::to_string(&parsed).unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reasons: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            reasons,
            ["wrong_input", "wrong_input", "no_run_input", "no_run_input"]
        );
    }

    #[test]
    fn document_and_check_headers_match_the_oracle() {
        let base = json!({"version":1,"checks":{"unit":{"trust_levels":["agent"],
            "kinds":{"wrapper":{"command":["test","{repository}","{check}"]}}}}});
        let parse = |text: &str| PolicyDocument::parse(text, "unit")?.into_header();
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
            r#"{"version":1,"checks":{"ignored":{"n":1e1000,"n":2},"ignored":{"n":3,"n":4},"unit":{"kinds":{"wrapper":{"command":["test"]}},"trust_levels":["agent"]}}}"#,
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
        let shadowed = cases.len()..cases.len() + 3;
        cases.extend([
            base.to_string()
                .replace(r#""version":1"#, r#""version":1e1000,"version":1"#),
            base.to_string()
                .replace(r#""checks":"#, r#""checks":false,"checks":"#),
            base.to_string()
                .replace(r#"{"unit":"#, r#"{"unit":1e1000,"unit":"#),
        ]);
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
                    assert!(!error.detail.to_string().is_empty());
                    json!({"reason":error.reason})
                });
            if shadowed.contains(&index) {
                assert!(expected["trust_levels"].is_array());
                assert_eq!(actual, json!({"reason":"error"}), "{text}");
            } else if index == cases.len() - 1 {
                assert!(expected["max_age_s"].is_number()); // max-age-above-u64.
                assert_eq!(actual, json!({"reason":"error"}));
            } else {
                assert_eq!(actual, expected, "{text}");
            }
        }
        other["checks"]["unit"]["kinds"] = json!({"raw":false});
        assert_eq!(
            PolicyDocument::parse(&other.to_string(), "unit")
                .unwrap()
                .into_rules("owner/repository")
                .unwrap_err()
                .reason,
            "error"
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
                    assert!(error.detail.to_string().starts_with("fixture: "));
                    json!({"reason":error.reason})
                }
            };
            assert_eq!(actual, expected, "{case}");
        }
    }
}

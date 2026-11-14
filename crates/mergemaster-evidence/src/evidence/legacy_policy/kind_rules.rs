//! Complete legacy kind/level declarations; no record evaluation.
use super::check_names::CheckName;
use super::level_rules::{LevelRule, checked_levels, fill, normalized};
use super::normalized_text::NormalizedText;
use super::value_rules::{ValueRules, checked_value_rules};
use super::{
    CommandInputs, PolicyError, checked_base_inputs, checked_command_inputs, exception, invalid,
    names, rule_error,
};
use crate::evidence::legacy_verify::{failure_json::TextRef, python_repr::Repr};
use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Serialize)]
pub struct KindRule {
    #[serde(flatten)]
    pub inputs: CommandInputs,
    pub runner_prefix: Option<NormalizedText>,
    pub trust_levels: Option<Vec<String>>,
    #[serde(serialize_with = "super::serialize_pairs")]
    pub by_level: Vec<(String, LevelRule)>,
    #[serde(flatten)]
    pub values: ValueRules,
    #[serde(serialize_with = "super::serialize_pairs")]
    pub base_inputs: Vec<(String, String)>,
}
pub fn checked_kinds<'a>(
    kinds: Map<String, Value>,
    levels: &[String],
    repository: &str,
    check: impl Into<CheckName<'a>>,
) -> Result<Vec<(String, KindRule)>, PolicyError> {
    let check = check.into();
    kinds
        .into_iter()
        .map(|(kind, raw)| {
            let error = || {
                invalid(NormalizedText::around(
                    "skip policy for ",
                    check.text(),
                    &format!(": kind {} is not valid", Repr(TextRef::Str(&kind))),
                ))
            };
            if !matches!(kind.as_str(), "nix" | "wrapper" | "sekrets" | "observed") {
                return Err(error());
            }
            let Value::Object(mut rule) = raw else {
                return Err(error());
            };
            if rule.keys().any(|key| {
                ![
                    "command",
                    "runner_prefix",
                    "required_inputs",
                    "bind_inputs",
                    "trust_levels",
                    "by_level",
                    "input_order",
                    "shard_inputs",
                    "base_inputs",
                ]
                .contains(&key.as_str())
            }) || !rule.contains_key("command")
            {
                return Err(error());
            }
            let where_ = [check.text(), TextRef::Str("/"), TextRef::Str(&kind)];
            let inputs = checked_command_inputs(&mut rule, &where_)?;
            let values = checked_value_rules(&mut rule, &where_)?;
            let base_inputs = checked_base_inputs(&mut rule, &where_)?;
            let trust_levels = match rule.remove("trust_levels") {
                None | Some(Value::Null) => None,
                Some(value) => Some(names(value).ok_or_else(|| {
                    rule_error(&where_, "trust_levels must be a nonempty list of names")
                })?),
            };
            let runner_prefix = match rule.remove("runner_prefix") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if !value.is_empty() => {
                    Some(fill(NormalizedText::Scalar(value), repository, check))
                }
                _ => return Err(rule_error(&where_, "malformed runner_prefix")),
            };
            let attribute = |kind| {
                exception(
                    "AttributeError",
                    format!("'{kind}' object has no attribute 'items'"),
                )
            };
            let overrides = match rule.remove("by_level").unwrap_or(Value::Null) {
                Value::Object(map) => map,
                Value::Null | Value::Bool(false) => Map::new(),
                Value::String(s) if s.is_empty() => Map::new(),
                Value::Array(a) if a.is_empty() => Map::new(),
                Value::Number(n) if n.as_f64() == Some(0.0) => Map::new(),
                Value::Bool(true) => return Err(attribute("bool")),
                Value::Number(n) => {
                    return Err(attribute(if n.is_f64() { "float" } else { "int" }));
                }
                Value::String(_) => return Err(attribute("str")),
                Value::Array(_) => return Err(attribute("list")),
            };
            let by_level = checked_levels(
                overrides,
                trust_levels.as_deref().unwrap_or(levels),
                repository,
                check,
                &kind,
            )?;
            Ok((
                kind,
                KindRule {
                    inputs: normalized(inputs, repository, check),
                    runner_prefix,
                    trust_levels,
                    by_level,
                    values,
                    base_inputs,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
#[path = "kind_diagnostics_tests.rs"]
mod diagnostics_tests;

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    #[test]
    fn complete_kind_schemas_match_the_pinned_oracle() {
        let mut cases: Vec<Value> = serde_json::from_str(
            r#"[
          {"nix":{"command":["true"]}}, {"wrapper":{"command":["true"]}},
          {"sekrets":{"command":["true"]}}, {"observed":{"command":["true"]}},
          {"unknown":{"command":["true"]}}, {"wrapper":null}, {"wrapper":{}},
          {"wrapper":{"command":["true"],"unknown":true}},
          {"wrapper":{"command":["{repository}","{check}"],"runner_prefix":"{repository}:{check}",
            "required_inputs":["z","a","z"],"bind_inputs":{"b":"{check}","a":"literal"},
            "input_order":{"z":["strong","weak"]},"base_inputs":{"a":"."},
            "shard_inputs":{"count":"n","results":"r","pull_request_count":null},
            "by_level":{"agent":{"command":["{repository}"],"events":["merge_group","pull_request"],
              "required_inputs":["z","z"],"bind_inputs":{"a":"{repository}"},"lane":"tree"}}}},
          {"wrapper":{"command":["true"],"trust_levels":["host"],"by_level":{
            "host":{"command":["true"],"events":["pull_request"],"lane":true}}}},
          {"wrapper":{"command":["true"],"trust_levels":["host"],"by_level":{
            "agent":{"command":["true"],"events":["pull_request"]}}}}
        ]"#,
        )
        .unwrap();
        for field in ["trust_levels", "runner_prefix", "by_level"] {
            for value in [
                json!(null),
                json!(false),
                json!(true),
                json!(0),
                json!(1),
                json!(0.0),
                json!(""),
                json!("0"),
                json!("prefix"),
                json!([]),
                json!({}),
                json!(["agent"]),
                json!(["agent", "agent"]),
                json!([""]),
            ] {
                let mut rule = json!({"command":["true"]});
                rule[field] = value;
                cases.push(json!({"wrapper":rule}));
            }
        }
        let overrides: Vec<Value> = serde_json::from_str(
            r#"[
          null, {}, {"agent":null}, {"":{}},
          {"agent":{"command":["true"]}}, {"agent":{"events":["pull_request"]}},
          {"agent":{"command":["true"],"events":[]}},
          {"agent":{"command":["true"],"events":["pull_request","pull_request"]}},
          {"agent":{"command":["true"],"events":["push"]}},
          {"agent":{"command":["true"],"events":[[]]}},
          {"agent":{"command":["true"],"events":["pull_request"],"unknown":true}},
          {"host":{"command":["true"],"events":["pull_request"]}},
          {"agent":{"command":["true"],"events":["pull_request"]}}
        ]"#,
        )
        .unwrap();
        cases.extend(
            overrides
                .into_iter()
                .map(|value| json!({"wrapper":{"command":["true"],"by_level":value}})),
        );
        for lane in [
            json!(false),
            json!(true),
            json!("tree"),
            json!(0),
            json!(1),
            json!(null),
            json!("base"),
            json!([]),
        ] {
            cases.push(json!({"wrapper":{"command":["true"],"by_level":{
                "agent":{"command":["true"],"events":["pull_request"],"lane":lane}}}}));
        }
        let root = std::env::var("MERGEMASTER_PYTHON_ORACLE")
            .expect("MERGEMASTER_PYTHON_ORACLE must point to the pinned Python oracle");
        let script = r#"
import json, runpy, sys
oracle = runpy.run_path(sys.argv[1] + '/scripts/evidence-verify')
results = []
for kinds in json.loads(sys.argv[2]):
    try:
        policy = dict(version=1, checks=dict(check=dict(kinds=kinds, trust_levels=['agent'])))
        results.append(oracle['policy_rules'](json.dumps(policy), 'check', 'owner/{check}'))
    except (oracle['Failure'], TypeError, AttributeError, KeyError):
        results.append(dict(reason='error'))
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
        assert_eq!(cases.len(), expected.len());
        for (kinds, expected) in cases.into_iter().zip(expected) {
            let policy =
                json!({"version":1,"checks":{"check":{"kinds":kinds,"trust_levels":["agent"]}}});
            let actual = super::super::PolicyDocument::parse(&policy.to_string(), "check")
                .and_then(|document| document.into_rules("owner/{check}"))
                .map(|rules| serde_json::to_value(rules).unwrap())
                .unwrap_or_else(|error| json!({"reason":error.reason}));
            assert_eq!(actual, expected, "{kinds}");
        }
    }
}
